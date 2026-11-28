<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Facade.php';
require_once __DIR__ . '/ArgProvenance.php';

/** Thrown by {@see Adapters::decodePcaHeader} for a `PCA-Action` value that is not strict unpadded base64url of UTF-8 text (`errorCode` is `invalid_pca_header`). */
final class PcaHeaderError extends \RuntimeException
{
    public readonly string $errorCode;

    public function __construct(string $message)
    {
        $this->errorCode = 'invalid_pca_header';
        parent::__construct($message);
    }
}

/**
 * The agent-side tool-call bridge for AI frameworks (adapters.ts): the helpers that feed an agent's provenance recorder the way the reference does
 * (the principal's turns are TRUSTED, tool output UNTRUSTED), the provenance header, the `PCA-Action` header reader and `bridgeToolCall`. Nothing here
 * authorizes: the resource server's verifier decides. Without a recorder the record helpers do nothing.
 *
 * A "target" is an {@see AgentHandle} (its `provenance`), a {@see ProvenanceRecorder}, or null. Messages are PHP arrays, {@see Obj} or objects with
 * `role` / `type` / `content` members (or `getType()`), the shapes the framework adapters see.
 */
final class Adapters
{
    /** Largest bundle carried as a header (base64url characters); a larger one goes in the request body as `pca_provenance`. */
    public const PROV_HEADER_MAX = 8192;
    public const PCA_HEADER = 'PCA-Action';

    private const PRINCIPAL_ROLES = ['user', 'human'];
    private const MODEL_ROLES = ['assistant', 'ai', 'model', 'system', 'developer'];

    /** `PCA-Provenance: <base64url canonical JSON>` for a bundle that fits {@see PROV_HEADER_MAX}; `[]` otherwise (send it in the body). @return array<string,string> */
    public static function provenanceHeaders(?Obj $bundle): array
    {
        if ($bundle === null) {
            return [];
        }
        $v = Pca::b64u(Json::canonicalizeNative($bundle));
        return strlen($v) <= self::PROV_HEADER_MAX ? [ArgProvenance::HEADER => $v] : [];
    }

    /** Headers carrying an encoded PCActn (and its provenance bundle as `PCA-Provenance`). @return array<string,string> */
    public static function pcaHeaders(string $encoded, ?Obj $provenance = null): array
    {
        return [self::PCA_HEADER => Pca::b64u($encoded)] + self::provenanceHeaders($provenance);
    }

    /** Reverse {@see pcaHeaders}: the `PCA-Action` header value to the encoded PCActn JSON text. Throws {@see PcaHeaderError} (strict base64url and UTF-8, nothing normalized). */
    public static function decodePcaHeader(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            throw new PcaHeaderError('PCA-Action header is empty');
        }
        $bytes = Pca::unb64u($value);
        if ($bytes === null) {
            throw new PcaHeaderError('PCA-Action header is not strict unpadded base64url');
        }
        if (!mb_check_encoding($bytes, 'UTF-8')) {
            throw new PcaHeaderError('PCA-Action header does not decode to UTF-8 text');
        }
        return $bytes;
    }

    private static function recorderOf(mixed $t): ?ProvenanceRecorder
    {
        if ($t instanceof ProvenanceRecorder) {
            return $t;
        }
        return $t instanceof AgentHandle ? $t->provenance : null;
    }

    /** Record the principal's own message in the agent's provenance chain (TRUSTED). */
    public static function recordPrincipal(mixed $agent, string $text): void
    {
        self::recorderOf($agent)?->principal($text);
    }

    /** Record a tool result entering the model's context (UNTRUSTED). */
    public static function recordToolResult(mixed $agent, string $tool, mixed $output): void
    {
        self::recorderOf($agent)?->tool($tool, $output);
    }

    private static function get(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        if (is_array($o)) {
            return $o[$k] ?? null;
        }
        return is_object($o) && isset($o->{$k}) ? $o->{$k} : null;
    }

    private static function roleOf(mixed $m): string
    {
        if (is_object($m) && !($m instanceof Obj)) {
            foreach (['getType', '_getType', 'getRole', 'type'] as $g) {
                if (is_callable([$m, $g])) {
                    try {
                        $r = $m->{$g}();
                        if (is_string($r)) {
                            return $r;
                        }
                    } catch (\Throwable) {
                        // fall through
                    }
                }
            }
        }
        foreach (['role', 'type'] as $k) {
            $r = self::get($m, $k);
            if (is_string($r)) {
                return $r;
            }
        }
        return '';
    }

    private static function first(mixed ...$vals): mixed
    {
        foreach ($vals as $v) {
            if ($v !== null) {
                return $v;
            }
        }
        return null;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /**
     * The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL; a `tool_result` / `tool-result` /
     * `function_call_output` part inside any turn, a `tool` / `function` turn and a turn of an unknown role are UNTRUSTED tool output; assistant / system /
     * developer turns add nothing. Each segment: `['origin' => 'principal'|'tool', 'source' => string, 'content' => mixed]`.
     * @return list<array{origin:string,source:string,content:mixed}>
     */
    public static function messageSegments(mixed $m): array
    {
        if ($m === null || is_string($m) || is_bool($m) || is_int($m) || is_float($m)) {
            return [];
        }
        $role = strtolower(self::roleOf($m));
        if (in_array($role, self::MODEL_ROLES, true)) {
            return [];
        }
        $content = self::get($m, 'content');
        $toolName = static fn(mixed $x): string => Js::str(self::first(self::get($x, 'toolName'), self::get($x, 'name'), self::get($x, 'tool_use_id'),
            self::get($x, 'toolCallId'), self::get($x, 'tool_call_id'), self::get($m, 'name'), self::get($m, 'tool_call_id'), 'tool'));
        if (!in_array($role, self::PRINCIPAL_ROLES, true)) {
            return [['origin' => 'tool', 'source' => $toolName($m), 'content' => $content ?? $m]];
        }
        if (!self::isList($content)) {
            return [['origin' => 'principal', 'source' => 'user', 'content' => $content ?? '']];
        }
        $out = [];
        $text = [];
        foreach ($content as $part) {
            $pt = is_array($part) || is_object($part) ? $part : ['type' => 'text', 'text' => Js::str($part)];
            $t = self::get($pt, 'type');
            $t = is_string($t) ? $t : '';
            if (in_array($t, ['tool_result', 'tool-result', 'function_call_output'], true)) {
                $out[] = ['origin' => 'tool', 'source' => $toolName($pt), 'content' => self::first(self::get($pt, 'content'), self::get($pt, 'result'), self::get($pt, 'output'), $pt)];
            } elseif (is_string(self::get($pt, 'text'))) {
                $text[] = self::get($pt, 'text');
            } else {
                $out[] = ['origin' => 'principal', 'source' => 'user', 'content' => $pt];
            }
        }
        if ($text !== []) {
            array_unshift($out, ['origin' => 'principal', 'source' => 'user', 'content' => implode("\n", $text)]);
        }
        return $out;
    }

    /** @var \WeakMap<ProvenanceRecorder,int>|null messages already recorded per recorder */
    private static ?\WeakMap $seen = null;

    /**
     * Record a conversation's new messages in the agent's provenance chain (call it with the whole list before each model turn; messages already
     * recorded are skipped, a shorter list starts over).
     */
    public static function recordMessages(mixed $target, mixed $messages): void
    {
        $rec = self::recorderOf($target);
        if ($rec === null || !self::isList($messages)) {
            return;
        }
        self::$seen ??= new \WeakMap();
        $seen = self::$seen[$rec] ?? 0;
        for ($i = count($messages) < $seen ? 0 : $seen; $i < count($messages); $i++) {
            foreach (self::messageSegments($messages[$i]) as $seg) {
                if ($seg['origin'] === 'principal') {
                    $c = $seg['content'];
                    $c = is_object($c) && !($c instanceof Obj) ? json_decode((string)json_encode($c), true) : $c;
                    $rec->principal(is_string($c) ? $c : Js::stringify(Sign::n(Sign::plain($c))));
                } else {
                    $rec->tool($seg['source'], $seg['content']);
                }
            }
        }
        self::$seen[$rec] = count($messages);
    }

    /**
     * Record what the principal asked for: a string is the principal's message; a message list (or `['messages' => [...]]`) goes through
     * {@see recordMessages}; a map's `input` / `prompt` / `query` / `question` / `message` / `text` string (or message list) is the principal's message.
     * Anything else records nothing (the gate then keeps the context at `agent`: fail closed).
     */
    public static function recordInput(mixed $target, mixed $input): void
    {
        $rec = self::recorderOf($target);
        if ($rec === null) {
            return;
        }
        if (is_string($input)) {
            $rec->principal($input);
        } elseif (self::isList($input)) {
            self::recordMessages($rec, $input);
        } elseif (is_object($input) || (is_array($input) && !array_is_list($input))) {   // any object is a map, as the reference's typeof === 'object'
            if (self::isList(self::get($input, 'messages'))) {
                self::recordMessages($rec, self::get($input, 'messages'));
            }
            foreach (['input', 'prompt', 'query', 'question', 'message', 'text'] as $k) {
                $v = self::get($input, $k);
                if (is_string($v)) {
                    $rec->principal($v);
                } elseif (self::isList($v)) {
                    self::recordMessages($rec, $v);
                }
            }
        }
    }

    /** Wrap a framework entry point so its first argument, the principal's request, is recorded before it runs. */
    public static function withPrincipalInput(mixed $target, callable $fn): \Closure
    {
        return static function (mixed ...$args) use ($target, $fn): mixed {
            self::recordInput($target, $args[0] ?? null);
            return $fn(...$args);
        };
    }

    /**
     * Turn `['name' => ..., 'arguments' => ...]` into a PCActn using `$mapping(call): ['verb' => ..., 'resource' => ...]|null`; null when the mapping
     * declines the call (an unmapped tool). `$aud` signs for another audience than the handle's. No dry run here: an out-of-policy call still yields
     * a signed PCActn and is refused server-side. Returns `['encoded', 'pcactn', 'headers', 'provenance']`.
     * @param array<string,mixed> $call
     * @return array{encoded:string,pcactn:Obj,headers:array<string,string>,provenance:?Obj}|null
     */
    public static function bridgeToolCall(AgentHandle $agent, array $call, callable $mapping, ?string $aud = null): ?array
    {
        $m = $mapping($call);
        if (!is_array($m) || !isset($m['verb'], $m['resource'])) {
            return null;
        }
        $a = $agent->act($m['verb'], $m['resource'], $call['arguments'] ?? null, null, $aud);
        return ['encoded' => $a['encoded'], 'pcactn' => $a['pcactn'], 'headers' => $a['headers'], 'provenance' => $a['provenance']];
    }
}
