<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Explain.php';
require_once __DIR__ . '/Facade.php';
require_once __DIR__ . '/Adapters.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/ArgProvenance.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/StateStore.php';

/** A URL the WHATWG parser rejects (the reference's ERR_INVALID_URL). */
final class PcaUrlError extends \InvalidArgumentException
{
    public string $errorCode = 'ERR_INVALID_URL';
}

/** An in-memory per-holder state store (replay counter, budget): a drop-in budget store for tests. Nothing persists. */
final class TestStateStore
{
    /** @var array<string,mixed> */
    private array $m = [];

    public function get(string $key): mixed
    {
        return $this->m[$key] ?? null;
    }

    public function put(string $key, mixed $state): void
    {
        $this->m[$key] = $state;
    }
}

/**
 * Testing kit for Proof-Carrying Authority (the reference's pca-testing): the acceptance constants and request-to-operation route
 * mapping, a fake verifier that runs the REAL core verifier rooted at the PCActn's own grant, a tamper helper and an in-memory state
 * store. Nothing here authorizes anything. A grant lifted from the artifact is never trusted for a post-quantum root (no pin exists).
 * {@see runAdapterAcceptance} runs the per-adapter acceptance matrix through a harness for your own adapter.
 */
final class PcaTesting
{
    public const ADAPTER_ACCEPTANCE_AUDIENCE = 'payments-rs';
    private const NO_GRANT = 'fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant';
    private const SPECIAL = ['http', 'https', 'ftp', 'ws', 'wss', 'file'];

    /**
     * Mint a REAL agent handle with test defaults (testAgent): the genuine article (real signed grant, real `act` / `dryRun` / `subAgent`), so a PCActn it
     * builds verifies against {@see fakeVerify} out of the box. `$o` may carry permissions (default `stripe => [refund]`), limits (default `refund => $500/day`),
     * goal (`test`), aud (`ins_test`), principal and holder (a KeyPair each; fresh pairs when omitted).
     * @param array<string,mixed> $o
     */
    public static function testAgent(array $o = []): AgentHandle
    {
        return Facade::createAgent($o['principal'] ?? KeyPair::generate(), $o['goal'] ?? 'test', $o['permissions'] ?? ['stripe' => ['refund']],
            array_key_exists('limits', $o) ? $o['limits'] : ['refund' => '$500/day'], $o['holder'] ?? null, null, null, null, null, $o['aud'] ?? 'ins_test');
    }

    /**
     * Build a PCActn from `$a` for one action (makePCActn): `a->act(...)` reduced to the `pcactn` and its wire `encoded` pair. `counter` auto-increments per holder
     * when omitted.
     * @return array{pcactn:Obj,encoded:string}
     */
    public static function makePCActn(AgentHandle $a, string $verb, string $resource, mixed $params = null, ?int $counter = null, ?int $now = null): array
    {
        $r = $a->act($verb, $resource, $params, $counter, null, $now);
        return ['pcactn' => $r['pcactn'], 'encoded' => $r['encoded']];
    }

    /** The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches. */
    public static function adapterAcceptanceExpected(): Obj
    {
        $o = static fn(int $s, bool $ran, bool $bound): Obj => Obj::of(['status' => $s, 'handlerRan' => $ran, 'bound' => $bound]);
        $e = new Obj();
        foreach (['over_limit_predicate', 'over_limit_max_spend', 'body_differs', 'other_operation', 'escalate_unanswered', 'missing_revocation', 'missing_store'] as $k) {
            $e->set($k, $o(403, false, false));
        }
        $e->set('valid_first', $o(200, true, true));
        $e->set('replay_second', $o(403, false, false));
        return $e;
    }

    public static function memoryStateStore(): TestStateStore
    {
        return new TestStateStore();
    }

    // ---- fake verifier ----------------------------------------------------------------------------------------------------

    /** `pcactn.cap_chain[0]` as JavaScript reads it; throws where JavaScript would throw or find nothing. */
    private static function liftGrant(mixed $pcactn): mixed
    {
        if (!($pcactn instanceof Obj)) {
            throw new \InvalidArgumentException(self::NO_GRANT);
        }
        $chain = $pcactn->get('cap_chain');
        $first = null;
        if (is_array($chain) && array_is_list($chain) && $chain !== []) {
            $first = $chain[0];
        } elseif (is_string($chain) && $chain !== '') {
            $first = Explain::slice16($chain, 0, 1);
        } elseif ($chain instanceof Obj) {
            $first = $chain->get('0');
        }
        if (!Jsx::truthy($first ?? Jsx::$U)) {
            throw new \InvalidArgumentException(self::NO_GRANT);
        }
        return $first;
    }

    /**
     * Run the real core verifier against `$pcactn`, rooting the check at `opts.grant` or the PCActn's own chain root and defaulting
     * the verifier audience to the PCActn's own `aud` (omit `audience`; null opts out; a mismatching string forces the audience check
     * to fail). `opts.now` is epoch ms (wall clock when omitted). Throws when there is no grant to root at.
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     */
    public static function fakeVerify(mixed $pcactn, mixed $opts = null): array
    {
        $o = $opts instanceof Obj ? $opts : new Obj();
        $grant = $o->has('grant') ? $o->get('grant') : null;
        $root = $grant ?? self::liftGrant($pcactn);
        $lifted = $grant === null;
        $hasAud = $o->has('audience');
        $audience = $hasAud ? $o->get('audience') : null;
        if ($hasAud && $audience !== null) {
            $aud = is_string($audience) ? $audience : "\0non-string audience";
        } else {
            if (!$hasAud && $pcactn === null) {
                throw new \InvalidArgumentException('fakeVerify: no PCActn');
            }
            $own = $pcactn instanceof Obj ? $pcactn->get('aud') : null;
            $aud = is_string($own) ? $own : null; // opt-out accepts the PCActn's own audience; a non-string one fails the wire check
        }
        if (!($root instanceof Obj)) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: the grant is not an object'];
        }
        if ($lifted && $root->has('alg') && $root->get('alg') !== 'ed25519') {
            return ['allow' => false, 'checks' => ['cap_chain' => false],
                'reason' => 'cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it'];
        }
        $now = $o->has('now') && $o->get('now') !== null ? (int)Js::num($o->get('now')) : (int)(microtime(true) * 1000);
        return Pca::verifyPcactnCore($pcactn, $root, $now, $aud, null, null, null, null, null, true);
    }

    /** Assert that `$pcactn` verifies: throws naming the failing checks and the reason, else returns the verdict. */
    public static function expectVerifies(mixed $pcactn, mixed $opts = null): array
    {
        $res = self::fakeVerify($pcactn, $opts);
        if (!$res['allow']) {
            $failing = [];
            foreach ($res['checks'] as $name => $ok) {
                if ($ok === false) {
                    $failing[] = (string)$name;
                }
            }
            throw new \RuntimeException(sprintf('expectVerifies: PCActn was denied. failing checks: [%s]%s', implode(', ', $failing), ($res['reason'] ?? '') !== '' ? ' — ' . $res['reason'] : ''));
        }
        return $res;
    }

    /** The inverse of expectVerifies: throws when `$pcactn` unexpectedly verifies. */
    public static function expectDenied(mixed $pcactn, mixed $opts = null): array
    {
        $res = self::fakeVerify($pcactn, $opts);
        if ($res['allow']) {
            throw new \RuntimeException('expectDenied: PCActn verified but was expected to be denied. checks: ' . json_encode($res['checks']));
        }
        return $res;
    }

    // ---- tampering --------------------------------------------------------------------------------------------------------

    private static function decodePcactn(string $s): Obj
    {
        if (strlen($s) > Pca::MAX_ARTIFACT_BYTES) { // FIRST: before any parsing
            throw new \InvalidArgumentException(Pca::ARTIFACT_SIZE_REASON);
        }
        $v = Json::parseStrict($s);
        if (!($v instanceof Obj)) {
            throw new \TypeError('decodePCActn: not an object');
        }
        return $v;
    }

    /** Apply one path mutation ({op: 'none'} | {op: 'set', path, value} | {op: 'delete', path}) to a copy of the record. */
    public static function applyMutation(Obj $rec, Obj $m): Obj
    {
        $op = $m->get('op');
        if ($op === 'none') {
            return $rec;
        }
        $path = $m->get('path');
        return self::applyAt($rec, array_values($path), 0, $op === 'set', $m->get('value'));
    }

    private static function applyAt(mixed $node, array $path, int $i, bool $set, mixed $value): mixed
    {
        $k = $path[$i];
        $last = $i === count($path) - 1;
        if ($node instanceof Obj) {
            $key = Js::str($k);
            $o = new Obj();
            foreach ($node->keys() as $n) {
                if ($n === $key && $last && !$set) {
                    continue; // delete
                }
                $o->set($n, $n === $key && !$last ? self::applyAt($node->get($n), $path, $i + 1, $set, $value) : ($n === $key && $last ? $value : $node->get($n)));
            }
            if (!$node->has($key)) {
                if (!$last) {
                    throw new \OutOfBoundsException("tamper: no member $key");
                }
                if ($set) {
                    $o->set($key, $value);
                }
            }
            return $o;
        }
        if (is_array($node) && array_is_list($node)) {
            $idx = (int)(Js::isNum($k) ? Js::num($k) : (float)Js::str($k));
            if ($idx < 0 || $idx >= count($node) + ($last && $set ? 1 : 0)) {
                throw new \OutOfBoundsException('tamper: index out of range');
            }
            $out = $node;
            if (!$last) {
                $out[$idx] = self::applyAt($node[$idx], $path, $i + 1, $set, $value);
            } else {
                $out[$idx] = $set ? $value : null; // a deleted array element is a hole: null once stringified
            }
            return $out;
        }
        throw new \TypeError('tamper: cannot descend into a scalar');
    }

    /**
     * Decode an encoded PCActn (strict profile, size-capped), let `$mutate` (a callable Obj -> Obj, or a mutation spec) corrupt it,
     * then re-encode it so a test can assert the corruption is caught. A change touching the signed body breaks `leaf_signature`.
     */
    public static function tamper(string $encoded, callable|Obj $mutate): string
    {
        $rec = self::decodePcactn($encoded);
        $rec = $mutate instanceof Obj ? self::applyMutation($rec, $mutate) : $mutate($rec);
        return Json::canonicalizeLenient(self::decodePcactn(Js::stringify($rec)));
    }

    // ---- request -> operation ---------------------------------------------------------------------------------------------

    private static function hostEmpty(string $rest): bool
    {
        $rest = ltrim($rest, '/');
        $end = strpos($rest, '/');
        return ($end === false ? $rest : substr($rest, 0, $end)) === '';
    }

    /**
     * The pathname of `$url` resolved against a base origin as a WHATWG URL parser yields it, for the shapes a request carries
     * (absolute and scheme-relative URLs, rooted and relative paths, dot segments, query, fragment). Throws where the parser rejects
     * the URL. shortcut: percent-encoding of the path is not reproduced (an encoded spelling never equals a route); upgrade if routes
     * ever contain non-ASCII.
     */
    private static function pathnameOf(string $url): string
    {
        $s = preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $url) ?? $url;
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        $cut = strcspn($s, '?#');
        $rest = substr($s, 0, $cut);
        if (preg_match('/\A([A-Za-z][A-Za-z0-9+.\-]*):/', $rest, $sm) === 1) {
            $scheme = strtolower($sm[1]);
            $rest = substr($rest, strlen($sm[0]));
            if (!in_array($scheme, self::SPECIAL, true)) {
                if (str_starts_with($rest, '//')) {
                    $end = strpos($rest, '/', 2);
                    $path = $end === false ? '' : substr($rest, $end);
                } elseif (str_starts_with($rest, '/')) {
                    $path = $rest;
                } else {
                    return $rest; // opaque path: never a route
                }
            } elseif ($scheme === 'file') {
                $rest = str_replace('\\', '/', $rest);
                if (str_starts_with($rest, '//')) {
                    $end = strpos($rest, '/', 2);
                    $path = $end === false ? '/' : substr($rest, $end);
                } else {
                    $path = str_starts_with($rest, '/') ? $rest : '/' . $rest;
                }
            } else {
                $rest = str_replace('\\', '/', $rest);
                if ($scheme === 'http' && !str_starts_with($rest, '//')) { // same scheme as the base: relative
                    $path = str_starts_with($rest, '/') ? $rest : '/' . $rest;
                } else {
                    if (self::hostEmpty($rest)) {
                        throw new PcaUrlError('Invalid URL');
                    }
                    $rest = ltrim($rest, '/');
                    $end = strpos($rest, '/');
                    $path = $end === false ? '/' : substr($rest, $end);
                }
            }
        } else {
            $rest = str_replace('\\', '/', $rest);
            if (str_starts_with($rest, '//')) {
                $t = ltrim(substr($rest, 2), '/');
                $end = strpos($t, '/');
                if (($end === false ? $t : substr($t, 0, $end)) === '') {
                    throw new PcaUrlError('Invalid URL');
                }
                $path = $end === false ? '/' : substr($t, $end);
            } else {
                $path = str_starts_with($rest, '/') ? $rest : '/' . $rest;
            }
        }
        if ($path === '') {
            return '';
        }
        $out = [];
        $segs = explode('/', substr($path, 1));
        foreach ($segs as $i => $seg) {
            $low = strtolower($seg);
            $last = $i === count($segs) - 1;
            if (in_array($low, ['..', '.%2e', '%2e.', '%2e%2e'], true)) {
                array_pop($out);
                if ($last) {
                    $out[] = '';
                }
            } elseif ($low === '.' || $low === '%2e') {
                if ($last) {
                    $out[] = '';
                }
            } else {
                $out[] = $seg;
            }
        }
        return '/' . implode('/', $out);
    }

    /**
     * The server's mapping from request to operation: a route table on method + path with the JSON body as params. `$req` is
     * {method, url, body}. Returns null for an unknown route or a body that is not an object, else {verb, resource, params}.
     */
    public static function acceptanceOperation(mixed $req): ?Obj
    {
        $url = $req instanceof Obj ? $req->get('url') : null;
        $path = is_string($url) ? self::pathnameOf($url) : '';
        $method = $req instanceof Obj ? $req->get('method') : null;
        $key = mb_strtoupper(Jsx::str($method)) . ' ' . $path;
        if ($key === 'POST /payments') {
            $verb = 'payments.send';
        } elseif ($key === 'POST /refunds') {
            $verb = 'payments.refund';
        } else {
            return null;
        }
        $body = $req->get('body');
        if (!($body instanceof Obj)) {
            return null;
        }
        return Obj::of(['verb' => $verb, 'resource' => 'payments', 'params' => $body]);
    }

    // ---- the acceptance matrix runner ---------------------------------------------------------------------------------------

    private static function fixture(string $limit): array
    {
        $principal = KeyPair::generate();
        $holder = KeyPair::generate();
        $where = in_array($limit, ['predicate', 'escalate'], true) ? [['field' => 'action.params.amount', 'op' => 'lte', 'value' => 100]] : [];
        $envelope = [
            'predicates' => [['verb' => ['payments.send', 'payments.refund'], 'resource' => 'payments', 'where' => $where]],
            'caveats' => [], 'agent_binding' => new Obj(),
            // "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
            'risk_policy' => ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0], 'theta1' => 1, 'theta2' => 1, 'kappa' => 100,
                'lambda' => 0, 'rho' => 0.5, 'bMax' => 1000000],
        ];
        if ($limit === 'escalate') { // a payment over 50 asks the principal; with no answer it is refused
            $envelope['tighten'] = [['id' => 'big_payment', 'when' => ['field' => 'action.params.amount', 'op' => 'gt', 'value' => 50], 'signal' => 'escalate']];
        }
        $grant = Sign::mintGrant($principal, $holder->public, $envelope, 'pay invoices')['grant'];
        if ($limit === 'max_spend') { // a ROOT caveat outside the envelope, enforced like a delegated one
            $grant = Sign::mintRoot($principal, $holder->public, array_merge($grant->get('caveats'), [Obj::of(['type' => 'max_spend', 'usd' => new Num('100')])]));
        }
        $recorder = static fn(): ProvenanceRecorder => new ProvenanceRecorder('adapter-acceptance', 'k1', new KeyPair(str_repeat("\x03", 32)));
        $counter = 0;
        $request = static function (array $signed, array $sent) use ($grant, $holder, $recorder, &$counter): array {
            $params = Obj::of(['payee' => 'acme', 'amount' => new Num((string)$signed['amount'])]);
            $node = ['id' => 'n1', 'verb' => $signed['verb'], 'resource' => 'payments', 'params_digest' => Pca::paramsDigest($params), 'reversibility_class' => 'irreversible'];
            $p = Sign::buildPcactn($grant, [$grant], [$node], 'n1', ++$counter, $holder, self::ADAPTER_ACCEPTANCE_AUDIENCE, $params);
            $prov = ArgProvenance::principalDirect($recorder(), Obj::of(['verb' => $signed['verb'], 'resource' => 'payments', 'params' => $params]));
            return ['method' => 'POST', 'path' => $sent['path'], 'headers' => Adapters::pcaHeaders(Json::canonicalizeNative($p), $prov) + ['content-type' => 'application/json'],
                'body' => Obj::of(['payee' => 'acme', 'amount' => new Num((string)$sent['amount'])])];
        };
        $options = static function (array $over = []) use ($grant, $recorder): array {
            $o = [
                'audience' => self::ADAPTER_ACCEPTANCE_AUDIENCE,
                'resolveGrant' => static fn($ref) => $ref === $grant->get('id') ? $grant : null,
                'stateStore' => new MemoryStateStore(),
                'isRevoked' => static fn() => false,
                'plan' => 'single-step',
                'hard' => ['risk' => static function (array $op, mixed $g, mixed $p): array {
                    $a = $op['params'] instanceof Obj ? Js::num($op['params']->get('amount')) : null;
                    return ['blastRadius' => min(1, (float)($a ?? 0) / 100), 'semanticDistance' => 0, 'reversibility' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];
                }],
                'provenanceMediators' => [$recorder()->pin],
            ];
            return array_merge($o, $over);
        };
        return ['request' => $request, 'options' => $options];
    }

    /**
     * Run the matrix through $harness and return the outcome per scenario (compare it with {@see adapterAcceptanceExpected}).
     *
     * `$harness(array $options)` builds the adapter ONCE from `$options` (the named arguments of {@see Authorize::authorize} minus the per-request ones:
     * pass them through unchanged) and returns `send(array $req)` for one request `['method', 'path', 'headers', 'body']`; `send` returns
     * `['status' => int, 'handlerRan' => bool, 'operation' => ?AuthorizedOperation]` (`operation` = the operation an allowed call attached). The adapter
     * derives the operation with {@see acceptanceOperation} (`method`, `url` = the path, `body`), takes the proof from the `PCA-Action` header and the
     * bundle from `PCA-Provenance`.
     */
    public static function runAdapterAcceptance(callable $harness): Obj
    {
        $out = new Obj();
        $settle = static function (array $req, array $o): Obj {
            $ran = self::acceptanceOperation(Obj::of(['method' => $req['method'], 'url' => $req['path'], 'body' => $req['body']]));
            $op = $o['operation'] ?? null;
            $bound = $op !== null && $ran !== null && Authorize::isAuthorizedFor(new AuthorizeResult(true, 200, operation: $op, decision: 'allow'), $ran);
            return Obj::of(['status' => new Num((string)$o['status']), 'handlerRan' => $o['handlerRan'], 'bound' => $bound]);
        };
        $sendOf = static fn(array $opts): callable => $harness($opts);
        $once = static function (string $name, array $f, array $req, array $over = []) use (&$out, $settle, $sendOf): void {
            $out->set($name, $settle($req, ($sendOf(($f['options'])($over)))($req)));
        };
        $pay = static fn(array $f, string $verb, int $signed, string $path, int $sent): array => ($f['request'])(['verb' => $verb, 'amount' => $signed], ['path' => $path, 'amount' => $sent]);
        $pred = self::fixture('predicate');
        $spend = self::fixture('max_spend');
        $esc = self::fixture('escalate');
        $once('over_limit_predicate', $pred, $pay($pred, 'payments.send', 400, '/payments', 400));
        $once('over_limit_max_spend', $spend, $pay($spend, 'payments.send', 400, '/payments', 400));
        $once('body_differs', $pred, $pay($pred, 'payments.send', 50, '/payments', 400));
        $once('other_operation', $pred, $pay($pred, 'payments.send', 50, '/refunds', 50));
        $once('escalate_unanswered', $esc, $pay($esc, 'payments.send', 70, '/payments', 70));
        $once('missing_revocation', $pred, $pay($pred, 'payments.send', 50, '/payments', 50), ['isRevoked' => null]);
        $once('missing_store', $pred, $pay($pred, 'payments.send', 50, '/payments', 50), ['stateStore' => null]);
        $send = $sendOf(($pred['options'])());
        $valid = $pay($pred, 'payments.send', 50, '/payments', 50);
        $out->set('valid_first', $settle($valid, $send($valid)));
        $out->set('replay_second', $settle($valid, $send($valid)));
        return $out;
    }
}
