<?php

declare(strict_types=1);

namespace Atlas\Pca;

/** A syntax error of the authoring-file YAML text layer (1-based line and column of the offending place). */
final class ActionsYamlError extends \RuntimeException
{
    public function __construct(string $message, public readonly int $yamlLine = 1, public readonly int $yamlColumn = 1)
    {
        parent::__construct($message);
    }
}

/**
 * A parsed node: kind 'scalar' | 'map' | 'seq', the resolved value of a scalar (null, bool, string, Num, or a raw float for NaN and the
 * infinities), the children (seq: nodes; map: [key node, value node] pairs) and the 1-based start position.
 */
final class YamlNode
{
    /** @var list<mixed> */
    public array $items = [];
    public mixed $value = null;
    public bool $quoted = false;

    public function __construct(public string $kind, public int $line, public int $col)
    {
    }
}

/**
 * YAML text for the authoring-file loader (loadActionsText). The syntax layer is libyaml (the parser Ruby's Psych uses) over ext-ffi: its
 * EVENT API only (yaml_parser_parse), never a library resolver. Everything the reference decides about meaning is done here: the tree is
 * built from events, plain scalars are resolved with the YAML 1.2 core schema (null, bool, int, 0o / 0x, float, .inf, .nan; everything else
 * a string), mapping keys are stringified the way JavaScript does, aliases are refused, `<<` is an ordinary key, and positions are the
 * 1-based start marks of the events (columns count characters).
 *
 * Where this differs from the reference it is STRICTER (it refuses), exactly as the Python and Ruby loaders do: an explicit tag other than
 * !!str / !!map / !!seq, a complex (non-scalar) mapping key, two keys that are equal once stringified, a bare carriage return used as a
 * line break, an alias, more than one document. Anchors are accepted (they only matter to aliases). Syntax error wording and the position
 * of a syntax error are libyaml's own. A missing ext-ffi / libyaml is a RuntimeException (never a silent fallback).
 */
final class ActionsYamlLoad
{
    private const MAX_DEPTH = 1000;
    private const SAFE = 9007199254740992;
    private const STR = 'tag:yaml.org,2002:str';
    private const OK_TAGS = [self::STR, 'tag:yaml.org,2002:map', 'tag:yaml.org,2002:seq'];
    // yaml_event_type_t
    private const E_STREAM_END = 2;
    private const E_DOC_START = 3;
    private const E_DOC_END = 4;
    private const E_ALIAS = 5;
    private const E_SCALAR = 6;
    private const E_SEQ_START = 7;
    private const E_SEQ_END = 8;
    private const E_MAP_START = 9;
    private const E_MAP_END = 10;
    private const STYLE_PLAIN = 1; // YAML_PLAIN_SCALAR_STYLE

    /**
     * The yaml.h layouts (libyaml 0.2.x) for the parts read here; the C compiler-equivalent layout is computed by FFI. The parser struct is
     * opaque past its error block: it is allocated with room to spare (sizeof is under 1 KiB) and only passed by pointer.
     */
    private const CDEF = <<<'CDEF'
        typedef struct { size_t index; size_t line; size_t column; } yaml_mark_t;
        typedef struct yaml_event_s {
            int type;
            union {
                struct { int encoding; } stream_start;
                struct { void *version_directive; struct { void *start; void *end; } tag_directives; int implicit; } document_start;
                struct { int implicit; } document_end;
                struct { char *anchor; } alias;
                struct { char *anchor; char *tag; char *value; size_t length; int plain_implicit; int quoted_implicit; int style; } scalar;
                struct { char *anchor; char *tag; int implicit; int style; } sequence_start;
                struct { char *anchor; char *tag; int implicit; int style; } mapping_start;
            } data;
            yaml_mark_t start_mark;
            yaml_mark_t end_mark;
        } yaml_event_t;
        typedef struct {
            int error;
            const char *problem;
            size_t problem_offset;
            int problem_value;
            yaml_mark_t problem_mark;
            const char *context;
            yaml_mark_t context_mark;
            char rest[8192];
        } yaml_parser_alloc_t;
        int yaml_parser_initialize(void *parser);
        void yaml_parser_delete(void *parser);
        void yaml_parser_set_input_string(void *parser, const char *input, size_t size);
        int yaml_parser_parse(void *parser, yaml_event_t *event);
        void yaml_event_delete(yaml_event_t *event);
        CDEF;

    private static ?\FFI $ffi = null;

    private static function ffi(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (!extension_loaded('FFI')) {
            throw new \RuntimeException('YAML needs ext-ffi and libyaml (apt install libyaml-dev / brew install libyaml)');
        }
        $names = [];
        $env = getenv('ATLAS_PCA_LIBYAML');
        if (is_string($env) && $env !== '') {
            $names[] = $env;
        }
        foreach (['libyaml-0.so.2', 'libyaml.so.2', 'libyaml-0.2.dylib', 'libyaml.dylib', '/opt/homebrew/lib/libyaml.dylib', '/usr/local/lib/libyaml.dylib', 'yaml.dll', 'libyaml-0-2.dll'] as $n) {
            $names[] = $n;
        }
        foreach ($names as $n) {
            try {
                return self::$ffi = \FFI::cdef(self::CDEF, $n);
            } catch (\Throwable) {
                // next candidate
            }
        }
        throw new \RuntimeException('YAML needs libyaml (apt install libyaml-dev / brew install libyaml)');
    }

    /**
     * The libyaml event stream of `$text`: list of [type, tag|null, value|null, style, line, column] (1-based line and column).
     * @return list<array{0:int,1:?string,2:?string,3:int,4:int,5:int}>
     * @throws ActionsYamlError on a syntax error
     */
    private static function events(string $text): array
    {
        $f = self::ffi();
        $n = strlen($text);
        $buf = $f->new('char[' . ($n + 1) . ']'); // owned by us: the parser keeps the pointer until it is deleted
        if ($n > 0) {
            \FFI::memcpy($buf, $text, $n);
        }
        $parser = $f->new('yaml_parser_alloc_t');
        $pp = \FFI::addr($parser);
        if ($f->yaml_parser_initialize($pp) !== 1) {
            throw new \RuntimeException('libyaml: parser initialisation failed');
        }
        $ev = $f->new('yaml_event_t');
        $ep = \FFI::addr($ev);
        $out = [];
        try {
            $f->yaml_parser_set_input_string($pp, $buf, $n);
            while (true) {
                if ($f->yaml_parser_parse($pp, $ep) !== 1) {
                    $p = $parser->problem;
                    $msg = self::cstr($p) ?? 'syntax error'; // a const char* field reads as a PHP string, a char* one as a pointer
                    throw new ActionsYamlError($msg, (int)$parser->problem_mark->line + 1, (int)$parser->problem_mark->column + 1);
                }
                $type = (int)$ev->type;
                $line = (int)$ev->start_mark->line + 1;
                $col = (int)$ev->start_mark->column + 1;
                $tag = null;
                $value = null;
                $style = 0;
                if ($type === self::E_SCALAR) {
                    $s = $ev->data->scalar;
                    $len = (int)$s->length;
                    $value = $len === 0 ? '' : \FFI::string($s->value, $len);
                    $tag = self::cstr($s->tag);
                    $style = (int)$s->style;
                } elseif ($type === self::E_SEQ_START) {
                    $tag = self::cstr($ev->data->sequence_start->tag);
                } elseif ($type === self::E_MAP_START) {
                    $tag = self::cstr($ev->data->mapping_start->tag);
                }
                $f->yaml_event_delete($ep);
                if ($type === self::E_STREAM_END) {
                    return $out;
                }
                $out[] = [$type, $tag, $value, $style, $line, $col];
            }
        } finally {
            $f->yaml_event_delete($ep); // a no-op on an already deleted (zeroed) event
            $f->yaml_parser_delete($pp);
        }
    }

    private static function cstr(mixed $p): ?string
    {
        return is_string($p) ? $p : ($p === null || \FFI::isNull($p) ? null : \FFI::string($p));
    }

    /**
     * The one document of `$text` as a node tree (null for an empty stream). `$strict` (YAML files) refuses duplicate keys; JSON text is
     * parsed leniently because only its positions are used.
     * @throws ActionsYamlError
     */
    public static function parseDocument(string $text, bool $strict = true): ?YamlNode
    {
        if (preg_match('/\r(?!\n)/', $text) === 1) {
            throw new ActionsYamlError('bare carriage return is not accepted as a line break');
        }
        if (str_starts_with($text, "\xEF\xBB\xBF")) {
            $text = substr($text, 3); // a byte order mark is not content
        }
        $events = self::events($text);
        $pos = 0;
        $docs = 0;
        $root = null;
        $count = count($events);
        while ($pos < $count) {
            if ($events[$pos][0] === self::E_DOC_START) {
                if (++$docs > 1) {
                    throw new ActionsYamlError('Source contains multiple documents; please use YAML.parseAllDocuments()');
                }
                $pos++;
                if ($events[$pos][0] !== self::E_DOC_END) {
                    $root = self::node($events, $pos, $strict, 0);
                }
            } else {
                $pos++;
            }
        }
        return $root;
    }

    /** @param list<array{0:int,1:?string,2:?string,3:int,4:int,5:int}> $ev */
    private static function node(array $ev, int &$pos, bool $strict, int $depth): YamlNode
    {
        [$type, $tag, $value, $style, $line, $col] = $ev[$pos++];
        if ($depth > self::MAX_DEPTH) {
            throw new ActionsYamlError('nesting is too deep', $line, $col);
        }
        if ($type === self::E_ALIAS) {
            throw new ActionsYamlError('Alias resolution is disabled', $line, $col);
        }
        if ($tag !== null && !in_array($tag, self::OK_TAGS, true)) {
            throw new ActionsYamlError("Unresolved or unsupported tag: $tag", $line, $col);
        }
        if ($type === self::E_SCALAR) {
            $n = new YamlNode('scalar', $line, $col);
            $n->quoted = !($style === self::STYLE_PLAIN && $tag === null);
            $n->value = $n->quoted ? $value : self::resolve((string)$value);
            return $n;
        }
        if ($type === self::E_SEQ_START) {
            $n = new YamlNode('seq', $line, $col);
            while ($ev[$pos][0] !== self::E_SEQ_END) {
                $n->items[] = self::node($ev, $pos, $strict, $depth + 1);
            }
            $pos++;
            return $n;
        }
        if ($type === self::E_MAP_START) {
            $n = new YamlNode('map', $line, $col);
            $seen = [];
            while ($ev[$pos][0] !== self::E_MAP_END) {
                $key = self::node($ev, $pos, $strict, $depth + 1);
                $val = self::node($ev, $pos, $strict, $depth + 1);
                if ($strict) {
                    if ($key->kind !== 'scalar') {
                        throw new ActionsYamlError('complex mapping keys are not accepted', $key->line, $key->col);
                    }
                    $s = self::jsKey($key->value);
                    if (isset($seen[$s])) {
                        throw new ActionsYamlError('Map keys must be unique', $key->line, $key->col);
                    }
                    $seen[$s] = true;
                }
                $n->items[] = [$key, $val];
            }
            $pos++;
            return $n;
        }
        throw new ActionsYamlError("unexpected parser event $type", $line, $col);
    }

    /** The value of a node tree in the package JSON model (Obj, list, string, Num, bool, null; NaN and the infinities as floats). */
    public static function toValue(?YamlNode $n): mixed
    {
        if ($n === null) {
            return null;
        }
        if ($n->kind === 'scalar') {
            return $n->value;
        }
        if ($n->kind === 'seq') {
            return array_map(static fn(mixed $x): mixed => self::toValue($x), $n->items);
        }
        $o = new Obj();
        foreach ($n->items as [$k, $v]) {
            $o->set(self::jsKey($k->value), self::toValue($v));
        }
        return $o;
    }

    /** JavaScript's String(key) of a resolved scalar. */
    public static function jsKey(mixed $v): string
    {
        return is_string($v) ? $v : IntentWb::jsStr($v);
    }

    // ---- scalars: the YAML 1.2 core schema --------------------------------------------------------------------------------

    /** The core schema value of a plain scalar, as the JavaScript number / boolean / null / string the reference sees. */
    public static function resolve(string $t): mixed
    {
        if ($t === '' || $t === '~' || $t === 'null' || $t === 'Null' || $t === 'NULL') {
            return null;
        }
        if ($t === 'true' || $t === 'True' || $t === 'TRUE') {
            return true;
        }
        if ($t === 'false' || $t === 'False' || $t === 'FALSE') {
            return false;
        }
        if (preg_match('/\A[-+]?[0-9]+\z/', $t) === 1) {
            return self::intNum($t[0] === '-', ltrim(ltrim($t, '+-'), '0'), $t);
        }
        if (preg_match('/\A0o[0-7]+\z/', $t) === 1) {
            return self::radix(octdec(substr($t, 2)));
        }
        if (preg_match('/\A0x[0-9a-fA-F]+\z/', $t) === 1) {
            return self::radix(hexdec(substr($t, 2)));
        }
        if (preg_match('/\A[-+]?\.(?:inf|Inf|INF)\z/', $t) === 1) {
            return $t[0] === '-' ? -INF : INF;
        }
        if (preg_match('/\A\.(?:nan|NaN|NAN)\z/', $t) === 1) {
            return NAN;
        }
        if (preg_match('/\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z/', $t) === 1) {
            $f = (float)$t;
            if (is_infinite($f)) {
                return $f;
            }
            if ($f === 0.0 && str_starts_with(ltrim($t, '+'), '-')) {
                return new Num('-0');
            }
            if (floor($f) === $f && abs($f) <= (float)self::SAFE) {
                return new Num((string)(int)$f);
            }
            return new Num(IntentWb::jsNumStr($f));
        }
        return $t;
    }

    /** A decimal integer: an exact lexeme up to 2^53, the binary64 form beyond; -0 stays negative zero. */
    private static function intNum(bool $neg, string $digits, string $text): Num
    {
        if ($digits === '') {
            return new Num($neg ? '-0' : '0');
        }
        if (strlen($digits) < 16 || (strlen($digits) === 16 && strcmp($digits, '9007199254740992') <= 0)) {
            return new Num(($neg ? '-' : '') . $digits);
        }
        return new Num(IntentWb::jsNumStr((float)$text));
    }

    private static function radix(int|float $n): Num
    {
        return is_int($n) && $n <= self::SAFE ? new Num((string)$n) : new Num(IntentWb::jsNumStr((float)$n));
    }

    // ---- positions of an authoring document ---------------------------------------------------------------------------------

    /**
     * Per-entry positions of an authoring document (the `actions` items and their `params` keys), by entry index; null when the root is
     * not a mapping. Each entry is [line, column, list of [param name, line, column]].
     * @return list<array{0:int,1:int,2:list<array{0:string,1:int,2:int}>}>|null
     */
    public static function positionsOf(?YamlNode $root): ?array
    {
        if ($root === null || $root->kind !== 'map') {
            return null;
        }
        $actions = null;
        foreach ($root->items as [$k, $v]) {
            if ($k->kind === 'scalar' && $k->value === 'actions') {
                $actions = $v;
            }
        }
        $items = $actions !== null && $actions->kind === 'seq' ? $actions->items : [$root];
        $out = [];
        foreach ($items as $it) {
            $params = [];
            if ($it->kind === 'map') {
                $pm = null;
                foreach ($it->items as [$k, $v]) {
                    if ($k->kind === 'scalar' && $k->value === 'params') {
                        $pm = $v;
                    }
                }
                if ($pm !== null && $pm->kind === 'map') {
                    foreach ($pm->items as [$k, $_]) {
                        if ($k->kind === 'scalar') {
                            $params[] = [$k->value === null ? '' : self::jsKey($k->value), $k->line, $k->col];
                        }
                    }
                }
            }
            $out[] = [$it->line, $it->col, $params];
        }
        return $out;
    }
}
