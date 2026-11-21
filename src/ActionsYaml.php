<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The YAML text the reference writes for an action pack (defsToYaml): a line-for-line port of the default stringifier of the `yaml` package
 * (v2, core schema, 80 columns): plain, quoted and block scalars, folding, escapes, anchors and aliases for repeated containers.
 *
 * Strings are processed as UTF-16 code units (an astral character is two surrogate characters) because the reference measures and folds in
 * code units. A "unit string" below is a UTF-8 string where every code unit is one character (a surrogate is its 3-byte form), so a pair is
 * recombined only at the end; all patterns run bytewise. Values are the package JSON model (Obj, list arrays, string, bool, Num/int/float, null);
 * a container reachable twice must be an Obj or a YamlSeq (arrays have no identity) to become an anchor and its aliases.
 * Comments, tags, flow collections and custom schemas are not produced for plain data and are not ported.
 */
final class ActionsYaml
{
    private const LINE_WIDTH = 80;
    private const MIN_CONTENT_WIDTH = 20;
    private const DQ_MIN_MULTILINE = 40;
    private const INDENT_STEP = '  ';
    private const PLAIN_BAD = '/\A[\n\t ,\[\]{}#&*!|>\'"%@`]|\A[?-]\z|\A[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]\z/';
    private const TAG_TESTS = ['(?:~|[Nn]ull|NULL)?', '(?:[Tt]rue|TRUE|[Ff]alse|FALSE)', '0o[0-7]+', '[-+]?[0-9]+', '0x[0-9a-fA-F]+',
        '(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)', '[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+', '[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)'];
    private const DOC_MARKER = '/(?:\A|(?<=[\n\r]|\xE2\x80[\xA8\xA9]))(?:%|---|\.\.\.)/';
    private const CONTROL = '/[\x00-\x08\x0b-\x1f\x7f]|\xC2[\x80-\x9F]/';

    // ---- UTF-16 code unit domain ----------------------------------------------------------------------------------------

    private static function enc3(int $c): string
    {
        return chr(0xE0 | ($c >> 12)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F));
    }

    private static function toUnits(string $s): string
    {
        if (preg_match('/[\xF0-\xF7]/', $s) !== 1) {
            return $s;
        }
        return (string)preg_replace_callback('/[\xF0-\xF7][\x80-\xBF]{3}/', function (array $m): string {
            $o = mb_ord($m[0], 'UTF-8') - 0x10000;
            return self::enc3(0xD800 + ($o >> 10)) . self::enc3(0xDC00 + ($o & 0x3FF));
        }, $s);
    }

    private static function fromUnits(string $s): string
    {
        return (string)preg_replace_callback('/\xED[\xA0-\xAF][\x80-\xBF]\xED[\xB0-\xBF][\x80-\xBF]/', function (array $m): string {
            $hi = ((ord($m[0][0]) & 0x0F) << 12) | ((ord($m[0][1]) & 0x3F) << 6) | (ord($m[0][2]) & 0x3F);
            $lo = ((ord($m[0][3]) & 0x0F) << 12) | ((ord($m[0][4]) & 0x3F) << 6) | (ord($m[0][5]) & 0x3F);
            return (string)mb_chr(0x10000 + (($hi - 0xD800) << 10) + ($lo - 0xDC00), 'UTF-8');
        }, $s);
    }

    /** @return list<string> the code units of a unit string, one entry each */
    private static function ucs(string $s): array
    {
        preg_match_all('/[\x00-\x7F]|[\xC0-\xFF][\x80-\xBF]*/', $s, $m);
        return $m[0];
    }

    private static function ulen(string $s): int
    {
        return (int)preg_match_all('/[^\x80-\xBF]/', $s);
    }

    private static function cp(string $ch): int
    {
        $n = strlen($ch);
        $b = ord($ch[0]);
        if ($n === 1) {
            return $b;
        }
        if ($n === 2) {
            return (($b & 0x1F) << 6) | (ord($ch[1]) & 0x3F);
        }
        return (($b & 0x0F) << 12) | ((ord($ch[1]) & 0x3F) << 6) | (ord($ch[2]) & 0x3F);
    }

    /** Python slice a:b over a unit array, as text. */
    private static function sl(array $cs, int $a, ?int $b = null): string
    {
        $n = count($cs);
        $b ??= $n;
        $a = $a < 0 ? max(0, $n + $a) : min($a, $n);
        $b = $b < 0 ? max(0, $n + $b) : min($b, $n);
        return $a >= $b ? '' : implode('', array_slice($cs, $a, $b - $a));
    }

    private static function at(array $cs, int $i): string
    {
        return $i >= 0 && $i < count($cs) ? $cs[$i] : '';
    }

    /** JSON.stringify of a string in the code unit domain (well-formed: lone surrogates are escaped). */
    private static function jsonString(string $s): string
    {
        $cs = self::ucs($s);
        $n = count($cs);
        $out = ['"'];
        foreach ($cs as $i => $c) {
            $o = self::cp($c);
            if ($c === '"') {
                $out[] = '\\"';
            } elseif ($c === '\\') {
                $out[] = '\\\\';
            } elseif ($c === "\x08") {
                $out[] = '\\b';
            } elseif ($c === "\x0c") {
                $out[] = '\\f';
            } elseif ($c === "\n") {
                $out[] = '\\n';
            } elseif ($c === "\r") {
                $out[] = '\\r';
            } elseif ($c === "\t") {
                $out[] = '\\t';
            } elseif ($o < 0x20) {
                $out[] = sprintf('\\u%04x', $o);
            } elseif ($o >= 0xD800 && $o <= 0xDBFF && $i + 1 < $n && self::cp($cs[$i + 1]) >= 0xDC00 && self::cp($cs[$i + 1]) <= 0xDFFF) {
                $out[] = $c;
            } elseif ($o >= 0xDC00 && $o <= 0xDFFF && $i > 0 && self::cp($cs[$i - 1]) >= 0xD800 && self::cp($cs[$i - 1]) <= 0xDBFF) {
                $out[] = $c;
            } elseif ($o >= 0xD800 && $o <= 0xDFFF) {
                $out[] = sprintf('\\u%04x', $o);
            } else {
                $out[] = $c;
            }
        }
        $out[] = '"';
        return implode('', $out);
    }

    // ---- folding --------------------------------------------------------------------------------------------------------

    private static function consumeMoreIndented(array $t, int $i, int $indent): int
    {
        $end = $i;
        $start = $i + 1;
        $ch = self::at($t, $start);
        while ($ch === ' ' || $ch === "\t") {
            if ($i < $start + $indent) {
                $i++;
                $ch = self::at($t, $i);
            } else {
                do {
                    $i++;
                    $ch = self::at($t, $i);
                } while ($ch !== '' && $ch !== "\n");
                $end = $i;
                $start = $i + 1;
                $ch = self::at($t, $start);
            }
        }
        return $end;
    }

    private static function fold(string $text, string $indent, string $mode, ?int $indentAtStart, ?\Closure $onOverflow = null): string
    {
        $lineWidth = self::LINE_WIDTH;
        $minContent = self::MIN_CONTENT_WIDTH;
        if ($minContent > $lineWidth) {
            $minContent = 0;
        }
        $t = self::ucs($text);
        $n = count($t);
        $il = self::ulen($indent);
        $endStep = max(1 + $minContent, 1 + $lineWidth - $il);
        if ($n <= $endStep) {
            return $text;
        }
        $folds = [];
        $escaped = [];
        $end = $lineWidth - $il;
        if ($indentAtStart !== null) {
            if ($indentAtStart > $lineWidth - max(2, $minContent)) {
                $folds[] = 0;
            } else {
                $end = $lineWidth - $indentAtStart;
            }
        }
        $split = null;
        $prev = '';
        $overflow = false;
        $i = -1;
        $escStart = -1;
        $escEnd = -1;
        if ($mode === 'block') {
            $i = self::consumeMoreIndented($t, $i, $il);
            if ($i !== -1) {
                $end = $i + $endStep;
            }
        }
        while (true) {
            $i++;
            $ch = self::at($t, $i);
            if ($ch === '') {
                break;
            }
            if ($mode === 'quoted' && $ch === '\\') {
                $escStart = $i;
                $nxt = self::at($t, $i + 1);
                $i += $nxt === 'x' ? 3 : ($nxt === 'u' ? 5 : ($nxt === 'U' ? 9 : 1));
                $escEnd = $i;
            }
            if ($ch === "\n") {
                if ($mode === 'block') {
                    $i = self::consumeMoreIndented($t, $i, $il);
                }
                $end = $i + $il + $endStep;
                $split = null;
            } else {
                if ($ch === ' ' && $prev !== '' && strpos(" \n\t", $prev) === false) {
                    $nxt = self::at($t, $i + 1);
                    if ($nxt !== '' && strpos(" \n\t", $nxt) === false) {
                        $split = $i;
                    }
                }
                if ($i >= $end) {
                    if ($split !== null) {
                        $folds[] = $split;
                        $end = $split + $endStep;
                        $split = null;
                    } elseif ($mode === 'quoted') {
                        while ($prev === ' ' || $prev === "\t") {
                            $prev = $ch;
                            $i++;
                            $ch = self::at($t, $i);
                            $overflow = true;
                        }
                        $j = $i > $escEnd + 1 ? $i - 2 : $escStart - 1;
                        if (!empty($escaped[$j])) {
                            return $text;
                        }
                        $folds[] = $j;
                        $escaped[$j] = true;
                        $end = $j + $endStep;
                        $split = null;
                    } else {
                        $overflow = true;
                    }
                }
            }
            $prev = $ch;
        }
        if ($overflow && $onOverflow !== null) {
            $onOverflow();
        }
        if (!$folds) {
            return $text;
        }
        $res = self::sl($t, 0, $folds[0]);
        foreach ($folds as $k => $fold) {
            $nxtFold = $folds[$k + 1] ?? 0;
            $stop = $nxtFold ? $nxtFold : $n;
            if ($fold === 0) {
                $res = "\n" . $indent . self::sl($t, 0, $stop);
            } else {
                if ($mode === 'quoted' && !empty($escaped[$fold])) {
                    $res .= ($fold >= 0 && $fold < $n ? $t[$fold] : '') . '\\';
                }
                $res .= "\n" . $indent . self::sl($t, $fold + 1, $stop);
            }
        }
        return $res;
    }

    // ---- strings --------------------------------------------------------------------------------------------------------

    private static function containsDocMarker(string $s): bool
    {
        return preg_match(self::DOC_MARKER, $s) === 1;
    }

    private static function lineLenOver(string $s, int $lineWidth, int $indentLen): bool
    {
        if (!$lineWidth || $lineWidth < 0) {
            return false;
        }
        $limit = $lineWidth - $indentLen;
        $cs = self::ucs($s);
        $n = count($cs);
        if ($n <= $limit) {
            return false;
        }
        $start = 0;
        for ($i = 0; $i < $n; $i++) {
            if ($cs[$i] === "\n") {
                if ($i - $start > $limit) {
                    return true;
                }
                $start = $i + 1;
                if ($n - $start <= $limit) {
                    return false;
                }
            }
        }
        return true;
    }

    private static function doubleQuoted(string $value, YCtx $ctx): string
    {
        $js = self::jsonString($value);
        $implicit = $ctx->implicitKey;
        $indent = $ctx->indent !== '' ? $ctx->indent : (self::containsDocMarker($value) ? '  ' : '');
        $c = self::ucs($js);
        $n = count($c);
        $out = '';
        $start = 0;
        $i = 0;
        $esc = ['0000' => '\\0', '0007' => '\\a', '000b' => '\\v', '001b' => '\\e', '0085' => '\\N', '00a0' => '\\_', '2028' => '\\L', '2029' => '\\P'];
        while ($i < $n) {
            $ch = $c[$i];
            if ($ch === ' ' && self::at($c, $i + 1) === '\\' && self::at($c, $i + 2) === 'n') {
                $out .= self::sl($c, $start, $i) . '\\ ';
                $i++;
                $start = $i;
                $ch = '\\';
            }
            if ($ch === '\\') {
                $nx = self::at($c, $i + 1);
                if ($nx === 'u') {
                    $out .= self::sl($c, $start, $i);
                    $code = self::sl($c, $i + 2, $i + 6);
                    if (isset($esc[$code])) {
                        $out .= $esc[$code];
                    } elseif (substr($code, 0, 2) === '00') {
                        $out .= '\\x' . substr($code, 2);
                    } else {
                        $out .= self::sl($c, $i, $i + 6);
                    }
                    $i += 5;
                    $start = $i + 1;
                } elseif ($nx === 'n') {
                    if ($implicit || self::at($c, $i + 2) === '"' || $n < self::DQ_MIN_MULTILINE) {
                        $i++;
                    } else {
                        $out .= self::sl($c, $start, $i) . "\n\n";
                        while (self::at($c, $i + 2) === '\\' && self::at($c, $i + 3) === 'n' && self::at($c, $i + 4) !== '"') {
                            $out .= "\n";
                            $i += 2;
                        }
                        $out .= $indent;
                        if (self::at($c, $i + 2) === ' ') {
                            $out .= '\\';
                        }
                        $i++;
                        $start = $i + 1;
                    }
                } else {
                    $i++;
                }
            }
            $i++;
        }
        $out = $start ? $out . self::sl($c, $start) : $js;
        return $implicit ? $out : self::fold($out, $indent, 'quoted', $ctx->indentAtStart);
    }

    private static function singleQuoted(string $value, YCtx $ctx): string
    {
        if (($ctx->implicitKey && str_contains($value, "\n")) || preg_match('/[ \t]\n|\n[ \t]/', $value) === 1) {
            return self::doubleQuoted($value, $ctx);
        }
        $indent = $ctx->indent !== '' ? $ctx->indent : (self::containsDocMarker($value) ? '  ' : '');
        $res = "'" . preg_replace_callback('/\n+/', fn(array $m) => $m[0] . "\n" . $indent, str_replace("'", "''", $value)) . "'";
        return $ctx->implicitKey ? $res : self::fold($res, $indent, 'flow', $ctx->indentAtStart);
    }

    private static function quoted(string $value, YCtx $ctx): string
    {
        $hasD = str_contains($value, '"');
        $hasS = str_contains($value, "'");
        if ($hasD && !$hasS) {
            return self::singleQuoted($value, $ctx);
        }
        return self::doubleQuoted($value, $ctx);   // a lone single quote, both or neither: double (the default)
    }

    private static function blockString(string $value, YCtx $ctx): string
    {
        if (preg_match('/\n[\t ]+\z/', $value) === 1) {
            return self::quoted($value, $ctx);
        }
        $indent = $ctx->indent !== '' ? $ctx->indent : (($ctx->forceBlockIndent || self::containsDocMarker($value)) ? '  ' : '');
        $literal = !self::lineLenOver($value, self::LINE_WIDTH, strlen($indent));
        if ($value === '') {
            return $literal ? "|\n" : ">\n";
        }
        $endStart = strlen($value);
        while ($endStart > 0 && strpos("\n\t ", $value[$endStart - 1]) !== false) {
            $endStart--;
        }
        $end = substr($value, $endStart);
        $nl = strpos($end, "\n");
        if ($nl === false) {
            $chomp = '-';
        } elseif ($value === $end || $nl !== strlen($end) - 1) {
            $chomp = '+';
        } else {
            $chomp = '';
        }
        if ($end !== '') {
            $value = substr($value, 0, strlen($value) - strlen($end));
            if (substr($end, -1) === "\n") {
                $end = substr($end, 0, -1);
            }
            $end = (string)preg_replace_callback('/(\A|(?<!\n))\n+(?!\n|\z)/', fn(array $m) => $m[0] . $indent, $end);
        }
        $startWithSpace = false;
        $startEnd = 0;
        $startNl = -1;
        $vl = strlen($value);
        while ($startEnd < $vl) {
            $ch = $value[$startEnd];
            if ($ch === ' ') {
                $startWithSpace = true;
            } elseif ($ch === "\n") {
                $startNl = $startEnd;
            } else {
                break;
            }
            $startEnd++;
        }
        $start = substr($value, 0, $startNl < $startEnd ? $startNl + 1 : $startEnd);
        if ($start !== '') {
            $value = substr($value, strlen($start));
            $start = (string)preg_replace_callback('/\n+/', fn(array $m) => $m[0] . $indent, $start);
        }
        $header = $startWithSpace ? ($indent !== '' ? '2' : '1') : '';
        $header .= $chomp;
        if (!$literal) {
            $folded = (string)preg_replace_callback('/\n+/', fn(array $m) => "\n" . $m[0], $value);
            $folded = (string)preg_replace_callback('/(?:\A|\n)([\t ](?:[^\n\r\xE2]|\xE2(?!\x80[\xA8\xA9]))*)(?:([\n\t ]*)\n(?![\n\t ]))?/',
                fn(array $m) => $m[1] . ($m[2] ?? ''), $folded);
            $folded = (string)preg_replace_callback('/\n+/', fn(array $m) => $m[0] . $indent, $folded);
            $fell = false;
            $body = self::fold($start . $folded . $end, $indent, 'block', self::ulen($ctx->indent), function () use (&$fell): void {
                $fell = true;
            });
            if (!$fell) {
                return '>' . $header . "\n" . $indent . $body;
            }
        }
        $value = (string)preg_replace_callback('/\n+/', fn(array $m) => $m[0] . $indent, $value);
        return '|' . $header . "\n" . $indent . $start . $value . $end;
    }

    private static function plain(string $value, YCtx $ctx): string
    {
        if ($ctx->implicitKey && str_contains($value, "\n")) {
            return self::quoted($value, $ctx);
        }
        if (preg_match(self::PLAIN_BAD, $value) === 1) {
            return ($ctx->implicitKey || !str_contains($value, "\n")) ? self::quoted($value, $ctx) : self::blockString($value, $ctx);
        }
        if (!$ctx->implicitKey && str_contains($value, "\n")) {
            return self::blockString($value, $ctx);
        }
        if (self::containsDocMarker($value)) {
            if ($ctx->indent === '') {
                $ctx->forceBlockIndent = true;
                return self::blockString($value, $ctx);
            }
            if ($ctx->implicitKey && $ctx->indent === self::INDENT_STEP) {
                return self::quoted($value, $ctx);
            }
        }
        $s = (string)preg_replace_callback('/\n+/', fn(array $m) => $m[0] . "\n" . $ctx->indent, $value);
        if ($ctx->actualString) {
            foreach (self::TAG_TESTS as $p) {
                if (preg_match('/\A(?:' . $p . ')\z/', $s) === 1) {
                    return self::quoted($value, $ctx);
                }
            }
        }
        return $ctx->implicitKey ? $s : self::fold($s, $ctx->indent, 'flow', $ctx->indentAtStart);
    }

    private static function string(string $raw, YCtx $ctx): string
    {
        $lone = Json::hasLoneSurrogate($raw);
        $value = self::toUnits($raw);
        if ($lone || preg_match(self::CONTROL, $value) === 1) {
            return self::doubleQuoted($value, $ctx);
        }
        return self::plain($value, $ctx);
    }

    private static function number(mixed $v): string
    {
        $f = $v instanceof Num ? $v->float() : (float)$v;
        if (!is_finite($f)) {
            return is_nan($f) ? '.nan' : ($f < 0 ? '-.inf' : '.inf');
        }
        if ($f == 0.0 && fdiv(1.0, $f) === -INF) {
            return '-0';
        }
        return IntentWb::jsNumStr($f);
    }

    // ---- nodes ----------------------------------------------------------------------------------------------------------

    /**
     * createNode with aliasDuplicateObjects: a container met twice becomes an anchor (named a1, a2, ... in the order the repeats are met) on its
     * first occurrence and an alias on every later one; cycles are allowed. A node is a YNode, an alias a string ("*name" target) in YAlias.
     *
     * @param array<int,array{0:?string,1:?YNode}> $seen
     */
    private static function node(mixed $v, array &$seen, int &$n, array &$sources): YNode|YAlias
    {
        if ($v instanceof Obj || $v instanceof YamlSeq || is_array($v)) {
            $id = is_array($v) ? null : spl_object_id($v);
            if ($id !== null && isset($seen[$id])) {
                if ($seen[$id][0] === null) {
                    $n++;
                    $seen[$id][0] = 'a' . $n;
                }
                return new YAlias($seen[$id][0]);
            }
            $ref = [null, null];
            if ($id !== null) {
                $seen[$id] = &$ref;
            }
            if ($v instanceof Obj) {
                $m = new YNode('map');
                $ref[1] = $m;
                foreach ($v->keys() as $k) {
                    $m->items[] = [new YNode('scalar', $k), self::node($v->get($k), $seen, $n, $sources)];
                }
            } else {
                $s = new YNode('seq');
                $ref[1] = $s;
                foreach ($v instanceof YamlSeq ? $v->items : $v as $x) {
                    $s->items[] = self::node($x, $seen, $n, $sources);
                }
                $m = $s;
            }
            $sources[] = &$ref;
            unset($ref);
            return $m;
        }
        if ($v === null || is_string($v) || is_bool($v) || is_int($v) || is_float($v) || $v instanceof Num) {
            return new YNode('scalar', $v);
        }
        throw new \InvalidArgumentException('cannot write a ' . get_debug_type($v) . ' as YAML');
    }

    private static function stringifyNode(YNode|YAlias $item, YCtx $ctx): string
    {
        if ($item instanceof YAlias) {
            if (!isset($ctx->anchors[$item->source])) {
                throw new \RuntimeException('Unresolved alias (the anchor must be set before the alias): ' . $item->source);
            }
            return $ctx->implicitKey ? '*' . $item->source . ' ' : '*' . $item->source;
        }
        $props = '';
        if ($item->anchor !== null) {
            $ctx->anchors[$item->anchor] = true;
            $props = '&' . $item->anchor;
            $ctx->indentAtStart = ($ctx->indentAtStart ?? 0) + strlen($props) + 1;
        }
        if ($item->kind === 'scalar') {
            $v = $item->value;
            if (is_string($v)) {
                $c = clone $ctx;
                $c->actualString = true;
                $s = self::string($v, $c);
            } elseif ($v === null) {
                $s = 'null';
            } elseif (is_bool($v)) {
                $s = $v ? 'true' : 'false';
            } else {
                $s = self::number($v);
            }
        } elseif ($item->kind === 'seq') {
            $ictx = self::itemCtx($ctx, $ctx->indent . '  ');
            $lines = [];
            foreach ($item->items as $x) {
                $lines[] = '- ' . self::stringifyNode($x, $ictx);
            }
            $s = self::block($ctx, $lines, '[', ']');
        } else {
            $ictx = self::itemCtx($ctx, $ctx->indent);
            $lines = [];
            foreach ($item->items as [$k, $v]) {
                $lines[] = self::pair($k, $v, $ictx);
            }
            $s = self::block($ctx, $lines, '{', '}');
        }
        if ($props === '') {
            return $s;
        }
        return $item->kind === 'scalar' || $s[0] === '{' || $s[0] === '[' ? $props . ' ' . $s : $props . "\n" . $ctx->indent . $s;
    }

    private static function itemCtx(YCtx $ctx, string $indent): YCtx
    {
        $c = clone $ctx;
        $c->indent = $indent;
        return $c;
    }

    /** @param list<string> $lines */
    private static function block(YCtx $ctx, array $lines, string $start, string $end): string
    {
        if (!$lines) {
            return $start . $end;
        }
        $out = $lines[0];
        foreach (array_slice($lines, 1) as $line) {
            $out .= $line !== '' ? "\n" . $ctx->indent . $line : "\n";
        }
        return $out;
    }

    private static function pair(YNode $key, YNode|YAlias $value, YCtx $ctx): string
    {
        $indent = $ctx->indent;
        $ctx = clone $ctx;
        $ctx->implicitKey = true;
        $ctx->indent = $indent . self::INDENT_STEP;
        $s = self::stringifyNode($key, $ctx);
        $explicit = self::ulen($s) > 1024;
        $s = $explicit ? '? ' . $s . "\n" . $indent . ':' : $s . ':';
        $ctx->implicitKey = false;
        $isScalar = $value instanceof YNode && $value->kind === 'scalar';
        $isColl = $value instanceof YNode && $value->kind !== 'scalar';
        if (!$explicit && $isScalar) {
            $ctx->indentAtStart = self::ulen($s) + 1;
        }
        $vs = self::stringifyNode($value, $ctx);
        $ws = ' ';
        if (!$explicit && $isColl) {
            $nl0 = strpos($vs, "\n");
            $hasNl = $nl0 !== false;
            $flow = count($value->items) === 0;
            if ($hasNl || !$flow) {
                $propsLine = false;
                if ($hasNl && ($vs[0] === '&' || $vs[0] === '!')) {
                    $sp0 = strpos($vs, ' ');
                    if ($vs[0] === '&' && $sp0 !== false && $sp0 < $nl0 && ($vs[$sp0 + 1] ?? '') === '!') {
                        $sp0 = strpos($vs, ' ', $sp0 + 1);
                    }
                    if ($sp0 === false || $nl0 < $sp0) {
                        $propsLine = true;
                    }
                }
                if (!$propsLine) {
                    $ws = "\n" . $ctx->indent;
                }
            }
        } elseif ($vs === '' || $vs[0] === "\n") {
            $ws = '';
        }
        return $s . $ws . $vs;
    }

    /** The YAML text of plain data (Obj / list / string / bool / number / null); repeated Obj / YamlSeq containers become anchors and aliases. */
    public static function stringify(mixed $value): string
    {
        $seen = [];
        $n = 0;
        $sources = [];
        $root = self::node($value, $seen, $n, $sources);
        foreach ($sources as $ref) {
            if ($ref[0] !== null) {
                $ref[1]->anchor = $ref[0];
            }
        }
        return self::fromUnits(self::stringifyNode($root, new YCtx())) . "\n";
    }

    /**
     * `ns: <ns>` and `actions: [...]` as YAML; a def whose verb has an own entry in `$rules` (an Obj) gets it re-attached as its `rules` member.
     *
     * @param list<Obj> $defs
     */
    public static function defsToYaml(string $ns, array $defs, ?Obj $rules = null): string
    {
        $rules ??= new Obj();
        $actions = [];
        foreach ($defs as $d) {
            if ($rules->has($d->get('verb'))) {
                $c = new Obj();
                foreach ($d->keys() as $k) {
                    $c->set($k, $d->get($k));
                }
                $c->set('rules', $rules->get($d->get('verb')));
                $d = $c;
            }
            $actions[] = $d;
        }
        return self::stringify(Obj::of(['ns' => $ns, 'actions' => $actions]));
    }
}

/** The writer context (copied per scalar and per pair; the set of anchors seen so far is shared by every copy). */
final class YCtx
{
    public string $indent = '';
    public ?int $indentAtStart = null;
    public bool $implicitKey = false;
    public bool $actualString = false;
    public bool $forceBlockIndent = false;
    public \ArrayObject $anchors;

    public function __construct()
    {
        $this->anchors = new \ArrayObject();
    }
}

final class YNode
{
    public ?string $anchor = null;
    /** @var list<mixed> seq: nodes; map: [key node, value node] */
    public array $items = [];

    public function __construct(public readonly string $kind, public readonly mixed $value = null)
    {
    }
}

final class YAlias
{
    public function __construct(public readonly string $source)
    {
    }
}
