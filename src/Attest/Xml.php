<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

/** Ill-formed XML (or a construct the profile cannot represent). */
final class XmlError extends \RuntimeException
{
}

/** An attribute (namespace declarations are kept apart in {@see XmlElement::$decls}). */
final class XmlAttr
{
    public string $prefix = '';
    public string $local;
    public string $ns = '';

    public function __construct(public string $qname, public string $value)
    {
        $pos = strpos($qname, ':');
        if ($pos === false) {
            $this->local = $qname;
        } else {
            $this->prefix = substr($qname, 0, $pos);
            $this->local = substr($qname, $pos + 1);
        }
    }
}

final class XmlElement
{
    public string $prefix = '';
    public string $local;
    public string $ns = '';
    /** @var list<XmlAttr> */
    public array $attrs = [];
    /** @var array<string,string> prefix ('' = default) => uri declared on this element */
    public array $decls = [];
    /** @var array<string,string> in scope on this element (after its own declarations) */
    public array $scope = [];
    /** @var list<XmlElement|string> */
    public array $children = [];

    public function __construct(public string $qname, public ?XmlElement $parent)
    {
        $pos = strpos($qname, ':');
        if ($pos === false) {
            $this->local = $qname;
        } else {
            $this->prefix = substr($qname, 0, $pos);
            $this->local = substr($qname, $pos + 1);
        }
    }

    public function getAttribute(string $qname): string
    {
        foreach ($this->attrs as $a) {
            if ($a->qname === $qname) {
                return $a->value;
            }
        }
        return '';
    }

    /** @return list<XmlElement> */
    public function elementChildren(?string $ns = null, ?string $local = null): array
    {
        $out = [];
        foreach ($this->children as $c) {
            if ($c instanceof XmlElement && ($ns === null || $c->ns === $ns) && ($local === null || $c->local === $local)) {
                $out[] = $c;
            }
        }
        return $out;
    }

    /** @return list<XmlElement> */
    public function descendants(string $ns, string $local): array
    {
        $out = [];
        foreach ($this->children as $c) {
            if ($c instanceof XmlElement) {
                if ($c->ns === $ns && $c->local === $local) {
                    $out[] = $c;
                }
                array_push($out, ...$c->descendants($ns, $local));
            }
        }
        return $out;
    }

    public function textContent(): string
    {
        $out = '';
        foreach ($this->children as $c) {
            $out .= $c instanceof XmlElement ? $c->textContent() : $c;
        }
        return $out;
    }
}

final class XmlDocument
{
    public ?XmlElement $root = null;
    /** @var list<string> in document order */
    public array $violations = [];
}

/**
 * A strict XML subset parser and Inclusive Canonical XML (C14N 1.0, identical to C14N 1.1 for documents without `xml:*`
 * attributes) for the NVIDIA RIM XMLDSig check. Accepted: elements, attributes, text, CDATA, the five predefined entities and
 * character references. Comments, processing instructions (including the XML declaration) and a DOCTYPE are PARSED but recorded
 * as profile violations (the RIM profile rejects all of them); anything ill-formed throws XmlError.
 */
final class Xml
{
    private const NAME = '/\G[A-Za-z_:\x{C0}-\x{2FF}\x{370}-\x{1FFF}\x{2C00}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}][A-Za-z0-9_:.\-\x{B7}\x{C0}-\x{2FF}\x{300}-\x{1FFF}\x{2C00}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}]*/u';
    private const WS = " \t\r\n";
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';
    private const ENTITIES = ['lt' => '<', 'gt' => '>', 'amp' => '&', 'quot' => '"', 'apos' => "'"];

    private static function unescape(string $s, bool $attr): string
    {
        if (!str_contains($s, '&') && !$attr) {
            return $s;
        }
        $out = '';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $ch = $s[$i];
            if ($ch === '&') {
                $j = strpos($s, ';', $i + 1);
                if ($j === false) {
                    throw new XmlError('unterminated entity reference');
                }
                $ref = substr($s, $i + 1, $j - $i - 1);
                if (str_starts_with($ref, '#x') || str_starts_with($ref, '#X')) {
                    if (preg_match('/\A[0-9a-fA-F]+\z/', substr($ref, 2)) !== 1) {
                        throw new XmlError('bad character reference');
                    }
                    $out .= self::chr((int)hexdec(substr($ref, 2)));
                } elseif (str_starts_with($ref, '#')) {
                    if (preg_match('/\A[0-9]+\z/', substr($ref, 1)) !== 1) {
                        throw new XmlError('bad character reference');
                    }
                    $out .= self::chr((int)substr($ref, 1));
                } elseif (isset(self::ENTITIES[$ref])) {
                    $out .= self::ENTITIES[$ref];
                } else {
                    throw new XmlError("unknown entity &$ref;");
                }
                $i = $j;
                continue;
            }
            if ($attr && strpos("\t\r\n", $ch) !== false) {
                $out .= ' ';
            } elseif ($ch === '<' && $attr) {
                throw new XmlError("'<' in an attribute value");
            } else {
                $out .= $ch;
            }
        }
        return $out;
    }

    private static function chr(int $cp): string
    {
        $c = $cp > 0x10FFFF || ($cp >= 0xD800 && $cp <= 0xDFFF) ? false : mb_chr($cp, 'UTF-8');
        return $c === false ? "\xEF\xBF\xBD" : $c;
    }

    private static function skipWs(string $s, int $i): int
    {
        $n = strlen($s);
        while ($i < $n && strpos(self::WS, $s[$i]) !== false) {
            $i++;
        }
        return $i;
    }

    public static function parse(string $text): XmlDocument
    {
        $doc = new XmlDocument();
        $n = strlen($text);
        $i = 0;
        /** @var list<XmlElement> $stack */
        $stack = [];
        while ($i < $n) {
            if ($text[$i] !== '<') {
                $j = strpos($text, '<', $i);
                $j = $j === false ? $n : $j;
                $chunk = substr($text, $i, $j - $i);
                if ($stack === []) {
                    if (trim($chunk, self::WS) !== '') {
                        throw new XmlError('text outside the root element');
                    }
                } else {
                    $stack[count($stack) - 1]->children[] = self::unescape($chunk, false);
                }
                $i = $j;
                continue;
            }
            if (str_starts_with(substr($text, $i, 4), '<!--')) {
                $j = strpos($text, '-->', $i + 4);
                if ($j === false) {
                    throw new XmlError('unterminated comment');
                }
                $doc->violations[] = 'XML comments are not permitted';
                $i = $j + 3;
                continue;
            }
            if (substr($text, $i, 9) === '<![CDATA[') {
                $j = strpos($text, ']]>', $i + 9);
                if ($j === false || $stack === []) {
                    throw new XmlError('bad CDATA section');
                }
                $stack[count($stack) - 1]->children[] = substr($text, $i + 9, $j - $i - 9);
                $i = $j + 3;
                continue;
            }
            if (substr($text, $i, 2) === '<?') {
                $j = strpos($text, '?>', $i + 2);
                if ($j === false) {
                    throw new XmlError('unterminated processing instruction');
                }
                $doc->violations[] = 'XML processing instructions are not permitted';
                $i = $j + 2;
                continue;
            }
            if (substr($text, $i, 2) === '<!') {
                $depth = 0;
                $j = $i + 2;
                while ($j < $n) {
                    $c = $text[$j];
                    if ($c === '[') {
                        $depth++;
                    } elseif ($c === ']') {
                        $depth--;
                    } elseif ($c === '>' && $depth <= 0) {
                        break;
                    }
                    $j++;
                }
                if ($j >= $n) {
                    throw new XmlError('unterminated declaration');
                }
                $doc->violations[] = 'DTD / DOCTYPE is not permitted';
                $i = $j + 1;
                continue;
            }
            if (substr($text, $i, 2) === '</') {
                if (preg_match(self::NAME, $text, $m, 0, $i + 2) !== 1) {
                    throw new XmlError('bad end tag');
                }
                $j = self::skipWs($text, $i + 2 + strlen($m[0]));
                if ($j >= $n || $text[$j] !== '>') {
                    throw new XmlError('bad end tag');
                }
                if ($stack === [] || $stack[count($stack) - 1]->qname !== $m[0]) {
                    throw new XmlError("mismatched end tag </{$m[0]}>");
                }
                array_pop($stack);
                $i = $j + 1;
                continue;
            }
            // start tag
            if (preg_match(self::NAME, $text, $m, 0, $i + 1) !== 1) {
                throw new XmlError('bad start tag');
            }
            $parent = $stack === [] ? null : $stack[count($stack) - 1];
            if ($parent === null && $doc->root !== null) {
                throw new XmlError('more than one root element');
            }
            $el = new XmlElement($m[0], $parent);
            $j = $i + 1 + strlen($m[0]);
            $rawAttrs = [];
            while (true) {
                $k = self::skipWs($text, $j);
                if ($k >= $n) {
                    throw new XmlError('unterminated start tag');
                }
                if ($text[$k] === '>' || substr($text, $k, 2) === '/>') {
                    break;
                }
                if ($k === $j) {
                    throw new XmlError('missing whitespace before an attribute');
                }
                if (preg_match(self::NAME, $text, $am, 0, $k) !== 1) {
                    throw new XmlError('bad attribute name');
                }
                $k = self::skipWs($text, $k + strlen($am[0]));
                if ($k >= $n || $text[$k] !== '=') {
                    throw new XmlError('attribute without a value');
                }
                $k = self::skipWs($text, $k + 1);
                if ($k >= $n || ($text[$k] !== '"' && $text[$k] !== "'")) {
                    throw new XmlError('unquoted attribute value');
                }
                $q = $text[$k];
                $e = strpos($text, $q, $k + 1);
                if ($e === false) {
                    throw new XmlError('unterminated attribute value');
                }
                foreach ($rawAttrs as [$a]) {
                    if ($a === $am[0]) {
                        throw new XmlError("duplicate attribute {$am[0]}");
                    }
                }
                $rawAttrs[] = [$am[0], self::unescape(substr($text, $k + 1, $e - $k - 1), true)];
                $j = $e + 1;
            }
            $selfClose = substr($text, $k, 2) === '/>';
            $i = $k + ($selfClose ? 2 : 1);
            $scope = $parent !== null ? $parent->scope : [];
            foreach ($rawAttrs as [$qn, $val]) {
                if ($qn === 'xmlns') {
                    $el->decls[''] = $val;
                } elseif (str_starts_with($qn, 'xmlns:')) {
                    if ($val === '') {
                        throw new XmlError('namespace prefix cannot be undeclared');
                    }
                    $el->decls[substr($qn, 6)] = $val;
                } else {
                    $el->attrs[] = new XmlAttr($qn, $val);
                }
            }
            foreach ($el->decls as $p => $uri) {
                if ($uri === '' && (string)$p === '') {
                    unset($scope['']);
                } else {
                    $scope[(string)$p] = $uri;
                }
            }
            $el->scope = $scope;
            if ($el->prefix !== '') {
                if (!isset($scope[$el->prefix])) {
                    throw new XmlError("unbound namespace prefix {$el->prefix}");
                }
                $el->ns = $scope[$el->prefix];
            } else {
                $el->ns = $scope[''] ?? '';
            }
            foreach ($el->attrs as $a) {
                if ($a->prefix === 'xml') {
                    $a->ns = self::XML_NS;
                } elseif ($a->prefix !== '') {
                    if (!isset($scope[$a->prefix])) {
                        throw new XmlError("unbound namespace prefix {$a->prefix}");
                    }
                    $a->ns = $scope[$a->prefix];
                }
                if (str_starts_with(strtolower($a->qname), 'xml:')) {
                    $doc->violations[] = "xml:* attribute '{$a->qname}' is not permitted (C14N 1.1 profile)";
                }
            }
            if ($parent !== null) {
                $parent->children[] = $el;
            } else {
                $doc->root = $el;
            }
            if (!$selfClose) {
                $stack[] = $el;
            }
        }
        if ($stack !== []) {
            throw new XmlError('unclosed element <' . $stack[count($stack) - 1]->qname . '>');
        }
        if ($doc->root === null) {
            throw new XmlError('no root element');
        }
        return $doc;
    }

    // ---- canonical XML ---------------------------------------------------------------------------------------------------------

    private static function encText(string $s): string
    {
        return str_replace(['&', '<', '>', "\r"], ['&amp;', '&lt;', '&gt;', '&#xD;'], $s);
    }

    private static function encAttr(string $s): string
    {
        return str_replace(['&', '<', '"', "\t", "\n", "\r"], ['&amp;', '&lt;', '&quot;', '&#x9;', '&#xA;', '&#xD;'], $s);
    }

    /**
     * Inclusive C14N of the subtree at `$el` (an apex: every in-scope namespace is declared on it). `$skip` drops one descendant
     * (the enveloped Signature).
     */
    public static function canonicalize(XmlElement $el, ?XmlElement $skip = null): string
    {
        $out = '';
        self::render($el, $el->scope, null, $skip, $out);
        return $out;
    }

    /** @param array<string,string> $scope @param array<string,string>|null $parentOut */
    private static function render(XmlElement $el, array $scope, ?array $parentOut, ?XmlElement $skip, string &$out): void
    {
        $out .= '<' . $el->qname;
        $prev = $parentOut ?? [];
        $nsOut = [];
        foreach ($scope as $prefix => $uri) {
            if ($parentOut === null || ($prev[$prefix] ?? null) !== $uri) {
                $nsOut[(string)$prefix] = $uri;
            }
        }
        if ($parentOut !== null && array_key_exists('', $prev) && !array_key_exists('', $scope)) {
            $nsOut[''] = ''; // xmlns="" undeclares the inherited default namespace
        }
        $keys = array_map('strval', array_keys($nsOut));
        usort($keys, 'strcmp');
        foreach ($keys as $prefix) {
            $uri = $nsOut[$prefix];
            $out .= $prefix === '' ? ' xmlns="' . self::encAttr($uri) . '"' : " xmlns:$prefix=\"" . self::encAttr($uri) . '"';
        }
        $attrs = $el->attrs;
        usort($attrs, static fn(XmlAttr $a, XmlAttr $b): int => [$a->ns, $a->local] <=> [$b->ns, $b->local]);
        foreach ($attrs as $a) {
            $out .= " {$a->qname}=\"" . self::encAttr($a->value) . '"';
        }
        $out .= '>';
        foreach ($el->children as $c) {
            if (is_string($c)) {
                $out .= self::encText($c);
            } elseif ($c !== $skip) {
                self::render($c, $c->scope, $scope, $skip, $out);
            }
        }
        $out .= '</' . $el->qname . '>';
    }
}
