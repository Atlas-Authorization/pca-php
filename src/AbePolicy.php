<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Access structures for ciphertext-policy ABE: a monotone boolean formula as a threshold tree.
 *
 *   {attr}                      leaf
 *   {allOf: [...]}              AND (n-of-n)
 *   {anyOf: [...]}              OR  (1-of-n)
 *   {threshold: k, of: [...]}   k-of-n
 *
 * normalize() fails closed on any malformed node, empty gate, out-of-range threshold or oversized tree. Internally a node is
 * ['leaf' => true, 'attr' => string] or ['leaf' => false, 't' => int, 'of' => list<node>]; toJson() gives the wire form
 * {kind:"leaf",attr} / {kind:"gate",t,of}.
 */
final class AbePolicy
{
    public const MAX_POLICY_NODES = 1024;
    /** Gate nesting bound, so that "encryptable" implies "decryptable" under the canonical JSON depth cap. */
    public const MAX_POLICY_DEPTH = 10;

    /** @return array{leaf:true,attr:string} */
    public static function leaf(string $attr): array
    {
        return ['leaf' => true, 'attr' => $attr];
    }

    /** @param list<array> $of */
    public static function gate(int $t, array $of): array
    {
        return ['leaf' => false, 't' => $t, 'of' => $of];
    }

    /** The wire form of a node. */
    public static function toJson(array $n): Obj
    {
        if ($n['leaf']) {
            return Obj::of(['kind' => 'leaf', 'attr' => $n['attr']]);
        }
        return Obj::of(['kind' => 'gate', 't' => new Num((string) $n['t']), 'of' => array_map(self::toJson(...), $n['of'])]);
    }

    public static function leafCount(array $n): int
    {
        return $n['leaf'] ? 1 : array_sum(array_map(self::leafCount(...), $n['of']));
    }

    /** @return list<string> the leaf attributes in depth-first order (one span-program row each) */
    public static function leafAttrs(array $n): array
    {
        if ($n['leaf']) {
            return [$n['attr']];
        }
        $out = [];
        foreach ($n['of'] as $c) {
            array_push($out, ...self::leafAttrs($c));
        }
        return $out;
    }

    /** The first attribute named by two leaves, or null (attributes are non-empty). */
    public static function firstRepeatedAttribute(array $n): ?string
    {
        $seen = [];
        foreach (self::leafAttrs($n) as $a) {
            if (isset($seen[$a])) {
                return $a;
            }
            $seen[$a] = true;
        }
        return null;
    }

    /** @param callable(string):bool $has */
    public static function satisfies(array $n, callable $has): bool
    {
        if ($n['leaf']) {
            return $has($n['attr']);
        }
        $met = 0;
        foreach ($n['of'] as $c) {
            if (self::satisfies($c, $has)) {
                $met++;
            }
        }
        return $met >= $n['t'];
    }

    /** A string with an unpaired UTF-16 surrogate (kept as its WTF-8 form by the parser) or invalid UTF-8: such strings alias each other once encoded. */
    public static function illFormed(string $s): bool
    {
        return Json::hasLoneSurrogate($s) || preg_match('//u', $s) !== 1;
    }

    /** Sort in UTF-16 code unit order, as the reference sorts. @param list<string> $l @return list<string> */
    public static function jsSort(array $l): array
    {
        $key = static fn(string $s): string => mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        usort($l, static fn(string $a, string $b): int => strcmp($key($a), $key($b)));
        return $l;
    }

    /** A JSON number that is a positive integer (JavaScript Number.isInteger semantics): its value, or null. */
    public static function posInt(mixed $v): ?float
    {
        if (!($v instanceof Num)) {
            return null;
        }
        $f = $v->float();
        return is_finite($f) && $f > 0 && $f === floor($f) ? $f : null;
    }

    /**
     * Validate and normalise an access structure.
     *
     * @return array{tree:?array,reason:string} the node, or the reason it was refused
     */
    public static function normalize(mixed $policy): array
    {
        $nodes = 0;
        $why = '';
        $tree = self::walk($policy, 'policy', 0, $nodes, $why);
        return $tree === null ? ['tree' => null, 'reason' => $why] : ['tree' => $tree, 'reason' => ''];
    }

    /** {ok:true, tree} or {ok:false, reason}: the reference's result object. */
    public static function normalizeJson(mixed $policy): Obj
    {
        $r = self::normalize($policy);
        return $r['tree'] === null ? Obj::of(['ok' => false, 'reason' => $r['reason']]) : Obj::of(['ok' => true, 'tree' => self::toJson($r['tree'])]);
    }

    private static function walk(mixed $p, string $path, int $gates, int &$nodes, string &$why): ?array
    {
        $nodes++;
        if ($nodes > self::MAX_POLICY_NODES) {
            $why = 'policy too large (> ' . self::MAX_POLICY_NODES . ' nodes)';
            return null;
        }
        if (!($p instanceof Obj)) {
            $why = $path . ': not an object';
            return null;
        }
        if ($p->has('attr')) {
            $s = $p->get('attr');
            if (!is_string($s) || $s === '') {
                $why = $path . ": 'attr' must be a non-empty string";
                return null;
            }
            if (self::illFormed($s)) {
                $why = $path . ": 'attr' is not well-formed UTF-16";
                return null;
            }
            if ($p->has('allOf') || $p->has('anyOf') || $p->has('threshold') || $p->has('of')) {
                $why = $path . ": a leaf must not mix 'attr' with a gate";
                return null;
            }
            return self::leaf($s);
        }
        $gateKeys = [];
        foreach (['allOf', 'anyOf', 'threshold', 'of'] as $k) {
            if ($p->has($k) && ($k !== 'of' || !$p->has('threshold'))) {
                $gateKeys[] = $k;
            }
        }
        if (count($gateKeys) > 1) {
            $why = "$path: ambiguous node (" . implode(', ', $gateKeys) . '); a gate must use exactly one of allOf/anyOf/threshold';
            return null;
        }
        if (count($gateKeys) === 1 && $gates + 1 > self::MAX_POLICY_DEPTH) {
            $why = "$path: policy nested deeper than " . self::MAX_POLICY_DEPTH . ' gates';
            return null;
        }
        if ($p->has('allOf')) {
            $kids = self::children($p->get('allOf'), 'allOf', $path, $gates, $nodes, $why);
            return $kids === null ? null : self::gate(count($kids), $kids);
        }
        if ($p->has('anyOf')) {
            $kids = self::children($p->get('anyOf'), 'anyOf', $path, $gates, $nodes, $why);
            return $kids === null ? null : self::gate(1, $kids);
        }
        if ($p->has('threshold')) {
            $f = self::posInt($p->get('threshold'));
            if ($f === null) {
                $why = $path . ": 'threshold' must be a positive integer";
                return null;
            }
            $kids = self::children($p->get('of'), 'of', $path, $gates, $nodes, $why);
            if ($kids === null) {
                return null;
            }
            if ($f > count($kids)) {
                $why = "$path: threshold " . IntentWb::jsNumStr($f) . ' exceeds the number of branches (' . count($kids) . ')';
                return null;
            }
            return self::gate((int) $f, $kids);
        }
        $why = $path . ': unknown policy node (expected attr/allOf/anyOf/threshold)';
        return null;
    }

    /** @return ?list<array> */
    private static function children(mixed $raw, string $key, string $path, int $gates, int &$nodes, string &$why): ?array
    {
        if (!is_array($raw) || !array_is_list($raw) || $raw === []) {
            $why = "$path: '$key' must be a non-empty array";
            return null;
        }
        $out = [];
        foreach ($raw as $i => $c) {
            $k = self::walk($c, $path . '.' . $key . '[' . $i . ']', $gates + 1, $nodes, $why);
            if ($k === null) {
                return null;
            }
            $out[] = $k;
        }
        return $out;
    }

    /** Validate an untrusted (ciphertext) tree: the node, or null on any deviation. A bounded node budget limits the work. */
    public static function parseTree(mixed $x, int $gates = 0, int &$nodes = 0): ?array
    {
        $nodes++;
        if ($nodes > self::MAX_POLICY_NODES || !($x instanceof Obj)) {
            return null;
        }
        $n = count($x->keys());
        if ($x->get('kind') === 'leaf') {
            $a = $x->get('attr');
            return !is_string($a) || $a === '' || self::illFormed($a) || $n !== 2 ? null : self::leaf($a);
        }
        if ($x->get('kind') === 'gate') {
            $t = self::posInt($x->get('t'));
            $of = $x->get('of');
            if ($gates + 1 > self::MAX_POLICY_DEPTH || $n !== 3 || $t === null || !is_array($of) || !array_is_list($of) || $of === []
                || $t > count($of) || count($of) >= self::MAX_POLICY_NODES) {
                return null;
            }
            $kids = [];
            foreach ($of as $b) {
                $sub = self::parseTree($b, $gates + 1, $nodes);
                if ($sub === null) {
                    return null;
                }
                $kids[] = $sub;
            }
            return self::gate((int) $t, $kids);
        }
        return null;
    }

    /** The pure, non-cryptographic check that the attribute set satisfies a wire tree (a convenience and test oracle). @param list<string> $attrs */
    public static function treeSatisfies(mixed $tree, array $attrs): bool
    {
        $t = self::parseTree($tree);
        $set = array_fill_keys($attrs, true);
        return $t !== null && self::satisfies($t, static fn(string $a): bool => isset($set[$a]));
    }

    /** Every attribute a wire tree names, sorted; null when it is not a valid tree. @return ?list<string> */
    public static function policyAttributes(mixed $tree): ?array
    {
        $t = self::parseTree($tree);
        return $t === null ? null : self::jsSort(array_map('strval', array_keys(array_fill_keys(self::leafAttrs($t), true))));
    }
}
