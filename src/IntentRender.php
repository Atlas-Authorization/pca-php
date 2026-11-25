<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/WalletOmega.php';
require_once __DIR__ . '/IntentPolicy.php';
require_once __DIR__ . '/IntentSlots.php';

/**
 * Deterministic plain-language rendering and the back-translation diff. Every sentence is a fixed template over the grant's own data (no
 * language model anywhere); anything the templates do not know is rendered as an explicit "not understood" line. Values are the
 * parsed-JSON model (Obj, lists, strings, numbers, bool, null; an absent member is Jsx::$U); hostile inputs refuse (throw) where the
 * reference throws.
 */
final class IntentRender
{
    private static function g(mixed $o, string $k): mixed
    {
        return Jsx::rd($o, $k);
    }

    /** The catalog spec of a verb (null catalog: the built-in one), or null. */
    public static function catalogGet(mixed $catalog, string $verb): mixed
    {
        if ($catalog === null || Jsx::isUndef($catalog)) {
            $catalog = Catalog::BUILTIN_ACTIONS;
        }
        if ($catalog instanceof Catalog) {
            $s = $catalog->get($verb);
            return $s === null ? null : Obj::of($s);
        }
        if ($catalog instanceof Obj) {
            return $catalog->get($verb);
        }
        if (!is_array($catalog)) {
            throw new \TypeError('catalog is not iterable');
        }
        $found = null;
        foreach ($catalog as $a) { // a list of specs: a later spec with the same verb replaces an earlier one
            if (is_array($a) && !array_is_list($a)) {
                $a = Obj::of($a);
            }
            if ($a instanceof Obj && $a->get('verb') === $verb) {
                $found = $a;
            }
        }
        return $found;
    }

    public static function labelOf(string $path): string
    {
        if ($path === 'action.resource') {
            return 'resource';
        }
        $parts = explode('.', $path);
        return str_replace('_', ' ', end($parts));
    }

    private static function fmt(mixed $v): string
    {
        if (is_string($v)) {
            return '"' . $v . '"';
        }
        if (is_array($v) && array_is_list($v)) {
            return implode(', ', array_map(self::fmt(...), $v));
        }
        return Jsx::str($v);
    }

    /** @return list<mixed> */
    private static function arr(mixed $x): array
    {
        if ($x === null || Jsx::isUndef($x)) {
            return [];
        }
        if (!is_array($x) || !array_is_list($x)) {
            throw new \TypeError('map is not a function');
        }
        return $x;
    }

    public static function renderCondition(mixed $c): string
    {
        if (!($c instanceof Obj)) {
            return 'an unreadable condition (not understood)';
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of')) {
                return 'all of: ' . implode(' and ', array_map(static fn($x) => '(' . self::renderCondition($x) . ')', self::arr($c->get('all_of'))));
            }
            if ($c->has('any_of')) {
                return 'either ' . implode(' or ', array_map(static fn($x) => '(' . self::renderCondition($x) . ')', self::arr($c->get('any_of'))));
            }
            return 'it is not the case that ' . self::renderCondition($c->get('not'));
        }
        if (!Predicates::isLeafCondition($c)) {
            return 'an unreadable condition (not understood)';
        }
        $L = 'the ' . self::labelOf($c->get('field'));
        $V = $c->has('ref') ? 'the ' . self::labelOf($c->get('ref')) : self::fmt(Jsx::get($c, 'value'));
        $op = Jsx::get($c, 'op');
        $T = [
            'eq' => '%s is %s', 'ne' => '%s is not %s', 'in' => '%s is one of %s', 'nin' => '%s is none of %s', 'lt' => '%s is less than %s',
            'lte' => '%s is at most %s', 'gt' => '%s is more than %s', 'gte' => '%s is at least %s', 'prefix' => '%s starts with %s',
            'like' => '%s matches the pattern %s', 'matches' => '%s matches the regular expression %s', 'is_a' => '%s is of type %s',
            'member_of' => '%s belongs to %s',
        ];
        if (is_string($op) && isset($T[$op])) {
            return sprintf($T[$op], $L, $V);
        }
        if ($op === 'exists') {
            return Jsx::get($c, 'value') === false ? "$L is absent" : "$L is present";
        }
        return $L . ' has an unrecognised test "' . Jsx::str($op) . '" (not understood)';
    }

    private static function renderResource(mixed $r): string
    {
        if (Jsx::isUndef($r) || $r === '*') {
            return 'on any resource';
        }
        if (!is_string($r)) {
            return 'on an unreadable resource matcher (not understood)';
        }
        if (str_starts_with($r, 're:')) {
            return 'on resources matching the regular expression "' . substr($r, 3) . '"';
        }
        if (str_ends_with($r, '*')) {
            return 'on resources under "' . substr($r, 0, -1) . '"';
        }
        return 'only on resource "' . $r . '"';
    }

    private static function lowerFirst(string $s): string
    {
        return $s !== '' && $s[0] !== "\n" ? mb_strtolower(mb_substr($s, 0, 1)) . mb_substr($s, 1) : $s;
    }

    private static function desc(mixed $s): string
    {
        $d = Js::opt($s, 'description');
        return str_ends_with($d, '.') ? substr($d, 0, -1) : $d;
    }

    private static function dash(string $s): string
    {
        $i = strpos($s, '_');
        return $i === false ? $s : substr($s, 0, $i) . '-' . substr($s, $i + 1);
    }

    private static function renderVerb(mixed $v, mixed $catalog): string
    {
        $one = static function (string $x) use ($catalog): string {
            if ($x === '*') {
                return 'ANY action of any connector';
            }
            $s = self::catalogGet($catalog, $x);
            if ($s !== null) {
                return self::lowerFirst(self::desc($s)) . ' [' . $x . ', ' . self::dash((string)Js::opt($s, 'reversibility')) . ']';
            }
            return '"' . $x . '" [uncatalogued: treated as irreversible]';
        };
        if (is_array($v) && array_is_list($v)) {
            return implode('; or ', array_map(static fn($x) => $one(Jsx::str($x)), $v));
        }
        return $one(Jsx::str($v));
    }

    /** new Date(Number(t)).toISOString(); a RangeError (thrown) for an invalid date. */
    private static function iso(mixed $t): string
    {
        $n = Jsx::isUndef($t) ? NAN : ($t === null ? 0.0 : Jsx::toNum($t));
        if (is_nan($n) || abs($n) > 8.64e15) {
            throw new \RangeException('Invalid time value');
        }
        $ms = (int)$n; // TimeClip truncates toward zero
        $rem = (($ms % 86400000) + 86400000) % 86400000;
        $days = intdiv($ms - $rem, 86400000);
        $z = $days + 719468;
        $era = intdiv($z - ($z >= 0 ? 0 : 146096), 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp < 10 ? $mp + 3 : $mp - 9;
        if ($m <= 2) {
            $y++;
        }
        $ys = $y >= 0 && $y <= 9999 ? sprintf('%04d', $y) : ($y > 0 ? '+' : '-') . sprintf('%06d', abs($y));
        $h = intdiv($rem, 3600000);
        $rem %= 3600000;
        $mi = intdiv($rem, 60000);
        $rem %= 60000;
        return sprintf('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', $ys, $m, $d, $h, $mi, intdiv($rem, 1000), $rem % 1000);
    }

    public static function renderCaveat(mixed $c): string
    {
        $t = Jsx::get($c, 'type');
        $g = static fn(string $k) => Jsx::get($c, $k);
        if ($t === 'expires') {
            return 'The grant expires at ' . self::iso($g('at')) . '.';
        }
        if ($t === 'not_before') {
            return 'The grant is not valid before ' . self::iso($g('at')) . '.';
        }
        if ($t === 'rate') {
            return 'At most ' . Jsx::str($g('max')) . ' actions in any ' . Jsx::str($g('per_secs')) . ' seconds.';
        }
        if ($t === 'max_blast_radius') {
            return 'No action whose blast radius exceeds ' . Jsx::str($g('max')) . " (on a 0\u{2013}1 scale).";
        }
        if ($t === 'reversibility_max') {
            return 'Nothing more severe than "' . self::dash(Jsx::str($g('class'))) . '" (reversible < rate-limited < irreversible).';
        }
        if ($t === 'delegation_depth') {
            return 'It may be re-delegated at most ' . Jsx::str($g('max')) . ' level(s) deep.';
        }
        if ($t === 'budget_alloc') {
            return 'A trust-budget allocation of ' . Jsx::str($g('limit')) . ' is carried for sub-delegation.';
        }
        return 'An unrecognised constraint of type "' . Jsx::str($t) . '" (NOT UNDERSTOOD: do not rely on this grant until it is explained).';
    }

    /** Render a grant as numbered plain-language sentences. Deterministic: same grant, same text. */
    public static function renderGrant(mixed $policy, mixed $catalog = null): string
    {
        $n = IntentPolicy::normalizePolicy($policy);
        $preds = $n->get('predicates');
        $caveats = $n->get('caveats');
        if (count($preds) === 0) {
            return 'This grant allows nothing.';
        }
        $lines = ['The agent may do the following, and nothing else:'];
        foreach ($preds as $i => $p) {
            $w = self::g($p, 'where');
            $conds = array_map(self::renderCondition(...), self::arr($w));
            $lines[] = ($i + 1) . '. ' . self::renderVerb(self::g($p, 'verb'), $catalog) . ', ' . self::renderResource(self::g($p, 'resource'))
                . ($conds !== [] ? ', only when ' . implode(', and ', $conds) : '') . '.';
        }
        if (is_array($caveats) && count($caveats) > 0) {
            $lines[] = 'Limits that apply to everything above:';
            foreach ($caveats as $c) {
                $lines[] = '- ' . self::renderCaveat($c);
            }
        }
        return implode("\n", $lines);
    }

    private static function renderDimCell(mixed $d, int $i): string
    {
        $L = self::labelOf(Js::opt($d, 'path'));
        if (Js::opt($d, 'kind') === 'num') {
            $c = WalletOmega::numCells($d)[$i];
            if ($c['lo'] == $c['hi']) {
                return "$L exactly " . Js::str($c['lo']);
            }
            return "any $L from " . Js::str($c['lo']) . ' to ' . Js::str($c['hi']) . ' (e.g. ' . Js::str($i > 0 ? $c['lo'] : $c['hi']) . ')';
        }
        $v = Js::opt($d, 'values')[$i];
        $kind = Js::opt($v, 'kind');
        if ($kind === 'exact') {
            return $L . ' "' . Js::opt($v, 'value') . '"';
        }
        if ($kind === 'prefix') {
            return 'a ' . $L . ' under "' . Js::opt($v, 'value') . '" (not otherwise named)';
        }
        return "a $L not named anywhere in the grant or your request";
    }

    /** @param list<int> $cell */
    public static function renderQuestion(mixed $vs, array $cell, mixed $catalog = null): string
    {
        $s = self::catalogGet($catalog, Js::opt($vs, 'verb'));
        $what = $s !== null ? self::desc($s) . ' [' . Js::opt($vs, 'verb') . ']' : 'perform "' . Js::opt($vs, 'verb') . '"';
        $parts = [];
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            $parts[] = self::renderDimCell($d, $cell[$k]);
        }
        return "Should the agent be allowed to: $what" . ($parts !== [] ? ', with ' . implode(', ', $parts) : '') . '?';
    }

    // ---- back-translation diff -----------------------------------------------------------------------------------------------

    /**
     * The claim IR of a policy over the outcome space: verb by verb and dimension by dimension.
     * @return list<array<string,mixed>>
     */
    public static function claimsOf(mixed $policy, mixed $omega): array
    {
        $a = IntentPolicy::admitter($policy);
        $out = [];
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $n = WalletOmega::verbCellCount($vs);
            $dims0 = Js::opt($vs, 'dims');
            $acc = [];
            for ($c = 0; $c < $n; $c++) {
                $idx = WalletOmega::decodeCell($vs, $c);
                if ($a->admits($vs, WalletOmega::cellRep($vs, $idx))) {
                    $acc[] = $idx;
                }
            }
            $proj = array_fill(0, count($dims0), []);
            foreach ($acc as $x) {
                foreach ($dims0 as $k => $_) {
                    $proj[$k][$x[$k]] = true;
                }
            }
            $boxCount = 1;
            foreach ($proj as $s) {
                $boxCount *= count($s);
            }
            $dims = [];
            foreach ($dims0 as $k => $d) {
                $ids = array_keys($proj[$k]);
                sort($ids);
                $total = WalletOmega::cellCount($d);
                if (Js::opt($d, 'kind') === 'num') {
                    $cells = WalletOmega::numCells($d);
                    $dc = ['path' => Js::opt($d, 'path'), 'any' => count($ids) === $total];
                    if ($ids !== []) {
                        $dc['range'] = [$cells[$ids[0]]['lo'], $cells[$ids[count($ids) - 1]]['hi']];
                    }
                    $dims[] = $dc;
                } else {
                    $vals = Js::opt($d, 'values');
                    $dims[] = ['path' => Js::opt($d, 'path'), 'any' => count($ids) === $total,
                        'values' => array_map(static fn($i) => Js::opt($vals[$i], 'kind') === 'prefix' ? Js::opt($vals[$i], 'value') . '*' : Js::opt($vals[$i], 'value'), $ids)];
                }
            }
            $out[] = ['verb' => Js::opt($vs, 'verb'), 'allowed' => count($acc) > 0, 'boxShaped' => count($acc) === $boxCount, 'dims' => $dims];
        }
        return $out;
    }

    private static function dimText(?array $c): string
    {
        if (!$c) {
            return 'anything';
        }
        if ($c['any']) {
            return 'any value';
        }
        if (isset($c['range'])) {
            return Js::str($c['range'][0]) . ' to ' . Js::str($c['range'][1]);
        }
        return !empty($c['values']) ? implode(', ', $c['values']) : 'nothing';
    }

    /** @return list<array<string,mixed>> */
    private static function diffClaims(array $g, array $s, array $w): array
    {
        $out = [];
        foreach ($g as $i => $gc) {
            $sc = $s[$i];
            if ($gc['allowed'] && !$sc['allowed']) {
                $out[] = ['verb' => $gc['verb'], 'kind' => 'extra-verb', 'text' => $w['extra']($gc['verb'])];
                continue;
            }
            if (!$gc['allowed'] && $sc['allowed']) {
                $out[] = ['verb' => $gc['verb'], 'kind' => 'missing-verb', 'text' => $w['missing']($gc['verb'])];
                continue;
            }
            if (!$gc['allowed']) {
                continue;
            }
            if ((!$gc['boxShaped'] || !$sc['boxShaped']) && $gc['boxShaped'] !== $sc['boxShaped']) {
                $out[] = ['verb' => $gc['verb'], 'kind' => 'shape', 'text' => $w['shape']($gc['verb'])];
            }
            foreach ($gc['dims'] as $k => $gd) {
                $sd = $sc['dims'][$k];
                if ($gd === $sd) {
                    continue;
                }
                $kind = 'different';
                if (isset($gd['range'], $sd['range'])) {
                    $gr = $gd['range'];
                    $sr = $sd['range'];
                    $kind = $gr[0] <= $sr[0] && $gr[1] >= $sr[1] ? 'looser' : ($gr[0] >= $sr[0] && $gr[1] <= $sr[1] ? 'tighter' : 'different');
                } elseif (isset($gd['values'], $sd['values'])) {
                    $kind = !array_diff($sd['values'], $gd['values']) ? 'looser' : (!array_diff($gd['values'], $sd['values']) ? 'tighter' : 'different');
                } elseif ($gd['any'] && !$sd['any']) {
                    $kind = 'looser';
                }
                $out[] = ['verb' => $gc['verb'], 'kind' => $kind, 'path' => $gd['path'], 'text' => $w['dim']($gc['verb'], $gd['path'], self::dimText($gd), self::dimText($sd))];
            }
        }
        return $out;
    }

    /** Render the grant and the intent slots into the same claim IR and list every difference. @return list<array<string,mixed>> */
    public static function backTranslationDiff(mixed $grant, mixed $slots, mixed $omega): array
    {
        return self::diffClaims(self::claimsOf($grant, $omega), self::claimsOf(IntentSlots::slotsToPolicy($slots), $omega), [
            'extra' => static fn($v) => "The grant allows $v, which your request did not mention.",
            'missing' => static fn($v) => "Your request mentions $v, but the grant does not allow it.",
            'shape' => static fn($v) => "The grant's rule for $v is a combination of cases that your request did not describe.",
            'dim' => static fn($v, $path, $a, $b) => "For $v, the grant allows " . self::labelOf($path) . " $a; your request said $b.",
        ]);
    }

    /** The same claim diff between two grants (two readings); kind is from a's point of view. @return list<array<string,mixed>> */
    public static function claimDiff(mixed $a, mixed $b, mixed $omega, array $names = ['the first reading', 'the second reading']): array
    {
        [$n0, $n1] = [$names[0], $names[1]];
        return self::diffClaims(self::claimsOf($a, $omega), self::claimsOf($b, $omega), [
            'extra' => static fn($v) => "$n0 allows $v; $n1 does not.",
            'missing' => static fn($v) => "$n1 allows $v; $n0 does not.",
            'shape' => static fn($v) => "$n0 and $n1 describe $v with differently shaped rules.",
            'dim' => static fn($v, $path, $x, $y) => "For $v, $n0 allows " . self::labelOf($path) . " $x; $n1 allows $y.",
        ]);
    }

    /** A concrete action in plain language; values are printed verbatim so nothing is hidden. */
    public static function renderAction(mixed $vs, mixed $values, mixed $catalog = null): string
    {
        $verb = Js::opt($vs, 'verb');
        $s = self::catalogGet($catalog, $verb);
        $rev = self::dash(Jsx::str(Jsx::get($vs, 'reversibility')));
        $what = $s !== null ? self::desc($s) . " [$verb, $rev]" : "perform \"$verb\" [uncatalogued: treated as irreversible]";
        $keys = $values instanceof Obj ? $values->keys() : [];
        usort($keys, static fn($a, $b) => strcmp(AnalyzerJs::u16key($a), AnalyzerJs::u16key($b)));
        $parts = [];
        foreach ($keys as $k) {
            $v = $values->get($k);
            $parts[] = self::labelOf($k) . ' ' . (is_string($v) ? '"' . $v . '"' : Jsx::str($v));
        }
        return "The agent wants to: $what" . ($parts !== [] ? ', with ' . implode(', ', $parts) : '') . '.';
    }
}
