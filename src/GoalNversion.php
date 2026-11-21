<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalNormalize.php';
require_once __DIR__ . '/GoalDisambiguate.php';

/**
 * N-version interpretation: the enforced policy is the semantic meet of the readings. Allow(meet gs) a implies Allow(g) a for every
 * g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named `x&y&z`), resources
 * intersect through `all_of`, conditions conjoin; a bound of one reading counts the actions admitted by the merged grants derived
 * from the grants that bound selected.
 */
final class GoalNversion
{
    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    /** A copy of `$o` (an Obj) with the members of `$set` written over it (insertion order kept, new members appended). */
    private static function with(mixed $o, array $set): Obj
    {
        $c = AnalyzerJs::spread($o);
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    /** Map key of a JS value (Map / Set identity: SameValueZero over JSON values). */
    private static function mk(mixed $v): string
    {
        return $v instanceof Undef ? 'u' : 'v' . Js::stringify($v);
    }

    /** @param list<mixed> $xs @return list<mixed> the first of every strictly equal run of values (`new Set(xs)`) */
    private static function uniq(array $xs): array
    {
        $out = [];
        foreach ($xs as $x) {
            if (!AnalyzerJs::includes($out, $x)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    /** Default `Array.prototype.sort` of values compared as strings (UTF-16 code unit order). @param list<mixed> $xs @return list<mixed> */
    private static function sorted(array $xs): array
    {
        return GoalJs::stableSort($xs, static fn(mixed $a, mixed $b): int => AnalyzerJs::u16cmp(AnalyzerJs::jsStr($a), AnalyzerJs::jsStr($b)));
    }

    /** Math.min / Math.max of a non-empty list of numbers: the winning element itself, NaN when any element is not a number. */
    private static function extreme(array $xs, bool $max): mixed
    {
        $best = null;
        $bv = 0.0;
        foreach ($xs as $x) {
            $v = AnalyzerJs::toNumber($x);
            if (is_nan($v)) {
                return NAN;
            }
            if ($best === null || ($max ? $v > $bv : $v < $bv)) {
                $best = $x;
                $bv = $v;
            }
        }
        return $best ?? ($max ? -INF : INF);
    }

    /** @return list<mixed> */
    private static function partsOf(mixed $s): array
    {
        $k = self::g($s, 'k');
        return $k === 'all_of' ? AnalyzerJs::reqList(self::g($s, 'parts')) : ($k === 'any' ? [] : [$s]);
    }

    private static function intersect(mixed $a, mixed $b): mixed
    {
        if (self::g($a, 'k') === 'any') {
            return $b;
        }
        if (self::g($b, 'k') === 'any') {
            return $a;
        }
        $m = [];
        foreach ([...self::partsOf($a), ...self::partsOf($b)] as $p) {
            $m['k' . GoalNormalize::stable($p)] = $p;
        }
        $uniq = array_values($m);
        return count($uniq) === 1 ? $uniq[0] : Obj::of(['k' => 'all_of', 'parts' => $uniq]);
    }

    private static function conj(mixed $a, mixed $b): mixed
    {
        if (self::g($a, 'k') === 'true') {
            return $b;
        }
        return self::g($b, 'k') === 'true' ? $a : Obj::of(['k' => 'and', 'a' => $a, 'b' => $b]);
    }

    /**
     * @param list<array{g:mixed,from:list<mixed>}> $a
     * @param list<array{g:mixed,from:list<mixed>}> $b
     * @return list<array{g:mixed,from:list<mixed>}>
     */
    private static function cross(array $a, array $b): array
    {
        $out = [];
        foreach ($a as $x) {
            foreach ($b as $y) {
                if (!AnalyzerJs::strictEq(self::g($x['g'], 'verb'), self::g($y['g'], 'verb'))) {
                    continue;
                }
                $out[] = ['g' => AnalyzerJs::uobj([
                    'gid' => AnalyzerJs::jsStr(self::g($x['g'], 'gid')) . '&' . AnalyzerJs::jsStr(self::g($y['g'], 'gid')),
                    'verb' => self::g($x['g'], 'verb'),
                    'res' => self::intersect(self::g($x['g'], 'res'), self::g($y['g'], 'res')),
                    'cond' => self::conj(self::g($x['g'], 'cond'), self::g($y['g'], 'cond')),
                ]), 'from' => [...$x['from'], ...$y['from']]];
            }
        }
        return $out;
    }

    /** @return list<array{g:mixed,from:list<mixed>}> */
    private static function track(mixed $grants): array
    {
        return array_map(static fn(mixed $g): array => ['g' => $g, 'from' => [self::g($g, 'gid')]], AnalyzerJs::reqList($grants));
    }

    /** Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions. @return list<mixed> */
    public static function meetGrants(mixed $a, mixed $b): array
    {
        return array_map(static fn(array $t): mixed => $t['g'], self::cross(self::track($a), self::track($b)));
    }

    /** The semantic meet of readings that share principal, ontology and text. */
    public static function meet(mixed $goals): mixed
    {
        $goals = AnalyzerJs::reqList($goals);
        if ($goals === []) {
            throw new \InvalidArgumentException('meet: no goals');
        }
        $first = $goals[0];
        foreach ($goals as $g) {
            if (!AnalyzerJs::strictEq(self::g($g, 'principal'), self::g($first, 'principal')) || !AnalyzerJs::strictEq(self::g($g, 'ontDigest'), self::g($first, 'ontDigest'))
                || !AnalyzerJs::strictEq(self::g($g, 'nlDigest'), self::g($first, 'nlDigest'))) {
                throw new \InvalidArgumentException('meet: readings must share principal, ontology and text');
            }
        }
        if (count($goals) === 1) {
            return $first;
        }
        $tracked = self::track(self::g($first, 'grants'));
        foreach (array_slice($goals, 1) as $g) {
            $tracked = self::cross($tracked, self::track(self::g($g, 'grants')));
        }
        $grants = array_map(static fn(array $t): mixed => $t['g'], $tracked);
        $derived = static function (int $i, mixed $gids) use ($tracked): array {
            $out = [];
            foreach ($tracked as $t) {
                if (AnalyzerJs::includes($gids, $t['from'][$i] ?? AnalyzerJs::undef())) {
                    $out[] = self::g($t['g'], 'gid');
                }
            }
            return $out;
        };

        $prohibits = [];
        $pseen = [];
        foreach ($goals as $i => $g) {
            foreach (AnalyzerJs::reqList(self::g($g, 'prohibits')) as $p) {
                $body = GoalNormalize::stable(self::with($p, ['pid' => '']));
                if (array_key_exists('k' . $body, $pseen)) {
                    continue;
                }
                $taken = false;
                foreach ($pseen as $v) {
                    if (AnalyzerJs::strictEq($v, self::g($p, 'pid'))) {
                        $taken = true;
                        break;
                    }
                }
                $pseen['k' . $body] = self::g($p, 'pid');
                $prohibits[] = $taken ? self::with($p, ['pid' => AnalyzerJs::jsStr(self::g($p, 'pid')) . '#' . $i]) : $p;
            }
        }

        $bounds = [];
        $bseen = [];
        foreach ($goals as $i => $g) {
            foreach (AnalyzerJs::reqList(self::g($g, 'bounds')) as $b) {
                $bsel = self::g($b, 'sel');
                $isGids = self::g($bsel, 'k') === 'gids';
                $sel = $isGids ? Obj::of(['k' => 'gids', 'gids' => self::sorted($derived($i, self::g($bsel, 'gids')))]) : $bsel;
                if ($isGids && $sel->get('gids') === []) {
                    continue; // no merged grant derives from the selected grants: nothing to count
                }
                $cap = self::g($b, 'cap');
                $key = GoalNormalize::stable(AnalyzerJs::uobj(['sel' => $sel, 'agg' => self::g($b, 'agg'), 'value' => self::g($b, 'value'), 'key' => self::g($b, 'key'),
                    'window' => self::g($b, 'window'), 'scope' => self::g($b, 'scope'), 'unit' => self::g($cap, 'u')]));
                if (isset($bseen['k' . $key])) { // the same aggregate over the same counted grants in several readings: the minimum cap, the stricter exceed action
                    $prev = $bseen['k' . $key];
                    if (AnalyzerJs::jsLt(self::g($cap, 'n'), self::g(self::g($prev, 'cap'), 'n'))) {
                        $prev->set('cap', $cap);
                    }
                    if (self::g($b, 'onExceed') === 'deny') {
                        $prev->set('onExceed', 'deny');
                    }
                    continue;
                }
                $taken = false;
                foreach ($bounds as $x) {
                    if (AnalyzerJs::strictEq(self::g($x, 'bid'), self::g($b, 'bid'))) {
                        $taken = true;
                        break;
                    }
                }
                $nb = self::with($b, ['sel' => $sel, 'bid' => $taken ? AnalyzerJs::jsStr(self::g($b, 'bid')) . '#' . $i : self::g($b, 'bid')]);
                $bounds[] = $nb;
                $bseen['k' . $key] = $nb;
            }
        }

        $esc = [];
        foreach ($goals as $g) {
            foreach (AnalyzerJs::reqList(self::g($g, 'escalateOn')) as $c) {
                $esc['k' . GoalNormalize::stable($c)] = $c;
            }
        }
        $idle = array_values(array_filter(array_map(static fn(mixed $g): mixed => self::g(self::g($g, 'validity'), 'maxIdle'), $goals),
            static fn(mixed $x): bool => AnalyzerJs::jsGt($x, 0)));
        $touch = [];
        foreach ($tracked as $t) {
            $all = true;
            foreach ($goals as $i => $g) {
                if (!AnalyzerJs::includes(self::g(self::g($g, 'deleg'), 'mayTouch'), $t['from'][$i] ?? AnalyzerJs::undef())) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                $touch[] = self::g($t['g'], 'gid');
            }
        }
        $ack = [];
        foreach ($tracked as $t) {
            if (self::g(self::g($t['g'], 'res'), 'k') !== 'any') {
                continue;
            }
            $all = true;
            foreach ($goals as $i => $g) {
                $from = $t['from'][$i] ?? AnalyzerJs::undef();
                $x = null;
                foreach (AnalyzerJs::reqList(self::g($g, 'grants')) as $y) {
                    if (AnalyzerJs::strictEq(self::g($y, 'gid'), $from)) {
                        $x = $y;
                        break;
                    }
                }
                if (!($x === null || self::g(self::g($x, 'res'), 'k') !== 'any' || AnalyzerJs::includes(self::g($g, 'wildcardAck'), $from))) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                $ack[] = self::g($t['g'], 'gid');
            }
        }

        $holes = [];
        foreach ($goals as $i => $g) {
            foreach (AnalyzerJs::reqList(self::g($g, 'holes')) as $h) {
                $mk = self::mk(self::g($h, 'hid'));
                $prev = $holes[$mk] ?? null;
                $affects = self::sorted(self::uniq([...($prev === null ? [] : AnalyzerJs::reqList(self::g($prev, 'affects'))), ...$derived($i, self::g($h, 'affects'))]));
                $gl = self::g($h, 'global');
                $holes[$mk] = self::with($h, ['affects' => $affects,
                    'global' => AnalyzerJs::truthy($gl) ? $gl : ($prev === null ? false : AnalyzerJs::nn(self::g($prev, 'global'), false))]);
            }
        }

        $sources = [];
        foreach ($goals as $g) {
            array_push($sources, ...AnalyzerJs::reqList(self::g($g, 'sources')));
        }
        $vs = array_map(static fn(mixed $g): mixed => self::g($g, 'validity'), $goals);
        return GoalNormalize::canonicalizeGoal(self::with($first, [
            'grants' => $grants, 'prohibits' => $prohibits, 'bounds' => $bounds, 'escalateOn' => array_values($esc), 'sources' => self::uniq($sources),
            'validity' => AnalyzerJs::uobj([
                'notBefore' => self::extreme(array_map(static fn(mixed $v): mixed => self::g($v, 'notBefore'), $vs), true),
                'notAfter' => self::extreme(array_map(static fn(mixed $v): mixed => self::g($v, 'notAfter'), $vs), false),
                'maxIdle' => $idle === [] ? 0 : self::extreme($idle, false)]),
            'deleg' => Obj::of(['maxDepth' => self::extreme(array_map(static fn(mixed $g): mixed => self::g(self::g($g, 'deleg'), 'maxDepth'), $goals), false),
                'narrowOnly' => true, 'mayTouch' => $touch]),
            'holes' => array_values($holes), 'wildcardAck' => $ack,
        ]));
    }

    /**
     * Panel requirements: k >= 3, at least one deterministic non-LLM interpreter, at least two distinct model families.
     * @return list<Obj>
     */
    public static function checkPanel(mixed $readings): array
    {
        $readings = AnalyzerJs::reqList($readings);
        $out = [];
        if (count($readings) < 3) {
            $out[] = Obj::of(['code' => 'too_few', 'msg' => 'need at least 3 interpreters']);
        }
        $det = static fn(mixed $r): bool => AnalyzerJs::truthy(self::g($r, 'deterministic'));
        if (array_filter($readings, $det) === []) {
            $out[] = Obj::of(['code' => 'no_deterministic', 'msg' => 'need at least one deterministic template interpreter']);
        }
        $fams = self::uniq(array_map(static fn(mixed $r): mixed => self::g($r, 'family'), array_values(array_filter($readings, static fn(mixed $r): bool => !$det($r)))));
        if (count($fams) < 2) {
            $out[] = Obj::of(['code' => 'no_family_diversity', 'msg' => 'need at least two distinct model families']);
        }
        return $out;
    }

    /**
     * The question options (`ont`, ...) plus `massThreshold`. Auto-signable only when the panel is valid and no hole remains.
     * @param mixed $opts an Obj or a PHP assoc array
     */
    public static function nVersion(mixed $readings, mixed $opts): Obj
    {
        $readings = AnalyzerJs::reqList($readings);
        $merged = self::meet(array_map(static fn(mixed $r): mixed => self::g($r, 'goal'), $readings));
        $panelIssues = self::checkPanel($readings);
        $verbSets = array_map(static fn(mixed $r): array => self::uniq(array_map(static fn(mixed $g): mixed => self::g($g, 'verb'),
            AnalyzerJs::reqList(self::g(self::g($r, 'goal'), 'grants')))), $readings);
        $allVerbs = [];
        foreach ($verbSets as $s) {
            array_push($allVerbs, ...$s);
        }
        $holes = [];
        foreach (self::sorted(self::uniq($allVerbs)) as $v) {
            foreach ($verbSets as $s) {
                if (!AnalyzerJs::includes($s, $v)) {
                    $holes[] = Obj::of(['hid' => 'nv:verb:' . AnalyzerJs::jsStr($v), 'q' => 'Only some readings allow "' . AnalyzerJs::jsStr($v) . '". Should it be allowed at all?',
                        'domain' => [], 'affects' => [], 'global' => false]);
                    break;
                }
            }
        }
        $mass = GoalDisambiguate::disagreementMass($readings, Js::opt($opts, 'ont'));
        $thr = Js::opt($opts, 'massThreshold');
        if (AnalyzerJs::jsGt($mass, $thr ?? 0)) {
            $qs = GoalDisambiguate::questions($readings, $opts);
            $holes[] = Obj::of(['hid' => 'nv:split', 'q' => $qs === [] ? 'The readings disagree.' : AnalyzerJs::nn(self::g($qs[0], 'text'), 'The readings disagree.'), 'domain' => [], 'affects' => [], 'global' => true]);
        }
        $all = [...AnalyzerJs::reqList(self::g($merged, 'holes')), ...$holes];
        $byHid = [];
        foreach ($all as $h) {
            $byHid[self::mk(self::g($h, 'hid'))] = $h;
        }
        return Obj::of([
            'merged' => GoalNormalize::canonicalizeGoal(self::with($merged, ['holes' => array_values($byHid)])),
            'panelIssues' => $panelIssues, 'disagreementHoles' => $holes, 'mass' => $mass,
            'signable' => $panelIssues === [] && $all === [],
        ]);
    }
}
