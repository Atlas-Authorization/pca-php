<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalDigests.php';
require_once __DIR__ . '/GoalNormalize.php';
require_once __DIR__ . '/GoalRefsem.php';
require_once __DIR__ . '/GoalSign.php';

/**
 * Boundary examples and signed GoalTests over the Goal IR and its reference semantics. An action is classified per coordinate
 * (verb, resource, relation bits, each parameter) against the literals of the policy; `cells` enumerates one representative per
 * decision cell. A Case is `{act, rels}`: an action plus the relation facts it is decided under. A Space is
 * `{verbs, resources, rels, q, d}` with `q` param -> unit key -> sorted numbers and `d` param -> sorted discrete literals.
 */
final class GoalExamples
{
    public const MAX_CELLS = 40000;
    public const OTHER = "\0other";
    public const KIND_W = ['probe' => 0, 'cap_sequence' => 1, 'allow_witness' => 2, 'prohibit_trigger' => 3, 'member' => 4, 'boundary' => 5];

    private static function j(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    private static function num(int|float $x): Num
    {
        return new Num(is_int($x) || (is_finite($x) && floor($x) === $x && abs($x) < 1e15) ? (string)(int)$x : Js::stringify($x));
    }

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v instanceof Undef;
    }

    /** A fresh empty history `{adms: [], last: -1, aggs: {}}`. */
    public static function emptyHist(): Obj
    {
        return Obj::of(['adms' => [], 'last' => self::num(-1), 'aggs' => new Obj()]);
    }

    public static function decisionOf(mixed $d): string
    {
        $f = Js::num($d);
        return $f === 2.0 ? 'allow' : ($f === 1.0 ? 'escalate' : 'deny');
    }

    public static function rankOf(mixed $d): int
    {
        return $d === 'allow' ? 0 : ($d === 'escalate' ? 1 : 2);
    }

    /** An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0). */
    public static function mkAct(mixed $verb, mixed $res, mixed $params = null, mixed $over = null): Obj
    {
        $a = AnalyzerJs::uobj(['verb' => $verb, 'res' => $res, 'params' => self::nullish($params) ? new Obj() : $params, 't' => self::num(0), 'sess' => 's',
            'prin' => 'p', 'org' => 'o', 'agent' => 'a', 'depth' => self::num(0)]);
        if ($over instanceof Obj) {
            foreach ($over->keys() as $k) {
                $a->set($k, $over->get($k));
            }
        } elseif (is_array($over) && !array_is_list($over)) {
            foreach ($over as $k => $v) {
                $a->set((string)$k, $v);
            }
        }
        return $a;
    }

    /** The reference decision of a goal for `{act, hist?, rels?}`: `{decision, witness, prohibited}`. */
    public static function decideCase(mixed $g, mixed $ont, mixed $c): Obj
    {
        $rels = self::j($c, 'rels');
        $hist = self::j($c, 'hist');
        if (AnalyzerJs::truthy($rels)) {
            $ont2 = AnalyzerJs::copy($ont);
            $ont2->set('rels', $rels);
        } else {
            $ont2 = $ont;
        }
        $x = GoalRefsem::refExplain($g, $ont2, self::j($c, 'act'), self::nullish($hist) ? self::emptyHist() : $hist);
        return Obj::of(['decision' => self::decisionOf($x->get('d')), 'witness' => $x->get('witness'), 'prohibited' => Js::num($x->get('prohibit')) < 2]);
    }

    /** The history of the admitted prefix of `acts` (an action the goal refuses is not recorded). */
    public static function replay(mixed $g, mixed $ont, mixed $acts, mixed $rels): Obj
    {
        $h = self::emptyHist();
        foreach (AnalyzerJs::reqList($acts) as $act) {
            $v = self::decideCase($g, $ont, Obj::of(['act' => $act, 'hist' => $h, 'rels' => $rels]));
            if ($v->get('decision') !== 'allow' || $v->get('witness') === null) {
                continue;
            }
            $h->set('adms', [...$h->get('adms'), Obj::of(['gid' => $v->get('witness'), 'act' => $act])]);
            $h->set('last', self::j($act, 't'));
        }
        return $h;
    }

    private static function qkey(mixed $q): string
    {
        $u = self::j($q, 'u');
        return self::j($u, 'k') === 'money' ? 'money:' . AnalyzerJs::jsStr(self::j($u, 'ccy')) : AnalyzerJs::jsStr(self::j($u, 'k'));
    }

    private static function unitOfKey(string $key): Obj
    {
        return str_starts_with($key, 'money:') ? Obj::of(['k' => 'money', 'ccy' => substr($key, 6)]) : Obj::of(['k' => $key]);
    }

    private static function dkey(mixed $v): ?string
    {
        return self::j($v, 'k') === 's' ? 's:' . AnalyzerJs::jsStr(self::j($v, 's')) : null;
    }

    /** Calls `$f(param, literal)` for every literal a condition compares a parameter against. */
    private static function walkCond(mixed $c, callable $f): void
    {
        $kind = self::j($c, 'k');
        switch (is_string($kind) ? $kind : '') {
            case 'cmp':
                $l = self::j($c, 'l');
                $r = self::j($c, 'r');
                $p = self::j($l, 'k') === 'param' ? self::j($l, 'path') : (self::j($r, 'k') === 'param' ? self::j($r, 'path') : null);
                $other = self::j($l, 'k') === 'param' ? $r : $l;
                if ($p === null || self::j($other, 'k') !== 'lit') {
                    return;
                }
                $v = self::j($other, 'v');
                if (self::j($v, 'k') === 'set') {
                    foreach (AnalyzerJs::reqList(self::j($v, 'items')) as $i) {
                        $f($p, $i);
                    }
                } else {
                    $f($p, $v);
                }
                return;
            case 'and':
            case 'or':
                self::walkCond(self::j($c, 'a'), $f);
                self::walkCond(self::j($c, 'b'), $f);
                return;
            case 'not':
                self::walkCond(self::j($c, 'c'), $f);
                return;
        }
    }

    /** @return list<mixed> */
    private static function partsOf(mixed $s): array
    {
        $k = self::j($s, 'k');
        return $k === 'all_of' ? AnalyzerJs::reqList(self::j($s, 'parts')) : ($k === 'any' ? [] : [$s]);
    }

    /** @param array<string,array{0:string,1:mixed}> $pairs 'k'.key => [key, value] @return Obj the pairs in JavaScript own-key order */
    private static function ordObj(array $pairs): Obj
    {
        $keys = array_map(static fn($p) => $p[0], array_values($pairs));
        $o = new Obj();
        foreach (Js::ownKeys($keys) as $k) {
            $o->set($k, $pairs['k' . $k][1]);
        }
        return $o;
    }

    /** @return list<mixed> */
    private static function sortedU16(array $xs): array
    {
        $xs = array_values($xs);
        usort($xs, static fn($a, $b) => AnalyzerJs::u16cmp($a, $b));
        return $xs;
    }

    /** The decision-space of a set of goals: every verb, resource, relation and parameter literal they mention. */
    public static function buildSpace(mixed $goals, mixed $extraVerbs = null): Obj
    {
        $verbs = [];
        $resources = [];
        $rels = [];
        $q = [];
        $d = [];
        $addVerb = static function (mixed $v) use (&$verbs): void {
            $s = AnalyzerJs::jsStr($v);
            $verbs['k' . $s] = $s;
        };
        foreach (self::nullish($extraVerbs) ? [] : AnalyzerJs::reqList($extraVerbs) as $v) {
            $addVerb($v);
        }
        $lit = static function (mixed $p, mixed $v) use (&$q, &$d): void {
            $ps = AnalyzerJs::jsStr($p);
            if (self::j($v, 'k') === 'q') {
                $ql = self::j($v, 'q');
                $key = self::qkey($ql);
                $n = Js::num(self::j($ql, 'n'));
                if ($n === null) {
                    throw new \TypeError('a quantity literal must be a number');
                }
                $n += 0.0;
                $q['k' . $ps] ??= ['p' => $ps, 'u' => []];
                $q['k' . $ps]['u']['k' . $key] ??= ['u' => $key, 's' => []];
                $q['k' . $ps]['u']['k' . $key]['s'][var_export($n, true)] = $n;
            } elseif (($k = self::dkey($v)) !== null) {
                $d['k' . $ps] ??= ['p' => $ps, 's' => []];
                $d['k' . $ps]['s']['k' . $k] = $k;
            }
        };
        $res = static function (mixed $s) use (&$resources, &$rels): void {
            foreach (self::partsOf($s) as $x) {
                $k = self::j($x, 'k');
                if ($k === 'exact') {
                    $id = AnalyzerJs::jsStr(self::j($x, 'id'));
                    $resources['k' . $id] = $id;
                } elseif ($k === 'oneof') {
                    foreach (AnalyzerJs::reqList(self::j($x, 'ids')) as $i) {
                        $id = AnalyzerJs::jsStr($i);
                        $resources['k' . $id] = $id;
                    }
                } else {
                    $rels[AnalyzerJs::jsStr(self::j($x, 'rel')) . "\0" . AnalyzerJs::jsStr(self::j($x, 'anchor'))] = AnalyzerJs::uobj(['rel' => self::j($x, 'rel'), 'anchor' => self::j($x, 'anchor')]);
                }
            }
        };
        foreach (AnalyzerJs::reqList($goals) as $g) {
            foreach (AnalyzerJs::reqList(self::j($g, 'grants')) as $gr) {
                $addVerb(self::j($gr, 'verb'));
                $res(self::j($gr, 'res'));
                self::walkCond(self::j($gr, 'cond'), $lit);
            }
            foreach (AnalyzerJs::reqList(self::j($g, 'prohibits')) as $p) {
                $t = self::j($p, 'target');
                if (self::j($t, 'k') === 'verb') {
                    $addVerb(self::j($t, 'verb'));
                }
                $res(self::j($p, 'res'));
                self::walkCond(self::j($p, 'cond'), $lit);
            }
            foreach (AnalyzerJs::reqList(self::j($g, 'escalateOn')) as $c) {
                self::walkCond($c, $lit);
            }
            foreach (AnalyzerJs::reqList(self::j($g, 'bounds')) as $b) {
                $v = self::j($b, 'value');
                // reps around the cap so witnesses carry the summed param
                if (self::j($b, 'agg') === 'sum' && self::j($v, 'k') === 'param') {
                    $lit(self::j($v, 'path'), Obj::of(['k' => 'q', 'q' => self::j($b, 'cap')]));
                }
            }
        }
        $relList = GoalJs::stableSort(array_values($rels), static fn($a, $b) => AnalyzerJs::u16cmp(
            AnalyzerJs::jsStr(self::j($a, 'rel')) . AnalyzerJs::jsStr(self::j($a, 'anchor')), AnalyzerJs::jsStr(self::j($b, 'rel')) . AnalyzerJs::jsStr(self::j($b, 'anchor'))));
        $qp = [];
        foreach ($q as $e) {
            $units = [];
            foreach ($e['u'] as $u) {
                $vals = array_values($u['s']);
                sort($vals);
                $units['k' . $u['u']] = [$u['u'], array_map(self::num(...), $vals)];
            }
            $qp['k' . $e['p']] = [$e['p'], self::ordObj($units)];
        }
        $dp = [];
        foreach ($d as $e) {
            $dp['k' . $e['p']] = [$e['p'], self::sortedU16($e['s'])];
        }
        return Obj::of(['verbs' => self::sortedU16($verbs), 'resources' => self::sortedU16($resources), 'rels' => $relList, 'q' => self::ordObj($qp), 'd' => self::ordObj($dp)]);
    }

    private static function get(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : null;
    }

    private static function classifyLit(Obj $sp, string $p, mixed $l): string
    {
        if ($l instanceof Undef || self::j($l, 'k') === 'set') {
            return 'missing';
        }
        $groups = self::get($sp->get('q'), $p);
        $ds = self::get($sp->get('d'), $p);
        if (self::j($l, 'k') === 'q') {
            $key = self::qkey(self::j($l, 'q'));
            $g = self::get($groups, $key);
            if ($g === null) {
                return $groups !== null || $ds !== null ? 'unit' : 'any';
            }
            $v = Js::num(self::j(self::j($l, 'q'), 'n'));
            if ($v === null) {
                throw new \TypeError('a quantity literal must be a number');
            }
            foreach ($g as $i => $x) {
                if (Js::num($x) == $v) {
                    return "$key=$i";
                }
            }
            $pos = 0;
            while ($pos < count($g) && Js::num($g[$pos]) < $v) {
                $pos++;
            }
            return "$key@$pos"; // strictly between literal pos-1 and pos
        }
        $k = self::dkey($l);
        if ($ds === null) {
            return $groups === null ? 'any' : 'unit';
        }
        return $k !== null && in_array($k, $ds, true) ? $k : 'other';
    }

    private static function relBit(mixed $c, mixed $rel, mixed $anchor): int
    {
        foreach (AnalyzerJs::reqList(self::j($c, 'rels')) as $x) {
            if (AnalyzerJs::strictEq(self::j($x, 'rel'), $rel) && AnalyzerJs::strictEq(self::j($x, 'anchor'), $anchor)) {
                return AnalyzerJs::includes(self::j($x, 'members'), self::j(self::j($c, 'act'), 'res')) ? 1 : 0;
            }
        }
        return 0;
    }

    /** @return list<string> */
    private static function paramsOf(Obj $sp): array
    {
        return self::sortedU16(array_values(array_unique([...$sp->get('q')->keys(), ...$sp->get('d')->keys()])));
    }

    /** The decision cell of a case under a space (canonical string; the unit of precedents). */
    public static function cellKey(mixed $sp, mixed $c): string
    {
        $act = self::j($c, 'act');
        $params = self::j($act, 'params');
        $p = new Obj();
        foreach (self::paramsOf($sp) as $name) {
            $p->set($name, self::classifyLit($sp, $name, $params instanceof Obj && $params->has($name) ? $params->get($name) : AnalyzerJs::undef()));
        }
        $rels = [];
        foreach ($sp->get('rels') as $x) {
            $rels[] = self::num(self::relBit($c, self::j($x, 'rel'), self::j($x, 'anchor')));
        }
        return GoalNormalize::stable(Obj::of([
            'v' => AnalyzerJs::includes($sp->get('verbs'), self::j($act, 'verb')) ? self::j($act, 'verb') : '*',
            'r' => AnalyzerJs::includes($sp->get('resources'), self::j($act, 'res')) ? self::j($act, 'res') : '*',
            'l' => $rels, 'p' => $p,
        ]));
    }

    /** @return list<mixed> the parameter's literals around every mentioned value; null = the parameter is absent */
    private static function paramOptions(Obj $sp, string $p): array
    {
        $out = [null];
        $seen = [];
        $add = static function (Obj $v) use (&$out, &$seen): void {
            $k = GoalNormalize::stable($v);
            if (isset($seen['k' . $k])) {
                return;
            }
            $seen['k' . $k] = true;
            $out[] = $v;
        };
        $qp = self::get($sp->get('q'), $p);
        if ($qp instanceof Obj) {
            foreach ($qp->keys() as $key) {
                $isInstant = $key === 'instant';
                foreach ($qp->get($key) as $nv) {
                    $v = Js::num($nv);
                    foreach ([$v - 1, $v, $v + 1] as $x) {
                        if ($x >= 0 || $isInstant) {
                            $add(Obj::of(['k' => 'q', 'q' => Obj::of(['u' => self::unitOfKey($key), 'n' => self::num($x)])]));
                        }
                    }
                }
                if (str_starts_with($key, 'money:')) {
                    $add(Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => 'ZZZ']), 'n' => self::num(0)])])); // unit mismatch -> Unknown
                }
            }
        }
        foreach (self::get($sp->get('d'), $p) ?? [] as $k) {
            $add(Obj::of(['k' => 's', 's' => substr($k, 2)]));
        }
        if ($sp->get('d')->has($p)) {
            $add(Obj::of(['k' => 's', 's' => self::OTHER]));
        }
        return $out;
    }

    /** One representative per decision cell. `complete` is false when the grid exceeded MAX_CELLS (then it is a subset). */
    public static function cells(mixed $sp, mixed $opts = null): Obj
    {
        $vs = Js::opt($opts, 'verbs');
        $verbs = $vs === null ? [...$sp->get('verbs'), "\0other-verb"] : AnalyzerJs::reqList($vs);
        $resources = [...$sp->get('resources'), "\0other-resource"];
        $params = self::paramsOf($sp);
        $pOpts = array_map(static fn($p) => self::paramOptions($sp, $p), $params);
        $relBits = count($sp->get('rels'));
        $total = count($verbs) * count($resources) * (2 ** $relBits);
        foreach ($pOpts as $o) {
            $total *= count($o);
        }
        $complete = $total <= self::MAX_CELLS;
        $out = [];
        $seen = [];
        $push = static function (Obj $c) use (&$out, &$seen, $sp): void {
            $k = self::cellKey($sp, $c);
            if (!isset($seen['k' . $k])) {
                $seen['k' . $k] = true;
                $out[] = $c;
            }
        };
        $build = static function (mixed $verb, mixed $resource, int $bits, array $choice) use ($params, $sp): Obj {
            $pr = new Obj();
            foreach ($params as $i => $p) {
                if ($choice[$i] !== null) {
                    $pr->set($p, $choice[$i]);
                }
            }
            $rels = [];
            foreach ($sp->get('rels') as $i => $x) {
                $rels[] = Obj::of(['rel' => $x->get('rel'), 'anchor' => $x->get('anchor'), 'members' => ($bits & (1 << $i)) === 0 ? [] : [$resource]]);
            }
            return Obj::of(['act' => self::mkAct($verb, $resource, $pr), 'rels' => $rels]);
        };
        if ($complete) {
            foreach ($verbs as $verb) {
                foreach ($resources as $res) {
                    for ($bits = 0; $bits < 2 ** $relBits; $bits++) {
                        $idx = array_fill(0, count($params), 0);
                        while (true) {
                            $choice = [];
                            foreach ($idx as $i => $jx) {
                                $choice[] = $pOpts[$i][$jx];
                            }
                            $push($build($verb, $res, $bits, $choice));
                            $k = 0;
                            while ($k < count($idx)) {
                                $idx[$k]++;
                                if ($idx[$k] !== count($pOpts[$k])) {
                                    break;
                                }
                                $idx[$k] = 0;
                                $k++;
                            }
                            if ($k === count($idx)) {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            $base = static fn(): array => array_map(static fn($o) => $o[min(2, count($o) - 1)], $pOpts);
            foreach ($verbs as $verb) {
                $push($build($verb, $resources[0], 0, $base()));
                foreach ($resources as $res) {
                    for ($bits = 0; $bits < 2 ** $relBits; $bits++) {
                        $push($build($verb, $res, $bits, $base()));
                    }
                }
                foreach ($pOpts as $i => $o) {
                    foreach ($o as $l) {
                        $ch = $base();
                        $ch[$i] = $l;
                        $push($build($verb, $resources[0], 0, $ch));
                    }
                }
            }
        }
        return Obj::of(['cases' => $out, 'complete' => $complete]);
    }

    private static function magnitude(mixed $a): float
    {
        $s = 0.0;
        $params = self::j($a, 'params');
        foreach ($params instanceof Obj ? $params->keys() : [] as $k) {
            $v = $params->get($k);
            $s += self::j($v, 'k') === 'q' ? abs((float)Js::num(self::j(self::j($v, 'q'), 'n'))) : 0.0;
        }
        return $s;
    }

    /** The smallest-magnitude case the grant admits (a minimal Allow witness), or null if its Allow set is empty. */
    public static function allowWitness(mixed $g, mixed $gr, mixed $ont): ?Obj
    {
        $sp = self::buildSpace([$g]);
        $best = null;
        foreach (self::cells($sp, Obj::of(['verbs' => [self::j($gr, 'verb')]]))->get('cases') as $c) {
            $v = self::decideCase($g, $ont, $c);
            if ($v->get('decision') === 'allow' && AnalyzerJs::strictEq($v->get('witness'), self::j($gr, 'gid'))
                && ($best === null || self::magnitude($c->get('act')) < self::magnitude($best->get('act')))) {
                $best = $c;
            }
        }
        return $best;
    }

    /** `Math.floor(a / b)` with JavaScript division (x / 0 is +-Infinity, 0 / 0 is NaN). */
    private static function fdivFloor(float $a, float $b): float
    {
        if ($b == 0.0) {
            return $a == 0.0 || is_nan($a) ? NAN : ($a > 0 ? INF : -INF);
        }
        return floor($a / $b);
    }

    /** The full example set: decision-cell representatives, cap sequences and unmentioned-dimension probes. */
    public static function boundaryExamples(mixed $g, mixed $opts): Obj
    {
        $ont = Js::opt($opts, 'ont');
        $extra = Js::opt($opts, 'extra');
        $goals = [$g, ...($extra === null ? [] : AnalyzerJs::reqList($extra))];
        $sp = self::buildSpace($goals, Js::opt($opts, 'verbs') ?? []);
        $c = self::cells($sp);
        $out = [];
        $add = static function (string $kind, string $why, Obj $cs, ?Obj $hist = null) use (&$out, $g, $ont): void {
            $h = $hist ?? self::emptyHist();
            $out[] = Obj::of(['id' => $kind . ':' . substr(Pca::hashCanonical(Obj::of(['act' => $cs->get('act'), 'hist' => $h, 'rels' => $cs->get('rels')])), 0, 12),
                'kind' => $kind, 'why' => $why, 'act' => $cs->get('act'), 'hist' => $h, 'rels' => $cs->get('rels'),
                'decision' => self::decideCase($g, $ont, Obj::of(['act' => $cs->get('act'), 'hist' => $h, 'rels' => $cs->get('rels')]))->get('decision')]);
        };
        foreach ($c->get('cases') as $cs) {
            $v = self::decideCase($g, $ont, $cs);
            $dec = $v->get('decision');
            $add($v->get('prohibited') && $dec === 'deny' ? 'prohibit_trigger' : ($dec === 'allow' ? 'member' : 'boundary'), "cell $dec", $cs);
        }
        foreach (AnalyzerJs::reqList(self::j($g, 'grants')) as $gr) {
            $w = self::allowWitness($g, $gr, $ont);
            if ($w !== null) {
                $add('allow_witness', 'minimal Allow witness of grant ' . AnalyzerJs::jsStr(self::j($gr, 'gid')), $w);
            }
        }
        foreach (AnalyzerJs::reqList(self::j($g, 'bounds')) as $b) {
            $sel = self::j($b, 'sel');
            $gids = self::j($sel, 'k') === 'gids' ? self::j($sel, 'gids') : [];
            $gr = null;
            foreach (AnalyzerJs::reqList(self::j($g, 'grants')) as $x) {
                if (AnalyzerJs::includes($gids, self::j($x, 'gid'))) {
                    $gr = $x;
                    break;
                }
            }
            $w = $gr === null ? null : self::allowWitness($g, $gr, $ont);
            if ($w === null) {
                continue;
            }
            $capN = (float)Js::num(self::j(self::j($b, 'cap'), 'n'));
            if (self::j($b, 'agg') === 'count') {
                $per = 1.0;
            } else {
                $val = self::j($b, 'value');
                $wp = self::j($w->get('act'), 'params');
                $v = self::j($val, 'k') === 'param' ? ($wp instanceof Obj && is_string(self::j($val, 'path')) && $wp->has(self::j($val, 'path')) ? $wp->get(self::j($val, 'path')) : AnalyzerJs::undef()) : AnalyzerJs::undef();
                $per = !($v instanceof Undef) && AnalyzerJs::truthy($v) && self::j($v, 'k') === 'q' ? (float)Js::num(self::j(self::j($v, 'q'), 'n')) : 0.0;
            }
            if (self::j($b, 'agg') === 'sum' && $per <= 0) {
                continue;
            }
            $n = self::fdivFloor($capN, $per);
            if ($n > 60) {
                continue; // sequence too long to review; the aggregate theorem (not examples) covers it
            }
            $count = is_finite($n) ? (int)$n : 0;
            $add('cap_sequence', 'reach the ' . AnalyzerJs::jsStr(self::j($b, 'bid')) . ' cap with ' . AnalyzerJs::jsStr($n) . ' action(s), then one more', $w,
                self::replay($g, $ont, array_fill(0, max($count, 0), $w->get('act')), $w->get('rels')));
        }
        foreach (AnalyzerJs::reqList(self::j($g, 'grants')) as $gr) { // unmentioned-dimension probes: extreme amount, other resource, other relation anchor
            $w = self::allowWitness($g, $gr, $ont);
            if ($w === null) {
                continue;
            }
            $wact = $w->get('act');
            $wparams = self::j($wact, 'params');
            foreach ($wparams instanceof Obj ? $wparams->keys() : [] as $p) {
                $l = $wparams->get($p);
                if (!(self::j($l, 'k') === 'q' && self::j(self::j(self::j($l, 'q'), 'u'), 'k') === 'money')) {
                    continue;
                }
                $q2 = AnalyzerJs::copy($l->get('q'));
                $q2->set('n', self::num(1000000000));
                $params2 = AnalyzerJs::copy($wparams);
                $params2->set($p, Obj::of(['k' => 'q', 'q' => $q2]));
                $act = AnalyzerJs::copy($wact);
                $act->set('params', $params2);
                $w2 = AnalyzerJs::copy($w);
                $w2->set('act', $act);
                $add('probe', "extreme $p", $w2);
            }
            $nothing = array_map(static function ($r): Obj {
                $c2 = AnalyzerJs::copy($r);
                $c2->set('members', []);
                return $c2;
            }, AnalyzerJs::reqList($w->get('rels')));
            $act2 = AnalyzerJs::copy($wact);
            $act2->set('res', "\0other-resource");
            $add('probe', 'other resource', Obj::of(['act' => $act2, 'rels' => $nothing]));
            $add('probe', 'other customer/anchor', Obj::of(['act' => $wact, 'rels' => $nothing]));
        }
        $seen = [];
        $res = [];
        foreach ($out as $e) {
            if (!isset($seen['k' . $e->get('id')])) {
                $seen['k' . $e->get('id')] = true;
                $res[] = $e;
            }
        }
        return Obj::of(['examples' => $res, 'complete' => $c->get('complete')]);
    }

    /** Cap examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable. */
    public static function reviewSet(mixed $examples, mixed $cap): array
    {
        $n = Js::num($cap);
        if ($n === null || $n < 0) {
            throw new \InvalidArgumentException('a review cap is a non-negative number');
        }
        $sorted = GoalJs::stableSort(AnalyzerJs::reqList($examples), static function ($a, $b): int {
            $x = self::rankOf(self::j($a, 'decision')) <=> self::rankOf(self::j($b, 'decision'));
            if ($x !== 0) {
                return $x;
            }
            $x = self::KIND_W[self::j($a, 'kind')] <=> self::KIND_W[self::j($b, 'kind')];
            return $x !== 0 ? $x : AnalyzerJs::u16cmp(self::j($a, 'id'), self::j($b, 'id'));
        });
        return array_slice($sorted, 0, (int)$n);
    }

    public static function expectedDecision(mixed $a): string
    {
        return $a === 'allow' ? 'allow' : ($a === 'deny' ? 'deny' : 'escalate');
    }

    /** Order-independent digest of a test list. */
    public static function testsDigest(mixed $tests): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-tests/v1',
            'tests' => GoalJs::stableSort(AnalyzerJs::reqList($tests), static fn($a, $b) => AnalyzerJs::u16cmp(self::j($a, 'id'), self::j($b, 'id')))]));
    }

    /** The test set of the confirmed examples (`[{example, answer}]`) of a goal. */
    public static function makeGoalTests(mixed $g, mixed $confirmed): Obj
    {
        $tests = [];
        foreach (AnalyzerJs::reqList($confirmed) as $c) {
            $e = self::j($c, 'example');
            $tests[] = AnalyzerJs::uobj(['id' => self::j($e, 'id'), 'act' => self::j($e, 'act'), 'hist' => self::j($e, 'hist'), 'rels' => self::j($e, 'rels'), 'answer' => self::j($c, 'answer')]);
        }
        return Obj::of(['goal_digest' => GoalDigests::goalDigest($g), 'ontology_digest' => self::j($g, 'ontDigest'), 'tests' => $tests, 'tests_digest' => self::testsDigest($tests)]);
    }

    /** Signs a test set; `$opts` carries the signer suite (`alg`, `pq`). */
    public static function signGoalTests(mixed $s, mixed $secret, mixed $opts = null): Obj
    {
        return GoalSign::signPayload('goal-tests', $s, $secret, $opts);
    }

    /** Recompile check: any recompile must reproduce every confirmed test or the policy is refused. `$decideFn(test)` returns a decision. */
    public static function checkGoalTests(mixed $s, mixed $pins, callable $decideFn): Obj
    {
        if (!GoalSign::verifyPayload($s, 'goal-tests', $pins)) {
            return Obj::of(['ok' => false, 'reason' => 'signature', 'failures' => []]);
        }
        $pl = self::j($s, 'payload');
        if (!AnalyzerJs::strictEq(self::testsDigest(self::j($pl, 'tests')), self::j($pl, 'tests_digest'))) {
            return Obj::of(['ok' => false, 'reason' => 'tests_digest', 'failures' => []]);
        }
        $failures = [];
        foreach (AnalyzerJs::reqList(self::j($pl, 'tests')) as $t) {
            $got = $decideFn($t);
            $want = self::expectedDecision(self::j($t, 'answer'));
            if ($got !== $want) {
                $failures[] = Obj::of(['id' => self::j($t, 'id'), 'expected' => $want, 'got' => $got]);
            }
        }
        return $failures === [] ? Obj::of(['ok' => true, 'failures' => $failures]) : Obj::of(['ok' => false, 'reason' => 'test_regression', 'failures' => $failures]);
    }

    /** The pin: the policy version cannot silently change under a signed test set. */
    public static function signPin(mixed $p, mixed $secret, mixed $opts = null): Obj
    {
        return GoalSign::signPayload('policy-pin', $p, $secret, $opts);
    }

    public static function checkPin(mixed $pin, mixed $pins, mixed $cur): Obj
    {
        if (!GoalSign::verifyPayload($pin, 'policy-pin', $pins)) {
            return Obj::of(['ok' => false, 'reason' => 'signature']);
        }
        $p = self::j($pin, 'payload');
        $goal = self::j($cur, 'goal');
        $tests = self::j($cur, 'tests');
        if (!AnalyzerJs::strictEq(self::j($p, 'goal_digest'), GoalDigests::goalDigest($goal))) {
            return Obj::of(['ok' => false, 'reason' => 'goal changed under the pin']);
        }
        if (!AnalyzerJs::strictEq(self::j($p, 'policy_digest'), self::j($cur, 'policy_digest'))) {
            return Obj::of(['ok' => false, 'reason' => 'policy changed under the pin']);
        }
        if (!AnalyzerJs::strictEq(self::j($p, 'tests_digest'), self::j($tests, 'tests_digest')) || !AnalyzerJs::strictEq(self::j($p, 'tests_digest'), self::testsDigest(self::j($tests, 'tests')))) {
            return Obj::of(['ok' => false, 'reason' => 'tests changed under the pin']);
        }
        if (!AnalyzerJs::strictEq(self::j($p, 'ontology_digest'), self::j($goal, 'ontDigest'))) {
            return Obj::of(['ok' => false, 'reason' => 'ontology changed under the pin']);
        }
        return Obj::of(['ok' => true]);
    }
}
