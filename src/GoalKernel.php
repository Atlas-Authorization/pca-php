<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/GoalIrError.php';

/** Raised inside the tape reader when the tape does not decode (the reference's Fail). */
final class GoalKernelFail extends \Exception
{
}

/**
 * Fixed-order cursor over a token tape. Any mismatch throws {@see GoalKernelFail}. Terms, conditions, values and selectors are
 * tagged lists (['param', path, ty], ['cmp', op, l, r], ...); records are associative arrays.
 */
final class GoalKernelReader
{
    private int $i = 0;

    /** @param list<array{0:string,1:int|string}> $ts */
    public function __construct(private readonly array $ts)
    {
    }

    private function fail(): never
    {
        throw new GoalKernelFail();
    }

    public function rest(): int
    {
        return count($this->ts) - $this->i;
    }

    public function done(): bool
    {
        return $this->i >= count($this->ts);
    }

    private function tok(): array
    {
        if (!isset($this->ts[$this->i])) {
            $this->fail();
        }
        return $this->ts[$this->i++];
    }

    public function str(): string
    {
        $t = $this->tok();
        return $t[0] === 's' ? $t[1] : $this->fail();
    }

    public function int(): int
    {
        $t = $this->tok();
        return $t[0] === 'i' ? $t[1] : $this->fail();
    }

    public function kw(): int
    {
        $t = $this->tok();
        return $t[0] === 'k' ? $t[1] : $this->fail();
    }

    private function expect(int $k): void
    {
        if ($this->kw() !== $k) {
            $this->fail();
        }
    }

    public function bool(): bool
    {
        $v = $this->int();
        return $v === 0 || $v === 1 ? $v === 1 : $this->fail();
    }

    public function lst(callable $f): array
    {
        $n = $this->int();
        if ($n < 0) {
            $this->fail();
        }
        $out = [];
        for ($k = 0; $k < $n; $k++) {
            $out[] = $f();
        }
        return $out;
    }

    public function strs(): array
    {
        return $this->lst(fn() => $this->str());
    }

    public function unit(): array
    {
        return match ($this->kw()) {
            300 => ['money', $this->str()],
            301 => ['count'],
            302 => ['duration'],
            303 => ['instant'],
            304 => ['bytes'],
            305 => ['ratio'],
            default => $this->fail(),
        };
    }

    public function q(): array
    {
        $u = $this->unit();
        return ['u' => $u, 'n' => $this->int()];
    }

    public function ty(): array
    {
        return match ($this->kw()) {
            310 => ['tyq', $this->unit()],
            311 => ['tys'],
            default => $this->fail(),
        };
    }

    public function atom(): array
    {
        return match ($this->kw()) {
            320 => ['aq', $this->q()],
            321 => ['as', $this->str()],
            default => $this->fail(),
        };
    }

    public function val(): array
    {
        return match ($this->kw()) {
            330 => ['vq', $this->q()],
            331 => ['vs', $this->str()],
            332 => ['vset', $this->lst(fn() => $this->atom())],
            default => $this->fail(),
        };
    }

    public function term(): array
    {
        switch ($this->kw()) {
            case 340:
                $s = $this->str();
                return ['param', $s, $this->ty()];
            case 341:
                return ['lit', $this->val()];
            case 342:
                $s = $this->str();
                return ['hist_agg', $s, $this->unit()];
            default:
                $this->fail();
        }
    }

    public function op(): string
    {
        $k = $this->kw();
        return $k >= 350 && $k <= 357 ? GoalKernel::OPS_BY_KW[$k - 350] : $this->fail();
    }

    public function cond(int $fuel): array
    {
        if ($fuel === 0) {
            $this->fail();
        }
        switch ($this->kw()) {
            case 360:
                return ['ctrue'];
            case 361:
                $o = $this->op();
                $l = $this->term();
                return ['cmp', $o, $l, $this->term()];
            case 362:
                $x = $this->cond($fuel - 1);
                return ['and', $x, $this->cond($fuel - 1)];
            case 363:
                $x = $this->cond($fuel - 1);
                return ['or', $x, $this->cond($fuel - 1)];
            case 364:
                return ['not', $this->cond($fuel - 1)];
            default:
                $this->fail();
        }
    }

    public function condTop(): array
    {
        return $this->cond($this->rest());
    }

    public function part(): array
    {
        switch ($this->kw()) {
            case 375:
                return ['pexact', $this->str()];
            case 376:
                return ['poneof', $this->strs()];
            case 377:
                $a = $this->str();
                return ['prelated', $a, $this->str()];
            default:
                $this->fail();
        }
    }

    public function resSel(): array
    {
        switch ($this->kw()) {
            case 370:
                return ['exact', $this->str()];
            case 371:
                return ['oneof', $this->strs()];
            case 372:
                $a = $this->str();
                return ['related', $a, $this->str()];
            case 373:
                return ['anyres', $this->str()];
            case 374:
                return ['allof', $this->lst(fn() => $this->part())];
            default:
                $this->fail();
        }
    }

    public function grant(): array
    {
        $this->expect(380);
        $gid = $this->str();
        $verb = $this->str();
        $res = $this->resSel();
        return ['gid' => $gid, 'verb' => $verb, 'res' => $res, 'cond' => $this->condTop()];
    }

    public function prohTarget(): array
    {
        return match ($this->kw()) {
            390 => ['pverb', $this->str()],
            391 => ['peffect', $this->str()],
            default => $this->fail(),
        };
    }

    public function prohibit(): array
    {
        $this->expect(392);
        $pid = $this->str();
        $target = $this->prohTarget();
        $res = $this->resSel();
        return ['pid' => $pid, 'target' => $target, 'res' => $res, 'cond' => $this->condTop()];
    }

    public function sel(): array
    {
        return match ($this->kw()) {
            410 => ['sel_gids', $this->strs()],
            411 => ['sel_effect', $this->str()],
            default => $this->fail(),
        };
    }

    public function window(): array
    {
        switch ($this->kw()) {
            case 420:
                return ['wtask'];
            case 421:
                return ['wsliding', $this->int()];
            case 422:
                $ms = $this->int();
                return ['wperiod', $ms, $this->int()];
            case 423:
                return ['wlifetime'];
            default:
                $this->fail();
        }
    }

    public function scope(): array
    {
        return match ($this->kw()) {
            430 => ['ssession'],
            431 => ['sprincipal'],
            432 => ['sorg'],
            433 => ['sfleet', $this->strs()],
            default => $this->fail(),
        };
    }

    public function onExceed(): string
    {
        return match ($this->kw()) {
            440 => 'on_deny',
            441 => 'on_escalate',
            default => $this->fail(),
        };
    }

    public function agg(): string
    {
        $k = $this->kw();
        return $k >= 400 && $k <= 403 ? GoalKernel::AGGS[$k - 400] : $this->fail();
    }

    public function bcore(): array
    {
        $this->expect(450);
        $agg = $this->agg();
        $value = $this->term();
        $key = $this->str();
        $window = $this->window();
        $scope = $this->scope();
        $cap = $this->q();
        return ['agg' => $agg, 'value' => $value, 'key' => $key, 'window' => $window, 'scope' => $scope, 'cap' => $cap, 'onExceed' => $this->onExceed()];
    }

    public function bound(): array
    {
        $this->expect(451);
        $bid = $this->str();
        $sel = $this->sel();
        return ['bid' => $bid, 'sel' => $sel, 'core' => $this->bcore()];
    }

    public function validity(): array
    {
        $this->expect(460);
        $nb = $this->int();
        $na = $this->int();
        return ['notBefore' => $nb, 'notAfter' => $na, 'maxIdle' => $this->int()];
    }

    public function deleg(): array
    {
        $this->expect(461);
        $d = $this->int();
        $n = $this->bool();
        return ['maxDepth' => $d, 'narrowOnly' => $n, 'mayTouch' => $this->strs()];
    }

    public function hole(): array
    {
        $this->expect(470);
        $hid = $this->str();
        $q = $this->str();
        $domain = $this->strs();
        $affects = $this->strs();
        return ['hid' => $hid, 'q' => $q, 'domain' => $domain, 'affects' => $affects, 'global' => $this->bool()];
    }

    public function goal(): array
    {
        if ($this->rest() < 5) {
            $this->fail();
        }
        $this->expect(480);
        $v = $this->int();
        $principal = $this->str();
        $ontD = $this->str();
        $nlD = $this->str();
        $sources = $this->strs();
        $grants = $this->lst(fn() => $this->grant());
        $prohibits = $this->lst(fn() => $this->prohibit());
        $bounds = $this->lst(fn() => $this->bound());
        $validity = $this->validity();
        $deleg = $this->deleg();
        $esc = $this->lst(fn() => $this->condTop());
        $wild = $this->strs();
        return ['v' => $v, 'principal' => $principal, 'ontDigest' => $ontD, 'nlDigest' => $nlD, 'sources' => $sources, 'grants' => $grants,
            'prohibits' => $prohibits, 'bounds' => $bounds, 'validity' => $validity, 'deleg' => $deleg, 'escalateOn' => $esc,
            'wildcardAck' => $wild, 'holes' => $this->lst(fn() => $this->hole())];
    }

    public function paramDecl(): array
    {
        $this->expect(500);
        $p = $this->str();
        return ['path' => $p, 'ty' => $this->ty()];
    }

    public function verbDecl(): array
    {
        $this->expect(501);
        $v = $this->str();
        $c = $this->str();
        return ['verb' => $v, 'cls' => $c, 'params' => $this->lst(fn() => $this->paramDecl())];
    }

    public function relDecl(): array
    {
        $this->expect(502);
        $r = $this->str();
        $a = $this->str();
        return ['rel' => $r, 'anchor' => $a, 'members' => $this->strs()];
    }

    public function ontology(): array
    {
        $this->expect(510);
        $vs = $this->lst(fn() => $this->verbDecl());
        return ['verbs' => $vs, 'rels' => $this->lst(fn() => $this->relDecl())];
    }

    /** The first entry of a key wins (the reference applies the head over the decoded tail). */
    public function keyed(int $kwn, callable $f): array
    {
        $out = [];
        $pairs = $this->lst(function () use ($kwn, $f) {
            $this->expect($kwn);
            $k = $this->str();
            return [$k, $f()];
        });
        foreach ($pairs as [$k, $v]) {
            if (!array_key_exists($k, $out)) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    public function act(): array
    {
        $this->expect(530);
        $verb = $this->str();
        $res = $this->str();
        $params = $this->keyed(520, fn() => $this->val());
        $t = $this->int();
        $sess = $this->str();
        $prin = $this->str();
        $org = $this->str();
        $agent = $this->str();
        return ['verb' => $verb, 'res' => $res, 'params' => $params, 't' => $t, 'sess' => $sess, 'prin' => $prin, 'org' => $org,
            'agent' => $agent, 'depth' => $this->int()];
    }

    public function adm(): array
    {
        $this->expect(531);
        $gid = $this->str();
        return ['gid' => $gid, 'act' => $this->act()];
    }

    public function hist(): array
    {
        $this->expect(541);
        $adms = $this->lst(fn() => $this->adm());
        $last = $this->int();
        return ['adms' => $adms, 'last' => $last, 'aggs' => $this->keyed(540, fn() => $this->q())];
    }
}

/**
 * The goal kernel (the TypeScript reference is the verified-core goal bridge over the proved goal compiler): typecheck / compile /
 * decide (reference semantics and compiled policy with its witness) / render over TOKEN TAPES. A tape is a list of
 * ['k', keyword] | ['i', integer] | ['s', string] tokens. First output token: i0 ok, i1 rejected with reasons, i9 malformed
 * input. A hand port checked against the reference's tape corpus.
 */
final class GoalKernel
{
    public const MAX_SAFE = 9007199254740991;
    public const OPS = ['typecheck', 'compile', 'decideg', 'decidep', 'render'];
    public const DENY = 0;
    public const ESCALATE = 1;
    public const ALLOW = 2;
    public const OPS_BY_KW = ['eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'nin'];
    public const AGGS = ['count', 'sum', 'max', 'distinct'];
    public const BAD = [['i', 9]];

    // ---- Kleene truth and decisions (false < unknown < true; Deny < Escalate < Allow)
    public static function b2t(bool $b): int
    {
        return $b ? 2 : 0;
    }

    public static function andK(int $a, int $b): int
    {
        return $a <= $b ? $a : $b;
    }

    public static function orK(int $a, int $b): int
    {
        return $a >= $b ? $a : $b;
    }

    public static function notK(int $a): int
    {
        return 2 - $a;
    }

    // ---- values, terms and conditions
    public static function atomV(array $a): array
    {
        return $a[0] === 'aq' ? ['vq', $a[1]] : ['vs', $a[1]];
    }

    public static function typeOfV(array $v): ?array
    {
        return match ($v[0]) {
            'vq' => ['tyq', $v[1]['u']],
            'vs' => ['tys'],
            default => null,
        };
    }

    private static function eqT(array $x, array $y): int
    {
        if ($x[0] === 'vq') {
            return $y[0] === 'vq' && $x[1]['u'] === $y[1]['u'] ? self::b2t($x[1]['n'] === $y[1]['n']) : 1;
        }
        if ($x[0] === 'vs') {
            return $y[0] === 'vs' ? self::b2t($x[1] === $y[1]) : 1;
        }
        return 1;
    }

    private static function ltT(array $x, array $y): int
    {
        return $x[0] === 'vq' && $y[0] === 'vq' && $x[1]['u'] === $y[1]['u'] ? self::b2t($x[1]['n'] < $y[1]['n']) : 1;
    }

    private static function inT(array $x, array $items): int
    {
        $m = 0;
        foreach ($items as $i) {
            $m = max($m, self::eqT($x, self::atomV($i)));
        }
        return $m;
    }

    private static function cmpT(string $op, ?array $x, ?array $y): int
    {
        if ($x === null || $y === null) {
            return 1;
        }
        return match ($op) {
            'eq' => self::eqT($x, $y),
            'ne' => self::notK(self::eqT($x, $y)),
            'lt' => self::ltT($x, $y),
            'gte' => self::notK(self::ltT($x, $y)),
            'gt' => self::ltT($y, $x),
            'lte' => self::notK(self::ltT($y, $x)),
            'in' => $y[0] === 'vset' ? self::inT($x, $y[1]) : 1,
            'nin' => self::notK($y[0] === 'vset' ? self::inT($x, $y[1]) : 1),
        };
    }

    private static function negOp(string $op): string
    {
        return ['eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'gte' => 'lt', 'gt' => 'lte', 'lte' => 'gt', 'in' => 'nin', 'nin' => 'in'][$op];
    }

    private static function evalT(array $t, array $a, array $h): ?array
    {
        return match ($t[0]) {
            'param' => $a['params'][$t[1]] ?? null,
            'lit' => $t[1],
            'hist_agg' => array_key_exists($t[1], $h['aggs']) ? ['vq', $h['aggs'][$t[1]]] : null,
        };
    }

    private static function evalC(array $c, array $a, array $h): int
    {
        return match ($c[0]) {
            'ctrue' => 2,
            'cmp' => self::cmpT($c[1], self::evalT($c[2], $a, $h), self::evalT($c[3], $a, $h)),
            'and' => self::andK(self::evalC($c[1], $a, $h), self::evalC($c[2], $a, $h)),
            'or' => self::orK(self::evalC($c[1], $a, $h), self::evalC($c[2], $a, $h)),
            'not' => self::notK(self::evalC($c[1], $a, $h)),
        };
    }

    private static function evalN(array $c, array $a, array $h): int
    {
        return match ($c[0]) {
            'ntrue' => 2,
            'nfalse' => 0,
            'natom' => self::cmpT($c[1], self::evalT($c[2], $a, $h), self::evalT($c[3], $a, $h)),
            'nand' => self::andK(self::evalN($c[1], $a, $h), self::evalN($c[2], $a, $h)),
            'nor' => self::orK(self::evalN($c[1], $a, $h), self::evalN($c[2], $a, $h)),
        };
    }

    /** pos = the polarity: nnf(c, false) is the normal form of `not c`. */
    public static function nnf(array $c, bool $pos): array
    {
        return match ($c[0]) {
            'ctrue' => $pos ? ['ntrue'] : ['nfalse'],
            'cmp' => ['natom', $pos ? $c[1] : self::negOp($c[1]), $c[2], $c[3]],
            'and' => $pos ? ['nand', self::nnf($c[1], true), self::nnf($c[2], true)] : ['nor', self::nnf($c[1], false), self::nnf($c[2], false)],
            'or' => $pos ? ['nor', self::nnf($c[1], true), self::nnf($c[2], true)] : ['nand', self::nnf($c[1], false), self::nnf($c[2], false)],
            'not' => self::nnf($c[1], !$pos),
        };
    }

    // ---- resource patterns
    private static function resOk(array $p, string $r): bool
    {
        return $p[0] === 'pstar' || in_array($r, $p[1], true);
    }

    private static function relMembers(array $rels, string $rel, string $anchor): array
    {
        foreach ($rels as $x) {
            if ($x['rel'] === $rel && $x['anchor'] === $anchor) {
                return $x['members'];
            }
        }
        return [];
    }

    private static function interPat(array $x, array $y): array
    {
        if ($x[0] === 'pstar') {
            return $y;
        }
        if ($y[0] === 'pstar') {
            return $x;
        }
        $o = [];
        foreach ($x[1] as $s) {
            if (in_array($s, $y[1], true)) {
                $o[] = $s;
            }
        }
        return ['pset', $o];
    }

    private static function resolvePart(array $ont, array $p): array
    {
        return match ($p[0]) {
            'pexact' => ['pset', [$p[1]]],
            'poneof' => ['pset', $p[1]],
            'prelated' => ['pset', self::relMembers($ont['rels'], $p[1], $p[2])],
        };
    }

    public static function resolveSel(array $ont, array $s): array
    {
        switch ($s[0]) {
            case 'exact':
                return ['pset', [$s[1]]];
            case 'oneof':
                return ['pset', $s[1]];
            case 'related':
                return ['pset', self::relMembers($ont['rels'], $s[1], $s[2])];
            case 'anyres':
                return ['pstar'];
            default:
                $acc = ['pstar'];
                foreach (array_reverse($s[1]) as $p) {
                    $acc = self::interPat(self::resolvePart($ont, $p), $acc);
                }
                return $acc;
        }
    }

    private static function verbsOfClass(array $vs, string $cls): array
    {
        $o = [];
        foreach ($vs as $v) {
            if ($v['cls'] === $cls) {
                $o[] = $v['verb'];
            }
        }
        return $o;
    }

    private static function resolveBsel(array $ont, array $s): array
    {
        return $s[0] === 'sel_gids' ? ['gids' => $s[1], 'verbs' => []] : ['gids' => [], 'verbs' => self::verbsOfClass($ont['verbs'], $s[1])];
    }

    private static function prohVerbs(array $ont, array $t): array
    {
        return $t[0] === 'pverb' ? [$t[1]] : self::verbsOfClass($ont['verbs'], $t[1]);
    }

    // ---- bounds
    private static function appliesL(array $s, string $gid, string $verb): bool
    {
        return in_array($gid, $s['gids'], true) || in_array($verb, $s['verbs'], true);
    }

    private static function inScope(array $sc, array $a, array $x): bool
    {
        return match ($sc[0]) {
            'ssession' => $a['sess'] === $x['sess'],
            'sprincipal' => $a['prin'] === $x['prin'],
            'sorg' => $a['org'] === $x['org'],
            'sfleet' => in_array($a['agent'], $sc[1], true) && in_array($x['agent'], $sc[1], true),
        };
    }

    private static function floorDiv(int $a, int $b): int
    {
        $q = intdiv($a, $b);
        return ($a % $b !== 0 && ($a < 0) !== ($b < 0)) ? $q - 1 : $q;
    }

    private static function inWindow(array $w, array $a, array $x): bool
    {
        return match ($w[0]) {
            'wtask', 'wlifetime' => true,
            'wsliding' => $x['t'] > $a['t'] - $w[1] && $x['t'] <= $a['t'],
            'wperiod' => $w[1] > 0 && self::floorDiv($a['t'] - $w[2], $w[1]) === self::floorDiv($x['t'] - $w[2], $w[1]),
        };
    }

    /** The admitted actions this bound counts, followed by the candidate itself. */
    private static function selItems(array $core, array $s, array $adms, array $a): array
    {
        $o = [];
        foreach ($adms as $m) {
            if (self::appliesL($s, $m['gid'], $m['act']['verb']) && self::inScope($core['scope'], $a, $m['act']) && self::inWindow($core['window'], $a, $m['act'])) {
                $o[] = $m['act'];
            }
        }
        $o[] = $a;
        return $o;
    }

    private static function itemVals(array $core, array $items, array $h): ?array
    {
        $o = [];
        foreach ($items as $it) {
            $v = self::evalT($core['value'], $it, $h);
            if ($v === null || $v[0] !== 'vq' || $v[1]['u'] !== $core['cap']['u']) {
                return null;
            }
            $o[] = $v[1]['n'];
        }
        return $o;
    }

    private static function keyVals(array $core, array $items): ?array
    {
        $o = [];
        foreach ($items as $it) {
            if (!array_key_exists($core['key'], $it['params'])) {
                return null;
            }
            $o[] = $it['params'][$core['key']];
        }
        return $o;
    }

    /** true / unknown / false = exceeded / unreadable / within. */
    private static function exceeded(array $core, array $items, array $h): int
    {
        switch ($core['agg']) {
            case 'count':
                return self::b2t(count($items) > $core['cap']['n']);
            case 'sum':
                $xs = self::itemVals($core, $items, $h);
                return $xs !== null ? self::b2t(array_sum($xs) > $core['cap']['n']) : 1;
            case 'max':
                $xs = self::itemVals($core, $items, $h);
                return $xs === null || $xs === [] ? 1 : self::b2t(max($xs) > $core['cap']['n']);
            default:
                $vs = self::keyVals($core, $items);
                return $vs !== null ? self::b2t(count(array_unique(array_map('serialize', $vs))) > $core['cap']['n']) : 1;
        }
    }

    private static function boundStat(array $core, array $s, array $a, array $h): int
    {
        $e = self::exceeded($core, self::selItems($core, $s, $h['adms'], $a), $h);
        if ($e === 2) {
            return $core['onExceed'] === 'on_deny' ? self::DENY : self::ESCALATE;
        }
        return $e === 1 ? self::ESCALATE : self::ALLOW;
    }

    // ---- the decision D_G
    private static function validityDec(array $v, array $dg, array $a, array $h): int
    {
        if ($a['t'] < $v['notBefore'] || $a['t'] > $v['notAfter']) {
            return self::DENY;
        }
        if ($v['maxIdle'] > 0 && $h['last'] >= 0 && $a['t'] - $h['last'] > $v['maxIdle']) {
            return self::DENY;
        }
        if ($a['depth'] < 0 || $a['depth'] > $dg['maxDepth']) {
            return self::DENY;
        }
        return self::ALLOW;
    }

    private static function delegOk(array $dg, string $gid, array $a): bool
    {
        return $a['depth'] === 0 || in_array($gid, $dg['mayTouch'], true);
    }

    private static function escOne(int $m): int
    {
        return $m === 0 ? self::ALLOW : self::ESCALATE;
    }

    private static function prohOne(array $verbs, array $res, int $ce, array $a): int
    {
        $m = self::andK(self::b2t(in_array($a['verb'], $verbs, true)), self::andK(self::b2t(self::resOk($res, $a['res'])), $ce));
        return $m === 2 ? self::DENY : ($m === 1 ? self::ESCALATE : self::ALLOW);
    }

    /** @param list<int> $xs */
    private static function minOr(array $xs, int $d): int
    {
        return $xs === [] ? $d : min($xs);
    }

    private static function prohDecG(array $ont, array $ps, array $a, array $h): int
    {
        $o = [];
        foreach ($ps as $p) {
            $o[] = self::prohOne(self::prohVerbs($ont, $p['target']), self::resolveSel($ont, $p['res']), self::evalC($p['cond'], $a, $h), $a);
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function escDecG(array $cs, array $a, array $h): int
    {
        $o = [];
        foreach ($cs as $c) {
            $o[] = self::escOne(self::evalC($c, $a, $h));
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function boundsDecG(array $ont, array $bs, string $gid, array $a, array $h): int
    {
        $o = [];
        foreach ($bs as $b) {
            $s = self::resolveBsel($ont, $b['sel']);
            $o[] = self::appliesL($s, $gid, $a['verb']) ? self::boundStat($b['core'], $s, $a, $h) : self::ALLOW;
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function grantDecG(array $ont, array $g, array $gr, array $a, array $h): int
    {
        $m = self::andK(self::b2t($a['verb'] === $gr['verb'] && self::delegOk($g['deleg'], $gr['gid'], $a)),
            self::andK(self::b2t(self::resOk(self::resolveSel($ont, $gr['res']), $a['res'])), self::evalC($gr['cond'], $a, $h)));
        return min($m, self::boundsDecG($ont, $g['bounds'], $gr['gid'], $a, $h));
    }

    /** The reference decision D_G of a goal for one action. */
    public static function dg(array $ont, array $g, array $a, array $h): int
    {
        $best = self::DENY;
        foreach ($g['grants'] as $gr) {
            $best = max($best, self::grantDecG($ont, $g, $gr, $a, $h));
        }
        return min(self::validityDec($g['validity'], $g['deleg'], $a, $h), self::prohDecG($ont, $g['prohibits'], $a, $h),
            self::escDecG($g['escalateOn'], $a, $h), $g['grants'] === [] ? self::DENY : $best);
    }

    // ---- the lowered policy and its decision D_P
    private static function prohDecP(array $ps, array $a, array $h): int
    {
        $o = [];
        foreach ($ps as $p) {
            $o[] = self::prohOne($p['verbs'], $p['res'], self::evalN($p['cond'], $a, $h), $a);
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function escDecP(array $cs, array $a, array $h): int
    {
        $o = [];
        foreach ($cs as $c) {
            $o[] = self::escOne(self::evalN($c, $a, $h));
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function ceilsDecP(array $cs, string $gid, array $a, array $h): int
    {
        $o = [];
        foreach ($cs as $c) {
            $o[] = self::appliesL($c['sel'], $gid, $a['verb']) ? self::boundStat($c['core'], $c['sel'], $a, $h) : self::ALLOW;
        }
        return self::minOr($o, self::ALLOW);
    }

    private static function predDec(array $p, array $ceils, array $dg, array $a, array $h): int
    {
        $m = self::andK(self::b2t($a['verb'] === $p['verb'] && self::delegOk($dg, $p['gid'], $a)),
            self::andK(self::b2t(self::resOk($p['res'], $a['res'])), self::evalN($p['cond'], $a, $h)));
        return min($m, self::ceilsDecP($ceils, $p['gid'], $a, $h));
    }

    /** The compiled-policy decision D_P for one action. */
    public static function dp(array $p, array $a, array $h): int
    {
        $best = self::DENY;
        foreach ($p['preds'] as $x) {
            $best = max($best, self::predDec($x, $p['ceils'], $p['deleg'], $a, $h));
        }
        return min(self::validityDec($p['validity'], $p['deleg'], $a, $h), self::prohDecP($p['prohs'], $a, $h),
            self::escDecP($p['escs'], $a, $h), $best);
    }

    // ---- typing
    private static function strictlySorted(array $xs): bool
    {
        for ($i = 1; $i < count($xs); $i++) {
            if (strcmp($xs[$i - 1], $xs[$i]) >= 0) {
                return false;
            }
        }
        return true;
    }

    private static function unitOk(array $u): bool
    {
        return $u[0] !== 'money' || $u[1] !== '';
    }

    private static function tyOk(array $t): bool
    {
        return $t[0] === 'tys' || self::unitOk($t[1]);
    }

    private static function vOk(array $v): bool
    {
        switch ($v[0]) {
            case 'vq':
                return self::unitOk($v[1]['u']);
            case 'vs':
                return true;
            default:
                foreach ($v[1] as $i) {
                    if ($i[0] !== 'as' && !self::unitOk($i[1]['u'])) {
                        return false;
                    }
                }
                return true;
        }
    }

    private static function typeOfTerm(array $t): ?array
    {
        return match ($t[0]) {
            'param' => $t[2],
            'lit' => self::typeOfV($t[1]),
            'hist_agg' => ['tyq', $t[2]],
        };
    }

    private static function termOk(array $t): bool
    {
        return match ($t[0]) {
            'param' => $t[1] !== '' && self::tyOk($t[2]),
            'lit' => self::vOk($t[1]),
            'hist_agg' => $t[1] !== '' && self::unitOk($t[2]),
        };
    }

    private static function cmpTyped(string $op, array $l, array $r): bool
    {
        if (!(self::termOk($l) && self::termOk($r))) {
            return false;
        }
        $lt = self::typeOfTerm($l);
        if ($lt === null) {
            return false;
        }
        switch ($op) {
            case 'eq':
            case 'ne':
                return $lt === self::typeOfTerm($r);
            case 'lt':
            case 'lte':
            case 'gt':
            case 'gte':
                return $lt === self::typeOfTerm($r) && $lt[0] === 'tyq';
            default:
                if (!($r[0] === 'lit' && $r[1][0] === 'vset')) {
                    return false;
                }
                foreach ($r[1][1] as $i) {
                    if (self::typeOfV(self::atomV($i)) !== $lt) {
                        return false;
                    }
                }
                return true;
        }
    }

    private static function condTyped(array $c, callable $ok): bool
    {
        return match ($c[0]) {
            'ctrue' => true,
            'cmp' => self::cmpTyped($c[1], $c[2], $c[3]) && self::paramsOk($c[2], $ok) && self::paramsOk($c[3], $ok),
            'and', 'or' => self::condTyped($c[1], $ok) && self::condTyped($c[2], $ok),
            'not' => self::condTyped($c[1], $ok),
        };
    }

    private static function paramsOk(array $t, callable $ok): bool
    {
        return $t[0] !== 'param' || $ok($t[1], $t[2]);
    }

    private static function findDecl(array $vs, string $verb): ?array
    {
        foreach ($vs as $d) {
            if ($d['verb'] === $verb) {
                return $d;
            }
        }
        return null;
    }

    private static function declaredFor(array $ont, array $verbs, string $p, array $ty): bool
    {
        foreach ($verbs as $v) {
            $d = self::findDecl($ont['verbs'], $v);
            if ($d === null || !in_array(['path' => $p, 'ty' => $ty], $d['params'], true)) {
                return false;
            }
        }
        return true;
    }

    private static function noConflict(array $vs, string $p, array $ty): bool
    {
        foreach ($vs as $d) {
            foreach ($d['params'] as $x) {
                if ($x['path'] === $p && $x['ty'] !== $ty) {
                    return false;
                }
            }
        }
        return true;
    }

    private static function relDeclared(array $ont, string $rel, string $anchor): bool
    {
        foreach ($ont['rels'] as $r) {
            if ($r['rel'] === $rel && $r['anchor'] === $anchor) {
                return true;
            }
        }
        return false;
    }

    private static function partOk(array $ont, array $p): bool
    {
        return match ($p[0]) {
            'pexact' => $p[1] !== '',
            'poneof' => $p[1] !== [],
            'prelated' => self::relDeclared($ont, $p[1], $p[2]),
        };
    }

    private static function resSelOk(array $ont, array $s): bool
    {
        switch ($s[0]) {
            case 'exact':
                return $s[1] !== '';
            case 'oneof':
                return $s[1] !== [];
            case 'related':
                return self::relDeclared($ont, $s[1], $s[2]);
            case 'anyres':
                return true;
            default:
                if (count($s[1]) < 2) {
                    return false;
                }
                foreach ($s[1] as $p) {
                    if (!self::partOk($ont, $p)) {
                        return false;
                    }
                }
                return true;
        }
    }

    private static function grantOk(array $ont, array $g, array $gr): bool
    {
        return $gr['gid'] !== '' && self::findDecl($ont['verbs'], $gr['verb']) !== null && self::resSelOk($ont, $gr['res'])
            && ($gr['res'][0] !== 'anyres' || in_array($gr['gid'], $g['wildcardAck'], true))
            && self::condTyped($gr['cond'], fn(string $p, array $ty) => self::declaredFor($ont, [$gr['verb']], $p, $ty));
    }

    private static function prohibitOk(array $ont, array $p): bool
    {
        if (!($p['pid'] !== '' && self::resSelOk($ont, $p['res']))) {
            return false;
        }
        $tgt = $p['target'][0] === 'pverb'
            ? self::findDecl($ont['verbs'], $p['target'][1]) !== null
            : ($p['target'][1] !== '' && self::verbsOfClass($ont['verbs'], $p['target'][1]) !== []);
        return $tgt && self::condTyped($p['cond'], fn(string $q, array $ty) => self::declaredFor($ont, self::prohVerbs($ont, $p['target']), $q, $ty));
    }

    private static function windowOk(array $w): bool
    {
        return in_array($w[0], ['wsliding', 'wperiod'], true) ? $w[1] > 0 : true;
    }

    private static function scopeOk(array $s): bool
    {
        return $s[0] !== 'sfleet' || $s[1] !== [];
    }

    private static function gidIn(array $g, string $id): bool
    {
        foreach ($g['grants'] as $x) {
            if ($x['gid'] === $id) {
                return true;
            }
        }
        return false;
    }

    private static function allGidIn(array $g, array $ids): bool
    {
        foreach ($ids as $id) {
            if (!self::gidIn($g, $id)) {
                return false;
            }
        }
        return true;
    }

    private static function boundOk(array $g, array $b): bool
    {
        $c = $b['core'];
        if (!($b['bid'] !== '' && self::termOk($c['value']) && self::unitOk($c['cap']['u']) && $c['cap']['n'] >= 0
            && self::windowOk($c['window']) && self::scopeOk($c['scope']))) {
            return false;
        }
        $sel = $b['sel'][0] === 'sel_gids' ? ($b['sel'][1] !== [] && self::allGidIn($g, $b['sel'][1])) : $b['sel'][1] !== '';
        if (!$sel) {
            return false;
        }
        return match ($c['agg']) {
            'count' => $c['cap']['u'] === ['count'],
            'sum', 'max' => self::typeOfTerm($c['value']) === ['tyq', $c['cap']['u']],
            'distinct' => $c['cap']['u'] === ['count'] && $c['key'] !== '',
        };
    }

    private static function validityOk(array $v, array $dg, array $g): bool
    {
        return $v['notBefore'] <= $v['notAfter'] && $v['maxIdle'] >= 0 && $dg['maxDepth'] >= 0 && $dg['maxDepth'] <= 16
            && $dg['narrowOnly'] && self::allGidIn($g, $dg['mayTouch']);
    }

    private static function holeOk(array $g, array $h): bool
    {
        return $h['hid'] !== '' && self::allGidIn($g, $h['affects']);
    }

    private static function escsTyped(array $ont, array $g): bool
    {
        foreach ($g['escalateOn'] as $c) {
            if (!self::condTyped($c, fn(string $p, array $ty) => self::noConflict($ont['verbs'], $p, $ty))) {
                return false;
            }
        }
        return true;
    }

    private static function sorted4(array $g): bool
    {
        return self::strictlySorted(array_column($g['grants'], 'gid')) && self::strictlySorted(array_column($g['prohibits'], 'pid'))
            && self::strictlySorted(array_column($g['bounds'], 'bid')) && self::strictlySorted(array_column($g['holes'], 'hid'));
    }

    private static function allOf(array $xs, callable $f): bool
    {
        foreach ($xs as $x) {
            if (!$f($x)) {
                return false;
            }
        }
        return true;
    }

    /** The typing reasons of a goal under an ontology (empty = well typed). @return list<string> */
    public static function typeReasons(array $ont, array $g): array
    {
        $r = [];
        if (!self::sorted4($g)) {
            $r[] = 'not_canonical_order';
        }
        if (!self::allOf($g['grants'], fn($x) => self::grantOk($ont, $g, $x))) {
            $r[] = 'ill_typed_grant';
        }
        if (!self::allOf($g['prohibits'], fn($x) => self::prohibitOk($ont, $x))) {
            $r[] = 'ill_typed_prohibit';
        }
        if (!self::allOf($g['bounds'], fn($x) => self::boundOk($g, $x))) {
            $r[] = 'ill_typed_bound';
        }
        if (!self::escsTyped($ont, $g)) {
            $r[] = 'ill_typed_escalation';
        }
        if (!self::validityOk($g['validity'], $g['deleg'], $g)) {
            $r[] = 'bad_validity_or_delegation';
        }
        if (!self::allOf($g['holes'], fn($x) => self::holeOk($g, $x))) {
            $r[] = 'bad_hole';
        }
        return $r;
    }

    // ---- compile: strip the grants a hole touches, then lower
    private static function dependsOn(array $hs, string $gid): bool
    {
        foreach ($hs as $h) {
            if ($h['global'] || in_array($gid, $h['affects'], true)) {
                return true;
            }
        }
        return false;
    }

    private static function strip(array $g): array
    {
        $g['grants'] = array_values(array_filter($g['grants'], fn($gr) => !self::dependsOn($g['holes'], $gr['gid'])));
        $g['holes'] = [];
        return $g;
    }

    private static function lower(array $ont, array $g): array
    {
        return [
            'preds' => array_map(fn($x) => ['gid' => $x['gid'], 'verb' => $x['verb'], 'res' => self::resolveSel($ont, $x['res']), 'cond' => self::nnf($x['cond'], true)], $g['grants']),
            'prohs' => array_map(fn($x) => ['pid' => $x['pid'], 'verbs' => self::prohVerbs($ont, $x['target']), 'res' => self::resolveSel($ont, $x['res']), 'cond' => self::nnf($x['cond'], true)], $g['prohibits']),
            'ceils' => array_map(fn($x) => ['bid' => $x['bid'], 'sel' => self::resolveBsel($ont, $x['sel']), 'core' => $x['core']], $g['bounds']),
            'escs' => array_map(fn($c) => self::nnf($c, true), $g['escalateOn']),
            'validity' => $g['validity'],
            'deleg' => $g['deleg'],
        ];
    }

    /** ['compiled', policy] | ['escalate', reasons]. */
    public static function compile(array $ont, array $g): array
    {
        $rs = self::typeReasons($ont, $g);
        return $rs === [] ? ['compiled', self::lower($ont, self::strip($g))] : ['escalate', $rs];
    }

    // ---- witness
    private static function applicable(array $cs, string $gid, string $verb): array
    {
        $o = [];
        foreach ($cs as $c) {
            if (self::appliesL($c['sel'], $gid, $verb)) {
                $o[] = $c['bid'];
            }
        }
        return $o;
    }

    /** [decision, gid, bids]. */
    public static function decideW(array $p, array $a, array $h): array
    {
        $d = self::dp($p, $a, $h);
        if ($d !== self::ALLOW) {
            return [$d, '', []];
        }
        foreach ($p['preds'] as $x) {
            if (self::predDec($x, $p['ceils'], $p['deleg'], $a, $h) === self::ALLOW) {
                return [self::ALLOW, $x['gid'], self::applicable($p['ceils'], $x['gid'], $a['verb'])];
            }
        }
        return [self::DENY, '', []];
    }

    public static function verifyWitness(array $p, array $a, array $h, string $gid, array $bids): bool
    {
        if (!(self::validityDec($p['validity'], $p['deleg'], $a, $h) === self::ALLOW && self::prohDecP($p['prohs'], $a, $h) === self::ALLOW
            && self::escDecP($p['escs'], $a, $h) === self::ALLOW)) {
            return false;
        }
        $any = false;
        foreach ($p['preds'] as $x) {
            if ($x['gid'] === $gid && self::predDec($x, $p['ceils'], $p['deleg'], $a, $h) === self::ALLOW) {
                $any = true;
                break;
            }
        }
        return $any && $bids === self::applicable($p['ceils'], $gid, $a['verb']);
    }

    /** Parse a whole tape with a reader method; null when it does not parse or leaves tokens over. */
    private static function whole(array $ts, string $m): ?array
    {
        $r = new GoalKernelReader($ts);
        try {
            $v = $r->$m();
        } catch (GoalKernelFail) {
            return null;
        }
        return $r->done() ? $v : null;
    }

    // ---- tape encoding
    private static function tk(int $n): array
    {
        return ['k', $n];
    }

    private static function ti(int $n): array
    {
        return ['i', $n];
    }

    private static function ts(string $s): array
    {
        return ['s', $s];
    }

    private static function encStrs(array $xs): array
    {
        $o = [self::ti(count($xs))];
        foreach ($xs as $s) {
            $o[] = self::ts($s);
        }
        return $o;
    }

    private static function encList(array $xs, callable $f): array
    {
        $o = [self::ti(count($xs))];
        foreach ($xs as $x) {
            array_push($o, ...$f($x));
        }
        return $o;
    }

    private static function encUnit(array $u): array
    {
        if ($u[0] === 'money') {
            return [self::tk(300), self::ts($u[1])];
        }
        return [self::tk(301 + array_search($u[0], ['count', 'duration', 'instant', 'bytes', 'ratio'], true))];
    }

    private static function encQ(array $q): array
    {
        return [...self::encUnit($q['u']), self::ti($q['n'])];
    }

    private static function encTy(array $t): array
    {
        return $t[0] === 'tyq' ? [self::tk(310), ...self::encUnit($t[1])] : [self::tk(311)];
    }

    private static function encAtom(array $a): array
    {
        return $a[0] === 'aq' ? [self::tk(320), ...self::encQ($a[1])] : [self::tk(321), self::ts($a[1])];
    }

    private static function encV(array $v): array
    {
        switch ($v[0]) {
            case 'vq':
                return [self::tk(330), ...self::encQ($v[1])];
            case 'vs':
                return [self::tk(331), self::ts($v[1])];
            default:
                return [self::tk(332), ...self::encList($v[1], fn($a) => self::encAtom($a))];
        }
    }

    private static function encTerm(array $t): array
    {
        return match ($t[0]) {
            'param' => [self::tk(340), self::ts($t[1]), ...self::encTy($t[2])],
            'lit' => [self::tk(341), ...self::encV($t[1])],
            'hist_agg' => [self::tk(342), self::ts($t[1]), ...self::encUnit($t[2])],
        };
    }

    private static function encOp(string $op): array
    {
        return [self::tk(350 + array_search($op, self::OPS_BY_KW, true))];
    }

    private static function encResPat(array $p): array
    {
        return $p[0] === 'pstar' ? [self::tk(630)] : [self::tk(631), ...self::encStrs($p[1])];
    }

    private static function encNc(array $c): array
    {
        return match ($c[0]) {
            'ntrue' => [self::tk(600)],
            'nfalse' => [self::tk(601)],
            'natom' => [self::tk(602), ...self::encOp($c[1]), ...self::encTerm($c[2]), ...self::encTerm($c[3])],
            'nand' => [self::tk(603), ...self::encNc($c[1]), ...self::encNc($c[2])],
            'nor' => [self::tk(604), ...self::encNc($c[1]), ...self::encNc($c[2])],
        };
    }

    private static function encWindow(array $w): array
    {
        return match ($w[0]) {
            'wtask' => [self::tk(420)],
            'wsliding' => [self::tk(421), self::ti($w[1])],
            'wperiod' => [self::tk(422), self::ti($w[1]), self::ti($w[2])],
            'wlifetime' => [self::tk(423)],
        };
    }

    private static function encScope(array $s): array
    {
        return match ($s[0]) {
            'ssession' => [self::tk(430)],
            'sprincipal' => [self::tk(431)],
            'sorg' => [self::tk(432)],
            'sfleet' => [self::tk(433), ...self::encStrs($s[1])],
        };
    }

    private static function encBcore(array $b): array
    {
        return [self::tk(450), self::tk(400 + array_search($b['agg'], self::AGGS, true)), ...self::encTerm($b['value']), self::ts($b['key']),
            ...self::encWindow($b['window']), ...self::encScope($b['scope']), ...self::encQ($b['cap']), self::tk($b['onExceed'] === 'on_deny' ? 440 : 441)];
    }

    private static function encValidityDeleg(array $v, array $d): array
    {
        return [self::tk(460), self::ti($v['notBefore']), self::ti($v['notAfter']), self::ti($v['maxIdle']),
            self::tk(461), self::ti($d['maxDepth']), self::ti($d['narrowOnly'] ? 1 : 0), ...self::encStrs($d['mayTouch'])];
    }

    private static function encPol(array $p): array
    {
        return [self::tk(650),
            ...self::encList($p['preds'], fn($x) => [self::tk(620), self::ts($x['gid']), self::ts($x['verb']), ...self::encResPat($x['res']), ...self::encNc($x['cond'])]),
            ...self::encList($p['prohs'], fn($x) => [self::tk(640), self::ts($x['pid']), ...self::encStrs($x['verbs']), ...self::encResPat($x['res']), ...self::encNc($x['cond'])]),
            ...self::encList($p['ceils'], fn($c) => [self::tk(610), self::ts($c['bid']), ...self::encStrs($c['sel']['gids']), ...self::encStrs($c['sel']['verbs']), ...self::encBcore($c['core'])]),
            ...self::encList($p['escs'], fn($x) => self::encNc($x)),
            ...self::encValidityDeleg($p['validity'], $p['deleg'])];
    }

    private static function encCond(array $c): array
    {
        return match ($c[0]) {
            'ctrue' => [self::tk(360)],
            'cmp' => [self::tk(361), ...self::encOp($c[1]), ...self::encTerm($c[2]), ...self::encTerm($c[3])],
            'and' => [self::tk(362), ...self::encCond($c[1]), ...self::encCond($c[2])],
            'or' => [self::tk(363), ...self::encCond($c[1]), ...self::encCond($c[2])],
            'not' => [self::tk(364), ...self::encCond($c[1])],
        };
    }

    private static function encPart(array $p): array
    {
        return match ($p[0]) {
            'pexact' => [self::tk(375), self::ts($p[1])],
            'poneof' => [self::tk(376), ...self::encStrs($p[1])],
            'prelated' => [self::tk(377), self::ts($p[1]), self::ts($p[2])],
        };
    }

    private static function encResSel(array $s): array
    {
        return match ($s[0]) {
            'exact' => [self::tk(370), self::ts($s[1])],
            'oneof' => [self::tk(371), ...self::encStrs($s[1])],
            'related' => [self::tk(372), self::ts($s[1]), self::ts($s[2])],
            'anyres' => [self::tk(373), self::ts($s[1])],
            'allof' => [self::tk(374), ...self::encList($s[1], fn($p) => self::encPart($p))],
        };
    }

    private static function encGrant(array $g): array
    {
        return [self::tk(380), self::ts($g['gid']), self::ts($g['verb']), ...self::encResSel($g['res']), ...self::encCond($g['cond'])];
    }

    private static function encProhibit(array $p): array
    {
        $t = $p['target'][0] === 'pverb' ? [self::tk(390), self::ts($p['target'][1])] : [self::tk(391), self::ts($p['target'][1])];
        return [self::tk(392), self::ts($p['pid']), ...$t, ...self::encResSel($p['res']), ...self::encCond($p['cond'])];
    }

    private static function encSel(array $s): array
    {
        return $s[0] === 'sel_gids' ? [self::tk(410), ...self::encStrs($s[1])] : [self::tk(411), self::ts($s[1])];
    }

    private static function encBound(array $b): array
    {
        return [self::tk(451), self::ts($b['bid']), ...self::encSel($b['sel']), ...self::encBcore($b['core'])];
    }

    private static function encHole(array $h): array
    {
        return [self::tk(470), self::ts($h['hid']), self::ts($h['q']), ...self::encStrs($h['domain']), ...self::encStrs($h['affects']), self::ti($h['global'] ? 1 : 0)];
    }

    /** The tape of a decoded goal (Render). */
    public static function render(array $g): array
    {
        return [self::tk(480), self::ti($g['v']), self::ts($g['principal']), self::ts($g['ontDigest']), self::ts($g['nlDigest']),
            ...self::encStrs($g['sources']),
            ...self::encList($g['grants'], fn($x) => self::encGrant($x)),
            ...self::encList($g['prohibits'], fn($x) => self::encProhibit($x)),
            ...self::encList($g['bounds'], fn($x) => self::encBound($x)),
            ...self::encValidityDeleg($g['validity'], $g['deleg']),
            ...self::encList($g['escalateOn'], fn($c) => self::encCond($c)),
            ...self::encStrs($g['wildcardAck']),
            ...self::encList($g['holes'], fn($x) => self::encHole($x))];
    }

    // ---- entry points
    private static function ival(mixed $v): int
    {
        $bad = fn() => new GoalIrError('goal tape: ' . (is_scalar($v) ? var_export($v, true) : 'value') . ' is not a safe integer');
        if (is_bool($v) || !Js::isNum($v)) {
            throw $bad();
        }
        if (is_int($v)) {
            $i = $v;
        } else {
            $f = Js::num($v);
            if (!is_finite($f) || $f !== floor($f) || abs($f) > self::MAX_SAFE) {
                throw $bad();
            }
            $i = (int) $f;
        }
        if (abs($i) > self::MAX_SAFE) {
            throw $bad();
        }
        return $i;
    }

    /**
     * Validate a caller tape (each token a [tag, value] pair) and normalize it to ['k'|'i'|'s', value].
     *
     * @return list<array{0:string,1:int|string}>
     */
    private static function checkTape(mixed $tape): array
    {
        if (!is_array($tape) || !array_is_list($tape)) {
            throw new GoalIrError('goal tape: an Array of tokens expected');
        }
        $o = [];
        foreach ($tape as $t) {
            if (!is_array($t) || !array_is_list($t) || count($t) !== 2) {
                throw new GoalIrError('goal tape: token expected');
            }
            [$tag, $v] = $t;
            if ($tag === 'k' || $tag === 'i') {
                $o[] = [$tag, self::ival($v)];
            } elseif ($tag === 's') {
                if (!is_string($v)) {
                    throw new GoalIrError('goal tape: string token expected');
                }
                $o[] = ['s', $v];
            } else {
                throw new GoalIrError('goal tape: unknown token tag ' . (is_string($tag) ? var_export($tag, true) : 'value'));
            }
        }
        return $o;
    }

    /**
     * One proved entry point over token tapes (op in typecheck compile decideg decidep render).
     *
     * @return list<array{0:string,1:int|string}>
     */
    public static function kernelCall(string $op, array $goalTape, ?array $ontTape = null, ?array $actTape = null, ?array $histTape = null): array
    {
        if (!in_array($op, self::OPS, true)) {
            throw new \InvalidArgumentException('goal kernel: unknown op ' . var_export($op, true));
        }
        $gt = self::checkTape($goalTape);
        if ($op === 'render') {
            $g = self::whole($gt, 'goal');
            return $g !== null ? [self::ti(0), ...self::render($g)] : self::BAD;
        }
        $g = self::whole($gt, 'goal');
        $o = self::whole(self::checkTape($ontTape ?? []), 'ontology');
        if ($g === null || $o === null) {
            return self::BAD;
        }
        if ($op === 'typecheck') {
            $rs = self::typeReasons($o, $g);
            return $rs === [] ? [self::ti(0)] : [self::ti(1), ...self::encStrs($rs)];
        }
        if ($op === 'compile') {
            [$kind, $x] = self::compile($o, $g);
            return $kind === 'compiled' ? [self::ti(0), ...self::encPol($x)] : [self::ti(1), ...self::encStrs($x)];
        }
        $a = self::whole(self::checkTape($actTape ?? []), 'act');
        $h = self::whole(self::checkTape($histTape ?? []), 'hist');
        if ($a === null || $h === null) {
            return self::BAD;
        }
        return $op === 'decideg' ? [self::ti(0), self::ti(self::dg($o, $g, $a, $h))] : self::decideP($o, $g, $a, $h);
    }

    private static function decideP(array $o, array $g, array $a, array $h): array
    {
        [$kind, $x] = self::compile($o, $g);
        if ($kind === 'escalate') {
            return [self::ti(1), ...self::encStrs($x)];
        }
        [$d, $gid, $bids] = self::decideW($x, $a, $h);
        return [self::ti(0), self::ti($d), self::ts($gid), ...self::encStrs($bids), self::ti($d === self::ALLOW && self::verifyWitness($x, $a, $h, $gid, $bids) ? 1 : 0)];
    }

    // ---- tape text (the corpus syntax): kN, iN, s<hex>.<hex>..., a bare s is the empty string
    /** The code points of a (WTF-8) string. @return list<int> */
    private static function codepoints(string $s): array
    {
        $o = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $o[] = $b;
                $i++;
            } elseif ($b < 0xE0) {
                $o[] = (($b & 0x1F) << 6) | (ord($s[$i + 1] ?? "\0") & 0x3F);
                $i += 2;
            } elseif ($b < 0xF0) {
                $o[] = (($b & 0x0F) << 12) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 2] ?? "\0") & 0x3F);
                $i += 3;
            } else {
                $o[] = (($b & 7) << 18) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 12) | ((ord($s[$i + 2] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 3] ?? "\0") & 0x3F);
                $i += 4;
            }
        }
        return $o;
    }

    private static function utf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp > 0x10FFFF) {
            throw new \InvalidArgumentException('goal tape text: code point out of range');
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    public static function tapeToText(array $tape): string
    {
        $o = [];
        foreach ($tape as [$tag, $v]) {
            $o[] = $tag === 's' ? 's' . implode('.', array_map('dechex', self::codepoints($v))) : $tag . $v;
        }
        return implode(' ', $o);
    }

    /** @return list<array{0:string,1:int|string}> */
    public static function tapeFromText(string $s): array
    {
        $o = [];
        foreach (preg_split('/\s+/', trim($s), -1, PREG_SPLIT_NO_EMPTY) as $x) {
            $b = substr($x, 1);
            if ($x[0] === 'k' || $x[0] === 'i') {
                if (preg_match('/\A-?[0-9]+\z/', $b) !== 1) {
                    throw new \InvalidArgumentException('goal tape text: bad integer ' . var_export($x, true));
                }
                // beyond int64 the value is kept as a float, which the integer check then refuses
                $o[] = [$x[0], strlen(ltrim($b, '-')) > 18 ? (float) $b : (int) $b];
            } elseif ($x[0] === 's') {
                $str = '';
                if ($b !== '') {
                    foreach (explode('.', $b) as $h) {
                        if ($h === '' || !ctype_xdigit($h)) {
                            throw new \InvalidArgumentException('goal tape text: bad code point ' . var_export($x, true));
                        }
                        $str .= self::utf8((int) hexdec($h));
                    }
                }
                $o[] = ['s', $str];
            } else {
                throw new GoalIrError('goal tape text: bad token ' . var_export($x, true));
            }
        }
        return $o;
    }
}
