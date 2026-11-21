<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalCard.php';
require_once __DIR__ . '/GoalDigests.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/GoalSign.php';

/** A refusal of the review layer; `errorCode` is one of card_too_large, unrenderable, holes, wildcard_unacknowledged, diff_too_large, too_many_widenings. */
final class GoalReviewError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $detail)
    {
        parent::__construct("goal review: $errorCode: $detail");
    }
}

/**
 * Principal review and signing for a Goal IR.
 *
 * PolicyCard: a deterministic, template-only rendering of the WHOLE Goal from the same phrase table as the plain text card, with
 * exact numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card fail; the card is never
 * truncated. The reviewer-fatigue limits (REVIEW_LIMITS) are hard caps that REFUSE a goal or diff that is too large to read;
 * callers may only tighten them. Semantic diff: clause-level, widenings first; anything not PROVEN narrower counts as a widening.
 * GoalApproval: a pinned reviewer signs the digests of goal, compiled policy, card, ontology, tests, instruction and model set;
 * `loadApprovedGoal` trusts nothing the submission claims about itself (recomputes every digest, recompiles, re-renders,
 * re-runs the confirmed examples) and never throws.
 */
final class GoalReview
{
    public const REVIEW_LIMITS = [
        'max_grants' => 32, 'max_prohibits' => 64, 'max_bounds' => 32, 'max_escalate_on' => 32, 'max_examples' => 40, 'max_card_lines' => 200,
        'max_card_bytes' => 24576, 'max_diff_changes' => 60, 'max_diff_widenings' => 12, 'max_witnesses' => 20,
    ];
    public const D_CARD = 'atlas-pca/policy-card/v1';
    public const D_CLAUSE = 'atlas-pca/goal-clause/v1';
    public const GOAL_APPROVAL_KIND = 'goal-approval';
    public const MAX_GOAL_APPROVAL_TTL_MS = 24 * 3600000;
    public const DEFAULT_TTL_MS = 3600000;
    public const GOAL_APPROVAL_SIGNED_FIELDS = ['v', 'goal_digest', 'policy_digest', 'card_digest', 'ontology_digest', 'tests_digest', 'nl_digest', 'model_set_digest', 'reviewer', 'approved_at', 'expires_at'];
    private const FIELD_REASON = [
        ['goal_digest', 'goal_digest_mismatch'], ['policy_digest', 'policy_digest_mismatch'], ['ontology_digest', 'ontology_mismatch'],
        ['tests_digest', 'tests_digest_mismatch'], ['nl_digest', 'nl_digest_mismatch'], ['model_set_digest', 'model_set_digest_mismatch'],
        ['card_digest', 'card_digest_mismatch'],
    ];
    private const MAX_SAFE = 9007199254740991.0;

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    private static function s(mixed $v): string
    {
        return AnalyzerJs::jsStr($v);
    }

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** The callable member `$name` of a kernel object (compile, policyDigest, analyze, decide, newlyAllowed), or null when absent. */
    private static function kfn(mixed $kernel, string $name): ?\Closure
    {
        $f = Js::opt($kernel, $name);
        return $f === null ? null : \Closure::fromCallable($f);
    }

    private static function fail(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason]);
    }

    /** `x.length` of an array or string; null for a value without one; null / undefined throws. */
    private static function len(mixed $x): ?int
    {
        if ($x === null || $x instanceof Undef) {
            throw new \TypeError('cannot read properties of null or undefined (reading length)');
        }
        if (self::isList($x)) {
            return count($x);
        }
        return is_string($x) ? Js::len($x) : null;
    }

    /** Number.isSafeInteger (and not -0 when `$noNegZero`): the integer, else null. */
    private static function safeInt(mixed $v, bool $noNegZero = false): ?int
    {
        $f = Js::num($v);
        if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > self::MAX_SAFE) {
            return null;
        }
        if ($noNegZero && $f == 0.0 && fdiv(1.0, $f) < 0) {
            return null;
        }
        return (int)$f;
    }

    /** JS `a >= b` (false when either side is NaN). */
    private static function ge(mixed $a, mixed $b): bool
    {
        if (is_string($a) && is_string($b)) {
            return !AnalyzerJs::jsLt($a, $b);
        }
        $x = AnalyzerJs::toNumber($a);
        $y = AnalyzerJs::toNumber($b);
        return !is_nan($x) && !is_nan($y) && $x >= $y;
    }

    /** JS `a <= b` (false when either side is NaN). */
    private static function le(mixed $a, mixed $b): bool
    {
        return self::ge($b, $a);
    }

    // ---- limits -------------------------------------------------------------------------------------------------------

    /** Caller overrides may only TIGHTEN a limit (a larger number is ignored). @return array<string,int> */
    public static function limitsOf(mixed $o = null): array
    {
        $out = self::REVIEW_LIMITS;
        if (Js::truthy($o)) {
            foreach ($out as $k => $cur) {
                $v = Js::opt($o, $k);
                $n = self::safeInt($v);
                if ($n !== null && $n >= 0 && $n < $cur) {
                    $out[$k] = $n;
                }
            }
        }
        return $out;
    }

    public static function effectiveLimits(mixed $o = null): Obj
    {
        $out = new Obj();
        foreach (self::limitsOf($o) as $k => $v) {
            $out->set($k, self::num($v));
        }
        return $out;
    }

    // ---- the card -----------------------------------------------------------------------------------------------------

    private static function jsonOf(mixed $v): string
    {
        try {
            return Json::canonicalizeNative($v);
        } catch (\Throwable) {
            throw new GoalReviewError('unrenderable', 'a clause has no canonical form (float, undefined or cycle)');
        }
    }

    private static function line(mixed $id, string $kind, string $text, mixed $clause, string $severity = 'info'): Obj
    {
        return AnalyzerJs::uobj([
            'id' => $id, 'kind' => $kind, 'severity' => $severity, 'text' => $text,
            'clause_digest' => Pca::hashCanonical(Obj::of(['d' => self::D_CLAUSE, 'kind' => $kind, 'clause' => $clause])),
        ]);
    }

    /** Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped. */
    private static function safeText(callable $f, mixed $clause): string
    {
        try {
            $t = $f();
            if (str_contains($t, 'undefined')) {
                throw new \InvalidArgumentException('unknown clause shape');
            }
            return $t;
        } catch (\Throwable) {
            return self::jsonOf($clause);
        }
    }

    private static function go(mixed $goal): string
    {
        try {
            return GoalDigests::goalDigest($goal);
        } catch (\Throwable) {
            throw new GoalReviewError('unrenderable', 'the Goal has no canonical form (float, undefined or cycle)');
        }
    }

    /**
     * Render the card. Deterministic, no model, no locale. Throws GoalReviewError: `holes` (a draft is not reviewable for signing),
     * `wildcard_unacknowledged`, `card_too_large` (a fatigue cap), `unrenderable`. Option `allowHoles` renders a DRAFT for display.
     */
    public static function renderPolicyCard(mixed $goal, mixed $tests = null, mixed $opts = null): Obj
    {
        $tests ??= [];
        $lim = self::limitsOf(Js::opt($opts, 'limits'));
        $big = static function (string $what, int $n, int $mx): void {
            if ($n > $mx) {
                throw new GoalReviewError('card_too_large', "$n $what exceed the cap of $mx: split the goal into smaller goals");
            }
        };
        if (!($goal instanceof Obj)) {
            throw new GoalReviewError('unrenderable', 'not a Goal IR');
        }
        foreach (['grants', 'prohibits', 'bounds', 'escalateOn', 'holes'] as $k) {
            if (!self::isList(self::g($goal, $k))) {
                throw new GoalReviewError('unrenderable', 'not a Goal IR');
            }
        }
        if (!(self::g($goal, 'validity') instanceof Obj) || !(self::g($goal, 'deleg') instanceof Obj)) {
            throw new GoalReviewError('unrenderable', 'not a Goal IR');
        }
        $grants = $goal->get('grants');
        $prohibits = $goal->get('prohibits');
        $bounds = $goal->get('bounds');
        $escalate = $goal->get('escalateOn');
        $holes = $goal->get('holes');
        $testCount = self::len($tests) ?? 0;
        $big('grants', count($grants), $lim['max_grants']);
        $big('prohibitions', count($prohibits), $lim['max_prohibits']);
        $big('bounds', count($bounds), $lim['max_bounds']);
        $big('escalation triggers', count($escalate), $lim['max_escalate_on']);
        $big('boundary examples', $testCount, $lim['max_examples']);
        $big('card lines', 4 + count($grants) + count($prohibits) + count($bounds) + count($escalate) + count($holes) + $testCount, $lim['max_card_lines']);
        if (count($holes) > 0 && !Js::truthy(Js::opt($opts, 'allowHoles'))) {
            throw new GoalReviewError('holes', count($holes) . ' unresolved question(s): a goal with holes is a draft and cannot be signed');
        }

        $wa = self::g($goal, 'wildcardAck');
        $ack = self::isList($wa) ? $wa : [];
        $principal = self::g($goal, 'principal');
        $lines = [];
        $lines[] = self::line('principal', 'meta', 'Acting for principal ' . self::jsonOf($principal) . '. Nothing outside this card is allowed (default deny).', $principal);
        foreach ($grants as $gr) {
            $res = self::g($gr, 'res');
            $wild = $res !== null && !($res instanceof Undef) ? self::g($res, 'k') === 'any' : false;
            if ($wild && !AnalyzerJs::includes($ack, self::g($gr, 'gid'))) {
                throw new GoalReviewError('wildcard_unacknowledged', 'grant ' . self::jsonOf(self::g($gr, 'gid')) . ' allows ANY resource without a wildcard acknowledgement');
            }
            $lines[] = self::line(self::g($gr, 'gid'), 'grant', self::safeText(static fn() => GoalCard::grantLine($gr) . '.' . ($wild ? ' WILDCARD acknowledged by the principal.' : ''), $gr), $gr, $wild ? 'red' : 'info');
        }
        foreach ($prohibits as $p) {
            $pr = self::g($p, 'res');
            $lines[] = self::line(self::g($p, 'pid'), 'prohibit', self::safeText(static fn() => GoalCard::prohibitLine($p) . '.', $p), $p,
                $pr !== null && !($pr instanceof Undef) && self::g($pr, 'k') === 'any' ? 'red' : 'info');
        }
        foreach ($bounds as $b) {
            $lines[] = self::line(self::g($b, 'bid'), 'bound', self::safeText(static fn() => GoalCard::boundLine($b) . '.', $b), $b);
        }
        $validity = $goal->get('validity');
        $deleg = $goal->get('deleg');
        $lines[] = self::line('validity', 'validity', self::safeText(static fn() => GoalCard::validityLine($validity) . '.', $validity), $validity);
        $lines[] = self::line('delegation', 'delegation', self::safeText(static fn() => GoalCard::delegationLine($deleg) . '.', $deleg), $deleg,
            AnalyzerJs::truthy(self::g($deleg, 'narrowOnly')) ? 'info' : 'red');
        foreach ($escalate as $i => $c) {
            $lines[] = self::line("escalate_on[$i]", 'escalate', self::safeText(static fn() => GoalCard::escalateLine($c) . '.', $c), $c);
        }
        foreach ($holes as $i => $h) {
            $lines[] = self::line("hole[$i]", 'hole', self::safeText(static fn() => GoalCard::holeLine($h) . '. Everything depending on it is dropped.', $h), $h, 'red');
        }
        foreach (AnalyzerJs::reqList($tests) as $t) {
            $act = self::g($t, 'act');
            $n = self::len(self::g(self::g($t, 'hist'), 'adms'));
            $ans = self::g($t, 'answer');
            $lines[] = self::line('example:' . self::s(self::g($t, 'id')), 'example',
                'EXAMPLE you confirmed: ' . self::jsonOf(self::g($act, 'verb')) . ' on ' . self::jsonOf(self::g($act, 'res')) . ' with ' . self::jsonOf(self::g($act, 'params'))
                . ($n !== null && $n > 0 ? " after $n earlier admitted action(s)" : '') . ' must be ' . ($ans === 'ask' ? 'ASKED about' : ($ans === 'allow' ? 'ALLOWED' : 'DENIED')) . '.', $t);
        }
        $big('card lines', count($lines), $lim['max_card_lines']);
        $card = AnalyzerJs::uobj([
            'v' => self::num(1), 'goal_digest' => self::go($goal), 'ontology_digest' => self::g($goal, 'ontDigest'), 'nl_digest' => self::g($goal, 'nlDigest'),
            'principal' => $principal, 'lines' => $lines,
        ]);
        $big('bytes of card', strlen(Json::canonicalizeNative($card)), $lim['max_card_bytes']);
        return $card;
    }

    public static function cardDigest(mixed $card): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::D_CARD, 'card' => $card]));
    }

    /** Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`. */
    public static function cardToText(mixed $card): string
    {
        return implode("\n", array_map(
            static fn($l) => (self::g($l, 'severity') === 'red' ? '!! ' : '   ') . self::s(self::g($l, 'text')),
            AnalyzerJs::reqList(self::g($card, 'lines'))
        ));
    }

    // ---- semantic diff ------------------------------------------------------------------------------------------------

    private static function same(mixed $a, mixed $b): bool
    {
        return self::jsonOf($a) === self::jsonOf($b);
    }

    /** @return list<mixed> */
    private static function conjuncts(mixed $c): array
    {
        $k = self::g($c, 'k');
        if ($k === 'and') {
            return array_merge(self::conjuncts(self::g($c, 'a')), self::conjuncts(self::g($c, 'b')));
        }
        return $k === 'true' ? [] : [$c];
    }

    private static function whereNoWider(mixed $oldW, mixed $newW): bool
    {
        $have = array_map(self::jsonOf(...), self::conjuncts($newW));
        foreach (self::conjuncts($oldW) as $c) {
            if (!in_array(self::jsonOf($c), $have, true)) {
                return false;
            }
        }
        return true;
    }

    private static function grantDir(mixed $o, mixed $n): string
    {
        if (self::same($o, $n)) {
            return 'neutral';
        }
        return AnalyzerJs::strictEq(self::g($o, 'verb'), self::g($n, 'verb')) && self::same(self::g($o, 'res'), self::g($n, 'res'))
            && self::whereNoWider(self::g($o, 'cond'), self::g($n, 'cond')) ? 'narrow' : 'unknown';
    }

    /** A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set. */
    private static function prohibitDir(mixed $o, mixed $n): string
    {
        if (self::same($o, $n)) {
            return 'neutral';
        }
        return self::same(self::g($o, 'target'), self::g($n, 'target')) && self::same(self::g($o, 'res'), self::g($n, 'res'))
            && self::whereNoWider(self::g($n, 'cond'), self::g($o, 'cond')) ? 'narrow' : 'unknown';
    }

    private static function boundDir(mixed $o, mixed $n): string
    {
        if (self::same($o, $n)) {
            return 'neutral';
        }
        $rest = static function ($b): Obj {
            $c = AnalyzerJs::spread($b);
            $c->set('cap', null);
            return $c;
        };
        if (!self::same($rest($o), $rest($n)) || !self::same(self::g(self::g($o, 'cap'), 'u'), self::g(self::g($n, 'cap'), 'u'))) {
            return 'unknown';
        }
        $on = self::g(self::g($o, 'cap'), 'n');
        $nn = self::g(self::g($n, 'cap'), 'n');
        return AnalyzerJs::jsLt($nn, $on) ? 'narrow' : (AnalyzerJs::jsGt($nn, $on) ? 'widen' : 'neutral');
    }

    /** maxIdle 0 means "no idle limit": the widest. */
    private static function idle(mixed $x): mixed
    {
        return Js::isNum($x) && Js::num($x) == 0.0 ? INF : $x;
    }

    private static function validityDir(mixed $o, mixed $n): string
    {
        if (self::same($o, $n)) {
            return 'neutral';
        }
        $nb = self::g($n, 'notBefore');
        $na = self::g($n, 'notAfter');
        $ni = self::idle(self::g($n, 'maxIdle'));
        $ob = self::g($o, 'notBefore');
        $oa = self::g($o, 'notAfter');
        $oi = self::idle(self::g($o, 'maxIdle'));
        $nar = self::ge($nb, $ob) && self::le($na, $oa) && self::le($ni, $oi);
        $wid = self::le($nb, $ob) && self::ge($na, $oa) && self::ge($ni, $oi);
        return $nar ? 'narrow' : ($wid ? 'widen' : 'unknown');
    }

    /** `new Set(x)` of a list; an absent or null value is an empty set. @return list<mixed> */
    private static function setOf(mixed $x): array
    {
        return $x === null || $x instanceof Undef ? [] : AnalyzerJs::reqList($x);
    }

    private static function delegationDir(mixed $o, mixed $n): string
    {
        if (self::same($o, $n)) {
            return 'neutral';
        }
        $touchO = self::setOf(self::g($o, 'mayTouch'));
        $touchN = self::setOf(self::g($n, 'mayTouch'));
        $sub = true;
        foreach ($touchN as $x) {
            $sub = $sub && AnalyzerJs::includes($touchO, $x);
        }
        $sup = true;
        foreach ($touchO as $x) {
            $sup = $sup && AnalyzerJs::includes($touchN, $x);
        }
        $on = AnalyzerJs::truthy(self::g($o, 'narrowOnly'));
        $nn = AnalyzerJs::truthy(self::g($n, 'narrowOnly'));
        $nar = self::le(self::g($n, 'maxDepth'), self::g($o, 'maxDepth')) && $sub && ($nn || !$on);
        $wid = self::ge(self::g($n, 'maxDepth'), self::g($o, 'maxDepth')) && $sup && ($on || !$nn);
        return $nar ? 'narrow' : ($wid ? 'widen' : 'unknown');
    }

    /**
     * @param list<array{0:mixed,1:mixed}> $prev
     * @param list<array{0:mixed,1:mixed}> $next
     * @return list<Obj>
     */
    private static function pairs(array $prev, array $next, string $kind, string $added, string $removed, callable $changed, callable $text): array
    {
        $out = [];
        $find = static function (array $xs, mixed $id): ?array {
            $hit = null;
            foreach ($xs as $e) {
                if (AnalyzerJs::strictEq($e[0], $id) || (Js::isNum($e[0]) && Js::isNum($id) && is_nan((float)Js::num($e[0])) && is_nan((float)Js::num($id)))) {
                    $hit = $e;
                }
            }
            return $hit;
        };
        foreach ($next as [$id, $v]) {
            $o = $find($prev, $id);
            if ($o === null) {
                $out[] = AnalyzerJs::uobj(['change' => 'added', 'kind' => $kind, 'id' => $id, 'direction' => $added, 'text' => 'ADDED ' . $text($id, $v)]);
            } elseif (!self::same($o[1], $v)) {
                $out[] = AnalyzerJs::uobj(['change' => 'changed', 'kind' => $kind, 'id' => $id, 'direction' => $changed($o[1], $v),
                    'text' => 'CHANGED ' . $text($id, $v) . ' (was: ' . $text($id, $o[1]) . ')']);
            }
        }
        foreach ($prev as [$id, $v]) {
            if ($find($next, $id) === null) {
                $out[] = AnalyzerJs::uobj(['change' => 'removed', 'kind' => $kind, 'id' => $id, 'direction' => $removed, 'text' => 'REMOVED ' . $text($id, $v)]);
            }
        }
        return $out;
    }

    /** @return list<array{0:mixed,1:mixed}> */
    private static function keyed(mixed $xs, string $key): array
    {
        return array_map(static fn($x) => [self::g($x, $key), $x], AnalyzerJs::reqList($xs));
    }

    private static function isWide(Obj $c): bool
    {
        $d = $c->get('direction');
        return $d === 'widen' || $d === 'unknown';
    }

    /**
     * Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Throws
     * GoalReviewError `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not offered as one.
     * Options: `limits`, `ontology`.
     */
    public static function diffGoals(mixed $prev, mixed $next, mixed $kernel = null, mixed $opts = null): Obj
    {
        $lim = self::limitsOf(Js::opt($opts, 'limits'));
        $gl = static fn($id, $g): string => 'grant ' . self::jsonOf($id) . ': ' . self::jsonOf(self::g($g, 'verb')) . ' on ' . GoalCard::res(self::g($g, 'res'))
            . ' when ' . GoalCard::cond(self::g($g, 'cond'));
        $pl = static function ($id, $p): string {
            $t = self::g($p, 'target');
            $tgt = self::g($t, 'k') === 'verb' ? self::jsonOf(self::g($t, 'verb')) : 'effect class ' . self::jsonOf(self::g($t, 'cls'));
            return 'prohibition ' . self::jsonOf($id) . ': ' . $tgt . ' on ' . GoalCard::res(self::g($p, 'res')) . ' when ' . GoalCard::cond(self::g($p, 'cond'));
        };
        $esc = static fn($xs): array => array_map(static fn($c) => [self::jsonOf($c), $c], AnalyzerJs::reqList($xs));
        $changes = array_merge(
            self::pairs(self::keyed(self::g($prev, 'grants'), 'gid'), self::keyed(self::g($next, 'grants'), 'gid'), 'grant', 'widen', 'narrow', self::grantDir(...), $gl),
            self::pairs(self::keyed(self::g($prev, 'prohibits'), 'pid'), self::keyed(self::g($next, 'prohibits'), 'pid'), 'prohibit', 'narrow', 'widen', self::prohibitDir(...), $pl),
            self::pairs(self::keyed(self::g($prev, 'bounds'), 'bid'), self::keyed(self::g($next, 'bounds'), 'bid'), 'bound', 'narrow', 'widen', self::boundDir(...),
                static fn($id, $b): string => 'bound ' . self::jsonOf($id) . ': ' . GoalCard::boundLine($b) . ' (' . GoalCard::quantity(self::g($b, 'cap')) . ')'),
            self::pairs($esc(self::g($prev, 'escalateOn')), $esc(self::g($next, 'escalateOn')), 'escalate', 'narrow', 'widen', static fn($a, $b): string => 'unknown',
                static fn($id, $c): string => 'escalation when ' . GoalCard::cond($c))
        );
        $meta = static fn(string $kind, string $id, string $dir, string $text): Obj => Obj::of(['change' => 'changed', 'kind' => $kind, 'id' => $id, 'direction' => $dir, 'text' => $text]);
        $pv = self::g($prev, 'validity');
        $nv = self::g($next, 'validity');
        if (!self::same($pv, $nv)) {
            $changes[] = $meta('validity', 'validity', self::validityDir($pv, $nv), 'CHANGED validity: ' . self::jsonOf($nv) . ' (was: ' . self::jsonOf($pv) . ')');
        }
        $pd = self::g($prev, 'deleg');
        $nd = self::g($next, 'deleg');
        if (!self::same($pd, $nd)) {
            $changes[] = $meta('delegation', 'delegation', self::delegationDir($pd, $nd), 'CHANGED delegation: ' . self::jsonOf($nd) . ' (was: ' . self::jsonOf($pd) . ')');
        }
        // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
        if (!AnalyzerJs::strictEq(self::g($prev, 'principal'), self::g($next, 'principal'))) {
            $changes[] = $meta('meta', 'principal', 'unknown', 'CHANGED principal: ' . self::jsonOf(self::g($next, 'principal')) . ' (was: ' . self::jsonOf(self::g($prev, 'principal')) . ')');
        }
        if (!AnalyzerJs::strictEq(self::g($prev, 'ontDigest'), self::g($next, 'ontDigest'))) {
            $changes[] = $meta('meta', 'ontology', 'unknown', 'CHANGED ontology: every term now means what the new vocabulary says (was '
                . self::jsonOf(self::g($prev, 'ontDigest')) . ', now ' . self::jsonOf(self::g($next, 'ontDigest')) . ')');
        }
        if (!self::same(self::g($prev, 'wildcardAck'), self::g($next, 'wildcardAck'))) {
            $changes[] = $meta('meta', 'wildcard_ack', 'unknown', 'CHANGED wildcard acknowledgements: ' . self::jsonOf(self::g($next, 'wildcardAck'))
                . ' (was: ' . self::jsonOf(self::g($prev, 'wildcardAck')) . ')');
        }
        if (!AnalyzerJs::strictEq(self::g($prev, 'nlDigest'), self::g($next, 'nlDigest'))) {
            $changes[] = $meta('meta', 'instruction', 'neutral', 'CHANGED the instruction text the goal was interpreted from');
        }
        $wide = array_values(array_filter($changes, self::isWide(...)));
        $rest = array_values(array_filter($changes, static fn($c) => !self::isWide($c)));
        $widenings = count($wide);
        if (count($changes) > $lim['max_diff_changes']) {
            throw new GoalReviewError('diff_too_large', count($changes) . " changes exceed the cap of {$lim['max_diff_changes']}: review the new goal as a whole instead");
        }
        if ($widenings > $lim['max_diff_widenings']) {
            throw new GoalReviewError('too_many_widenings', "$widenings widenings exceed the cap of {$lim['max_diff_widenings']} per review");
        }
        $na = null;
        $ont = Js::opt($opts, 'ontology');
        $newly = $kernel === null ? null : self::kfn($kernel, 'newlyAllowed');
        if (Js::truthy($ont) && $newly !== null) {
            $na = $newly($prev, $next, $ont, $lim['max_witnesses']);
            $na = AnalyzerJs::truthy($na) ? $na : null;
        }
        $witnesses = $na === null ? [] : AnalyzerJs::reqList(self::g($na, 'witnesses'));
        $complete = false;
        if ($na !== null) {
            $c = self::g($na, 'complete');
            $complete = AnalyzerJs::truthy($c) ? count($witnesses) <= $lim['max_witnesses'] : $c;
        }
        return AnalyzerJs::uobj([
            'v' => self::num(1), 'from_goal_digest' => self::go($prev), 'to_goal_digest' => self::go($next),
            'newly_allowed' => array_slice($witnesses, 0, $lim['max_witnesses']), 'newly_allowed_complete' => $complete,
            'changes' => array_merge($wide, $rest), 'widenings' => self::num($widenings),
        ]);
    }

    public static function diffToText(mixed $d): string
    {
        $head = array_map(
            static fn($w) => '!! NEWLY ALLOWED: ' . self::jsonOf(self::g($w, 'verb')) . ' on ' . self::jsonOf(self::g($w, 'res')) . ' with ' . self::jsonOf(self::g($w, 'params')),
            AnalyzerJs::reqList(self::g($d, 'newly_allowed'))
        );
        if (!AnalyzerJs::truthy(self::g($d, 'newly_allowed_complete'))) {
            $head[] = '!! The list of newly allowed actions is incomplete or unavailable: read every widening below.';
        }
        return implode("\n", array_merge($head, array_map(
            static function ($c): string {
                $dir = self::g($c, 'direction');
                return ($dir === 'widen' || $dir === 'unknown' ? '!! ' : '   ') . self::s(self::g($c, 'text'));
            },
            AnalyzerJs::reqList(self::g($d, 'changes'))
        )));
    }

    // ---- GoalApproval -------------------------------------------------------------------------------------------------

    /**
     * @return array{ok:bool,reason?:string,policy?:mixed,digests?:array<string,mixed>}
     */
    private static function derive(mixed $sub, mixed $kernel, mixed $limits): array
    {
        $bad = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        if (!($sub instanceof Obj) || !(self::g($sub, 'goal') instanceof Obj) || !(self::g($sub, 'ontology') instanceof Obj) || !is_string(self::g($sub, 'instruction'))
            || !self::isList(self::g($sub, 'model_set')) || ($sub->has('tests') && !self::isList($sub->get('tests')))) {
            return $bad('malformed_submission');
        }
        foreach ($sub->get('model_set') as $m) {
            if (!is_string($m)) {
                return $bad('malformed_submission');
            }
        }
        $goal = $sub->get('goal');
        $tests = $sub->has('tests') ? $sub->get('tests') : [];
        try {
            $card = self::renderPolicyCard($goal, $tests, $limits === null ? null : ['limits' => $limits]);
        } catch (GoalReviewError $e) {
            return $bad($e->errorCode);
        } catch (\Throwable) {
            return $bad('malformed_goal');
        }
        try {
            $gd = GoalDigests::goalDigest($goal);
            $nl = GoalDigests::nlDigest($sub->get('instruction'));
            $ts = GoalExamples::testsDigest($tests);
            $ms = GoalDigests::modelSetDigest($sub->get('model_set'));
        } catch (\Throwable) {
            return $bad('malformed_goal');
        }
        $gnl = self::g($goal, 'nlDigest');
        if (!is_string($gnl) || $nl !== $gnl) {
            return $bad('instruction_mismatch');
        }
        try {
            $compiled = (self::kfn($kernel, 'compile') ?? throw new \InvalidArgumentException('kernel has no compile'))($goal, $sub->get('ontology'));
        } catch (\Throwable) {
            return $bad('compile_error');
        }
        if (!AnalyzerJs::truthy(self::g($compiled, 'ok'))) {
            return $bad('compile_error');
        }
        $policy = self::g($compiled, 'policy');
        try {
            $analyze = self::kfn($kernel, 'analyze');
            $found = $analyze === null ? [] : $analyze($policy);
            if (($found === null ? 0 : (self::len($found) ?? 0)) > 0) {
                return $bad('analyzer_error');
            }
            $pd = (self::kfn($kernel, 'policyDigest') ?? throw new \InvalidArgumentException('kernel has no policyDigest'))($policy);
        } catch (\Throwable) {
            return $bad('analyzer_error');
        }
        if (count(AnalyzerJs::reqList($tests)) > 0) {
            $decide = self::kfn($kernel, 'decide');
            if ($decide === null) {
                return $bad('tests_unverifiable');
            }
            // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
            foreach ($tests as $t) {
                try {
                    $ont = $sub->get('ontology');
                    if (AnalyzerJs::truthy(self::g($t, 'rels'))) {
                        $ont = AnalyzerJs::spread($ont);
                        $ont->set('rels', self::g($t, 'rels'));
                    }
                    $got = $decide($goal, $ont, self::g($t, 'act'), self::g($t, 'hist'));
                } catch (\Throwable) {
                    return $bad('tests_unverifiable');
                }
                if (!AnalyzerJs::strictEq($got, GoalExamples::expectedDecision(self::g($t, 'answer')))) {
                    return $bad('tests_contradicted');
                }
            }
        }
        return ['ok' => true, 'policy' => $policy, 'digests' => [
            'goal_digest' => $gd, 'policy_digest' => $pd, 'card_digest' => self::cardDigest($card), 'ontology_digest' => self::g($goal, 'ontDigest'),
            'tests_digest' => $ts, 'nl_digest' => $nl, 'model_set_digest' => $ms,
        ]];
    }

    private static function nowMs(): int
    {
        return (int)floor(microtime(true) * 1000);
    }

    /** The kernel of the options (an Obj of callables, as {@see GoalCompiler::provedKernel} returns), the proved one when absent. */
    private static function kernelOf(mixed $k): mixed
    {
        if ($k !== null) {
            return $k;
        }
        require_once __DIR__ . '/GoalCompiler.php';
        return GoalCompiler::provedKernel();
    }

    /**
     * The human step: sign the exact goal. Re-derives everything the loader will; throws when the goal is not signable (holes,
     * wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the compiled policy contradicts,
     * an instruction that does not match `nlDigest`). Options: kernel, now, ttlMs, limits, base, alg, pq. `$reviewerSecret` is what
     * {@see GoalSign} accepts as a signer secret.
     */
    public static function approveGoal(mixed $sub, mixed $reviewerSecret, mixed $opts = null): Obj
    {
        $now = Js::opt($opts, 'now');
        $nowI = $now === null ? self::nowMs() : self::safeInt($now);
        $ttl = Js::opt($opts, 'ttlMs');
        $ttlI = $ttl === null ? self::DEFAULT_TTL_MS : self::safeInt($ttl);
        if ($nowI === null || $ttlI === null || $ttlI <= 0 || $ttlI > self::MAX_GOAL_APPROVAL_TTL_MS) {
            throw new \InvalidArgumentException('approveGoal: invalid time or ttl');
        }
        $kernel = self::kernelOf(Js::opt($opts, 'kernel'));
        $limits = Js::opt($opts, 'limits');
        $d = self::derive($sub, $kernel, $limits);
        if (!$d['ok']) {
            throw new \InvalidArgumentException('approveGoal: ' . $d['reason']);
        }
        $base = Js::opt($opts, 'base');
        if (Js::truthy($base)) {
            self::diffGoals($base, $sub->get('goal'), null, ['limits' => $limits]);
        }
        $body = new Obj();
        foreach ($d['digests'] as $k => $v) {
            $body->set($k, $v);
        }
        $body->set('v', self::num(1));
        $body->set('reviewer', GoalSign::signerId($reviewerSecret));
        $body->set('approved_at', self::num($nowI));
        $body->set('expires_at', self::num($nowI + $ttlI));
        return GoalSign::signGoalArtifact(self::GOAL_APPROVAL_KIND, $body, $reviewerSecret, ['alg' => Js::opt($opts, 'alg'), 'pq' => Js::opt($opts, 'pq')]);
    }

    /**
     * The only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy, re-renders the
     * card and re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission or the
     * approval says about itself. Never throws. Options: kernel, reviewers (pinned), ontology_digest, now, limits.
     */
    public static function loadApprovedGoal(mixed $sub, mixed $approval, mixed $opts): Obj
    {
        try {
            $now = Js::opt($opts, 'now');
            $now = $now === null ? self::nowMs() : $now;
            $reviewers = Js::opt($opts, 'reviewers');
            if (!self::isList($reviewers) || $reviewers === []) {
                return self::fail('no_reviewers_pinned');
            }
            $a = $approval;
            if (!($a instanceof Obj)) {
                return self::fail('malformed_approval');
            }
            $v = self::g($a, 'v');
            $ap = self::safeInt(self::g($a, 'approved_at'), true);
            $ex = self::safeInt(self::g($a, 'expires_at'), true);
            if (!(Js::isNum($v) && Js::num($v) == 1.0) || !is_string(self::g($a, 'sig')) || !is_string(self::g($a, 'reviewer')) || $ap === null || $ex === null) {
                return self::fail('malformed_approval');
            }
            foreach (self::FIELD_REASON as [$f]) {
                if (!is_string(self::g($a, $f))) {
                    return self::fail('malformed_approval');
                }
            }
            $kernel = self::kernelOf(Js::opt($opts, 'kernel'));
            $d = self::derive($sub, $kernel, Js::opt($opts, 'limits'));
            if (!$d['ok']) {
                return self::fail($d['reason']);
            }
            $goal = $sub->get('goal');
            $od = Js::opt($opts, 'ontology_digest');
            if ($od !== null && !AnalyzerJs::strictEq(self::g($goal, 'ontDigest'), $od)) {
                return self::fail('ontology_mismatch');
            }
            foreach (self::FIELD_REASON as [$f, $reason]) {
                if (!AnalyzerJs::strictEq(self::g($a, $f), $d['digests'][$f])) {
                    return self::fail($reason);
                }
            }
            $pinned = false;
            foreach ($reviewers as $p) {
                if (AnalyzerJs::strictEq(is_string($p) ? $p : self::g($p, 'pk'), self::g($a, 'reviewer'))) {
                    $pinned = true;
                    break;
                }
            }
            if (!$pinned) {
                return self::fail('reviewer_not_pinned');
            }
            if ($ex - $ap <= 0 || $ex - $ap > self::MAX_GOAL_APPROVAL_TTL_MS) {
                return self::fail('ttl_too_long');
            }
            $nowOk = Js::isNum($now) && is_finite((float)Js::num($now));
            if (!($nowOk && AnalyzerJs::toNumber(self::g($a, 'approved_at')) <= (float)Js::num($now))) {
                return self::fail('not_yet_valid');
            }
            if (!($nowOk && AnalyzerJs::toNumber($now) < AnalyzerJs::toNumber(self::g($a, 'expires_at')))) {
                return self::fail('expired');
            }
            if (GoalSign::verifyGoalArtifact(self::GOAL_APPROVAL_KIND, $a, 'reviewer', $reviewers) !== true) {
                return self::fail('bad_signature');
            }
            $ref = Obj::of(['goal_digest' => $d['digests']['goal_digest'], 'policy_digest' => $d['digests']['policy_digest']]);
            return Obj::of(['ok' => true, 'approved' => Obj::of([
                'goal' => $goal, 'ontology' => $sub->get('ontology'), 'policy' => $d['policy'], 'ref' => $ref, 'goal_string' => Pca::intentGoalV3($ref),
                'intent_policy' => Obj::of(['approved_goal' => $ref]), 'instruction' => $sub->get('instruction'), 'reviewer' => self::g($a, 'reviewer'),
                'expires_at' => self::g($a, 'expires_at'),
            ])]);
        } catch (\Throwable) {
            return self::fail('malformed_approval');
        }
    }
}
