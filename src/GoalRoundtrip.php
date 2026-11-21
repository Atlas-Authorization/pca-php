<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalCard.php';
require_once __DIR__ . '/GoalCodec.php';
require_once __DIR__ . '/GoalInterpret.php';
require_once __DIR__ . '/GoalNormalize.php';

/**
 * Round-trip checks: the lossless card tape, semantic widening mutations and the explainer + comparator detector, measured by
 * mutation and tighten-only (it can only escalate). An explainer is a callable `(list<string> proseLines): string`; a comparator a
 * callable `(string goalText, string explanation): {equivalent, reason?}`.
 */
final class GoalRoundtrip
{
    public const MUTATION_KINDS = ['widen_cap', 'widen_where', 'drop_prohibit', 'drop_bound', 'swap_resource', 'add_grant'];

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    /** decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape. */
    public static function cardRoundTrips(mixed $g): bool
    {
        return GoalNormalize::stable(GoalCodec::decodeGoal(GoalCodec::encodeGoal($g))) === GoalNormalize::stable($g);
    }

    /** The explainer sees ONLY the compiled card lines, never the goal text or the model's reasoning: 'ok' or 'escalate'. */
    public static function roundTrip(mixed $goal, mixed $goalText, callable $explainer, callable $comparator): string
    {
        try {
            $e = $explainer(self::g(GoalCard::renderCard($goal), 'lines'));
            return AnalyzerJs::truthy(self::g($comparator($goalText, $e), 'equivalent')) ? 'ok' : 'escalate';
        } catch (\Throwable) {
            return 'escalate';
        }
    }

    /** Offline reference explainer: the card lines themselves, joined by newlines. */
    public static function deterministicExplainer(): GoalCardExplainer
    {
        return new GoalCardExplainer();
    }

    /** Offline reference comparator: the card lines judged lexically (ids, amounts). */
    public static function lexicalComparator(mixed $o): GoalLexicalComparator
    {
        return new GoalLexicalComparator($o);
    }

    private static function scale(mixed $x, int $f): mixed
    {
        $k = self::g(self::g($x, 'u'), 'k');
        if ($k !== 'money' && $k !== 'count') {
            return $x;
        }
        $c = AnalyzerJs::spread($x);
        $n = AnalyzerJs::toNumber(self::g($x, 'n')) * $f;
        $c->set('n', is_finite($n) && $n == floor($n) && abs($n) < 9007199254740992.0 ? (int)$n : $n);
        return $c;
    }

    private static function mapLits(mixed $c, callable $f): mixed
    {
        $k = self::g($c, 'k');
        if ($k === 'cmp') {
            $r = self::g($c, 'r');
            $hit = self::g($r, 'k') === 'lit' && self::g(self::g($r, 'v'), 'k') === 'q' && in_array(self::g($c, 'op'), ['lte', 'lt'], true);
            $o = AnalyzerJs::spread($c);
            $o->set('r', $hit ? Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => $f(self::g(self::g($r, 'v'), 'q'))])]) : $r);
            return $o;
        }
        if ($k === 'and' || $k === 'or') {
            $o = AnalyzerJs::spread($c);
            $o->set('a', self::mapLits(self::g($c, 'a'), $f));
            $o->set('b', self::mapLits(self::g($c, 'b'), $f));
            return $o;
        }
        return $c;
    }

    /** Semantic mutations that WIDEN the policy (or leave it equal); null when the goal has nothing to mutate. */
    public static function mutateGoal(mixed $g, mixed $kind, mixed $ontology): ?Obj
    {
        $x = Js::parse(Js::stringify($g)); // JSON.parse(JSON.stringify(g)): an independent deep copy
        $ten = static fn(mixed $z): mixed => self::scale($z, 10);
        switch ($kind) {
            case 'widen_cap':
                $b = self::g(self::g($x, 'bounds'), '0');
                if (!AnalyzerJs::truthy($b)) {
                    return null;
                }
                $b->set('cap', self::scale(self::g($b, 'cap'), 10));
                return $x;
            case 'widen_where':
                foreach (AnalyzerJs::reqList(self::g($x, 'grants')) as $y) {
                    if (Js::stringify(self::mapLits(self::g($y, 'cond'), $ten)) !== Js::stringify(self::g($y, 'cond'))) {
                        $y->set('cond', self::mapLits(self::g($y, 'cond'), $ten));
                        return $x;
                    }
                }
                return null;
            case 'drop_prohibit':
            case 'drop_bound':
                $key = $kind === 'drop_prohibit' ? 'prohibits' : 'bounds';
                $xs = AnalyzerJs::reqList(self::g($x, $key));
                if ($xs === []) {
                    return null;
                }
                array_pop($xs);
                $x->set($key, $xs);
                return $x;
            case 'swap_resource':
                foreach (AnalyzerJs::reqList(self::g($x, 'grants')) as $y) {
                    if (self::g(self::g($y, 'res'), 'k') === 'exact') {
                        $y->set('res', Obj::of(['k' => 'exact', 'id' => AnalyzerJs::jsStr(self::g(self::g($y, 'res'), 'id')) . '9']));
                        return $x;
                    }
                }
                return null;
            case 'add_grant':
                $grants = AnalyzerJs::reqList(self::g($x, 'grants'));
                $have = array_map(static fn(mixed $y): mixed => self::g($y, 'verb'), $grants);
                $prohibits = AnalyzerJs::reqList(self::g($x, 'prohibits'));
                $v = null;
                foreach (AnalyzerJs::reqList(self::g($ontology, 'verbs')) as $y) {
                    if (self::g($y, 'effect') === 'read' || AnalyzerJs::includes($have, self::g($y, 'id'))) {
                        continue;
                    }
                    $banned = false;
                    foreach ($prohibits as $p) {
                        if (self::g(self::g($p, 'target'), 'k') === 'verb' && AnalyzerJs::strictEq(self::g(self::g($p, 'target'), 'verb'), self::g($y, 'id'))) {
                            $banned = true;
                            break;
                        }
                    }
                    if (!$banned) {
                        $v = $y;
                        break;
                    }
                }
                if ($v === null) {
                    return null;
                }
                $grants[] = Obj::of(['gid' => 'injected', 'verb' => self::g($v, 'id'), 'res' => Obj::of(['k' => 'any', 'reason' => 'injected']), 'cond' => Obj::of(['k' => 'true'])]);
                $x->set('grants', $grants);
                $ack = AnalyzerJs::reqList(self::g($x, 'wildcardAck'));
                $ack[] = 'injected';
                $x->set('wildcardAck', $ack);
                return GoalNormalize::canonicalizeGoal($x);
            default:
                return null;
        }
    }

    /**
     * Fraction of semantic widenings the explainer + comparator pair flags (they can only escalate; this is a measured detector).
     * @return list<Obj> one `{kind, applied, detected, rate}` per mutation kind
     */
    public static function measureDetection(mixed $cases, mixed $ontology, callable $explainer, callable $comparator): array
    {
        $out = [];
        foreach (self::MUTATION_KINDS as $kind) {
            $applied = 0;
            $detected = 0;
            foreach (AnalyzerJs::reqList($cases) as $c) {
                $m = self::mutateGoal(self::g($c, 'goal'), $kind, $ontology);
                if ($m === null) {
                    continue;
                }
                $applied++;
                if (self::roundTrip($m, self::g($c, 'text'), $explainer, $comparator) === 'escalate') {
                    $detected++;
                }
            }
            $out[] = Obj::of(['kind' => $kind, 'applied' => $applied, 'detected' => $detected, 'rate' => $applied > 0 ? $detected / $applied : 0]);
        }
        return $out;
    }
}

/** The offline reference explainer: the compiled card lines joined by newlines. */
final class GoalCardExplainer
{
    public function id(): string
    {
        return 'card-prose';
    }

    /** @param list<string> $proseLines */
    public function explain(array $proseLines): string
    {
        return implode("\n", $proseLines);
    }

    public function __invoke(mixed $proseLines): string
    {
        return $this->explain(AnalyzerJs::reqList($proseLines));
    }
}

/** The offline reference comparator: ids and amounts of the goal text against those of the explanation. */
final class GoalLexicalComparator
{
    public function __construct(private readonly mixed $o)
    {
    }

    public function id(): string
    {
        return 'lexical';
    }

    public function family(): string
    {
        return 'rule';
    }

    /** `{equivalent, reason?}` */
    public function equivalent(mixed $text, mixed $explanation): Obj
    {
        $a = GoalInterpret::extractCandidates($text, $this->o);
        $b = GoalInterpret::extractCandidates($explanation, $this->o);
        $bAmounts = [];
        if (preg_match_all('/([0-9]+) ([A-Z]{3}) minor units/', (string)$explanation, $ms, PREG_SET_ORDER) > 0) {
            foreach ($ms as $m) {
                $bAmounts[] = [$m[2], (float)$m[1]]; // Number(): huge values are doubles
            }
        }
        $ids = static function (mixed $x): string {
            $u = [];
            foreach (AnalyzerJs::reqList($x) as $e) {
                if (!AnalyzerJs::includes($u, $e)) {
                    $u[] = $e;
                }
            }
            $s = array_map(static fn(mixed $e): string => AnalyzerJs::jsStr($e), $u);
            usort($s, static fn(string $p, string $q): int => AnalyzerJs::u16cmp($p, $q));
            return implode(',', $s);
        };
        if ($ids(AnalyzerJs::jget($a, 'ids')) !== $ids(AnalyzerJs::jget($b, 'ids'))) {
            return Obj::of(['equivalent' => false, 'reason' => 'ids differ']);
        }
        // every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
        $aAmounts = AnalyzerJs::reqList(AnalyzerJs::jget($a, 'amounts'));
        $wrote = [];
        foreach ($aAmounts as $m) {
            $wrote[AnalyzerJs::jsStr(AnalyzerJs::jget($m, 'ccy')) . AnalyzerJs::jsStr(AnalyzerJs::jget($m, 'minor'))] = true;
        }
        foreach ($bAmounts as [$ccy, $minor]) {
            if (!isset($wrote[$ccy . AnalyzerJs::jsStr($minor)])) {
                return Obj::of(['equivalent' => false, 'reason' => "amount $ccy " . AnalyzerJs::jsStr($minor) . ' not stated by the principal']);
            }
        }
        if ($aAmounts !== [] && $bAmounts === []) {
            return Obj::of(['equivalent' => false, 'reason' => 'no amount in the policy']);
        }
        return Obj::of(['equivalent' => true]);
    }

    public function __invoke(mixed $text, mixed $explanation): Obj
    {
        return $this->equivalent($text, $explanation);
    }
}
