<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentRegion.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/IntentMapKit.php';

/**
 * Cut refinement and partial answers: a "partly" answer inserts the stated cuts / values (or adds a whole dimension) to the outcome space,
 * re-enumerates the hypotheses and replays every earlier observation as a value-space region. Refinements, partial answers and questions
 * are plain objects (an Obj or an assoc array).
 */
final class IntentRefine
{
    private static function m(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function plain(mixed $x): mixed
    {
        return WalletOmega::plain($x);
    }

    /** A deep copy of a parsed-JSON value (Obj, lists, scalars). */
    private static function deep(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::deep($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::deep(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::deep($x));
            }
            return $o;
        }
        return $v;
    }

    private static function isInteger(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    /** @param list<mixed> $xs */
    private static function uniq(array $xs): array
    {
        $out = [];
        foreach ($xs as $x) {
            if (!in_array($x, $out, false)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    private static function sortU16(array $xs): array
    {
        usort($xs, static fn($a, $b) => Jsx::cmp($a, $b));
        return $xs;
    }

    private static function nonEmpty(mixed $x): bool
    {
        return is_array($x) ? count($x) > 0 : Js::truthy($x);
    }

    /** @return list<Obj> the exact values, the prefix values and the OTHER cell, each group deduplicated and sorted */
    private static function sortedCat(array $values): array
    {
        $ex = $pre = [];
        foreach ($values as $v) {
            if (self::m($v, 'kind') === 'exact' && !in_array(self::m($v, 'value'), $ex, true)) {
                $ex[] = self::m($v, 'value');
            }
            if (self::m($v, 'kind') === 'prefix' && !in_array(self::m($v, 'value'), $pre, true)) {
                $pre[] = self::m($v, 'value');
            }
        }
        $out = [];
        foreach (self::sortU16($ex) as $v) {
            $out[] = Obj::of(['kind' => 'exact', 'value' => $v]);
        }
        foreach (self::sortU16($pre) as $v) {
            $out[] = Obj::of(['kind' => 'prefix', 'value' => $v]);
        }
        $out[] = Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER]);
        return $out;
    }

    private static function inRange(array $cuts, mixed $lo, mixed $hi): array
    {
        $r = array_values(array_filter(self::uniq($cuts), static fn($c) => $c >= $lo && $c <= $hi));
        sort($r);
        return $r;
    }

    /** Omega with one verb's dimension refined (a deep copy; other verbs and the weights are unchanged). */
    public static function refineOmega(mixed $omega, mixed $r): Obj
    {
        $out = self::deep(self::plain($omega));
        $r = self::plain($r);
        $verb = self::m($r, 'verb');
        $path = self::m($r, 'path');
        $vs = null;
        foreach (self::m($out, 'verbs') as $v) {
            if (self::m($v, 'verb') === $verb) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            throw new \InvalidArgumentException("refineOmega: no verb $verb in \u{03A9}");
        }
        $dims = self::m($vs, 'dims');
        $i = -1;
        foreach ($dims as $k => $d) {
            if (self::m($d, 'path') === $path) {
                $i = $k;
                break;
            }
        }
        $newDim = self::m($r, 'newDim');
        if (Js::truthy($newDim)) {
            if ($i >= 0) {
                throw new \InvalidArgumentException("refineOmega: $path is already a dimension of $verb");
            }
            if (self::m($newDim, 'path') !== $path) {
                throw new \InvalidArgumentException('refineOmega: newDim.path must equal path');
            }
            $d = self::deep($newDim);
            if (self::m($d, 'kind') === 'cat') {
                $d->set('values', self::sortedCat(self::m($d, 'values')));
            } else {
                $d->set('cuts', self::inRange(self::m($d, 'cuts'), self::m($d, 'lo'), self::m($d, 'hi')));
            }
            $dims[] = $d;
            $dims = self::sortByPath($dims);
            $vs->set('dims', $dims);
            return $out;
        }
        if ($i < 0) {
            throw new \InvalidArgumentException("refineOmega: $verb has no dimension $path (pass newDim to add it)");
        }
        $d = $dims[$i];
        if (self::m($d, 'kind') === 'num') {
            if (self::nonEmpty(self::m($r, 'values')) || self::nonEmpty(self::m($r, 'prefixes'))) {
                throw new \InvalidArgumentException("refineOmega: $path is numeric");
            }
            $cuts = array_values(array_filter(self::m($r, 'cuts') ?? [], static fn($c) => self::isInteger($c)));
            $d->set('cuts', self::inRange(array_merge(self::m($d, 'cuts'), $cuts), self::m($d, 'lo'), self::m($d, 'hi')));
        } else {
            if (self::nonEmpty(self::m($r, 'cuts'))) {
                throw new \InvalidArgumentException("refineOmega: $path is categorical");
            }
            $all = self::m($d, 'values');
            foreach (self::m($r, 'values') ?? [] as $v) {
                $all[] = Obj::of(['kind' => 'exact', 'value' => $v]);
            }
            foreach (self::m($r, 'prefixes') ?? [] as $v) {
                $all[] = Obj::of(['kind' => 'prefix', 'value' => $v]);
            }
            $vals = self::sortedCat($all);
            if (count($vals) > 20) {
                throw new \InvalidArgumentException("refineOmega: $path would have more than 20 values");
            }
            $d->set('values', $vals);
        }
        return $out;
    }

    private static function sortByPath(array $dims): array
    {
        usort($dims, static fn($a, $b) => Jsx::cmp(self::m($a, 'path'), self::m($b, 'path')));
        return $dims;
    }

    private static function vsOf(mixed $omega, mixed $verb): mixed
    {
        foreach (self::m($omega, 'verbs') as $v) {
            if (self::m($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    /** The value-space region an observation was about, in the omega it was recorded in. */
    public static function regionOfObservation(mixed $omega, mixed $o): mixed
    {
        $region = self::m($o, 'region');
        if (Js::truthy($region)) {
            return $region;
        }
        $vs = self::vsOf($omega, self::m($o, 'verb'));
        if ($vs === null) {
            throw new \InvalidArgumentException('regionOfObservation: no verb ' . self::m($o, 'verb'));
        }
        return IntentRegion::regionOfCell($vs, array_values(self::m($o, 'cell')));
    }

    /**
     * Rebuild a learner over a refined omega and replay every observation as a region (rescope may rewrite a region).
     * @param (\Closure(mixed,mixed):mixed)|null $rescope
     */
    public static function refineLearner(IntentLearner $l, mixed $r, ?\Closure $rescope = null): IntentLearner
    {
        $omega = self::refineOmega($l->omega, $r);
        $nxt = IntentMapKit::createLearner($omega, IntentMapKit::learnerOptionsOf($l));
        foreach ($l->observations as $o) {
            $region = self::regionOfObservation($l->omega, $o);
            if ($rescope !== null) {
                $region = $rescope($o, $region);
            }
            $vs = self::vsOf($omega, $o['verb']);
            $values = self::deep($o['values']);
            foreach (self::m($vs, 'dims') as $d) {
                if (!$values->has(self::m($d, 'path'))) {
                    $values->set(self::m($d, 'path'), IntentOmega::repValue($d, 0));
                }
            }
            $nxt->observe(Obj::of(['verb' => $o['verb'], 'values' => $values]), $o['y'], $o['source'], $region);
        }
        return $nxt;
    }

    private static function partLabel(mixed $d, int $j, mixed $parts): ?int
    {
        $x = IntentOmega::repValue($d, $j);
        foreach ($parts as $p) {
            if (Js::has($p, 'lo')) {
                if (self::m($d, 'kind') !== 'num') {
                    continue;
                }
                $c = IntentOmega::numCells($d)[$j];
                if ($c->get('lo') >= self::m($p, 'lo') && $c->get('hi') <= self::m($p, 'hi')) {
                    return (int)Js::num(self::m($p, 'y'));
                }
            } elseif (Js::has($p, 'values')) {
                if (self::m($d, 'kind') === 'cat' && self::m(self::m($d, 'values')[$j], 'kind') === 'exact' && in_array((string)$x, self::m($p, 'values'), true)) {
                    return (int)Js::num(self::m($p, 'y'));
                }
            } elseif (self::m($d, 'kind') === 'cat' && self::m(self::m($d, 'values')[$j], 'kind') !== 'exact') {
                return (int)Js::num(self::m($p, 'y'));
            }
        }
        return null;
    }

    /** Sub-cells of dimension d (in the refined omega) that lie inside the questioned region's dimension. @return list<int> */
    private static function subCells(mixed $d, mixed $region): array
    {
        $n = IntentOmega::cellCount($d);
        $rd = self::m(self::m($region, 'dims'), self::m($d, 'path'));
        $out = [];
        for ($j = 0; $j < $n; $j++) {
            if (!Js::truthy($rd)) {
                $out[] = $j;
            } elseif (self::m($d, 'kind') === 'num' && self::m($rd, 'kind') === 'num') {
                $c = IntentOmega::numCells($d)[$j];
                if ($c->get('lo') >= self::m($rd, 'lo') && $c->get('hi') <= self::m($rd, 'hi')) {
                    $out[] = $j;
                }
            } elseif (self::m($d, 'kind') === 'cat' && self::m($rd, 'kind') === 'cat') {
                $cell = IntentOmega::catCellOf(Obj::of(['kind' => 'cat', 'path' => self::m($d, 'path'), 'values' => self::m($rd, 'values')]), IntentOmega::repValue($d, $j));
                if (in_array($cell, self::m($rd, 'cells'), false)) {
                    $out[] = $j;
                }
            }
        }
        return $out;
    }

    /**
     * Apply a partial answer to question q ({verb, cell, outcome, ...}): a NEW learner over the refined omega and the observations the
     * answer added.
     * @return array{learner:IntentLearner,added:list<array<string,mixed>>}
     */
    public static function answerPartial(IntentLearner $l, mixed $q, mixed $a): array
    {
        $q = self::plain($q);
        $a = self::plain($a);
        $verb = self::m($q, 'verb');
        $oldVs = self::vsOf($l->omega, $verb);
        if ($oldVs === null) {
            throw new \InvalidArgumentException("answerPartial: no verb $verb");
        }
        $cell = array_values(self::m($q, 'cell'));
        $qRegion = IntentRegion::regionOfCell($oldVs, $cell);
        $path = self::m($a, 'path');
        $r = Obj::of(['verb' => $verb, 'path' => $path]);
        foreach (['cuts', 'values', 'newDim'] as $k) {
            if (self::nonEmpty(self::m($a, $k))) {
                $r->set($k, self::m($a, $k));
            }
        }
        $refined = self::refineOmega($l->omega, $r);
        $nvs = self::vsOf($refined, $verb);
        $d = null;
        foreach (self::m($nvs, 'dims') as $x) {
            if (self::m($x, 'path') === $path) {
                $d = $x;
                break;
            }
        }
        if ($d === null) {
            throw new \OutOfBoundsException('answerPartial: no such dimension');
        }
        $rescope = null;
        if (Js::truthy(self::m($a, 'newDim'))) {
            $nD = IntentOmega::cellCount($d);
            $yesCells = [];
            for ($j = 0; $j < $nD; $j++) {
                if (self::partLabel($d, $j, self::m($a, 'parts')) === 1) {
                    $yesCells[] = $j;
                }
            }
            $rescope = static function (mixed $o, mixed $region) use ($verb, $d, $yesCells) {
                if ($o['verb'] !== $verb || $o['y'] !== 1) {
                    return $region;
                }
                if (self::m($d, 'kind') === 'cat') {
                    return IntentRegion::restrictRegion($region, $d, Obj::of(['cells' => $yesCells]));
                }
                // numeric: restrict to the contiguous accepted span (the "typical" range the earlier yes was about)
                if (count($yesCells) === 0) {
                    return IntentRegion::restrictRegion($region, $d, Obj::of(['lo' => self::m($d, 'hi') + 1, 'hi' => self::m($d, 'hi') + 1]));
                }
                $cells = IntentOmega::numCells($d);
                return IntentRegion::restrictRegion($region, $d, Obj::of(['lo' => $cells[$yesCells[0]]->get('lo'), 'hi' => $cells[$yesCells[count($yesCells) - 1]]->get('hi')]));
            };
        }
        $nxt = self::refineLearner($l, $r, $rescope);
        $added = [];
        foreach (self::subCells($d, $qRegion) as $j) {
            $y = self::partLabel($d, $j, self::m($a, 'parts'));
            if ($y === null) {
                continue;
            }
            if (self::m($d, 'kind') === 'num') {
                $c = IntentOmega::numCells($d)[$j];
                $region = IntentRegion::restrictRegion($qRegion, $d, Obj::of(['lo' => $c->get('lo'), 'hi' => $c->get('hi')]));
            } else {
                $region = IntentRegion::restrictRegion($qRegion, $d, Obj::of(['cells' => [$j]]));
            }
            $values = self::deep(self::m(self::m($q, 'outcome'), 'values'));
            $values->set(self::m($d, 'path'), IntentOmega::repValue($d, $j));
            foreach (self::m($nvs, 'dims') as $x) {
                if (!$values->has(self::m($x, 'path'))) {
                    $values->set(self::m($x, 'path'), IntentOmega::repValue($x, 0));
                }
            }
            $ob = $nxt->observe(Obj::of(['verb' => $verb, 'values' => $values]), $y, 'elicitation', $region);
            if ($ob) {
                $added[] = $ob;
            }
        }
        return ['learner' => $nxt, 'added' => $added];
    }

    /**
     * Elicitation that accepts "yes", "no" and "partly": the stop rule and audit of `elicit`, a partial answer counts as one question and
     * swaps in the refined learner; after maxRefinements partial answers a further one is treated as "no". $answer is a Closure(question,
     * learner): 0 | 1 | a partial answer (an Obj / assoc array) | null.
     * @return array<string,mixed>
     */
    public static function elicitAdaptive(IntentLearner $learner, \Closure $answer, mixed $o): array
    {
        $l = $learner;
        $asked = [];
        $refinements = 0;
        $maxRef = self::m($o, 'maxRefinements');
        $maxRef = $maxRef === null ? 8 : (float)Js::num($maxRef);
        $maxQ = (float)Js::num(self::m($o, 'maxQuestions'));
        $epsRisk = (float)Js::num(self::m($o, 'epsRisk'));
        $epsBurden = (float)Js::num(self::m($o, 'epsBurden'));
        $apply = static function (array $q) use (&$l, &$asked, &$refinements, $maxRef, $answer): void {
            $a = $answer($q, $l);
            $asked[] = $q;
            if ($a === null || $a instanceof Obj || (is_array($a) && !array_is_list($a))) {
                if ($refinements < $maxRef) {
                    $l = self::answerPartial($l, $q, $a)['learner'];
                    $refinements++;
                } else {
                    $l->observe($q['outcome'], 0, 'elicitation');
                }
            } else {
                $l->observe($q['outcome'], (int)Js::num($a), 'elicitation');
            }
        };
        $seedQuestions = 0;
        $seeds = self::m($o, 'seed');
        foreach (Js::truthy($seeds) ? $seeds : [] as $s) {
            if (!(count($asked) < $maxQ)) {
                break;
            }
            $vs = self::vsOf($l->omega, self::m($s, 'verb'));
            $cell = self::m($s, 'cell');
            if ($vs === null || count($cell) !== count(self::m($vs, 'dims'))) {
                continue;
            }
            $values = new Obj();
            foreach (self::m($vs, 'dims') as $k => $d) {
                $values->set(self::m($d, 'path'), IntentOmega::repValue($d, $cell[$k]));
            }
            $outcome = Obj::of(['verb' => self::m($s, 'verb'), 'values' => $values]);
            $p = $l->acceptance($outcome);
            if ($p <= 1e-9 || $p >= 1 - 1e-9 || $l->isVetoed($outcome)) {
                continue;
            }
            $apply(['verb' => self::m($s, 'verb'), 'cell' => array_values($cell), 'outcome' => $outcome, 'p' => $p, 'score' => 0]);
            $seedQuestions++;
        }
        $stop = null;
        while ($stop === null) {
            $m = $l->metrics();
            if ($m['residualRisk'] <= $epsRisk && $m['burden'] <= $epsBurden) {
                $stop = 'converged';
            } elseif (!(count($asked) < $maxQ)) {
                $stop = 'budget';
            } else {
                $q = $l->nextQuestion();
                if ($q === null) {
                    $stop = 'no-disagreement';
                } else {
                    $apply($q);
                }
            }
        }
        $auditQuestions = 0;
        if (Js::truthy(self::m($o, 'audit'))) {
            while (true) {
                $pending = $l->unconfirmedGrantCells();
                $total = 0.0;
                foreach ($pending as $x) {
                    $total += $x['weight'];
                }
                if (count($pending) === 0 || $total <= $epsRisk) {
                    break;
                }
                if (!(count($asked) < $maxQ)) {
                    $stop = 'budget';
                    break;
                }
                $top = $pending[0];
                $vs = self::vsOf($l->omega, $top['verb']);
                $outcome = IntentOmega::cellRep($vs, $top['cell']);
                $apply(['verb' => $top['verb'], 'cell' => $top['cell'], 'outcome' => $outcome, 'p' => $l->acceptance($outcome), 'score' => $top['weight']]);
                $auditQuestions++;
            }
        }
        return ['stop' => $stop, 'questions' => count($asked), 'auditQuestions' => $auditQuestions, 'seedQuestions' => $seedQuestions, 'asked' => $asked,
            'learner' => $l, 'refinements' => $refinements];
    }
}
