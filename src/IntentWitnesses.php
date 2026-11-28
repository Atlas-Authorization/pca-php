<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentPolicy.php';

/**
 * Specification by example for a fixed grant: boundary, verb and unconstrained witness actions to ask the principal about. Questions are
 * rendered by IntentRender::renderQuestion.
 */
final class IntentWitnesses
{
    /**
     * @return list<array<string,mixed>> witnesses {kind, side, verb, cell, outcome, grantAllows, facet, question}
     */
    public static function boundaryWitnesses(mixed $grant, mixed $omega, mixed $catalog = null): array
    {
        require_once __DIR__ . '/IntentRender.php';
        $omega = WalletOmega::plain($omega);
        $g = IntentPolicy::admitter($grant);
        $out = [];
        $seen = [];
        $push = static function (mixed $vs, string $kind, array $idx, bool $allows, string $facet) use (&$out, &$seen, $catalog): void {
            $key = Js::opt($vs, 'verb') . '|' . implode(',', $idx);
            if (isset($seen[$key])) {
                return;
            }
            $seen[$key] = true;
            $out[] = ['kind' => $kind, 'side' => $allows ? 'inside' : 'outside', 'verb' => Js::opt($vs, 'verb'), 'cell' => $idx,
                'outcome' => IntentOmega::cellRep($vs, $idx), 'grantAllows' => $allows, 'facet' => $facet, 'question' => IntentRender::renderQuestion($vs, $idx, $catalog)];
        };
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $verb = Js::opt($vs, 'verb');
            $dims = Js::opt($vs, 'dims');
            $n = IntentOmega::verbCellCount($vs);
            $acc = array_fill(0, $n, 0);
            $mass = array_fill(0, $n, 0.0);
            $typical = -1;
            $typicalOut = -1;
            for ($c = 0; $c < $n; $c++) {
                $idx = IntentOmega::decodeCell($vs, $c);
                $acc[$c] = $g->admits($vs, IntentOmega::cellRep($vs, $idx)) ? 1 : 0;
                $mass[$c] = IntentOmega::cellStats($vs, $idx)['mass'];
                if ($acc[$c] && ($typical < 0 || $mass[$c] > $mass[$typical])) {
                    $typical = $c;
                }
                if ($typicalOut < 0 || $mass[$c] > $mass[$typicalOut]) {
                    $typicalOut = $c;
                }
            }
            if ($typical < 0) {
                $push($vs, 'verb', IntentOmega::decodeCell($vs, $typicalOut), false, "$verb|verb");
                continue;
            }
            $base = IntentOmega::decodeCell($vs, $typical);
            $push($vs, 'verb', $base, true, "$verb|verb");
            $best = [];
            for ($c = 0; $c < $n; $c++) {
                if (!$acc[$c]) {
                    continue;
                }
                $idx = IntentOmega::decodeCell($vs, $c);
                foreach ($dims as $k => $d) {
                    $nk = IntentOmega::cellCount($d);
                    $isNum = Js::opt($d, 'kind') === 'num';
                    if ($isNum) {
                        $neigh = array_values(array_filter([$idx[$k] - 1, $idx[$k] + 1], static fn(int $x) => $x >= 0 && $x < $nk));
                    } else {
                        $neigh = array_values(array_filter(range(0, $nk - 1), static fn(int $x) => $x !== $idx[$k]));
                    }
                    foreach ($neigh as $x) {
                        $j = $idx;
                        $j[$k] = $x;
                        if ($acc[IntentOmega::encodeCell($vs, $j)]) {
                            continue;
                        }
                        $facet = $isNum ? "$verb|" . Js::opt($d, 'path') . '|' . min($x, $idx[$k]) . '~' . max($x, $idx[$k]) : "$verb|" . Js::opt($d, 'path') . "|$x";
                        $shared = 0;
                        foreach ($idx as $t => $v) {
                            if ($t !== $k && $v === $base[$t]) {
                                $shared++;
                            }
                        }
                        $score = $shared * 10 + $mass[$c];
                        $prev = $best[$facet] ?? null;
                        if ($prev === null || $score > $prev['score']) {
                            $best[$facet] = ['ins' => $idx, 'outs' => $j, 'score' => $score];
                        }
                    }
                }
            }
            $facets = array_map('strval', array_keys($best));
            usort($facets, static fn($a, $b) => Jsx::cmp($a, $b));
            foreach ($facets as $facet) {
                $b = $best[$facet];
                $push($vs, 'boundary', $b['ins'], true, $facet);
                $push($vs, 'boundary', $b['outs'], false, $facet);
            }
            foreach ($dims as $k => $d) {
                $nk = IntentOmega::cellCount($d);
                if ($nk < 2) {
                    continue;
                }
                $depends = false;
                for ($c = 0; $c < $n && !$depends; $c++) {
                    $idx = IntentOmega::decodeCell($vs, $c);
                    for ($x = 0; $x < $nk && !$depends; $x++) {
                        $j = $idx;
                        $j[$k] = $x;
                        if ($acc[IntentOmega::encodeCell($vs, $j)] !== $acc[$c]) {
                            $depends = true;
                        }
                    }
                }
                if ($depends) {
                    continue;
                }
                $j = $base;
                if (Js::opt($d, 'kind') === 'num') {
                    $j[$k] = $nk - 1;
                } else {
                    $j[$k] = -1;
                    foreach (Js::opt($d, 'values') as $i => $v) {
                        if (Js::opt($v, 'kind') === 'other') {
                            $j[$k] = $i;
                            break;
                        }
                    }
                }
                $push($vs, 'unconstrained', $j, true, "$verb|" . Js::opt($d, 'path') . '|unconstrained');
            }
        }
        return $out;
    }

    /**
     * Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree.
     * @param list<mixed> $witnesses
     * @param \Closure(mixed):bool $oracle
     * @return array{questions:int,mismatches:list<mixed>}
     */
    public static function checkWitnesses(array $witnesses, \Closure $oracle): array
    {
        $mismatches = [];
        foreach ($witnesses as $w) {
            if ($oracle($w) !== Js::opt($w, 'grantAllows')) {
                $mismatches[] = $w;
            }
        }
        return ['questions' => count($witnesses), 'mismatches' => $mismatches];
    }
}
