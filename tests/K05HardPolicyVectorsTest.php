<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** policy-vectors.json: the whole policy decision (reason codes + failed types per group) and the caveat projection, all 413 rows. */
final class K05HardPolicyVectorsTest extends TestCase
{
    /** The tool call an action denotes (policy-vm toolCallOf): tool = the verb, args = the params object (else empty). */
    private static function toolCall(Obj $context): array
    {
        $a = $context->get('action');
        $params = $a instanceof Obj ? $a->get('params') : null;
        return ['tool' => $a instanceof Obj && is_string($a->get('verb')) ? $a->get('verb') : '', 'args' => $params instanceof Obj ? $params : new Obj()];
    }

    /** @return array{allow: bool, reasons: list<string>, failed: array<string, list<string>>} */
    private static function decision(Obj $v): array
    {
        $grant = $v->get('grant');
        $chain = $v->get('chain');
        $context = $v->get('context');
        $action = Obj::of(['action' => $context->get('action')]);
        $cctx = Obj::of([]);
        foreach ($context->keys() as $k) {
            if ($k !== 'delegation_depth') {
                $cctx->set($k, $context->get($k));
            }
        }
        if (is_array($chain) && $chain !== []) {
            $cctx->set('delegation_depth', new Num((string)(count($chain) - 1)));
        }
        $reasons = [];
        $failed = ['envelope' => [], 'root' => [], 'delegated' => []];
        $env = Authorize::readEnvelope($grant);
        if ($env === null) {
            return ['allow' => false, 'reasons' => ['envelope_missing'], 'failed' => $failed];
        }
        $pr = \Atlas\Pca\Predicates::evaluatePredicates($env->get('predicates'), $action);
        if (($pr['allowed'] ?? false) !== true) {
            $reasons[] = 'predicates_unsatisfied';
        }
        $extra = null;
        if (!is_array($chain) || $chain === []) {
            $reasons[] = 'chain_malformed';
        } else {
            $leaf = $chain[count($chain) - 1];
            $extra = array_slice($leaf->get('caveats'), count($grant->get('caveats')));
        }
        $groups = [['envelope_caveats_unsatisfied', 'envelope', $env->get('caveats')], ['root_caveats_unsatisfied', 'root', Authorize::rootCaveats($grant)], ['delegated_caveats_unsatisfied', 'delegated', $extra]];
        foreach ($groups as [$code, $key, $list]) {
            if ($list === null) {
                continue;
            }
            $r = Authorize::evaluateAgentCaveats($list, $cctx, $action, self::toolCall($context));
            if (!$r['ok']) {
                $reasons[] = $code;
                $failed[$key] = $r['failed'];
            }
        }
        return ['allow' => $reasons === [], 'reasons' => $reasons, 'failed' => $failed];
    }

    public function testPolicyDecisionVectors(): void
    {
        $rows = Vectors::load('policy-vectors.json')->get('policy_decision');
        $this->assertGreaterThanOrEqual(413, count($rows));
        $bad = [];
        foreach ($rows as $v) {
            $n = $v->get('name');
            try {
                $x = $v->get('expect');
                $d = self::decision($v);
                $xd = $x->get('decision');
                $want = ['allow' => $xd->get('allow'), 'reasons' => $xd->get('reasons'), 'failed' => ['envelope' => $xd->get('failed')->get('envelope'), 'root' => $xd->get('failed')->get('root'), 'delegated' => $xd->get('failed')->get('delegated')]];
                if ($d !== $want) {
                    $bad[] = "$n decision: got " . json_encode($d) . ' want ' . json_encode($want);
                }
                $c = Authorize::evaluateAgentCaveats(Pca::policyCaveats($v->get('grant'), $v->get('chain')), $v->get('context'), Obj::of(['action' => $v->get('context')->get('action')]), self::toolCall($v->get('context')));
                $xc = $x->get('caveats');
                if ($c['ok'] !== $xc->get('allow') || $c['failed'] !== $xc->get('failed')) {
                    $bad[] = "$n caveats: got " . json_encode($c) . ' want ' . json_encode(['allow' => $xc->get('allow'), 'failed' => $xc->get('failed')]);
                }
            } catch (\Throwable $t) {
                $bad[] = "$n THREW " . get_class($t) . ': ' . $t->getMessage();
            }
        }
        $this->assertSame([], array_slice($bad, 0, 15), count($bad) . ' policy rows failed');
    }
}
