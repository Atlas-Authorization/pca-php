<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/GoalDigests.php';
require_once __DIR__ . '/../src/GoalBinding.php';
require_once __DIR__ . '/../src/Decision.php';
require_once __DIR__ . '/../src/Json.php';

use Atlas\Pca\Decision;
use Atlas\Pca\GoalBinding;
use Atlas\Pca\GoalCompiler;
use Atlas\Pca\GoalDigests;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Replays the goal conformance vectors through the typed layer: goal digest, typecheck reasons, policy digest, decision + witness
 * of every probe (the witness checked on an allow, the reference decision equal to the policy decision), and the helper vectors
 * (canonical form, commitment, claim gate, tighten-only meet). A missing corpus fails. Selector expansion and the unit / polarity /
 * PEP helpers are replayed by their own suites.
 */
final class GoalVectorsTest extends TestCase
{
    private static function dir(string $name): string
    {
        $c = [$name === 'goal' ? (getenv('PCA_GOAL_VECTORS') ?: '') : '', __DIR__ . '/../../../packages/pca-conformance/vectors/' . $name,
            __DIR__ . '/../packages/pca-conformance/vectors/' . $name, __DIR__ . '/../conformance/' . $name];
        foreach ($c as $d) {
            if ($d !== '' && is_dir($d)) {
                return $d;
            }
        }
        throw new \RuntimeException("$name vectors not found");
    }

    /** Strip(g) of the proof: every grant a hole depends on is dropped (a global hole touches all of them) and the holes are emptied. */
    private static function stripGoal(Obj $g): Obj
    {
        $holes = $g->get('holes') ?? [];
        $keep = [];
        foreach ($g->get('grants') as $x) {
            $dep = false;
            foreach ($holes as $h) {
                $dep = $dep || $h->get('global') === true || in_array($x->get('gid'), $h->get('affects') ?? [], true);
            }
            if (!$dep) {
                $keep[] = $x;
            }
        }
        $s = new Obj();
        foreach ($g->keys() as $k) {
            $s->set($k, $g->get($k));
        }
        $s->set('grants', $keep);
        $s->set('holes', []);
        return $s;
    }

    /** @return list<string> what the reference decision of g says against the compiled policy's decision (with holes the policy lowers Strip(g)) */
    private static function refDecisionProblems(string $id, int $i, string $call, Obj $g, mixed $o, Obj $p, string $policyDecision): array
    {
        $rank = ['deny' => 0, 'escalate' => 1, 'allow' => 2];
        $out = [];
        $stripped = $call::decideGoal(self::stripGoal($g), $o, $p->get('action'), $p->get('history'));
        if ($stripped !== $policyDecision) {
            $out[] = "$id#$i: decideGoal(Strip g) != decidePolicy";
        }
        $full = $call::decideGoal($g, $o, $p->get('action'), $p->get('history'));
        if ($rank[$policyDecision] > $rank[$full]) {
            $out[] = "$id#$i: decidePolicy is more permissive than decideGoal(g)";
        }
        if (($g->get('holes') ?? []) === [] && $full !== $policyDecision) {
            $out[] = "$id#$i: decideGoal != decidePolicy";
        }
        return $out;
    }

    /** @return array{int, int, list<string>} */
    private static function replay(string $dir): array
    {
        $files = array_values(array_filter(scandir($dir) ?: [], static fn(string $f) => str_ends_with($f, '.json') && $f !== 'index.json'));
        sort($files);
        $bad = [];
        $probes = 0;
        foreach ($files as $f) {
            $v = Json::parseLax((string)file_get_contents($dir . '/' . $f));
            $id = (string)$v->get('id');
            if ($v->get('kind') === 'fn') {
                $e = self::runFn($v);
                if ($e !== null && Base::canon($e) !== Base::canon($v->get('expect'))) {
                    $bad[] = "$id: fn";
                }
                continue;
            }
            $g = $v->get('goal');
            $o = $v->get('ontology');
            if (GoalDigests::goalDigest($g) !== $v->get('goal_digest')) {
                $bad[] = "$id: goal_digest";
            }
            $compile = $v->get('compile');
            if (Base::canon(GoalCompiler::typecheck($g, $o)) !== Base::canon($compile->get('reasons'))) {
                $bad[] = "$id: reasons";
            }
            $r = GoalCompiler::compileGoal($g, $o);
            if (($r->get('ok') === true ? GoalCompiler::policyDigest($r->get('policy')) : null) !== $v->get('policy_digest')) {
                $bad[] = "$id: policy_digest";
            }
            if ($compile->get('ok') !== true) {
                continue;
            }
            foreach ($v->get('probes') as $i => $p) {
                $probes++;
                $d = GoalCompiler::decidePolicy($g, $o, $p->get('action'), $p->get('history'));
                $ok = $d->get('ok') === true;
                $got = $ok ? ['decision' => $d->get('decision'), 'witness' => $d->get('witness')] : ['decision' => 'deny', 'witness' => null];
                $want = $p->get('expect');
                if (Base::canon($got) !== Base::canon($want) || ($ok && $d->get('decision') === 'allow' && $d->get('witnessChecked') !== true)) {
                    $bad[] = "$id#$i: " . Base::canon($got) . ' != ' . Base::canon($want);
                }
                if ($ok) {
                    array_push($bad, ...self::refDecisionProblems($id, $i, GoalCompiler::class, $g, $o, $p, (string) $d->get('decision')));
                }
            }
        }
        return [count($files), $probes, $bad];
    }

    private static function runFn(Obj $v): mixed
    {
        $i = $v->get('input');
        switch ($v->get('fn')) {
            case 'canon':
                return Obj::of(['canon' => Json::canonicalizeStrict($i), 'digest' => GoalDigests::goalDigest($i)]);
            case 'meet':
                return Decision::tighten($i->get('decision'), $i->get('signal'));
            case 'commit':
                return Obj::of(['commit' => GoalBinding::goalCommit($i->get('goal_digest'), $i->get('policy_digest'), $i->get('salt')), 'opens_other_goal' => false]);
            case 'claim':
                return GoalBinding::claimGate($i->get('base'), $i->get('min_ppm'), $i->get('claimed_ppm'), $i->get('replayed_ppm'));
            default:
                return null; // units, polarity and pep belong to other suites
        }
    }

    public function testGoalVectors(): void
    {
        [$n, $probes, $bad] = self::replay(self::dir('goal'));
        $this->assertGreaterThanOrEqual(240, $n);
        $this->assertGreaterThan(6000, $probes);
        $this->assertSame([], array_slice($bad, 0, 20));
    }

    public function testSelectorVectorsTypedLayer(): void
    {
        $dir = dirname(self::dir('goal')) . '/goal-select';
        $this->assertDirectoryExists($dir);
        [$n, $probes, $bad] = self::replay($dir);
        $this->assertGreaterThanOrEqual(48, $n);
        $this->assertGreaterThan(1000, $probes);
        $this->assertSame([], array_slice($bad, 0, 20));
    }
}
