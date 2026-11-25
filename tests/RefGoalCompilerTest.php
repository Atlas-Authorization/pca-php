<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/GoalCodec.php';
require_once __DIR__ . '/../src/Json.php';

use Atlas\Pca\GoalCodec as C;
use Atlas\Pca\GoalCompiler as CP;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * The typed front door of the goal compiler (typecheck / compile / decide / render over the kernel) on the goal conformance
 * vectors themselves: reasons, policy digest, decision + witness of every probe, and the card round trip.
 */
final class RefGoalCompilerTest extends TestCase
{
    private const DIR = __DIR__ . '/../../../packages/pca-conformance/vectors/goal';

    /** @return list<Obj> */
    private static function vectors(): array
    {
        if (!is_dir(self::DIR)) {
            return [];
        }
        $files = array_filter(scandir(self::DIR) ?: [], static fn(string $f) => str_ends_with($f, '.json') && $f !== 'index.json');
        sort($files);
        $out = [];
        foreach ($files as $f) {
            $v = Json::parseLax((string)file_get_contents(self::DIR . '/' . $f));
            if ($v instanceof Obj && $v->get('kind') !== 'fn') {
                $out[] = $v;
            }
        }
        return $out;
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

    public function testTypedFrontDoorOnConformanceVectors(): void
    {
        $vs = self::vectors();
        if ($vs === []) {
            $this->markTestSkipped('goal conformance vectors not in this layout');
        }
        $bad = [];
        foreach ($vs as $v) {
            $id = (string)$v->get('id');
            $compile = $v->get('compile');
            if (Base::canon(CP::typecheck($v->get('goal'), $v->get('ontology'))) !== Base::canon($compile->get('reasons'))) {
                $bad[] = "$id: reasons";
            }
            $r = CP::compileGoal($v->get('goal'), $v->get('ontology'));
            if (($r->get('ok') === true ? CP::policyDigest($r->get('policy')) : null) !== $v->get('policy_digest')) {
                $bad[] = "$id: policy_digest";
            }
            if (Base::canon(C::decodeGoal(CP::renderTape($v->get('goal')))) !== Base::canon(C::decodeGoal(C::encodeGoal($v->get('goal'))))) {
                $bad[] = "$id: render";
            }
            if ($compile->get('ok') !== true) {
                continue;
            }
            foreach ($v->get('probes') as $i => $p) {
                $d = CP::decidePolicy($v->get('goal'), $v->get('ontology'), $p->get('action'), $p->get('history'));
                $ok = $d->get('ok') === true;
                $got = $ok ? ['decision' => $d->get('decision'), 'witness' => $d->get('witness')] : ['decision' => 'deny', 'witness' => null];
                if (Base::canon($got) !== Base::canon($p->get('expect')) || ($ok && $d->get('decision') === 'allow' && $d->get('witnessChecked') !== true)) {
                    $bad[] = "$id#$i: " . Base::canon($got) . ' != ' . Base::canon($p->get('expect'));
                }
                if ($ok) {
                    array_push($bad, ...self::refDecisionProblems($id, $i, CP::class, $v->get('goal'), $v->get('ontology'), $p, (string) $d->get('decision')));
                }
            }
        }
        $this->assertSame([], array_slice($bad, 0, 25), count($bad) . ' divergence(s)');
    }

    public function testProvedKernelWiring(): void
    {
        $pk = CP::provedKernel();
        $this->assertSame(CP::policyDigest(['a']), ($pk->get('policyDigest'))(['a']));
        $this->assertTrue($pk->has('compile') && $pk->has('decide'));
    }
}
