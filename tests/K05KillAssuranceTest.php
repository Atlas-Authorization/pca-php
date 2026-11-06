<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceRequirement;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for src/Assurance.php: defaults, fromJson, multiRootLevel, report fields, str() and unmet() edges. */
final class K05KillAssuranceTest extends TestCase
{
    private static function labelled(string $level, ?string $vendor = null, bool $audit = false): object
    {
        return Assurance::setLabel(new \stdClass(), new AssuranceLabel($level, $vendor, $audit));
    }

    public function testDefaultsAndFromJson(): void
    {
        $this->assertFalse((new AssuranceLabel('x'))->awaitingAudit);
        $this->assertFalse((new AssuranceRequirement())->allowAwaitingAudit);
        $r = AssuranceRequirement::fromJson(['attestation' => 'hardware', 'zk' => 'snark', 'signature' => 'pq',
            'threshold' => ['frost', 1, 'mpc'], 'allowAwaitingAudit' => true]);
        $this->assertSame(['hardware', 'snark', 'pq', ['frost', 'mpc'], true],
            [$r->attestation, $r->zk, $r->signature, $r->threshold, $r->allowAwaitingAudit]);
        $this->assertTrue(AssuranceRequirement::fromJson(['allowPreview' => true])->allowAwaitingAudit);
        $e = AssuranceRequirement::fromJson([]);
        $this->assertSame([null, null, false], [$e->attestation, $e->threshold, $e->allowAwaitingAudit]);
        $this->assertTrue(Assurance::isAwaitingAuditScheme('frost'));
        $this->assertFalse(Assurance::isAwaitingAuditScheme('multisig'));
    }

    public function testMultiRootLevel(): void
    {
        $u = new \stdClass();
        $h1 = self::labelled('hardware');
        $h2 = self::labelled('hardware');
        $h3 = self::labelled('hardware');
        $odd = self::labelled('groth16'); // a level outside the attestation ranks counts as unknown
        $this->assertSame('unknown', Assurance::multiRootLevel([['verifier' => $odd]], 1));
        $this->assertSame('unknown', Assurance::multiRootLevel([['verifier' => $u]], 1));
        // no `required` member: optional, so the weakest one fills the quorum
        $this->assertSame('unknown', Assurance::multiRootLevel([['verifier' => $u], ['verifier' => $h1], ['verifier' => $h2]], 1));
        $this->assertSame('multi_root', Assurance::multiRootLevel([['verifier' => $h1], ['verifier' => $h2]], 2));
        // a required root is never also counted as an optional one
        $this->assertSame('hardware', Assurance::multiRootLevel([['verifier' => $u, 'required' => true], ['verifier' => $h1]], 2));
        // the optional roots are sorted weakest first
        $this->assertSame('unknown', Assurance::multiRootLevel([['verifier' => $h1], ['verifier' => $u]], 1));
        // threshold below the required count adds no optional root
        $this->assertSame('hardware', Assurance::multiRootLevel([['verifier' => $h1, 'required' => true], ['verifier' => $h2], ['verifier' => $h3]], 0));
    }

    public function testReportFields(): void
    {
        $rev = self::labelled('x', 'vend', true);
        $r = Assurance::report(['revocation' => 'pass'], null, ['revocation' => $rev]);
        $this->assertSame(['outcome' => 'pass', 'level' => 'x', 'vendor' => 'vend', 'awaiting_audit' => true], $r['revocation']);
        $r = Assurance::report(['revocation' => 'pass'], null, ['revocation' => self::labelled('x')]);
        $this->assertSame(['outcome' => 'pass', 'level' => 'x'], $r['revocation']);

        // leaf suite: pure PQ unless the unbound-PQ mode is asked for
        $leaf = static fn (mixed $alg, bool $unbound = false): array
            => Assurance::report(['leaf_signature' => 'pass'], Obj::of(['alg' => $alg]), allowUnboundPq: $unbound)['leaf_signature'];
        $this->assertSame(['pq', ['ml-dsa-65']], [$leaf('ml-dsa-65')['level'], $leaf('ml-dsa-65')['suites']]);
        $this->assertSame('unbound_pq', $leaf('ml-dsa-65', true)['level']);
        // suites render like JavaScript's String()
        $this->assertSame(['7'], $leaf(new Num('7'))['suites']);
        $this->assertSame(['true'], $leaf(true)['suites']);
        $this->assertSame(['false'], $leaf(false)['suites']);
        $this->assertSame(['null'], $leaf(['x'])['suites']);

        $chain = static fn (array $caps, bool $unbound = false): array
            => Assurance::report(['cap_chain' => 'pass'], Obj::of(['cap_chain' => $caps]), allowUnboundPq: $unbound)['cap_chain'];
        $c = $chain([Obj::of(['alg' => 'ml-dsa-65']), 'x']);
        $this->assertSame([['ml-dsa-65', 'ed25519'], 'ed25519'], [$c['suites'], $c['level']]);
        $c = $chain([Obj::of(['alg' => new Num('5')]), Obj::of(['alg' => true])]);
        $this->assertSame([['5', 'true'], 'unknown'], [$c['suites'], $c['level']]);
        $this->assertSame('unknown', $chain([new Obj(), Obj::of(['alg' => 'bogus'])])['level']);
        $this->assertSame('ed25519', $chain([new Obj()], true)['level']);
        $this->assertSame('unbound_pq', $chain([Obj::of(['alg' => 'ml-dsa-65'])], true)['level']);

        $t = static fn (float $v): mixed => Assurance::report(['threshold' => 'pass'], null, ['threshold' => new \stdClass()], null, $v)['threshold']['t'];
        $this->assertSame(2, $t(2.0));
        $this->assertSame(-3, $t(-3.0));
        $this->assertSame(2.5, $t(2.5));
        $this->assertSame(999999999999999, $t(999999999999999.0));
        $this->assertSame(1e15, $t(1e15));
    }

    public function testUnmetEdges(): void
    {
        $att = ['attestation' => ['outcome' => 'pass', 'level' => 'weird']];
        $this->assertNull(Assurance::unmet($att, new AssuranceRequirement(attestation: 'unknown')));
        $this->assertSame('assurance: software attestation required but the evidence is weird',
            Assurance::unmet($att, new AssuranceRequirement(attestation: 'software')));
        $this->assertSame('assurance: zk compliance (attested_vm) required but the evidence is weird',
            Assurance::unmet(['zk_compliance' => ['outcome' => 'pass', 'level' => 'weird']], new AssuranceRequirement(zk: 'attested_vm')));

        $tail = '; set allowAwaitingAudit or list the scheme to accept it';
        $this->assertSame("assurance: x rests on crypto awaiting audit (unknown)$tail",
            Assurance::unmet(['x' => ['outcome' => 'pass', 'awaiting_audit' => true, 'preview' => false]], new AssuranceRequirement()));
        $this->assertSame("assurance: b rests on crypto awaiting audit (frost)$tail",
            Assurance::unmet(['a' => ['outcome' => 'fail'], 'b' => ['outcome' => 'pass', 'awaiting_audit' => true, 'level' => 'frost']], new AssuranceRequirement()));
        $this->assertSame("assurance: zk_compliance rests on crypto awaiting audit (groth16)$tail",
            Assurance::unmet(['threshold' => ['outcome' => 'pass', 'level' => 'frost', 'awaiting_audit' => true],
                'zk_compliance' => ['outcome' => 'pass', 'level' => 'groth16', 'awaiting_audit' => true]], new AssuranceRequirement(threshold: ['frost'])));
    }
}
