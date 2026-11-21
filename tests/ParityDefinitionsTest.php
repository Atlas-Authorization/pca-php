<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\Aggsig;
use Atlas\Pca\Conformance;
use Atlas\Pca\FheOrigin;
use Atlas\Pca\IntentRuntime;
use Atlas\Pca\PolicyClasses;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PcaCall;
use Atlas\Pca\Sandbox;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/Actions.php';
require_once __DIR__ . '/../src/Aggsig.php';
require_once __DIR__ . '/../src/Conformance.php';
require_once __DIR__ . '/../src/FheOrigin.php';
require_once __DIR__ . '/../src/IntentRuntime.php';
require_once __DIR__ . '/../src/PolicyClasses.php';
require_once __DIR__ . '/../src/PcaCall.php';
require_once __DIR__ . '/../src/Sandbox.php';

/** The small public definitions added for parity with the reference: core trait defs, the conformance harness, PcaCall, trustFromAttestation, isRegisteredKey. */
final class ParityDefinitionsTest extends TestCase
{
    public function testCoreTraitDefsAreTheRegistryInOrder(): void
    {
        $defs = Actions::coreTraitDefs();
        self::assertCount(22, $defs);
        self::assertSame(array_keys(Actions::coreRegistry()), array_map(static fn(Obj $d): string => $d->get('id'), $defs));
        self::assertSame(['id', 'implies', 'floor', 'card_phrase'], $defs[0]->keys());
    }

    public function testFirstFailedCheckIsTheEarliestFail(): void
    {
        self::assertSame('b', Conformance::firstFailedCheck(Obj::of(['a' => 'pass', 'b' => 'fail', 'c' => 'fail'])));
        self::assertSame('x', Conformance::firstFailedCheck(['w' => 'pass', 'x' => 'fail']));
        self::assertNull(Conformance::firstFailedCheck(Obj::of(['a' => 'pass', 'b' => 'not-enforced'])));
        self::assertNull(Conformance::firstFailedCheck(null));
    }

    public function testRunConformanceReportsMatchesAndDivergences(): void
    {
        $vec = static fn(string $id, bool $ok, ?string $first, array $per): Obj => Obj::of(['id' => $id, 'pcactn' => Obj::of(['cap_chain' => [Obj::of(['id' => 'g'])]]), 'aud' => null,
            'verifyOptions' => Obj::of(['nowEpoch' => new Num('5')]), 'expect' => Obj::of(['ok' => $ok, 'firstFailedCheck' => $first, 'perCheck' => Obj::of($per)])]);
        $seen = [];
        $verify = static function (Obj $p, Obj $in) use (&$seen): array {
            $seen[] = $in;
            return ['allow' => false, 'checks' => ['wire' => 'pass', 'audience' => 'fail']];
        };
        $r = Conformance::runConformance($verify, [$vec('hit', false, 'audience', ['wire' => 'pass', 'audience' => 'fail']), $vec('miss', true, null, ['wire' => 'pass'])]);
        self::assertFalse($r->get('ok'));
        self::assertSame(1, $r->get('passed')->int());
        self::assertSame(1, $r->get('failed')->int());
        self::assertTrue($r->get('results')[0]->get('matched'));
        self::assertCount(3, $r->get('results')[1]->get('divergences'));
        self::assertSame('g', $seen[0]->get('grant')->get('id'));
        self::assertSame(5, $seen[0]->get('nowEpoch')->int());
    }

    public function testTrustFromAttestationAdmitsTheDigestOnlyWhenOkAndBound(): void
    {
        $doc = Obj::of(['kind' => 'x', 'data' => new Num('1')]);
        $o = static fn(callable $v): array => ['document' => $doc, 'verifier' => $v, 'ctx' => Obj::of([]), 'expected' => Obj::of([]), 'nowMs' => new Num('5'),
            'pinnedAttestors' => ['p'], 'passportDigest' => 'pd'];
        $t = Sandbox::trustFromAttestation($o(static fn(Obj $i): array => ['ok' => true, 'bound' => true]));
        self::assertSame([Sandbox::evidenceDigest($doc)], $t->get('verifiedEvidenceDigests'));
        self::assertSame(['p'], $t->get('pinnedAttestors'));
        self::assertSame('pd', $t->get('passportDigest'));
        foreach ([['ok' => true, 'bound' => false], ['ok' => false, 'bound' => true], [], null] as $answer) {
            self::assertSame([], Sandbox::trustFromAttestation($o(static fn(Obj $i): mixed => $answer))->get('verifiedEvidenceDigests'));
        }
        self::assertSame([], Sandbox::trustFromAttestation($o(static function (Obj $i): never {
            throw new \RuntimeException('x');
        }))->get('verifiedEvidenceDigests'));
    }

    public function testPcaCallCarriesTheBridgeMembers(): void
    {
        $p = Obj::of(['v' => new Num('2')]);
        $c = PcaCall::fromBridge(['encoded' => '{}', 'pcactn' => $p, 'headers' => ['PCA-Action' => 'e30'], 'provenance' => null]);
        self::assertSame('{}', $c->encoded);
        self::assertSame($p, $c->pcactn);
        self::assertSame(['PCA-Action' => 'e30'], $c->headers);
        self::assertNull($c->provenance);
    }

    public function testOnlyAdmittedKeysAreRegisteredKeys(): void
    {
        self::assertFalse(Aggsig::isRegisteredKey(new \stdClass()));
        self::assertFalse(Aggsig::isRegisteredKey('x'));
    }

    public function testThePolicyClassLimitIsOnePerClass(): void
    {
        self::assertSame(count(PolicyClasses::CLASSES), PolicyClasses::MAX_POLICY_CLASSES);
    }

    public function testEvalSignedRiskClaimRefusesAnUnsignedClaimBeforeAnyEvaluation(): void
    {
        $r = FheOrigin::evalSignedRiskClaim('pk', 'gk', Obj::of(['claim' => 'x']), ['s'], 'ctx', Obj::of([]), Obj::of([]), static fn(string $k): bool => true);
        self::assertFalse($r['ok']);
        self::assertSame('claim is not signed: malformed envelope', $r['reason']);
    }

    public function testCheckIntentConformanceAsksThePanelThenAttests(): void
    {
        $seen = [];
        $verify = static function (mixed $verdicts, Obj $o) use (&$seen): Obj {
            $seen[] = [$verdicts, $o];
            return Obj::of(['ok' => true, 'agreeCount' => new Num('1'), 'aggregateScore' => new Num('1')]);
        };
        $input = Obj::of(['goalCommitment' => 'g', 'actionDigest' => 'a']);
        $r = IntentRuntime::checkIntentConformance(static fn($i): array => ['v1'], $input, Obj::of(['judgeKeys' => [], 'k' => new Num('1')]), $verify, static fn($v): string => 'd');
        self::assertSame(['v1'], $r->get('verdicts'));
        self::assertInstanceOf(Obj::class, $r->get('att'));
        self::assertSame(['v1'], $seen[0][0]);
        self::assertSame('g', $seen[0][1]->get('goalCommitment'));
    }
}
