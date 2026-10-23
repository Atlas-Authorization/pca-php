<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Rule 19 (committed map / Z0 disclosure) and rule 18 (classifier dimensions) differential tests against the TS reference:
 * test-data/k042-mapartcls.json.gz is written by tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs. Every validator
 * case asserts the EXACT reason (or null), every decision the exact verdict and members.
 */
final class MapArtClsDifferentialKillTest extends TestCase
{
    /** @var ?list<Obj> */
    private static ?array $cases = null;

    /** @return list<Obj> */
    private static function of(string $fn): array
    {
        self::$cases ??= OracleData::raw('k042-mapartcls.json.gz');
        $out = array_values(array_filter(self::$cases, fn(Obj $c) => $c->get('fn') === $fn));
        self::assertNotEmpty($out, "no oracle cases for $fn");
        return $out;
    }

    /** @param list<string> $bad */
    private function report(array $bad): void
    {
        $this->assertSame([], array_slice($bad, 0, 20), count($bad) . ' divergent case(s)');
    }

    /** @param callable(mixed): ?string $f */
    private function validators(string $fn, callable $f): void
    {
        $bad = [];
        foreach (self::of($fn) as $c) {
            $want = $c->get('out');
            try {
                $got = $f($c->get('args')[0]);
            } catch (\Throwable $t) {
                $got = 'THROWS ' . $t->getMessage();
            }
            if ($got !== $want) {
                $bad[] = $c->get('name') . ' want ' . var_export($want, true) . ' got ' . var_export($got, true);
            }
        }
        $this->report($bad);
    }

    public function testHeaderLeaf(): void
    {
        $this->validators('header', IntentV2::mapHeaderError(...));
    }

    public function testCellLeaf(): void
    {
        $this->validators('cell', IntentV2::mapCellError(...));
    }

    public function testMetricsLeaf(): void
    {
        $this->validators('metrics', IntentV2::mapMetricsError(...));
    }

    public function testLearnerLeaf(): void
    {
        $this->validators('learner', IntentV2::mapLearnerError(...));
    }

    public function testDisclosureShape(): void
    {
        $this->validators('disclosure', IntentV2::mapDisclosureError(...));
    }

    public function testVerdictWire(): void
    {
        $this->validators('verdictwire', IntentWb::validateClassifierVerdictWire(...));
    }

    public function testClassifierPolicy(): void
    {
        $this->validators('policy', IntentWb::validateClassifierPolicy(...));
    }

    public function testNumericCells(): void
    {
        $bad = [];
        foreach (self::of('numcells') as $c) {
            $got = IntentV2::mapNumCells($c->get('args')[0]);
            $a = Json::canonicalizeStrict(OracleData::asJson($got));
            $w = Json::canonicalizeStrict($c->get('out'));
            if ($a !== $w) {
                $bad[] = $c->get('name') . " want $w got $a";
            }
        }
        $this->report($bad);
    }

    public function testCellOfTheAction(): void
    {
        $bad = [];
        foreach (self::of('cellof') as $c) {
            $a = $c->get('args');
            $r = IntentV2::mapCellOf($a[0], $a[1], $a[2] ?? null);
            $got = isset($r['error']) ? 'null' : Json::canonicalizeStrict(OracleData::asJson($r));
            $w = $c->get('out') === null ? 'null' : Json::canonicalizeStrict($c->get('out'));
            if ($got !== $w) {
                $bad[] = $c->get('name') . " want $w got $got";
            }
        }
        $this->report($bad);
    }

    public function testCommitment(): void
    {
        $bad = [];
        foreach (self::of('commit') as $c) {
            try {
                $got = IntentV2::mapCommitOfLeaves($c->get('args')[0]);
            } catch (\Throwable $t) {
                $got = 'THROWS ' . $t->getMessage();
            }
            if ($got !== $c->get('out')) {
                $bad[] = $c->get('name') . ' want ' . $c->get('out') . ' got ' . $got;
            }
        }
        $this->report($bad);
    }

    public function testMapDecisions(): void
    {
        $bad = [];
        foreach (self::of('decide') as $c) {
            $in = $c->get('args')[0];
            $eps = $in->get('max_residual_risk_ppm');
            $r = IntentV2::decideMapDisclosure($in->get('map_commit'), $in->get('action'), $in->has('params') ? $in->get('params') : IntentV2::undef(),
                $in->get('disclosure'), $eps);
            $got = Json::canonicalizeStrict(OracleData::asJson($r));
            $w = Json::canonicalizeStrict($c->get('out'));
            if ($got !== $w) {
                $bad[] = $c->get('name') . "\n  want $w\n  got  $got";
            }
        }
        $this->report($bad);
    }

    public function testClassifierDecisions(): void
    {
        $bad = [];
        foreach (self::of('classify') as $c) {
            $r = IntentWb::decideClassifierDimensions($c->get('args')[0]);
            $o = $c->get('out');
            $want = [$o->get('ok'), $o->has('reason') ? $o->get('reason') : null, $o->has('classes') ? Json::canonicalizeStrict($o->get('classes')) : null];
            $got = [$r['ok'], $r['reason'] ?? null, isset($r['classes']) ? Json::canonicalizeStrict(OracleData::asJson($r['classes'])) : null];
            if ($want !== $got) {
                $bad[] = $c->get('name') . "\n  want " . json_encode($want) . "\n  got  " . json_encode($got);
            }
        }
        $this->report($bad);
    }

    public function testArtifactSignatureUnderThePinnedKey(): void
    {
        $a = self::of('sigfixture')[0]->get('args');
        [$v, $pk, $other] = $a;
        $dom = IntentWb::INTENT_CLASSIFIER_DOMAIN;
        $this->assertTrue(IntentWb::verifyArtifactSig($dom, $v, $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig($dom, $v, $other));
        $this->assertFalse(IntentWb::verifyArtifactSig($dom . 'x', $v, $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig($dom, $v->without('sig'), $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig($dom, $v, null));
    }
}
