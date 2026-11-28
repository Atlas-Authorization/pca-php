<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SignersMore.php';

use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\IntentV2;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The signing side of the registry documents and the intent artifacts against the TS reference: every case of
 * test-data/ref-action-pin.json.gz (registry signatures, evolution records, key entries, re-approvals and their verification) and the
 * accumulator receipt, receipt core digest, sequencer key set and classifier verdict signers of test-data/ref-intent-misc2.json.gz.
 * Keys travel as labels: a secret is sha256("atlas-pca-conformance/" . label); a suite {alg, pqSeed} is ML-DSA-65 from that seed
 * (deterministic signatures, so the outputs are compared byte for byte).
 */
final class RefIntentSignersDifferentialTest extends TestCase
{
    private const PIN = 'ref-action-pin.json.gz';
    private const PIN_TOTAL = 111;
    private const MISC = 'ref-intent-misc2.json.gz';
    private const MISC_FNS = ['signAccReceipt' => 16, 'accReceiptCoreDigest' => 4, 'signSequencerKeySet' => 15, 'signClassifierVerdict' => 7];

    public static function provide(): array
    {
        $out = [];
        foreach (Base::datasets(self::PIN) as $k => $d) {
            $out["pin $k"] = $d;
        }
        foreach (Base::datasets(self::MISC) as $k => $d) {
            if (isset(self::MISC_FNS[$d[1]])) {
                $out["misc $k"] = $d;
            }
        }
        return $out;
    }

    private static function raw(mixed $v): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$bytes')->get('$seed'), true);
    }

    private static function key(mixed $v): KeyPair
    {
        return new KeyPair(self::raw($v));
    }

    /** @return array{0:?string,1:?PqKeyPair} the suite arguments of a corpus suite spec (null = the default suite) */
    private static function suite(mixed $s): array
    {
        if (!($s instanceof Obj)) {
            return [null, null];
        }
        return [$s->get('alg'), $s->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::raw($s->get('pqSeed'))) : null];
    }

    /** {"$num": "NaN"} becomes the float, at any depth (a signer must refuse it). */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => [
                'ACTION_PIN_ON_NEW' => ActionsRegistry::ACTION_PIN_ON_NEW, 'EVOLUTION_CLASSES' => ActionsRegistry::EVOLUTION_CLASSES,
                'EVOLUTION_DIFF_DOMAIN' => ActionsRegistry::EVOLUTION_DIFF_DOMAIN, 'EVOLUTION_DOMAIN' => ActionsRegistry::EVOLUTION_DOMAIN,
                'EVOLUTION_RECORD_KIND' => ActionsRegistry::EVOLUTION_RECORD_KIND, 'MAX_ESC_TIER' => ActionsRegistry::MAX_ESC_TIER,
                'MAX_EVOLUTION_STEPS' => ActionsRegistry::MAX_EVOLUTION_STEPS, 'REAPPROVAL_DOMAIN' => ActionsRegistry::REAPPROVAL_DOMAIN,
                'REAPPROVAL_KIND' => ActionsRegistry::REAPPROVAL_KIND,
            ],
            'signRegistryDoc' => static fn(array $a) => SignersMore::signRegistryDoc($a[0], self::un($a[1]), $a[2], self::key($a[3]), ...self::suite($a[4])),
            'signEvolutionRecord' => static fn(array $a) => SignersMore::signEvolutionRecord($a[0], $a[1], self::key($a[2]), ...self::suite($a[3])),
            'registryKeyOf' => static fn(array $a) => SignersMore::registryKeyOf($a[0], self::key($a[1]), ...self::suite($a[2])),
            'signReapproval' => static fn(array $a) => SignersMore::signReapproval($a[0]->get('grantId'), $a[0]->get('record'), self::key($a[0]->get('principalSecret'))),
            'verifyRegistrySig' => static fn(array $a) => IntentV2::verifyRegistrySig($a[0], $a[1], $a[2], $a[3]),
            'verifyEvolutionRecord' => static fn(array $a) => ActionsRegistry::verifyEvolutionRecord($a[0], $a[1]),
            'reapprovalValid' => static fn(array $a) => ActionsRegistry::reapprovalValid($a[0], $a[1], $a[2], $a[3], $a[4]),
            'signAccReceipt' => static fn(array $a) => SignersMore::signAccReceipt(self::un($a[0]), self::key($a[1]), ...self::suite($a[2])),
            'accReceiptCoreDigest' => static fn(array $a) => SignersMore::accReceiptCoreDigest($a[0]),
            'signSequencerKeySet' => static fn(array $a) => SignersMore::signSequencerKeySet(self::un($a[0]), self::key($a[1]), ...self::suite($a[2])),
            'signClassifierVerdict' => static fn(array $a) => SignersMore::signClassifierVerdict(self::un($a[0]), self::key($a[1]), ...self::suite($a[2])),
        ]);
    }

    public function testCorporaHaveTheExpectedCases(): void
    {
        $pin = 0;
        foreach (gzfile(Base::path(self::PIN)) as $line) {
            $pin += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::PIN_TOTAL, $pin);
        $n = [];
        foreach (Base::datasets(self::MISC) as [, $fn, $k]) {
            if (isset(self::MISC_FNS[$fn])) {
                $n[$fn] = ($n[$fn] ?? 0) + count(Base::cases(self::MISC, $fn, $k));
            }
        }
        $this->assertEquals(self::MISC_FNS, $n);
        $this->assertSame(['session', 'principal', 'org', 'fleet'], SignersMore::ACC_SCOPES);
        $this->assertSame('atlas-pca/acc-receipt-core/v1', SignersMore::ACC_RECEIPT_CORE_DOMAIN);
    }
}
