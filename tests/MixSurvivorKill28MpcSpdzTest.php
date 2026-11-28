<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcField;
use Atlas\Pca\MpcFieldRng;
use Atlas\Pca\MpcMacCheckAbort;
use Atlas\Pca\MpcSpdz;
use Atlas\Pca\MpcSpdzEngine;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in MpcSpdz: MAC soundness, shape checks, the sacrifice (b sharing, the zero challenge, the residual) and Beaver labels. */
final class MixSurvivorKill28MpcSpdzTest extends TestCase
{
    private static function rng(int $seed = 28): MpcFieldRng
    {
        return new MpcFieldRng(gmp_init($seed));
    }

    /** A seeded generator whose FIRST draw is 0: SplitMix64 maps state 0 to 0, and the state after one step is seed + c0 (mod 2^64). */
    private static function zeroFirst(): MpcFieldRng
    {
        return new MpcFieldRng(gmp_sub(gmp_pow(2, 64), gmp_init('9e3779b97f4a7c15', 16)));
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    /** Soundness is keys * (log2 p - 1), snapped to the exact integer for a power-of-two p, never for any other p. */
    public function testMacSoundnessBits(): void
    {
        self::assertSame(120.0, MpcSpdz::macSoundnessBits(2));
        for ($k = 1; $k <= 200; $k++) {
            self::assertSame((float) (2 * ($k - 1)), MpcSpdz::macSoundnessBits(2, gmp_pow(2, $k)), "p = 2^$k");
        }
        $three = MpcSpdz::macSoundnessBits(2, gmp_init(3));
        self::assertNotSame(2.0, $three);
        self::assertEqualsWithDelta(1.1699250014423124, $three, 1e-9);
        $near = MpcSpdz::macSoundnessBits(2, gmp_add(gmp_pow(2, 40), 1));
        self::assertNotSame(78.0, $near, 'within 1e-9 of an integer but not a power of two: not snapped');
        self::assertEqualsWithDelta(78.0, $near, 1e-9);
    }

    /** setupMac refuses a party count below one. */
    public function testSetupMacRefusesZeroParties(): void
    {
        self::refuses(\InvalidArgumentException::class, 'setupMac: n must be a positive integer', static fn() => MpcSpdz::setupMac(0, self::rng()));
    }

    /** Adding two values under three MAC keys keeps BOTH extra MAC rows, each still a valid MAC of the sum. */
    public function testAddKeepsEveryExtraMacRow(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng, 3);
        $s = MpcSpdz::addAuth(MpcSpdz::authShare(gmp_init(3), $ctx, $rng), MpcSpdz::authShare(gmp_init(4), $ctx, $rng));
        self::assertCount(2, $s['extraMac']);
        foreach ($s['extraMac'] as $l => $row) {
            self::assertSame(0, gmp_cmp(MpcField::fmul($ctx['extraKeys'][$l]['alpha'], gmp_init(7)), MpcSpdz::authValue(['value' => $row])));
        }
    }

    /** Two shared values of different shapes are refused with the reason, before any arithmetic. */
    public function testShapeMismatchRefused(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $x = MpcSpdz::authShare(gmp_init(7), $ctx, $rng);
        $party = 'authenticated shared values must have the same party count';
        $v = $x;
        $v['value'][] = gmp_init(0);
        self::refuses(\InvalidArgumentException::class, $party, static fn() => MpcSpdz::addAuth($x, $v));
        $e = $x;
        $e['extraMac'][] = $x['extraMac'][0];
        self::refuses(\InvalidArgumentException::class, 'authenticated shared values must carry the same number of MAC keys', static fn() => MpcSpdz::addAuth($x, $e));
        $r = $x;
        $r['extraMac'][0] = [$x['extraMac'][0][0]];
        self::refuses(\InvalidArgumentException::class, $party, static fn() => MpcSpdz::addAuth($x, $r));
        self::assertSame(0, gmp_cmp(gmp_init(14), MpcSpdz::authValue(MpcSpdz::addAuth($x, $x))));
    }

    /** Adding a public constant refuses a value whose shape disagrees with the MAC context. */
    public function testAddPublicRefusesShapeMismatch(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $x = MpcSpdz::authShare(gmp_init(7), $ctx, $rng);
        $v = $x;
        $v['value'][] = gmp_init(1);
        self::refuses(\InvalidArgumentException::class, 'addPublicAuth: shared value and MAC context disagree on the party count', static fn() => MpcSpdz::addPublicAuth($v, gmp_init(1), $ctx));
        $m = $x;
        $m['mac'][] = gmp_init(1);
        self::refuses(\InvalidArgumentException::class, 'addPublicAuth: shared value and MAC context disagree on the party count', static fn() => MpcSpdz::addPublicAuth($m, gmp_init(1), $ctx));
        $e = $x;
        $e['extraMac'] = [];
        self::refuses(\InvalidArgumentException::class, 'addPublicAuth: shared value and MAC context disagree on the key count', static fn() => MpcSpdz::addPublicAuth($e, gmp_init(1), $ctx));
        $r = $x;
        $r['extraMac'][0][] = gmp_init(1);
        self::refuses(\InvalidArgumentException::class, 'addPublicAuth: extra MAC party count mismatch', static fn() => MpcSpdz::addPublicAuth($r, gmp_init(1), $ctx));
        self::assertSame(0, gmp_cmp(gmp_init(12), MpcSpdz::authValue(MpcSpdz::addPublicAuth($x, gmp_init(5), $ctx))));
    }

    /** The sacrifice certifies an honest triple, and refuses a triple with no partners or a partner that does not share b. */
    public function testSacrificeChecksPartners(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $batch = [MpcSpdz::genTripleWithPartners($ctx, $rng)];
        $out = MpcSpdz::sacrificeVerify($batch, $ctx, self::rng(5), []);
        self::assertSame([$batch[0]['keep']], $out);
        $none = $batch;
        $none[0]['partners'] = [];
        self::refuses(MpcMacCheckAbort::class, 'sacrifice: a triple without partners cannot be certified', static fn() => MpcSpdz::sacrificeVerify($none, $ctx, self::rng(5), []));
        $other = $batch;
        $other[0]['partners'][0]['b'] = MpcSpdz::authShare(gmp_init(9), $ctx, $rng);
        self::refuses(MpcMacCheckAbort::class, 'sacrifice: partner does not share b with the triple', static fn() => MpcSpdz::sacrificeVerify($other, $ctx, self::rng(5), []));
        $short = $batch;
        $short[0]['partners'][0]['b'] = MpcSpdz::authShare(gmp_init(9), MpcSpdz::setupMac(3, $rng), $rng);
        self::refuses(MpcMacCheckAbort::class, 'sacrifice: partner does not share b with the triple', static fn() => MpcSpdz::sacrificeVerify($short, $ctx, self::rng(5), []));
    }

    /** A zero challenge is replaced by one, so tau = delta_keep - delta_partner: equal deltas cancel, a lone partner delta is the residual. */
    public function testZeroChallengeBecomesOne(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $equal = [MpcSpdz::genTripleWithPartners($ctx, $rng, 1, ['keepCDelta' => gmp_init(5), 'partnerCDelta' => [gmp_init(5)]])];
        self::assertSame([$equal[0]['keep']], MpcSpdz::sacrificeVerify($equal, $ctx, self::zeroFirst(), []));
        $lone = [MpcSpdz::genTripleWithPartners($ctx, $rng, 1, ['keepCDelta' => null, 'partnerCDelta' => [gmp_init(5)]])];
        self::refuses(MpcMacCheckAbort::class, 'Beaver-triple sacrifice FAILED: residual tau=2305843009213693946 != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted',
            static fn() => MpcSpdz::sacrificeVerify($lone, $ctx, self::zeroFirst(), []));
    }

    /** Beaver multiplication labels its two openings `<label>:d` and `<label>:e` and computes x*y. */
    public function testBeaverLabelsAndProduct(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $x = MpcSpdz::authShare(gmp_init(6), $ctx, $rng);
        $y = MpcSpdz::authShare(gmp_init(7), $ctx, $rng);
        $engine = new MpcSpdzEngine($ctx);
        $z = MpcSpdz::beaverMulAuth($x, $y, MpcSpdz::genAuthTriple($ctx, $rng), $ctx, $engine, 'mul');
        self::assertSame(0, gmp_cmp(gmp_init(42), MpcSpdz::authValue($z)));
        $opened = (new \ReflectionProperty(MpcSpdzEngine::class, 'opened'))->getValue($engine);
        self::assertSame(['mul:d', 'mul:e'], array_column($opened, 'label'));
    }

    /** Beaver multiplication checks x against a, b, c and y, in that order, before it opens anything. */
    public function testBeaverChecksShapesBeforeOpening(): void
    {
        $rng = self::rng();
        $ctx = MpcSpdz::setupMac(2, $rng);
        $x = MpcSpdz::authShare(gmp_init(6), $ctx, $rng);
        $party = MpcSpdz::authShare(gmp_init(1), MpcSpdz::setupMac(3, $rng), $rng);
        $keys = MpcSpdz::authShare(gmp_init(1), MpcSpdz::setupMac(2, $rng, 3), $rng);
        $msgParty = 'authenticated shared values must have the same party count';
        $t = MpcSpdz::genAuthTriple($ctx, $rng);
        $cases = [
            [['a' => $party, 'b' => $t['b'], 'c' => $keys], $x, $msgParty],
            [['a' => $t['a'], 'b' => $party, 'c' => $t['c']], $x, $msgParty],
            [['a' => $t['a'], 'b' => $t['b'], 'c' => $party], $x, $msgParty],
            [$t, $party, $msgParty],
        ];
        foreach ($cases as $i => [$triple, $y, $msg]) {
            $engine = new MpcSpdzEngine($ctx);
            self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcSpdz::beaverMulAuth($x, $y, $triple, $ctx, $engine, 'mul'));
            self::assertSame(0, $engine->openCount(), "case $i opened before the shape check");
        }
    }

    /** The commitment is SHA-256 of hex(value) ':' hex(nonce). */
    public function testCommitFormat(): void
    {
        self::assertSame(hash('sha256', 'ff:10'), MpcSpdz::commit(gmp_init(255), gmp_init(16)));
        self::assertNotSame(MpcSpdz::commit(gmp_init(1), gmp_init(0x23)), MpcSpdz::commit(gmp_init(0x12), gmp_init(3)));
    }
}
