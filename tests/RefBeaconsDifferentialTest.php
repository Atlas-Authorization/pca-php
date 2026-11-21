<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Beacons.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\BeaconAcceptor;
use Atlas\Pca\Beacons;
use Atlas\Pca\Json;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An in-memory AtomicKv whose next update can be made to fail. */
final class BeaconTestKv implements AtomicKv
{
    /** @var array<string,string> */
    public array $m = [];
    public bool $failNext = false;

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function update(string $key, callable $fn): void
    {
        if ($this->failNext) {
            $this->failNext = false;
            throw new \RuntimeException('kv down');
        }
        $next = $fn($this->m[$key] ?? null);
        if ($next !== null) {
            $this->m[$key] = $next;
        }
    }
}

/**
 * The liveness beacons against the TS reference: every case of test-data/ref-beacons.json.gz (issuing under three suites, the signed message, the reference,
 * verification, replay acceptance, the frozen-liveness check, the durable acceptor over a kv that can fail or hold junk). `{"$num": ...}` is that double.
 * RULING: `allowUnboundPq` is not ported, so the case the reference accepts only through it must be REFUSED (counted).
 */
final class RefBeaconsDifferentialTest extends TestCase
{
    private const FILE = 'ref-beacons.json.gz';
    private const FNS = ['issueLivenessBeacon' => 36, 'livenessBeaconMessage' => 12, 'beaconRef' => 8, 'verifyLivenessBeacon' => 67, 'acceptBeacon' => 18,
        'isFrozenLiveness' => 8, 'acceptor' => 19, 'ctor' => 5, 'constants' => 1];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function secret(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    /** @return array{0: mixed, 1: array} the verify arguments of a check */
    private static function check(mixed $c): array
    {
        $c = self::conv($c);
        $get = static fn(string $k, mixed $d) => $c->has($k) ? $c->get($k) : $d;
        return ['issuers' => $c->get('issuers'), 'now' => $get('now', Jsx::$U), 'instance' => $get('instance', Jsx::$U),
            'scope' => $c->has('scope') ? $c->get('scope') : null, 'pqPins' => $c->has('pqPins') ? $c->get('pqPins') : null];
    }

    private static function unbound(mixed $c): bool
    {
        return $c instanceof Obj && $c->get('allowUnboundPq') === true;
    }

    private static function acceptor(array $ops): array
    {
        $kv = new BeaconTestKv();
        $acc = new BeaconAcceptor($kv);
        $out = [];
        foreach ($ops as $op) {
            if ($op[0] === 'accept') {
                $out[] = $acc->accept($op[1], self::check($op[2]));
            } elseif ($op[0] === 'fail') {
                $kv->failNext = true;
                $out[] = null;
            } elseif ($op[0] === 'raw') {
                $b = $op[1];
                $kv->m['beacon-seq/v1/' . json_encode([$b->get('instance'), $b->get('scope'), $b->get('issuer')], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)] = Json::canonicalizeLenient($op[2]);
                $out[] = null;
            } else {
                $out[] = Obj::of(['$err' => 'op']);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Jsx::init();
        Base::run($file, $fn, $k, [
            'issueLivenessBeacon' => static function (array $a) {
                $o = self::conv($a[0]);
                $su = $o->has('suite') ? $o->get('suite') : null;
                $suite = null;
                if ($su instanceof Obj) {
                    $suite = ['alg' => $su->get('alg'), 'pq' => $su->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed'))) : null];
                }
                $in = Jsx::spread($o);
                $in->set('issuerSecret', self::secret($o->get('issuerSecret')));
                return Beacons::issue($in, $suite);
            },
            'livenessBeaconMessage' => static fn(array $a) => Base::outBytes(Beacons::message(self::conv($a[0]))),
            'beaconRef' => static fn(array $a) => Beacons::beaconRef(self::conv($a[0])),
            'verifyLivenessBeacon' => static function (array $a, Obj $c) {
                $ck = self::check($a[1]);
                $have = Beacons::verify(self::conv($a[0]), $ck['issuers'], $ck['now'], $ck['instance'], $ck['scope'], $ck['pqPins']);
                $want = $c->get('out');
                if (self::unbound($a[1]) && $want instanceof Obj && $want->get('ok') === true) {
                    Assert::assertFalse($have['ok'], 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
                    return [Base::SKIP, 'allowUnboundPq ruling'];
                }
                return $have;
            },
            'acceptBeacon' => static fn(array $a) => Beacons::accept(self::conv($a[0]), self::conv($a[1])),
            'isFrozenLiveness' => static fn(array $a) => Beacons::isFrozen(self::conv($a[0]), self::check($a[1])),
            'acceptor' => static fn(array $a) => self::acceptor($a[0]),
            'ctor' => static function (array $a) {
                $spec = $a[0];
                $arg = $spec === 'ok' || ($spec instanceof Obj && $spec->get('update') === 'fn') ? new BeaconTestKv() : $spec;
                try {
                    new BeaconAcceptor($arg);
                    return ['built' => true];
                } catch (\TypeError) {
                    return ['built' => false];
                }
            },
            'constants' => static fn(array $a) => ['GLOBAL_SCOPE' => Beacons::GLOBAL_SCOPE, 'BEACON_EPOCH_MS' => Beacons::EPOCH_MS, 'BEACON_MAX_VALIDITY_MS' => Beacons::MAX_VALIDITY_MS,
                'BEACON_CLOCK_SKEW_MS' => Beacons::CLOCK_SKEW_MS],
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        $unbound = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                if (str_starts_with($line, '{"fn":"' . $fn . '"')) {
                    $have[$fn]++;
                    $unbound += $fn === 'verifyLivenessBeacon' && str_contains($line, '"allowUnboundPq":true') && str_contains($line, '"out":{"ok":true') ? 1 : 0;
                }
            }
        }
        $this->assertSame(self::FNS, $have);
        $this->assertSame(1, $unbound, 'the verify cases refused for allowUnboundPq');
    }
}
