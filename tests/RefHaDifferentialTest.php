<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Ha.php';

use Atlas\Pca\FenceError;
use Atlas\Pca\FenceGuard;
use Atlas\Pca\Ha;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Jsx;
use Atlas\Pca\KvLeaseStore;
use Atlas\Pca\LeaseStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Guardian-set high availability and the fenced leader lease against the TS reference: every case of test-data/ref-ha.json.gz.
 * {"$num": ...} is a non-finite double, in arguments and in results. A lease script runs against ONE fresh in-memory store whose
 * clock is the `clock` op; a record written raw with a non-finite number holds that number as text (equally corrupt).
 */
final class RefHaDifferentialTest extends TestCase
{
    private const FILE = 'ref-ha.json.gz';
    private const KEY = 'ha/lease';
    private const FNS = ['liveGuardians' => 144, 'quorumStatus' => 144, 'selectSigners' => 144, 'failoverPlan' => 144, 'degradeMode' => 70, 'lease' => 45,
        'validateGuardianSet' => 33, 'kvCas' => 17, 'fenceGuard' => 11, 'constants' => 1];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    private static function out(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::out($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    /** A non-finite double becomes its name as text, so the value can be written as JSON. */
    private static function writable(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::writable($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::writable(...), $v);
        }
        return is_float($v) && !is_finite($v) ? (is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')) : $v;
    }

    private static function stored(MemoryAtomicKv $kv): mixed
    {
        $raw = $kv->get(self::KEY);
        return $raw === null ? null : Json::parseLax($raw);
    }

    private static function lease(array $ops): array
    {
        $kv = new MemoryAtomicKv();
        $clock = 0;
        $st = new \stdClass();
        $st->fault = 'none';
        $st->loseOnce = false;
        $inner = new KvLeaseStore($kv, self::KEY, static function () use (&$clock) {
            return $clock;
        });
        $store = new class($inner, $st) implements LeaseStore {
            public function __construct(private readonly KvLeaseStore $kvs, private readonly \stdClass $st)
            {
            }

            public function read(): mixed
            {
                if ($this->st->fault === 'read') {
                    throw new \RuntimeException('boom');
                }
                return $this->kvs->read();
            }

            public function now(): int|float
            {
                if ($this->st->fault === 'now') {
                    throw new \RuntimeException('boom');
                }
                return $this->kvs->now();
            }

            public function cas(mixed $expected, Obj $next): bool
            {
                if ($this->st->fault === 'cas') {
                    throw new \RuntimeException('boom');
                }
                if ($this->st->loseOnce) {
                    $this->st->loseOnce = false;
                    return false;
                }
                return $this->kvs->cas($expected, $next);
            }
        };
        $refs = [];
        $res = static function (mixed $x) use (&$refs): mixed { // by reference: an arrow function would freeze the (empty) array at this point
            return is_string($x) ? ($refs[$x] ?? Jsx::$U) : $x;
        };
        $out = [];
        foreach ($ops as $op) {
            try {
                switch ($op[0]) {
                    case 'clock':
                        $clock = $op[1] instanceof \Atlas\Pca\Num ? $op[1]->float() : $op[1];
                        $out[] = null;
                        break;
                    case 'fault':
                        if ($op[1] === 'loseCas') {
                            $st->loseOnce = true;
                        } else {
                            $st->fault = $op[1];
                        }
                        $out[] = null;
                        break;
                    case 'raw':
                        $kv->update(self::KEY, static fn(?string $p): string => Json::canonicalizeLenient(self::writable($op[1])));
                        $out[] = null;
                        break;
                    case 'read':
                        $out[] = self::stored($kv);
                        break;
                    case 'acquire':
                        $r = Ha::acquireLease($store, $op[2], $op[3]);
                        if ($r['ok']) {
                            $refs[$op[1]] = $r['lease'];
                        }
                        $out[] = $r;
                        break;
                    case 'renew':
                        $r = Ha::renewLease($store, $res($op[1]), $op[2]);
                        if ($r['ok'] && is_string($op[1])) {
                            $refs[$op[1]] = $r['lease'];
                        }
                        $out[] = $r;
                        break;
                    case 'release':
                        $r = Ha::releaseLease($store, $res($op[1]));
                        if ($r['ok'] && is_string($op[1])) {
                            $refs[$op[1]] = $r['lease'];
                        }
                        $out[] = $r;
                        break;
                    case 'fence':
                        $out[] = Ha::assertFence($store, $res($op[1]), $op[2]);
                        break;
                    case 'signer':
                        $l = $op[1] === null ? Jsx::$U : $res($op[1]);
                        $f = Ha::fencedSigner($store, static fn() => $l, static function () use (&$clock, $op): string {
                            $clock += $op[3] instanceof \Atlas\Pca\Num ? $op[3]->float() : $op[3];
                            if ($op[4]) {
                                throw new \RuntimeException('sign');
                            }
                            return 'signed';
                        }, $op[2]);
                        try {
                            $r = $f();
                            $out[] = ['ok' => true, 'result' => $r['result'], 'epoch' => $r['epoch']];
                        } catch (FenceError $e) {
                            $out[] = ['ok' => false, 'reason' => $e->reason];
                        } catch (\Throwable $e) {
                            $out[] = ['ok' => false, 'error' => $e->getMessage()];
                        }
                        break;
                    default:
                        throw new \LogicException('bad op');
                }
            } catch (\Throwable $e) {
                $out[] = Obj::of(['$err' => $e->getMessage()]);
            }
        }
        return $out;
    }

    private static function kvCas(mixed $prev, mixed $exp, mixed $next): array
    {
        $kv = new MemoryAtomicKv();
        if ($prev !== null) {
            $kv->update(self::KEY, static fn(?string $p): string => Json::canonicalizeLenient(self::writable($prev)));
        }
        $ok = (new KvLeaseStore($kv, self::KEY, static fn() => 0))->cas($exp === null ? Jsx::$U : $exp, $next);
        return ['ok' => $ok, 'stored' => self::stored($kv)];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'liveGuardians' => static fn(array $a) => self::out(Ha::liveGuardians(self::un($a[0]), self::un($a[1]), self::un($a[2]))),
            'quorumStatus' => static fn(array $a) => self::out(Ha::quorumStatus(self::un($a[0]), self::un($a[1]), self::un($a[2]))),
            'selectSigners' => static fn(array $a) => self::out(Ha::selectSigners(self::un($a[0]), self::un($a[1]), self::un($a[2]))),
            'failoverPlan' => static fn(array $a) => self::out(Ha::failoverPlan(self::un($a[0]), self::un($a[1]), self::un($a[2]))),
            'degradeMode' => static fn(array $a) => Ha::degradeMode(self::un($a[0]), self::un($a[1])),
            'validateGuardianSet' => static fn(array $a) => Ha::validateGuardianSet(self::un($a[0])),
            'fenceGuard' => static function (array $a) {
                $g = new FenceGuard(self::un($a[0]));
                $admits = array_map(static fn($e) => $g->admit(self::un($e)), $a[1]);
                return ['admits' => $admits, 'highest' => $g->highest()];
            },
            'lease' => static fn(array $a) => self::out(self::lease(self::un($a[0]))),
            'kvCas' => static fn(array $a) => self::kvCas(self::un($a[0]), self::un($a[1]), self::un($a[2])),
            'constants' => static fn(array $a) => ['MAX_LEASE_TTL_MS' => Ha::MAX_LEASE_TTL_MS, 'DEFAULT_LEASE_SKEW_MS' => Ha::DEFAULT_LEASE_SKEW_MS],
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
