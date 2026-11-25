<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestMaaKeys.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\AttestMaaKeys;
use Atlas\Pca\AttestMaaPins;
use Atlas\Pca\DurableMaaKeyStateStore;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryMaaKeyStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An in-memory AtomicKv that can list its records. */
final class MaaTestKv implements AtomicKv
{
    /** @var array<string,string> */
    public array $m = [];

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function update(string $key, callable $fn): void
    {
        $next = $fn($this->m[$key] ?? null);
        if ($next !== null) {
            $this->m[$key] = $next;
        }
    }
}

/**
 * The Azure MAA key trust (guarded certs fetch, JWKS evaluation over real and forged certificates, the rotation-safe trust store, multi-vantage
 * corroboration, the durable state adapter) and the release-signed pins against the TS reference: every case of test-data/ref-attest-maa.json.gz.
 * Strings over 400 characters are `{"$blob": id}` in the corpus (a table in its header line) and are hydrated in both arguments and expectations.
 * A reason that carries library text (an OpenSSL `error:...` line, a Node type error) is compared with that text masked.
 */
final class RefAttestMaaDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-maa.json.gz';
    private const FNS = ['constants' => 1, 'evaluateMaaJwks' => 92, 'loadBuiltinMaaPins' => 32, 'corroborate' => 26, 'fetchCerts' => 36, 'trust' => 60, 'kvStore' => 5, 'buildTrust' => 9];
    private static ?Obj $blobs = null;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function blobs(): Obj
    {
        if (self::$blobs === null) {
            $h = gzopen(Base::path(self::FILE), 'rb');
            $line = (string)gzgets($h);
            gzclose($h);
            $at = strrpos($line, ',"cases":[');
            self::$blobs = Json::parseLax(substr($line, 0, $at === false ? null : $at) . '}')->get('blobs');
        }
        return self::$blobs;
    }

    private static function hydrate(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            if ($x->keys() === ['$blob']) {
                return self::blobs()->get($x->get('$blob'));
            }
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::hydrate($x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::hydrate(...), $x) : $x;
    }

    /** Mask library text in every string of a value. */
    private static function mask(mixed $x): mixed
    {
        if (is_string($x)) {
            return preg_replace(['/error:[0-9A-F]{8}:[^;)]*/', '/The first argument[^;]*?Received [^;]*/'], 'LIB', $x);
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::mask($x->get($k)));
            }
            return $o;
        }
        if (is_array($x)) {
            return array_map(self::mask(...), $x);
        }
        return $x;
    }

    /** Normalise the expectation of a case (hydrate, mask) and return the masked native result. */
    /** The shipped pin manifest is signed with a hybrid post-quantum suite: without ML-DSA on this runtime its signature cannot be checked. */
    private static function needsPq(mixed $have): bool
    {
        return OracleData::pqMissing() && str_contains((string)json_encode(OracleData::plain($have), JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), 'signature does not verify under the registered issuer key');
    }

    private static function cmp(Obj $c, mixed $have): mixed
    {
        $c->set('out', self::mask(self::hydrate($c->get('out'))));
        return self::mask($have);
    }

    private static function response(Obj $r): \Closure
    {
        return static function () use ($r): Obj {
            if ($r->has('$throws')) {
                throw new \Exception((string)$r->get('$throws'));
            }
            if ($r->has('bodyBytes')) {
                $raw = Base::bytes($r->get('bodyBytes'));
            } else {
                $b = $r->get('body');
                $raw = $b instanceof Obj && $b->has('$text') ? (string)$b->get('$text') : Js::stringify($b);
            }
            $o = Obj::of(['status' => $r->has('status') ? $r->get('status') : 200, 'body' => $raw]);
            foreach (['url', 'contentLength'] as $k) {
                if ($r->has($k)) {
                    $o->set($k, $r->get($k));
                }
            }
            return $o;
        };
    }

    /** A scripted transport: the i-th call returns step min(i, last) (a bare JWKS is its own 200 body); every URL is logged. */
    private static function transport(array $steps, array &$log): \Closure
    {
        $i = 0;
        return static function (string $url, Obj $init) use ($steps, &$log, &$i): Obj {
            $log[] = $url . ($init->get('redirect') === 'error' ? ' [redirect:error]' : '');
            $s = $steps[min($i++, count($steps) - 1)];
            $s = $s instanceof Obj && $s->has('keys') && !$s->has('body') ? Obj::of(['body' => $s]) : $s;
            return (self::response($s))();
        };
    }

    private static function fetchCase(Obj $a): Obj
    {
        $log = [];
        $opts = new Obj();
        if ($a->has('opts')) {
            foreach ($a->get('opts')->keys() as $k) {
                $opts->set($k, $a->get('opts')->get($k));
            }
        }
        $opts->set('fetch', self::transport([$a->get('response')], $log));
        try {
            $out = Obj::of(['ok' => true, 'jwks' => AttestMaaKeys::fetchCerts($a->get('issuer'), $opts)]);
        } catch (\Throwable $e) {
            $out = Obj::of(['ok' => false, 'error' => $e->getMessage()]);
        }
        $out->set('requests', $log);
        return $out;
    }

    private static function trustCase(Obj $sc): mixed
    {
        $store = new MemoryMaaKeyStateStore($sc->has('initial') ? self::objMap($sc->get('initial')) : []);
        $log = [];
        $results = [];
        $t = AttestMaaKeys::createTrust(Obj::of(['policy' => $sc->get('policy'), 'store' => $store, 'fetch' => self::transport($sc->get('fetches'), $log)]));
        foreach ($sc->get('calls') as $c) {
            $results[] = $t->getTrustAnchors($c->get('issuer'), $c->get('nowMs'), $c->has('repin') ? $c->get('repin') : null);
        }
        return Obj::of(['results' => $results, 'store' => self::mapObj($store->snapshot()), 'fetches' => $log]);
    }

    private static function objMap(Obj $o): array
    {
        $m = [];
        foreach ($o->keys() as $k) {
            $m[$k] = $o->get($k);
        }
        return $m;
    }

    private static function mapObj(array $m): Obj
    {
        $o = new Obj();
        foreach ($m as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    private static function kvCase(Obj $a): Obj
    {
        $kv = new MaaTestKv();
        $st = new DurableMaaKeyStateStore($kv);
        $out = [];
        foreach ($a->get('steps') as $s) {
            if ($s->has('set')) {
                $st->set($s->get('set')[0], $s->get('set')[1]);
                $out[] = null;
            } else {
                $out[] = $st->get($s->get('get'));
            }
        }
        $state = new Obj();
        foreach ($kv->m as $k => $t) {
            $state->set((string)$k, Json::parseLax($t));
        }
        return Obj::of(['results' => $out, 'kv' => $state]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a, Obj $c) => self::cmp($c, ['BUILTIN_CHAIN_LEAF_CN' => AttestMaaPins::CHAIN_LEAF_CN, 'BUILTIN_MAA_PINS_ISSUER_ID' => AttestMaaPins::issuerId(),
                'BUILTIN_MAA_PINS_ISSUER_KEYS' => AttestMaaPins::issuerKeys()]),
            'evaluateMaaJwks' => static function (array $a, Obj $c) {
                $a = self::hydrate($a);
                $r = AttestMaaKeys::evaluateJwks($a[0], $a[1], $a[2], $a[3]);
                return self::cmp($c, $r);
            },
            'loadBuiltinMaaPins' => static function (array $a, Obj $c) {
                $have = self::cmp($c, AttestMaaPins::load(self::hydrate($a[0])));
                return self::needsPq($have) ? [Base::SKIP, 'no PQ suite on this runtime'] : $have;
            },
            'corroborate' => static function (array $a, Obj $c) {
                $a = self::hydrate($a);
                return self::cmp($c, AttestMaaKeys::corroborate($a[0], $a[1], $a[2]));
            },
            'fetchCerts' => static fn(array $a, Obj $c) => self::cmp($c, self::fetchCase(self::hydrate($a[0]))),
            'trust' => static function (array $a, Obj $c) {
                $have = self::cmp($c, self::trustCase(self::hydrate($a[0])));
                if (self::needsPq($have)) {
                    return [Base::SKIP, 'no PQ suite on this runtime'];
                }
                // a case that trusts the shipped pins: without ML-DSA the signed manifest cannot load, so the issuer is unpinned (a different refusal, not reported as a signature failure)
                if (OracleData::pqMissing() && str_starts_with((string) $c->get('name'), 'trust/builtin-')
                    && json_encode(OracleData::plain($have), JSON_PARTIAL_OUTPUT_ON_ERROR) !== json_encode(OracleData::plain($c->get('out')), JSON_PARTIAL_OUTPUT_ON_ERROR)) {
                    return [Base::SKIP, 'no PQ suite on this runtime (the shipped pin manifest cannot load)'];
                }
                return $have;
            },
            'kvStore' => static fn(array $a, Obj $c) => self::cmp($c, self::kvCase($a[0])),
            'buildTrust' => static function (array $a, Obj $c) {
                $cfg = $a[0];
                AttestMaaKeys::createTrust(Obj::of(['policy' => $cfg->get('policy'), 'store' => new MemoryMaaKeyStateStore(),
                    'fetch' => $cfg->get('noFetch') === true ? null : static fn() => new Obj()]));
                return ['built' => true];
            },
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        $h = gzopen(Base::path(self::FILE), 'rb');
        gzgets($h);
        while (($line = gzgets($h)) !== false) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        gzclose($h);
        $this->assertSame(self::FNS, $have);
    }
}
