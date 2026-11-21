<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Entropy.php';

use Atlas\Pca\AdaUrl;
use Atlas\Pca\Entropy;
use Atlas\Pca\EntropyError;
use Atlas\Pca\HttpQrngSource;
use Atlas\Pca\NullQrngSource;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\QrngFetchAborted;
use Atlas\Pca\QrngOpaqueFailure;
use Atlas\Pca\QrngResponse;
use Atlas\Pca\QrngSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A source of the corpus: answers as its spec says and records every requested size. */
final class EntropySpecSource implements QrngSource
{
    /** @var list<int> */
    public array $requests = [];

    /** @param array<string,mixed> $spec */
    public function __construct(private readonly array $spec)
    {
    }

    public function name(): string
    {
        return (string) ($this->spec['name'] ?? 'test-src');
    }

    public function fetch(int $numBytes)
    {
        $this->requests[] = $numBytes;
        return match ($this->spec['kind']) {
            'bytes' => $this->spec['value'],
            'nonbytes' => 7,
            'rejectString' => throw new QrngOpaqueFailure((string) $this->spec['message']),
            'reject', 'throwSync' => throw new \RuntimeException((string) $this->spec['message']),
        };
    }
}

/** A transport response of the corpus. */
final class EntropySpecResponse implements QrngResponse
{
    /** @param array<string,mixed> $spec the decoded transport spec @param mixed $body the JSON body as parsed from the corpus */
    public function __construct(private readonly array $spec, private readonly mixed $body)
    {
    }

    public function status(): int
    {
        return (int) ($this->spec['status'] ?? 200);
    }

    public function ok(): bool
    {
        return $this->spec['ok'] ?? ($this->status() >= 200 && $this->status() <= 299);
    }

    public function json(): mixed
    {
        return match ($this->spec['kind']) {
            'json' => $this->body,
            'jsonThrows' => throw new \JsonException('bad json'),
            'textThrows' => new Obj(),
            default => throw new \RuntimeException('json unused'),
        };
    }

    public function text(): string
    {
        return match ($this->spec['kind']) {
            'text' => (string) $this->spec['text'],
            'textThrows' => throw new \RuntimeException('read failed'),
            'jsonThrows' => '',
            default => throw new \RuntimeException('text unused'),
        };
    }
}

/**
 * The entropy module (QRNG sources, SP 800-90B health tests, the HKDF combiner, secureSeed, the key-pair helper) against the TS
 * reference: test-data/ref-entropy.json.gz. The local CSPRNG, every source and the HTTP transport are injected by each case. A
 * refusal is compared by its class, its code and, for the messages the module words itself, its text; the recorded requests and
 * hook arguments are compared as well. Cases whose argument is a JavaScript type confusion (a string or null where bytes, a count or
 * an options object is required) are skipped. With PCA_ADA_REQUIRED=1 the URL builder must run on libada.
 */
final class RefEntropyDifferentialTest extends TestCase
{
    private const FILE = 'ref-entropy.json.gz';
    private const TOTAL = 562;
    private const SKIP = [Base::SKIP, 'JS type confusion'];

    /** @var list<string> what a refusal case got wrong besides refusing (Base::run only sees the throw) */
    private static array $wrong = [];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** A corpus value as plain PHP: bytes, non-finite doubles, int / float numbers, assoc arrays for objects. */
    private static function un(mixed $v): mixed
    {
        if ($v instanceof Num) {
            $f = $v->float();
            return floor($f) === $f && abs($f) < 9.0e15 ? (int) $f : $f;
        }
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        $keys = $v->keys();
        if ($keys === ['$bytes']) {
            return (string) Pca::unb64u($v->get('$bytes'));
        }
        if ($keys === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = self::un($v->get($k));
        }
        return $out;
    }

    private static function isBytes(mixed $raw): bool
    {
        return $raw instanceof Obj && $raw->keys() === ['$bytes'];
    }

    private static function num(int|float $n): mixed
    {
        return is_float($n) && !is_finite($n) ? Obj::of(['$num' => is_nan($n) ? 'NaN' : ($n > 0 ? 'Infinity' : '-Infinity')]) : $n;
    }

    private static function cls(\Throwable $e): string
    {
        return match (true) {
            $e instanceof EntropyError => 'EntropyError',
            $e instanceof \RangeException => 'RangeError',
            $e instanceof \TypeError => 'TypeError',
            $e instanceof QrngOpaqueFailure => 'string',
            default => 'Error',
        };
    }

    /** @return array{cls:string,message:string,code?:string} */
    private static function errRec(\Throwable $e): array
    {
        return ['cls' => self::cls($e), 'message' => $e->getMessage()] + ($e instanceof EntropyError ? ['code' => $e->errorCode] : []);
    }

    private static function note(Obj $c, string $what, mixed $want, mixed $have): void
    {
        $w = Base::canon($want);
        $h = Base::canon($have);
        if ($w !== $h) {
            self::$wrong[] = $c->get('name') . " $what: want $w, have $h";
        }
    }

    /**
     * Runs `$f`; on a throw, checks what the reference recorded about the refusal (class and text of the module's own messages, plus the
     * `$extra` members such as the requests made so far), then rethrows so the case counts as a refusal. A code that belongs to the
     * JavaScript runtime (not an EntropyError) is dropped from the expectation.
     * @param callable():mixed $f @param callable():array<string,mixed> $extra
     */
    private static function guarded(Obj $c, callable $f, ?callable $extra = null): mixed
    {
        $want = $c->get('out');
        if ($want instanceof Obj && $want->has('$throws') && $want->has('code') && $want->get('cls') !== 'EntropyError') {
            $want = $want->without('code');
            $c->set('out', $want);
        }
        try {
            return $f();
        } catch (\Throwable $e) {
            if ($want instanceof Obj && $want->has('$throws')) {
                $msg = (string) $want->get('$throws');
                if (preg_match('/\A(QRNG|HttpQrngSource|mixEntropy|secureSeed)/', $msg) === 1) {
                    self::note($c, 'message', $msg, $e->getMessage());
                    if ($want->has('cls')) {
                        self::note($c, 'class', $want->get('cls'), self::cls($e));
                    }
                }
                foreach ($extra !== null ? $extra() : [] as $k => $v) {
                    if ($want->has($k)) {
                        self::note($c, $k, $want->get($k), $v);
                    }
                }
            }
            throw $e;
        }
    }

    /** secureSeed / generateKeyPairWithEntropy over the injected CSPRNG, source and hook of a case. */
    private static function seedRun(Obj $c, array $a, bool $keyPair): mixed
    {
        $spec = self::un($a[0]);
        $opts = array_diff_key($spec, ['hook' => 1, 'local' => 1, 'source' => 1]);
        $locals = [];
        $errs = [];
        $source = isset($spec['source']) ? new EntropySpecSource($spec['source']) : null;
        $opts['source'] = $source;
        if (isset($spec['local'])) {
            $local = $spec['local'];
            $opts['randomBytesImpl'] = static function (int $n) use ($local, &$locals) {
                $locals[] = $n;
                return match ($local['kind']) {
                    'fixed' => $local['value'],
                    'throw' => throw new \RuntimeException((string) $local['message']),
                    default => 12345,
                };
            };
        }
        $hook = $spec['hook'] ?? 'none';
        if ($hook !== 'none') {
            $opts['onQrngError'] = static function (\Throwable $e) use ($hook, &$errs): void {
                $errs[] = self::errRec($e);
                if ($hook === 'throw') {
                    throw new \RuntimeException('hook boom');
                }
            };
        }
        $seen = static function () use (&$errs, &$locals, $source): array {
            return ['qrngErrors' => $errs, 'localRequested' => $locals[0] ?? null, 'requests' => $source?->requests ?? []];
        };
        return self::guarded($c, static function () use ($opts, $keyPair, $seen): array {
            if ($keyPair) {
                $r = Entropy::generateKeyPairWithEntropy($opts);
                return ['publicKey' => Base::outBytes($r['publicKey']), 'secretKeySha256' => hash('sha256', $r['secretKey']), 'usedQuantum' => $r['usedQuantum']] + $seen();
            }
            $r = Entropy::secureSeed($opts);
            return ['seed' => Base::outBytes($r->seed), 'usedQuantum' => $r->usedQuantum, 'quantumByteCount' => $r->quantumByteCount, 'source' => $r->source] + $seen();
        }, $seen);
    }

    private static function httpRun(Obj $c, array $a): mixed
    {
        if (!($a[1] instanceof Num) && !($a[1] instanceof Obj)) {
            return self::SKIP; // a string or null count
        }
        $cfg = self::un($a[0]);
        $n = self::un($a[1]);
        $tr = self::un($a[2]);
        $body = $a[2]->get('body');
        $log = [];
        if (isset($cfg['buildUrl'])) {
            $suffix = (string) $cfg['buildUrl']['suffix'];
            $cfg['buildUrl'] = static fn(string $base, int $k): string => "$base/$k$suffix";
        }
        if ($tr['kind'] !== 'none') {
            $cfg['transport'] = static function (string $url, array $headers, string $redirect, int $timeoutMs) use ($tr, $body, &$log): QrngResponse {
                $log[] = ['url' => $url, 'headers' => $headers, 'redirect' => $redirect, 'signal' => $timeoutMs > 0];
                return match ($tr['kind']) {
                    'throw' => throw new \RuntimeException((string) $tr['message']),
                    'throwString' => throw new QrngOpaqueFailure((string) $tr['message']),
                    'hang' => throw new QrngFetchAborted('The operation was aborted'),
                    default => new EntropySpecResponse($tr, $body),
                };
            };
        }
        $src = self::guarded($c, static fn(): HttpQrngSource => new HttpQrngSource($cfg));
        $apiKey = is_string($cfg['apiKey'] ?? null) ? $cfg['apiKey'] : '';
        $leaks = false;
        return self::guarded($c, static function () use ($src, $n, &$log, &$leaks, $apiKey): array {
            try {
                return ['name' => $src->name(), 'bytes' => Base::outBytes($src->fetch($n)), 'requests' => $log];
            } catch (\Throwable $e) {
                $leaks = $apiKey !== '' && str_contains($e->getMessage(), $apiKey);
                throw $e;
            }
        }, static function () use ($src, &$log, &$leaks): array {
            return ['name' => $src->name(), 'requests' => $log, 'leaksKey' => $leaks];
        });
    }

    private static function unavailable(Obj $c, QrngSource $src, array $a): mixed
    {
        self::note($c, 'name', $c->get('out')->get('name'), $src->name());
        return self::guarded($c, static function () use ($src, $a): array {
            $src->fetch(self::un($a[1]));
            return ['name' => $src->name(), 'ok' => true];
        });
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        self::$wrong = [];
        $bytes = static fn(string $x): Obj => Base::outBytes($x);
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => [
                'MAX_HKDF_OUTPUT' => Entropy::MAX_HKDF_OUTPUT, 'MIN_LOCAL_BYTES' => Entropy::MIN_LOCAL_BYTES, 'DEFAULT_SEED_BYTES' => Entropy::DEFAULT_SEED_BYTES,
                'DEFAULT_MAX_QRNG_BYTES' => Entropy::DEFAULT_MAX_QRNG_BYTES, 'DEFAULT_TIMEOUT_MS' => Entropy::DEFAULT_TIMEOUT_MS,
            ],
            'repetitionCutoff' => static fn(array $a) => self::num(Entropy::repetitionCutoff(self::un($a[0]))),
            'proportionCutoff' => static fn(array $a) => Entropy::proportionCutoff(self::un($a[0]), self::un($a[1])),
            'healthTestBytes' => static function (array $a) {
                if (array_key_exists(1, $a) && !($a[1] instanceof Obj)) {
                    return self::SKIP; // null options
                }
                $o = self::un($a[1] ?? new Obj());
                return Entropy::healthTestBytes(self::un($a[0]), $o['h'] ?? null, $o['window'] ?? null);
            },
            'parseAnuUint8' => static fn(array $a, Obj $c) => $bytes(self::guarded($c, static fn() => Entropy::parseAnuUint8($a[0]))),
            'parseHex' => static fn(array $a, Obj $c) => $bytes(self::guarded($c, static fn() => Entropy::parseHex($a[0]))),
            'parseBase64' => static fn(array $a, Obj $c) => $bytes(self::guarded($c, static fn() => Entropy::parseBase64($a[0]))),
            'mixEntropy' => static function (array $a, Obj $c) use ($bytes) {
                $o = self::un($a[2] ?? new Obj());
                if (!self::isBytes($a[0]) || !self::isBytes($a[1]) || (array_key_exists('context', $o) && !is_string($o['context']))) {
                    return self::SKIP;
                }
                return $bytes(self::guarded($c, static fn() => Entropy::mixEntropy(self::un($a[0]), self::un($a[1]), $o['length'] ?? null, $o['context'] ?? null)));
            },
            'secureSeed' => static fn(array $a, Obj $c) => self::seedRun($c, $a, false),
            'generateKeyPairWithEntropy' => static fn(array $a, Obj $c) => self::seedRun($c, $a, true),
            'httpQrng' => static fn(array $a, Obj $c) => self::httpRun($c, $a),
            'nullQrng' => static fn(array $a, Obj $c) => self::unavailable($c, $a[0] === null ? new NullQrngSource() : new NullQrngSource($a[0]), $a),
            'unavailableSource' => static fn(array $a, Obj $c) => self::unavailable($c, Entropy::unavailableSource($a[0]), $a),
            'entropyError' => static function (array $a) {
                $e = new EntropyError($a[0], $a[1]);
                return ['name' => 'EntropyError', 'code' => $e->errorCode, 'message' => $e->getMessage(), 'isError' => $e instanceof \Throwable];
            },
        ]);
        $this->assertSame([], self::$wrong);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }

    public function testTheUrlBuilderRunsOnAdaWhereRequired(): void
    {
        if (getenv('PCA_ADA_REQUIRED') !== '1') {
            $this->markTestSkipped('libada is optional here');
        }
        $this->assertTrue(AdaUrl::available(), 'set ATLAS_PCA_LIBADA to a libada build');
        $this->assertSame('https://xn--mnchen-3ya.example/a%20b?q=1&length=4#f', AdaUrl::withParams('https://München.example/a b?q=1#f', [['length', '4']]));
        $this->assertNull(AdaUrl::withParams('not a url', []));
    }

    /** Real randomness: seeds differ from run to run, a seed never equals its local share, and the key pair is the seed's Ed25519 pair. */
    public function testThePlatformCsprngPath(): void
    {
        $a = Entropy::secureSeed();
        $b = Entropy::secureSeed();
        $this->assertSame(32, strlen($a->seed));
        $this->assertNotSame($a->seed, $b->seed);
        $this->assertFalse($a->usedQuantum);
        $this->assertSame(0, $a->quantumByteCount);
        $this->assertNull($a->source);
        $kp = Entropy::generateKeyPairWithEntropy();
        $this->assertSame(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($kp['secretKey'])), $kp['publicKey']);
    }
}
