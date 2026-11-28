<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AdaUrl;
use Atlas\Pca\Entropy;
use Atlas\Pca\EntropyError;
use Atlas\Pca\HttpQrngSource;
use Atlas\Pca\NodeTypeError;
use Atlas\Pca\Num;
use Atlas\Pca\QrngResponse;
use Atlas\Pca\QrngSource;
use PHPUnit\Framework\TestCase;

/** Entropy: HTTP source config / URL building / body parsing, SP 800-90B cutoffs and windows, number text, and secureSeed counts. */
final class CredSurvivorKill23EntropyTest extends TestCase
{
    /** @var ?array{0:bool,1:mixed} the AdaUrl probe state to restore */
    private ?array $ada = null;

    protected function tearDown(): void
    {
        if ($this->ada !== null) {
            (new \ReflectionProperty(AdaUrl::class, 'tried'))->setValue(null, $this->ada[0]);
            (new \ReflectionProperty(AdaUrl::class, 'lib'))->setValue(null, $this->ada[1]);
            $this->ada = null;
        }
    }

    /** Make AdaUrl report unavailable so the built-in URL serializer runs. */
    private function withoutAda(): void
    {
        $t = new \ReflectionProperty(AdaUrl::class, 'tried');
        $l = new \ReflectionProperty(AdaUrl::class, 'lib');
        $this->ada = [$t->getValue(), $l->getValue()];
        $t->setValue(null, true);
        $l->setValue(null, null);
    }

    private function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $msg");
    }

    private static function res(string $text): QrngResponse
    {
        return new class ($text) implements QrngResponse {
            public function __construct(private readonly string $t)
            {
            }

            public function ok(): bool
            {
                return true;
            }

            public function status(): int
            {
                return 200;
            }

            public function json(): mixed
            {
                throw new \RuntimeException('json unused');
            }

            public function text(): string
            {
                return $this->t;
            }
        };
    }

    /** A hex source over `$url`; `$seen` receives the requested URL and timeout. @param array<string,mixed> $extra */
    private static function src(string $url, ?array &$seen, array $extra = [], string $body = '00010203'): HttpQrngSource
    {
        $seen = null;
        return new HttpQrngSource($extra + ['url' => $url, 'format' => 'hex', 'transport' => static function (string $u, array $h, string $r, int $t) use (&$seen, $body): QrngResponse {
            $seen = [$u, $t, $h];
            return self::res($body);
        }]);
    }

    /** Non-string header / format / length names are cast; integral float limits are accepted; a float count is a count. */
    public function testConfigCasts(): void
    {
        $s = self::src('https://q.example/r', $seen, ['apiKeyHeader' => 5, 'apiKey' => 'k', 'timeoutMs' => 5000.0, 'maxBytes' => 1024.0, 'lengthParam' => 5,
            'buildUrl' => static fn(string $u, int $n): string => "$u?n=$n"]);
        $this->assertSame("\0\1\2\3", $s->fetch(4.0));
        $this->assertSame(['https://q.example/r?n=4', 5000, ['accept' => 'application/json, text/plain', 5 => 'k']], $seen);
        $b = new HttpQrngSource(['url' => 'https://q.example/r', 'format' => 5, 'buildUrl' => static fn(string $u, int $n): string => $u,
            'transport' => static fn(string $u, array $h, string $r, int $t): QrngResponse => self::res('AAECAw==')]);
        $this->assertSame("\0\1\2\3", $b->fetch(4));
    }

    /** buildUrl must return a string; a built URL that does not parse is an insecure transport; text is trimmed as JavaScript trims. */
    public function testBuildUrlAndTrim(): void
    {
        $this->throws(fn() => self::src('https://q.example/r', $seen, ['buildUrl' => static fn(): int => 5])->fetch(4), \TypeError::class,
            'HttpQrngSource: buildUrl must return a string');
        $bad = self::src('https://q.example/r', $seen, ['buildUrl' => static fn(): string => 'not a url']);
        $this->throws(fn() => $bad->fetch(4), EntropyError::class, 'QRNG: endpoint URL is not a valid URL');
        $this->assertSame("\0\1\2\3", self::src('https://q.example/r', $seen, ['buildUrl' => static fn(string $u): string => $u], "\u{A0}00010203\u{2028}")->fetch(4));
    }

    /** The built-in serializer (no libada): fragments, empty and bare pairs, '+' as space, userinfo and extra params as URL does. */
    public function testBuiltInUrlBuilder(): void
    {
        $this->withoutAda();
        foreach ([
            'https://q.example/r?a=b#f' => 'https://q.example/r?a=b&length=4#f',
            'https://q.example/r?&a=b' => 'https://q.example/r?a=b&length=4',
            'https://q.example/r?flag' => 'https://q.example/r?flag=&length=4',
            'https://q.example/r?x+y=a+b' => 'https://q.example/r?x+y=a+b&length=4',
            'https://u@q.example/r' => 'https://u@q.example/r?length=4',
            'https://u:@q.example/r' => 'https://u@q.example/r?length=4',
            'https://u:p@q.example/r' => 'https://u:p@q.example/r?length=4',
        ] as $in => $want) {
            self::src((string)$in, $seen)->fetch(4);
            $this->assertSame($want, $seen[0], (string)$in);
        }
        self::src('https://q.example/r', $seen, ['extraParams' => [7 => 5]])->fetch(4);
        $this->assertSame('https://q.example/r?length=4&7=5', $seen[0]);
        $this->throws(fn() => self::src('https://q.ex\u{E4}mple/r', $seen)->fetch(4), \RuntimeException::class,
            'QRNG: a URL with non-ASCII characters needs the URL parser library (ext-ffi and libada)');
    }

    /** With libada the length and the extra params are set through URLSearchParams; an invalid URL is ERR_INVALID_URL. */
    public function testAdaUrlBuilder(): void
    {
        if (!AdaUrl::available()) {
            $this->markTestSkipped('needs ext-ffi and libada');
        }
        self::src('https://q.example/r', $seen, ['extraParams' => ['a' => 'b', 7 => 5]])->fetch(4);
        $this->assertSame('https://q.example/r?length=4&a=b&7=5', $seen[0]);
        $this->throws(fn() => self::src('not a url', $seen)->fetch(4), NodeTypeError::class, 'Invalid URL');
    }

    /** Count messages print the number as JavaScript String(n) does. */
    public function testJsNumber(): void
    {
        $this->assertSame(['1000000000000000', '1e+21', '1.5e-7', '3', '7', 'Infinity', '-Infinity', 'NaN', '0'],
            array_map(Entropy::jsNumber(...), [1e15, 1e21, 1.5e-7, 3.0, 7, INF, -INF, NAN, -0.0]));
        $this->throws(fn() => self::src('https://q.example/r', $seen)->fetch(1e15), \RangeException::class, 'QRNG: requested 1000000000000000 bytes exceeds per-request cap 1024');
    }

    /** The repetition cutoff is an int; the proportion cutoff covers h = 1/8 and 64, stops at equality and reads the whole mantissa. */
    public function testCutoffs(): void
    {
        $this->assertSame(4, Entropy::repetitionCutoff(8));
        $this->assertSame(65, Entropy::proportionCutoff(0.125, 64));
        $this->assertSame(1, Entropy::proportionCutoff(64, 2));
        $this->assertSame(20, Entropy::proportionCutoff(1, 20)); // sum C(20, i) for i <= 19 is exactly (1 - 2^-20) * 2^20
        $this->assertSame(41, Entropy::proportionCutoff(0.5, 40)); // the low mantissa bit of sqrt(0.5) moves this cutoff
    }

    /** 2^-h multiplies 0.5 per whole bit, then sqrt(0.5), its root and the next root for bits 4, 2, 1 of 8h mod 8. */
    public function testProportionP(): void
    {
        $f = new \ReflectionMethod(Entropy::class, 'proportionP');
        $s1 = sqrt(0.5);
        $s2 = sqrt($s1);
        $s3 = sqrt($s2);
        for ($i = 0; $i < 8; $i++) {
            $p = 0.5;
            if (($i & 4) !== 0) {
                $p *= $s1;
            }
            if (($i & 2) !== 0) {
                $p *= $s2;
            }
            if (($i & 1) !== 0) {
                $p *= $s3;
            }
            $this->assertSame($p, $f->invoke(null, 1 + $i / 8), (string)$i);
        }
    }

    /** `$n` bytes whose sample byte 'A' sits at the given positions, the rest distinct non-'A' bytes (no run of 4). @param list<int> $at */
    private static function bytes(int $n, array $at): string
    {
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= in_array($i, $at, true) ? 'A' : chr(128 + $i % 100);
        }
        return $s;
    }

    /** The defaults are h = 8 (cutoff 13 over 512) and a 512-byte window; a numeric string h is refused, not used. */
    public function testHealthDefaults(): void
    {
        $fail = ['ok' => false, 'test' => 'adaptive-proportion'];
        $this->assertSame($fail, Entropy::healthTestBytes(self::bytes(512, range(0, 36, 3))));
        $this->assertSame($fail, Entropy::healthTestBytes(self::bytes(512, [...range(0, 33, 3), 511])));
        $this->assertSame(['ok' => true], Entropy::healthTestBytes(self::bytes(513, [...range(0, 33, 3), 512])));
        $this->assertSame(['ok' => false, 'test' => 'repetition-count'], Entropy::healthTestBytes('ab', '4'));
    }

    /** Body parsers: a stdClass ANU body; every JS-string form of a base64 payload; a non-scalar payload is malformed. */
    public function testParsers(): void
    {
        $this->assertSame("\1\2", Entropy::parseAnuUint8((object)['data' => [1, 2]]));
        $this->assertSame(base64_decode('AAAA'), Entropy::parseBase64('AAAA'));
        $this->assertSame(base64_decode('null'), Entropy::parseBase64(null));
        $this->assertSame(base64_decode('true'), Entropy::parseBase64(true));
        $this->assertSame(base64_decode('1234'), Entropy::parseBase64(1234));
        $this->assertSame(base64_decode('1234'), Entropy::parseBase64(new Num('1234')));
        $this->throws(fn() => Entropy::parseBase64(false), \RuntimeException::class, 'QRNG: malformed base64 payload');
        $this->throws(fn() => Entropy::parseBase64([]), \RuntimeException::class, 'QRNG: malformed base64 payload');
    }

    /** Integral float lengths and counts are accepted by mixEntropy and secureSeed (the quantum source receives an int). */
    public function testFloatCounts(): void
    {
        $local = str_repeat('l', 16);
        $this->assertSame(Entropy::mixEntropy($local, '', 16), Entropy::mixEntropy($local, '', 16.0));
        $this->assertSame(32, strlen(Entropy::secureSeed(['localBytes' => 32.0])->seed));
        $src = new class implements QrngSource {
            public function name(): string
            {
                return 'fixed';
            }

            public function fetch(int $numBytes)
            {
                return substr(hash('sha512', 'q', true), 0, $numBytes);
            }
        };
        $r = Entropy::secureSeed(['source' => $src, 'quantumBytes' => 32.0, 'healthTest' => false]);
        $this->assertSame([true, 32], [$r->usedQuantum, $r->quantumByteCount]);
    }

    /** unavailableSource is public and fails with its reason. */
    public function testUnavailableSource(): void
    {
        $this->throws(fn() => Entropy::unavailableSource('down')->fetch(1), \RuntimeException::class, 'QRNG unavailable: down');
    }
}
