<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Dpop;
use Atlas\Pca\DpopNonceIssuer;
use Atlas\Pca\DpopReplayStore;
use Atlas\Pca\InMemoryDpopReplayStore;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslEd448;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DPoP proofs, mTLS confirmation, the PCActn binding, replay stores and server nonces against the TS reference:
 * test-data/ref-dpop.json.gz. Verify options arrive as JSON: seenJti is a list (an ArrayObject here, returned as `seen`),
 * replayStore names a kind (memory with maxEntries / preload, or a store that always returns true / false / throws),
 * nonceIssuer carries a base64url secret.
 */
final class RefDpopDifferentialTest extends TestCase
{
    private const FILE = 'ref-dpop.json.gz';
    private const RSA_FILE = 'ref-dpop-rsa.json.gz';
    private const NO_ED448 = [Base::SKIP, 'Ed448 is not available (no ext-ffi / OpenSSL libcrypto)'];
    private const NO_PSS_SIGN = [Base::SKIP, 'RSA-PSS signing needs phpseclib/phpseclib'];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function fixed(mixed $result): DpopReplayStore
    {
        return new class ($result) implements DpopReplayStore {
            public function __construct(private readonly mixed $r)
            {
            }

            public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool
            {
                if ($this->r === 'throws') {
                    throw new \RuntimeException('boom');
                }
                return $this->r;
            }
        };
    }

    private static function store(Obj $s): DpopReplayStore
    {
        switch ($s->get('kind')) {
            case 'memory':
                $st = $s->has('maxEntries') ? new InMemoryDpopReplayStore($s->get('maxEntries')) : new InMemoryDpopReplayStore();
                foreach ($s->get('preload') ?? [] as [$k, $e, $n]) {
                    $st->addIfAbsent($k, Js::num($e), Js::num($n));
                }
                return $st;
            case 'true':
                return self::fixed(true);
            case 'false':
                return self::fixed(false);
            default:
                return self::fixed('throws');
        }
    }

    /** @return array{0: array<string,mixed>, 1: ?\ArrayObject} the native options and the seen set */
    private static function adapt(Obj $opts): array
    {
        $o = [];
        foreach ($opts->keys() as $k) {
            $o[$k] = $opts->get($k);
        }
        $seen = null;
        if ($opts->has('seenJti')) {
            $o['seenJti'] = $seen = new \ArrayObject($opts->get('seenJti'));
        }
        if ($opts->has('replayStore')) {
            $o['replayStore'] = self::store($opts->get('replayStore'));
        }
        if ($opts->has('nonceIssuer')) {
            $n = $opts->get('nonceIssuer');
            $o['nonceIssuer'] = new DpopNonceIssuer(Pca::unb64u($n->get('secret')), $n->get('ttl'));
        }
        return [$o, $seen];
    }

    private static function withSeen(array $r, ?\ArrayObject $seen): array
    {
        if ($seen !== null) {
            $r['seen'] = array_values((array)$seen);
        }
        return $r;
    }

    private static function isEd448(mixed $jwk): bool
    {
        return Js::opt($jwk, 'crv') === 'Ed448';
    }

    /** A proof whose embedded key is Ed448 cannot be checked here: a success is skipped, a refusal still has to match. */
    private static function ed448Proof(mixed $proof): bool
    {
        if (!is_string($proof) || substr_count($proof, '.') !== 2) {
            return false;
        }
        try {
            $h = Json::parseLax(Jose::lenientB64d(explode('.', $proof)[0]));
        } catch (\Throwable) {
            return false;
        }
        return $h instanceof Obj && self::isEd448($h->get('jwk'));
    }

    private static function wantsThrow(Obj $c): bool
    {
        $o = $c->get('out');
        return $o instanceof Obj && $o->has('$throws');
    }

    /** Null when the case can run here, else the skip. */
    private static function createSkip(Obj $input, Obj $c): ?array
    {
        $pub = $input->get('publicJwk');
        if (!OpensslEd448::available() && (self::isEd448($pub) || (self::isEd448($input->get('privateKey')) && !self::wantsThrow($c)))) {
            return self::NO_ED448;
        }
        return Js::opt($pub, 'kty') === 'RSA' && !class_exists(\phpseclib3\Crypt\RSA::class) ? self::NO_PSS_SIGN : null;
    }

    private static function nonceOps(mixed $secret, mixed $ttl, array $ops): array
    {
        $iss = new DpopNonceIssuer($secret === null ? null : Pca::unb64u($secret), $ttl);
        $issued = [];
        $out = [];
        foreach ($ops as $op) {
            if ($op->get('op') === 'issue') {
                $out[] = $issued[] = $op->has('now') ? $iss->issue($op->get('now')) : $iss->issue();
                continue;
            }
            $n = $op->get('nonce');
            if ($n instanceof Obj && $n->has('$issued')) {
                $n = $issued[(int)Js::num($n->get('$issued'))];
            }
            $out[] = $op->has('now') ? $iss->check($n, $op->get('now')) : $iss->check($n);
        }
        return $out;
    }

    private static function storeOps(mixed $max, array $ops): array
    {
        $st = $max === null ? new InMemoryDpopReplayStore() : new InMemoryDpopReplayStore($max);
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = $st->addIfAbsent($op->get('key'), Js::num($op->get('exp')), Js::num($op->get('now')));
            } catch (\Throwable) {
                $out[] = 'throws';
            }
        }
        return $out;
    }

    private static function conformance(string $kind): array
    {
        return Dpop::runReplayStoreConformance(static fn(): DpopReplayStore => match ($kind) {
            'memory' => new InMemoryDpopReplayStore(),
            'alwaysTrue' => self::fixed(true),
            'alwaysFalse' => self::fixed(false),
            default => new class () implements DpopReplayStore {
                private array $seen = [];

                public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool
                {
                    if (isset($this->seen[$key])) {
                        return false;
                    }
                    return $this->seen[$key] = true;
                }
            },
        });
    }

    private static function createThenVerify(Obj $input, Obj $vo): array
    {
        $proof = Dpop::createDpopProof($input);
        $base = Obj::of(['method' => $input->get('method'), 'url' => $input->get('url'), 'maxAgeSec' => 300,
            'nowSec' => (Js::num($input->get('iat')) ?? 1800000000) + 1, 'seenJti' => []]);
        foreach ($vo->keys() as $k) {
            $base->set($k, $vo->get($k));
        }
        [$o, $seen] = self::adapt($base);
        return self::withSeen(Dpop::verifyDpopProof($proof, $o), $seen);
    }

    /** @return array<string,callable> the oracle fn -> native twin table, shared by the main and the RSA corpus */
    private static function table(): array
    {
        return [
            'constants' => fn() => ['allowedAlgs' => Dpop::ALLOWED_ALGS, 'typ' => Dpop::JWT_TYP, 'defaultMaxAgeSec' => Dpop::DEFAULT_MAX_AGE_SEC,
                'clockSkewSec' => Dpop::CLOCK_SKEW_SEC, 'maxProofBytes' => Dpop::MAX_PROOF_BYTES, 'inMemoryMaxEntries' => Dpop::INMEMORY_MAX_ENTRIES],
            'jwkThumbprint' => fn(array $a) => count($a) > 1 ? Dpop::jwkThumbprint($a[0], $a[1]) : Dpop::jwkThumbprint($a[0]),
            'dpopAlgForJwk' => fn(array $a) => Dpop::algForJwk($a[0] ?? null),
            'dpopAlgMatchesJwk' => fn(array $a) => Dpop::algMatchesJwk($a[0] ?? null, $a[1] ?? null),
            'normalizeHtu' => fn(array $a) => Dpop::normalizeHtu($a[0] ?? null),
            'athFor' => fn(array $a) => Dpop::athFor($a[0] ?? null),
            'nonceIssuer' => fn(array $a) => self::nonceOps($a[0], $a[1], $a[2]),
            'replayStore' => fn(array $a) => self::storeOps($a[0], $a[1]),
            'replayConformance' => fn(array $a) => self::conformance($a[0]),
            'createDpopProof' => fn(array $a, Obj $c) => self::createSkip($a[0], $c) ?? Dpop::createDpopProof($a[0]),
            'createThenVerify' => fn(array $a, Obj $c) => self::createSkip($a[0], $c) ?? self::createThenVerify($a[0], $a[1]),
            'verifyDpopProof' => function (array $a, Obj $c) {
                if (!OpensslEd448::available() && self::ed448Proof($a[0]) && !self::wantsThrow($c)) {
                    return self::NO_ED448;
                }
                [$o, $seen] = self::adapt($a[1]);
                return self::withSeen(Dpop::verifyDpopProof($a[0], $o), $seen);
            },
            'mtlsCnf' => fn(array $a) => Dpop::mtlsCnf(Base::bytes($a[0])),
            'mtlsThumbprint' => fn(array $a) => Dpop::mtlsThumbprint(Base::bytes($a[0])),
            'assertMtlsBound' => fn(array $a) => Dpop::assertMtlsBound(Base::bytes($a[0]), $a[1]),
            'leafHolderJwk' => fn(array $a) => Dpop::leafHolderJwk($a[0]),
            'bindPcaToDpop' => fn(array $a) => Dpop::bindPcaToDpop($a[0]),
            'assertPcaDpop' => function (array $a, Obj $c) {
                if (!OpensslEd448::available() && self::ed448Proof($a[1]) && !self::wantsThrow($c)) {
                    return self::NO_ED448;
                }
                [$o, $seen] = self::adapt($a[2]);
                return self::withSeen(Dpop::assertPcaDpop($a[0], $a[1], $o), $seen);
            },
        ];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, self::table());
    }

    private static function rsaPath(): string
    {
        return getenv('PCA_DPOP_RSA_CORPUS') ?: __DIR__ . '/../test-data/' . self::RSA_FILE;
    }

    /** The RSA DPoP cases: ref-dpop-rsa.json.gz, generated by CI (never committed); a placeholder dataset when it is absent. */
    public static function provideRsa(): array
    {
        return is_file(self::rsaPath()) ? Base::datasets(self::RSA_FILE) : ['missing' => [self::RSA_FILE, '', 0]];
    }

    #[DataProvider('provideRsa')]
    public function testRsaCorpusAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            $msg = 'ref-dpop-rsa.json.gz not found at ' . self::rsaPath() . ' (generate with .github/scripts/dpop-rsa-corpus.sh or set PCA_DPOP_RSA_CORPUS)';
            if (in_array(getenv('CI'), ['true', '1'], true)) {
                self::fail($msg);
            }
            self::markTestSkipped($msg);
        }
        Base::run($file, $fn, $k, self::table());
    }

    public function testTheInMemoryStoreConforms(): void
    {
        self::assertSame([], Dpop::runReplayStoreConformance(static fn() => new InMemoryDpopReplayStore()));
    }

    /** A non-finite maxAgeSec would disable the stale check and a non-finite nowSec would void the window: both refused; absent means 300 s. */
    public function testNonFiniteMaxAgeAndNowAreRefused(): void
    {
        $seed = hash('sha256', 'dpop-non-finite', true);
        $b64 = static fn(string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $x = $b64(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)));
        $url = 'https://rs.example/r';
        $proof = Dpop::createDpopProof(Obj::of(['method' => 'GET', 'url' => $url, 'iat' => 1800000000,
            'privateKey' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x, 'd' => $b64($seed)]),
            'publicJwk' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x])]));
        $base = ['method' => 'GET', 'url' => $url, 'requireReplayStore' => false];
        $code = static function (array $o) use ($proof): string {
            try {
                Dpop::verifyDpopProof($proof, $o);
                return 'ok';
            } catch (\Atlas\Pca\DpopVerificationError $e) {
                return $e->codeName;
            }
        };
        self::assertSame('ok', $code($base + ['nowSec' => 1800000001]));
        self::assertSame('iat_stale', $code($base + ['nowSec' => 1800000301]));
        foreach ([INF, -INF, NAN] as $v) {
            self::assertSame('max_age', $code($base + ['nowSec' => 1800000001, 'maxAgeSec' => $v]));
            self::assertSame('now', $code($base + ['nowSec' => $v]));
        }
    }

    public function testAVerifierWithoutAReplayStoreRefuses(): void
    {
        $this->expectExceptionMessage('no replay store configured');
        Dpop::verifyDpopProof('a.b.c', ['method' => 'GET', 'url' => 'https://a.example/', 'maxAgeSec' => 300]);
    }
}
