<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FalconBackend;
use Atlas\Pca\Fndsa;
use Atlas\Pca\FnDsaBackendMissing;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The FN-DSA suite registry, wire framing, hybrid composition and backend seam (Atlas\Pca\Fndsa) against the TypeScript reference corpus
 * (test-data/ref-fndsa.json.gz, 480 cases). The Falcon primitive is not covered here (the reference ships none): every case runs through the
 * deterministic hash-derived test backend or an explicit stub backend. The real primitive is RefFndsaNativeTest.
 */
final class RefFndsaDifferentialTest extends TestCase
{
    private const FILE = 'ref-fndsa.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    /** A byte argument: {$bytes} to raw bytes, null stays null, any other JSON value (a text string, a number...) becomes a non-bytes array. */
    private static function dec(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            return Pca::unb64u($v->get('$bytes'));
        }
        return $v === null ? null : [$v];
    }

    private static function out(string $raw): Obj
    {
        return Base::outBytes($raw);
    }

    private static function install(string $kind): void
    {
        Fndsa::resetFalconBackend();
        $mock = Fndsa::registerTestBackend();
        switch ($kind) {
            case 'mock':
                return;
            case 'none':
                Fndsa::resetFalconBackend();
                return;
            case 'verify-only':
                Fndsa::setFalconBackend(new FalconBackend($mock->verify));
                return;
            case 'short-sig':
                Fndsa::setFalconBackend(new FalconBackend($mock->verify, static fn(string $sk, string $m): string => str_repeat("\0", 10)));
                return;
            case 'all-true':
                Fndsa::setFalconBackend(new FalconBackend(static fn(): bool => true, $mock->sign));
                return;
            case 'throws':
                Fndsa::setFalconBackend(new FalconBackend(static function (): bool {
                    throw new \RuntimeException('backend exploded');
                }, $mock->sign));
                return;
        }
        throw new \LogicException("unknown backend kind $kind");
    }

    private static function with(string $kind, callable $f): mixed
    {
        try {
            self::install($kind);
            return $f();
        } finally {
            Fndsa::resetFalconBackend();
        }
    }

    private static function suite(mixed $alg): ?array
    {
        $s = Fndsa::resolveAlg($alg);
        return $s === null ? null : [
            'alg' => $s->alg, 'variant' => $s->variant, 'hasEd25519' => $s->hasEd25519, 'sigBytes' => $s->sigBytes, 'needsPqPk' => $s->needsPqPk,
            'pqPkBytes' => $s->pqPkBytes, 'needsPqSig' => $s->needsPqSig, 'pqSigBytes' => $s->pqSigBytes, 'fnSigBytes' => $s->fnSigBytes,
        ];
    }

    private static function vectors(mixed $list): array
    {
        $o = [];
        foreach ($list as $v) {
            $o[] = ['pk' => self::dec($v->get('pk')), 'msg' => self::dec($v->get('msg')), 'sig' => self::dec($v->get('sig'))];
        }
        return $o;
    }

    private static function katVerify(mixed $variant, mixed $pk, mixed $msg, mixed $sig, mixed $vectors): bool
    {
        Fndsa::resetFalconBackend();
        Fndsa::registerTestBackend(self::vectors($vectors));
        try {
            return Fndsa::verify($variant, self::dec($pk), self::dec($msg), self::dec($sig));
        } finally {
            Fndsa::resetFalconBackend();
        }
    }

    private static function signInput(Obj $in): array
    {
        $f = $in->get('fnDsa');
        $fn = $f instanceof Obj ? ['pk' => self::dec($f->get('pk')), 'sk' => self::dec($f->get('sk'))] : $f;
        return [$in->get('alg'), $in->get('leaf'), $fn, self::dec($in->get('edSecret'))];
    }

    private static function verifyIn(string $kind, Obj $in): bool
    {
        return self::with($kind, static fn(): bool => Fndsa::verifyPca(
            $in->get('alg'), $in->get('leaf'), $in->get('holder'), $in->get('pq_pk'), $in->get('sig'), $in->get('pq_sig'),
        ));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'resolveFnDsaAlg' => fn(array $a) => self::suite($a[0]),
            'isKnownFnDsaAlg' => fn(array $a) => Fndsa::isKnownAlg($a[0]),
            'isFnDsaVariant' => fn(array $a) => Fndsa::isVariant($a[0]),
            'hashKat' => fn(array $a) => self::out(Fndsa::hashKat((string) Base::bytes($a[0]), (int) Js::num($a[1]))),
            'mockKeypair' => function (array $a) {
                $kp = isset($a[1]) ? Fndsa::mockKeypair($a[0], $a[1] instanceof Obj ? (string) Base::bytes($a[1]) : $a[1]) : Fndsa::mockKeypair($a[0]);
                return ['pk' => self::out($kp['pk']), 'sk' => self::out($kp['sk'])];
            },
            'fndsaLeafMessage' => fn(array $a) => self::out(Fndsa::leafMessage($a[0], $a[1], $a[2])),
            'fndsaSignWith' => fn(array $a) => self::out(self::with($a[0], static fn() => Fndsa::sign($a[1], self::dec($a[2]), self::dec($a[3])))),
            'fndsaVerifyWith' => fn(array $a) => self::with($a[0], static fn() => Fndsa::verify($a[1], self::dec($a[2]), self::dec($a[3]), self::dec($a[4]))),
            'fndsaVerifyKat' => fn(array $a) => self::katVerify($a[0], $a[1], $a[2], $a[3], $a[4]),
            'fndsaSignKat' => function (array $a, Obj $c) {
                // the case name ends in the variant; the signing key is the mock key of the vector's own public key
                $variant = substr((string) $c->get('name'), strlen('fndsaSignKat/'));
                $vectors = self::vectors($a[0]);
                Fndsa::resetFalconBackend();
                Fndsa::registerTestBackend($vectors);
                try {
                    return self::out(Fndsa::sign($variant, "atlas-pca/fn-dsa/mock-sk/v1\x00" . $vectors[0]['pk'], 'm'));
                } finally {
                    Fndsa::resetFalconBackend();
                }
            },
            'signPcaWithFndsa' => function (array $a) {
                [$alg, $leaf, $fnDsa, $ed] = self::signInput($a[0]);
                return self::with('mock', static fn() => Fndsa::signPca($alg, $leaf, $fnDsa, $ed));
            },
            'verifyPcaFndsa' => fn(array $a) => self::verifyIn('mock', $a[0]),
            'verifyPcaFndsaNone' => fn(array $a) => self::verifyIn('none', $a[0]),
        ]);
    }

    public function testNoBackendRefuses(): void
    {
        Fndsa::resetFalconBackend();
        $this->expectException(FnDsaBackendMissing::class);
        Fndsa::verify('fn-dsa-512', str_repeat("\0", Fndsa::FN_DSA_512_PUBLIC_KEY_BYTES), 'm', str_repeat("\0", Fndsa::FN_DSA_512_SIGNATURE_BYTES));
    }
}
