<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcEndemicOt;
use Atlas\Pca\MpcLweLattice;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The endemic LWE base OT (Kyber-768 K-PKE through liblweot over ext-ffi) against the TS reference: test-data/ref-mpc-endemic.json.gz. Receiver key
 * seeds are labels (sha256("atlas-pca-conformance/" . label)); every random draw comes from a seeded stream, so the outputs are exact. Needs
 * ext-ffi and liblweot (ATLAS_PCA_LIBLWEOT); ATLAS_PCA_LIBLWEOT_REQUIRED=1 (the lwe-ot workflow) fails instead of skipping.
 */
final class RefMpcEndemicOtDifferentialTest extends TestCase
{
    private const FILE = 'ref-mpc-endemic.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    protected function setUp(): void
    {
        if (!MpcLweLattice::available()) {
            if (getenv('ATLAS_PCA_LIBLWEOT_REQUIRED') === '1') {
                $this->fail('liblweot must load (ATLAS_PCA_LIBLWEOT, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and liblweot (ATLAS_PCA_LIBLWEOT)');
        }
    }

    private static function by(mixed $o): string
    {
        return Pca::unb64u((string) RefMpcSupport::obj($o)->get('$bytes'));
    }

    private static function seed(mixed $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function rng(mixed $s): MpcOtRandom
    {
        return MpcOtRandom::fromSeed(RefMpcSupport::b($s));
    }

    private static function bl(array $a): array
    {
        return array_map(static fn(string $x): Obj => Base::outBytes($x), $a);
    }

    private static function bp(array $a): array
    {
        return array_map(static fn(array $p): array => [Base::outBytes($p[0]), Base::outBytes($p[1])], $a);
    }

    private static function pairs(mixed $o): array
    {
        return array_map(static fn($p): array => [self::by($p[0]), self::by($p[1])], $o);
    }

    private static function flip(string $b): string
    {
        return $b ^ str_repeat("\x01", strlen($b));
    }

    private static function fill(int $n, int $k): string
    {
        $o = '';
        for ($i = 0; $i < $n; $i++) {
            $o .= chr(($i * 31 + $k * 7 + ($i >> 3)) & 255);
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $i = RefMpcSupport::i(...);
        Base::run($file, $fn, $k, [
            'lweKeygenFips' => static function (array $a) {
                [$pk, $sk] = MpcLweLattice::keygenFips203(self::seed($a[0]));
                return ['pk' => Base::outBytes($pk), 'skSha256' => hash('sha256', $sk)];
            },
            'lweKeygen' => static function (array $a) {
                [$pk, $sk] = MpcLweLattice::keygen(self::seed($a[0]));
                return ['pk' => Base::outBytes($pk), 'skSha256' => hash('sha256', $sk)];
            },
            'lweEnc' => static fn(array $a) => Base::outBytes(MpcLweLattice::enc(MpcLweLattice::keygen(self::seed($a[0]))[0], self::by($a[1]), self::by($a[2]))),
            'lweDec' => static fn(array $a) => Base::outBytes(MpcLweLattice::dec(MpcLweLattice::keygen(self::seed($a[0]))[1], self::by($a[1]))),
            'lweRing' => static fn(array $a) => Base::outBytes($a[0] === 'add' ? MpcLweLattice::ringAdd(self::by($a[1]), self::by($a[2])) : MpcLweLattice::ringSub(self::by($a[1]), self::by($a[2]))),
            'lweHash' => static fn(array $a) => Base::outBytes(MpcLweLattice::hashToRing(self::by($a[0]))),
            'randomOt' => static function (array $a) use ($i) {
                $rv = MpcEndemicOt::receive(array_map($i, $a[0]), self::rng($a[1]));
                $sm = MpcEndemicOt::sendRandom($rv['message'], self::rng($a[2]));
                $m = $rv['message'];
                return ['rn' => Base::outBytes($m['rn']), 'points' => self::bp($m['points']), 'rhos' => self::bl($m['rhos']), 'ciphertexts' => self::bp($sm['ciphertexts']),
                    'senderPads' => self::bp($sm['senderPads']), 'recvPads' => self::bl(MpcEndemicOt::recoverRandom($rv['state'], $sm))];
            },
            'randomOtTamper' => static function (array $a) use ($i) {
                $rv = MpcEndemicOt::receive(array_map($i, $a[0]), self::rng($a[1]));
                $sm = MpcEndemicOt::sendRandom($rv['message'], self::rng($a[2]), static function (array $c): array {
                    $c[0][0] = substr($c[0][0], 0, 1087);
                    return $c;
                });
                return self::bl(MpcEndemicOt::recoverRandom($rv['state'], $sm));
            },
            'baseOt' => static function (array $a) use ($i) {
                $choices = array_map($i, $a[1]);
                $c0 = $choices[0] & 1;
                $one = self::rng($a[2]); // one generator serves the receiver, then the sender, as the reference does
                $tamper = match ($a[3]) {
                    'enc' => static function (array $e): array {
                        $e[0][0] = self::flip($e[0][0]);
                        return $e;
                    },
                    'encChosen' => static function (array $e) use ($c0): array {
                        $e[0][$c0] = self::flip($e[0][$c0]);
                        return $e;
                    },
                    default => null,
                };
                $r = MpcEndemicOt::baseOT(self::pairs($a[0]), $choices, $one, $one, $tamper);
                $t = $r['transcript'];
                return ['received' => self::bl($r['received']), 'ciphertexts' => self::bp($t['ciphertexts']), 'encrypted' => self::bp($t['encrypted']), 'commitments' => self::bp($t['commitments'])];
            },
            'sendMalformed' => static function (array $a) {
                $m = MpcEndemicOt::receive([0, 1], self::rng('77'))['message'];
                switch ($a[0]) {
                    case 'nonce':
                        $m['rn'] = self::fill(31, 1);
                        break;
                    case 'count':
                        $m['rhos'] = array_slice($m['rhos'], 1);
                        break;
                    case 'point':
                        $m['points'][1][0] = self::fill(1151, 1);
                        break;
                    case 'rho':
                        $m['rhos'][0] = self::fill(33, 1);
                        break;
                }
                return count(MpcEndemicOt::sendRandom($m, self::rng('78'))['ciphertexts']);
            },
        ]);
    }
}
