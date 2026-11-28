<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\MpcEc;
use Atlas\Pca\MpcHybridOt;
use Atlas\Pca\MpcKemOt;
use Atlas\Pca\MpcMascot;
use Atlas\Pca\MpcMlKem768;
use Atlas\Pca\MpcOfflineCheatingAbort;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtChannel;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\MpcOtx;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\MpcSpdzRunner;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The MPC oblivious-transfer stack (Ed25519 group, Schnorr proofs, Chou-Orlandi base OT, IKNP/KOS extension kernels and channel)
 * against the TS reference: test-data/ref-mpc-ot.json.gz. Every random draw comes from a seeded stream, so the outputs are exact.
 * The ML-KEM / hybrid base OTs run on OpenSSL >= 3.5 ML-KEM-768 through ext-ffi (those cases skip when it is unavailable); the
 * no-dealer offline phase (Mascot) replays too. Needs the Ed25519 core functions of ext-sodium and ext-openssl (AES).
 */
final class RefMpcOtDifferentialTest extends TestCase
{
    private const FILE = 'ref-mpc-ot.json.gz';

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    protected function setUp(): void
    {
        if (!Ed25519Core::available() || !function_exists('openssl_encrypt')
            || !\Atlas\Pca\MpcShake256::available()) {
            $this->markTestSkipped('needs ext-sodium with the Ed25519 core functions (libsodium >= 1.0.18), ext-openssl and ext-ffi + libcrypto (SHAKE256)');
        }
    }

    private static function by(mixed $o): string
    {
        return Pca::unb64u((string) RefMpcSupport::obj($o)->get('$bytes'));
    }

    /** @return list<int> unsigned 32-bit words */
    private static function words(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        // u32 words arrive as JS numbers up to 2^32 - 1 (RefMpcSupport::i clamps to int32, which is for counts and indexes)
        return array_map(static function ($x): int {
            if (!($x instanceof Num) || !is_finite($x->float()) || $x->float() !== floor($x->float())) {
                throw new \InvalidArgumentException('not an integer');
            }
            return (int)$x->float() & 0xFFFFFFFF;
        }, $o);
    }

    private static function pt(mixed $o): array
    {
        if (!is_array($o) || count($o) < 4) {
            throw new \InvalidArgumentException('not a point');
        }
        return ['X' => RefMpcSupport::b($o[0]), 'Y' => RefMpcSupport::b($o[1]), 'Z' => RefMpcSupport::b($o[2]), 'T' => RefMpcSupport::b($o[3])];
    }

    private static function aff(array $p): array
    {
        [$x, $y] = MpcEc::toAffine($p);
        return ['x' => gmp_strval($x), 'y' => gmp_strval($y)];
    }

    private static function bl(array $a): array
    {
        return array_map(static fn(string $x): Obj => Base::outBytes($x), $a);
    }

    private static function pairsOut(array $a): array
    {
        return array_map(static fn(array $p): array => [Base::outBytes($p[0]), Base::outBytes($p[1])], $a);
    }

    private static function pairs(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        return array_map(static fn($p): array => [self::by($p[0]), self::by($p[1])], $o);
    }

    private static function orng(mixed $seed): MpcOtRandom
    {
        return MpcOtRandom::fromSeed(RefMpcSupport::b($seed));
    }

    private static function order2(): array
    {
        return ['X' => gmp_init(0), 'Y' => gmp_sub(MpcEc::q(), 1), 'Z' => gmp_init(1), 'T' => gmp_init(0)];
    }

    private static function flip(string $b, int $mask): string
    {
        return $b ^ str_repeat(chr($mask), strlen($b));
    }

    private static function tamper(string $name): ?array
    {
        $first = static function (array $a): array {
            if ($a === []) {
                throw new \OutOfBoundsException('empty');
            }
            return $a;
        };
        return match ($name) {
            'none' => null,
            'S_identity' => ['tamperS' => static fn(array $p): array => MpcEc::identity()],
            'S_order2' => ['tamperS' => static fn(array $p): array => self::order2()],
            'S_other' => ['tamperS' => static fn(array $p): array => MpcEc::addPoints($p, MpcEc::base())],
            'proof_z' => ['tamperProof' => static fn(array $p): array => ['U' => $p['U'], 'z' => gmp_mod(gmp_add($p['z'], 1), MpcEc::l())]],
            'proof_U' => ['tamperProof' => static fn(array $p): array => ['U' => MpcEc::addPoints($p['U'], MpcEc::base()), 'z' => $p['z']]],
            'R0_identity' => ['tamperR' => static function (array $R) use ($first): array {
                $first($R);
                $R[0] = MpcEc::identity();
                return $R;
            }],
            'R1_order2' => ['tamperR' => static function (array $R): array {
                if (count($R) > 1) {
                    $R[1] = self::order2();
                }
                return $R;
            }],
            'R_swap' => ['tamperR' => static function (array $R): array {
                if (count($R) > 1) {
                    [$R[0], $R[1]] = [$R[1], $R[0]];
                }
                return $R;
            }],
            'ct_flip' => ['tamperCiphertext' => static function (array $ct) use ($first): array {
                $first($ct);
                $ct[0][0] = self::flip($ct[0][0], 1);
                return $ct;
            }],
            'ct_flip1' => ['tamperCiphertext' => static function (array $ct) use ($first): array {
                $first($ct);
                $n = count($ct) - 1;
                $ct[$n][1] = self::flip($ct[$n][1], 0x80);
                return $ct;
            }],
            default => throw new \InvalidArgumentException($name),
        };
    }

    private static function idx(mixed $o): int
    {
        $d = RefMpcSupport::d($o);
        if ($d !== floor($d)) {
            throw new \InvalidArgumentException('not an integer');
        }
        return (int) $d;
    }

    private static function tweak(mixed $off, mixed $dom): array
    {
        return ['offset' => (int) RefMpcSupport::d($off), 'domain' => self::words($dom)];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        $S = RefMpcSupport::class;
        $b = $S::b(...);
        $i = $S::i(...);
        $ba = $S::ba(...);
        $out = static fn(string $x): Obj => Base::outBytes($x);
        $kem = static fn(callable $f) => static fn(array $a) => MpcMlKem768::available() ? $f($a) : [Base::SKIP, 'ML-KEM-768 needs OpenSSL >= 3.5 via ext-ffi'];
        $swap = static function (array $pk): array {
            [$pk[0][0], $pk[0][1]] = [$pk[0][1], $pk[0][0]];
            return $pk;
        };
        Base::run($file, $fn, $k, [
            'ecOp' => static function (array $a) use ($b, $out) {
                switch ($a[0]) {
                    case 'mulBase':
                        $p = MpcEc::mulBase($b($a[1]));
                        return ['p' => self::aff($p), 'enc' => $out(MpcEc::encodePoint($p)), 'comp' => $out(MpcEc::compressPoint($p))];
                    case 'mul':
                        return self::aff(MpcEc::mul($b($a[1]), self::pt($a[2])));
                    case 'add':
                        return self::aff(MpcEc::addPoints(self::pt($a[1]), self::pt($a[2])));
                    case 'sub':
                        return self::aff(MpcEc::sub(self::pt($a[1]), self::pt($a[2])));
                    case 'neg':
                        return self::aff(MpcEc::neg(self::pt($a[1])));
                    case 'dbl':
                        return self::aff(MpcEc::dbl(self::pt($a[1])));
                    case 'decompress':
                        $p = MpcEc::decompressPoint(self::by($a[1]));
                        return ['p' => self::aff($p), 'onCurve' => MpcEc::isOnCurve($p), 'identity' => MpcEc::isIdentity($p), 'prime' => MpcEc::hasPrimeOrder($p), 'inSub' => MpcEc::isInSubgroup($p)];
                    default:
                        throw new \InvalidArgumentException((string) $a[0]);
                }
            },
            'ecValidate' => static function (array $a) {
                $p = self::pt($a[0]);
                return ['onCurve' => MpcEc::isOnCurve($p), 'identity' => MpcEc::isIdentity($p), 'prime' => MpcEc::hasPrimeOrder($p), 'inSubgroup' => MpcEc::isInSubgroup($p)];
            },
            'ecAssert' => static function (array $a) {
                MpcEc::assertInSubgroup(self::pt($a[0]), 'p');
                return true;
            },
            'schnorr' => static function (array $a) use ($b) {
                $y = $b($a[0]);
                $nonce = $b($a[1]);
                $ctx = Pca::unb64u((string) $a[2]);
                $S = MpcEc::mulBase($y);
                $proof = MpcEc::schnorrProve($y, $S, static fn(): \GMP => $nonce, $ctx);
                $forged = ['U' => $proof['U'], 'z' => gmp_mod(gmp_add($proof['z'], 1), MpcEc::l())];
                $oor = ['U' => $proof['U'], 'z' => MpcEc::l()];
                return ['S' => self::aff($S), 'U' => self::aff($proof['U']), 'z' => gmp_strval($proof['z']), 'ok' => MpcEc::schnorrVerify($S, $proof, $ctx),
                    'badCtx' => MpcEc::schnorrVerify($S, $proof, 'other-ctx'), 'forged' => MpcEc::schnorrVerify($S, $forged, $ctx), 'oor' => MpcEc::schnorrVerify($S, $oor, $ctx),
                    'wrongS' => MpcEc::schnorrVerify(MpcEc::mulBase(gmp_add($y, 1)), $proof, $ctx), 'identityS' => MpcEc::schnorrVerify(MpcEc::identity(), $proof, $ctx)];
            },
            'prg' => static fn(array $a) => MpcOtx::prgColumn(Pca::unb64u((string) $a[0]), (int) $S::d($a[1]), $i($a[2])),
            'maskTail' => static function (array $a) use ($i) {
                $w = self::words($a[0]);
                MpcOtx::maskTail($w, $i($a[1]));
                return $w;
            },
            'transpose32' => static function (array $a) {
                $w = self::words($a[0]);
                MpcOtx::transpose32($w, 0);
                return $w;
            },
            'transposeCols' => static fn(array $a) => MpcOtx::transposeCols(self::words($a[0]), $i($a[1]), $i($a[2])),
            'gfMulX' => static function (array $a) {
                $w = self::words($a[0]);
                MpcOtx::gfMulX($w);
                return $w;
            },
            'gfXorInto' => static function (array $a) {
                $w = self::words($a[0]);
                MpcOtx::gfXorInto($w, self::words($a[1]), 0);
                return $w;
            },
            'gfBig' => static function (array $a) {
                $v = MpcOtx::gfToBig(self::words($a[0]));
                return ['big' => gmp_strval($v), 'back' => MpcOtx::gfFromBig($v)];
            },
            'accumColumn' => static function (array $a) {
                $c = self::words($a[0]);
                $acc = [0, 0, 0, 0];
                MpcOtx::accumColumn($c, 0, count($c), self::words($a[1]), $acc);
                return $acc;
            },
            'kosCombine' => static fn(array $a) => MpcOtx::kosCombine(self::words($a[0]), $i($a[1]), self::words($a[2])),
            'tmmo' => static fn(array $a) => MpcOtx::tmmoCrh(self::words($a[0]), $i($a[1]), self::tweak($a[2], $a[3])),
            'tweakDomain' => static fn(array $a) => MpcOtx::otTweakDomain(Pca::unb64u((string) $a[0])),
            'bigBytes' => static fn(array $a) => $out(MpcOtx::bigToBytes($b($a[0]), $i($a[1]))),
            'bytesBig' => static fn(array $a) => gmp_strval(MpcOtx::bytesToBig(Pca::unb64u((string) $a[0]))),
            'word64' => static fn(array $a) => gmp_strval(MpcOtx::word64(self::words($a[0]), $i($a[1]))),
            'bindingBytes' => static fn(array $a) => $out(MpcOt::bindingBytes(['sessionId' => Pca::unb64u((string) $a[0]), 'senderIndex' => self::idx($a[1]),
                'receiverIndex' => self::idx($a[2]), 'round' => $a[3]])),
            'baseOtKdf' => static function (array $a) use ($i, $out) {
                $b0 = MpcOt::randomBinding(self::orng(gmp_strval(gmp_init(4242))), 'base-ot');
                $R = [MpcEc::mulBase(gmp_init(5)), MpcEc::mulBase(gmp_init(6))];
                $th = MpcOt::baseOtTranscriptHash($b0, MpcEc::mulBase(gmp_init(3)), $R);
                return ['th' => $out($th), 'k' => $out(MpcOt::baseOtKdf($th, $i($a[0]), $R[0], MpcEc::mulBase(gmp_init(9))))];
            },
            'randomOt' => static function (array $a) use ($S) {
                $r = MpcOt::malBaseRandomOT($S::ia($a[0]), self::orng($a[1]), self::tamper((string) $a[2]));
                return ['S' => self::aff($r['S']), 'U' => self::aff($r['proof']['U']), 'z' => gmp_strval($r['proof']['z']), 'R' => array_map(self::aff(...), $r['R']),
                    'senderPads' => self::pairsOut($r['senderPads']), 'recvPads' => self::bl($r['recvPads'])];
            },
            'baseOt' => static function (array $a) use ($S) {
                $res = MpcOt::baseOT(self::pairs($a[0]), $S::ia($a[1]), self::orng($a[2]), self::tamper((string) $a[3]));
                $t = $res['transcript'];
                return ['received' => self::bl($res['received']), 'S' => self::aff($t['S']), 'U' => self::aff($t['proof']['U']), 'z' => gmp_strval($t['proof']['z']),
                    'R' => array_map(self::aff(...), $t['R']), 'ct' => self::pairsOut($t['ct']), 'com' => self::pairsOut($t['com'])];
            },
            'channel' => static function (array $a) use ($S, $i, $ba) {
                $ch = new MpcOtChannel(self::orng($a[3]));
                $tn = $a[5];
                $ch->tamperU = match ($tn) {
                    'flip00' => static function (array $u, int $round): array {
                        $u[0] = gmp_xor($u[0], 1);
                        return $u;
                    },
                    'flipLast' => static function (array $u, int $round): array {
                        $u[127] = gmp_xor($u[127], gmp_mul(1, 32));
                        return $u;
                    },
                    'oversize' => static function (array $u, int $round): array {
                        $u[3] = gmp_or($u[3], gmp_pow(2, 5000));
                        return $u;
                    },
                    'negative' => static function (array $u, int $round): array {
                        $u[3] = gmp_init(-1);
                        return $u;
                    },
                    'round2flip' => static function (array $u, int $round): array {
                        if ($round === 1) {
                            $u[10] = gmp_xor($u[10], 2);
                        }
                        return $u;
                    },
                    default => null,
                };
                $outs = [];
                for ($j = 0, $n = $i($a[4]); $j < $n; $j++) {
                    $e = $ch->extend($S::ia($a[0]), $ba($a[1]), $ba($a[2]));
                    $outs[] = ['received' => $S::s($e['received']), 'uMatrix' => $S::s($e['uMatrix'])];
                }
                $selector = gmp_strval($ch->selector());
                $base = $ch->baseTranscript === null ? null : ['S' => self::aff($ch->baseTranscript['S']), 'R' => count($ch->baseTranscript['R'])];
                return ['selector' => $selector, 'outs' => $outs, 'base' => $base];
            },
            'kosChi' => static function (array $a) use ($i, $ba, $S) {
                $bd = Pca::unb64u((string) $a[0]);
                $u = $ba($a[2]);
                $mExt = $i($a[3]);
                return ['w' => MpcOt::kosChiWords($bd, $i($a[1]), $u, $mExt), 'chi' => $S::s(MpcOt::kosChallenges($bd, $i($a[1]), $u, $mExt))];
            },
            'kemOt' => $kem(static function (array $a) use ($S, $swap) {
                $tn = $a[4];
                $tamper = $tn === 'badKey' ? ['tamperOpenedKeys' => $swap] : ($tn === 'badSid' ? ['tamperReceiverSid' => static fn(string $x): string => $x ^ str_repeat("\x01", strlen($x))] : null);
                $g = self::orng($a[3]);
                $bl = static fn(array $x): array => array_map(static fn(array $p): array => [Base::outBytes($p[0]), Base::outBytes($p[1])], $x);
                if ($a[0] === 'kemBaseOT') {
                    $r = MpcKemOt::kemBaseOT(self::pairs($a[1]), $S::ia($a[2]), $g);
                    $t = $r['transcript'];
                    return ['received' => self::bl($r['received']), 'transcript' => ['publicKeys' => $bl($t['publicKeys']), 'ciphertexts' => $bl($t['ciphertexts']), 'encrypted' => $bl($t['encrypted'])]];
                }
                if ($a[0] === 'kemBaseOtMal') {
                    $r = MpcKemOt::kemBaseOtMal(self::pairs($a[1]), $S::ia($a[2]), $g, $tamper);
                    $t = $r['transcript'];
                    return ['received' => self::bl($r['received']), 'transcript' => ['rn' => Base::outBytes($t['rn']), 'commitments' => self::bl($t['commitments']), 'sn' => Base::outBytes($t['sn']),
                        'publicKeys' => $bl($t['publicKeys']), 'ciphertexts' => $bl($t['ciphertexts']), 'encrypted' => $bl($t['encrypted'])]];
                }
                $r = MpcKemOt::kemBaseOtMalRandom($S::ia($a[2]), $g, $tamper);
                $t = $r['transcript'];
                return ['senderSecrets' => $bl($r['senderSecrets']), 'recvSecrets' => self::bl($r['recvSecrets']), 'sid' => Base::outBytes($r['sid']),
                    'transcript' => ['rn' => Base::outBytes($t['rn']), 'commitments' => self::bl($t['commitments']), 'sn' => Base::outBytes($t['sn']),
                        'publicKeys' => $bl($t['publicKeys']), 'ciphertexts' => $bl($t['ciphertexts'])]];
            }),
            'kemPad' => static function (array $a) use ($i) {
                if (count($a) === 1) {
                    return Base::outBytes(MpcKemOt::kemOtPad(0, 0, str_repeat("\0", 32), $i($a[0])));
                }
                return Base::outBytes(MpcKemOt::kemOtPad($i($a[0]), $i($a[1]), implode('', array_map('chr', range(0, 31))), $i($a[2])));
            },
            'hybridOt' => $kem(static function (array $a) use ($S, $swap) {
                $tn = $a[3];
                $tamper = match ($tn) {
                    'ec' => ['ec' => self::tamper('ct_flip')],
                    'ecS' => ['ec' => self::tamper('S_identity')],
                    'enc' => ['tamperEncrypted' => static function (array $e): array {
                        $e[0][0] = $e[0][0] ^ str_repeat("\x01", strlen($e[0][0]));
                        return $e;
                    }],
                    'kem' => ['kem' => ['tamperOpenedKeys' => $swap]],
                    default => null,
                };
                $r = MpcHybridOt::hybridBaseOT(self::pairs($a[0]), $S::ia($a[1]), self::orng($a[2]), $tamper);
                $t = $r['transcript'];
                return ['received' => self::bl($r['received']), 'sid' => Base::outBytes($t['sid']), 'ecS' => self::aff($t['ecS']), 'kemSid' => Base::outBytes($t['kemSid']),
                    'encrypted' => self::pairsOut($t['encrypted']), 'commitments' => self::pairsOut($t['commitments'])];
            }),
            'hybridKey' => static fn(array $a) => Base::outBytes(MpcHybridOt::hybridTransferKey(str_repeat("\x01", 32), 3, 1, str_repeat("\x02", 16), str_repeat("\x03", 32), $i($a[0]))),
            'offline' => static function (array $a) use ($S, $i, $b, $ba) {
                $o = $a[3] === null ? null : $S::obj($a[3]);
                $opts = [];
                if ($o !== null) {
                    foreach (['sacrifice' => 'sacrifice', 'partners' => 'sacrificePartners', 'keys' => 'macKeys', 'statSec' => 'statSec', 'unsafe' => 'unsafeStatSec'] as $from => $to) {
                        $v = $o->get($from);
                        if ($v !== null) {
                            $opts[$to] = is_bool($v) ? $v : $i($v);
                        }
                    }
                    if ($o->get('dev') !== null) {
                        $dv = $o->get('dev');
                        $opts['deviation'] = ['productMul' => $i($dv[0]), 'delta' => $b($dv[1])];
                    }
                }
                $off = MpcMascot::make($i($a[0]), $b($a[1]), $opts);
                $ctx = $S::ctx($off->macContext());
                $base = ['n' => $off->n(), 'statSec' => $off->statSec, 'ctx' => $ctx];
                $n = $off->n();
                switch ($a[2]) {
                    case 'ctx':
                        return $base;
                    case 'triple':
                        return $base + ['t' => $S::triple($off->genAuthTriple())];
                    case 'input':
                        return $base + ['v' => $S::authSV($off->authInput($b($o->get('value')), $i($o->get('owner'))))];
                    case 'multiply':
                        $x = array_slice($ba($o->get('x')), 0, $n);
                        $y = array_slice($ba($o->get('y')), 0, $n);
                        $z = $off->otShareMultiply($x, $y);
                        $sum = static fn(array $v): \GMP => array_reduce($v, static fn(\GMP $acc, \GMP $e): \GMP => \Atlas\Pca\MpcField::fadd($acc, $e), gmp_init(0));
                        return $base + ['z' => $S::s($z), 'sum' => gmp_strval($sum($z)), 'expect' => gmp_strval(\Atlas\Pca\MpcField::fmul($sum($x), $sum($y)))];
                    case 'consistency':
                        $ins = [];
                        foreach ($o->get('values') as $k => $v) {
                            $ins[] = $off->authInput($b($v), $k % $n);
                        }
                        if ($o->get('tamper') === true) {
                            $ins[0]['value'][0] = \Atlas\Pca\MpcField::fadd($ins[0]['value'][0], gmp_init(1));
                        }
                        $off->checkInputConsistency($ins);
                        return $base + ['ok' => true];
                    default:
                        throw new \InvalidArgumentException((string) $a[2]);
                }
            },
            'offlineBlame' => static function (array $a) use ($i, $b) {
                try {
                    MpcMascot::make($i($a[0]), $b($a[1]), ['deviation' => ['productMul' => $i($a[2]), 'delta' => $b($a[3])]])->genAuthTriple();
                    return ['aborted' => false];
                } catch (MpcOfflineCheatingAbort $e) {
                    return ['aborted' => true, 'name' => 'OfflineCheatingAbort', 'blamed' => $e->blamed];
                }
            },
            'noDealerRun' => static function (array $a) use ($S, $i, $b) {
                $m = $S::obj($a[1]);
                $cfg = ['Q' => $i($m->get('Q')), 'seed' => $b($m->get('seed'))];
                if ($m->get('deviations') !== null) {
                    $cfg['deviations'] = $S::devs($m->get('deviations'));
                }
                $r = MpcSpdzRunner::composeSecureMalicious($S::vectors($a[0]), $cfg);
                return ['composed' => ['allow' => $r['composed']['allow'], 't' => $r['composed']['t'], 'rQuant' => $r['composed']['rQuant']], 'parties' => $r['parties'], 'Q' => $r['Q'],
                    'opens' => $r['opens'], 'multiplications' => $r['multiplications'], 'offlineMode' => $r['offlineMode'], 'triplesVerified' => $r['triplesVerified'], 'macChecked' => $r['macChecked']];
            },
        ]);
    }
}
