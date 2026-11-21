<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\MpcBeaver;
use Atlas\Pca\MpcCompose;
use Atlas\Pca\MpcEnc;
use Atlas\Pca\MpcField;
use Atlas\Pca\MpcFieldRng;
use Atlas\Pca\MpcGf128;
use Atlas\Pca\MpcParty;
use Atlas\Pca\MpcRunner;
use Atlas\Pca\MpcSharing;
use Atlas\Pca\MpcSpdz;
use Atlas\Pca\MpcSpdzEngine;
use Atlas\Pca\MpcSpdzRunner;
use Atlas\Pca\MpcThermometer;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The MPC deterministic layer (field, sharing, GF(2^128), choice-bit encoding, Beaver, SPDZ authenticated shares / triples / engine,
 * the semi-honest and malicious runners) against the TS reference: test-data/ref-mpc.json.gz. Every random draw comes from a
 * seeded SplitMix64, so the outputs are exact. The corpus carries only integer PRNG seeds, no key material.
 */
final class RefMpcDifferentialTest extends TestCase
{
    private const FILE = 'ref-mpc.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function opened(array $l): array
    {
        return array_map(static fn(array $m): array => ['label' => $m['label'], 'value' => gmp_strval($m['value']), 'shares' => RefMpcSupport::s($m['shares'])], $l);
    }

    private static function composed(array $c): array
    {
        return ['allow' => $c['allow'], 't' => $c['t'], 'rQuant' => $c['rQuant']];
    }

    private static function partnered(array $t): array
    {
        return ['keep' => RefMpcSupport::triple($t['keep']), 'partners' => array_map(RefMpcSupport::triple(...), $t['partners'])];
    }

    private static function gens(MpcFieldRng $g, int $n): array
    {
        $o = [];
        for ($i = 0; $i < $n; $i++) {
            $o[] = gmp_strval($g->next());
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $S = RefMpcSupport::class;
        $b = $S::b(...);
        $i = $S::i(...);
        $rng = $S::rng(...);
        Base::run($file, $fn, $k, [
            'mod' => static fn(array $a) => gmp_strval(MpcField::mod($b($a[0]))),
            'fneg' => static fn(array $a) => gmp_strval(MpcField::fneg($b($a[0]))),
            'fadd' => static fn(array $a) => gmp_strval(MpcField::fadd($b($a[0]), $b($a[1]))),
            'fsub' => static fn(array $a) => gmp_strval(MpcField::fsub($b($a[0]), $b($a[1]))),
            'fmul' => static fn(array $a) => gmp_strval(MpcField::fmul($b($a[0]), $b($a[1]))),
            'fieldRng' => static fn(array $a) => self::gens($rng($a[0]), $i($a[1])),
            'fieldRngDefault' => static fn(array $a) => self::gens(new MpcFieldRng(), $i($a[0])),
            'share' => static fn(array $a) => $S::s(MpcSharing::share($b($a[0]), $i($a[1]), $rng($a[2]))),
            'reconstruct' => static fn(array $a) => gmp_strval(MpcSharing::reconstruct($S::ba($a[0]))),
            'shareConstant' => static fn(array $a) => $S::s(MpcSharing::shareConstant($b($a[0]), $i($a[1]))),
            'sv' => static function (array $a) use ($S, $b) {
                $x = $S::ba($a[1]);
                return $S::s(match ($a[0]) {
                    'add' => MpcSharing::addSV($x, $S::ba($a[2])),
                    'sub' => MpcSharing::subSV($x, $S::ba($a[2])),
                    'neg' => MpcSharing::negSV($x),
                    'scale' => MpcSharing::scaleSV($x, $b($a[2])),
                    'addPublic' => MpcSharing::addPublicSV($x, $b($a[2])),
                    'notBit' => MpcSharing::notBitSV($x),
                    default => throw new \InvalidArgumentException((string) $a[0]),
                });
            },
            'gf' => static function (array $a) use ($b, $i) {
                $x = $b($a[1]);
                return gmp_strval(match ($a[0]) {
                    'add' => MpcGf128::add($x, $b($a[2])),
                    'mul' => MpcGf128::mul($x, $b($a[2])),
                    'mulX' => MpcGf128::mulX($x),
                    'mulByXi' => MpcGf128::mulByXi($x, $i($a[2])),
                    default => throw new \InvalidArgumentException((string) $a[0]),
                });
            },
            'encBits' => static fn(array $a) => MpcEnc::encBits($i($a[0])),
            'makeGadget' => static fn(array $a) => $S::s(MpcEnc::makeGadget($i($a[0]), $rng($a[1]), ($a[2] ?? null) === true)),
            'plainShare' => static function (array $a) use ($b, $S) {
                $e = MpcEnc::plainShare($b($a[0]));
                return ['value' => gmp_strval($e['value']), 'bits' => $e['bits']];
            },
            'plainGadget' => static fn(array $a) => $S::s(MpcEnc::plainGadget()),
            'randomBits' => static fn(array $a) => MpcEnc::randomBits($i($a[0]), $rng($a[1])),
            'sampleEnc' => static function (array $a) use ($i, $rng, $S) {
                $g = $rng($a[1]);
                $gad = MpcEnc::makeGadget($i($a[0]), $g, true);
                $e = MpcEnc::sampleEnc($gad, $g);
                return ['gadget' => $S::s($gad), 'e' => ['value' => gmp_strval($e['value']), 'bits' => $e['bits']]];
            },
            'encValue' => static fn(array $a) => gmp_strval(MpcEnc::encValue($S::ba($a[0]), $S::ia($a[1]))),
            'genTriple' => static function (array $a) use ($i, $rng, $S) {
                $t = MpcBeaver::genTriple($i($a[0]), $rng($a[1]));
                return ['a' => $S::s($t['a']), 'b' => $S::s($t['b']), 'c' => $S::s($t['c'])];
            },
            'beaverMul' => static function (array $a) use ($S) {
                $op = [];
                $z = MpcBeaver::beaverMul($S::ba($a[0]), $S::ba($a[1]), ['a' => $S::ba($a[2]), 'b' => $S::ba($a[3]), 'c' => $S::ba($a[4])], $op);
                return ['z' => $S::s($z), 'opened' => self::opened($op)];
            },
            'thermometerEncode' => static fn(array $a) => MpcThermometer::thermometerEncode($S::d($a[0]), $i($a[1])),
            'thermometerDecode' => static function (array $a) {
                $bits = array_map(static fn($x) => $x instanceof Num && $x->float() === 1.0 ? 1 : 0, $a[0]);
                return MpcThermometer::thermometerDecode($bits);
            },
            'quantizeR' => static fn(array $a) => MpcParty::quantizeR($S::d($a[0]), $i($a[1])),
            'composeClear' => static fn(array $a) => self::composed(MpcCompose::composeClear($S::vectors($a[0]), $i($a[1]))),
            'assertDecisionVectors' => static function (array $a) use ($S, $i) {
                MpcCompose::assertDecisionVectors($S::vectors($a[0]), $i($a[1]));
                return true;
            },
            'composeSecure' => static function (array $a) use ($S, $i, $b) {
                $r = MpcRunner::composeSecure($S::vectors($a[0]), $i($a[1]), $b($a[2]));
                $sh = array_map(static fn(array $s): array => ['label' => $s['label'], 'party' => $s['party'], 'secret' => gmp_strval($s['secret']), 'shares' => $S::s($s['shares'])], $r['sharings']);
                return ['composed' => self::composed($r['composed']), 'parties' => $r['parties'], 'Q' => $r['Q'], 'multiplications' => $r['multiplications'],
                    'opened' => self::opened($r['opened']), 'sharings' => $sh, 'heldShares0' => $S::s($r['views'][0]['heldShares']), 'viewsLen' => count($r['views'])];
            },
            'setupMac' => static fn(array $a) => $S::ctx(MpcSpdz::setupMac($i($a[0]), $rng($a[1]), $i($a[2]))),
            'macSoundnessBits' => static fn(array $a) => count($a) === 1 ? MpcSpdz::macSoundnessBits($i($a[0])) : MpcSpdz::macSoundnessBits($i($a[0]), $b($a[1])),
            'authShare' => static function (array $a) use ($S, $i, $rng, $b) {
                $g = $rng($a[1]);
                $c = MpcSpdz::setupMac($i($a[0]), $g);
                return ['ctx' => $S::ctx($c), 'sv' => $S::authSV(MpcSpdz::authShare($b($a[2]), $c, $g))];
            },
            'authConstant' => static fn(array $a) => $S::authSV(MpcSpdz::authConstant($b($a[2]), MpcSpdz::setupMac($i($a[0]), $rng($a[1])))),
            'authOp' => static function (array $a) use ($S, $i, $rng, $b) {
                $op = $a[0];
                $g = $rng($a[2]);
                $c = MpcSpdz::setupMac($i($a[1]), $g);
                $x = MpcSpdz::authShare($b($a[3]), $c, $g);
                $y = MpcSpdz::authShare($b($a[4]), $c, $g);
                $k = $b($a[5]);
                if ($op === 'open') {
                    return ['val' => gmp_strval(MpcSpdz::authValue($x))];
                }
                $res = match ($op) {
                    'add' => MpcSpdz::addAuth($x, $y),
                    'sub' => MpcSpdz::subAuth($x, $y),
                    'neg' => MpcSpdz::negAuth($x),
                    'scale' => MpcSpdz::scaleAuth($x, $k),
                    'addPublic' => MpcSpdz::addPublicAuth($x, $k, $c),
                    'notBit' => MpcSpdz::notBitAuth($x, $c),
                    default => throw new \InvalidArgumentException((string) $op),
                };
                $val = MpcSpdz::authValue($res);
                $rows = array_merge([$res['mac']], $res['extraMac']);
                $keys = MpcSpdz::macKeys($c);
                $ok = true;
                foreach ($rows as $l => $row) {
                    $sum = gmp_init(0);
                    foreach ($row as $m) {
                        $sum = MpcField::fadd($sum, $m);
                    }
                    $ok = $ok && gmp_cmp($sum, MpcField::fmul($keys[$l]['alpha'], $val)) === 0;
                }
                return ['res' => $S::authSV($res), 'val' => gmp_strval($val), 'okMac' => $ok];
            },
            'genAuthTriple' => static function (array $a) use ($S, $i, $rng) {
                $g = $rng($a[1]);
                return $S::triple(MpcSpdz::genAuthTriple(MpcSpdz::setupMac($i($a[0]), $g), $g));
            },
            'genTripleWithPartners' => static function (array $a) use ($S, $i, $rng) {
                if (count($a) === 2) {
                    $g = $rng($a[1]);
                    return self::partnered(MpcSpdz::genTripleWithPartners(MpcSpdz::setupMac($i($a[0]), $g), $g));
                }
                $g = $rng($a[0]);
                return self::partnered(MpcSpdz::genTripleWithPartners(MpcSpdz::setupMac(2, $g), $g, $i($a[1]), $S::fault($a[2])));
            },
            'sacrifice' => static function (array $a) use ($S, $i, $rng) {
                $g = $rng($a[1]);
                $c = MpcSpdz::setupMac($i($a[0]), $g);
                $f = $S::fault($a[4]);
                $batch = [];
                for ($j = 0; $j < $i($a[2]); $j++) {
                    $batch[] = MpcSpdz::genTripleWithPartners($c, $g, $i($a[3]), $j === 0 ? $f : null);
                }
                return ['certified' => array_map($S::triple(...), MpcSpdz::sacrificeVerify($batch, $c, $g, $S::devs($a[5])))];
            },
            'engineRun' => static function (array $a) use ($S, $i, $rng, $b) {
                $g = $rng($a[1]);
                $c = MpcSpdz::setupMac($i($a[0]), $g, count($a) > 4 ? $i($a[4]) : MpcSpdz::MAC_KEYS);
                $e = new MpcSpdzEngine($c, $S::devs($a[3]));
                $outs = [];
                foreach ($a[2] as $j => $v) {
                    $outs[] = gmp_strval($e->open(MpcSpdz::authShare($b($v), $c, $g), 'v' . $j));
                }
                $e->macCheck($g);
                return ['outs' => $outs, 'count' => $e->openCount()];
            },
            'macResiduals' => static function (array $a) use ($S, $b) {
                $op = [];
                foreach ($a[2] as $o) {
                    $m = $S::obj($o);
                    $op[] = ['value' => $b($m->get('value')), 'macShares' => $S::baa($m->get('macShares')), 'label' => ''];
                }
                return $S::ss(MpcSpdz::macResiduals($b($a[0]), $S::baa($a[1]), $op, $S::baa($a[3])));
            },
            'beaverAuth' => static function (array $a) use ($S, $i, $rng, $b) {
                $g = $rng($a[1]);
                $c = MpcSpdz::setupMac($i($a[0]), $g);
                $e = new MpcSpdzEngine($c, $S::devs($a[4]));
                $x = MpcSpdz::authShare($b($a[2]), $c, $g);
                $y = MpcSpdz::authShare($b($a[3]), $c, $g);
                $t = MpcSpdz::genAuthTriple($c, $g);
                $z = MpcSpdz::beaverMulAuth($x, $y, $t, $c, $e, 'm');
                $val = MpcSpdz::authValue($z);
                $out = $e->open($z, 'out');
                $e->macCheck($g);
                return ['z' => $S::authSV($z), 'val' => gmp_strval($val), 'out' => gmp_strval($out), 'opens' => $e->openCount()];
            },
            'composeSecureMalicious' => static function (array $a) use ($S, $i, $b) {
                $m = $S::obj($a[1]);
                $cfg = ['insecureTrustedDealer' => $m->get('insecureTrustedDealer') === true];
                if ($m->get('Q') !== null) {
                    $cfg['Q'] = $i($m->get('Q'));
                }
                if ($m->get('seed') !== null) {
                    $cfg['seed'] = $b($m->get('seed'));
                }
                if ($m->get('deviations') !== null) {
                    $cfg['deviations'] = $S::devs($m->get('deviations'));
                }
                if ($m->get('dealer') !== null) {
                    $d = $S::obj($m->get('dealer'));
                    $cfg['dealer'] = ['verifyTriples' => $d->get('verifyTriples'), 'partners' => $d->get('partners') === null ? null : $i($d->get('partners')),
                        'fault' => $S::fault($d->get('fault'))];
                }
                if (!$cfg['insecureTrustedDealer'] && !Ed25519Core::available()) {
                    return [Base::SKIP, 'the no-dealer offline phase needs the Ed25519 core functions of ext-sodium (libsodium >= 1.0.18)'];
                }
                $r = MpcSpdzRunner::composeSecureMalicious($S::vectors($a[0]), $cfg);
                return ['composed' => self::composed($r['composed']), 'parties' => $r['parties'], 'Q' => $r['Q'], 'opens' => $r['opens'], 'multiplications' => $r['multiplications'],
                    'offlineMode' => $r['offlineMode'], 'triplesVerified' => $r['triplesVerified'], 'macChecked' => $r['macChecked']];
            },
        ]);
    }
}
