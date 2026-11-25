<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcEc;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetForensics;
use Atlas\Pca\MpcNetFrameSplitter;
use Atlas\Pca\MpcNetPa;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The pure parts of the MPC networked runner against the TS reference: test-data/ref-mpc-net.json.gz (pairwise-authenticated shares,
 * wire framing, aborts, forensic disclosures, OT-over-network codecs and gadget-seed helpers). The codec point cases need the
 * Ed25519 group (pure PHP, no sodium).
 */
final class RefMpcNetDifferentialTest extends TestCase
{
    private const FILE = 'ref-mpc-net.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function pa(mixed $o): array
    {
        $m = RefMpcSupport::obj($o);
        return ['x' => RefMpcSupport::b($m->get('x')), 'tag' => RefMpcSupport::ba($m->get('tag')), 'key' => RefMpcSupport::ba($m->get('key'))];
    }

    private static function aw(mixed $o): array
    {
        $m = RefMpcSupport::obj($o);
        return ['v' => self::pa($m->get('v')), 'm' => array_map(self::pa(...), $m->get('m'))];
    }

    private static function paJ(array $p): array
    {
        return ['x' => gmp_strval($p['x']), 'tag' => RefMpcSupport::s($p['tag']), 'key' => RefMpcSupport::s($p['key'])];
    }

    private static function awJ(array $a): array
    {
        return ['v' => self::paJ($a['v']), 'm' => array_map(self::paJ(...), $a['m'])];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $S = RefMpcSupport::class;
        $b = $S::b(...);
        $i = $S::i(...);
        $by = static fn(mixed $o): string => Pca::unb64u((string) RefMpcSupport::obj($o)->get('$bytes'));
        $ob = static fn(string $x): Obj => Base::outBytes($x);
        $strs = static fn(array $l): array => array_map(static fn(\GMP $g): string => gmp_strval($g), $l);
        $sideJ = static fn(array $m): array => array_map(static fn(int $p, array $v): array => [$p, array_map(static fn(\GMP $g): string => gmp_strval($g), $v)], array_keys($m), array_values($m));
        Base::run($file, $fn, $k, [
            'pa' => static function (array $a) use ($b, $i, $S) {
                $op = $a[0];
                $p = self::pa($a[1]);
                $n = count($p['tag']);
                return match ($op) {
                    'add' => self::paJ(MpcNetPa::paAdd($p, self::pa($a[2]))),
                    'sub' => self::paJ(MpcNetPa::paSub($p, self::pa($a[2]))),
                    'neg' => self::paJ(MpcNetPa::paNeg($p)),
                    'scale' => self::paJ(MpcNetPa::paScale($p, $b($a[2]))),
                    'addPublic0' => self::paJ(MpcNetPa::paAddPublic0(['id' => $i($a[2]), 'n' => $n, 'delta' => $b($a[3]), 'tagged' => ($a[4] ?? null) === true], $p, $b($a[5]))),
                    'verify' => MpcNetPa::paVerify(['id' => $i($a[2]), 'n' => $n, 'delta' => $b($a[3]), 'tagged' => true], $p, $i($a[4]), $b($a[5]), $b($a[6])),
                    'flat' => (static function () use ($a, $i, $p, $n, $S) {
                        $id = $i($a[2]);
                        $tg = ($a[3] ?? null) === true;
                        $f = MpcNetPa::paFlat($p, $id, $n, $tg);
                        return ['f' => $S::s($f), 'w' => MpcNetPa::paWidth($n, $tg), 'back' => self::paJ(MpcNetPa::paParse($f, 0, $id, $n, $tg))];
                    })(),
                    default => throw new \InvalidArgumentException((string) $op),
                };
            },
            'aw' => static function (array $a) use ($b, $i, $S) {
                if (count($a) === 1) {
                    return MpcNetPa::sharingsPerTriple($i($a[0]));
                }
                if (count($a) === 3) {
                    $x = self::aw($a[0]);
                    $n = count($x['v']['tag']);
                    $keys = count($x['m']);
                    $id = $i($a[1]);
                    $tg = $a[2] === true;
                    $f = MpcNetPa::awFlat($x, $id, $n, $tg);
                    return ['f' => $S::s($f), 'w' => MpcNetPa::awWidth($n, $keys, $tg), 'back' => self::awJ(MpcNetPa::awParse($f, 0, $id, $n, $keys, $tg))];
                }
                $x = self::aw($a[0]);
                $y = self::aw($a[1]);
                $n = count($x['v']['tag']);
                $alpha = array_map(self::pa(...), $a[2]);
                $tg = $a[3] === true;
                $c = $b($a[4]);
                return ['add' => self::awJ(MpcNetPa::wAdd($x, $y)), 'sub' => self::awJ(MpcNetPa::wSub($x, $y)), 'neg' => self::awJ(MpcNetPa::wNeg($x)),
                    'scale' => self::awJ(MpcNetPa::wScale($x, $c)),
                    'addPublic' => self::awJ(MpcNetPa::wAddPublic(['id' => 1, 'n' => $n, 'delta' => gmp_init(7), 'tagged' => $tg], $x, $c, $alpha)),
                    'addPublic0' => self::awJ(MpcNetPa::wAddPublic(['id' => 0, 'n' => $n, 'delta' => gmp_init(7), 'tagged' => $tg], $x, $c, $alpha))];
            },
            'encodeFrame' => static function (array $a) use ($ob) {
                $f = RefMpcSupport::obj($a[0]);
                return $ob(MpcNetWire::encodeFrame(['v' => $f->get('v'), 'ty' => $f->get('ty'), 'sid' => $f->get('sid'), 'seq' => $f->get('seq'), 'rd' => $f->get('rd'), 'd' => $f->get('d')]));
            },
            'split' => static function (array $a) use ($by, $ob) {
                $sp = new MpcNetFrameSplitter();
                $out = [];
                foreach ($a[0] as $c) {
                    foreach ($sp->push($by($c)) as $fr) {
                        $out[] = $ob($fr);
                    }
                }
                return ['frames' => $out];
            },
            'peekVersion' => static fn(array $a) => MpcNetWire::peekVersion($by($a[0])),
            'parseFrame' => static fn(array $a) => MpcNetWire::parseFrame($by($a[0])),
            'versionMismatch' => static fn(array $a) => MpcNetWire::versionMismatch($by($a[0])),
            'hx' => static fn(array $a) => MpcNetWire::hx($b($a[0])),
            'unhx' => static function (array $a) {
                $v = MpcNetWire::unhx($a[0]);
                return $v === null ? null : gmp_strval($v);
            },
            'unhxArray' => static function (array $a) use ($i, $strs) {
                $r = MpcNetWire::unhxArray($a[0], $i($a[1]));
                return $r === null ? null : $strs($r);
            },
            'netAbort' => static function (array $a) use ($i) {
                $op = $a[6] === null ? null : RefMpcSupport::obj($a[6]);
                $num = static fn(mixed $x): ?int => $x === null ? null : $i($x);
                $e = new MpcNetAbort((string) $a[0], $num($a[1]), $i($a[2]), (string) $a[3], $a[4] === null ? null : (string) $a[4], $a[5] === 'U' ? null : $num($a[5]),
                    $op?->get('reason'), $op?->get('evidence'), $op === null ? null : $num($op->get('deadlineMs')));
                return ['message' => $e->getMessage(), 'name' => 'NetAbort', 'kind' => $e->kind, 'blamed' => $e->blamed, 'reporter' => $e->reporter, 'reason' => $e->reason,
                    'claimedKind' => $e->claimedKind, 'claimedBlame' => $e->claimedBlame, 'evidence' => $e->evidence, 'deadlineMs' => $e->deadlineMs];
            },
            'abortKinds' => static function (array $a) {
                $k = MpcNetWire::ABORT_KINDS;
                sort($k);
                return $k;
            },
            'forensics' => static function (array $a, $c) use ($b, $i, $S, $strs, $sideJ) {
                $name = (string) $c->get('name');
                if (str_starts_with($name, 'forensics/parse/')) {
                    $dd = MpcNetForensics::parseDisclosure($a[0], $i($a[1]), $i($a[2]), $S::ia($a[3]));
                    return ['dd' => array_map(static fn(array $s): array => ['bits' => $s['bits'], 'y' => gmp_strval($s['y']), 'z' => gmp_strval($s['z']),
                        'recv' => $sideJ($s['recv']), 'rho' => $sideJ($s['rho'])], $dd), 'back' => MpcNetForensics::wireDisclosure($dd)];
                }
                if (str_starts_with($name, 'forensics/audit/')) {
                    $all = [];
                    $m = RefMpcSupport::obj($a[0]);
                    foreach ($m->keys() as $k) {
                        $slots = [];
                        foreach ($m->get($k) as $sl) {
                            $so = RefMpcSupport::obj($sl);
                            $side = static function (mixed $l) use ($S, $b, $i): array {
                                $r = [];
                                foreach ($l as $e) {
                                    $r[$i($e[0])] = $S::ba($e[1]);
                                }
                                return $r;
                            };
                            $slots[] = ['bits' => $S::ia($so->get('bits')), 'y' => $b($so->get('y')), 'z' => $b($so->get('z')), 'recv' => $side($so->get('recv')), 'rho' => $side($so->get('rho'))];
                        }
                        $all[(int) $k] = $slots;
                    }
                    if ($a[2] !== null) {
                        unset($all[$i($a[2])]);
                    }
                    $res = MpcNetForensics::auditDisclosures($all, $S::ba($a[1]));
                    return ['selfBad' => $res['selfBad'], 'pairBad' => $res['pairBad'], 'blame' => array_map(static fn(int $me): ?int => MpcNetForensics::blameFrom($me, $res), [0, 1, 2])];
                }
                if (str_starts_with($name, 'forensics/blame/')) {
                    return MpcNetForensics::blameFrom($i($a[0]), ['selfBad' => $S::ia($a[1]), 'pairBad' => array_map($S::ia(...), $a[2])]);
                }
                if (str_starts_with($name, 'forensics/commit')) {
                    return MpcNetForensics::disclosureCommit((string) $a[0], $i($a[1]), $i($a[2]), $i($a[3]), (string) $a[4], $a[5]);
                }
                if ($name === 'forensics/slotsFor') {
                    return MpcNetForensics::slotsFor($i($a[0]));
                }
                throw new \InvalidArgumentException($name);
            },
            'codec' => static function (array $a) use ($b, $i, $by, $ob) {
                switch ($a[0]) {
                    case 'unb64':
                        return $ob(MpcNetCodec::unb64($a[1], $a[2] === null ? -1 : $i($a[2])));
                    case 'b64':
                        return MpcNetCodec::b64($by($a[1]));
                    case 'hexBig':
                        return gmp_strval(MpcNetCodec::hexBig($a[1]));
                    case 'jPt':
                        return MpcNetCodec::ptJ(MpcNetCodec::jPt($a[1]));
                    case 'ptJ':
                        return MpcNetCodec::ptJ(MpcEc::mulBase($b($a[1])));
                    case 'gadgetCommit':
                        return MpcNetCodec::gadgetCommit((string) $a[1], $i($a[2]), $by($a[3]));
                    case 'gadgetStatement':
                        return $ob(MpcNetCodec::gadgetStatement((string) $a[1], (string) $a[2], $i($a[3]), (string) $a[4]));
                    default:
                        throw new \InvalidArgumentException((string) $a[0]);
                }
            },
        ]);
    }
}
