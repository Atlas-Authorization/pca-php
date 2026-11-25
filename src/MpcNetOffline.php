<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares; every party samples its own MAC key
 * shares and triple shares, and the products needed for the triples and MACs are computed by Gilboa OT multiplication between every
 * ordered pair (kappa = 128 base OTs per ordered pair, OT extension with the KOS correlation check). Two multiplication layers
 * (products and the MACs of known values, then the MACs of the products) and a third layer giving every share pairwise tags
 * T_ij = K_ij + Delta_j * x_i, so the online phase can name a party that lies. Receivers choose with the privacy-amplified encoding of
 * their share (selective-failure remedy) under a gadget all parties contribute a signed seed to. The triple sacrifice and the
 * input-consistency check run online. No security proof; a wrong OT operand in the offline triple products is attributable from the
 * OT transcript only after the sacrifice fails (the `forensics` entry of the returned Prep).
 */
final class MpcNetOffline
{
    /** Most OT rows per extension round (bounds frame size and memory). */
    private const ROWS_PER_ROUND = 128 * MpcEnc::FIELD_BITS;

    private MpcNetMesh $mesh;
    private MpcNetExchanger $io;
    private int $id;
    private int $n;
    private string $beh;
    /** @var list<int> */
    private array $others = [];
    private MpcOtRandom $rng;
    private MpcFieldRng $frng;
    private \GMP $delta;
    /** @var list<\GMP> */
    private array $gadget = [];
    private string $sid;
    /** @var array<int,MpcOtExtReceiver> */
    private array $recvCh = [];
    /** @var array<int,MpcOtExtSender> */
    private array $sendCh = [];

    /**
     * Run the offline phase for one party and return its Prep (see MpcNetProtocol).
     *
     * @param array{mesh:MpcNetMesh,id:int,n:int,C:int,keys:int,partners:int,sessionId:string,input:array,Q:int,behavior:?array,io:MpcNetExchanger,crashIf:callable} $a
     * @return array<string,mixed>
     */
    public static function run(array $a): array
    {
        return (new self($a))->go();
    }

    /** @param array<string,mixed> $a */
    private function __construct(private readonly array $a)
    {
        $this->mesh = $a['mesh'];
        $this->io = $a['io'];
        $this->id = $a['id'];
        $this->n = $a['n'];
        $this->beh = (string) ($a['behavior']['kind'] ?? '');
        for ($i = 0; $i < $this->n; $i++) {
            if ($i !== $this->id) {
                $this->others[] = $i;
            }
        }
        $this->rng = MpcOtRandom::secure();
        $this->frng = MpcFieldRng::secure();
        $d = $this->frng->next(); // my pairwise verification key: non-zero and secret
        while (gmp_sign($d) === 0) {
            $d = $this->frng->next();
        }
        $this->delta = $d;
        $this->sid = hash('sha256', 'atlas-pca-mpc/net-session/v2' . Js::utf8($this->mesh->sessionId()), true);
    }

    /** The public gadget: H(all seeds in party order, session) expanded by a hash chain; every party contributed a committed seed. @param list<string> $seeds @return list<\GMP> */
    public static function gadgetFromSeeds(string $sessionId, array $seeds): array
    {
        $seed = hash('sha256', 'atlas-pca-mpc/enc-gadget' . Js::utf8($sessionId) . implode('', $seeds), true);
        $ctr = 0;
        $g = [];
        for ($k = 0; $k < MpcEnc::encBits(MpcEnc::STAT_SEC); $k++) {
            while (true) {
                $v = unpack('P', hash('sha256', $seed . pack('P', $ctr++), true))[1] & ((1 << 61) - 1);
                if ($v !== (1 << 61) - 1) {
                    $g[] = gmp_init($v);
                    break;
                }
            }
        }
        return $g;
    }

    private static function hex128(mixed $s): \GMP
    {
        if (!is_string($s) || preg_match('/\A(?:0|[1-9a-f][0-9a-f]{0,31})\z/', $s) !== 1) {
            throw new \InvalidArgumentException('bad 128-bit value');
        }
        return gmp_init($s, 16);
    }

    private static function obj(mixed $raw, string $what): Obj
    {
        return $raw instanceof Obj ? $raw : throw new \InvalidArgumentException($what);
    }

    /** @param list<array{0:string,1:string}> $ps @return list<list<string>> */
    private static function pairsB64(array $ps): array
    {
        return array_map(static fn(array $p): array => [MpcNetCodec::b64($p[0]), MpcNetCodec::b64($p[1])], $ps);
    }

    /** @return list<array{0:string,1:string}> */
    private static function parsePairs(mixed $raw, int $count, int $len): array
    {
        if (!is_array($raw) || !array_is_list($raw) || count($raw) !== $count) {
            throw new \InvalidArgumentException('bad pair array');
        }
        return array_map(static function (mixed $p) use ($len): array {
            if (!is_array($p) || !array_is_list($p) || count($p) !== 2) {
                throw new \InvalidArgumentException('bad pair');
            }
            return [MpcNetCodec::unb64($p[0], $len), MpcNetCodec::unb64($p[1], $len)];
        }, $raw);
    }

    /** @param array{u:list<\GMP>,x:\GMP,tComb:\GMP} $msg */
    private static function encodeU(array $msg, int $mExt): array
    {
        $cb = intdiv($mExt + 7, 8);
        return ['u' => MpcNetCodec::b64(implode('', array_map(static fn(\GMP $c): string => MpcOtx::bigToBytes($c, $cb), $msg['u']))),
            'x' => gmp_strval($msg['x'], 16), 't' => gmp_strval($msg['tComb'], 16)];
    }

    private static function decodeU(mixed $raw, int $mExt): array
    {
        $o = self::obj($raw, 'bad extension message');
        $cb = intdiv($mExt + 7, 8);
        $bytes = MpcNetCodec::unb64($o->get('u'), MpcOt::KAPPA * $cb);
        $u = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $u[] = MpcOtx::bytesToBig(substr($bytes, $i * $cb, $cb));
        }
        return ['u' => $u, 'x' => self::hex128($o->get('x')), 'tComb' => self::hex128($o->get('t'))];
    }

    /** @param list<\GMP> $y0 @param list<\GMP> $y1 */
    private static function encodeY(array $y0, array $y1): array
    {
        $f = static fn(array $ys): string => MpcNetCodec::b64(implode('', array_map(static fn(\GMP $v): string => MpcOtx::bigToBytes($v, 8), $ys)));
        return ['y0' => $f($y0), 'y1' => $f($y1)];
    }

    /** @return array{y0:list<\GMP>,y1:list<\GMP>} */
    private static function decodeY(mixed $raw, int $m): array
    {
        $o = self::obj($raw, 'bad ciphertext message');
        $f = static function (string $b) use ($m): array {
            $out = [];
            for ($i = 0; $i < $m; $i++) {
                $out[] = MpcOtx::bytesToBig(substr($b, $i * 8, 8));
            }
            return $out;
        };
        return ['y0' => $f(MpcNetCodec::unb64($o->get('y0'), $m * 8)), 'y1' => $f(MpcNetCodec::unb64($o->get('y1'), $m * 8))];
    }

    /** Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is $recv and extension sender is $send. */
    private function chan(int $recv, int $send, string $round): array
    {
        return ['sessionId' => $this->sid, 'senderIndex' => $recv, 'receiverIndex' => $send, 'round' => $round];
    }

    /** Run a check that may throw an OT error, turning it into an abort that names $peer. */
    private function otGuard(int $peer, string $what, callable $f): mixed
    {
        try {
            return $f();
        } catch (MpcNetAbort $e) {
            throw $e;
        } catch (\Throwable $e) {
            $kind = $e instanceof MpcBaseOtAbort || $e instanceof MpcMalOtAbort || $e instanceof MpcPointError ? 'ot-check' : 'malformed';
            $ne = new MpcNetAbort($kind, $peer, $this->id, $what . ': ' . $e->getMessage());
            $this->mesh->fail($ne);
            throw $ne;
        }
    }

    /**
     * The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my item t and get
     * recv[p][t] = x_t*y^p_t + sum rho^p_t; as the OT SENDER towards p I offer (rho_k, rho_k + g_k*y_t) with fresh masks and keep
     * sendSum[p][t] = sum rho. So recv - sendSum over the pair is an additive sharing of x_t*y_t.
     *
     * @param list<array{bits:list<int>,gad:list<\GMP>,y:\GMP}> $items @param array<int,bool> $keep items whose OT transcript is kept
     * @return array{recv:array<int,list<\GMP>>,sendSum:array<int,list<\GMP>>,kept:array{recv:array,rho:array}}
     */
    private function otRows(string $layer, array $items, array $keep = []): array
    {
        $T = count($items);
        $zero = gmp_init(0);
        $recv = [];
        $sendSum = [];
        $kept = ['recv' => [], 'rho' => []];
        foreach ($this->others as $p) {
            $recv[$p] = array_fill(0, $T, $zero);
            $sendSum[$p] = array_fill(0, $T, $zero);
            $kept['recv'][$p] = [];
            $kept['rho'][$p] = [];
        }
        if ($T === 0 || $this->others === []) {
            return ['recv' => $recv, 'sendSum' => $sendSum, 'kept' => $kept];
        }
        $rows = 0;
        foreach ($items as $it) {
            $rows += count($it['bits']);
        }
        $rowItem = [];
        $choice = [];
        $m0 = [];
        $m1 = [];
        foreach ($this->others as $p) {
            $m0[$p] = [];
            $m1[$p] = [];
        }
        $off = 0;
        $itemOff = [];
        foreach ($items as $t => $it) {
            $len = count($it['bits']);
            $itemOff[$t] = $off;
            if (isset($keep[$t])) {
                foreach ($this->others as $p) {
                    $kept['recv'][$p][$t] = array_fill(0, $len, $zero);
                }
            }
            for ($k = 0; $k < $len; $k++) {
                $choice[$off + $k] = $it['bits'][$k];
                $rowItem[$off + $k] = $t;
            }
            foreach ($this->others as $p) {
                $sumRho = $zero;
                for ($k = 0; $k < $len; $k++) {
                    $rho = $this->frng->next();
                    $sumRho = MpcField::fadd($sumRho, $rho);
                    $m0[$p][$off + $k] = $rho;
                    $m1[$p][$off + $k] = MpcField::fadd($rho, MpcField::fmul($it['gad'][$k], $it['y']));
                }
                $sendSum[$p][$t] = $sumRho;
                if (isset($keep[$t])) {
                    $kept['rho'][$p][$t] = array_slice($m0[$p], $off, $len);
                }
            }
            $off += $len;
        }
        $chunk = 0;
        for ($start = 0; $start < $rows; $start += self::ROWS_PER_ROUND, $chunk++) {
            $m = min($rows, $start + self::ROWS_PER_ROUND) - $start;
            $mExt = $m + MpcOt::KAPPA + MpcOt::SSEC;
            $tag = 'ox' . $layer . '.' . $chunk;
            $begun = [];
            if ($this->beh === 'ot-u-lie') {
                // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                foreach ($this->others as $p) {
                    $this->recvCh[$p]->tamperU = static function (array $u): array {
                        for ($i = 0; $i < 64; $i++) {
                            $u[$i] = gmp_xor($u[$i], 1);
                        }
                        return $u;
                    };
                }
            }
            foreach ($this->others as $p) {
                $begun[$p] = $this->recvCh[$p]->begin(array_slice($choice, $start, $m));
            }
            $us = $this->io->exchange($tag . '.u', static fn(int $peer): array => self::encodeU($begun[$peer]['msg'], $mExt), static fn(int $p, mixed $raw): array => self::decodeU($raw, $mExt));
            $ys2 = [];
            foreach ($this->others as $p) {
                $ys2[$p] = $this->otGuard($p, "OT extension ($tag)", fn(): array => $this->sendCh[$p]->respond($us[$p], array_slice($m0[$p], $start, $m), array_slice($m1[$p], $start, $m)));
            }
            $cts = $this->io->exchange($tag . '.y', static fn(int $peer): array => self::encodeY($ys2[$peer]['y0'], $ys2[$peer]['y1']), static fn(int $p, mixed $raw): array => self::decodeY($raw, $m));
            foreach ($this->others as $p) {
                $got = $this->otGuard($p, "OT extension ($tag)", fn(): array => $this->recvCh[$p]->finish($begun[$p]['pending'], $cts[$p]['y0'], $cts[$p]['y1']));
                for ($j = 0; $j < $m; $j++) {
                    $t = $rowItem[$start + $j];
                    $v = MpcField::mod($got[$j]);
                    $recv[$p][$t] = MpcField::fadd($recv[$p][$t], $v);
                    if (isset($keep[$t])) {
                        $kept['recv'][$p][$t][$start + $j - $itemOff[$t]] = $v;
                    }
                }
            }
        }
        return ['recv' => $recv, 'sendSum' => $sendSum, 'kept' => $kept];
    }

    /**
     * Given my shares xs[t] of X_t and ys[t] of Y_t, my additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus,
     * for every ordered pair, the Gilboa OT product of one party's x with the other's y. Neither party learns the other's operand.
     *
     * @param list<array{value:\GMP,bits:list<int>}> $xs @param list<\GMP> $ys @param array<int,bool> $keep
     * @return array{z:list<\GMP>,kept:array}
     */
    private function mulLayer(string $layer, array $xs, array $ys, int $lieAt = -1, array $keep = []): array
    {
        $z = [];
        $items = [];
        foreach ($xs as $t => $x) {
            $z[$t] = MpcField::fmul($x['value'], $ys[$t]);
            $items[$t] = ['bits' => $x['bits'], 'gad' => $this->gadget, 'y' => $t === $lieAt ? MpcField::fadd($ys[$t], gmp_init(1)) : $ys[$t]];
        }
        $r = $this->otRows($layer, $items, $keep);
        foreach ($this->others as $p) {
            foreach ($z as $t => $_) {
                $z[$t] = MpcField::fsub(MpcField::fadd($z[$t], $r['recv'][$p][$t]), $r['sendSum'][$p][$t]);
            }
        }
        return ['z' => $z, 'kept' => $r['kept']];
    }

    /**
     * Pairwise tags for my shares xs: for every peer j, a tag T_ij (mine) and a key K_ji (for verifying j's share of the same item)
     * with T_ij = K_ij + Delta_j*x_i, Delta_j being j's secret verification key. One OT product of my x with j's Delta per item.
     * A tag operand is an arbitrary derived value with no uniform choice-bit encoding of its own, so each x is split as x = e + d with
     * a fresh encoded e and d = x - e; both halves are multiplied with Delta and the results added.
     *
     * @param list<\GMP> $xs @return array{tag:array<int,list<\GMP>>,key:array<int,list<\GMP>>}
     */
    private function tagLayer(string $layer, array $xs): array
    {
        $items = [];
        foreach ($xs as $x) {
            $e = MpcEnc::sampleEnc($this->gadget, $this->frng);
            $d = MpcEnc::plainShare(MpcField::fsub($x, $e['value']));
            $items[] = ['bits' => $e['bits'], 'gad' => $this->gadget, 'y' => $this->delta];
            $items[] = ['bits' => $d['bits'], 'gad' => MpcEnc::plainGadget(), 'y' => $this->delta];
        }
        $r = $this->otRows($layer, $items);
        $tag = [];
        $key = [];
        foreach ($this->others as $p) {
            foreach ($xs as $u => $_) {
                $tag[$p][$u] = MpcField::fadd($r['recv'][$p][2 * $u], $r['recv'][$p][2 * $u + 1]);
                $key[$p][$u] = MpcField::fadd($r['sendSum'][$p][2 * $u], $r['sendSum'][$p][2 * $u + 1]);
            }
        }
        return ['tag' => $tag, 'key' => $key];
    }

    /** @return array{x:\GMP,tag:list<\GMP>,key:list<\GMP>} */
    private function pa(\GMP $x): array
    {
        $z = array_fill(0, $this->n, gmp_init(0));
        return ['x' => $x, 'tag' => $z, 'key' => $z];
    }

    /** @param list<int> $macIdx @param list<\GMP> $z */
    private function aw(\GMP $value, array $macIdx, array $z): array
    {
        return ['v' => $this->pa($value), 'm' => array_map(fn(int $i): array => $this->pa($z[$i]), $macIdx)];
    }

    /** @return array<string,mixed> */
    private function go(): array
    {
        $a = $this->a;
        $mesh = $this->mesh;
        $io = $this->io;
        $id = $this->id;
        $n = $this->n;
        $C = $a['C'];
        $K = $a['keys'];
        $P = $a['partners'];
        $others = $this->others;
        $rng = $this->rng;

        // ------------------------------------------------------------------ base OTs (kappa per ordered pair, both roles)
        $seeds = [];
        $mySetup = [];
        $selector = [];
        foreach ($others as $p) {
            $r = new MpcOtExtReceiver($rng, MpcOt::bindingBytes($this->chan($id, $p, 'iknp-kos')));
            $seeds[$p] = $r->makeSeeds();
            $this->recvCh[$p] = $r;
            $mySetup[$p] = MpcOt::malBaseOtSenderSetup($rng, $this->chan($id, $p, 'offline-kappa'));
            $s = new MpcOtExtSender($rng, MpcOt::bindingBytes($this->chan($p, $id, 'iknp-kos')));
            $selector[$p] = $s->makeSelector();
            $this->sendCh[$p] = $s;
        }
        $lie = $this->beh === 'ot-proof-lie';
        $theirS = $io->exchange('ob-S', static function (int $peer) use ($mySetup, $lie): array {
            $st = $mySetup[$peer];
            return ['S' => MpcNetCodec::ptJ($st['S']), 'U' => MpcNetCodec::ptJ($st['proof']['U']), 'z' => MpcNetWire::hx($lie ? gmp_add($st['proof']['z'], 1) : $st['proof']['z'])];
        }, static function (int $p, mixed $raw): array {
            $o = self::obj($raw, 'bad S message');
            return ['S' => MpcNetCodec::jPt($o->get('S')), 'proof' => ['U' => MpcNetCodec::jPt($o->get('U')), 'z' => MpcNetCodec::hexBig($o->get('z'))]];
        });
        $respond = [];
        foreach ($others as $p) {
            $st = $theirS[$p];
            $respond[$p] = $this->otGuard($p, 'base OT (receiver)', fn(): array => MpcOt::malBaseOtReceiverRespond($st['S'], $st['proof'], $selector[$p], $rng, $this->chan($p, $id, 'offline-kappa')));
        }
        $theirR = $io->exchange('ob-R', static fn(int $peer): array => array_map(MpcNetCodec::ptJ(...), $respond[$peer]['R']), function (int $p, mixed $raw): array {
            if (!is_array($raw) || !array_is_list($raw) || count($raw) !== MpcOt::KAPPA) {
                $this->io->bad($p, 'bad R array');
            }
            return array_map(MpcNetCodec::jPt(...), $raw);
        });
        $enc = [];
        foreach ($others as $p) {
            $st = $mySetup[$p];
            $enc[$p] = $this->otGuard($p, 'base OT (sender)', function () use ($st, $theirR, $p, $id, $seeds): array {
                $pads = MpcOt::malBaseOtSenderDerive($st['y'], $st['T'], $theirR[$p], $st['S'], $this->chan($id, $p, 'offline-kappa'));
                return MpcOt::baseOtSenderEncrypt($seeds[$p], $pads);
            });
        }
        $theirCt = $io->exchange('ob-C', static fn(int $peer): array => ['ct' => self::pairsB64($enc[$peer][0]), 'com' => self::pairsB64($enc[$peer][1])], static function (int $p, mixed $raw): array {
            $o = self::obj($raw, 'bad ciphertext message');
            return ['ct' => self::parsePairs($o->get('ct'), MpcOt::KAPPA, 16), 'com' => self::parsePairs($o->get('com'), MpcOt::KAPPA, 32)];
        });
        foreach ($others as $p) {
            $m = $theirCt[$p];
            $got = $this->otGuard($p, 'base OT (receiver)', fn(): array => MpcOt::baseOtReceiverDecrypt($selector[$p], $respond[$p]['recvPads'], $m['ct'], $m['com']));
            $this->sendCh[$p]->setSeeds($got);
        }

        // ------------------------------------------------------------------ the jointly contributed choice-bit gadget
        // signed commit / reveal / echo: one corrupt party cannot give different honest parties different gadgets
        $agreed = MpcNetGadget::agreeGadgetSeeds($mesh, $n, $io);
        $this->gadget = self::gadgetFromSeeds($mesh->sessionId(), $agreed);
        $gadget = $this->gadget;
        $frng = $this->frng;

        // ------------------------------------------------------------------ my randomness and the input sharings
        $alphaEnc = [];
        for ($l = 0; $l < $K; $l++) {
            $alphaEnc[] = MpcEnc::sampleEnc($gadget, $frng);
        }
        $alphaShare = array_map(static fn(array $e): \GMP => $e['value'], $alphaEnc);
        $in = $a['input'];
        $myBits = array_merge([$in['allow']], MpcThermometer::thermometerEncode((float) $in['t'], MpcNetProtocol::T_M), MpcThermometer::thermometerEncode((float) $in['rQuant'], $a['Q']));
        if (count($myBits) !== $C) {
            throw new MpcNetAbort('local', null, $id, 'input chain count mismatch');
        }
        // split each of my bits into additive shares: a random share for every peer, the rest is mine
        $outShares = [];
        foreach ($others as $p) {
            for ($c = 0; $c < $C; $c++) {
                $outShares[$p][$c] = $frng->next();
            }
        }
        $myOwn = [];
        foreach ($myBits as $c => $b) {
            $s = gmp_init($b);
            foreach ($others as $p) {
                $s = MpcField::fsub($s, $outShares[$p][$c]);
            }
            $myOwn[$c] = $s;
        }
        $gotShares = $io->exchange('in-share', static fn(int $peer): array => array_map(MpcNetWire::hx(...), $outShares[$peer]), function (int $p, mixed $raw) use ($C): array {
            return MpcNetWire::unhxArray($raw, $C) ?? $this->io->bad($p, "expected $C canonical field elements");
        });
        $inputValue = []; // my value share of every (owner, chain)
        for ($o = 0; $o < $n; $o++) {
            for ($c = 0; $c < $C; $c++) {
                $inputValue[] = $o === $id ? $myOwn[$c] : $gotShares[$o][$c];
            }
        }
        $maskShare = $frng->next(); // my share of the input-check mask

        $nT = ($n - 1) * $C;
        $aE = [];
        $bS = [];
        $ahE = [];
        for ($t = 0; $t < $nT; $t++) {
            $aE[$t] = MpcEnc::sampleEnc($gadget, $frng);
            $bS[$t] = $frng->next();
            $ahE[$t] = [];
            for ($r = 0; $r < $P; $r++) {
                $ahE[$t][$r] = MpcEnc::sampleEnc($gadget, $frng);
            }
        }
        $aS = array_map(static fn(array $e): \GMP => $e['value'], $aE);
        $ahS = array_map(static fn(array $row): array => array_map(static fn(array $e): \GMP => $e['value'], $row), $ahE);

        // ------------------------------------------------------------------ layer 1: products and the MACs of known values
        $xs1 = [];
        $ys1 = [];
        $push1 = static function (array $x, \GMP $y) use (&$xs1, &$ys1): int {
            $xs1[] = $x;
            $ys1[] = $y;
            return count($xs1) - 1;
        };
        $iC = [];
        $iCh = [];
        $iMa = [];
        $iMb = [];
        $iMah = [];
        for ($t = 0; $t < $nT; $t++) {
            $iC[$t] = $push1($aE[$t], $bS[$t]);
            $iCh[$t] = [];
            for ($r = 0; $r < $P; $r++) {
                $iCh[$t][$r] = $push1($ahE[$t][$r], $bS[$t]);
            }
            $iMa[$t] = array_map(static fn(array $al): int => $push1($al, $aS[$t]), $alphaEnc);
            $iMb[$t] = array_map(static fn(array $al): int => $push1($al, $bS[$t]), $alphaEnc);
            $iMah[$t] = [];
            for ($r = 0; $r < $P; $r++) {
                $iMah[$t][$r] = array_map(static fn(array $al): int => $push1($al, $ahS[$t][$r]), $alphaEnc);
            }
        }
        $iIn = [];
        foreach ($inputValue as $q => $val) {
            $iIn[$q] = array_map(static fn(array $al): int => $push1($al, $val), $alphaEnc);
        }
        $iMask = array_map(static fn(array $al): int => $push1($al, $maskShare), $alphaEnc);
        $keep = [];
        foreach ($iC as $i) {
            $keep[$i] = true;
        }
        foreach ($iCh as $row) {
            foreach ($row as $i) {
                $keep[$i] = true;
            }
        }
        $l1 = $this->mulLayer('1', $xs1, $ys1, $this->beh === 'offline-lie' && $iC !== [] ? $iC[0] : -1, $keep);
        $z1 = $l1['z'];
        $kept1 = $l1['kept'];

        // ------------------------------------------------------------------ layer 2: the MACs of the products
        $cS = array_map(static fn(int $i): \GMP => $z1[$i], $iC);
        $chS = array_map(static fn(array $row): array => array_map(static fn(int $i): \GMP => $z1[$i], $row), $iCh);
        $xs2 = [];
        $ys2 = [];
        $push2 = static function (array $x, \GMP $y) use (&$xs2, &$ys2): int {
            $xs2[] = $x;
            $ys2[] = $y;
            return count($xs2) - 1;
        };
        $iMc = [];
        $iMch = [];
        for ($t = 0; $t < $nT; $t++) {
            $iMc[$t] = array_map(static fn(array $al): int => $push2($al, $cS[$t]), $alphaEnc);
            $iMch[$t] = array_map(static fn(\GMP $chv): array => array_map(static fn(array $al): int => $push2($al, $chv), $alphaEnc), $chS[$t]);
        }
        $z2 = $this->mulLayer('2', $xs2, $ys2)['z'];

        // ------------------------------------------------------------------ assemble, then pairwise-tag every share
        $triples = [];
        for ($t = 0; $t < $nT; $t++) {
            $sh = [$this->aw($aS[$t], $iMa[$t], $z1), $this->aw($bS[$t], $iMb[$t], $z1), $this->aw($cS[$t], $iMc[$t], $z2)];
            for ($r = 0; $r < $P; $r++) {
                $sh[] = $this->aw($ahS[$t][$r], $iMah[$t][$r], $z1);
                $sh[] = $this->aw($chS[$t][$r], $iMch[$t][$r], $z2);
            }
            if (count($sh) !== MpcNetCodec::sharingsPerTriple($P)) {
                throw new MpcNetAbort('local', null, $id, 'triple assembly mismatch');
            }
            $triples[] = $sh;
        }
        $inputs = [];
        foreach ($inputValue as $q => $val) {
            $inputs[] = $this->aw($val, $iIn[$q], $z1);
        }
        $checkMask = $this->aw($maskShare, $iMask, $z1);
        $alpha = array_map(fn(\GMP $x): array => $this->pa($x), $alphaShare);
        // every PA in one fixed order (alpha, then each AW's value and MAC shares): the tag layer works on that flat list
        $flat = $alpha;
        foreach (array_merge(array_merge(...$triples), $inputs, [$checkMask]) as $w) {
            $flat[] = $w['v'];
            foreach ($w['m'] as $mm) {
                $flat[] = $mm;
            }
        }
        $tags = $this->tagLayer('3', array_map(static fn(array $x): \GMP => $x['x'], $flat));
        $u = 0;
        $apply = function (array $x) use (&$u, $tags, $others): array {
            foreach ($others as $p) {
                $x['tag'][$p] = $tags['tag'][$p][$u];
                $x['key'][$p] = $tags['key'][$p][$u];
            }
            $u++;
            return $x;
        };
        $applyAw = static function (array $w) use ($apply): array {
            $w['v'] = $apply($w['v']);
            foreach ($w['m'] as $k => $mm) {
                $w['m'][$k] = $apply($mm);
            }
            return $w;
        };
        $alpha = array_map($apply, $alpha);
        foreach ($triples as $t => $sh) {
            $triples[$t] = array_map($applyAw, $sh);
        }
        $inputs = array_map($applyAw, $inputs);
        $checkMask = $applyAw($checkMask);

        return ['mode' => 'no-dealer', 'tagged' => true, 'delta' => $this->delta, 'alpha' => $alpha, 'triples' => $triples, 'inputs' => $inputs,
            'myPlain' => array_map(static fn(mixed $b): \GMP => gmp_init($b), $myBits), 'checkMask' => $checkMask,
            'forensics' => ['gadget' => $gadget, 'rows' => count($gadget), 'slots' => 1 + $P,
                'disclose' => static function (int $t) use ($others, $kept1, $bS, $aE, $ahE, $iC, $iCh, $cS, $chS, $P): array {
                    $slot = static function (int $item, array $x, \GMP $z) use ($t, $others, $kept1, $bS): array {
                        $recv = [];
                        $rho = [];
                        foreach ($others as $p) {
                            $recv[$p] = $kept1['recv'][$p][$item];
                            $rho[$p] = $kept1['rho'][$p][$item];
                        }
                        return ['bits' => $x['bits'], 'y' => $bS[$t], 'z' => $z, 'recv' => $recv, 'rho' => $rho];
                    };
                    $out = [$slot($iC[$t], $aE[$t], $cS[$t])];
                    for ($r = 0; $r < $P; $r++) {
                        $out[] = $slot($iCh[$t][$r], $ahE[$t][$r], $chS[$t][$r]);
                    }
                    return $out;
                }]];
    }
}
