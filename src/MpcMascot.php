<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious
 * transfers (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced triple
 * is certified by the sacrifice check. When a check fails the OT transcripts are searched to blame the cheating party.
 *
 * $opts keys (all optional): sacrifice bool, sacrificePartners int, macKeys int, deviation ['productMul' => int, 'delta' => GMP]
 * (TEST-ONLY: the productMul-th product's claimed share is shifted by delta), statSec int, unsafeStatSec bool.
 */
final class MpcMascot implements MpcOfflineProvider
{
    public readonly int $statSec;
    /** @var list<\GMP> */
    public readonly array $alphaShares;
    /** @var list<list<\GMP>> key -> party shares */
    private array $keyShares = [];
    /** @var list<list<array{value:\GMP,bits:list<int>}>> key -> party encoded share */
    private array $keyEnc = [];
    /** @var list<\GMP> */
    private array $gadget;
    private int $sacrificePartners;
    private MpcFieldRng $rng;
    private \GMP $seed;
    private bool $deterministic;
    /** @var array<string,MpcOtChannel> */
    private array $channels = [];
    private bool $sacrificeOn;
    private ?array $deviation;
    private int $productMulCount = 0;
    private ?array $log = null;
    private array $claims = [];

    public function __construct(private readonly int $n, ?\GMP $seed = null, array $opts = [])
    {
        if ($n < 1) {
            throw new \InvalidArgumentException('NoDealerOffline: n must be a positive integer');
        }
        $this->deterministic = $seed !== null;
        $this->seed = $seed ?? gmp_init('abcdef12345', 16);
        $this->rng = $this->deterministic ? new MpcFieldRng($this->seed) : MpcFieldRng::secure();
        $this->sacrificeOn = ($opts['sacrifice'] ?? true) !== false;
        $this->deviation = $opts['deviation'] ?? null;
        $keys = $opts['macKeys'] ?? MpcSpdz::MAC_KEYS;
        if ($keys < 1 || $keys > 16) {
            throw new \InvalidArgumentException('NoDealerOffline: macKeys must be an integer in [1, 16]');
        }
        $this->statSec = $opts['statSec'] ?? MpcEnc::STAT_SEC;
        $this->gadget = MpcEnc::makeGadget($this->statSec, $this->rng, ($opts['unsafeStatSec'] ?? false) === true);
        for ($l = 0; $l < $keys; $l++) {
            $enc = [];
            for ($i = 0; $i < $n; $i++) {
                $enc[$i] = MpcEnc::sampleEnc($this->gadget, $this->rng);
            }
            $this->keyEnc[$l] = $enc;
        }
        foreach ($this->keyEnc as $l => $row) {
            $this->keyShares[$l] = array_map(static fn(array $e): \GMP => $e['value'], $row);
        }
        $this->alphaShares = $this->keyShares[0];
        $this->sacrificePartners = $opts['sacrificePartners'] ?? MpcSpdz::SACRIFICE_PARTNERS;
        if ($this->sacrificePartners < 1 || $this->sacrificePartners > 8) {
            throw new \InvalidArgumentException('NoDealerOffline: sacrificePartners must be an integer in [1, 8]');
        }
    }

    public function n(): int
    {
        return $this->n;
    }

    /** The MAC context: the shares of each key and (for tests and the check only) their sums. */
    public function macContext(): array
    {
        $keys = [];
        foreach ($this->keyShares as $shares) {
            $alpha = gmp_init(0);
            foreach ($shares as $ai) {
                $alpha = MpcField::fadd($alpha, $ai);
            }
            $keys[] = ['alphaShares' => $shares, 'alpha' => $alpha];
        }
        return ['n' => $this->n, 'alphaShares' => $keys[0]['alphaShares'], 'alpha' => $keys[0]['alpha'], 'extraKeys' => array_slice($keys, 1)];
    }

    private function channel(int $i, int $j): MpcOtChannel
    {
        $key = "$i->$j";
        if (!isset($this->channels[$key])) {
            $rng = $this->deterministic
                ? MpcOtRandom::fromSeed(gmp_xor(gmp_xor($this->seed, gmp_mul($i + 1, gmp_init('100000001b3', 16))), gmp_mul($j + 1, gmp_init('1000000000', 16))))
                : MpcOtRandom::secure();
            $this->channels[$key] = new MpcOtChannel($rng);
        }
        return $this->channels[$key];
    }

    /**
     * Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request. A request is
     * ['x' => list<EncShare|GMP>, 'y' => list<GMP>]. Returns z[request][party].
     * @param list<array{x:array,y:list<\GMP>}> $reqs @return list<list<\GMP>>
     */
    private function mulBatch(array $reqs): array
    {
        $n = $this->n;
        foreach ($reqs as $r) {
            if (count($r['x']) !== $n || count($r['y']) !== $n) {
                throw new \InvalidArgumentException('otShareMultiply: wrong length');
            }
        }
        $pieces = [];
        foreach ($reqs as $r) {
            $row = [];
            foreach ($r['x'] as $xi) {
                if (is_array($xi)) {
                    $row[] = ['value' => $xi['value'], 'parts' => [['bits' => $xi['bits'], 'gad' => $this->gadget]]];
                } else {
                    $v = MpcField::mod($xi);
                    $e = MpcEnc::sampleEnc($this->gadget, $this->rng);
                    $d = MpcEnc::plainShare(MpcField::fsub($v, $e['value']));
                    $row[] = ['value' => $v, 'parts' => [['bits' => $e['bits'], 'gad' => $this->gadget], ['bits' => $d['bits'], 'gad' => MpcEnc::plainGadget()]]];
                }
            }
            $pieces[] = $row;
        }
        $z = [];
        foreach ($reqs as $q => $r) {
            for ($i = 0; $i < $n; $i++) {
                $z[$q][$i] = MpcField::fmul($pieces[$q][$i]['value'], $r['y'][$i]);
            }
        }
        for ($i = 0; $i < $n; $i++) {
            for ($j = 0; $j < $n; $j++) {
                if ($i === $j) {
                    continue;
                }
                $bits = [];
                $msg0 = [];
                $msg1 = [];
                $segs = [];
                $at = 0;
                foreach ($reqs as $q => $r) {
                    $y = MpcField::mod($r['y'][$j]);
                    foreach ($pieces[$q][$i]['parts'] as $part) {
                        $len = count($part['bits']);
                        $senderSum = gmp_init(0);
                        for ($k = 0; $k < $len; $k++) {
                            $rho = $this->rng->next();
                            $senderSum = MpcField::fadd($senderSum, $rho);
                            $bits[$at + $k] = $part['bits'][$k];
                            $msg0[$at + $k] = $rho;
                            $msg1[$at + $k] = MpcField::fadd($rho, MpcField::fmul($part['gad'][$k], $y));
                        }
                        $segs[] = ['q' => $q, 'start' => $at, 'len' => $len, 'senderSum' => $senderSum];
                        $at += $len;
                    }
                }
                $received = $this->channel($i, $j)->extend($bits, $msg0, $msg1)['received'];
                if ($this->log !== null) {
                    $this->log[] = ['receiver' => $i, 'sender' => $j, 'msg0' => $msg0, 'msg1' => $msg1, 'received' => $received];
                }
                foreach ($segs as $sg) {
                    $receiverSum = gmp_init(0);
                    for ($k = 0; $k < $sg['len']; $k++) {
                        $receiverSum = MpcField::fadd($receiverSum, MpcField::mod($received[$sg['start'] + $k]));
                    }
                    $z[$sg['q']][$i] = MpcField::fadd($z[$sg['q']][$i], $receiverSum);
                    $z[$sg['q']][$j] = MpcField::fadd($z[$sg['q']][$j], MpcField::fneg($sg['senderSum']));
                }
            }
        }
        return $z;
    }

    /**
     * Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT).
     * @param list<\GMP|array> $x @param list<\GMP> $y @return list<\GMP>
     */
    public function otShareMultiply(array $x, array $y): array
    {
        return $this->mulBatch([['x' => $x, 'y' => $y]])[0];
    }

    /** @return list<array> */
    private function keyReq(int $l): array
    {
        return $this->keyEnc[$l];
    }

    private function authenticate(array $valueShares): array
    {
        $reqs = [];
        foreach (array_keys($this->keyEnc) as $l) {
            $reqs[] = ['x' => $this->keyReq($l), 'y' => $valueShares];
        }
        return $this->toAuth($valueShares, $this->mulBatch($reqs));
    }

    private function toAuth(array $value, array $macs): array
    {
        return ['value' => $value, 'mac' => $macs[0], 'extraMac' => array_slice($macs, 1)];
    }

    private function claimProduct(array $implied): array
    {
        $z = $implied;
        $idx = $this->productMulCount++;
        if ($this->deviation !== null && $this->deviation['productMul'] === $idx) {
            $z[0] = MpcField::fadd($z[0], $this->deviation['delta']);
        }
        $this->claims[] = ['claimed' => $z, 'implied' => $implied];
        return $z;
    }

    private function sampleShare(): array
    {
        return MpcEnc::sampleEnc($this->gadget, $this->rng);
    }

    private static function macOf(array $z, int $start, int $per, int $off, int $K): array
    {
        $out = [];
        for ($l = 0; $l < $K; $l++) {
            $out[$l] = $z[$start + $l * $per + $off];
        }
        return $out;
    }

    /** @return array{keep:array,partners:list<array>} */
    private function rawTripleWithPartners(int $partners): array
    {
        $n = $this->n;
        $K = count($this->keyEnc);
        $aEnc = [];
        for ($i = 0; $i < $n; $i++) {
            $aEnc[$i] = $this->sampleShare();
        }
        $bShares = [];
        for ($i = 0; $i < $n; $i++) {
            $bShares[$i] = $this->rng->next();
        }
        $ahEnc = [];
        for ($r = 0; $r < $partners; $r++) {
            for ($i = 0; $i < $n; $i++) {
                $ahEnc[$r][$i] = $this->sampleShare();
            }
        }
        $aVal = array_map(static fn(array $e): \GMP => $e['value'], $aEnc);
        $ahVal = [];
        for ($r = 0; $r < $partners; $r++) {
            $ahVal[$r] = array_map(static fn(array $e): \GMP => $e['value'], $ahEnc[$r]);
        }
        $reqs = [['x' => $aEnc, 'y' => $bShares]];
        for ($r = 0; $r < $partners; $r++) {
            $reqs[] = ['x' => $ahEnc[$r], 'y' => $bShares];
        }
        $macStart = count($reqs);
        for ($l = 0; $l < $K; $l++) {
            $reqs[] = ['x' => $this->keyReq($l), 'y' => $aVal];
            $reqs[] = ['x' => $this->keyReq($l), 'y' => $bShares];
            for ($r = 0; $r < $partners; $r++) {
                $reqs[] = ['x' => $this->keyReq($l), 'y' => $ahVal[$r]];
            }
        }
        $z1 = $this->mulBatch($reqs);
        $cShares = $this->claimProduct($z1[0]);
        $chShares = [];
        for ($r = 0; $r < $partners; $r++) {
            $chShares[$r] = $this->claimProduct($z1[1 + $r]);
        }
        $per = 2 + $partners;
        $reqs2 = [];
        for ($l = 0; $l < $K; $l++) {
            $reqs2[] = ['x' => $this->keyReq($l), 'y' => $cShares];
            for ($r = 0; $r < $partners; $r++) {
                $reqs2[] = ['x' => $this->keyReq($l), 'y' => $chShares[$r]];
            }
        }
        $z2 = $this->mulBatch($reqs2);
        $per2 = 1 + $partners;
        $b = $this->toAuth($bShares, self::macOf($z1, $macStart, $per, 1, $K));
        $keep = ['a' => $this->toAuth($aVal, self::macOf($z1, $macStart, $per, 0, $K)), 'b' => $b, 'c' => $this->toAuth($cShares, self::macOf($z2, 0, $per2, 0, $K))];
        $parts = [];
        for ($r = 0; $r < $partners; $r++) {
            $parts[] = ['a' => $this->toAuth($ahVal[$r], self::macOf($z1, $macStart, $per, 2 + $r, $K)), 'b' => $b,
                'c' => $this->toAuth($chShares[$r], self::macOf($z2, 0, $per2, 1 + $r, $K))];
        }
        return ['keep' => $keep, 'partners' => $parts];
    }

    private function attribute(MpcMacCheckAbort $abort): MpcOfflineCheatingAbort
    {
        $blamed = [];
        foreach ($this->log ?? [] as $r) {
            foreach ($r['received'] as $k => $recv) {
                $got = MpcField::mod($recv);
                if (gmp_cmp($got, $r['msg0'][$k]) !== 0 && gmp_cmp($got, $r['msg1'][$k]) !== 0) {
                    $blamed[$r['sender']] = true;
                    break;
                }
            }
        }
        foreach ($this->claims as $c) {
            foreach ($c['claimed'] as $i => $v) {
                if (gmp_cmp($v, $c['implied'][$i]) !== 0) {
                    $blamed[$i] = true;
                }
            }
        }
        $ids = array_keys($blamed);
        sort($ids);
        return new MpcOfflineCheatingAbort($abort->getMessage(), $ids);
    }

    /** One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off). */
    public function genAuthTriple(): array
    {
        if (!$this->sacrificeOn) {
            return $this->rawTripleWithPartners(0)['keep'];
        }
        $this->log = [];
        $this->claims = [];
        try {
            $t = $this->rawTripleWithPartners($this->sacrificePartners);
            return MpcSpdz::sacrificeVerify([$t], $this->macContext(), $this->rng, [])[0];
        } catch (MpcMacCheckAbort $e) {
            throw $this->attribute($e);
        } finally {
            $this->log = null;
            $this->claims = [];
        }
    }

    /** @return list<array> */
    public function genAuthTriples(int $count): array
    {
        $out = [];
        for ($k = 0; $k < $count; $k++) {
            $out[] = $this->genAuthTriple();
        }
        return $out;
    }

    /** An authenticated sharing of a value contributed by $owner, MACed by OT under the distributed key. */
    public function authInput(\GMP $value, int $owner): array
    {
        if ($owner < 0 || $owner >= $this->n) {
            throw new \InvalidArgumentException('authInput: owner out of range');
        }
        return $this->authenticate(MpcSharing::share(MpcField::mod($value), $this->n, $this->rng));
    }

    /** Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise). @param list<array> $inputs */
    public function checkInputConsistency(array $inputs): void
    {
        if ($inputs === []) {
            return;
        }
        foreach ($inputs as $inp) {
            if (count($inp['value']) !== $this->n || count($inp['mac']) !== $this->n) {
                throw new \InvalidArgumentException('checkInputConsistency: input party count mismatch');
            }
        }
        $engine = new MpcSpdzEngine($this->macContext(), []);
        $rShares = [];
        for ($i = 0; $i < $this->n; $i++) {
            $rShares[$i] = $this->rng->next();
        }
        $w = $this->authenticate($rShares);
        foreach ($inputs as $inp) {
            $e = $this->rng->next();
            if (gmp_sign($e) === 0) {
                $e = gmp_init(1);
            }
            $w = MpcSpdz::addAuth($w, MpcSpdz::scaleAuth($inp, $e));
        }
        $engine->open($w, 'input-check:w');
        $engine->macCheck($this->rng);
    }

    /** The no-dealer offline provider of $n parties; a non-null seed makes every draw reproducible (tests only). */
    public static function make(int $n, ?\GMP $seed = null, array $opts = []): self
    {
        return new self($n, $seed, $opts);
    }
}
