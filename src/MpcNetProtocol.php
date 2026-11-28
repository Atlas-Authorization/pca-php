<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Thrown by the test-only `silent` behaviour; the host process then idles with its sockets open. */
final class MpcNetSilentParty extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('silent');
    }
}

/** Thrown by the test-only `crash` behaviour; the host closes the node abruptly. */
final class MpcNetCrashParty extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('crash');
    }
}

/**
 * The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol: same circuit and semantics as the in-process runner
 * (allow = AND, t = MAX, r = MAX via thermometers, authenticated Beaver multiplication, batched MAC-check before any output), but each
 * party is its own node holding only its own shares and every opening is a message over the TLS MpcNetMesh. Rounds: prep, coin1-*,
 * sac-rho, sac-tau, inputs (or in-check), mul0.., out, the pairwise tag rounds (the `.t` rounds), coin-c/o, sig-c/o, digest, and on a
 * failed MAC-check a blame round. No output is decoded until the MAC-check and the transcript echo pass.
 *
 * Offline modes: `trusted-dealer` (a separate node that knows every share and key; a dealer that gives a wrong triple is detected by the
 * sacrifice, one that deals inconsistent MACs is named by the blame round) and `no-dealer` (the parties derive everything from OT,
 * see MpcNetOffline). In both modes shares are pairwise-authenticated so an online lie is attributable. There is no security proof; the
 * echo is a hash exchange, not Byzantine agreement; the dealer is trusted for privacy.
 *
 * Records: Prep ['mode','tagged','delta','alpha','triples','inputs','myPlain','checkMask','forensics'] (see MpcNetOffline); a decision
 * vector is ['allow','t','rQuant']; a behavior is ['kind','round'].
 */
final class MpcNetProtocol
{
    public const T_M = 3;
    public const DEFAULT_Q = 100;
    /** Numbers per dealer prep frame (the first frame and each `prep.<c>` follow-up). */
    public const PREP_CHUNK = 30000;

    public static function chainCount(int $Q): int
    {
        return 1 + self::T_M + $Q;
    }

    // ---------------------------------------------------------------------------------------------- dealer

    /** @param list<\GMP> $x @param list<\GMP> $deltas @return list<array> */
    private static function dealPA(array $x, array $deltas, MpcFieldRng $rng): array
    {
        $n = count($x);
        $K = [];
        for ($i = 0; $i < $n; $i++) {
            for ($j = 0; $j < $n; $j++) {
                $K[$i][$j] = $i === $j ? gmp_init(0) : $rng->next();
            }
        }
        $out = [];
        for ($p = 0; $p < $n; $p++) {
            $tag = [];
            $key = [];
            for ($j = 0; $j < $n; $j++) {
                $tag[$j] = $j === $p ? gmp_init(0) : MpcField::fadd($K[$p][$j], MpcField::fmul($deltas[$j], $x[$p]));
                $key[$j] = $j === $p ? gmp_init(0) : $K[$j][$p];
            }
            $out[] = ['x' => $x[$p], 'tag' => $tag, 'key' => $key];
        }
        return $out;
    }

    /** @param list<\GMP> $deltas @return list<array> */
    private static function dealAW(array $sv, array $deltas, MpcFieldRng $rng): array
    {
        $dealt = [];
        foreach (array_merge([$sv['value'], $sv['mac']], $sv['extraMac']) as $c) {
            $dealt[] = self::dealPA($c, $deltas, $rng);
        }
        $out = [];
        for ($p = 0; $p < count($sv['value']); $p++) {
            $m = [];
            for ($l = 1; $l < count($dealt); $l++) {
                $m[] = $dealt[$l][$p];
            }
            $out[] = ['v' => $dealt[0][$p], 'm' => $m];
        }
        return $out;
    }

    /**
     * The TRUSTED DEALER role: samples the MAC keys, verification keys, sacrifice-certified authenticated triples and input masks, and
     * ships each party only its own slice. It never sees an input bit, but it knows every key and share.
     *
     * @param array{n:int,mesh:MpcNetMesh,insecureTrustedDealer?:bool,Q?:int,seed?:?\GMP,fault?:?array,macFaultAtInput?:?int} $cfg
     */
    public static function runDealer(array $cfg): void
    {
        $n = $cfg['n'];
        $mesh = $cfg['mesh'];
        if (($cfg['insecureTrustedDealer'] ?? false) !== true) {
            throw new \InvalidArgumentException('runDealer requires insecureTrustedDealer: true (a dealer sees every share and MAC key; the default offline phase has no dealer)');
        }
        $Q = $cfg['Q'] ?? self::DEFAULT_Q;
        $rng = isset($cfg['seed']) ? new MpcFieldRng($cfg['seed']) : MpcFieldRng::secure();
        $C = self::chainCount($Q);
        $ctx = MpcSpdz::setupMac($n, $rng, MpcSpdz::MAC_KEYS);
        $keys = MpcSpdz::macKeys($ctx);
        $deltas = [];
        for ($i = 0; $i < $n; $i++) {
            $d = $rng->next();
            while (gmp_sign($d) === 0) {
                $d = $rng->next();
            }
            $deltas[] = $d;
        }
        $perParty = [];
        for ($p = 0; $p < $n; $p++) {
            $perParty[$p] = [$deltas[$p]];
        }
        $alphaPA = array_map(static fn(array $k): array => self::dealPA($k['alphaShares'], $deltas, $rng), $keys);
        for ($p = 0; $p < $n; $p++) {
            foreach ($alphaPA as $a) {
                array_push($perParty[$p], ...MpcNetPa::paFlat($a[$p], $p, $n, true));
            }
        }
        $nTriples = ($n - 1) * $C;
        for ($t = 0; $t < $nTriples; $t++) {
            $tr = MpcSpdz::genTripleWithPartners($ctx, $rng, MpcSpdz::SACRIFICE_PARTNERS, $cfg['fault'] ?? null);
            $sharings = [$tr['keep']['a'], $tr['keep']['b'], $tr['keep']['c']];
            foreach ($tr['partners'] as $q) {
                $sharings[] = $q['a'];
                $sharings[] = $q['c'];
            }
            foreach ($sharings as $sv) {
                $aws = self::dealAW($sv, $deltas, $rng);
                for ($p = 0; $p < $n; $p++) {
                    array_push($perParty[$p], ...MpcNetPa::awFlat($aws[$p], $p, $n, true));
                }
            }
        }
        $masks = array_fill(0, $n, []);
        for ($q = 0; $q < $n * $C; $q++) {
            $owner = intdiv($q, $C);
            $r = $rng->next();
            $masks[$owner][] = $r;
            $sv = MpcSpdz::authShare($r, $ctx, $rng);
            if (($cfg['macFaultAtInput'] ?? null) === $q) {
                $sv['mac'][0] = MpcField::fadd($sv['mac'][0], gmp_init(1));
            }
            $aws = self::dealAW($sv, $deltas, $rng);
            for ($p = 0; $p < $n; $p++) {
                array_push($perParty[$p], ...MpcNetPa::awFlat($aws[$p], $p, $n, true));
            }
        }
        for ($p = 0; $p < $n; $p++) {
            array_push($perParty[$p], ...$masks[$p]);
        }
        for ($p = 0; $p < $n; $p++) {
            $nums = array_map(MpcNetWire::hx(...), $perParty[$p]);
            $chunk = self::prepChunk();
            $chunks = max(1, intdiv(count($nums) + $chunk - 1, $chunk));
            $mesh->send($p, 'prep', ['total' => count($nums), 'chunks' => $chunks, 'nums' => array_slice($nums, 0, $chunk)]);
            for ($c = 1; $c < $chunks; $c++) {
                $mesh->send($p, 'prep.' . $c, array_slice($nums, $c * $chunk, $chunk));
            }
        }
        $mesh->finish();
    }

    // ---------------------------------------------------------------------------------------------- party

    /** SHA-256 of the parts, each followed by a zero byte (raw digest). */
    public static function sha(string ...$parts): string
    {
        $h = hash_init('sha256');
        foreach ($parts as $p) {
            hash_update($h, $p);
            hash_update($h, "\0");
        }
        return hash_final($h, true);
    }

    /** Uniform non-zero field element $j of the public challenge stream $label derived from $seed. */
    public static function challenge(string $seed, string $label, int $j): \GMP
    {
        for ($ctr = 0;; $ctr++) {
            $h = self::sha('chal', $seed, $label . ':' . $j . ':' . $ctr);
            $x = unpack('J', $h)[1] & ((1 << 61) - 1);
            if ($x !== 0 && $x !== (1 << 61) - 1) {
                return gmp_init($x);
            }
        }
    }

    /**
     * Run one party. Config: id, n, input, mesh, sessionId; optional Q, dealerId (default n), offline ('no-dealer' default |
     * 'trusted-dealer', which also needs insecureTrustedDealer), behavior + unsafeTestHooks (test-only), forensicDeadlineMs,
     * offlineRunner (callable(array ctx): array prep).
     *
     * @param array<string,mixed> $cfg
     * @return array<string,mixed> the party result (composed decision, rounds, transcript digest, ...)
     */
    public static function runParty(array $cfg): array
    {
        return (new MpcNetPartyRun($cfg))->run();
    }

    /** @internal Test seam: when set, the dealer splits prep into frames of this many numbers instead of PREP_CHUNK. */
    public static ?\Closure $prepChunkHook = null;

    private static function prepChunk(): int
    {
        return self::$prepChunkHook !== null ? (self::$prepChunkHook)() : self::PREP_CHUNK;
    }
}

/** One party's run of the online protocol (state of a single runParty call). */
final class MpcNetPartyRun implements MpcNetExchanger
{
    private int $id;
    private int $n;
    private int $Q;
    private int $dealerId;
    private int $C;
    private int $K;
    private int $P;
    private MpcNetMesh $mesh;
    private string $sessionId;
    private string $offlineMode;
    private ?array $beh;
    private float $t0;
    /** @var list<array{rd:string,ms:float,bytesOut:int,bytesIn:int}> */
    private array $rounds = [];
    private string $transcript = '';
    /** @var list<int> */
    private array $others = [];
    /** @var list<array{val:\GMP,mac:list<array>}> */
    private array $opened = [];
    private array $prep = [];
    private array $env = [];
    /** @var list<\GMP> */
    private array $masked = [];
    /** @var array<int,list<\GMP>> */
    private array $gotMasked = [];

    /** @param array<string,mixed> $cfg */
    public function __construct(private readonly array $cfg)
    {
        $this->id = $cfg['id'];
        $this->n = $cfg['n'];
        $this->mesh = $cfg['mesh'];
        $this->sessionId = $cfg['sessionId'];
        $this->Q = $cfg['Q'] ?? MpcNetProtocol::DEFAULT_Q;
        $this->dealerId = $cfg['dealerId'] ?? $this->n;
        $this->offlineMode = $cfg['offline'] ?? 'no-dealer';
        $this->C = MpcNetProtocol::chainCount($this->Q);
        $this->K = MpcSpdz::MAC_KEYS;
        $this->P = MpcSpdz::SACRIFICE_PARTNERS;
        $this->beh = $cfg['behavior'] ?? null;
        $this->t0 = microtime(true);
        for ($i = 0; $i < $this->n; $i++) {
            if ($i !== $this->id) {
                $this->others[] = $i;
            }
        }
    }

    /** @return array{0:int,1:int} bytes out, bytes in over every link */
    private function totals(): array
    {
        $o = 0;
        $i = 0;
        foreach ($this->mesh->stats() as $s) {
            $o += $s['appBytesOut'];
            $i += $s['appBytesIn'];
        }
        return [$o, $i];
    }

    public function crashIf(string $rd): void
    {
        if ($this->beh !== null && ($this->beh['round'] ?? null) === $rd) {
            if ($this->beh['kind'] === 'crash') {
                throw new MpcNetCrashParty();
            }
            if ($this->beh['kind'] === 'silent') {
                throw new MpcNetSilentParty();
            }
        }
    }

    private function at(string $kind, string $rd): bool
    {
        return $this->beh !== null && $this->beh['kind'] === $kind && ($this->beh['round'] ?? null) === $rd;
    }

    public function bad(int $p, string $what): never
    {
        throw new MpcNetAbort('malformed', $p, $this->id, $what);
    }

    private function abort(MpcNetAbort $e): MpcNetAbort
    {
        $this->mesh->fail($e);
        return $e;
    }

    /** @return list<\GMP> */
    private function arr(int $p, mixed $raw, int $len): array
    {
        return MpcNetWire::unhxArray($raw, $len) ?? $this->bad($p, "expected $len canonical field elements");
    }

    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array
    {
        return $this->xchg($rd, $mine, $parse, null, false, $timeoutMs);
    }

    /** One all-to-all round; $hashed = false keeps a round (peer-specific tags, forensics) out of the echoed transcript. */
    private function xchg(string $rd, callable $mine, callable $parse, mixed $common, bool $hashed, ?int $timeoutMs): array
    {
        $this->crashIf($rd);
        $a = $this->totals();
        $s = microtime(true);
        foreach ($this->others as $p) {
            $this->mesh->send($p, $rd, $mine($p));
        }
        $raw = $this->mesh->collect($rd, $this->others, $timeoutMs);
        $parsed = [];
        foreach ($this->others as $p) {
            try {
                $parsed[$p] = $parse($p, $raw[$p]);
            } catch (MpcNetAbort $e) {
                $this->mesh->fail($e);
                throw $e;
            } catch (\Throwable $e) {
                $ne = new MpcNetAbort('malformed', $p, $this->id, "round '$rd': " . $e->getMessage());
                $this->mesh->fail($ne);
                throw $ne;
            }
        }
        if ($hashed) {
            // transcript: party order, canonical JSON of what each party broadcast in this round
            $this->transcript .= $rd;
            for ($p = 0; $p < $this->n; $p++) {
                $this->transcript .= '|' . $p . ':' . MpcNetWire::stringify($p === $this->id ? $common : $raw[$p]);
            }
        }
        $b = $this->totals();
        $this->rounds[] = ['rd' => $rd, 'ms' => (microtime(true) - $s) * 1000, 'bytesOut' => $b[0] - $a[0], 'bytesIn' => $b[1] - $a[1]];
        return $parsed;
    }

    // ---- trusted-dealer prep ----

    private function intOf(mixed $o): ?int
    {
        if (!$o instanceof Num) {
            return null;
        }
        $d = $o->float();
        return $d === floor($d) && abs($d) < 1e9 ? (int) $d : null;
    }

    /** @return list<\GMP> */
    private function take(mixed $raw, int $len): array
    {
        return MpcNetWire::unhxArray($raw, $len) ?? $this->bad($this->dealerId, 'bad prep numbers');
    }

    private function receiveDealerPrep(): array
    {
        $n = $this->n;
        $K = $this->K;
        $P = $this->P;
        $aw = MpcNetPa::awWidth($n, $K, true);
        $triplesN = ($n - 1) * $this->C;
        $inputsN = $n * $this->C;
        $spt = MpcNetCodec::sharingsPerTriple($P);
        $total = 1 + $K * MpcNetPa::paWidth($n, true) + $triplesN * $spt * $aw + $inputsN * $aw + $this->C;
        $chunkN = MpcNetProtocol::PREP_CHUNK;
        $first = $this->mesh->recv($this->dealerId, 'prep');
        try {
            if (!$first instanceof Obj || $this->intOf($first->get('total')) !== $total) {
                $this->bad($this->dealerId, 'bad prep size');
            }
            $chunks = $this->intOf($first->get('chunks'));
            if ($chunks !== max(1, intdiv($total + $chunkN - 1, $chunkN))) {
                $this->bad($this->dealerId, 'bad prep chunk count');
            }
            $nums = $this->take($first->get('nums'), min($chunkN, $total));
            for ($c = 1; $c < $chunks; $c++) {
                $part = $this->mesh->recv($this->dealerId, 'prep.' . $c);
                array_push($nums, ...$this->take($part, min($chunkN, $total - $c * $chunkN)));
            }
        } catch (MpcNetAbort $e) {
            throw $this->abort($e);
        } catch (\Throwable $e) {
            throw $this->abort(new MpcNetAbort('malformed', $this->dealerId, $this->id, $e->getMessage()));
        }
        $o = 0;
        $delta = $nums[$o++];
        if (gmp_sign($delta) === 0) {
            throw $this->abort(new MpcNetAbort('dealer', $this->dealerId, $this->id, 'the dealer gave me a zero verification key'));
        }
        $w = MpcNetPa::paWidth($n, true);
        $alpha = [];
        for ($l = 0; $l < $K; $l++) {
            $alpha[] = MpcNetPa::paParse($nums, $o, $this->id, $n, true);
            $o += $w;
        }
        $triples = [];
        for ($t = 0; $t < $triplesN; $t++) {
            $sh = [];
            for ($s = 0; $s < $spt; $s++) {
                $sh[] = MpcNetPa::awParse($nums, $o, $this->id, $n, $K, true);
                $o += $aw;
            }
            $triples[] = $sh;
        }
        $inputs = [];
        for ($q = 0; $q < $inputsN; $q++) {
            $inputs[] = MpcNetPa::awParse($nums, $o, $this->id, $n, $K, true);
            $o += $aw;
        }
        return ['mode' => 'trusted-dealer', 'tagged' => true, 'delta' => $delta, 'alpha' => $alpha, 'triples' => $triples, 'inputs' => $inputs,
            'myPlain' => array_slice($nums, $o, $this->C), 'checkMask' => null, 'forensics' => null];
    }

    private function addPub(array $x, \GMP $c): array
    {
        return MpcNetPa::wAddPublic($this->env, $x, $c, $this->prep['alpha']);
    }

    private function not(array $x): array
    {
        return $this->addPub(MpcNetPa::wNeg($x), gmp_init(1));
    }

    /**
     * Open authenticated values: broadcast value shares, verify pairwise tags, record for the MAC-check.
     * @param list<array> $ws @return list<\GMP>
     */
    private function openMany(string $rd, array $ws): array
    {
        $cnt = count($ws);
        $sendVals = [];
        $macs = [];
        foreach ($ws as $i => $x) {
            $sendVals[$i] = $x['v']['x'];
            $macs[$i] = $x['m'];
        }
        if ($this->beh !== null && ($this->beh['round'] ?? null) === $rd) {
            if ($this->beh['kind'] === 'open-lie') {
                $sendVals[0] = MpcField::fadd($sendVals[0], gmp_init(1));
            }
            if ($this->beh['kind'] === 'mac-lie') {
                $macs[0][0]['x'] = MpcField::fadd($macs[0][0]['x'], gmp_init(1));
            }
        }
        $common = array_map(MpcNetWire::hx(...), $sendVals);
        $mineFn = function (int $peer) use ($rd, $common): array {
            if ($this->at('equivocate', $rd) && $peer === $this->others[0]) {
                $c = $common;
                $c[0] = MpcNetWire::hx(MpcField::fadd(gmp_init($common[0], 16), gmp_init(1)));
                return $c;
            }
            if ($this->at('short-array', $rd)) {
                return array_slice($common, 1);
            }
            if ($this->at('noncanonical', $rd)) {
                $c = $common;
                $c[0] = MpcNetWire::hx(MpcField::prime());
                return $c;
            }
            return $common;
        };
        $got = $this->xchg($rd, $mineFn, fn(int $p, mixed $raw): array => $this->arr($p, $raw, $cnt), $common, true, null);
        if ($this->prep['tagged']) {
            // pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
            $tagMsg = function (int $peer) use ($ws, $rd): array {
                $t = [];
                foreach ($ws as $i => $x) {
                    $tag = $x['v']['tag'][$peer];
                    $t[] = MpcNetWire::hx($this->at('bad-tag', $rd) && $i === 0 ? MpcField::fadd($tag, gmp_init(1)) : $tag);
                }
                return $t;
            };
            $tags = $this->xchg($rd . '.t', $tagMsg, fn(int $p, mixed $raw): array => $this->arr($p, $raw, $cnt), null, false, null);
            foreach ($this->others as $p) {
                foreach ($ws as $i => $x) {
                    if (!MpcNetPa::paVerify($this->env, $x['v'], $p, $got[$p][$i], $tags[$p][$i])) {
                        throw $this->abort(new MpcNetAbort('mac-check', $p, $this->id,
                            "pairwise MAC on party $p's opened share failed in round '$rd' (index $i): the share or its tag is not what the dealer issued"));
                    }
                }
            }
        }
        $out = [];
        foreach ($ws as $i => $_) {
            $sum = $sendVals[$i];
            foreach ($this->others as $p) {
                $sum = MpcField::fadd($sum, $got[$p][$i]);
            }
            $out[] = $sum;
            $this->opened[] = ['val' => $sum, 'mac' => $macs[$i]];
        }
        return $out;
    }

    /** Commit / open of a random seed, giving a joint public seed (raw 32 bytes). */
    private function coin(string $label, bool $tamperOpen): string
    {
        $mySeed = random_bytes(32);
        $seedCommit = bin2hex(MpcNetProtocol::sha('seed', $this->sessionId, $label, (string) $this->id, $mySeed));
        $isHex = static fn(mixed $x): bool => is_string($x) && preg_match('/\A[0-9a-f]{64}\z/', $x) === 1;
        $seedCommits = $this->xchg($label . '-c', static fn(int $p): string => $seedCommit, function (int $p, mixed $raw) use ($isHex): string {
            return $isHex($raw) ? $raw : $this->bad($p, 'bad commitment');
        }, $seedCommit, true, null);
        $openMsg = function (int $p) use ($tamperOpen, $mySeed): string {
            if ($tamperOpen && $this->beh !== null && $this->beh['kind'] === 'bad-coin-open') {
                return bin2hex(random_bytes(32));
            }
            return bin2hex($mySeed);
        };
        $seeds = $this->xchg($label . '-o', $openMsg, function (int $p, mixed $raw) use ($isHex, $label, $seedCommits): string {
            if (!$isHex($raw)) {
                $this->bad($p, 'bad seed');
            }
            $sd = (string) hex2bin($raw);
            if (bin2hex(MpcNetProtocol::sha('seed', $this->sessionId, $label, (string) $p, $sd)) !== $seedCommits[$p]) {
                throw new MpcNetAbort('commitment', $p, $this->id, "party $p opened a coin seed that does not match its commitment");
            }
            return $sd;
        }, bin2hex($mySeed), true, null);
        $parts = ['joint', $this->sessionId, $label];
        for ($p = 0; $p < $this->n; $p++) {
            $parts[] = $p === $this->id ? $mySeed : $seeds[$p];
        }
        return MpcNetProtocol::sha(...$parts);
    }

    /** @param list<\GMP> $s */
    private function sigCommit(int $p, array $s, string $nonce): string
    {
        return bin2hex(MpcNetProtocol::sha('sigma', $this->sessionId, (string) $p, implode(',', array_map(MpcNetWire::hx(...), $s)), $nonce));
    }

    private static function bitOf(\GMP $x): int
    {
        return gmp_cmp($x, 1) === 0 ? 1 : 0;
    }

    private function bitShare(int $owner, int $k): array
    {
        if ($this->prep['mode'] === 'trusted-dealer') {
            $pub = $owner === $this->id ? $this->masked[$k] : $this->gotMasked[$owner][$k];
            return $this->addPub($this->prep['inputs'][$owner * $this->C + $k], $pub);
        }
        return $this->prep['inputs'][$owner * $this->C + $k];
    }

    /** @return array<string,mixed> */
    public function run(): array
    {
        $cfg = $this->cfg;
        $id = $this->id;
        $n = $this->n;
        $Q = $this->Q;
        $C = $this->C;
        $K = $this->K;
        $P = $this->P;
        if ($this->offlineMode === 'trusted-dealer' && ($cfg['insecureTrustedDealer'] ?? false) !== true) {
            throw new MpcNetAbort('local', null, $id, "offline 'trusted-dealer' requires insecureTrustedDealer: true (the dealer sees every share and key); the default is 'no-dealer'");
        }
        if ($this->offlineMode !== 'trusted-dealer' && $this->offlineMode !== 'no-dealer') {
            throw new MpcNetAbort('local', null, $id, 'unknown offline mode');
        }
        if ($this->beh !== null && ($cfg['unsafeTestHooks'] ?? false) !== true) {
            throw new MpcNetAbort('local', null, $id, 'the behavior test hook requires unsafeTestHooks: true (test-only)');
        }
        if ($n < 1) {
            throw new MpcNetAbort('local', null, $id, 'n must be >= 1');
        }
        $v = $cfg['input'] ?? null;
        if (!is_array($v) || !in_array($v['allow'] ?? null, [0, 1], true) || !in_array($v['t'] ?? null, [1, 2, 3], true)
            || !is_int($v['rQuant'] ?? null) || $v['rQuant'] < 0 || $v['rQuant'] > $Q) {
            throw new MpcNetAbort('local', null, $id, 'invalid decision vector');
        }

        // ---- offline phase ----
        $this->crashIf('prep');
        $prepStart = microtime(true);
        $before = $this->totals();
        if ($this->offlineMode === 'trusted-dealer') {
            $this->prep = $this->receiveDealerPrep();
        } else {
            $runner = $cfg['offlineRunner'] ?? MpcNetOffline::run(...);
            $this->prep = $runner(['mesh' => $this->mesh, 'id' => $id, 'n' => $n, 'C' => $C, 'keys' => $K, 'partners' => $P, 'sessionId' => $this->sessionId,
                'input' => $v, 'Q' => $Q, 'behavior' => $this->beh, 'io' => $this, 'crashIf' => $this->crashIf(...)]);
        }
        $after = $this->totals();
        $this->rounds[] = ['rd' => 'prep', 'ms' => (microtime(true) - $prepStart) * 1000, 'bytesOut' => $after[0] - $before[0], 'bytesIn' => $after[1] - $before[1]];
        $this->env = ['id' => $id, 'n' => $n, 'delta' => $this->prep['delta'], 'tagged' => $this->prep['tagged']];

        // ---- sacrifice: certify every triple against its partners before it is used ----
        $nT = count($this->prep['triples']);
        if ($nT > 0) {
            $this->sacrifice($nT);
        }

        // ---- inputs ----
        $therm = MpcThermometer::thermometerEncode((float) $v['t'], MpcNetProtocol::T_M);
        $rtherm = MpcThermometer::thermometerEncode((float) $v['rQuant'], $Q);
        $myBits = [gmp_init($v['allow'])];
        foreach ($therm as $b) {
            $myBits[] = gmp_init($b);
        }
        foreach ($rtherm as $b) {
            $myBits[] = gmp_init($b);
        }
        if ($this->prep['mode'] === 'trusted-dealer') {
            $this->masked = [];
            $maskedMsg = [];
            for ($k = 0; $k < $C; $k++) {
                $this->masked[$k] = MpcField::fsub($myBits[$k], $this->prep['myPlain'][$k]);
                $maskedMsg[] = MpcNetWire::hx($this->masked[$k]);
            }
            $this->gotMasked = $this->xchg('inputs', static fn(int $p): array => $maskedMsg, fn(int $p, mixed $raw): array => $this->arr($p, $raw, $C), $maskedMsg, true, null);
        } else {
            // No-dealer: inputs are already authenticated sharings; the input-consistency check joins the batched MAC-check.
            $jointIn = $this->coin('coin-in', false);
            $w = $this->prep['checkMask'];
            for ($q = 0; $q < $n * $C; $q++) {
                $w = MpcNetPa::wAdd($w, MpcNetPa::wScale($this->prep['inputs'][$q], MpcNetProtocol::challenge($jointIn, 'in', $q)));
            }
            $this->openMany('in-check', [$w]);
        }

        // ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
        $acc = [];
        for ($c = 0; $c < $C; $c++) {
            $b0 = $this->bitShare(0, $c);
            $acc[$c] = $c !== 0 ? $this->not($b0) : $b0;
        }
        $mults = 0;
        for ($s = 1; $s < $n; $s++) {
            $trs = [];
            for ($c = 0; $c < $C; $c++) {
                $trs[$c] = $this->prep['triples'][($s - 1) * $C + $c];
            }
            $ds = [];
            $es = [];
            for ($c = 0; $c < $C; $c++) {
                $b = $this->bitShare($s, $c);
                $y = $c !== 0 ? $this->not($b) : $b;
                $ds[$c] = MpcNetPa::wSub($acc[$c], $trs[$c][0]);
                $es[$c] = MpcNetPa::wSub($y, $trs[$c][1]);
            }
            $pub = $this->openMany('mul' . ($s - 1), array_merge($ds, $es));
            $next = [];
            for ($c = 0; $c < $C; $c++) {
                $d = $pub[$c];
                $e = $pub[$C + $c];
                $z = MpcNetPa::wAdd($trs[$c][2], MpcNetPa::wAdd(MpcNetPa::wScale($trs[$c][1], $d), MpcNetPa::wScale($trs[$c][0], $e)));
                $next[$c] = $this->addPub($z, MpcField::fmul($d, $e));
            }
            $acc = $next;
            $mults += $C;
        }

        // ---- outputs: allow as-is; or-chains are NOT of the product ----
        $outShares = [];
        for ($c = 0; $c < $C; $c++) {
            $outShares[$c] = $c !== 0 ? $this->not($acc[$c]) : $acc[$c];
        }
        $outVals = $this->openMany('out', $outShares);

        // ---- MAC-check ----
        $joint = $this->coin('coin', true);
        $aPub = [];
        $Gamma = [];
        $sigma = [];
        for ($l = 0; $l < $K; $l++) {
            $a = gmp_init(0);
            $g = gmp_init(0);
            foreach ($this->opened as $j => $o) {
                $ch = MpcNetProtocol::challenge($joint, 'mac' . $l, $j);
                $a = MpcField::fadd($a, MpcField::fmul($ch, $o['val']));
                $g = MpcField::fadd($g, MpcField::fmul($ch, $o['mac'][$l]['x']));
            }
            $aPub[$l] = $a;
            $Gamma[$l] = $g;
            $sigma[$l] = MpcField::fsub($g, MpcField::fmul($this->prep['alpha'][$l]['x'], $a));
        }
        $sigNonce = random_bytes(32);
        $sigmaSent = $sigma;
        if ($this->beh !== null && $this->beh['kind'] === 'sigma-lie') {
            $sigmaSent[0] = MpcField::fadd($sigmaSent[0], gmp_init(1));
        }
        $isHex = static fn(mixed $x): bool => is_string($x) && preg_match('/\A[0-9a-f]{64}\z/', $x) === 1;
        $mySigCommit = $this->sigCommit($id, $sigmaSent, $sigNonce);
        $sigCommits = $this->xchg('sig-c', static fn(int $p): string => $mySigCommit, function (int $p, mixed $raw) use ($isHex): string {
            return $isHex($raw) ? $raw : $this->bad($p, 'bad commitment');
        }, $mySigCommit, true, null);
        $mySigOpen = ['s' => array_map(MpcNetWire::hx(...), $sigmaSent), 'nonce' => bin2hex($sigNonce)];
        $sigOpens = $this->xchg('sig-o', function (int $p) use ($sigmaSent, $mySigOpen): array {
            if ($this->beh !== null && $this->beh['kind'] === 'bad-sigma-open') {
                $s2 = $sigmaSent;
                $s2[0] = MpcField::fadd($s2[0], gmp_init(1));
                return ['s' => array_map(MpcNetWire::hx(...), $s2), 'nonce' => $mySigOpen['nonce']];
            }
            return $mySigOpen;
        }, function (int $p, mixed $raw) use ($K, $isHex, $sigCommits): array {
            $o = $raw instanceof Obj ? $raw : null;
            $sv = $o === null ? null : MpcNetWire::unhxArray($o->get('s'), $K);
            if ($sv === null || !$isHex($o->get('nonce'))) {
                $this->bad($p, 'bad sigma opening');
            }
            if (!hash_equals($sigCommits[$p], $this->sigCommit($p, $sv, (string) hex2bin($o->get('nonce'))))) {
                throw new MpcNetAbort('commitment', $p, $this->id, "party $p opened a MAC residual that does not match its commitment");
            }
            return $sv;
        }, $mySigOpen, true, null);
        $macFailed = false;
        for ($l = 0; $l < $K; $l++) {
            $r = $sigmaSent[$l];
            foreach ($this->others as $p) {
                $r = MpcField::fadd($r, $sigOpens[$p][$l]);
            }
            if (gmp_sign($r) !== 0) {
                $macFailed = true;
            }
        }

        // ---- transcript echo: everyone must have seen the same broadcasts ----
        $digest = hash('sha256', $this->transcript);
        $digests = $this->xchg('digest', static fn(int $p): string => $digest, function (int $p, mixed $raw) use ($isHex): string {
            return $isHex($raw) ? $raw : $this->bad($p, 'bad digest');
        }, $digest, true, null);
        foreach ($this->others as $p) {
            if ($digest !== $digests[$p]) {
                throw $this->abort(new MpcNetAbort('equivocation', $p, $id, "transcript digest of party $p differs from mine (a broadcast was inconsistent)"));
            }
        }

        if ($macFailed) {
            $this->blame($aPub, $Gamma, $sigOpens, $joint);
        }

        // ---- only now decode ----
        $tBits = [];
        for ($i = 0; $i < MpcNetProtocol::T_M; $i++) {
            $tBits[] = self::bitOf($outVals[1 + $i]);
        }
        $rBits = [];
        for ($i = 0; $i < $Q; $i++) {
            $rBits[] = self::bitOf($outVals[1 + MpcNetProtocol::T_M + $i]);
        }
        $composed = ['allow' => self::bitOf($outVals[0]), 't' => min(3, max(1, MpcThermometer::thermometerDecode($tBits))), 'rQuant' => MpcThermometer::thermometerDecode($rBits)];
        $this->mesh->finish();
        return ['id' => $id, 'n' => $n, 'Q' => $Q, 'composed' => $composed, 'rounds' => $this->rounds, 'transcriptDigest' => $digest,
            'wallMs' => (microtime(true) - $this->t0) * 1000, 'multiplications' => $mults, 'opens' => count($this->opened), 'offlineMode' => $this->prep['mode'],
            'macKeys' => $K, 'sacrificedTriples' => $nT, 'sacrificePartners' => $P, 'identifiableAbort' => $this->prep['tagged']];
    }

    private function sacrifice(int $nT): void
    {
        $P = $this->P;
        $id = $this->id;
        $joint1 = $this->coin('coin1', false);
        // a peer that detects the failed sacrifice sends its tau share and disclosures and then its abort claim back to back; the claim is read in link order, after every frame that peer sent before it, so this party finishes its OWN verified detection instead of reporting the peer's unverified accusation
        $this->mesh->setDeferAborts(true);
        $rhoW = [];
        for ($t = 0; $t < $nT; $t++) {
            $tr = $this->prep['triples'][$t];
            for ($r = 0; $r < $P; $r++) {
                $e = MpcNetProtocol::challenge($joint1, 'sac', $t * $P + $r);
                $rhoW[$t * $P + $r] = MpcNetPa::wSub(MpcNetPa::wScale($tr[0], $e), $tr[3 + 2 * $r]);
            }
        }
        $rho = $this->openMany('sac-rho', $rhoW);
        $tauW = [];
        for ($t = 0; $t < $nT; $t++) {
            $tr = $this->prep['triples'][$t];
            for ($r = 0; $r < $P; $r++) {
                $e = MpcNetProtocol::challenge($joint1, 'sac', $t * $P + $r);
                $tauW[$t * $P + $r] = MpcNetPa::wSub(MpcNetPa::wSub(MpcNetPa::wScale($tr[2], $e), $tr[3 + 2 * $r + 1]), MpcNetPa::wScale($tr[1], $rho[$t * $P + $r]));
            }
        }
        $tau = $this->openMany('sac-tau', $tauW);
        $badAt = -1;
        foreach ($tau as $i => $x) {
            if (gmp_sign($x) !== 0) {
                $badAt = $i;
                break;
            }
        }
        if ($badAt < 0) {
            $this->mesh->setDeferAborts(false);
            return;
        }
        // Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a wrong operand.
        $attributed = null;
        $note = '';
        $fx = $this->prep['mode'] === 'no-dealer' ? $this->prep['forensics'] : null;
        if ($fx !== null) {
            $bt = intdiv($badAt, $P);
            $mine = ($fx['disclose'])($bt);
            // commit first, open only once every commitment is in hand; a late or absent party times out at the shared deadline
            $deadline = $this->cfg['forensicDeadlineMs'] ?? MpcNetForensics::DEFAULT_FORENSIC_DEADLINE_MS;
            // A party that finishes the audit first aborts, and its abort frame follows its disclosure on the same link: read in link order,
            // so a slower party still collecting that disclosure is not pre-empted by a peer-abort that hides what it would have named.
            $this->mesh->setDeferAborts(true);
            try {
                $got = MpcNetForensics::exchangeDisclosures($this->sessionId, $id, $this->n, $bt, $mine, $fx['slots'], $fx['rows'], $deadline, $this);
            } finally {
                $this->mesh->setDeferAborts(false);
            }
            $all = $got;
            $all[$id] = $mine;
            ksort($all);
            $res = MpcNetForensics::auditDisclosures($all, $fx['gadget']);
            $attributed = MpcNetForensics::blameFrom($id, $res);
            $note = $attributed === null
                ? ' (OT transcript audit: ' . count($res['pairBad']) . ' inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)'
                : " (OT transcript audit names party $attributed)";
        }
        $dealer = $this->prep['mode'] === 'trusted-dealer';
        $blamed = $dealer ? $this->dealerId : ($attributed ?? ($this->n === 2 ? 1 - $id : null));
        throw $this->abort(new MpcNetAbort($dealer ? 'dealer' : 'mac-check', $blamed, $id,
            'triple sacrifice FAILED at triple ' . intdiv($badAt, $P) . ' (partner ' . ($badAt % $P) . '): c != a*b in the offline material; aborting with no output' . $note,
            null, null, "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted as evidence)"));
    }

    /**
     * @param list<\GMP> $aPub @param list<\GMP> $Gamma @param array<int,list<\GMP>> $sigOpens
     */
    private function blame(array $aPub, array $Gamma, array $sigOpens, string $joint): never
    {
        $id = $this->id;
        $K = $this->K;
        $msg = 'MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output';
        if (!$this->prep['tagged']) {
            throw $this->abort(new MpcNetAbort('mac-check', $this->n === 2 ? 1 - $id : null, $id, $msg, null, null,
                'this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)'));
        }
        // every party opens its combined MAC shares with their pairwise tags; each verifier checks them
        $blameMsg = function (int $peer) use ($K, $joint, $Gamma): array {
            $gt = [];
            $a = [];
            $at = [];
            for ($l = 0; $l < $K; $l++) {
                $g = gmp_init(0);
                foreach ($this->opened as $j => $o) {
                    $g = MpcField::fadd($g, MpcField::fmul(MpcNetProtocol::challenge($joint, 'mac' . $l, $j), $o['mac'][$l]['tag'][$peer]));
                }
                $gt[] = MpcNetWire::hx($g);
                $a[] = MpcNetWire::hx($this->prep['alpha'][$l]['x']);
                $at[] = MpcNetWire::hx($this->prep['alpha'][$l]['tag'][$peer]);
            }
            return ['g' => array_map(MpcNetWire::hx(...), $Gamma), 'gt' => $gt, 'a' => $a, 'at' => $at];
        };
        // Abort claims arriving during this round are read in link order (see MpcNetMesh::setDeferAborts).
        $this->mesh->setDeferAborts(true);
        try {
            $blames = $this->xchg('blame', $blameMsg, function (int $p, mixed $raw) use ($K): array {
                $o = $raw instanceof Obj ? $raw : Obj::of([]);
                return ['g' => $this->arr($p, $o->get('g'), $K), 'gt' => $this->arr($p, $o->get('gt'), $K), 'a' => $this->arr($p, $o->get('a'), $K), 'at' => $this->arr($p, $o->get('at'), $K)];
            }, null, false, null);
        } finally {
            $this->mesh->setDeferAborts(false);
        }
        foreach ($this->others as $p) {
            $b = $blames[$p];
            for ($l = 0; $l < $K; $l++) {
                $keyCombo = gmp_init(0);
                foreach ($this->opened as $j => $o) {
                    $keyCombo = MpcField::fadd($keyCombo, MpcField::fmul(MpcNetProtocol::challenge($joint, 'mac' . $l, $j), $o['mac'][$l]['key'][$p]));
                }
                if (gmp_cmp(MpcField::fadd($keyCombo, MpcField::fmul($this->env['delta'], $b['g'][$l])), $b['gt'][$l]) !== 0) {
                    throw $this->abort(new MpcNetAbort('mac-check', $p, $id, $msg . " - party $p's MAC share (key $l) does not match its pairwise tag"));
                }
                if (gmp_cmp(MpcField::fadd($this->prep['alpha'][$l]['key'][$p], MpcField::fmul($this->env['delta'], $b['a'][$l])), $b['at'][$l]) !== 0) {
                    throw $this->abort(new MpcNetAbort('mac-check', $p, $id, $msg . " - party $p's key share (key $l) does not match its pairwise tag"));
                }
                if (gmp_cmp(MpcField::fsub($b['g'][$l], MpcField::fmul($b['a'][$l], $aPub[$l])), $sigOpens[$p][$l]) !== 0) {
                    throw $this->abort(new MpcNetAbort('mac-check', $p, $id, $msg . " - party $p's opened MAC residual (key $l) is not what its authenticated shares give"));
                }
            }
        }
        // Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
        if ($this->prep['mode'] === 'trusted-dealer') {
            throw $this->abort(new MpcNetAbort('dealer', $this->dealerId, $id, $msg . " - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"));
        }
        throw $this->abort(new MpcNetAbort('mac-check', $this->n === 2 ? 1 - $id : null, $id,
            $msg . " - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable", null, null,
            "every party's shares verify under its pairwise tags, so the fault lies in the offline material, which names no party"));
    }
}
