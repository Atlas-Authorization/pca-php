<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Optimistic.php';
require_once __DIR__ . '/OptimisticAdjudication.php';
require_once __DIR__ . '/LedgerLog.php';
require_once __DIR__ . '/StoreErrors.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Durable bond settlement, the pure half: exact micro-unit money arithmetic, the slash split, bond sizing, the evidence digests a signed
 * settlement record commits to, and the settlement anchors of the transparency ledger. INTERNAL ACCOUNTING ONLY: nothing here moves money.
 * Balances and amounts are PHP numbers; records are Obj (the reference's member names), plans are arrays
 * `{claimId, expect, next, open?, moves, record}`.
 */
final class BondSettlement
{
    public const ESCROW_ACCOUNT = 'escrow';
    public const COMPENSATION_POOL_ACCOUNT = 'pca:pool:compensation';
    public const MICROS_PER_UNIT = 1_000_000;
    public const SETTLEMENT_LEAF_DOMAIN = 'atlas-pca/settlement-leaf/v1';
    public const DEFAULT_SLASH_SPLIT_POLICY = ['challengerBps' => 5000, 'victimBps' => 4000];
    private const MAX_SAFE_MICROS = 1e15;
    private const MIN_SHARE_QUANTUM = 9.313225746154785e-10; // 2^-30

    /** A finite JSON number (Num or native, never a bool) as a float, else null. */
    public static function fin(mixed $x): ?float
    {
        $f = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $f !== null && is_finite($f) ? $f : null;
    }

    /** The largest exponent of a power curve (the integer part is a loop of multiplications). */
    public const POWER_CURVE_MAX_GAMMA = 64;

    /**
     * e^gamma for gamma a multiple of 1/8 in [1, 64], by operations every platform computes identically (pow is not correctly rounded: its
     * last digit differs between libm builds, and a bond amount is money). With gamma = n/8: multiply by `e` floor(n / 8) times, one
     * multiplication at a time, then by sqrt(e), sqrt(sqrt(e)), sqrt(sqrt(sqrt(e))) when bits 4, 2, 1 of (n mod 8) are set, in that order.
     * Multiplication and sqrt are exactly rounded IEEE operations. Any other gamma is refused, never rounded.
     */
    public static function powEighths(float $e, float $gamma): float
    {
        $n = $gamma * 8;
        if (!(is_finite($n) && floor($n) === $n && $gamma <= self::POWER_CURVE_MAX_GAMMA)) {
            throw new \InvalidArgumentException('bondAmount: power curve gamma must be a multiple of 1/8 and at most 64');
        }
        $ni = (int)$n;
        $r = 1.0;
        for ($i = 0, $whole = intdiv($ni, 8); $i < $whole; $i++) {
            $r *= $e;
        }
        $f = $ni % 8;
        $s1 = sqrt($e);
        $s2 = sqrt($s1);
        $s3 = sqrt($s2);
        if (($f & 4) !== 0) {
            $r *= $s1;
        }
        if (($f & 2) !== 0) {
            $r *= $s2;
        }
        if (($f & 1) !== 0) {
            $r *= $s3;
        }
        return $r;
    }

    private static function round(float $x): float
    {
        return floor($x + 0.5); // JavaScript Math.round
    }

    /** Integer micro-units of `$x` when it is (within float noise) a micro-grid amount below 1e15 micros, else null. */
    public static function toMicros(mixed $x): ?int
    {
        $x = self::fin($x);
        if ($x === null || $x < 0) {
            return null;
        }
        $scaled = $x * self::MICROS_PER_UNIT;
        if ($scaled > self::MAX_SAFE_MICROS) {
            return null;
        }
        $r = self::round($scaled);
        if ($r / self::MICROS_PER_UNIT !== $x && abs($scaled - $r) > 1e-3) {
            return null; // genuinely sub-micro: not a micro-grid amount
        }
        return (int)$r;
    }

    public static function fromMicros(int $m): float
    {
        return $m / self::MICROS_PER_UNIT;
    }

    /** `$a + $sign * $b` in exact micro-unit integers when both are micro-grid amounts (no float drift); plain float otherwise. */
    public static function exactAdd(mixed $a, mixed $b, int $sign): float
    {
        $ma = self::toMicros($a);
        $mb = self::toMicros($b);
        if ($ma === null || $mb === null) {
            return (float)self::fin($a) + $sign * (float)self::fin($b);
        }
        return self::fromMicros($sign === 1 ? $ma + $mb : $ma - $mb);
    }

    /**
     * Apply moves `[{account, op: debit|credit, amount}]` in order over a balance reader and return the resulting balances; THROWS (applying
     * nothing) on an invalid amount or an overdraft.
     * @param callable(string):(int|float) $balanceOf
     * @param list<array{account:string,op:string,amount:mixed}> $moves
     * @return array<string,float>
     */
    public static function applyBondMoves(callable $balanceOf, array $moves): array
    {
        $out = [];
        $bal = static fn(string $a) => array_key_exists($a, $out) ? $out[$a] : $balanceOf($a);
        foreach ($moves as $m) {
            $amt = self::fin($m['amount'] ?? null);
            if ($amt === null || $amt < 0) {
                throw new \RuntimeException(IntentWb::jsStr($m['op'] ?? null) . ': invalid amount');
            }
            $acct = (string)$m['account'];
            if (!is_finite((float)$bal($acct))) {
                throw new \RuntimeException(IntentWb::jsStr($m['op'] ?? null) . ": balance of $acct is not finite");
            }
            if (($m['op'] ?? null) === 'debit' && !($bal($acct) >= $amt)) {
                throw new \RuntimeException("debit: insufficient balance for $acct");
            }
            $out[$acct] = self::exactAdd($bal($acct), $amt, ($m['op'] ?? null) === 'debit' ? -1 : 1);
        }
        return $out;
    }

    /** Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed. */
    public static function quantizeUp(float $x): float
    {
        if (!is_finite($x) || $x <= 0) {
            return $x;
        }
        $scaled = $x * self::MICROS_PER_UNIT;
        if ($scaled > self::MAX_SAFE_MICROS) {
            return $x;
        }
        $r = self::round($scaled);
        $m = $r / self::MICROS_PER_UNIT === $x || abs($scaled - $r) <= 1e-3 ? $r : ceil($scaled);
        return $m / self::MICROS_PER_UNIT;
    }

    private static function assertSplitPolicy(mixed $p): void
    {
        $total = 0.0;
        foreach (['challengerBps', 'victimBps'] as $k) {
            $v = self::fin(self::get($p, $k));
            if ($v === null || $v !== floor($v) || $v < 0 || $v > 10_000) {
                throw new \InvalidArgumentException("slash split: $k must be an integer in [0,10000]");
            }
            $total += $v;
        }
        if ($total > 10_000) {
            throw new \InvalidArgumentException('slash split: challengerBps + victimBps must not exceed 10000');
        }
    }

    /** A member of an Obj or associative array. */
    private static function get(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : (is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null);
    }

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj ? $o->has($k) : (is_array($o) && array_key_exists($k, $o));
    }

    /** The unit in the last place of a positive finite double (an exact power of two). */
    private static function ulpOf(float $x): float
    {
        $e = (int)floor(log($x, 2));
        if (2.0 ** $e > $x) {
            $e--;
        } elseif (2.0 ** ($e + 1) <= $x) {
            $e++;
        }
        return 2.0 ** max($e - 52, -1074);
    }

    private static function shareQuantum(float $amount): float
    {
        $u = self::ulpOf($amount);
        return $amount === floor($amount) ? max(1.0, $u) : max(self::MIN_SHARE_QUANTUM, $u);
    }

    /** floor(micros * bps / 10000), exact in 64-bit integers (micros < 1e15, bps <= 10000). */
    private static function shareMicros(int $micros, int $bps): int
    {
        return intdiv($micros, 10_000) * $bps + intdiv(($micros % 10_000) * $bps, 10_000);
    }

    /**
     * The challenger / victim / treasury division of a slashed `$amount`: exact (treasury = amount - challenger - victim) and integer-safe.
     * `$dest` has `challengerAccount` (a string, or an explicit null for an anonymous challenge, which pays the whole bond to the treasury),
     * `victimAccount` and `treasuryAccount`.
     * @param array{challengerAccount?:?string,victimAccount:mixed,treasuryAccount:mixed} $dest
     * @return array<string,mixed>
     */
    public static function computeSlashSplit(mixed $amount, mixed $policy, array $dest): array
    {
        $amount = self::fin($amount);
        if ($amount === null || $amount <= 0) {
            throw new \InvalidArgumentException('computeSlashSplit: amount must be a positive finite number');
        }
        self::assertSplitPolicy($policy);
        $victim = $dest['victimAccount'] ?? null;
        $treasury = $dest['treasuryAccount'] ?? null;
        if (!is_string($victim) || $victim === '') {
            throw new \InvalidArgumentException('computeSlashSplit: victimAccount is required');
        }
        if (!is_string($treasury) || $treasury === '') {
            throw new \InvalidArgumentException('computeSlashSplit: treasuryAccount is required');
        }
        $has = array_key_exists('challengerAccount', $dest);
        $ch = $dest['challengerAccount'] ?? null;
        $out = static function (float|int $c, float|int $v, float|int $t, float|int $amt) use ($has, $ch, $victim, $treasury): array {
            $r = ['amount' => $amt, 'challengerReward' => $c, 'victimCompensation' => $v, 'treasuryRemainder' => $t];
            if ($has) {
                $r['challengerAccount'] = $ch;
            }
            return $r + ['victimAccount' => $victim, 'treasuryAccount' => $treasury];
        };
        if ($has && $ch === null) {
            return $out(0, 0, $amount, $amount); // anonymous: 100% treasury, no pool pre-funding
        }
        $cbps = (float)self::fin(self::get($policy, 'challengerBps'));
        $vbps = (float)self::fin(self::get($policy, 'victimBps'));
        $micros = $amount === floor($amount) ? null : self::toMicros($amount); // integer bonds keep whole-unit shares
        if ($micros !== null) {
            $c = self::shareMicros($micros, (int)$cbps);
            $v = self::shareMicros($micros, (int)$vbps);
            $t = $micros - $c - $v; // >= 0 because challengerBps + victimBps <= 10000
            return $out(self::fromMicros($c), self::fromMicros($v), self::fromMicros($t), self::fromMicros($micros));
        }
        $q = self::shareQuantum($amount);
        $share = static fn(float $bps): float => floor((($amount * $bps) / 10_000) / $q) * $q;
        $challenger = min($share($cbps), $amount);
        $victimComp = min($share($vbps), $amount - $challenger);
        return $out($challenger, $victimComp, $amount - $challenger - $victimComp, $amount);
    }

    /** The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder. */
    public static function defaultSlashSplitPolicy(): array
    {
        return self::DEFAULT_SLASH_SPLIT_POLICY;
    }

    /** @return array{floor:int,k:int,maxOpenClaims:int,maxOpenAmount:float} */
    public static function defaultBondPolicy(): array
    {
        return ['floor' => 1, 'k' => 1, 'maxOpenClaims' => 100, 'maxOpenAmount' => INF];
    }

    private static function curveComponent(mixed $curve, float $k, float $e): float
    {
        $kind = self::get($curve, 'kind');
        if ($curve === null || $kind === 'linear') {
            return $k * $e;
        }
        if ($kind === 'power') {
            $g = self::fin(self::get($curve, 'gamma'));
            if ($g === null || !($g >= 1)) {
                throw new \InvalidArgumentException('bondAmount: power curve requires finite gamma >= 1');
            }
            return $k * self::powEighths($e, $g);
        }
        $tiers = self::get($curve, 'tiers');
        if (!is_array($tiers) || !array_is_list($tiers) || $tiers === []) {
            throw new \InvalidArgumentException('bondAmount: piecewise curve requires at least one tier');
        }
        $acc = 0.0;
        $prevUp = 0.0;
        $prevMarginal = 0.0;
        foreach ($tiers as $tier) {
            if (!($tier instanceof Obj) && !(is_array($tier) && !array_is_list($tier))) {
                throw new \InvalidArgumentException('bondAmount: malformed tier');
            }
            $upRaw = self::get($tier, 'upTo');
            $upTo = self::fin($upRaw) ?? (($upRaw === INF) ? INF : null);
            $mk = self::fin(self::get($tier, 'marginalK'));
            if (!(($upTo !== null && is_finite($upTo) && $upTo > $prevUp) || $upTo === INF)) {
                throw new \InvalidArgumentException('bondAmount: piecewise tier `upTo` must be strictly increasing');
            }
            if ($mk === null || !($mk >= 0)) {
                throw new \InvalidArgumentException('bondAmount: piecewise `marginalK` must be a finite number >= 0');
            }
            if ($mk < $prevMarginal) {
                throw new \InvalidArgumentException('bondAmount: piecewise marginal rates must be non-decreasing (convex)');
            }
            $width = min($e, $upTo) - $prevUp;
            if ($width > 0) {
                $acc += $width * $mk;
            }
            $prevUp = $upTo;
            $prevMarginal = $mk;
            if ($e <= $upTo) {
                break;
            }
        }
        if ($e > $prevUp) {
            $acc += ($e - $prevUp) * $prevMarginal;
        }
        return $k * $acc;
    }

    /**
     * `max(floor, curve(k, exposure))` snapped up onto the micro grid; no curve = linear. A non-finite or non-positive exposure gives the floor.
     * @param array<string,mixed>|Obj $policy `{floor, k, curve?: {kind: linear} | {kind: power, gamma} | {kind: piecewise, tiers: [{upTo, marginalK}]}}`
     */
    public static function bondAmount(mixed $policy, mixed $exposure): float
    {
        $x = self::fin($exposure);
        $e = $x !== null && $x > 0 ? $x : 0.0;
        $floor = (float)self::fin(self::get($policy, 'floor'));
        return self::quantizeUp(max($floor, self::curveComponent(self::get($policy, 'curve'), (float)self::fin(self::get($policy, 'k')), $e)));
    }

    /** The claim identity every evidence digest binds. @return array<string,mixed> */
    private static function claimIdentity(mixed $claim): array
    {
        return ['claimDigest' => self::get($claim, 'pcactn_digest'), 'bond_ref' => self::get($claim, 'bond_ref')];
    }

    /** base64url(sha256(lenient canonical form)): server-only digests. */
    public static function lenient(mixed $v): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient(Sign::n($v)), true));
    }

    /** Binds a slash to the server-derived fraud verdict. @param array<string,mixed> $fraudVerdict */
    public static function settlementEvidenceDigest(mixed $claim, array $fraudVerdict): string
    {
        return self::lenient(self::claimIdentity($claim) + ['fraudulent' => $fraudVerdict['fraudulent'] ?? null, 'slashBondRef' => $fraudVerdict['slashBondRef'] ?? null,
            'reason' => $fraudVerdict['reason'] ?? null]);
    }

    public static function revocationEvidenceDigest(mixed $claim, string $revokedCapId): string
    {
        return self::lenient(self::claimIdentity($claim) + ['kind' => 'revocation', 'revokedCapId' => $revokedCapId]);
    }

    /** Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion. @param array<string,mixed> $verdict */
    public static function disputeEvidenceDigest(mixed $claim, array $verdict): string
    {
        return self::lenient(self::claimIdentity($claim) + ['kind' => 'dispute', 'outcome' => $verdict['outcome'] ?? null, 'input' => $verdict['input'] ?? null,
            'agentValue' => $verdict['agentValue'] ?? null, 'oracleValue' => $verdict['oracleValue'] ?? null, 'slashBondRef' => $verdict['slashBondRef'] ?? null,
            'reason' => $verdict['reason'] ?? null]);
    }

    /** Verify a settlement record's signature under the guardian public key; suite-agile ({@see Optimistic::settlementWireCheck}). */
    public static function verifySettlement(mixed $record, mixed $guardianPublic, mixed $pins = null): bool
    {
        return Optimistic::settlementWireCheck($record, $guardianPublic, $pins) === 'ok';
    }

    public static function settlementRecordDigest(mixed $record): string
    {
        return self::lenient(['t' => self::SETTLEMENT_LEAF_DOMAIN, 'record' => $record]);
    }

    /** The salted commitment of a settlement record (the opaque transparency-log leaf). */
    public static function settlementCommit(mixed $salt, mixed $record): string
    {
        if (!is_string($salt) || $salt === '') {
            throw new \InvalidArgumentException('settlementCommit: salt must be a non-empty string');
        }
        return self::lenient(['salt' => $salt, 'settlement_digest' => self::settlementRecordDigest($record)]);
    }

    /** True iff `$salt` + `$record` reproduce the anchored `$commit`. Never throws. */
    public static function verifySettlementCommit(mixed $commit, mixed $salt, mixed $record): bool
    {
        try {
            return self::settlementCommit($salt, $record) === $commit;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Append a settlement record into a {@see TransparencyLedger} as a salted commitment. The caller retains `{record, salt}` as the
     * off-log opening. @return array{index:int,commit:string,salt:string}
     */
    public static function appendSettlement(TransparencyLedger $ledger, mixed $record, ?string $salt = null): array
    {
        $salt ??= Pca::b64u(random_bytes(16));
        $commit = self::settlementCommit($salt, $record);
        return ['index' => $ledger->appendCommitment($commit)['index'], 'commit' => $commit, 'salt' => $salt];
    }
}

/**
 * The pure half of bond settlement: validates a transition against a read view, re-derives every slash verdict ITSELF, computes the
 * balance movements and signs the record. `$view` is `['bond' => fn(string $id): ?array, 'balanceOf' => fn(string $account): int|float,
 * 'openTotals' => fn(string $depositor): array{0:int,1:int|float}]`; a bond row is `['claimId', 'amount', 'depositor', 'status', 'window'?, 'records']`.
 */
final class BondSettlementPlanner
{
    public readonly string $guardianPublicKey;
    public readonly string $escrow;
    /** @var array<string,mixed> */
    public readonly array $bondPolicy;
    /** @var array<string,mixed> */
    public readonly array $slashSplitPolicy;

    public function __construct(private readonly KeyPair $guardian, private readonly ?int $guardianEpoch = null, private readonly ?string $alg = null,
        private readonly ?PqKeyPair $pq = null, ?string $escrowAccount = null, ?array $bondPolicy = null, ?array $slashSplitPolicy = null)
    {
        if ($guardianEpoch !== null && ($guardianEpoch < 0 || $guardianEpoch > 9007199254740991)) {
            throw new \InvalidArgumentException('BondLedger: guardianEpoch must be a non-negative safe integer');
        }
        $this->guardianPublicKey = $guardian->public;
        $this->escrow = $escrowAccount ?? BondSettlement::ESCROW_ACCOUNT;
        $this->bondPolicy = $bondPolicy ?? BondSettlement::defaultBondPolicy();
        $this->slashSplitPolicy = $slashSplitPolicy ?? BondSettlement::DEFAULT_SLASH_SPLIT_POLICY;
    }

    /** Sign a record body (the guardian epoch and the suite are bound into the signed bytes). @param array<string,mixed> $base */
    private function sign(array $base): Obj
    {
        if ($this->guardianEpoch !== null) {
            $base['guardian_epoch'] = $this->guardianEpoch;
        }
        $body = Sign::n($base);
        if ($this->alg !== null && $this->alg !== 'ed25519') {
            if ($this->pq === null) {
                throw new \InvalidArgumentException("{$this->alg} needs a post-quantum key pair");
            }
            $body->set('alg', $this->alg);
            $body->set('pq_pk', $this->pq->public);
        }
        $parts = Sign::signWithSuite($this->alg, $this->guardian, $this->pq, Optimistic::SETTLEMENT_DOMAIN . Json::canonicalizeLenient($body));
        foreach ($parts as $k => $v) {
            $body->set($k, $v);
        }
        return $body;
    }

    /** @return array{account:string,op:string,amount:mixed} */
    private static function move(string $account, string $op, mixed $amount): array
    {
        return ['account' => $account, 'op' => $op, 'amount' => $amount];
    }

    /** @return array<string,mixed> */
    private static function base(string $claimId, string $action, mixed $amount, string $from, string $to, mixed $at, string $evidence): array
    {
        return ['claimId' => $claimId, 'action' => $action, 'amount' => $amount, 'from' => $from, 'to' => $to, 'at' => $at, 'evidenceDigest' => $evidence];
    }

    /** @return array<string,mixed> */
    private static function plan(string $claimId, string $expect, string $next, array $moves, Obj $record): array
    {
        return ['claimId' => $claimId, 'expect' => $expect, 'next' => $next, 'moves' => $moves, 'record' => $record];
    }

    private static function openBondOf(array $view, string $who, mixed $claimId): array
    {
        $bond = ($view['bond'])((string)$claimId);
        if ($bond === null) {
            throw new \InvalidArgumentException("$who: no bond for " . IntentWb::jsStr($claimId));
        }
        if ($bond['status'] !== 'open') {
            throw new \InvalidArgumentException("$who: bond " . IntentWb::jsStr($claimId) . " is already {$bond['status']} (double-settle refused)");
        }
        return $bond;
    }

    private static function needTreasury(array $p, string $who): void
    {
        if (!is_string($p['treasury'] ?? null) || $p['treasury'] === '') {
            throw new \InvalidArgumentException("$who: treasury is required");
        }
    }

    /** @param array<string,mixed> $p */
    private function slashPlan(array $bond, string $claimId, mixed $now, string $evidence, array $p): array
    {
        $treasury = $p['treasury'];
        $amount = $bond['amount'];
        $policy = isset($p['splitPolicy']) && ($p['splitPolicy'] instanceof Obj || is_array($p['splitPolicy'])) ? $p['splitPolicy'] : $this->slashSplitPolicy;
        $comp = $p['compensationAccount'] ?? null;
        $split = BondSettlement::computeSlashSplit($amount, $policy, ['challengerAccount' => $p['challengerAccount'] ?? null,
            'victimAccount' => $comp !== null && $comp !== '' ? $comp : BondSettlement::COMPENSATION_POOL_ACCOUNT, 'treasuryAccount' => $treasury]);
        $moves = [self::move($this->escrow, 'debit', $amount)]; // the full bond leaves escrow
        if (isset($split['challengerAccount']) && $split['challengerAccount'] !== '' && $split['challengerReward'] > 0) {
            $moves[] = self::move($split['challengerAccount'], 'credit', $split['challengerReward']);
        }
        if ($split['victimCompensation'] > 0) {
            $moves[] = self::move($split['victimAccount'], 'credit', $split['victimCompensation']);
        }
        if ($split['treasuryRemainder'] > 0) {
            $moves[] = self::move($split['treasuryAccount'], 'credit', $split['treasuryRemainder']);
        }
        $b = self::base($claimId, 'slash', $amount, $this->escrow, $treasury, $now, $evidence);
        $b['split'] = $split;
        return self::plan($claimId, 'open', 'slashed', $moves, $this->sign($b));
    }

    /**
     * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, one that breaches the depositor's caps
     * and a double-open. The bond moves from the depositor into escrow.
     * @param array<string,mixed>|null $window `{registeredAt, windowMs, claimDigest}`
     */
    public function planOpen(array $view, mixed $claimId, mixed $amount, mixed $depositor, mixed $exposure, mixed $now, ?array $window = null): array
    {
        if (!is_string($claimId) || $claimId === '') {
            throw new \InvalidArgumentException('openBond: claimId is required');
        }
        $amt = BondSettlement::fin($amount);
        if ($amt === null || $amt <= 0) {
            throw new \InvalidArgumentException('openBond: amount must be a positive finite number');
        }
        if (!is_string($depositor) || $depositor === '') {
            throw new \InvalidArgumentException('openBond: depositor is required');
        }
        if (($view['bond'])($claimId) !== null) {
            throw new \InvalidArgumentException("openBond: bond $claimId already exists (double-open refused)");
        }
        $required = BondSettlement::bondAmount($this->bondPolicy, $exposure ?? 0);
        if (!($amt >= $required)) {
            throw new \InvalidArgumentException('openBond: amount ' . IntentWb::jsStr($amt) . ' is below the required bond ' . IntentWb::jsStr($required));
        }
        [$count, $sum] = ($view['openTotals'])($depositor);
        if (!(is_finite((float)$count) && $count + 1 <= $this->bondPolicy['maxOpenClaims'])) {
            throw new \InvalidArgumentException('openBond: depositor open-claim cap reached');
        }
        if (!(is_finite((float)($sum + $amt)) && $sum + $amt <= $this->bondPolicy['maxOpenAmount'])) {
            throw new \InvalidArgumentException('openBond: depositor aggregate open-bond cap exceeded');
        }
        if (!(is_finite((float)($view['balanceOf'])($depositor)) && ($view['balanceOf'])($depositor) >= $amt)) {
            throw new \InvalidArgumentException('openBond: insufficient balance for the bond');
        }
        $record = $this->sign(self::base($claimId, 'open', $amt, $depositor, $this->escrow, $now, ''));
        $open = ['amount' => $amt, 'depositor' => $depositor, 'maxOpenClaims' => $this->bondPolicy['maxOpenClaims'], 'maxOpenAmount' => $this->bondPolicy['maxOpenAmount']];
        if ($window !== null) {
            $open['window'] = $window;
        }
        $p = self::plan($claimId, 'none', 'open', [self::move($depositor, 'debit', $amt), self::move($this->escrow, 'credit', $amt)], $record);
        $p['open'] = $open;
        return $p;
    }

    /** Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond. */
    public function planRelease(array $view, mixed $claimId, mixed $now): array
    {
        $bond = ($view['bond'])((string)$claimId);
        if ($bond === null) {
            throw new \InvalidArgumentException('releaseBond: no bond for ' . IntentWb::jsStr($claimId));
        }
        if ($bond['status'] !== 'open') {
            throw new \InvalidArgumentException("releaseBond: bond $claimId is already {$bond['status']} (double-settle refused)");
        }
        $amount = $bond['amount'];
        $depositor = $bond['depositor'];
        return self::plan((string)$claimId, 'open', 'released', [self::move($this->escrow, 'debit', $amount), self::move($depositor, 'credit', $amount)],
            $this->sign(self::base((string)$claimId, 'release', $amount, $this->escrow, $depositor, $now, '')));
    }

    private static function pget(array $p, string $k): mixed
    {
        return $p[$k] ?? null;
    }

    private static function claimBond(mixed $claim): mixed
    {
        return $claim instanceof Obj ? $claim->get('bond_ref') : null;
    }

    /**
     * Slash against a VERIFIED fraud verdict; re-runs the policy VM itself. `$p`: claimId, claim, fraudProof, grant, openSnapshot, treasury,
     * and optionally challengerAccount, compensationAccount, splitPolicy.
     * @param array<string,mixed> $p
     */
    public function planSlash(array $view, array $p, mixed $now): array
    {
        $claimId = self::pget($p, 'claimId');
        $claim = self::pget($p, 'claim');
        $bond = self::openBondOf($view, 'slashBond', $claimId);
        self::needTreasury($p, 'slashBond');
        if (self::claimBond($claim) !== $claimId) {
            throw new \InvalidArgumentException('slashBond: claim.bond_ref does not match claimId');
        }
        $v = OptimisticAdjudication::verifyFraudProof($claim, self::pget($p, 'fraudProof'), self::pget($p, 'grant'), self::pget($p, 'openSnapshot'));
        if (($v['fraudulent'] ?? null) !== true || ($v['slashBondRef'] ?? null) !== $claimId) {
            throw new \InvalidArgumentException("slashBond: refused \u{2014} no verified fraud verdict slashing " . IntentWb::jsStr($claimId) . " ({$v['reason']})");
        }
        return $this->slashPlan($bond, $claimId, $now, BondSettlement::settlementEvidenceDigest($claim, $v), $p);
    }

    /** Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). `$p` adds revokedCapId. */
    public function planSlashOnRevocation(array $view, array $p, mixed $now): array
    {
        $claimId = self::pget($p, 'claimId');
        $claim = self::pget($p, 'claim');
        $bond = self::openBondOf($view, 'slashBondOnRevocation', $claimId);
        self::needTreasury($p, 'slashBondOnRevocation');
        if (self::claimBond($claim) !== $claimId) {
            throw new \InvalidArgumentException('slashBondOnRevocation: claim.bond_ref does not match claimId');
        }
        $revoked = self::pget($p, 'revokedCapId');
        if (!is_string($revoked) || $revoked === '') {
            throw new \InvalidArgumentException('slashBondOnRevocation: revokedCapId is required');
        }
        return $this->slashPlan($bond, $claimId, $now, BondSettlement::revocationEvidenceDigest($claim, $revoked), $p);
    }

    /** Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. `$p` adds dispute, oracle, rMargin?. */
    public function planSlashOnDispute(array $view, array $p, mixed $now): array
    {
        $claimId = self::pget($p, 'claimId');
        $claim = self::pget($p, 'claim');
        $bond = self::openBondOf($view, 'slashBondOnDispute', $claimId);
        self::needTreasury($p, 'slashBondOnDispute');
        if (self::claimBond($claim) !== $claimId) {
            throw new \InvalidArgumentException('slashBondOnDispute: claim.bond_ref does not match claimId');
        }
        $v = OptimisticAdjudication::adjudicateDispute($claim, self::pget($p, 'dispute'), self::pget($p, 'grant'), self::pget($p, 'openSnapshot'),
            self::pget($p, 'oracle'), self::pget($p, 'rMargin'));
        if (($v['outcome'] ?? null) !== 'agent-fraud' || ($v['fraudulent'] ?? null) !== true || ($v['slashBondRef'] ?? null) !== $claimId) {
            throw new \InvalidArgumentException("slashBondOnDispute: refused \u{2014} no verified agent-fraud verdict slashing " . IntentWb::jsStr($claimId)
                . ' (' . IntentWb::jsStr($v['outcome'] ?? null) . ': ' . IntentWb::jsStr($v['reason'] ?? null) . ')');
        }
        return $this->slashPlan($bond, $claimId, $now, BondSettlement::disputeEvidenceDigest($claim, $v), $p);
    }

    /** Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing): an anonymous slash, 100% to the treasury. */
    public function planSlashCounterBond(array $view, array $p, mixed $now): array
    {
        $cid = self::pget($p, 'counterBondId');
        $claim = self::pget($p, 'claim');
        $bond = ($view['bond'])((string)$cid);
        if ($bond === null) {
            throw new \InvalidArgumentException('slashCounterBond: no counter-bond for ' . IntentWb::jsStr($cid));
        }
        if ($bond['status'] !== 'open') {
            throw new \InvalidArgumentException('slashCounterBond: counter-bond ' . IntentWb::jsStr($cid) . " is already {$bond['status']} (double-settle refused)");
        }
        self::needTreasury($p, 'slashCounterBond');
        $v = OptimisticAdjudication::adjudicateDispute($claim, self::pget($p, 'dispute'), self::pget($p, 'grant'), self::pget($p, 'openSnapshot'),
            self::pget($p, 'oracle'), self::pget($p, 'rMargin'));
        if (($v['outcome'] ?? null) !== 'claim-upheld' || ($v['slashCounterBond'] ?? null) !== true) {
            throw new \InvalidArgumentException("slashCounterBond: refused \u{2014} the dispute is not frivolous (" . IntentWb::jsStr($v['outcome'] ?? null) . ': '
                . IntentWb::jsStr($v['reason'] ?? null) . ')');
        }
        return $this->slashPlan($bond, (string)$cid, $now, BondSettlement::disputeEvidenceDigest($claim, $v),
            ['treasury' => $p['treasury'], 'challengerAccount' => null, 'compensationAccount' => $p['compensationAccount'] ?? null, 'splitPolicy' => $p['splitPolicy'] ?? null]);
    }
}

/**
 * A finite, fail-closed insurance capital pool. Premiums are credited; victim payouts are debited and REFUSED when they exceed the pool's
 * free capital (scarce collateral). The three ledgers (`initial`, `premiumsIn`, `payoutsOut`) always reconcile to `balance` exactly.
 * Premiums are priced by the caller's underwriting quote (`['premium' => number, 'declined' => bool]`).
 */
final class InsuranceCapitalPool
{
    private float $premiumsIn = 0.0;
    private float $payoutsOut = 0.0;
    private readonly float $initial;

    public function __construct(mixed $initial = 0)
    {
        $f = BondSettlement::fin($initial);
        if ($f === null || $f < 0) {
            throw new \InvalidArgumentException('InsuranceCapitalPool: initial capital must be a non-negative finite number');
        }
        $this->initial = $f;
    }

    public function balance(): float
    {
        return $this->initial + $this->premiumsIn - $this->payoutsOut;
    }

    public function premiumsIn(): float
    {
        return $this->premiumsIn;
    }

    public function payoutsOut(): float
    {
        return $this->payoutsOut;
    }

    /** The current accounting snapshot (the conservation invariant always holds over these). @return array{initial:float,premiumsIn:float,payoutsOut:float,balance:float} */
    public function state(): array
    {
        return ['initial' => $this->initial, 'premiumsIn' => $this->premiumsIn, 'payoutsOut' => $this->payoutsOut, 'balance' => $this->balance()];
    }

    /**
     * Credit the premium of an underwriting `$pricing` (`premium`, `declined`) unless it was declined. A declined quote credits nothing.
     * @param array{premium:mixed,declined?:bool} $pricing
     * @return array{pricing:array<string,mixed>,state:array<string,float>}
     */
    public function collectPremium(array $pricing): array
    {
        $premium = BondSettlement::fin($pricing['premium'] ?? null);
        if (empty($pricing['declined']) && $premium !== null && $premium > 0) {
            $this->premiumsIn += $premium;
        } elseif (empty($pricing['declined']) && ($pricing['premium'] ?? 0) !== 0 && $premium === null) {
            throw new \RuntimeException('collectPremium: priced premium is not a non-negative finite number');
        }
        return ['pricing' => $pricing, 'state' => $this->state()];
    }

    /** True iff the pool currently holds at least `$amount` of free capital. */
    public function canCover(mixed $amount): bool
    {
        $f = BondSettlement::fin($amount);
        return $f !== null && $f >= 0 && $this->balance() >= $f;
    }

    /** Pay `$amount` of victim compensation out of the pool. REFUSED (throws) when it is non-positive / non-finite or exceeds the free capital. */
    public function payClaim(mixed $amount): array
    {
        $f = BondSettlement::fin($amount);
        if ($f === null || $f <= 0) {
            throw new \InvalidArgumentException('payClaim: amount must be a positive finite number');
        }
        if (!(is_finite((float)$this->balance()) && $f <= $this->balance())) {
            throw new \InvalidArgumentException('payClaim: insufficient pool capital (need ' . IntentWb::jsStr($f) . ', have ' . IntentWb::jsStr($this->balance()) . ')');
        }
        $this->payoutsOut += $f;
        return $this->state();
    }
}
