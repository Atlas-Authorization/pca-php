<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/BondStore.php';
require_once __DIR__ . '/BondSettlement.php';
require_once __DIR__ . '/Optimistic.php';
require_once __DIR__ . '/StoreErrors.php';

/**
 * Durable, restart-safe bond settlement over a {@see BondStore} (the reference `StoreBondLedger`). It plans each transition with the
 * {@see BondSettlementPlanner} (so a slash is still authorised by a verdict the ledger recomputes, never by the challenger), stamps every
 * time from a clock the claimant cannot touch, and FAILS CLOSED with a {@see BondStoreError}: `store_missing`, `guardian_key_missing`,
 * `clock_invalid`, `store_unavailable`, `store_corrupt`, `invalid_claim`, `window_open`, `window_closed`, `unregistered`, `claim_mismatch`
 * or `conflict`. Every method is idempotent under retry: repeating a transition that already committed returns the stored record and moves
 * nothing, while a conflicting transition (a release after a slash, a second slash with different evidence) throws. Planner failures keep
 * their own message (an InvalidArgumentException).
 *
 * THE CHALLENGE-WINDOW CLOCK: the window opens at the ledger's own `registeredAt` (its clock at `openClaim`), lasts the claim's
 * `challenge_window_ms` and is never derived from the claim's `issued_at`. The ledger's "now" is `max(clock(), highest time the store has
 * ever recorded)`, so a clock that steps backwards cannot reopen a closed window or release early.
 */
final class StoreBondLedger
{
    private readonly BondSettlementPlanner $planner;
    private readonly BondStore $store;
    /** @var \Closure():(int|float) */
    private readonly \Closure $clock;
    /** @var array<string,mixed> */
    private readonly array $windowPolicy;

    /**
     * @param ?callable():(int|float) $clock epoch-ms clock (default the wall clock); a non-finite reading fails the operation
     * @param ?array<string,mixed> $windowPolicy bounds applied to `openClaim` (default {@see Optimistic::DEFAULT_WINDOW_POLICY})
     */
    public function __construct(mixed $store, mixed $guardian, ?callable $clock = null, ?array $windowPolicy = null, ?int $guardianEpoch = null, ?string $alg = null,
        ?PqKeyPair $pq = null, ?string $escrowAccount = null, ?array $bondPolicy = null, ?array $slashSplitPolicy = null)
    {
        if (!($store instanceof BondStore)) {
            throw new BondStoreError('store_missing', 'a BondStore is required (there is no in-memory default)');
        }
        if (!($guardian instanceof KeyPair)) {
            throw new BondStoreError('guardian_key_missing', 'a guardian secret key is required');
        }
        $this->store = $store;
        $this->planner = new BondSettlementPlanner($guardian, $guardianEpoch, $alg, $pq, $escrowAccount, $bondPolicy, $slashSplitPolicy);
        $this->clock = $clock !== null ? \Closure::fromCallable($clock) : static fn() => microtime(true) * 1000;
        $this->windowPolicy = $windowPolicy ?? Optimistic::DEFAULT_WINDOW_POLICY;
    }

    /** The guardian/settlement public key (b64u) the records verify under. */
    public function guardianPublicKey(): string
    {
        return $this->planner->guardianPublicKey;
    }

    private function guard(callable $fn): mixed
    {
        try {
            return $fn();
        } catch (BondStoreError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new BondStoreError('store_unavailable', $e->getMessage() ?: 'store failed');
        }
    }

    /** @return array{0:array<string,mixed>,1:array<string,callable>,2:int|float} [snapshot, view, now] */
    private function load(string $claimId, ?string $depositor = null): array
    {
        $snap = $this->guard(fn() => $this->store->read($claimId, $depositor));
        $t = ($this->clock)();
        if (!(is_int($t) || is_float($t)) || !is_finite((float)$t)) {
            throw new BondStoreError('clock_invalid', 'the clock returned a non-finite time');
        }
        $bond = $snap['bond'] ?? null;
        $bal = [];
        foreach ($snap['balances'] as [$a, $v]) {
            $bal[(string)$a] = $v;
        }
        $view = [
            'bond' => static fn(string $cid): ?array => $bond !== null && (string)$bond['claimId'] === $cid ? $bond : null,
            'balanceOf' => static fn(string $a) => $bal[$a] ?? 0,
            'openTotals' => static fn(string $d): array => [$snap['openTotals']['count'], $snap['openTotals']['sum']],
        ];
        return [$snap, $view, max($t, $snap['highWater'])];
    }

    private function submit(array $plan, mixed $now): Obj
    {
        $out = $this->guard(fn() => $this->store->commit($plan, $now));
        if ($out['outcome'] === 'conflict') {
            throw new BondStoreError('conflict', $out['reason']);
        }
        return $out['record'];
    }

    /**
     * Settle: plan against the true view; if the bond is already settled, a retry that would have produced the same settlement returns
     * the stored record.
     * @param callable(array,mixed):array $plan
     * @param ?callable(array,mixed):void $gate
     */
    private function settle(string $claimId, callable $plan, ?callable $gate = null): Obj
    {
        [$snap, $view, $now] = $this->load($claimId);
        $bond = $snap['bond'] ?? null;
        if ($bond !== null && $bond['status'] !== 'open') {
            $last = $bond['records'] === [] ? null : $bond['records'][count($bond['records']) - 1];
            $asOpen = ['bond' => static fn(string $c): array => [...$bond, 'status' => 'open']] + $view;
            $again = $plan($asOpen, $now); // throws if the evidence no longer holds
            if ($last !== null && BondStoreDoc::sameSettlement($last, $again['record'])) {
                return $last;
            }
            return $plan($view, $now)['record']; // throws the standard double-settle refusal
        }
        if ($bond !== null && $gate !== null) {
            $gate($bond, $now);
        }
        return $this->submit($plan($view, $now), $now);
    }

    /** Top up an account of the internal books (a positive finite amount). */
    public function deposit(mixed $account, mixed $amount): float|int
    {
        return $this->guard(fn() => $this->store->deposit($account, $amount));
    }

    public function balanceOf(string $account): float|int
    {
        $snap = $this->guard(fn() => $this->store->read('', $account));
        return $snap['balances'][0][1] ?? 0;
    }

    public function bondStatus(string $claimId): string
    {
        return $this->guard(fn() => $this->store->read($claimId, null))['bond']['status'] ?? 'none';
    }

    /** @return ?array<string,mixed> */
    public function getBond(string $claimId): ?array
    {
        return $this->guard(fn() => $this->store->read($claimId, null))['bond'] ?? null;
    }

    /** Where the claim's challenge window stands on the ledger's clock; throws `unregistered` for a bond with no claim. @return array{phase:string,endsAt:int|float,now:int|float} */
    public function challengeStatus(string $claimId): array
    {
        [$snap, , $now] = $this->load($claimId);
        $w = $snap['bond']['window'] ?? null;
        if (!$w) {
            throw new BondStoreError('unregistered', "bond $claimId has no registered claim");
        }
        $ends = $w['registeredAt'] + $w['windowMs'];
        if (!is_finite((float)$now) || !is_finite((float)$ends)) {
            throw new BondStoreError('clock_invalid', 'the challenge window or the clock is not a finite time');
        }
        return ['phase' => $now > $ends ? 'finalized' : 'open', 'endsAt' => $ends, 'now' => $now];
    }

    /** A retried open: the same terms return the original `open` record; anything else is the standard double-open refusal. */
    private function replayOpen(array $prior, mixed $depositor, mixed $amount, ?array $window = null): Obj
    {
        $same = $prior['depositor'] === $depositor && BondSettlement::fin($prior['amount']) === BondSettlement::fin($amount)
            && ($prior['window']['claimDigest'] ?? null) === ($window['claimDigest'] ?? null);
        if ($same && $prior['records'] !== []) {
            return $prior['records'][0];
        }
        throw new BondStoreError('conflict', "openBond: bond {$prior['claimId']} already exists (double-open refused)");
    }

    /**
     * Register an optimistic claim and lock its bond in one atomic commit. The claim must pass the claim check against the ledger's clock
     * and its window must be at least the realistic floor; the window then runs from the ledger's own `registeredAt`.
     * Retrying the same call returns the original `open` record.
     */
    public function openClaim(Obj $claim, mixed $pcactn, string $signerPublic, mixed $amount, string $depositor, mixed $exposure = null): Obj
    {
        $ref = $claim->get('bond_ref');
        [$snap, $view, $now] = $this->load(IntentWb::jsStr($ref), $depositor);
        $v = Optimistic::verifyClaim($claim, $pcactn, $signerPublic, $now, $this->windowPolicy);
        if (!$v['ok']) {
            throw new BondStoreError('invalid_claim', (string)$v['reason']);
        }
        $floor = max(BondSettlement::fin($this->windowPolicy['minWindowMs']), (float)Optimistic::DEFAULT_MIN_CHALLENGE_WINDOW_MS);
        $cw = (float)BondSettlement::fin($claim->get('challenge_window_ms'));
        if ($cw < $floor) {
            throw new BondStoreError('invalid_claim', 'challenge window ' . IntentWb::jsStr($cw) . ' ms is below the ' . IntentWb::jsStr($floor) . ' ms floor');
        }
        if (!is_string($ref) || $ref === '') {
            throw new BondStoreError('invalid_claim', 'claim has no bond_ref');
        }
        $window = ['registeredAt' => $now, 'windowMs' => $claim->get('challenge_window_ms') instanceof Num ? $claim->get('challenge_window_ms')->float() : $cw,
            'claimDigest' => BondSettlement::lenient($claim)];
        if (isset($snap['bond'])) {
            return $this->replayOpen($snap['bond'], $depositor, $amount, $window);
        }
        return $this->submit($this->planner->planOpen($view, $ref, $amount, $depositor, $exposure, $now, $window), $now);
    }

    /** Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with `slashCounterBond` or `releaseUnregistered`. */
    public function openBond(string $claimId, mixed $amount, string $depositor, mixed $exposure = null): Obj
    {
        [$snap, $view, $now] = $this->load($claimId, $depositor);
        if (isset($snap['bond'])) {
            return $this->replayOpen($snap['bond'], $depositor, $amount);
        }
        return $this->submit($this->planner->planOpen($view, $claimId, $amount, $depositor, $exposure, $now, null), $now);
    }

    /** Release a registered claim's bond once its challenge window has closed on the ledger's clock. */
    public function release(string $claimId): Obj
    {
        $gate = static function (array $bond, mixed $now) use ($claimId): void {
            $w = $bond['window'] ?? null;
            if (!$w) {
                throw new BondStoreError('unregistered', "bond $claimId has no registered claim; use releaseUnregistered for a counter-bond");
            }
            if (!($now > $w['registeredAt'] + $w['windowMs'])) {
                throw new BondStoreError('window_open', "the challenge window of $claimId closes at " . IntentWb::jsStr($w['registeredAt'] + $w['windowMs']));
            }
        };
        return $this->settle($claimId, fn(array $view, mixed $now): array => $this->planner->planRelease($view, $claimId, $now), $gate);
    }

    /** Release a bond that backs no claim (a counter-bond). */
    public function releaseUnregistered(string $claimId): Obj
    {
        $gate = static function (array $bond) use ($claimId): void {
            if (!empty($bond['window'])) {
                throw new BondStoreError('conflict', "bond $claimId backs a registered claim; use release");
            }
        };
        return $this->settle($claimId, fn(array $view, mixed $now): array => $this->planner->planRelease($view, $claimId, $now), $gate);
    }

    private function challengeGate(mixed $claim): \Closure
    {
        return static function (array $bond, mixed $now) use ($claim): void {
            $w = $bond['window'] ?? null;
            if (!$w) {
                throw new BondStoreError('unregistered', "bond {$bond['claimId']} has no registered claim");
            }
            if ($w['claimDigest'] !== BondSettlement::lenient($claim)) {
                throw new BondStoreError('claim_mismatch', "the claim is not the one registered for {$bond['claimId']}");
            }
            if (!($now <= $w['registeredAt'] + $w['windowMs'])) {
                throw new BondStoreError('window_closed', "the challenge window of {$bond['claimId']} closed at " . IntentWb::jsStr($w['registeredAt'] + $w['windowMs']));
            }
        };
    }

    /**
     * Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. `$p`: claimId, claim, fraudProof, grant, openSnapshot,
     * treasury and optionally challengerAccount, compensationAccount, splitPolicy.
     * @param array<string,mixed> $p
     */
    public function slashBond(array $p): Obj
    {
        return $this->settle((string)$p['claimId'], fn(array $view, mixed $now): array => $this->planner->planSlash($view, $p, $now), $this->challengeGate($p['claim'] ?? null));
    }

    /** Slash on a dispute the ledger re-adjudicates itself, inside the challenge window. @param array<string,mixed> $p */
    public function slashBondOnDispute(array $p): Obj
    {
        return $this->settle((string)$p['claimId'], fn(array $view, mixed $now): array => $this->planner->planSlashOnDispute($view, $p, $now), $this->challengeGate($p['claim'] ?? null));
    }

    /** Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated). @param array<string,mixed> $p */
    public function slashBondOnRevocation(array $p): Obj
    {
        $gate = static function (array $bond) use ($p): void {
            if (!empty($bond['window']) && $bond['window']['claimDigest'] !== BondSettlement::lenient($p['claim'] ?? null)) {
                throw new BondStoreError('claim_mismatch', "the claim is not the one registered for {$bond['claimId']}");
            }
        };
        return $this->settle((string)$p['claimId'], fn(array $view, mixed $now): array => $this->planner->planSlashOnRevocation($view, $p, $now), $gate);
    }

    /** Slash a challenger's counter-bond after a frivolous dispute. @param array<string,mixed> $p */
    public function slashCounterBond(array $p): Obj
    {
        return $this->settle((string)$p['counterBondId'], fn(array $view, mixed $now): array => $this->planner->planSlashCounterBond($view, $p, $now));
    }
}
