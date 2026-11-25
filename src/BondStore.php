<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/BondSettlement.php';
require_once __DIR__ . '/StoreErrors.php';

/**
 * The persistence contract for bond settlement: `read(claimId, depositor?)`, `commit(plan, observedAt)` and `deposit(account, amount)`.
 * `commit` applies a plan ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance movement, the new phase and the signed
 * record become visible together; committing the same transition twice is a replay (the stored record, nothing moved). It never throws
 * for a refused plan (that is a `conflict`), only when the store itself fails. INTERNAL ACCOUNTING ONLY: nothing here moves money.
 */
interface BondStore
{
    /** @return array{bond?:array<string,mixed>,balances:list<array{0:string,1:float|int}>,openTotals:array{count:int,sum:float|int},highWater:float|int} */
    public function read(string $claimId, ?string $depositor = null): array;

    /** @return array{outcome:string,record?:Obj,reason?:string,current?:string} */
    public function commit(mixed $plan, mixed $observedAt): array;

    /** Atomically credit `$account` with `$amount` (a positive finite number). Returns the new balance. */
    public function deposit(mixed $account, mixed $amount): float|int;
}

/**
 * The reference transition function of a bond store (pure): a document is
 * `['balances' => array<string,number>, 'bonds' => array<string,row>, 'highWater' => number]`, a row
 * `['claimId', 'amount', 'depositor', 'status', 'window'?, 'records' => list<Obj>]`.
 */
final class BondStoreDoc
{
    private const PHASES = ['open', 'released', 'slashed'];

    /** @return array{balances:array<string,float|int>,bonds:array<string,array<string,mixed>>,highWater:float|int} */
    public static function emptyBondDoc(): array
    {
        return ['balances' => [], 'bonds' => [], 'highWater' => 0];
    }

    public static function isBondStore(mixed $s): bool
    {
        return $s instanceof BondStore;
    }

    /** Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored). */
    public static function sameSettlement(mixed $a, mixed $b): bool
    {
        $g = static fn(mixed $o, string $k): mixed => $o instanceof Obj ? $o->get($k) : (is_array($o) ? ($o[$k] ?? null) : null);
        $eq = static function (mixed $x, mixed $y): bool {
            $fx = BondSettlement::fin($x);
            $fy = BondSettlement::fin($y);
            return $fx !== null || $fy !== null ? $fx !== null && $fy !== null && $fx === $fy : $x === $y;
        };
        return $eq($g($a, 'claimId'), $g($b, 'claimId')) && $eq($g($a, 'action'), $g($b, 'action')) && $eq($g($a, 'amount'), $g($b, 'amount'))
            && $eq($g($a, 'from'), $g($b, 'from')) && $eq($g($a, 'to'), $g($b, 'to')) && $eq($g($a, 'evidenceDigest'), $g($b, 'evidenceDigest'))
            && BondSettlement::lenient($g($a, 'split')) === BondSettlement::lenient($g($b, 'split'));
    }

    /** registeredAt is the first call's. */
    private static function sameWindow(?array $a, ?array $b): bool
    {
        if ($a === null || $b === null) {
            return $a === $b;
        }
        return BondSettlement::fin($a['windowMs'] ?? null) === BondSettlement::fin($b['windowMs'] ?? null) && ($a['claimDigest'] ?? null) === ($b['claimDigest'] ?? null);
    }

    /** A plan (an Obj of the wire form, or an array) as the array the transition reads. @return array<string,mixed> */
    public static function planOf(mixed $plan): array
    {
        $g = static fn(string $k): mixed => $plan instanceof Obj ? $plan->get($k) : (is_array($plan) ? ($plan[$k] ?? null) : null);
        $num = static fn(mixed $x): mixed => $x instanceof Num ? ($x->isInt() ? $x->int() : $x->float()) : $x;
        $open = $g('open');
        if ($open instanceof Obj) {
            $o = [];
            foreach ($open->keys() as $k) {
                $o[$k] = $k === 'window' && $open->get($k) instanceof Obj ? Sign::plain($open->get($k)) : $num($open->get($k));
            }
            $open = $o;
        }
        $moves = $g('moves');
        if (is_array($moves)) {
            $moves = array_map(static fn(mixed $m): array => $m instanceof Obj ? ['account' => $m->get('account'), 'op' => $m->get('op'), 'amount' => $num($m->get('amount'))] : (array)$m, $moves);
        }
        return ['claimId' => $g('claimId'), 'expect' => $g('expect'), 'next' => $g('next'), 'open' => $open, 'moves' => $moves, 'record' => $g('record')];
    }

    /**
     * Apply `$plan` to `$doc` following the {@see BondStore::commit} rules. Mutates `$doc` ONLY on `committed` (the moves are checked on an
     * overlay first).
     * @param array<string,mixed> $doc
     * @return array{outcome:string,record?:Obj,reason?:string,current?:string}
     */
    public static function commitBondPlan(array &$doc, mixed $plan, mixed $observedAt): array
    {
        $plan = self::planOf($plan);
        $claimId = (string)$plan['claimId'];
        $bond = $doc['bonds'][$claimId] ?? null;
        $cur = $bond !== null ? $bond['status'] : 'none';
        $o = $plan['open'];
        if ($plan['expect'] === 'none') {
            if (!$o || $plan['next'] !== 'open') {
                return ['outcome' => 'conflict', 'reason' => 'malformed open plan', 'current' => $cur];
            }
            if ($bond !== null) {
                $same = $bond['depositor'] === $o['depositor'] && BondSettlement::fin($bond['amount']) === BondSettlement::fin($o['amount'])
                    && self::sameWindow($bond['window'] ?? null, $o['window'] ?? null) && $bond['records'] !== [] && self::sameSettlement($bond['records'][0], $plan['record']);
                return $same ? ['outcome' => 'replayed', 'record' => $bond['records'][0]]
                    : ['outcome' => 'conflict', 'reason' => "bond $claimId already exists", 'current' => $bond['status']];
            }
            $count = 0;
            $total = 0.0;
            foreach ($doc['bonds'] as $b) {
                if ($b['status'] === 'open' && $b['depositor'] === $o['depositor']) {
                    $count++;
                    $total += $b['amount'];
                }
            }
            if (!(is_finite((float)$count) && $count + 1 <= $o['maxOpenClaims'])) {
                return ['outcome' => 'conflict', 'reason' => 'depositor open-claim cap reached', 'current' => 'none'];
            }
            if (!(is_finite((float)($total + $o['amount'])) && $total + $o['amount'] <= $o['maxOpenAmount'])) {
                return ['outcome' => 'conflict', 'reason' => 'depositor aggregate open-bond cap exceeded', 'current' => 'none'];
            }
        } elseif ($bond === null) {
            return ['outcome' => 'conflict', 'reason' => "no bond for $claimId", 'current' => 'none'];
        } elseif ($bond['status'] !== $plan['expect']) {
            $last = $bond['records'] === [] ? null : $bond['records'][count($bond['records']) - 1];
            if ($bond['status'] === $plan['next'] && $last !== null && self::sameSettlement($last, $plan['record'])) {
                return ['outcome' => 'replayed', 'record' => $last];
            }
            return ['outcome' => 'conflict', 'reason' => "bond $claimId is already {$bond['status']}", 'current' => $bond['status']];
        }
        try {
            $next = BondSettlement::applyBondMoves(static fn(string $a) => $doc['balances'][$a] ?? 0, $plan['moves']);
        } catch (\RuntimeException $e) {
            return ['outcome' => 'conflict', 'reason' => $e->getMessage(), 'current' => $cur];
        }
        foreach ($next as $a => $v) {
            $doc['balances'][(string)$a] = $v;
        }
        if ($o) {
            $row = ['claimId' => $claimId, 'amount' => $o['amount'], 'depositor' => $o['depositor'], 'status' => 'open'];
            if (!empty($o['window'])) {
                $row['window'] = $o['window'];
            }
            $row['records'] = [$plan['record']];
            $doc['bonds'][$claimId] = $row;
        } else {
            $doc['bonds'][$claimId]['status'] = $plan['next'];
            $doc['bonds'][$claimId]['records'][] = $plan['record'];
        }
        $obs = BondSettlement::fin($observedAt);
        $doc['highWater'] = max($doc['highWater'], $obs ?? 0);
        return ['outcome' => 'committed', 'record' => $plan['record']];
    }

    /**
     * What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark.
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    public static function snapshotOf(array $doc, string $claimId, ?string $depositor = null): array
    {
        $bond = $doc['bonds'][$claimId] ?? null;
        $count = 0;
        $total = 0;
        $balances = [];
        if ($depositor !== null) {
            foreach ($doc['bonds'] as $b) {
                if ($b['status'] === 'open' && $b['depositor'] === $depositor) {
                    $count++;
                    $total += $b['amount'];
                }
            }
            $balances[] = [$depositor, $doc['balances'][$depositor] ?? 0];
        }
        $out = [];
        if ($bond !== null) {
            $out['bond'] = $bond;
        }
        return $out + ['balances' => $balances, 'openTotals' => ['count' => $count, 'sum' => $total], 'highWater' => $doc['highWater']];
    }

    private static function bad(string $why): BondStoreError
    {
        return new BondStoreError('store_corrupt', $why);
    }

    /** @return array<string,mixed> */
    public static function decodeDoc(?string $raw): array
    {
        if ($raw === null) {
            return self::emptyBondDoc();
        }
        $r = Json::parseLax($raw);
        $f = BondSettlement::fin(...);
        if (!($r instanceof Obj) || $f($r->get('v')) !== 1.0 || !is_array($r->get('balances')) || !array_is_list($r->get('balances'))
            || !is_array($r->get('bonds')) || !array_is_list($r->get('bonds')) || !($r->get('highWater') instanceof Num)) {
            throw self::bad('bond document has the wrong shape');
        }
        $doc = self::emptyBondDoc();
        $hw = $f($r->get('highWater'));
        if ($hw === null || $hw < 0) {
            throw self::bad('highWater is not a non-negative number');
        }
        $doc['highWater'] = $hw;
        foreach ($r->get('balances') as $e) {
            if (!is_array($e) || !array_is_list($e) || count($e) !== 2 || !is_string($e[0]) || $f($e[1]) === null || $f($e[1]) < 0) {
                throw self::bad('malformed balance entry');
            }
            $doc['balances'][$e[0]] = $f($e[1]);
        }
        foreach ($r->get('bonds') as $b) {
            if (!($b instanceof Obj) || !is_string($b->get('claimId')) || !is_string($b->get('depositor')) || $f($b->get('amount')) === null
                || !in_array($b->get('status'), self::PHASES, true) || !is_array($b->get('records')) || !array_is_list($b->get('records')) || $b->get('records') === []) {
                throw self::bad('malformed bond row');
            }
            if (isset($doc['bonds'][$b->get('claimId')])) {
                throw self::bad('duplicate bond row');
            }
            $row = ['claimId' => $b->get('claimId'), 'amount' => $f($b->get('amount')), 'depositor' => $b->get('depositor'), 'status' => $b->get('status')];
            if ($b->has('window')) {
                $w = Sign::plain($b->get('window'));
                $row['window'] = is_array($w) ? $w : [];
            }
            $row['records'] = $b->get('records');
            $doc['bonds'][$b->get('claimId')] = $row;
        }
        return $doc;
    }

    /** @param array<string,mixed> $d */
    public static function encodeDoc(array $d): string
    {
        $balances = [];
        foreach ($d['balances'] as $a => $v) {
            $balances[] = [(string)$a, $v];
        }
        return Json::canonicalizeLenient(Sign::n(['v' => 1, 'balances' => $balances, 'bonds' => array_values($d['bonds']), 'highWater' => $d['highWater']]));
    }
}

/**
 * The reference bond store: the whole book is one document in an atomic key/value store ({@see AtomicKv}), so every transition is a single
 * atomic read-modify-write. LIMIT: one document, rewritten on every commit; a production deployment implements {@see BondStore} over a
 * database transaction.
 */
final class KvBondStore implements BondStore
{
    public const DOC_KEY = 'pca-bond-store/v1';

    public function __construct(private readonly AtomicKv $kv, private readonly string $key = self::DOC_KEY)
    {
    }

    public function read(string $claimId, ?string $depositor = null): array
    {
        return BondStoreDoc::snapshotOf(BondStoreDoc::decodeDoc($this->kv->get($this->key)), $claimId, $depositor);
    }

    public function commit(mixed $plan, mixed $observedAt): array
    {
        $out = null;
        $this->kv->update($this->key, function (?string $prev) use (&$out, $plan, $observedAt): ?string {
            $doc = BondStoreDoc::decodeDoc($prev);
            $out = BondStoreDoc::commitBondPlan($doc, $plan, $observedAt);
            return $out['outcome'] === 'committed' ? BondStoreDoc::encodeDoc($doc) : null; // null: leave the key untouched
        });
        return $out;
    }

    public function deposit(mixed $account, mixed $amount): float|int
    {
        if (!is_string($account) || $account === '') {
            throw new \RangeException('deposit: account is required');
        }
        $amt = BondSettlement::fin($amount);
        if ($amt === null || $amt <= 0) {
            throw new \RangeException('deposit: amount must be a positive finite number');
        }
        $res = null;
        $this->kv->update($this->key, function (?string $prev) use (&$res, $account, $amt): string {
            $doc = BondStoreDoc::decodeDoc($prev);
            $bal = BondSettlement::applyBondMoves(static fn(string $a) => $doc['balances'][$a] ?? 0, [['account' => $account, 'op' => 'credit', 'amount' => $amt]])[$account];
            $doc['balances'][$account] = $bal;
            $res = $bal;
            return BondStoreDoc::encodeDoc($doc);
        });
        return $res;
    }
}
