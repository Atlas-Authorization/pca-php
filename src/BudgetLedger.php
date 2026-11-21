<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Grants.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentHistory.php';
require_once __DIR__ . '/LedgerStore.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/StoreErrors.php';

/**
 * Durable aggregate budgets: the reference {@see KvBudgetLedger}, signed and anchored releases, and scoped admission.
 *
 * CLAIMED: NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE, given a ledger that is linearizable per key and durable. An accumulator with
 * `scope: principal | org | fleet` counts the events of EVERY session and delegated agent of that scope in ONE state keyed by the scope id,
 * so N sessions share one cap and a split across sessions or agents buys nothing. A reservation counts as soon as it is made; the ledger
 * refuses one whose post-value would pass the accumulator's `domain_max`, inside the same atomic step that records it.
 *
 * TWO PHASES, THREE STEPS: `reserve` (counted at once), `start` (recorded BEFORE the effect runs), then `commit` (the effect happened) or
 * `release` (it did not; a signed event, {@see signRelease}, that can be anchored in a transparency log, {@see anchorRelease}). `expire`
 * frees only a reservation that was never started: expiry needs no trusted clock. A release that never arrives only OVER-restricts.
 * {@see admitAggregateAction} refuses (`not_durable`) a ledger whose `durable` is not true, and denies `scope_unbound` when the caller
 * names no id for a scope the root uses. Events are Obj `{id, verb, resource, params, t, status}`; outcomes are arrays `['outcome' => ...]`.
 *
 * The pure transitions (`reserveInDoc` and the others) work on a document Obj `{v: 1, ver, events}`.
 */
final class BudgetLedgerDoc
{
    public const PREFIX = 'pca-budget-ledger/v1/';
    public const RELEASE_DOMAIN = "atlas-pca/budget-release/v1\0";
    public const RELEASE_REASONS = ['effect_failed', 'effect_not_run', 'denied_downstream', 'rollback'];

    public static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    /** A non-empty string of at most 256 UTF-16 units without control characters. */
    public static function idOk(mixed $s): bool
    {
        return is_string($s) && $s !== '' && Js::len($s) <= 256 && preg_match('/[\x00-\x1f]/', $s) !== 1;
    }

    /** The ledger key of a scope (`principal` | `org` | `fleet`) and its id. Injective: the id is percent-encoded. */
    public static function scopeKey(string $scope, mixed $id): string
    {
        if (!self::idOk($id)) {
            throw new BudgetLedgerError('invalid', 'a scope id is a non-empty string of at most 256 characters without control characters');
        }
        return $scope . '/' . Js::encodeURIComponent($id);
    }

    public static function emptyBudgetDoc(): Obj
    {
        return Obj::of(['v' => self::num(1), 'ver' => self::num(0), 'events' => []]);
    }

    public static function ver(Obj $doc): int
    {
        return (int)$doc->get('ver')->float();
    }

    private static function bump(Obj $doc): int
    {
        $v = self::ver($doc) + 1;
        $doc->set('ver', self::num($v));
        return $v;
    }

    /** A member of a request (an Obj or an associative array). */
    private static function m(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : (is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null);
    }

    private static function find(Obj $doc, mixed $id): ?Obj
    {
        foreach ($doc->get('events') as $e) {
            if ($e->get('id') === $id) {
                return $e;
            }
        }
        return null;
    }

    private static function sameEvent(Obj $a, Obj $b): bool
    {
        $k = static fn(Obj $e): string => Pca::hashCanonical(Obj::of(['id' => $e->get('id'), 'verb' => $e->get('verb'), 'resource' => $e->get('resource'),
            'params' => $e->get('params'), 't' => $e->get('t')]));
        return $k($a) === $k($b);
    }

    /**
     * Reserve `req.event` in `$doc` unless it would pass an accumulator's cap. The pure transition every store is, plus a per-key lock.
     * @param Obj|array<string,mixed> $req `{event, accumulators, schema?, expectedVersion?, expiresAt?}`
     * @return array<string,mixed>
     */
    public static function reserveInDoc(Obj $doc, mixed $req): array
    {
        $e = self::m($req, 'event');
        if (!($e instanceof Obj) || !self::idOk($e->get('id')) || !is_string($e->get('verb')) || !is_string($e->get('resource')) || !IntentWb::isSafeInt($e->get('t'))
            || !($e->get('params') instanceof Obj || (is_array($e->get('params')) && array_is_list($e->get('params'))))) {
            throw new \RangeException('reserve: a malformed event');
        }
        $accs = self::m($req, 'accumulators');
        if (!is_array($accs) || !array_is_list($accs)) {
            throw new \RangeException('reserve: accumulators must be an array');
        }
        $ev = self::m($req, 'expectedVersion');
        if ($ev !== null && (!IntentWb::isSafeInt($ev) || LedgerDoc::num($ev) < 0)) {
            throw new \RangeException('reserve: expectedVersion must be a non-negative safe integer');
        }
        $exp = self::m($req, 'expiresAt');
        if ($exp !== null && !IntentWb::isSafeInt($exp)) {
            throw new \RangeException('reserve: expiresAt must be a safe integer');
        }
        $schema = self::m($req, 'schema');
        $ver = self::ver($doc);
        $prior = self::find($doc, $e->get('id'));
        if ($prior !== null) {
            return self::sameEvent($prior, $e) ? ['outcome' => 'replayed', 'version' => $ver, 'status' => $prior->get('status')] : ['outcome' => 'id_conflict', 'version' => $ver];
        }
        if ($ev !== null && (int)LedgerDoc::num($ev) !== $ver) {
            return ['outcome' => 'conflict', 'version' => $ver];
        }
        $post = new Obj();
        foreach ($accs as $a) {
            if ($a->get('domain_max') === null) {
                throw new \RangeException('reserve: accumulator ' . IntentWb::jsStr($a->get('id')) . ' has no domain_max (the cap)');
            }
            if (!IntentV2::accSelects($a, $e->get('verb'), $schema)) {
                continue;
            }
            try {
                $p = IntentHistory::accPost($a, $doc->get('events'), $e->get('verb'), $e->get('params'), $e->get('t'), $schema);
            } catch (\Throwable $err) {
                throw new BudgetLedgerError('store_corrupt', $err->getMessage() ?: 'unreadable history');
            }
            if (!(is_finite((float)$p) && $p <= LedgerDoc::num($a->get('domain_max')))) {
                return ['outcome' => 'over_cap', 'version' => $ver, 'acc' => $a->get('id'), 'post' => $p, 'cap' => $a->get('domain_max')];
            }
            $post->set((string)$a->get('id'), self::num($p));
        }
        $entry = Obj::of(['id' => $e->get('id'), 'verb' => $e->get('verb'), 'resource' => $e->get('resource'), 'params' => Grants::deepCopy($e->get('params')),
            't' => $e->get('t'), 'status' => 'reserved']);
        if ($exp !== null) {
            $entry->set('exp', $exp);
        }
        $events = $doc->get('events');
        $events[] = $entry;
        $doc->set('events', $events);
        return ['outcome' => 'reserved', 'version' => self::bump($doc), 'post' => $post];
    }

    /** The effect is about to run: mark the reservation non-expirable. @return array<string,mixed> */
    public static function startInDoc(Obj $doc, mixed $id): array
    {
        $e = self::find($doc, $id);
        $ver = self::ver($doc);
        if ($e === null) {
            return ['outcome' => 'unknown', 'version' => $ver];
        }
        if ($e->get('status') === 'released') {
            return ['outcome' => 'refused', 'version' => $ver, 'status' => $e->get('status')];
        }
        if ($e->get('started') === true || $e->get('status') === 'committed') {
            return ['outcome' => 'replayed', 'version' => $ver];
        }
        $e->set('started', true);
        return ['outcome' => 'settled', 'version' => self::bump($doc)];
    }

    /** @return array<string,mixed> */
    public static function commitInDoc(Obj $doc, mixed $id): array
    {
        $e = self::find($doc, $id);
        $ver = self::ver($doc);
        if ($e === null) {
            return ['outcome' => 'unknown', 'version' => $ver];
        }
        if ($e->get('status') === 'committed') {
            return ['outcome' => 'replayed', 'version' => $ver];
        }
        if ($e->get('status') !== 'reserved') {
            return ['outcome' => 'refused', 'version' => $ver, 'status' => $e->get('status')];
        }
        $e->set('status', 'committed');
        return ['outcome' => 'settled', 'version' => self::bump($doc)];
    }

    /** @return array<string,mixed> */
    public static function releaseInDoc(Obj $doc, string $key, mixed $id, mixed $evidence = null): array
    {
        $e = self::find($doc, $id);
        $ver = self::ver($doc);
        if ($e === null) {
            return ['outcome' => 'unknown', 'version' => $ver];
        }
        if ($e->get('status') === 'released') {
            return ['outcome' => 'replayed', 'version' => $ver];
        }
        if ($e->get('status') !== 'reserved') {
            return ['outcome' => 'refused', 'version' => $ver, 'status' => $e->get('status')];
        }
        if ($evidence !== null && (self::m($evidence, 'key') !== $key || self::m($evidence, 'id') !== $id)) {
            throw new \RangeException('release: the evidence is for another reservation');
        }
        $e->set('status', 'released');
        if (Js::truthy($evidence)) {
            $e->set('rel', Grants::deepCopy(Sign::n($evidence)));
        }
        return ['outcome' => 'settled', 'version' => self::bump($doc)];
    }

    /** Release every open, never-started reservation whose `exp` is at or before `$now`. @return array{released:list<string>,version:int} */
    public static function expireInDoc(Obj $doc, mixed $now): array
    {
        if (!IntentWb::isSafeInt($now)) {
            throw new \RangeException('expire: now must be a safe integer');
        }
        $released = [];
        foreach ($doc->get('events') as $e) {
            if ($e->get('status') === 'reserved' && $e->get('started') !== true && $e->get('exp') !== null && LedgerDoc::num($e->get('exp')) <= LedgerDoc::num($now)) {
                $e->set('status', 'released');
                $e->set('rel', Obj::of(['reason' => 'expired', 'at' => $now]));
                $released[] = $e->get('id');
            }
        }
        if ($released !== []) {
            self::bump($doc);
        }
        return ['released' => $released, 'version' => self::ver($doc)];
    }

    public static function decode(?string $raw): Obj
    {
        if ($raw === null) {
            return self::emptyBudgetDoc();
        }
        $r = Json::parseLax($raw);
        if (!($r instanceof Obj) || LedgerDoc::num($r->get('v')) !== 1.0 || !IntentWb::isSafeInt($r->get('ver')) || !is_array($r->get('events')) || !array_is_list($r->get('events'))) {
            throw new BudgetLedgerError('store_corrupt', 'budget document has the wrong shape');
        }
        foreach ($r->get('events') as $e) {
            if (!($e instanceof Obj) || !is_string($e->get('id'))) {
                throw new BudgetLedgerError('store_corrupt', 'budget document has the wrong shape');
            }
        }
        return $r;
    }
}

/** The reference budget ledger's contract: `snapshot`, `reserve`, `start`, `commit`, `release`, `expire`, and whether the store is durable. */
interface BudgetLedger
{
    public function durable(): bool;

    /** @return array{version:int,events:list<Obj>} */
    public function snapshot(mixed $key): array;

    /** @return array<string,mixed> */
    public function reserve(mixed $key, mixed $req): array;

    /** @return array<string,mixed> */
    public function start(mixed $key, mixed $id): array;

    /** @return array<string,mixed> */
    public function commit(mixed $key, mixed $id): array;

    /** @return array<string,mixed> */
    public function release(mixed $key, mixed $id, mixed $evidence = null): array;

    /** @return array{released:list<string>,version:int} */
    public function expire(mixed $key, mixed $now): array;
}

/**
 * The reference budget ledger: one document per key in an atomic key/value store ({@see AtomicKv}), so every operation is one atomic
 * read-modify-write. `durable` is declared by the caller because a kv cannot tell: true only for a persistent one ({@see openDurable}).
 */
final class KvBudgetLedger implements BudgetLedger
{
    private readonly bool $isDurable;

    /** @param bool $durable declared by the caller: true only for a persistent kv */
    public function __construct(private readonly mixed $kv, mixed $durable)
    {
        if (!($kv instanceof AtomicKv)) {
            throw new BudgetLedgerError('store_missing', 'KvBudgetLedger needs an atomic kv');
        }
        if (!is_bool($durable)) {
            throw new BudgetLedgerError('invalid', 'say whether the kv is durable (true or false)');
        }
        $this->isDurable = $durable;
    }

    /** The reference ledger over a SQLite file in `$dir` (created when absent): crash-safe and multi-process safe on one host. */
    public static function openDurable(string $dir): self
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new BudgetLedgerError('store_missing', 'cannot create the ledger directory');
        }
        $kv = new PdoAtomicKv(new \PDO('sqlite:' . rtrim($dir, '/') . '/budget-ledger.db'));
        $kv->createTable();
        return new self($kv, true);
    }

    public function durable(): bool
    {
        return $this->isDurable;
    }

    private function k(mixed $key): string
    {
        if (!BudgetLedgerDoc::idOk($key)) {
            throw new \RangeException('a ledger key is a non-empty string without control characters');
        }
        return BudgetLedgerDoc::PREFIX . $key;
    }

    /** @param callable(Obj):mixed $fn @param callable(mixed):bool $writes */
    private function txn(mixed $key, callable $fn, callable $writes): mixed
    {
        $out = null;
        $this->kv->update($this->k($key), function (?string $prev) use (&$out, $fn, $writes): ?string {
            $d = BudgetLedgerDoc::decode($prev);
            $out = $fn($d);
            return $writes($out) ? Json::canonicalizeLenient($d) : null;
        });
        return $out;
    }

    public function snapshot(mixed $key): array
    {
        $d = BudgetLedgerDoc::decode($this->kv->get($this->k($key)));
        return ['version' => BudgetLedgerDoc::ver($d), 'events' => $d->get('events')];
    }

    public function reserve(mixed $key, mixed $req): array
    {
        return $this->txn($key, static fn(Obj $d) => BudgetLedgerDoc::reserveInDoc($d, $req), static fn(array $r): bool => $r['outcome'] === 'reserved');
    }

    public function start(mixed $key, mixed $id): array
    {
        return $this->txn($key, static fn(Obj $d) => BudgetLedgerDoc::startInDoc($d, $id), static fn(array $r): bool => $r['outcome'] === 'settled');
    }

    public function commit(mixed $key, mixed $id): array
    {
        return $this->txn($key, static fn(Obj $d) => BudgetLedgerDoc::commitInDoc($d, $id), static fn(array $r): bool => $r['outcome'] === 'settled');
    }

    public function release(mixed $key, mixed $id, mixed $evidence = null): array
    {
        return $this->txn($key, static fn(Obj $d) => BudgetLedgerDoc::releaseInDoc($d, $key, $id, $evidence), static fn(array $r): bool => $r['outcome'] === 'settled');
    }

    public function expire(mixed $key, mixed $now): array
    {
        return $this->txn($key, static fn(Obj $d) => BudgetLedgerDoc::expireInDoc($d, $now), static fn(array $r): bool => $r['released'] !== []);
    }
}

/** Signed, anchored releases and scoped admission over a {@see BudgetLedger}. */
final class BudgetRelease
{
    private static function message(Obj $r): string
    {
        $body = new Obj();
        foreach (['v', 'key', 'id', 'reason', 'at', 'signer'] as $k) {
            $body->set($k, $r->get($k));
        }
        return BudgetLedgerDoc::RELEASE_DOMAIN . Json::canonicalizeNative($body);
    }

    /**
     * A signed statement by the releaser that a reservation's effect did NOT happen (`$reason`: effect_failed, effect_not_run,
     * denied_downstream or rollback).
     */
    public static function signRelease(mixed $key, mixed $id, mixed $reason, mixed $at, KeyPair $secret): Obj
    {
        if (!in_array($reason, BudgetLedgerDoc::RELEASE_REASONS, true) || !IntentWb::isSafeInt($at) || !BudgetLedgerDoc::idOk($key) || !BudgetLedgerDoc::idOk($id)) {
            throw new \RangeException('signRelease: a malformed release');
        }
        $base = Obj::of(['v' => BudgetLedgerDoc::num(1), 'key' => $key, 'id' => $id, 'reason' => $reason, 'at' => Sign::n($at), 'signer' => $secret->public]);
        $base->set('sig', Pca::b64u($secret->sign(self::message($base))));
        return $base;
    }

    /** True iff `$r` is well formed and signed by `$expectedSigner` over exactly its content. Never throws. */
    public static function verifyRelease(mixed $r, mixed $expectedSigner): bool
    {
        try {
            if (!($r instanceof Obj) || LedgerDoc::num($r->get('v')) !== 1.0 || $r->get('signer') !== $expectedSigner || !in_array($r->get('reason'), BudgetLedgerDoc::RELEASE_REASONS, true)
                || !IntentWb::isSafeInt($r->get('at')) || !BudgetLedgerDoc::idOk($r->get('key')) || !BudgetLedgerDoc::idOk($r->get('id'))
                || Pca::decodeB64uStrict($r->get('sig'), 64) === null || !is_string($expectedSigner)) {
                return false;
            }
            return Pca::verifyEd25519B64u($expectedSigner, self::message($r), $r->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    public static function releaseDigest(mixed $r): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/budget-release-ref/v1', 'r' => $r]));
    }

    /** The log leaf of a release. */
    public static function releaseCommit(mixed $r): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/budget-release-leaf/v1', 'digest' => self::releaseDigest($r)]));
    }

    /** Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index. */
    public static function anchorRelease(LedgerStore $log, mixed $r): int
    {
        $commit = self::releaseCommit($r);
        for ($i = 0; $i < 64; $i++) {
            $size = $log->size();
            $o = $log->append($size, [$commit]);
            if ($o['outcome'] === 'appended' || $o['outcome'] === 'replayed') {
                return $size;
            }
        }
        throw new BudgetLedgerError('conflict_exhausted', 'could not anchor the release: the log kept moving');
    }

    /** The ledger key of an accumulator for this admission, or null when it is session-scoped. Throws `scope_unbound`. */
    public static function aggregateKeyOf(mixed $a, mixed $ids): ?string
    {
        $scope = $a->get('scope');
        if ($scope === null || $scope === 'session') {
            return null;
        }
        $i = $ids instanceof Obj ? $ids->get((string)$scope) : (is_array($ids) ? ($ids[(string)$scope] ?? null) : null);
        if ($i === null) {
            throw new BudgetLedgerError('scope_unbound', 'accumulator ' . IntentWb::jsStr($a->get('id')) . ' is ' . IntentWb::jsStr($scope) . '-scoped but no ' . IntentWb::jsStr($scope) . ' id was given');
        }
        return BudgetLedgerDoc::scopeKey((string)$scope, $i);
    }

    /** A member of a reservation (an Obj or an array `{key, id}`). */
    private static function rm(mixed $r, string $k): mixed
    {
        return $r instanceof Obj ? $r->get($k) : (is_array($r) ? ($r[$k] ?? null) : null);
    }

    private static function jsNum(mixed $x): string
    {
        return IntentWb::jsStr($x instanceof Num ? $x->float() : $x);
    }

    /**
     * Admit one action against every non-session accumulator of the root, atomically per key: read each key's snapshot and compute the
     * pre-states, `verify(state)` (the host's verifier; returns a verdict with `allow`), then on allow `reserve` in every key with the
     * snapshot's version. A moved key repeats from the start; a key over its cap denies and releases what the earlier keys reserved.
     * Refuses (throws `not_durable`) a ledger that is not durable.
     * @param Obj|array<string,mixed> $ids scope => id
     * @param list<Obj> $accumulators
     * @param callable(Obj):mixed $verify
     * @return array<string,mixed> `['admitted' => true, 'verdict', 'reservations', 'state']` or `['admitted' => false, 'reason', 'verdict'?]`
     */
    public static function admitAggregateAction(BudgetLedger $ledger, mixed $ids, array $accumulators, mixed $schema, Obj $event, callable $verify,
        mixed $expiresAt = null, mixed $maxAttempts = null): array
    {
        $scoped = array_values(array_filter($accumulators, static fn(Obj $a): bool => $a->get('scope') !== null && $a->get('scope') !== 'session'));
        if ($scoped !== [] && $ledger->durable() !== true) {
            throw new BudgetLedgerError('not_durable', 'a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)');
        }
        $byKey = [];
        try {
            foreach ($scoped as $a) {
                $byKey[(string)self::aggregateKeyOf($a, $ids)][] = $a;
            }
        } catch (BudgetLedgerError $e) {
            if ($e->codeName === 'scope_unbound') {
                return ['admitted' => false, 'reason' => 'scope_unbound: ' . $e->getMessage()];
            }
            throw $e;
        }
        $keys = array_map('strval', array_keys($byKey));
        usort($keys, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b)); // JS default sort: UTF-16 code units
        $limit = $maxAttempts === null ? 256 : (int)LedgerDoc::num($maxAttempts);
        for ($attempt = 0; $attempt < $limit; $attempt++) {
            $snaps = [];
            $state = new Obj();
            foreach ($keys as $k) {
                $s = $ledger->snapshot($k);
                $snaps[$k] = $s;
                $ctx = IntentHistory::accContextFor(Obj::of(['accumulators' => $byKey[$k], 'monitors' => []]), $s['events'], $event, $schema);
                foreach ($ctx['state']->keys() as $sk) {
                    $state->set($sk, $ctx['state']->get($sk));
                }
            }
            $verdict = $verify($state);
            if (!(is_array($verdict) ? ($verdict['allow'] ?? false) : ($verdict instanceof Obj && $verdict->get('allow') === true))) {
                return ['admitted' => false, 'reason' => 'verifier denied', 'verdict' => $verdict];
            }
            $done = [];
            $moved = false;
            foreach ($keys as $k) {
                $req = ['event' => $event, 'accumulators' => $byKey[$k], 'schema' => $schema, 'expectedVersion' => $snaps[$k]['version']];
                if ($expiresAt !== null) {
                    $req['expiresAt'] = $expiresAt;
                }
                $r = $ledger->reserve($k, $req);
                if ($r['outcome'] === 'reserved' || ($r['outcome'] === 'replayed' && ($r['status'] ?? null) === 'reserved')) {
                    $done[] = ['key' => $k, 'id' => $event->get('id')];
                    continue;
                }
                foreach ($done as $d) {
                    $ledger->release($d['key'], $d['id']);
                }
                if ($r['outcome'] === 'conflict') {
                    $moved = true;
                    break;
                }
                $why = $r['outcome'] === 'over_cap' ? 'over_cap: ' . IntentWb::jsStr($r['acc']) . ' would reach ' . self::jsNum($r['post']) . ' (cap ' . self::jsNum($r['cap']) . ')'
                    : ($r['outcome'] === 'replayed' ? 'already ' . IntentWb::jsStr($r['status'] ?? null) : $r['outcome']);
                return ['admitted' => false, 'reason' => "aggregate: $why", 'verdict' => $verdict];
            }
            if (!$moved) {
                return ['admitted' => true, 'verdict' => $verdict, 'reservations' => $done, 'state' => $state];
            }
        }
        throw new BudgetLedgerError('conflict_exhausted', 'the aggregate kept moving under this admission');
    }

    /**
     * BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (it was released or expired in
     * the meantime): the effect must NOT run then.
     * @param list<array{key:string,id:string}> $reservations
     */
    public static function startAggregate(BudgetLedger $ledger, array $reservations): bool
    {
        foreach ($reservations as $r) {
            $o = $ledger->start(self::rm($r, 'key'), self::rm($r, 'id'));
            if ($o['outcome'] !== 'settled' && $o['outcome'] !== 'replayed') {
                return false;
            }
        }
        return true;
    }

    /**
     * After the effect: `committed` (it happened) or `released` (it did not; a signed `$evidence` is stored and can be anchored).
     * @param list<array{key:string,id:string}> $reservations
     * @param ?callable(array):mixed $evidence
     * @return list<array<string,mixed>>
     */
    public static function settleAggregate(BudgetLedger $ledger, array $reservations, string $status, ?callable $evidence = null): array
    {
        $out = [];
        foreach ($reservations as $r) {
            $key = self::rm($r, 'key');
            $id = self::rm($r, 'id');
            $out[] = $status === 'committed' ? $ledger->commit($key, $id) : $ledger->release($key, $id, $evidence ? $evidence($r) : null);
        }
        return $out;
    }
}
