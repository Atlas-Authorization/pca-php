<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/KvDoc.php';
require_once __DIR__ . '/Ledger.php';
require_once __DIR__ . '/LedgerLog.php';
require_once __DIR__ . '/StoreErrors.php';

/**
 * The persistence contract of a durable transparency ledger: `append` and `appendCheckpoint` are compare-and-swap on the current
 * length (all entries of a batch or none, so two writers never assign one index twice and a log never has holes); committing the
 * same batch again at the same position is a replay. Outcomes are `['outcome' => 'appended' | 'replayed' | 'conflict', ...]`.
 */
interface LedgerStore
{
    public function size(): int;

    /** @return list<string> the commits in [from, to) */
    public function read(mixed $from, mixed $to): array;

    /** @param list<string> $commits @return array{outcome:string,size:int} */
    public function append(mixed $expectedSize, mixed $commits): array;

    public function checkpointCount(): int;

    /** @return list<Obj> the checkpoints from position `$from` */
    public function checkpoints(mixed $from = 0): array;

    /** @return array{outcome:string,count:int,reason?:string} */
    public function appendCheckpoint(mixed $expectedCount, mixed $cp): array;
}

/**
 * The pure transitions of the reference store over a document `['commits' => list<string>, 'checkpoints' => list<Obj>]`
 * (each checkpoint is `{sth, proof?}`): every store is one of these plus a lock.
 */
final class LedgerDoc
{
    private const MAX_SAFE = 9007199254740991.0;

    private static function isNegZero(mixed $v): bool
    {
        return ($v instanceof Num && $v->lexeme === '-0') || (is_float($v) && $v === 0.0 && fdiv(1, $v) < 0);
    }

    public static function isCommit(mixed $c): bool
    {
        return is_string($c) && $c !== '';
    }

    /** A JSON number (Num or native, never a bool) as a float. */
    public static function num(mixed $x): ?float
    {
        return $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
    }

    public static function safeInt(mixed $x): bool
    {
        $v = self::num($x);
        return $v !== null && is_finite($v) && floor($v) === $v && abs($v) <= self::MAX_SAFE;
    }

    /** @return array{commits:list<string>,checkpoints:list<Obj>} */
    public static function emptyLedgerDoc(): array
    {
        return ['commits' => [], 'checkpoints' => []];
    }

    /**
     * Append `$commits` to `$doc` iff it has exactly `$expectedSize` entries (all or none); a batch already stored there is a replay.
     * @param array{commits:list<string>,checkpoints:list<Obj>} $doc
     * @return array{outcome:string,size:int}
     */
    public static function appendToLedgerDoc(array &$doc, mixed $expectedSize, mixed $commits): array
    {
        if (!self::safeInt($expectedSize) || self::num($expectedSize) < 0) {
            throw new \RangeException('append: expectedSize must be a non-negative safe integer');
        }
        if (!is_array($commits) || $commits === [] || !array_is_list($commits) || array_filter($commits, static fn($c) => !self::isCommit($c)) !== []) {
            throw new \RangeException('append: commits must be a non-empty array of non-empty strings');
        }
        $exp = (int)self::num($expectedSize);
        $size = count($doc['commits']);
        if ($exp < $size) {
            $same = true;
            foreach ($commits as $i => $c) {
                if (!($i + $exp < $size && $doc['commits'][$exp + $i] === $c)) {
                    $same = false;
                    break;
                }
            }
            return ['outcome' => $same ? 'replayed' : 'conflict', 'size' => $size];
        }
        if ($exp > $size) {
            return ['outcome' => 'conflict', 'size' => $size];
        }
        array_push($doc['commits'], ...$commits);
        return ['outcome' => 'appended', 'size' => count($doc['commits'])];
    }

    /**
     * @param array{commits:list<string>,checkpoints:list<Obj>} $doc
     * @return array{outcome:string,count:int,reason?:string}
     */
    public static function checkpointToLedgerDoc(array &$doc, mixed $expectedCount, mixed $cp): array
    {
        if (!self::safeInt($expectedCount) || self::num($expectedCount) < 0) {
            throw new \RangeException('appendCheckpoint: expectedCount must be a non-negative safe integer');
        }
        $exp = (int)self::num($expectedCount);
        $count = count($doc['checkpoints']);
        if ($exp < $count) {
            if (self::digest($doc['checkpoints'][$exp]) === self::digest($cp)) {
                return ['outcome' => 'replayed', 'count' => $count];
            }
            return ['outcome' => 'conflict', 'count' => $count, 'reason' => 'another checkpoint holds that position'];
        }
        if ($exp > $count) {
            return ['outcome' => 'conflict', 'count' => $count, 'reason' => 'the checkpoint position is ahead of the log'];
        }
        $sth = $cp instanceof Obj ? $cp->get('sth') : null;
        if (!($sth instanceof Obj) || !self::safeInt($sth->get('size')) || self::num($sth->get('size')) < 0 || self::isNegZero($sth->get('size')) || !is_string($sth->get('root'))) {
            return ['outcome' => 'conflict', 'count' => $count, 'reason' => 'malformed checkpoint'];
        }
        if (self::num($sth->get('size')) > count($doc['commits'])) {
            return ['outcome' => 'conflict', 'count' => $count, 'reason' => 'the checkpoint is beyond the end of the log'];
        }
        $last = $count > 0 ? $doc['checkpoints'][$count - 1]->get('sth') : null;
        if ($last instanceof Obj && (self::num($sth->get('size')) < self::num($last->get('size'))
            || (self::num($sth->get('size')) === self::num($last->get('size')) && $sth->get('root') !== $last->get('root')))) {
            return ['outcome' => 'conflict', 'count' => $count, 'reason' => 'the checkpoint does not extend the previous one'];
        }
        $doc['checkpoints'][] = $cp;
        return ['outcome' => 'appended', 'count' => count($doc['checkpoints'])];
    }

    private static function digest(mixed $v): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient($v), true)); // server-only digest, as the reference
    }
}

/**
 * The reference ledger store: the whole log is one document in an atomic key/value store ({@see AtomicKv}), so every write is one
 * atomic read-modify-write. LIMIT: rewritten on every write; a production log lives in a database with a unique index on the position.
 */
final class KvLedgerStore implements LedgerStore
{
    public const DOC_KEY = 'pca-ledger-store/v1';

    public function __construct(private readonly AtomicKv $kv, private readonly string $key = self::DOC_KEY)
    {
    }

    /** @return array{commits:list<string>,checkpoints:list<Obj>} */
    private static function decode(?string $raw): array
    {
        if ($raw === null) {
            return LedgerDoc::emptyLedgerDoc();
        }
        $d = Json::parseLax($raw);
        if (!($d instanceof Obj) || LedgerDoc::num($d->get('v')) !== 1.0 || !is_array($d->get('commits')) || !array_is_list($d->get('commits'))
            || !is_array($d->get('checkpoints')) || !array_is_list($d->get('checkpoints'))
            || array_filter($d->get('commits'), static fn($c) => !LedgerDoc::isCommit($c)) !== []) {
            throw new LedgerStoreError('store_corrupt', 'ledger document has the wrong shape');
        }
        foreach ($d->get('checkpoints') as $c) {
            if (!($c instanceof Obj) || !($c->get('sth') instanceof Obj)) {
                throw new LedgerStoreError('store_corrupt', 'malformed checkpoint entry');
            }
        }
        return ['commits' => $d->get('commits'), 'checkpoints' => $d->get('checkpoints')];
    }

    private static function encode(array $doc): string
    {
        return Json::canonicalizeLenient(Obj::of(['v' => new Num('1'), 'commits' => $doc['commits'], 'checkpoints' => $doc['checkpoints']]));
    }

    private function doc(): array
    {
        return self::decode($this->kv->get($this->key));
    }

    public function size(): int
    {
        return count($this->doc()['commits']);
    }

    public function read(mixed $from, mixed $to): array
    {
        $d = $this->doc();
        if (!LedgerDoc::safeInt($from) || !LedgerDoc::safeInt($to) || LedgerDoc::num($from) < 0 || LedgerDoc::num($from) > LedgerDoc::num($to)
            || LedgerDoc::num($to) > count($d['commits'])) {
            throw new \RangeException('read: range is not inside the log');
        }
        return array_slice($d['commits'], (int)LedgerDoc::num($from), (int)LedgerDoc::num($to) - (int)LedgerDoc::num($from));
    }

    public function append(mixed $expectedSize, mixed $commits): array
    {
        $out = null;
        $this->kv->update($this->key, function (?string $prev) use (&$out, $expectedSize, $commits): ?string {
            $d = self::decode($prev);
            $out = LedgerDoc::appendToLedgerDoc($d, $expectedSize, $commits);
            return $out['outcome'] === 'appended' ? self::encode($d) : null;
        });
        return $out;
    }

    public function checkpointCount(): int
    {
        return count($this->doc()['checkpoints']);
    }

    public function checkpoints(mixed $from = 0): array
    {
        $d = $this->doc();
        if (!LedgerDoc::safeInt($from) || LedgerDoc::num($from) < 0 || LedgerDoc::num($from) > count($d['checkpoints'])) {
            throw new \RangeException('checkpoints: from is not inside the list');
        }
        return array_slice($d['checkpoints'], (int)LedgerDoc::num($from));
    }

    public function appendCheckpoint(mixed $expectedCount, mixed $cp): array
    {
        $out = null;
        $this->kv->update($this->key, function (?string $prev) use (&$out, $expectedCount, $cp): ?string {
            $d = self::decode($prev);
            $out = LedgerDoc::checkpointToLedgerDoc($d, $expectedCount, $cp);
            return $out['outcome'] === 'appended' ? self::encode($d) : null;
        });
        return $out;
    }
}

/**
 * A transparency log over a {@see LedgerStore}, with guardian-signed checkpoints. Open it with {@see open}: the constructor is
 * private so that no instance exists whose state was not verified against the stored checkpoints.
 *
 * `open` rebuilds the Merkle tree from the stored commits and checks it against EVERY stored checkpoint (guardian signature, signed
 * `prev_root` chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each root): a store that lost
 * entries after a checkpoint (`rollback`), edited an entry (`tamper`) or holds a forged checkpoint FAILS CLOSED with a typed error.
 * `checkpoint` refuses to sign a head that is not consistent with the previous one.
 */
final class StoredLedger
{
    /** @var list<Obj> */
    private array $cps;

    private function __construct(
        private readonly LedgerStore $store,
        private readonly KeyPair $guardianKey,
        private readonly string $instanceId,
        private readonly string $principal,
        private readonly ?\Closure $clock,
        private readonly ?string $alg,
        private readonly ?PqKeyPair $pq,
        private readonly ?array $pin,
        private TransparencyLedger $log,
    ) {
        $this->cps = [];
    }

    /**
     * Load the log and verify it against every stored checkpoint. `$alg` / `$pq` choose a post-quantum or hybrid checkpoint suite (which
     * needs `$pin`, the PQ pins `[ed25519 b64u => pq_pk]`). Throws LedgerStoreError `store_missing`, `guardian_key_missing`, `pin_missing`,
     * `rollback`, `tamper`, `forged_checkpoint`, `inconsistent`, `store_corrupt` or `store_unavailable`.
     * @param ?callable():(int|float) $clock
     * @param ?array<string,string> $pin
     */
    public static function open(mixed $store, mixed $guardian, string $instanceId, string $principal, ?callable $clock = null, ?string $alg = null,
        ?PqKeyPair $pq = null, ?array $pin = null): self
    {
        if (!($store instanceof LedgerStore)) {
            throw new LedgerStoreError('store_missing', 'a LedgerStore is required (there is no in-memory default)');
        }
        if (!($guardian instanceof KeyPair)) {
            throw new LedgerStoreError('guardian_key_missing', 'a guardian secret key is required');
        }
        if ($alg !== null && ($alg !== 'ed25519' && (!in_array($alg, Pca::REGISTERED_SUITES, true) || !$pin))) {
            throw new LedgerStoreError('pin_missing', 'a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)');
        }
        try {
            $size = $store->size();
            $log = TransparencyLedger::fromCommits($store->read(0, $size), $principal);
            $self = new self($store, $guardian, $instanceId, $principal, $clock === null ? null : \Closure::fromCallable($clock), $alg, $pq, $pin, $log);
            $self->cps = $store->checkpoints(0);
            $self->verifyAgainstCheckpoints();
            return $self;
        } catch (\Throwable $e) {
            throw self::unavailable($e);
        }
    }

    private static function unavailable(\Throwable $e): LedgerStoreError
    {
        return $e instanceof LedgerStoreError ? $e : new LedgerStoreError('store_unavailable', $e->getMessage() ?: 'store failed');
    }

    /** @param list<Obj> $cps @return array{ok:bool,at?:int,reason?:string} */
    private function verifyChain(array $cps): array
    {
        $g = $this->guardianKey->public;
        foreach ($cps as $i => $cp) {
            if (!Ledger::verifyTreeHead($cp->get('sth'), $g, null, $this->pin)) {
                return ['ok' => false, 'at' => $i, 'reason' => 'head'];
            }
            if ($i === 0) {
                continue;
            }
            $proof = $cp->get('proof');
            if ($proof === null || ($proof instanceof Obj && $proof->keys() === [])) {
                return ['ok' => false, 'at' => $i, 'reason' => 'proof_missing'];
            }
            if (!Ledger::verifyHeadConsistency($cps[$i - 1]->get('sth'), $cp->get('sth'), $proof, $g, null, $this->pin)) {
                return ['ok' => false, 'at' => $i, 'reason' => 'inconsistent'];
            }
        }
        return ['ok' => true];
    }

    private function verifyAgainstCheckpoints(): void
    {
        $attested = 0;
        foreach ($this->cps as $c) {
            $sz = $c->get('sth')->get('size');
            $attested = max($attested, LedgerDoc::safeInt($sz) ? (int)LedgerDoc::num($sz) : 0);
        }
        if ($this->log->size() < $attested) {
            throw new LedgerStoreError('rollback', 'the log has ' . $this->log->size() . " entries but a checkpoint attests $attested");
        }
        foreach ($this->cps as $i => $cp) {
            $sth = $cp->get('sth');
            if ($sth->get('instance_id') !== $this->instanceId || $sth->get('principal') !== $this->principal) {
                throw new LedgerStoreError('forged_checkpoint', "checkpoint $i belongs to another log");
            }
            $size = $sth->get('size');
            if (!LedgerDoc::safeInt($size) || LedgerDoc::num($size) < 0 || LedgerDoc::num($size) > $this->log->size()) {
                throw new \RangeException('rootAt: size out of range');
            }
            if ($this->log->rootAt((int)LedgerDoc::num($size)) !== $sth->get('root')) {
                throw new LedgerStoreError('tamper', "the stored entries do not reproduce the root of checkpoint $i (size " . IntentWb::jsStr($size) . ')');
            }
        }
        if ($this->cps === []) {
            return;
        }
        $v = $this->verifyChain($this->cps);
        if (!$v['ok']) {
            throw new LedgerStoreError($v['reason'] === 'inconsistent' ? 'inconsistent' : 'forged_checkpoint', "checkpoint {$v['at']}: {$v['reason']}");
        }
    }

    public function size(): int
    {
        return $this->log->size();
    }

    /** The guardian public key (b64u) every checkpoint verifies under. */
    public function guardian(): string
    {
        return $this->guardianKey->public;
    }

    public function latestCheckpoint(): ?Obj
    {
        return $this->cps === [] ? null : $this->cps[count($this->cps) - 1]->get('sth');
    }

    /** @return list<Obj> */
    public function checkpointChain(): array
    {
        return $this->cps;
    }

    /** @return array{size:int,root:string} */
    public function head(): array
    {
        return $this->log->head();
    }

    public function inclusionProof(mixed $index): Obj
    {
        return $this->log->inclusionProof($index);
    }

    /** RFC 9162 proof from a size the caller already pinned to the current log. */
    public function consistencyProofFrom(mixed $oldSize): Obj
    {
        return $this->log->consistencyProof($oldSize, $this->log->size());
    }

    /** @return list<string> */
    public function commits(): array
    {
        return $this->log->commits();
    }

    /**
     * Append an opaque commitment leaf. Idempotent under retry at the position the caller read; if another writer took that position
     * the ledger reloads and appends at the new tail. @return array{index:int,commit:string}
     */
    public function append(mixed $commit): array
    {
        if (!LedgerDoc::isCommit($commit)) {
            throw new LedgerStoreError('invalid_commit', 'a commit must be a non-empty string');
        }
        for ($i = 0; $i < 16; $i++) {
            $index = $this->log->size();
            try {
                $out = $this->store->append($index, [$commit]);
            } catch (\Throwable $e) {
                throw self::unavailable($e);
            }
            if ($out['outcome'] === 'appended' || $out['outcome'] === 'replayed') {
                $this->log->appendCommitment($commit);
                return ['index' => $index, 'commit' => $commit];
            }
            $this->catchUpLocked(); // another writer advanced the log: pick up its entries, then try the new tail
        }
        throw new LedgerStoreError('conflict', 'the log kept moving; could not append');
    }

    /** Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints). */
    public function catchUp(): void
    {
        $this->catchUpLocked();
    }

    private function catchUpLocked(): void
    {
        try {
            $size = $this->store->size();
            if ($size < $this->log->size()) {
                throw new LedgerStoreError('rollback', 'the store shrank from ' . $this->log->size() . " to $size entries");
            }
            foreach ($this->store->read($this->log->size(), $size) as $c) {
                $this->log->appendCommitment($c);
            }
            array_push($this->cps, ...$this->store->checkpoints(count($this->cps)));
            $this->verifyAgainstCheckpoints();
        } catch (\Throwable $e) {
            throw self::unavailable($e);
        }
    }

    private function assertStoreMatchesMemory(): void
    {
        try {
            $stored = $this->store->read(0, $this->log->size());
        } catch (\Throwable $e) {
            throw self::unavailable($e);
        }
        if ($stored !== $this->log->commits()) {
            throw new LedgerStoreError('tamper', 'the stored entries no longer match this handle; refusing to sign a checkpoint over them');
        }
    }

    /**
     * Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the
     * previous checkpoint, so a log that was rewritten under this handle is refused (`inconsistent`). An unchanged head returns the
     * existing checkpoint.
     */
    public function checkpoint(): Obj
    {
        $this->catchUpLocked();
        $this->assertStoreMatchesMemory();
        $prev = $this->cps === [] ? null : $this->cps[count($this->cps) - 1];
        $h = $this->log->head();
        if ($prev !== null && (int)LedgerDoc::num($prev->get('sth')->get('size')) === $h['size']) {
            return $prev->get('sth');
        }
        $t = $this->clock !== null ? ($this->clock)() : microtime(true) * 1000;
        if (!(is_int($t) || is_float($t)) || !is_finite((float)$t)) {
            throw new LedgerStoreError('clock_invalid', 'the clock returned a non-finite time');
        }
        $t = (int)floor($t);
        $body = [
            'instance_id' => $this->instanceId, 'principal' => $this->principal, 'size' => $h['size'], 'root' => $h['root'],
            'prev_root' => $prev !== null ? $prev->get('sth')->get('root') : '', 'timestamp' => $t,
        ];
        $sth = TransparencyLedger::signTreeHead($this->guardianKey, $body, $this->alg, $this->pq);
        $cp = Obj::of(['sth' => $sth]);
        if ($prev !== null) {
            $cp->set('proof', $this->log->consistencyProof((int)LedgerDoc::num($prev->get('sth')->get('size')), $h['size']));
        }
        $v = $this->verifyChain([...$this->cps, $cp]);
        if (!$v['ok']) {
            if ($v['reason'] === 'head') {
                throw new LedgerStoreError('forged_checkpoint', 'the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)');
            }
            throw new LedgerStoreError('inconsistent', 'the new head is not consistent with checkpoint ' . ($v['at'] - 1));
        }
        try {
            $out = $this->store->appendCheckpoint(count($this->cps), $cp);
        } catch (\Throwable $e) {
            throw self::unavailable($e);
        }
        if ($out['outcome'] === 'conflict') {
            throw new LedgerStoreError('conflict', (string)($out['reason'] ?? 'conflict'));
        }
        $this->cps[] = $cp;
        return $sth;
    }
}
