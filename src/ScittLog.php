<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Scitt.php';

/** code: store_required | store_corrupt | append_contention | out_of_range | bad_statement. */
final class ScittLogError extends ScittError
{
}

/**
 * Transparency Service logs for SCITT: the durable service over a pluggable store (an append is O(log n) store reads and writes,
 * state lives entirely in the store), a file-backed and an in-memory store, the in-memory reference service for tests, and a
 * conformance check for stores. A store is any object with size(), getEntry($index), getNode($level, $index) and
 * append($expectedSize, $entry, $nodes), where nodes are arrays ['level', 'index', 'hash']; append is an atomic compare-and-set
 * on the size. Service options (an Obj or an assoc array): alg, key, issuer, and for the durable service the store.
 */
final class ScittLog
{
    public const MAX_APPEND_ATTEMPTS = 16;

    /** A signing key that is null or empty is refused when the service is built, never carried until a later signature fails. */
    public static function requireKey(mixed $key): void
    {
        if ($key === null || (is_string($key) && $key === '')) {
            throw new \InvalidArgumentException('a signing key is required');
        }
    }

    /** `Number.isInteger`. */
    public static function isInteger(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && !is_nan($f) && !is_infinite($f) && $f == floor($f);
    }

    public static function largestPow2Below(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    /** The signer options handed to buildReceipt: alg, key and, when given, issuer. */
    public static function signerOf(mixed $opts): array
    {
        $s = ['alg' => Js::opt($opts, 'alg'), 'key' => Js::opt($opts, 'key')];
        if (Js::has($opts, 'issuer')) {
            $s['issuer'] = Js::opt($opts, 'issuer');
        }
        return $s;
    }

    /** @return array{statement:string,index:int,receipt:string,root:string} */
    public static function registerStatement(string $statement, mixed $service): array
    {
        return $service->register($statement);
    }

    /**
     * Check a store against the contract the service relies on (compare-and-set, atomic entry-plus-nodes, immutability).
     * Returns the failures (empty = conforms).
     * @param callable():object $makeStore
     * @return list<string>
     */
    public static function checkScittLogStore(callable $makeStore): array
    {
        $failures = [];
        try {
            $s = $makeStore();
            if ($s->size() !== 0) {
                $failures[] = 'a new store is not empty';
            }
            $h = static fn(int $b): string => str_repeat(chr($b), 32);
            if (!$s->append(0, "\x01", [['level' => 0, 'index' => 0, 'hash' => $h(1)]])) {
                $failures[] = 'append at the right size was refused';
            }
            if ($s->append(0, "\x02", [['level' => 0, 'index' => 1, 'hash' => $h(2)]])) {
                $failures[] = 'append at a stale size was accepted (no compare-and-set)';
            }
            if ($s->size() !== 1) {
                $failures[] = 'a refused append changed the size';
            }
            if ($s->getNode(0, 1) !== null) {
                $failures[] = 'a refused append left a node behind (not atomic)';
            }
            if ($s->getEntry(1) !== null) {
                $failures[] = 'a refused append left an entry behind';
            }
            $e0 = $s->getEntry(0);
            if ($e0 === null || strlen($e0) !== 1 || ord($e0[0]) !== 1) {
                $failures[] = 'the stored entry does not read back';
            }
            $wins = 0;
            foreach ([1, 2, 3, 4] as $i) {
                if ($s->append(1, chr(10 + $i), [['level' => 0, 'index' => 1, 'hash' => $h(10 + $i)]])) {
                    $wins++;
                }
            }
            if ($wins !== 1) {
                $failures[] = 'concurrent appends at the same size did not produce exactly one winner';
            }
            if ($s->size() !== 2) {
                $failures[] = 'the size after a race is not 2';
            }
        } catch (\Throwable $e) {
            $failures[] = 'the store threw: ' . $e->getMessage();
        }
        return $failures;
    }
}

/** Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs). */
final class ScittLogReader
{
    public function __construct(private readonly object $store)
    {
    }

    private function node(int $level, int $index): string
    {
        $h = $this->store->getNode($level, $index);
        if (!is_string($h) || strlen($h) !== 32) {
            throw new ScittLogError("missing or malformed subtree hash ($level, $index)", 'store_corrupt');
        }
        return $h;
    }

    public function range(int $lo, int $n): string
    {
        if ($n === 1) {
            return $this->node(0, $lo);
        }
        if ($n > 0 && ($n & ($n - 1)) === 0 && $lo % $n === 0) {
            return $this->node(strlen(decbin($n)) - 1, intdiv($lo, $n));
        }
        $k = ScittLog::largestPow2Below($n);
        return Scitt::nodeHash($this->range($lo, $k), $this->range($lo + $k, $n - $k));
    }

    public function root(int $size): string
    {
        return $size === 0 ? Scitt::emptyRoot() : $this->range(0, $size);
    }

    /** @return list<string> */
    public function inclusion(int $index, int $size): array
    {
        return $this->walk(0, $size, $index);
    }

    /** @return list<string> */
    private function walk(int $lo, int $n, int $idx): array
    {
        if ($n === 1) {
            return [];
        }
        $k = ScittLog::largestPow2Below($n);
        if ($idx < $k) {
            return [...$this->walk($lo, $k, $idx), $this->range($lo + $k, $n - $k)];
        }
        return [...$this->walk($lo + $k, $n - $k, $idx - $k), $this->range($lo, $k)];
    }

    /** @return list<string> */
    public function consistency(int $m, int $size): array
    {
        return $this->sub(0, $size, $m, true);
    }

    /** @return list<string> */
    private function sub(int $lo, int $n, int $mm, bool $complete): array
    {
        if ($mm === $n) {
            return $complete ? [] : [$this->range($lo, $n)];
        }
        $k = ScittLog::largestPow2Below($n);
        if ($mm <= $k) {
            return [...$this->sub($lo, $k, $mm, $complete), $this->range($lo + $k, $n - $k)];
        }
        return [...$this->sub($lo + $k, $n - $k, $mm - $k, false), $this->range($lo, $k)];
    }
}

/** A durable SCITT Transparency Service over a store you supply (there is no in-memory default). */
final class DurableTransparencyService
{
    private readonly object $store;
    private readonly ScittLogReader $reader;
    /** @var array<string,mixed> */
    private readonly array $signer;

    public function __construct(mixed $opts)
    {
        $store = Js::opt($opts, 'store');
        if (!is_object($store)) {
            throw new ScittLogError('a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default', 'store_required');
        }
        foreach (['size', 'getEntry', 'getNode', 'append'] as $m) {
            if (!is_callable([$store, $m])) {
                throw new ScittLogError('a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default', 'store_required');
            }
        }
        ScittLog::requireKey(Js::opt($opts, 'key'));
        $this->store = $store;
        $this->reader = new ScittLogReader($store);
        $this->signer = ScittLog::signerOf($opts);
    }

    public function size(): int
    {
        $n = $this->store->size();
        $i = Js::num($n);
        if ($i === null || is_nan($i) || is_infinite($i) || $i != floor($i) || abs($i) > 9007199254740991 || $i < 0) {
            throw new ScittLogError('the store reported an invalid size', 'store_corrupt');
        }
        return (int)$i;
    }

    public function root(): string
    {
        return Pca::b64u($this->reader->root($this->size()));
    }

    /** @return array{index:int,receipt:string,root:string} */
    private function receiptFor(int $index, int $size): array
    {
        $root = $this->reader->root($size);
        $sides = Scitt::siblingSides($index, $size);
        $path = [];
        foreach ($this->reader->inclusion($index, $size) as $i => $h) {
            $path[] = ['side' => $sides[$i], 'hash' => Pca::b64u($h)];
        }
        return ['index' => $index, 'receipt' => Scitt::buildReceipt(Pca::b64u($root), ['index' => $index, 'size' => $size, 'path' => $path], $this->signer), 'root' => Pca::b64u($root)];
    }

    /**
     * Append a Signed Statement (validated structurally first) and return its receipt against the new root.
     * @return array{index:int,receipt:string,root:string}
     */
    public function register(string $statement): array
    {
        try {
            $cose = Scitt::decodeCoseSign1($statement);
            if ($cose['payload'] === null) {
                throw new \TypeError('detached payload');
            }
        } catch (\Throwable $e) {
            throw new ScittLogError('cannot register: ' . $e->getMessage(), 'bad_statement');
        }
        for ($attempt = 0; $attempt < ScittLog::MAX_APPEND_ATTEMPTS; $attempt++) {
            $n = $this->size();
            $h = Scitt::leafHash($statement);
            $nodes = [['level' => 0, 'index' => $n, 'hash' => $h]];
            $level = 1;
            while ((($n + 1) % (1 << $level)) === 0) { // the new leaf completes a subtree: its left sibling is already stored
                $idx = intdiv($n + 1, 1 << $level) - 1;
                $left = $this->store->getNode($level - 1, 2 * $idx);
                if (!is_string($left) || strlen($left) !== 32) {
                    throw new ScittLogError('missing subtree hash (' . ($level - 1) . ', ' . (2 * $idx) . ')', 'store_corrupt');
                }
                $h = Scitt::nodeHash($left, $h);
                $nodes[] = ['level' => $level, 'index' => $idx, 'hash' => $h];
                $level++;
            }
            if ($this->store->append($n, $statement, $nodes)) {
                return $this->receiptFor($n, $n + 1);
            }
        }
        throw new ScittLogError('could not append: the log kept changing', 'append_contention');
    }

    /** @return array<string,mixed> */
    public function appendAndReceipt(mixed $payload, mixed $opts): array
    {
        $statement = Scitt::signStatement($payload, $opts);
        return ['statement' => $statement] + $this->register($statement);
    }

    /** A receipt for an entry, against the CURRENT root. */
    public function getReceipt(mixed $index): array
    {
        $size = $this->size();
        if (!ScittLog::isInteger($index) || Js::num($index) < 0 || Js::num($index) >= $size) {
            throw new ScittLogError('getReceipt: index out of range', 'out_of_range');
        }
        return $this->receiptFor((int)Js::num($index), $size);
    }

    public function getEntry(mixed $index): string
    {
        $size = $this->size();
        if (!ScittLog::isInteger($index) || Js::num($index) < 0 || Js::num($index) >= $size) {
            throw new ScittLogError('getEntry: index out of range', 'out_of_range');
        }
        $e = $this->store->getEntry((int)Js::num($index));
        if ($e === null) {
            throw new ScittLogError('entry ' . (int)Js::num($index) . ' is missing', 'store_corrupt');
        }
        return $e;
    }

    /**
     * An RFC 9162 consistency proof that the first `$oldSize` entries are a prefix of the current log.
     * @return array{oldSize:int,newSize:int,oldRoot:string,newRoot:string,proof:string}
     */
    public function consistencyProof(mixed $oldSize): array
    {
        $size = $this->size();
        if (!ScittLog::isInteger($oldSize) || Js::num($oldSize) < 1 || Js::num($oldSize) > $size) {
            throw new ScittLogError('consistencyProof: size out of range', 'out_of_range');
        }
        $old = (int)Js::num($oldSize);
        $path = $this->reader->consistency($old, $size);
        return [
            'oldSize' => $old, 'newSize' => $size, 'oldRoot' => Pca::b64u($this->reader->root($old)), 'newRoot' => Pca::b64u($this->reader->root($size)),
            'proof' => Scitt::encode([$old, $size, array_map(static fn(string $h): Bytes => new Bytes($h), $path)]),
        ];
    }
}

/** In-memory store: single process, forgets everything on restart. For tests only. */
final class MemoryScittLogStore
{
    /** @var list<string> */
    private array $entries = [];
    /** @var array<string,string> */
    private array $nodes = [];

    public function size(): int
    {
        return count($this->entries);
    }

    public function getEntry(mixed $index): ?string
    {
        return ScittLog::isInteger($index) && Js::num($index) >= 0 && Js::num($index) < count($this->entries) ? $this->entries[(int)Js::num($index)] : null;
    }

    public function getNode(mixed $level, mixed $index): ?string
    {
        return $this->nodes[(string)Js::num($level) . ':' . (string)Js::num($index)] ?? null;
    }

    /** @param list<array{level:int,index:int,hash:string}> $nodes */
    public function append(mixed $expectedSize, string $entry, array $nodes): bool
    {
        if (Js::num($expectedSize) !== (float)count($this->entries)) {
            return false;
        }
        $this->entries[] = $entry;
        foreach ($nodes as $n) {
            $this->nodes[(string)Js::num($n['level']) . ':' . (string)Js::num($n['index'])] = $n['hash'];
        }
        return true;
    }
}

/**
 * File-backed store: one append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced before `append`
 * returns, so a crash leaves the whole transaction or none of it. A torn final record is discarded on open; corruption elsewhere
 * throws `store_corrupt`. SINGLE PROCESS: it does not lock the file.
 */
final class FileScittLogStore
{
    /** @var resource */
    private $fd;
    /** @var array<string,string> */
    private array $nodes = [];
    /** @var list<array{0:int,1:int}> */
    private array $offsets = [];
    private int $end = 0;

    /** @param resource $fd */
    private function __construct($fd)
    {
        $this->fd = $fd;
    }

    public static function open(string $path): self
    {
        if (!file_exists($path)) {
            touch($path);
            chmod($path, 0600);
        }
        $fd = fopen($path, 'r+b');
        if ($fd === false) {
            throw new ScittLogError("cannot open $path", 'store_corrupt');
        }
        $s = new self($fd);
        $s->load();
        return $s;
    }

    public function close(): void
    {
        fclose($this->fd);
    }

    private function read(int $at, int $n): string
    {
        fseek($this->fd, $at);
        $got = '';
        while (strlen($got) < $n) {
            $chunk = fread($this->fd, $n - strlen($got));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $got .= $chunk;
        }
        return $got;
    }

    private function load(): void
    {
        $total = (int)(fstat($this->fd)['size'] ?? 0);
        $pos = 0;
        while ($pos < $total) {
            $head = $this->read($pos, 4);
            $n = strlen($head) === 4 ? (int)unpack('N', $head)[1] : -1;
            $recEnd = $pos + 4 + $n + 32;
            if ($n < 6 || $recEnd > $total) {
                $this->discardTail($pos, $recEnd > $total);
                return;
            }
            $payload = $this->read($pos + 4, $n);
            if (!hash_equals(hash('sha256', $payload, true), $this->read($pos + 4 + $n, 32))) {
                $this->discardTail($pos, $recEnd === $total);
                return;
            }
            $entryLen = (int)unpack('N', substr($payload, 0, 4))[1];
            $p = 4 + $entryLen;
            if ($p + 2 > $n) {
                throw new ScittLogError('a log record has an inconsistent length', 'store_corrupt');
            }
            $count = (int)unpack('n', substr($payload, $p, 2))[1];
            $p += 2;
            if ($p + $count * 40 !== $n) {
                throw new ScittLogError('a log record has an inconsistent length', 'store_corrupt');
            }
            $this->offsets[] = [$pos + 8, $entryLen];
            for ($i = 0; $i < $count; $i++) {
                $this->nodes[ord($payload[$p]) . ':' . (int)unpack('N', substr($payload, $p + 1, 4))[1]] = substr($payload, $p + 8, 32);
                $p += 40;
            }
            $pos = $recEnd;
        }
        $this->end = $pos;
    }

    private function discardTail(int $pos, bool $isTail): void
    {
        if (!$isTail) {
            throw new ScittLogError("the log file is corrupt at offset $pos", 'store_corrupt');
        }
        ftruncate($this->fd, $pos);
        fflush($this->fd);
        fsync($this->fd);
        $this->end = $pos;
    }

    public function size(): int
    {
        return count($this->offsets);
    }

    public function getEntry(mixed $index): ?string
    {
        $f = Js::num($index);
        if (!ScittLog::isInteger($index) || $f < 0 || $f >= count($this->offsets)) {
            return null;
        }
        [$at, $n] = $this->offsets[(int)$f];
        return $this->read($at, $n);
    }

    public function getNode(mixed $level, mixed $index): ?string
    {
        return $this->nodes[(string)Js::num($level) . ':' . (string)Js::num($index)] ?? null;
    }

    /** @param list<array{level:mixed,index:mixed,hash:string}> $nodes */
    public function append(mixed $expectedSize, string $entry, array $nodes): bool
    {
        if (Js::num($expectedSize) !== (float)count($this->offsets)) {
            return false;
        }
        foreach ($nodes as $n) {
            if (!ScittLog::isInteger($n['level']) || Js::num($n['level']) < 0 || Js::num($n['level']) > 255 || !ScittLog::isInteger($n['index'])
                || Js::num($n['index']) < 0 || Js::num($n['index']) > 0xFFFFFFFF || !is_string($n['hash']) || strlen($n['hash']) !== 32) {
                throw new ScittLogError('a subtree node is malformed', 'store_corrupt');
            }
        }
        $payload = pack('N', strlen($entry)) . $entry . pack('n', count($nodes));
        foreach ($nodes as $n) {
            $payload .= chr((int)Js::num($n['level'])) . pack('N', (int)Js::num($n['index'])) . "\x00\x00\x00" . $n['hash'];
        }
        $record = pack('N', strlen($payload)) . $payload . hash('sha256', $payload, true);
        fseek($this->fd, $this->end);
        $w = 0;
        while ($w < strlen($record)) {
            $k = fwrite($this->fd, substr($record, $w));
            if ($k === false || $k === 0) {
                throw new ScittLogError('could not write the log record', 'store_corrupt');
            }
            $w += $k;
        }
        fflush($this->fd);
        fsync($this->fd);
        $this->offsets[] = [$this->end + 8, strlen($entry)];
        foreach ($nodes as $n) {
            $this->nodes[(string)(int)Js::num($n['level']) . ':' . (string)(int)Js::num($n['index'])] = $n['hash'];
        }
        $this->end += strlen($record);
        return true;
    }
}

/** In-memory reference log: recomputes the Merkle tree on every registration and loses everything on restart. For tests and demos only. */
final class TransparencyService
{
    /** @var list<string> */
    private array $statements = [];
    /** @var list<string> */
    private array $leafHashes = [];
    /** @var array<string,mixed> */
    private readonly array $signer;

    public function __construct(mixed $opts)
    {
        ScittLog::requireKey(Js::opt($opts, 'key'));
        $this->signer = ScittLog::signerOf($opts);
    }

    public function size(): int
    {
        return count($this->statements);
    }

    public function root(): string
    {
        return Pca::b64u(Scitt::treeHash($this->leafHashes));
    }

    /** @return list<string> */
    public function snapshot(): array
    {
        return array_map(static fn(string $s): string => Pca::b64u($s), $this->statements);
    }

    /** @return array{index:int,receipt:string,root:string} */
    private function receiptFor(int $index): array
    {
        $root = Scitt::treeHash($this->leafHashes);
        $size = count($this->leafHashes);
        $sides = Scitt::siblingSides($index, $size);
        $path = [];
        foreach (Scitt::inclusionPath($this->leafHashes, $index) as $i => $h) {
            $path[] = ['side' => $sides[$i], 'hash' => Pca::b64u($h)];
        }
        return ['index' => $index, 'receipt' => Scitt::buildReceipt(Pca::b64u($root), ['index' => $index, 'size' => $size, 'path' => $path], $this->signer), 'root' => Pca::b64u($root)];
    }

    /** @return array{index:int,receipt:string,root:string} */
    public function register(string $statement): array
    {
        $cose = Scitt::decodeCoseSign1($statement);
        if ($cose['payload'] === null) {
            throw new \TypeError('scitt: cannot register a statement with a detached payload');
        }
        $index = count($this->statements);
        $this->statements[] = $statement;
        $this->leafHashes[] = Scitt::leafHash($statement);
        return $this->receiptFor($index);
    }

    /** @return array<string,mixed> */
    public function appendAndReceipt(mixed $payload, mixed $opts): array
    {
        $statement = Scitt::signStatement($payload, $opts);
        return ['statement' => $statement] + $this->register($statement);
    }

    public function getReceipt(mixed $index): array
    {
        if (!ScittLog::isInteger($index) || Js::num($index) < 0 || Js::num($index) >= count($this->statements)) {
            throw new \RangeException('getReceipt: index out of range');
        }
        return $this->receiptFor((int)Js::num($index));
    }

    /**
     * The log at `$oldSize` entries is a prefix of the current log: both roots and the RFC 9942 proof encoding.
     * @return array{oldSize:int,newSize:int,oldRoot:string,newRoot:string,proof:string}
     */
    public function consistencyProof(mixed $oldSize): array
    {
        if (!ScittLog::isInteger($oldSize) || Js::num($oldSize) < 1 || Js::num($oldSize) > count($this->statements)) {
            throw new \RangeException('consistencyProof: size out of range');
        }
        $old = (int)Js::num($oldSize);
        $path = Scitt::consistencyPath($this->leafHashes, $old);
        return [
            'oldSize' => $old, 'newSize' => count($this->statements), 'oldRoot' => Pca::b64u(Scitt::treeHash(array_slice($this->leafHashes, 0, $old))),
            'newRoot' => $this->root(), 'proof' => Scitt::encode([$old, count($this->statements), array_map(static fn(string $h): Bytes => new Bytes($h), $path)]),
        ];
    }
}
