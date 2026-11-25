<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Ledger.php';
require_once __DIR__ . '/Grants.php';
require_once __DIR__ . '/StoreErrors.php';

/**
 * The issuing side of the transparency ledger (the reference `TransparencyLedger`): an in-memory RFC 9162 log over opaque
 * commits with inclusion and consistency proof generation, the salted entry commitment and the signed tree head. The verifiers
 * are {@see Ledger}. A commit is a non-empty string; the log keeps the leaf hashes of its commits.
 */
final class TransparencyLedger
{
    /** @var list<string> */
    private array $commits = [];
    /** @var list<string> */
    private array $hashes = [];
    /** @var list<array{salt:string,pcactn:mixed}|null> */
    private array $openings = [];

    public function __construct(public readonly string $principal = '')
    {
    }

    /** Rebuild from stored commits (e.g. after persistence, or to model tampering). @param list<string> $commits */
    public static function fromCommits(array $commits, string $principal = ''): self
    {
        $l = new self($principal);
        foreach ($commits as $c) {
            $l->push($c, null);
        }
        return $l;
    }

    private function push(string $commit, ?array $opening): int
    {
        $this->commits[] = $commit;
        $this->hashes[] = hash('sha256', "\x00" . Json::canonicalizeNative($commit), true);
        $this->openings[] = $opening;
        return count($this->commits) - 1;
    }

    public function size(): int
    {
        return count($this->commits);
    }

    /** A JSON number (Num or native) holding an integer, as an int; null otherwise (JavaScript `Number.isInteger`). */
    private static function asInt(mixed $x): ?int
    {
        $f = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) < 9.2e18 ? (int)$f : null;
    }

    /** The salted commitment of a PCActn: base64url(sha256(canonical({salt, pcactn_digest}))). */
    public static function entryCommit(string $salt, mixed $pcactn): string
    {
        return Pca::hashCanonical(Obj::of(['salt' => $salt, 'pcactn_digest' => Pca::hashCanonical($pcactn)]));
    }

    /** True when the opening reproduces the commit. @param array{salt:mixed,pcactn:mixed}|Obj $opening */
    public static function verifyOpening(string $commit, mixed $opening): bool
    {
        try {
            $salt = $opening instanceof Obj ? $opening->get('salt') : ($opening['salt'] ?? null);
            $p = $opening instanceof Obj ? $opening->get('pcactn') : ($opening['pcactn'] ?? null);
            return is_string($salt) && self::entryCommit($salt, $p) === $commit;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Root of an arbitrary commit sequence (the empty log is SHA-256 of the empty string). @param list<string> $commits */
    public static function rootOf(array $commits): string
    {
        return $commits === [] ? Ledger::emptyTreeRoot() : Pca::merkleRoot($commits);
    }

    /** Append a PCActn as a salted commitment (`$salt` for deterministic output). @return array{index:int,commit:string} */
    public function append(mixed $pcactn, ?string $salt = null): array
    {
        $salt ??= Pca::b64u(random_bytes(16));
        $commit = self::entryCommit($salt, $pcactn);
        return ['index' => $this->push($commit, ['salt' => $salt, 'pcactn' => $pcactn]), 'commit' => $commit];
    }

    /** Append a PRECOMPUTED opaque commitment leaf; refuses a non-string or empty commit. @return array{index:int,commit:string} */
    public function appendCommitment(mixed $commit): array
    {
        if (!is_string($commit) || $commit === '') {
            throw new \InvalidArgumentException('appendCommitment: commit must be a non-empty string');
        }
        return ['index' => $this->push($commit, null), 'commit' => $commit];
    }

    /** @return array{size:int,root:string} */
    public function head(): array
    {
        return ['size' => $this->size(), 'root' => self::rootOf($this->commits)];
    }

    /** The root the log had when it contained only the first `$size` entries. */
    public function rootAt(mixed $size): string
    {
        $n = self::asInt($size);
        if ($n === null || $n < 0 || $n > $this->size()) {
            throw new \RangeException('rootAt: size out of range');
        }
        return self::rootOf(array_slice($this->commits, 0, $n));
    }

    /** @return list<string> */
    public function commits(): array
    {
        return $this->commits;
    }

    /** Indices whose stored opening no longer matches its commit (storage tamper detection). @return list<int> */
    public function auditOpenings(): array
    {
        $bad = [];
        foreach ($this->openings as $i => $o) {
            if ($o !== null && !self::verifyOpening($this->commits[$i], $o)) {
                $bad[] = $i;
            }
        }
        return $bad;
    }

    /** Crypto-shred: destroy the opening, keep the commit. Returns whether an opening was removed. */
    public function shred(int $index): bool
    {
        if ($index < 0 || $index >= $this->size()) {
            throw new \RangeException('shred: index out of range');
        }
        $had = $this->openings[$index] !== null;
        $this->openings[$index] = null;
        return $had;
    }

    public function inclusionProof(mixed $index): Obj
    {
        return Grants::merkleProof($this->commits, $index); // a RangeException for an index outside the log
    }

    /** @param list<string> $hs @return string the Merkle tree hash (raw) of the leaf hashes */
    private static function mth(array $hs): string
    {
        if ($hs === []) {
            return hash('sha256', '', true);
        }
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = 1;
        while ($k * 2 < count($hs)) {
            $k *= 2;
        }
        return hash('sha256', "\x01" . self::mth(array_slice($hs, 0, $k)) . self::mth(array_slice($hs, $k)), true);
    }

    /** RFC 6962 SUBPROOF(m, D[n], true): the consistency proof between the first `$oldSize` and the first `$newSize` entries. */
    public function consistencyProof(mixed $oldSize, mixed $newSize = null): Obj
    {
        $oldSize = self::asInt($oldSize);
        $newSize = $newSize === null ? $this->size() : self::asInt($newSize);
        if ($oldSize === null || $newSize === null || $oldSize < 0 || $oldSize > $newSize || $newSize > $this->size()) {
            throw new \RangeException('consistencyProof: invalid sizes');
        }
        $out = [];
        $sub = function (int $m, array $hs, bool $b) use (&$sub, &$out): void {
            $n = count($hs);
            if ($m === $n) {
                if (!$b) {
                    $out[] = self::mth($hs);
                }
                return;
            }
            $k = 1;
            while ($k * 2 < $n) {
                $k *= 2;
            }
            if ($m <= $k) {
                $sub($m, array_slice($hs, 0, $k), $b);
                $out[] = self::mth(array_slice($hs, $k));
            } else {
                $sub($m - $k, array_slice($hs, $k), false);
                $out[] = self::mth(array_slice($hs, 0, $k));
            }
        };
        if ($oldSize > 0 && $oldSize < $newSize) {
            $sub($oldSize, array_slice($this->hashes, 0, $newSize), true);
        }
        return Obj::of(['oldSize' => new Num((string)$oldSize), 'newSize' => new Num((string)$newSize), 'path' => array_map([Pca::class, 'b64u'], $out)]);
    }

    /**
     * Sign a tree head `{instance_id, principal, size, root, prev_root, timestamp}` under {@see Ledger::STH_DOMAIN}: the head
     * plus `guardian`, `sig` and, for a post-quantum or hybrid suite, `alg`, `pq_pk` and `pq_sig`.
     * @param array<string,mixed>|Obj $head
     */
    public static function signTreeHead(KeyPair $guardian, mixed $head, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $h = Sign::n($head);
        $body = Obj::of([]);
        foreach (['instance_id', 'principal', 'size', 'root', 'prev_root', 'timestamp'] as $k) {
            $body->set($k, $h->get($k));
        }
        $signed = Sign::signArtifact(Ledger::STH_DOMAIN, $body, $guardian, $alg, $pq);
        $sth = $body->without();
        $sth->set('guardian', $guardian->public);
        foreach ($signed->keys() as $k) {
            if (!$body->has($k)) {
                $sth->set($k, $signed->get($k));
            }
        }
        return $sth;
    }
}
