<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Grants.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Mesh.php';

/**
 * The issuing side of the agent mesh (the reference `mesh` and `durable-mesh-witness`): an independent log witness ({@see MeshWitness}) with its
 * durable stores, the issuer-side domain ({@see MeshDomain}: delegation log, revocation set, head publication, per-hop evidence) and the revocation
 * set with its proofs ({@see RevocationSet}). Verification of a whole proof is {@see Mesh::verify}; signing the leaf action and assembling the proof are
 * {@see SignersMore}. Records are Obj values with the reference's member names; keys are {@see KeyPair}.
 */
interface MeshWitnessStore
{
    /** The saved state `{seen: [{head, rev_ids}]}`, or null on a first run. Throws on a damaged state (a witness never starts empty over it). */
    public function load(): ?Obj;

    /** Persist the state (all or nothing). */
    public function save(Obj $state): void;
}

/** In-process store (a test double, and the default when no store is given). It does not survive a restart. */
final class MemoryMeshWitnessStore implements MeshWitnessStore
{
    private ?string $state = null;

    public function load(): ?Obj
    {
        return $this->state === null ? null : Json::parseLax($this->state);
    }

    public function save(Obj $state): void
    {
        $this->state = Js::stringify($state);
    }
}

/**
 * A file-backed store. Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the directory, so a crash leaves the
 * old state or the new one, never a torn file. The file carries a digest of its state: a file that does not parse, has the wrong shape or fails the
 * digest makes `load` throw (a witness never starts empty over a damaged file). A missing file is a first run. Single process: two witnesses must
 * not share one file.
 */
final class FileMeshWitnessStore implements MeshWitnessStore
{
    public function __construct(private readonly string $path)
    {
    }

    public function load(): ?Obj
    {
        if (!file_exists($this->path)) {
            return null;
        }
        try {
            $doc = Json::parseLax((string)file_get_contents($this->path));
        } catch (\Throwable) {
            throw new \RuntimeException('FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty');
        }
        if (!($doc instanceof Obj) || !Js::isNum($doc->get('v')) || Js::num($doc->get('v')) != 1 || !is_string($doc->get('digest')) || !($doc->get('state') instanceof Obj)) {
            throw new \RuntimeException('FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty');
        }
        if (IntentV2::hashCanonical($doc->get('state')) !== $doc->get('digest')) {
            throw new \RuntimeException('FileMeshWitnessStore: the state file fails its digest; refusing to start empty');
        }
        return $doc->get('state');
    }

    public function save(Obj $state): void
    {
        $body = Js::stringify(Obj::of(['v' => new Num('1'), 'state' => $state, 'digest' => IntentV2::hashCanonical($state)]));
        $tmp = $this->path . '.tmp';
        $fh = PrivateFile::open($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("FileMeshWitnessStore: cannot write $tmp");
        }
        try {
            if (fwrite($fh, $body) !== strlen($body) || !fflush($fh) || (function_exists('fsync') && !fsync($fh))) {
                throw new \RuntimeException("FileMeshWitnessStore: cannot write $tmp");
            }
        } finally {
            fclose($fh);
        }
        if (!rename($tmp, $this->path)) {
            throw new \RuntimeException('FileMeshWitnessStore: cannot replace the state file');
        }
        $dir = @fopen(dirname(realpath($this->path) ?: $this->path), 'rb'); // some platforms cannot fsync a directory; the rename above is already atomic
        if ($dir !== false) {
            if (function_exists('fsync')) {
                @fsync($dir);
            }
            fclose($dir);
        }
    }
}

/** A sorted set of revoked ids (UTF-8 byte order). `root()` is bound to the size, so a prefix of the set never has the full root. */
final class RevocationSet
{
    /** @var list<string> */
    private array $ids = [];

    /** @param iterable<mixed> $initial */
    public function __construct(iterable $initial = [])
    {
        foreach ($initial as $i) {
            $this->revoke($i);
        }
    }

    public function size(): int
    {
        return count($this->ids);
    }

    private function lowerBound(string $rid): int
    {
        $lo = 0;
        $hi = count($this->ids);
        while ($lo < $hi) {
            $mid = ($lo + $hi) >> 1;
            if (strcmp($this->ids[$mid], $rid) < 0) {
                $lo = $mid + 1;
            } else {
                $hi = $mid;
            }
        }
        return $lo;
    }

    /** Idempotent. True when newly revoked. */
    public function revoke(mixed $rid): bool
    {
        if (!is_string($rid)) {
            throw new \TypeError('revoke: id must be a string');
        }
        $lo = $this->lowerBound($rid);
        if ($lo < count($this->ids) && $this->ids[$lo] === $rid) {
            return false;
        }
        array_splice($this->ids, $lo, 0, [$rid]);
        return true;
    }

    public function has(string $rid): bool
    {
        $lo = $this->lowerBound($rid);
        return $lo < count($this->ids) && $this->ids[$lo] === $rid;
    }

    /** Sorted revoked ids (a copy). @return list<string> */
    public function list(): array
    {
        return $this->ids;
    }

    public function root(): string
    {
        return (string)Mesh::bindRevRoot(count($this->ids), $this->ids ? Pca::merkleRoot($this->ids) : Mesh::emptyRevTree());
    }

    public function membershipProof(string $rid): Obj
    {
        $lo = $this->lowerBound($rid);
        if (!($lo < count($this->ids) && $this->ids[$lo] === $rid)) {
            throw new \InvalidArgumentException('membershipProof: id is not revoked');
        }
        return Grants::merkleProof($this->ids, $lo);
    }

    /** Throws when the id IS revoked (no such proof can exist). */
    public function nonMembershipProof(string $rid): Obj
    {
        if ($this->has($rid)) {
            throw new \InvalidArgumentException('nonMembershipProof: id is revoked');
        }
        $n = count($this->ids);
        $lo = $this->lowerBound($rid);
        $p = Obj::of(['size' => new Num((string)$n)]);
        if ($lo > 0) {
            $p->set('lo', Obj::of(['id' => $this->ids[$lo - 1], 'proof' => Grants::merkleProof($this->ids, $lo - 1)]));
        }
        if ($lo < $n) {
            $p->set('hi', Obj::of(['id' => $this->ids[$lo], 'proof' => Grants::merkleProof($this->ids, $lo)]));
        }
        return $p;
    }
}

/** An independent log witness: it cosigns a domain head only after every rule of the reference holds (see {@see MeshWitness::cosign}). */
final class MeshWitness
{
    public const MAX_REV_IDS = 1000000;
    public const DEFAULT_MAX_CLOCK_SKEW_MS = 60000;

    public readonly string $id;
    private readonly float $skew;
    /** @var array<string,array{head:Obj,rev:list<string>}> */
    private array $seen = [];

    /**
     * $secret is the witness's KeyPair; $store is durable memory (a corrupt state throws: the witness never starts empty over damaged memory); $clock
     * (`(): int|float` ms) and $maxClockSkewMs refuse heads from the witness's future.
     */
    public function __construct(private readonly KeyPair $secret, private readonly ?MeshWitnessStore $store = null, private readonly ?\Closure $clock = null, ?float $maxClockSkewMs = null)
    {
        $this->skew = $maxClockSkewMs ?? self::DEFAULT_MAX_CLOCK_SKEW_MS;
        $this->id = $secret->public;
        $loaded = $store?->load();
        if ($loaded !== null) {
            $this->importState($loaded);
        }
    }

    /** The newest head this witness cosigned for $domain (what a domain must prove consistency from). */
    public function lastSeen(string $domain): ?Obj
    {
        $s = $this->seen[$domain] ?? null;
        return $s ? $s['head']->without() : null;
    }

    /** @param array<string,array{head:Obj,rev:list<string>}> $seen */
    private static function stateOf(array $seen): Obj
    {
        $items = [];
        foreach ($seen as $s) {
            $items[] = Obj::of(['head' => $s['head']->without(), 'rev_ids' => $s['rev']]);
        }
        usort($items, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('head')->get('domain'), $b->get('head')->get('domain')));
        return Obj::of(['seen' => $items]);
    }

    /**
     * Cosign a head: $req is `{head: CosignedHead, consistency?, rev_ids}` (an Obj). Throws (and changes nothing) if any rule is violated.
     *
     * @return Obj {witness, sig}
     */
    public function cosign(mixed $req): Obj
    {
        $ch = $req instanceof Obj ? $req->get('head') : null;
        if (!($ch instanceof Obj) || !Mesh::validHead($ch->get('head')) || !is_string($ch->get('sig'))) {
            throw new \InvalidArgumentException('witness: malformed head');
        }
        $h = $ch->get('head');
        $m = Mesh::msg(Mesh::HEAD_DOMAIN, $h);
        if ($m === null || !Pca::verifyEd25519B64u($h->get('domain'), $m, $ch->get('sig'))) {
            throw new \InvalidArgumentException('witness: head not signed by its domain');
        }
        if ($this->clock !== null && !(is_finite($clk = (float)($this->clock)()) && is_finite($this->skew) && (float)Js::num($h->get('timestamp')) <= $clk + $this->skew)) {
            throw new \InvalidArgumentException('witness: head timestamp is in the future');
        }
        $ids = $req->get('rev_ids');
        if (!is_array($ids) || !array_is_list($ids) || count($ids) > self::MAX_REV_IDS || count(array_filter($ids, 'is_string')) !== count($ids)) {
            throw new \InvalidArgumentException('witness: malformed revocation list');
        }
        $rs = new RevocationSet($ids);
        if ($rs->size() !== (int)Js::num($h->get('rev_size')) || $rs->root() !== $h->get('rev_root')) {
            throw new \InvalidArgumentException('witness: revocation list does not match head');
        }
        $domain = $h->get('domain');
        $prev = $this->seen[$domain] ?? null;
        if ($prev !== null) {
            $why = Mesh::checkHeadAdvance($prev['head'], $h, $req->get('consistency'));
            if ($why !== '') {
                throw new \InvalidArgumentException("witness: $why");
            }
            if (!((float)Js::num($h->get('timestamp')) >= (float)Js::num($prev['head']->get('timestamp')))) {
                throw new \InvalidArgumentException('witness: timestamp regresses');
            }
            $now = array_flip($rs->list());
            foreach ($prev['rev'] as $i) {
                if (!isset($now[$i])) {
                    throw new \InvalidArgumentException('witness: revocation set drops a previously cosigned revocation');
                }
            }
        }
        $entry = ['head' => $h->without(), 'rev' => $rs->list()];
        if ($this->store !== null) {
            $nxt = $this->seen;
            $nxt[$domain] = $entry;
            try {
                $this->store->save(self::stateOf($nxt)); // persist first, commit to memory second
            } catch (\Throwable) {
                throw new \RuntimeException('witness: could not persist state; refusing to cosign');
            }
        }
        $this->seen[$domain] = $entry;
        return Obj::of(['witness' => $this->id, 'sig' => Pca::b64u($this->secret->sign((string)Mesh::msg(Mesh::COSIG_DOMAIN, $h)))]);
    }

    /** Memory for persistence, in a deterministic order. */
    public function exportState(): Obj
    {
        return self::stateOf($this->seen);
    }

    /** Restore memory; each record must be internally consistent (its revocation list reproduces its root). */
    public function importState(mixed $state): void
    {
        $nxt = [];
        $seen = $state instanceof Obj ? $state->get('seen') : null;
        if ($seen !== null && $seen !== '' && !(is_array($seen) && array_is_list($seen))) {
            throw new \InvalidArgumentException('witness: malformed state'); // not a list of records
        }
        foreach ($seen ?: [] as $s) {
            $ids = $s instanceof Obj ? $s->get('rev_ids') : null;
            if (!($s instanceof Obj) || !Mesh::validHead($s->get('head')) || !is_array($ids) || !array_is_list($ids) || count(array_filter($ids, 'is_string')) !== count($ids)) {
                throw new \InvalidArgumentException('witness: malformed state');
            }
            $rs = new RevocationSet($ids);
            if ($rs->size() !== (int)Js::num($s->get('head')->get('rev_size')) || $rs->root() !== $s->get('head')->get('rev_root')) {
                throw new \InvalidArgumentException('witness: malformed state');
            }
            $nxt[$s->get('head')->get('domain')] = ['head' => $s->get('head')->without(), 'rev' => $rs->list()];
        }
        $this->seen = $nxt;
    }
}

/** The RFC 6962 proofs a domain generates over its delegation log. */
final class LedgerProofs
{
    /**
     * SUBPROOF(m, D[n], true): the consistency proof between the first $oldSize and the first $newSize commits.
     *
     * @param list<string> $commits
     */
    public static function consistencyProof(array $commits, int $oldSize, ?int $newSize = null): Obj
    {
        $all = count($commits);
        $newSize ??= $all;
        if ($oldSize < 0 || $oldSize > $newSize || $newSize > $all) {
            throw new \RangeException('consistencyProof: invalid sizes');
        }
        $out = [];
        $sub = static function (int $m, array $cs, bool $b) use (&$sub, &$out): void {
            $n = count($cs);
            if ($m === $n) {
                if (!$b) {
                    $out[] = Pca::merkleRoot($cs);
                }
                return;
            }
            $k = 1;
            while ($k * 2 < $n) {
                $k *= 2;
            }
            if ($m <= $k) {
                $sub($m, array_slice($cs, 0, $k), $b);
                $out[] = Pca::merkleRoot(array_slice($cs, $k));
            } else {
                $sub($m - $k, array_slice($cs, $k), false);
                $out[] = Pca::merkleRoot(array_slice($cs, 0, $k));
            }
        };
        if (0 < $oldSize && $oldSize < $newSize) {
            $sub($oldSize, array_slice($commits, 0, $newSize), true);
        }
        return Obj::of(['oldSize' => new Num((string)$oldSize), 'newSize' => new Num((string)$newSize), 'path' => $out]);
    }
}

/** Issuer-side state of one organisation: an append-only delegation log, a revocation set and head publication (in memory, so the protocol can be exercised end to end). */
final class MeshDomain
{
    public readonly string $id;
    /** @var list<string> */
    private array $log = [];
    private RevocationSet $rev;
    /** @var array<string,array{log:list<string>,rev:RevocationSet}> */
    private array $snaps = [];

    public function __construct(public readonly string $name, private readonly KeyPair $secret)
    {
        $this->id = $secret->public;
        $this->rev = new RevocationSet();
    }

    /** The id used in a domain's revocation set to revoke an agent KEY (kills every capability it issues). */
    public static function keyRevocationId(string $agentPublic): string
    {
        return "key:$agentPublic";
    }

    /** Vouch that an agent key belongs to this domain. */
    public function enroll(string $agent, string $role): Obj
    {
        $body = Obj::of(['agent' => $agent, 'domain' => $this->id, 'role' => $role]);
        return Obj::of(['agent' => $agent, 'domain' => $this->id, 'role' => $role, 'sig' => Pca::b64u($this->secret->sign((string)Mesh::msg(Mesh::BINDING_DOMAIN, $body)))]);
    }

    /** Log a delegation hop issued in this domain. Idempotent. */
    public function record(Obj $cap): int
    {
        $h = Pca::capHash($cap);
        $i = array_search($h, $this->log, true);
        if ($i !== false) {
            return $i;
        }
        $this->log[] = $h;
        return count($this->log) - 1;
    }

    /** Revoke a capability id (`cap.id`) or an agent key ({@see keyRevocationId}). */
    public function revoke(mixed $rid): void
    {
        $this->rev->revoke($rid);
    }

    public function revocationSetCopy(): RevocationSet
    {
        return new RevocationSet($this->rev->list());
    }

    /** RFC 9162 consistency proof between two sizes of this domain's current log. */
    public function consistencyProof(int $oldSize, ?int $newSize = null): Obj
    {
        return LedgerProofs::consistencyProof($this->log, $oldSize, $newSize);
    }

    /** A tree size is a whole number; anything else is not a size the log can prove from (the reference's sizes check refuses it). */
    private static function sizeArg(mixed $v): int
    {
        $f = Js::num($v);
        if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0) {
            throw new \RangeException('consistencyProof: invalid sizes');
        }
        return (int)$f;
    }

    /** The proof a verifier holding $pin needs to accept $head (a head this domain published, larger than the pin). */
    public function pinProof(Obj $pin, Obj $head): Obj
    {
        $snap = $this->snaps[(string)$head->get('sig')] ?? null;
        if ($snap === null) {
            throw new \InvalidArgumentException('pinProof: unknown head');
        }
        return Obj::of(['domain' => $this->id, 'proof' => LedgerProofs::consistencyProof($snap['log'], self::sizeArg($pin->get('size')), self::sizeArg($head->get('head')->get('size')))]);
    }

    /**
     * Publish a head: domain-signed, then cosigned by $witnesses, each shown a real consistency proof from ITS last-seen head plus the revocation list.
     * Throws if a witness refuses (unless $threshold tolerates it); nothing is recorded as published on failure.
     *
     * @param list<MeshWitness> $witnesses
     */
    public function publishHead(array $witnesses, mixed $timestamp, ?int $threshold = null): Obj
    {
        $head = Obj::of(['domain' => $this->id, 'size' => new Num((string)count($this->log)), 'root' => $this->log ? Pca::merkleRoot($this->log) : '',
            'rev_root' => $this->rev->root(), 'rev_size' => new Num((string)$this->rev->size()), 'timestamp' => $timestamp]);
        $cosigs = [];
        $ch = Obj::of(['head' => $head, 'sig' => Pca::b64u($this->secret->sign((string)Mesh::msg(Mesh::HEAD_DOMAIN, $head))), 'cosigs' => []]);
        $revIds = $this->rev->list();
        $errors = [];
        foreach ($witnesses as $w) {
            $prev = $w->lastSeen($this->id);
            $consistency = null;
            $psize = $prev ? (int)Js::num($prev->get('size')) : null;
            if ($prev && $psize < count($this->log)) {
                $consistency = LedgerProofs::consistencyProof($this->log, $psize, count($this->log));
            } elseif ($prev && $psize > count($this->log)) {
                $consistency = Obj::of(['oldSize' => $prev->get('size'), 'newSize' => $head->get('size'), 'path' => []]); // will be refused as a rollback
            }
            try {
                $req = Obj::of(['head' => $ch, 'rev_ids' => $revIds]);
                if ($consistency !== null) {
                    $req->set('consistency', $consistency);
                }
                $cosigs[] = $w->cosign($req);
                $ch->set('cosigs', $cosigs);
            } catch (\Throwable $e) {
                $errors[] = $e;
            }
        }
        $need = $threshold ?? count($witnesses);
        if (count($cosigs) < $need) {
            throw $errors[0] ?? new \InvalidArgumentException('publishHead: not enough witnesses');
        }
        $this->snaps[$ch->get('sig')] = ['log' => $this->log, 'rev' => new RevocationSet($this->rev->list())];
        return $ch;
    }

    /**
     * Per-hop evidence against a previously published head. Throws if the cap is not in that head's log or if the cap or issuer key is revoked as of that
     * head (no non-membership proof can exist).
     */
    public function evidence(Obj $cap, Obj $head, ?Obj $binding = null): Obj
    {
        $snap = $this->snaps[(string)$head->get('sig')] ?? null;
        if ($snap === null) {
            throw new \InvalidArgumentException('evidence: unknown head');
        }
        $h = Pca::capHash($cap);
        $idx = array_search($h, $snap['log'], true);
        if ($idx === false) {
            throw new \InvalidArgumentException('evidence: capability not in this head');
        }
        $ev = Obj::of(['domain' => $this->id, 'head' => $head, 'inclusion' => Grants::merkleProof($snap['log'], $idx),
            'revocation' => Obj::of(['cap' => $snap['rev']->nonMembershipProof($cap->get('id')), 'issuer_key' => $snap['rev']->nonMembershipProof(self::keyRevocationId($cap->get('issuer')))])]);
        if ($binding) {
            $ev->set('binding', $binding);
        }
        return $ev;
    }
}
