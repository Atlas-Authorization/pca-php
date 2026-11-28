<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/CaveatLang.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/K3Sig.php';

/**
 * Chain compaction (chain-compact.ts): a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus
 * the leaf hop. A verifier that has already verified the full chain once remembers it under that root ({@see ChainMemo}); later
 * presentations carry only `{v, kind, depth, hops_root, leaf}`.
 *
 * Nothing is trusted from the presentation: a compact chain is accepted only when the verifier's OWN memo holds an entry for `hops_root`
 * that its own verifyChain produced ({@see ChainMemo::rememberVerified} runs the verification itself), the depth equals the memoized
 * depth and the presented leaf hashes to the memoized last hop. What it gives the caveat language is a {@see ChainView}.
 */
final class ChainCompact
{
    public const CHAIN_HOP_DOMAIN = 'atlas-pca/chain-hop/v1';
    /** A memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time). */
    public const CHAIN_MEMO_MAX_TTL_MS = 3_600_000;
    public const CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000;

    /** The Merkle leaf of one hop: its content hash under a domain tag. */
    public static function hopLeaf(mixed $hop): Obj
    {
        return Obj::of(['d' => self::CHAIN_HOP_DOMAIN, 'hop' => Pca::capHash($hop)]);
    }

    /** The handle of a chain: Merkle root over the ordered hop leaves. @param list<mixed> $chain */
    public static function hopsRoot(array $chain): string
    {
        return Pca::merkleRoot(array_map([self::class, 'hopLeaf'], array_values($chain)));
    }

    /**
     * Fold a chain. Throws on an empty or over-deep chain. Does not verify it (the memo does).
     * @param list<mixed> $chain
     */
    public static function compactChain(mixed $chain): Obj
    {
        if (!is_array($chain) || !array_is_list($chain) || count($chain) === 0 || count($chain) > Pca::MAX_CHAIN) {
            throw new \InvalidArgumentException('compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops');
        }
        return Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-chain-compact', 'depth' => new Num((string)count($chain)),
            'hops_root' => self::hopsRoot($chain), 'leaf' => $chain[count($chain) - 1],
        ]);
    }

    public static function compactChainShapeError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'not an object';
        }
        $e = IntentWb::closedMembers($c, ['v', 'kind', 'depth', 'hops_root', 'leaf'], [], 'compact chain');
        if ($e !== null) {
            return $e;
        }
        $v = $c->get('v');
        if (!($v instanceof Num) || !$v->isInt() || $v->int() !== 1 || $c->get('kind') !== 'pca-chain-compact') {
            return 'not a pca-chain-compact v1';
        }
        $d = $c->get('depth');
        if (!K3Sig::anySafeInt($d) || !($d instanceof Num) || $d->int() < 1 || $d->int() > Pca::MAX_CHAIN) {
            return 'depth must be 1..' . Pca::MAX_CHAIN;
        }
        $r = $c->get('hops_root');
        if (!is_string($r) || strlen($r) !== 43) {
            return 'hops_root must be a 43 character digest';
        }
        if (!($c->get('leaf') instanceof Obj)) {
            return 'leaf must be a capability';
        }
        return null;
    }

    /** The view of a full chain, for symmetry with {@see ChainMemo::resolve} (both feed the caveat language). */
    public static function viewOfChain(mixed $grant, mixed $chain): ChainView
    {
        return CaveatLang::chainView($grant, $chain);
    }
}

/** The verifier's memo of chains it has fully verified. `$maxEntries` / `$ttlMs` bound it. */
final class ChainMemo
{
    /** @var array<string,array{depth:int,hops_root:string,hashes:list<string>,counts:list<int>,expires_at:int}> */
    private array $entries = [];

    public function __construct(private readonly ?int $maxEntries = null, private readonly ?int $ttlMs = null)
    {
    }

    public function size(): int
    {
        return count($this->entries);
    }

    /**
     * Verify `$chain` (rooted at `$expectedRootIssuer`) with the full verifier ({@see Pca::verifyChain}; `$allowedSuites`, `$pqPins` and
     * `$trustedRoot` are its policy) and remember it. Throws when the chain does not verify or the memo is full of live entries (fail
     * closed: a full memo never evicts a live entry, so one tenant cannot push another out). Returns the compact form a holder presents.
     * @param list<mixed> $chain
     * @param list<string>|null $allowedSuites
     */
    public function rememberVerified(array $chain, string $expectedRootIssuer, int $now, ?array $allowedSuites = null, mixed $pqPins = null, ?Obj $trustedRoot = null): Obj
    {
        if (!K3Sig::anySafeInt($now)) {
            throw new \InvalidArgumentException('rememberVerified: the clock is not a safe integer');
        }
        [$reason, $ok] = Pca::verifyChain($chain, $expectedRootIssuer, true, $allowedSuites, $pqPins, $trustedRoot);
        if ($ok !== true) {
            throw new \InvalidArgumentException('rememberVerified: the chain does not verify: ' . (($reason ?? '') !== '' ? $reason : 'invalid'));
        }
        $compact = ChainCompact::compactChain($chain);
        $ttl = min($this->ttlMs ?? ChainCompact::CHAIN_MEMO_MAX_TTL_MS, ChainCompact::CHAIN_MEMO_MAX_TTL_MS);
        $this->prune($now);
        $root = $compact->get('hops_root');
        if (!isset($this->entries[$root]) && count($this->entries) >= ($this->maxEntries ?? ChainCompact::CHAIN_MEMO_DEFAULT_MAX_ENTRIES)) {
            throw new \RuntimeException('rememberVerified: the memo is full of live entries');
        }
        $this->entries[$root] = [
            'depth' => count($chain), 'hops_root' => $root,
            'hashes' => array_map(static fn($h): string => Pca::capHash($h), $chain),
            'counts' => array_map(static fn($h): int => count($h->get('caveats')), $chain),
            'expires_at' => $now + $ttl,
        ];
        return $compact;
    }

    /** Drop entries whose time is up. */
    public function prune(int $now): void
    {
        foreach ($this->entries as $k => $e) {
            if ($e['expires_at'] < $now) {
                unset($this->entries[$k]);
            }
        }
    }

    /** Forget a chain (e.g. when it is revoked). */
    public function forget(string $hopsRoot): bool
    {
        $had = isset($this->entries[$hopsRoot]);
        unset($this->entries[$hopsRoot]);
        return $had;
    }

    /**
     * Resolve a presented compact chain against the memo: `['ok' => true, 'view' => ChainView]` or `['ok' => false, 'reason' => ...]`. Total.
     * @return array{ok:bool,view?:ChainView,reason?:string}
     */
    public function resolve(mixed $compact, int $now): array
    {
        try {
            if (!K3Sig::anySafeInt($now)) {
                return ['ok' => false, 'reason' => 'the verifier clock is not a safe integer (fail closed)'];
            }
            $e = ChainCompact::compactChainShapeError($compact);
            if ($e !== null) {
                return ['ok' => false, 'reason' => "malformed compact chain: $e"];
            }
            $root = $compact->get('hops_root');
            $m = $this->entries[$root] ?? null;
            if ($m === null) {
                return ['ok' => false, 'reason' => 'the chain is not in this verifier memo (present the full chain)'];
            }
            if ($m['expires_at'] < $now) {
                unset($this->entries[$root]);
                return ['ok' => false, 'reason' => 'the memoized chain has expired (present the full chain)'];
            }
            if ($m['depth'] !== $compact->get('depth')->int()) {
                return ['ok' => false, 'reason' => 'the depth differs from the memoized chain'];
            }
            $leaf = $compact->get('leaf');
            if (Pca::capHash($leaf) !== $m['hashes'][$m['depth'] - 1]) {
                return ['ok' => false, 'reason' => 'the leaf is not the memoized last hop'];
            }
            $cv = $leaf->get('caveats');
            if (!is_array($cv) || !array_is_list($cv) || count($cv) !== $m['counts'][$m['depth'] - 1]) {
                return ['ok' => false, 'reason' => 'the leaf caveats differ from the memoized chain'];
            }
            return ['ok' => true, 'view' => new ChainView($m['depth'], $leaf, static fn(int $i): string => $m['hashes'][$i], static fn(int $i): int => $m['counts'][$i])];
        } catch (\Throwable $err) {
            return ['ok' => false, 'reason' => 'compact chain error (fail closed): ' . ($err->getMessage() !== '' ? $err->getMessage() : 'unknown')];
        }
    }
}
