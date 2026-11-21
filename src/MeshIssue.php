<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Mesh.php';
require_once __DIR__ . '/MeshWitness.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/SignersMore.php';

/**
 * The issuing side of the cross-domain mesh and its federation half (the TypeScript reference mesh.ts is authoritative): the public
 * caveat conjunction, the proof size and revocation-latency models, the worked example, cross-domain capability translation, the
 * federated budget tree and cross-reference commitments.
 *
 * Values are the parsed-JSON model (Obj, list arrays, string, Num, bool, null). Verifiers never throw; signers and translators throw.
 * A number the reference passes through unchanged is passed through as given (so a negative zero stays one).
 */
final class MeshIssue
{
    public const DEFAULT_MAX_HEAD_AGE_MS = 300000;
    public const DEFAULT_MAX_CLOCK_SKEW_MS = 60000;
    public const DEFAULT_MAX_CHAIN_LENGTH = 64;
    public const XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\0";
    public const XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\0";
    public const ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\0";
    /** Marks an argument that was not given (null is a value). */
    public const UNSET = "\0unset";
    private const MAX_SAFE = 9007199254740991.0;

    // ---- value helpers ---------------------------------------------------------------------------------------------

    /** The double of a finite JSON number, else null. */
    private static function f(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    private static function list(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** A non-negative safe integer, never -0. */
    private static function nat(mixed $x): bool
    {
        $v = self::f($x);
        return $v !== null && floor($v) === $v && $v >= 0 && $v <= self::MAX_SAFE && !K3Sig::isNegZero($x);
    }

    private static function isCaveatArray(mixed $x): bool
    {
        if (!self::list($x)) {
            return false;
        }
        foreach ($x as $c) {
            if (!($c instanceof Obj) || !is_string($c->get('type'))) {
                return false;
            }
        }
        return true;
    }

    /** The member, which must be present (the canonical form refuses an absent one, as the reference's does). */
    private static function need(Obj $o, string $k): mixed
    {
        if (!$o->has($k)) {
            throw new \InvalidArgumentException("canonicalize: member $k is missing");
        }
        return $o->get($k);
    }

    private static function bytes(mixed $v): int
    {
        return strlen(Json::canonicalizeNative($v));
    }

    // ---- small public helpers --------------------------------------------------------------------------------------

    /** The id used in a domain's revocation set to revoke an agent KEY; a non-string is coerced as the reference's template string does. */
    public static function keyRevocationId(mixed $agentPublic): string
    {
        return 'key:' . IntentWb::jsStr($agentPublic);
    }

    /**
     * The conjunction of all caveats as one authority: `{prefixes, actions?, maxAmount?, expiresAt?, audience?, maxHops?}` (an absent
     * member is unconstrained), or `{error}` when a caveat is unknown or malformed (fail closed). The first `scope` / `audience` is
     * deduplicated and sorted by UTF-8 bytes; a later one keeps the earlier order. Throws when `$caveats` is not a list or an entry is null.
     *
     * @return array<string, mixed>
     */
    public static function effectiveAuthority(mixed $caveats): array
    {
        if (!self::list($caveats)) {
            throw new \InvalidArgumentException('effectiveAuthority: caveats is not a list');
        }
        $e = ['prefixes' => []];
        $strings = static function (mixed $v): bool {
            if (!self::list($v)) {
                return false;
            }
            foreach ($v as $x) {
                if (!is_string($x)) {
                    return false;
                }
            }
            return true;
        };
        $intersect = static function (?array $a, array $b): array {
            if ($a === null) {
                $out = array_values(array_unique($b));
                usort($out, 'strcmp');
                return $out;
            }
            return array_values(array_filter($a, static fn(string $x): bool => in_array($x, $b, true)));
        };
        $min = static fn(?float $a, float $b): float => $a === null ? $b : min($a, $b);
        foreach ($caveats as $c) {
            if ($c === null) {
                throw new \InvalidArgumentException('effectiveAuthority: null caveat');
            }
            $t = $c instanceof Obj && $c->has('type') ? $c->get('type') : JsUndefined::U;
            switch (is_string($t) ? $t : "\0") { // strict dispatch
                case 'scope':
                    if (!$strings($c->get('actions'))) {
                        return ['error' => 'malformed scope caveat'];
                    }
                    $e['actions'] = $intersect($e['actions'] ?? null, $c->get('actions'));
                    break;
                case 'resource':
                    if (!is_string($c->get('prefix'))) {
                        return ['error' => 'malformed resource caveat'];
                    }
                    $e['prefixes'][] = $c->get('prefix');
                    break;
                case 'max_amount':
                    if (($v = self::f($c->get('max'))) === null) {
                        return ['error' => 'malformed max_amount caveat'];
                    }
                    $e['maxAmount'] = $min($e['maxAmount'] ?? null, $v);
                    break;
                case 'expires':
                    if (($v = self::f($c->get('at'))) === null) {
                        return ['error' => 'malformed expires caveat'];
                    }
                    $e['expiresAt'] = $min($e['expiresAt'] ?? null, $v);
                    break;
                case 'audience':
                    if (!$strings($c->get('domains'))) {
                        return ['error' => 'malformed audience caveat'];
                    }
                    $e['audience'] = $intersect($e['audience'] ?? null, $c->get('domains'));
                    break;
                case 'max_hops':
                    if (($v = self::f($c->get('n'))) === null) {
                        return ['error' => 'malformed max_hops caveat'];
                    }
                    $e['maxHops'] = $min($e['maxHops'] ?? null, $v);
                    break;
                default:
                    return ['error' => 'unknown caveat type "' . IntentWb::jsStr($t) . '" (fail closed)'];
            }
        }
        return $e;
    }

    /** Does every action `$child` admits also pass `$parent`? (monotone narrowing) */
    private static function narrows(array $child, array $parent): bool
    {
        foreach (['actions', 'audience'] as $k) {
            if (isset($parent[$k]) && (!isset($child[$k]) || array_diff($child[$k], $parent[$k]) !== [])) {
                return false;
            }
        }
        foreach (['maxAmount', 'expiresAt', 'maxHops'] as $k) {
            if (isset($parent[$k]) && (!isset($child[$k]) || $child[$k] > $parent[$k])) {
                return false;
            }
        }
        return array_diff($parent['prefixes'], $child['prefixes']) === [];
    }

    // ---- size and latency models -----------------------------------------------------------------------------------

    /** `$table[$i]` as the reference indexes it: a list by a natural number (or its decimal string), an object by the key's string form. */
    private static function at(mixed $table, mixed $i): mixed
    {
        if ($table instanceof Obj) {
            return $table->get(IntentWb::jsStr($i));
        }
        if (!is_array($table)) {
            return null;
        }
        if (is_string($i) && preg_match('/\A(0|[1-9][0-9]{0,15})\z/', $i) === 1) {
            return $table[(int)$i] ?? null;
        }
        return self::nat($i) ? ($table[(int)self::f($i)] ?? null) : null;
    }

    /**
     * Size accounting of a mesh proof: byte lengths of the canonical JSON of the whole proof and of its parts, and of the layout in
     * which every hop carries its own head copy and inline revocation leaves. Throws on a value that is not a proof.
     *
     * @return array{total_bytes: int, chain_bytes: int, heads_bytes: int, rev_leaves_bytes: int, hops_bytes: int, uncompacted_bytes: int}
     */
    public static function meshProofSize(mixed $p): array
    {
        if (!($p instanceof Obj)) {
            throw new \InvalidArgumentException('meshProofSize: not a proof');
        }
        $hops = $p->get('hops');
        if (!self::list($hops)) {
            throw new \InvalidArgumentException('meshProofSize: hops is not a list');
        }
        $leaves = $p->get('rev_leaves');
        $expand = static function (mixed $c) use ($leaves): Obj {
            if (!($c instanceof Obj)) {
                throw new \InvalidArgumentException('meshProofSize: malformed revocation proof');
            }
            $out = Obj::of(['size' => self::need($c, 'size')]);
            foreach (['lo', 'hi'] as $k) {
                if ($c->has($k) && Js::truthy($leaf = self::at($leaves, $c->get($k)))) {
                    $out->set($k, $leaf);
                }
            }
            return $out;
        };
        $un = self::bytes(self::need($p, 'chain')) + self::bytes(self::need($p, 'action')) + self::bytes(self::need($p, 'action_sig'));
        foreach ($hops as $h) {
            $rev = $h instanceof Obj ? $h->get('revocation') : null;
            $head = $h instanceof Obj && $h->has('head') ? self::at($p->get('heads'), $h->get('head')) : null;
            if (!($rev instanceof Obj) || $head === null) {
                throw new \InvalidArgumentException('meshProofSize: malformed hop');
            }
            $full = $h->without();
            $full->set('head', $head);
            $full->set('revocation', Obj::of(['cap' => $expand($rev->get('cap')), 'issuer_key' => $expand($rev->get('issuer_key'))]));
            $un += self::bytes($full);
        }
        return ['total_bytes' => self::bytes($p), 'chain_bytes' => self::bytes($p->get('chain')), 'heads_bytes' => self::bytes(self::need($p, 'heads')),
            'rev_leaves_bytes' => self::bytes(self::need($p, 'rev_leaves')), 'hops_bytes' => self::bytes($hops), 'uncompacted_bytes' => $un];
    }

    /**
     * Worst-case time from "revocation made" until it is enforced, per verifier posture (all milliseconds). `$p` is
     * `{maxHeadAgeMs, headIntervalMs, maxClockSkewMs?, pinRefreshMs?}`; a non-finite or negative input yields an unusable bound (INF, not viable).
     *
     * @return array{published_ms: float, unpinned_ms: float, pinned_ms: float, honest_provers_viable: bool}
     */
    public static function revocationLatencyBound(mixed $p): array
    {
        $ok = static fn(mixed $x): bool => ($v = self::f($x)) !== null && $v >= 0;
        $g = static fn(string $k): mixed => $p instanceof Obj ? $p->get($k) : null;
        $has = static fn(string $k): bool => $p instanceof Obj && $p->has($k);
        if (!$ok($g('maxHeadAgeMs')) || !$ok($g('headIntervalMs')) || ($has('maxClockSkewMs') && !$ok($g('maxClockSkewMs'))) || ($has('pinRefreshMs') && !$ok($g('pinRefreshMs')))) {
            return ['published_ms' => INF, 'unpinned_ms' => INF, 'pinned_ms' => INF, 'honest_provers_viable' => false];
        }
        $age = (float)self::f($g('maxHeadAgeMs'));
        $interval = (float)self::f($g('headIntervalMs'));
        $skew = $has('maxClockSkewMs') ? (float)self::f($g('maxClockSkewMs')) : 0.0;
        $unpinned = $age + $skew;
        return ['published_ms' => $interval, 'unpinned_ms' => $unpinned, 'pinned_ms' => $has('pinRefreshMs') ? min($unpinned, (float)self::f($g('pinRefreshMs'))) : $unpinned,
            'honest_provers_viable' => $interval + $skew < $age];
    }

    // ---- the worked example ----------------------------------------------------------------------------------------

    /** The example's key for a label: the first 32 BYTES OF THE TEXT of the canonical hash (not the decoded digest), as the reference derives it. */
    private static function seedKey(string $label): KeyPair
    {
        return new KeyPair(substr(Pca::hashCanonical(Obj::of(['seed' => "atlas-pca/mesh-example/$label"])), 0, 32));
    }

    /**
     * The worked example: a four-hop chain across three domains with three witnesses, a compact proof and the trust anchors that verify it.
     *
     * @return array{trust: Obj, proof: Obj, evidence: list<Obj>, domains: array<string, MeshDomain>, witnesses: list<MeshWitness>, keys: array<string, KeyPair>,
     *     chain: list<Obj>, heads: array<string, Obj>, bindings: array<string, Obj>}
     */
    public static function buildMeshExample(int|float $now = 1800000000000): array
    {
        $keys = [];
        foreach (['human', 'orchestrator', 'tool', 'service', 'leaf'] as $k) {
            $keys[$k] = self::seedKey($k);
        }
        $a = new MeshDomain('org-A', self::seedKey('domain-A'));
        $b = new MeshDomain('org-B', self::seedKey('domain-B'));
        $c = new MeshDomain('org-C', self::seedKey('domain-C'));
        $witnesses = [new MeshWitness(self::seedKey('witness-1')), new MeshWitness(self::seedKey('witness-2')), new MeshWitness(self::seedKey('witness-3'))];
        $root = Sign::mintRoot($keys['human'], $keys['orchestrator']->public, [
            ['type' => 'scope', 'actions' => ['payments.refund', 'payments.read', 'orders.read']],
            ['type' => 'resource', 'prefix' => '/orders/'],
            ['type' => 'max_amount', 'max' => 500],
            ['type' => 'expires', 'at' => $now + 3600000],
            ['type' => 'audience', 'domains' => [$c->id]],
        ]);
        $c1 = Sign::delegate($root, $keys['orchestrator'], $keys['tool']->public, [['type' => 'scope', 'actions' => ['payments.refund', 'payments.read']], ['type' => 'max_amount', 'max' => 100]]);
        $c2 = Sign::delegate($c1, $keys['tool'], $keys['service']->public, [['type' => 'resource', 'prefix' => '/orders/42'], ['type' => 'max_hops', 'n' => 4]]);
        $c3 = Sign::delegate($c2, $keys['service'], $keys['leaf']->public, [['type' => 'scope', 'actions' => ['payments.refund']], ['type' => 'max_amount', 'max' => 50]]);
        $chain = [$root, $c1, $c2, $c3];
        $a->record($root);
        $hA0 = $a->publishHead($witnesses, Sign::n($now - 2000));
        $a->record($c1);
        $hA = $a->publishHead($witnesses, Sign::n($now - 1000)); // size 1 -> 2: consistency-proven by every witness
        $b->record($c2);
        $c->record($c3);
        $hB = $b->publishHead($witnesses, Sign::n($now - 1000));
        $hC = $c->publishHead($witnesses, Sign::n($now - 1000));
        $bOrch = $a->enroll($keys['orchestrator']->public, 'orchestrator');
        $bTool = $b->enroll($keys['tool']->public, 'tool-agent');
        $bSvc = $c->enroll($keys['service']->public, 'service-agent');
        $evidence = [$a->evidence($root, $hA), $a->evidence($c1, $hA, $bOrch), $b->evidence($c2, $hB, $bTool), $c->evidence($c3, $hC, $bSvc)];
        $action = ['type' => 'payments.refund', 'resource' => '/orders/42/line/1', 'amount' => 25, 'service_domain' => $c->id, 'nonce' => 'n-0001', 'at' => $now];
        $proof = SignersMore::assembleMeshProof($chain, $evidence, $action, $keys['leaf']);
        $trust = Sign::n(['humanPrincipal' => $keys['human']->public, 'witnesses' => array_map(static fn(MeshWitness $w): string => $w->id, $witnesses), 'threshold' => 2,
            'now' => $now, 'allowedDomains' => [$a->id, $b->id, $c->id], 'rootDomain' => $a->id]);
        return ['trust' => $trust, 'proof' => $proof, 'evidence' => $evidence, 'domains' => ['A' => $a, 'B' => $b, 'C' => $c], 'witnesses' => $witnesses, 'keys' => $keys,
            'chain' => $chain, 'heads' => ['A0' => $hA0, 'A' => $hA, 'B' => $hB, 'C' => $hC], 'bindings' => ['orchestrator' => $bOrch, 'tool' => $bTool, 'service' => $bSvc]];
    }

    /**
     * A witness cosigns an honest extension and refuses a fork that rewrote history and merely grew past the prior size.
     *
     * @return array{honest_extension_cosigned: bool, fork_larger_than_prior: bool, size_only_check_would_accept: bool, fork_rejected: bool, fork_reason: string}
     */
    public static function demonstrateForkRejection(): array
    {
        $k = self::seedKey('fork-domain');
        $hk = self::seedKey('fork-human');
        $mk = static fn(int $n): Obj => Sign::mintRoot($hk, $hk->public, [['type' => 'scope', 'actions' => ["a$n"]]]);
        $w = new MeshWitness(self::seedKey('fork-witness'));
        $honest = new MeshDomain('X', $k);
        $honest->record($mk(0));
        $honest->record($mk(1));
        $honest->publishHead([$w], new Num('100'));
        $honest->record($mk(2));
        $honestOk = true;
        try {
            $honest->publishHead([$w], new Num('200'));
        } catch (\Throwable) {
            $honestOk = false;
        }
        $prior = (float)self::f($w->lastSeen($honest->id)?->get('size'));
        $fork = new MeshDomain('X', $k); // same key, rewritten history (entry 0 differs), grown past the prior size
        foreach ([100, 1, 2, 3] as $n) {
            $fork->record($mk($n));
        }
        $reason = '';
        $rejected = false;
        try {
            $fork->publishHead([$w], new Num('300'));
        } catch (\Throwable $e) {
            $rejected = true;
            $reason = $e->getMessage();
        }
        return ['honest_extension_cosigned' => $honestOk, 'fork_larger_than_prior' => 4 > $prior, 'size_only_check_would_accept' => 4 >= $prior, 'fork_rejected' => $rejected, 'fork_reason' => $reason];
    }

    // ---- cross-domain capability translation -----------------------------------------------------------------------

    private static function xcapBody(mixed $from, mixed $to, mixed $tip, mixed $caveats, mixed $issuedAt): Obj
    {
        return Obj::of(['v' => 'atlas-pca/mesh-xcap/v1', 'from' => $from, 'to' => $to, 'source_tip' => $tip, 'caveats' => $caveats, 'issued_at' => $issuedAt]);
    }

    /**
     * A bridge re-issues the tip of a verified source chain for another guardian: the caveats are the tip's, then `$additionalCaveats`
     * (append-only, so never wider), signed by the bridge key. Throws on an invalid source chain or malformed additional caveats.
     * `$pqPins` (root issuer => PQ public key) authorises a PQ or hybrid source root.
     *
     * @return Obj {source, fromGuardian, toGuardian, bridge, source_tip, caveats, issued_at, sig}
     */
    public static function translateCapability(mixed $chain, mixed $fromGuardian, mixed $toGuardian, KeyPair $bridge, mixed $issuedAt, mixed $additionalCaveats = self::UNSET, mixed $pqPins = null): Obj
    {
        [$reason, $ok] = Pca::verifyChain($chain, null, false, null, $pqPins);
        if (!$ok) {
            throw new \InvalidArgumentException("translateCapability: invalid source chain: $reason");
        }
        if ($additionalCaveats !== self::UNSET && !self::isCaveatArray($additionalCaveats)) {
            throw new \InvalidArgumentException('translateCapability: additionalCaveats must be an array of caveats');
        }
        $tip = $chain[count($chain) - 1];
        $caveats = [...$tip->get('caveats'), ...($additionalCaveats === self::UNSET ? [] : $additionalCaveats)];
        $tipHash = Pca::capHash($tip);
        $m = self::XCAP_DOMAIN . Json::canonicalizeNative(self::xcapBody($fromGuardian, $toGuardian, $tipHash, $caveats, $issuedAt));
        return Obj::of(['source' => $chain, 'fromGuardian' => $fromGuardian, 'toGuardian' => $toGuardian, 'bridge' => $bridge->public, 'source_tip' => $tipHash,
            'caveats' => $caveats, 'issued_at' => $issuedAt, 'sig' => Pca::b64u($bridge->sign($m))]);
    }

    /** The authority a translated capability conveys in the target domain, or `{error}`. @return array<string, mixed> */
    public static function translatedEffectiveAuthority(mixed $tc): array
    {
        if (!($tc instanceof Obj) || !self::isCaveatArray($tc->get('caveats'))) {
            return ['error' => 'malformed translated capability'];
        }
        return self::effectiveAuthority($tc->get('caveats'));
    }

    /**
     * Verify a translated capability: shape, the source chain (with the `rootIssuer` pin), the `fromGuardian` / `toGuardian` / `bridge`
     * pins, the tip binding, the append-only caveat prefix, the bridge signature, monotone narrowing, and expiry when `now` is given.
     * `$opts` is an Obj of `{pqPins?, fromGuardian?, toGuardian?, bridge?, rootIssuer?, now?}`; null options are refused, any other
     * non-object is no options. Never throws.
     *
     * @return array{ok: bool, reason?: string, from?: string, to?: string, bridge?: string, effective?: array}
     */
    public static function verifyTranslatedCapability(mixed $tc, mixed $opts = self::UNSET): array
    {
        $fail = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!($tc instanceof Obj) || !self::list($tc->get('source')) || !is_string($tc->get('fromGuardian')) || !is_string($tc->get('toGuardian'))
                || !is_string($tc->get('bridge')) || !is_string($tc->get('source_tip')) || !is_string($tc->get('sig')) || self::f($tc->get('issued_at')) === null
                || !self::isCaveatArray($tc->get('caveats')) || $opts === null) {
                return $fail('malformed translated capability');
            }
            $o = $opts instanceof Obj ? $opts : new Obj();
            [$reason, $ok] = Pca::verifyChain($tc->get('source'), $o->get('rootIssuer'), $o->has('rootIssuer'), null, $o->get('pqPins'));
            if (!$ok) {
                return $fail("source chain: $reason");
            }
            if ($o->has('fromGuardian') && $tc->get('fromGuardian') !== $o->get('fromGuardian')) {
                return $fail('source guardian mismatch');
            }
            if ($o->has('toGuardian') && $tc->get('toGuardian') !== $o->get('toGuardian')) {
                return $fail('target guardian mismatch');
            }
            if ($o->has('bridge') && $tc->get('bridge') !== $o->get('bridge')) {
                return $fail('bridge key mismatch');
            }
            if ($tc->get('fromGuardian') === $tc->get('toGuardian')) {
                return $fail('translation does not cross a domain boundary');
            }
            $source = $tc->get('source');
            $tip = $source[count($source) - 1];
            if ($tc->get('source_tip') !== Pca::capHash($tip)) {
                return $fail('source_tip does not match the source chain tip');
            }
            $caveats = $tc->get('caveats');
            $tipCaveats = $tip->get('caveats');
            if (count($caveats) < count($tipCaveats)) {
                return $fail('translation drops a source caveat (widening)');
            }
            foreach ($tipCaveats as $j => $c) {
                if (Json::canonicalizeNative($caveats[$j]) !== Json::canonicalizeNative($c)) {
                    return $fail("translation altered or reordered source caveat $j (widening)");
                }
            }
            $m = self::XCAP_DOMAIN . Json::canonicalizeNative(self::xcapBody($tc->get('fromGuardian'), $tc->get('toGuardian'), $tc->get('source_tip'), $caveats, $tc->get('issued_at')));
            if (!Pca::verifyEd25519B64u($tc->get('bridge'), $m, $tc->get('sig'))) {
                return $fail('translation not signed by the declared bridge key');
            }
            $effS = self::effectiveAuthority($tipCaveats);
            if (isset($effS['error'])) {
                return $fail('source caveats: ' . $effS['error']);
            }
            $effT = self::effectiveAuthority($caveats);
            if (isset($effT['error'])) {
                return $fail($effT['error']);
            }
            if (!self::narrows($effT, $effS)) {
                return $fail('translated authority widens the source authority');
            }
            if ($o->has('now') && isset($effT['expiresAt']) && !(Jsx::toNum($o->get('now')) <= Jsx::toNum($effT['expiresAt']))) {
                return $fail('translated capability expired');
            }
            return ['ok' => true, 'from' => $tc->get('fromGuardian'), 'to' => $tc->get('toGuardian'), 'bridge' => $tc->get('bridge'), 'effective' => $effT];
        } catch (\Throwable) {
            return $fail('malformed translated capability');
        }
    }

    // ---- federated budget tree -------------------------------------------------------------------------------------

    private static function validBudgetState(mixed $s): bool
    {
        if (!($s instanceof Obj) || !($s->get('nodes') instanceof Obj) || !is_string($s->get('root')) || ($k = self::f($s->get('kappa'))) === null || ($m = self::f($s->get('bMax'))) === null) {
            return false;
        }
        if ($k <= 0 || $m < 0 || !$s->get('nodes')->has($s->get('root'))) {
            return false;
        }
        foreach ($s->get('nodes')->keys() as $id) {
            $n = $s->get('nodes')->get($id);
            if (!($n instanceof Obj) || !is_string($n->get('domain')) || ($b = self::f($n->get('B'))) === null || $b < 0 || ($n->has('parent') && !is_string($n->get('parent')))) {
                return false;
            }
        }
        return true;
    }

    /** `$state` with `$nodes` entries added or replaced (a copy; the input is not changed). @param array<string, Obj> $nodes */
    private static function withNodes(Obj $state, array $nodes): array
    {
        $all = $state->get('nodes')->without();
        foreach ($nodes as $id => $n) {
            $all->set((string)$id, $n);
        }
        $out = $state->without();
        $out->set('nodes', $all);
        return ['ok' => true, 'state' => $out];
    }

    private static function nodeWithB(Obj $node, float $b): Obj
    {
        $n = $node->without();
        $n->set('B', Sign::n($b));
        return $n;
    }

    /**
     * A budget tree with one root node. `$args` is `{rootId, rootDomain, B0, kappa, bMax}`.
     *
     * @return array{ok: true, state: Obj}|array{ok: false, reason: string}
     */
    public static function createFederatedBudget(mixed $args): array
    {
        if (!($args instanceof Obj) || !is_string($args->get('rootId')) || !is_string($args->get('rootDomain'))) {
            return ['ok' => false, 'reason' => 'malformed root'];
        }
        $kappa = self::f($args->get('kappa'));
        if ($kappa === null || $kappa <= 0) {
            return ['ok' => false, 'reason' => 'kappa must be finite and > 0'];
        }
        $bMax = self::f($args->get('bMax'));
        if ($bMax === null || $bMax < 0) {
            return ['ok' => false, 'reason' => 'bMax must be finite and >= 0'];
        }
        $b0 = self::f($args->get('B0'));
        if ($b0 === null || $b0 < 0) {
            return ['ok' => false, 'reason' => 'B0 must be finite and >= 0'];
        }
        if ($b0 > $bMax) {
            return ['ok' => false, 'reason' => 'B0 exceeds bMax'];
        }
        $nodes = new Obj();
        $nodes->set($args->get('rootId'), Obj::of(['domain' => $args->get('rootDomain'), 'B' => $args->get('B0')]));
        return ['ok' => true, 'state' => Obj::of(['nodes' => $nodes, 'root' => $args->get('rootId'), 'kappa' => $args->get('kappa'), 'bMax' => $args->get('bMax')])];
    }

    /**
     * Allocate a sub-budget under `parent`: a CEILING bounded by the parent's current remaining budget; the parent is not reduced.
     * `$args` is `{id, domain, parent, alloc}`.
     *
     * @return array{ok: true, state: Obj}|array{ok: false, reason: string}
     */
    public static function allocateSub(mixed $state, mixed $args): array
    {
        if (!self::validBudgetState($state)) {
            return ['ok' => false, 'reason' => 'malformed budget state'];
        }
        if (!($args instanceof Obj) || !is_string($args->get('id')) || !is_string($args->get('domain')) || !is_string($args->get('parent'))) {
            return ['ok' => false, 'reason' => 'malformed allocation'];
        }
        $nodes = $state->get('nodes');
        if ($nodes->has($args->get('id'))) {
            return ['ok' => false, 'reason' => 'node id already exists'];
        }
        if (!$nodes->has($args->get('parent'))) {
            return ['ok' => false, 'reason' => 'unknown parent'];
        }
        $sub = Risk::subBudget(['B' => (float)self::f($nodes->get($args->get('parent'))->get('B')), 'tau' => 0.0], self::f($args->get('alloc')));
        if (!$sub['ok']) {
            return ['ok' => false, 'reason' => $sub['reason']];
        }
        return self::withNodes($state, [$args->get('id') => Obj::of(['domain' => $args->get('domain'), 'parent' => $args->get('parent'), 'B' => $args->get('alloc')])]);
    }

    /** The path from a node up to the root (node first), or why there is none. @return array{0: ?list<string>, 1: string} */
    private static function budgetPath(Obj $state, string $nodeId): array
    {
        $nodes = $state->get('nodes');
        $path = [];
        $cur = $nodeId;
        while ($cur !== null) {
            if (!$nodes->has($cur)) {
                return [null, 'unknown node'];
            }
            if (in_array($cur, $path, true)) {
                return [null, 'cycle in budget tree'];
            }
            if (count($path) >= self::DEFAULT_MAX_CHAIN_LENGTH) {
                return [null, 'budget tree too deep'];
            }
            $path[] = $cur;
            $cur = $nodes->get($cur)->has('parent') ? $nodes->get($cur)->get('parent') : null;
        }
        return $path[count($path) - 1] === $state->get('root') ? [$path, ''] : [null, 'node is not rooted at the budget root'];
    }

    /**
     * Spend `$c` at a node: atomic; every strict-interior ancestor must cover the cost, then the root and the spender are debited
     * together and each interior ancestor is debited.
     *
     * @return array{ok: true, state: Obj}|array{ok: false, reason: string}
     */
    public static function spendFederated(mixed $state, mixed $nodeId, mixed $c): array
    {
        if (!self::validBudgetState($state)) {
            return ['ok' => false, 'reason' => 'malformed budget state'];
        }
        if (!is_string($nodeId)) {
            return ['ok' => false, 'reason' => 'malformed node id'];
        }
        $cost = self::f($c);
        if ($cost === null || $cost < 0) {
            return ['ok' => false, 'reason' => 'spend must be finite and >= 0'];
        }
        [$path, $why] = self::budgetPath($state, $nodeId);
        if ($path === null) {
            return ['ok' => false, 'reason' => $why];
        }
        $nodes = $state->get('nodes');
        $rootId = $state->get('root');
        $b = static fn(string $id): float => (float)self::f($nodes->get($id)->get('B'));
        $bud = static fn(string $id): array => ['B' => $b($id), 'tau' => 0.0];
        if ($nodeId === $rootId) {
            if (!($b($rootId) >= $cost)) {
                return ['ok' => false, 'reason' => 'root budget insufficient'];
            }
            return self::withNodes($state, [$rootId => self::nodeWithB($nodes->get($rootId), Risk::debit($bud($rootId), $cost)['B'])]);
        }
        $interior = array_slice($path, 1, -1);
        foreach ($interior as $id) {
            if (!($b($id) >= $cost)) {
                return ['ok' => false, 'reason' => "ancestor \"$id\" budget insufficient"];
            }
        }
        $dc = Risk::debitConsolidated($bud($rootId), $bud($nodeId), $cost);
        if (!$dc['ok']) {
            return ['ok' => false, 'reason' => $dc['reason']];
        }
        $next = [$nodeId => self::nodeWithB($nodes->get($nodeId), $dc['sub']['B']), $rootId => self::nodeWithB($nodes->get($rootId), $dc['parent']['B'])];
        foreach ($interior as $id) {
            $next[$id] = self::nodeWithB($nodes->get($id), Risk::debit($bud($id), $cost)['B']);
        }
        return self::withNodes($state, $next);
    }

    /** The tree-wide spend bound bMax / kappa (0 for a malformed input or a non-positive kappa). */
    public static function federatedSafetyBound(mixed $p): float
    {
        if (!($p instanceof Obj) || ($bMax = self::f($p->get('bMax'))) === null || ($kappa = self::f($p->get('kappa'))) === null) {
            return 0.0;
        }
        return $kappa > 0 ? fdiv(max(0.0, $bMax), $kappa) : 0.0;
    }

    // ---- cross-reference commitments -------------------------------------------------------------------------------

    /** The digest of a mesh action. Throws on a value the canonical hash refuses. */
    public static function meshActionDigest(mixed $action): string
    {
        return Pca::hashCanonical(Obj::of(['v' => self::ACTION_DIGEST_DOMAIN, 'action' => $action]));
    }

    /** The commitment both domains anchor: binds `{action_digest, fromGuardian, toGuardian, nonce, at}`. Throws when a member is absent or unhashable. */
    public static function crossReferenceCommit(mixed $x): string
    {
        if ($x === null) {
            throw new \InvalidArgumentException('crossReferenceCommit: null');
        }
        $x = $x instanceof Obj ? $x : new Obj();
        return Pca::hashCanonical(Obj::of(['v' => 'atlas-pca/mesh-xref/v1', 'action_digest' => self::need($x, 'action_digest'), 'from' => self::need($x, 'fromGuardian'),
            'to' => self::need($x, 'toGuardian'), 'nonce' => self::need($x, 'nonce'), 'at' => self::need($x, 'at')]));
    }

    /** A domain's signed anchor `{domain, commit, seq, sig}` of a commitment at its log position `$seq` (the verifier checks that `$seq` is a natural number). */
    public static function anchorCrossReference(KeyPair $domain, mixed $commit, mixed $seq): Obj
    {
        $m = self::XANCHOR_DOMAIN . Json::canonicalizeNative(Obj::of(['commit' => $commit, 'seq' => $seq]));
        return Obj::of(['domain' => $domain->public, 'commit' => $commit, 'seq' => $seq, 'sig' => Pca::b64u($domain->sign($m))]);
    }

    private static function validAnchor(mixed $a): bool
    {
        return $a instanceof Obj && is_string($a->get('domain')) && is_string($a->get('commit')) && self::nat($a->get('seq')) && is_string($a->get('sig'));
    }

    /**
     * Both domains anchored the SAME commitment of this cross-reference. `$anchors` is `{from, to}`. Never throws.
     *
     * @return array{ok: bool, reason?: string, commit?: string}
     */
    public static function verifyCrossReference(mixed $x, mixed $anchors): array
    {
        $fail = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!($x instanceof Obj) || !is_string($x->get('action_digest')) || !is_string($x->get('fromGuardian')) || !is_string($x->get('toGuardian')) || !is_string($x->get('nonce')) || self::f($x->get('at')) === null) {
                return $fail('malformed cross-reference');
            }
            if (!($anchors instanceof Obj) || !self::validAnchor($from = $anchors->get('from')) || !self::validAnchor($to = $anchors->get('to'))) {
                return $fail('malformed anchors');
            }
            if ($x->get('fromGuardian') === $x->get('toGuardian')) {
                return $fail('cross-reference must span two distinct domains');
            }
            $expected = self::crossReferenceCommit($x);
            if ($from->get('domain') !== $x->get('fromGuardian')) {
                return $fail('source anchor domain does not match the cross-reference');
            }
            if ($to->get('domain') !== $x->get('toGuardian')) {
                return $fail('target anchor domain does not match the cross-reference');
            }
            if ($from->get('commit') !== $expected) {
                return $fail('source anchor commits a different action');
            }
            if ($to->get('commit') !== $expected) {
                return $fail('target anchor commits a different action');
            }
            $msg = static fn(Obj $a): string => self::XANCHOR_DOMAIN . Json::canonicalizeNative(Obj::of(['commit' => $a->get('commit'), 'seq' => $a->get('seq')]));
            if (!Pca::verifyEd25519B64u($from->get('domain'), $msg($from), $from->get('sig'))) {
                return $fail('source anchor signature invalid');
            }
            if (!Pca::verifyEd25519B64u($to->get('domain'), $msg($to), $to->get('sig'))) {
                return $fail('target anchor signature invalid');
            }
            return ['ok' => true, 'commit' => $expected];
        } catch (\Throwable) {
            return $fail('malformed cross-reference');
        }
    }
}
