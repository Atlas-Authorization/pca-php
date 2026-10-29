<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Ledger.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Mesh.php';

/**
 * Verifier-side revocation staleness policy (T9, additive: nothing changes unless a window is set). The signer chooses
 * `not_after`; this lets the VERIFIER cap how old (`now - issued_at`) the revocation state may be, with a stricter window for
 * actions that cannot be undone. The class is the stricter of the server's authoritative class and the PCActn's signed
 * `reversibility_class`; a missing or unknown class counts as irreversible (fail closed).
 */
final class RevocationStalenessPolicy
{
    /**
     * @param float|null                                      $maxRevocationAgeMs maximum age for any action (null: 5 minutes)
     * @param array{irreversible?:float|null,costly?:float|null}|null $staleness per-class windows, each capped by
     *        `maxRevocationAgeMs` (defaults: irreversible 2 minutes; costly and rate_limited = `maxRevocationAgeMs`)
     * @param bool                                            $allowUnsignedRootForIrreversible accept revocation state that is not
     *        guardian-signed (a bare root) for an irreversible action
     * @param (callable(Obj):array)|null                      $ids which capability ids need a non-membership proof, given the
     *        PCActn (default: every `id` in its cap_chain, so a revoked ancestor kills its descendants)
     * @param (callable(string,Obj):mixed)|array<string,mixed>|null $proofs the non-membership proof (an Obj `{size, lo?, hi?}`) for a
     *        capability id, given the PCActn, or a map keyed by id. A missing source or proof DENIES (fail closed); pass
     *        `ids: fn () => []` to check freshness only
     */
    public function __construct(
        public readonly ?float $maxRevocationAgeMs = null,
        public readonly ?array $staleness = null,
        public readonly bool $allowUnsignedRootForIrreversible = false,
        public readonly mixed $ids = null,
        public readonly mixed $proofs = null,
    ) {
    }

    /** True when the policy turns the staleness check on (any window set). */
    public function on(): bool
    {
        return $this->maxRevocationAgeMs !== null || $this->staleness !== null;
    }

    /** null when valid, else why not: every window that is set must be a finite positive number of milliseconds. */
    public function validate(): ?string
    {
        $chk = static fn(string $name, ?float $v): ?string => $v !== null && !(is_finite($v) && $v > 0)
            ? "$name must be a positive number of milliseconds" : null;
        if ($this->ids !== null && !is_callable($this->ids)) {
            return 'ids must be callable';
        }
        if ($this->proofs !== null && !is_callable($this->proofs) && !is_array($this->proofs)) {
            return 'proofs must be callable or an array';
        }
        return $chk('maxRevocationAgeMs', $this->maxRevocationAgeMs)
            ?? $chk('staleness.irreversible', $this->staleness['irreversible'] ?? null)
            ?? $chk('staleness.costly', $this->staleness['costly'] ?? null);
    }

    /**
     * Read {maxRevocationAgeMs?, staleness?: {irreversible?, costly?}, allowUnsignedRootForIrreversible?} from parsed JSON
     * (an Obj) or a PHP array. A set value that is not a number becomes NaN, which {@see validate} refuses.
     */
    public static function fromJson(mixed $v): self
    {
        $get = static function (mixed $o, string $k): array {
            if ($o instanceof Obj) {
                return [$o->has($k), $o->get($k)];
            }
            return is_array($o) ? [array_key_exists($k, $o), $o[$k] ?? null] : [false, null];
        };
        $num = static function (mixed $o, string $k) use ($get): ?float {
            [$has, $x] = $get($o, $k);
            if (!$has) {
                return null;
            }
            $f = $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : NAN);
            return $f;
        };
        [$hasS, $s] = $get($v, 'staleness');
        [, $allow] = $get($v, 'allowUnsignedRootForIrreversible');
        return new self($num($v, 'maxRevocationAgeMs'),
            $hasS ? ['irreversible' => $num($s, 'irreversible'), 'costly' => $num($s, 'rate_limited') ?? $num($s, 'costly')] : null, $allow === true);
    }
}

/**
 * The revocation state an {@see Authorize} call holds for a grant: a guardian-signed `epoch` (an Obj), or a bare `root` with
 * the time `rootIssuedAt` (epoch ms) your trusted source issued it. Both empty: no verifiable state.
 */
final class RevocationState
{
    public function __construct(
        public readonly ?Obj $epoch = null,
        public readonly ?string $root = null,
        public readonly ?float $rootIssuedAt = null,
        public readonly ?float $lastAcceptedEpoch = null,
    ) {
    }
}

/**
 * Revocation staleness (T9): the verifier-side age cap per reversibility class, the guardian-signed revocation epoch (Ed25519
 * and every suite this build implements, under the same pin rules as the ledger verifiers) and the gate that combines them.
 * Mirrors the reference revocation module (checkRevocationAge, revocationMaxAgeMs, effectiveReversibility, checkRevocationEpoch
 * and the staleness branch of the revocation checker). Every function is total: nothing throws on a hostile epoch.
 */
final class RevocationStaleness
{
    public const EPOCH_DOMAIN = "atlas-pca/revepoch/v1\0";
    /** The server re-signs the epoch at least this often. */
    public const EPOCH_REFRESH_MS = 60000;
    /** How long a signed epoch is acceptable (longer than the refresh period). */
    public const EPOCH_VALIDITY_MS = 300000;
    /** Default maximum age of revocation state for an irreversible action (two refreshes). */
    public const IRREVERSIBLE_MAX_AGE_MS = 120000;
    public const SKEW_MS = 60000;
    private const MAX_SAFE = 9007199254740991;
    private const BODY_KEYS = ['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'];
    /** Shared reversibility class table: reversible 0, rate_limited 1, costly 1, irreversible 2; unknown = 2. */
    private const CLASS_RANK = ['reversible' => 0, 'rate_limited' => 1, 'costly' => 1, 'irreversible' => 2];

    private static function rank(mixed $c): int
    {
        return is_string($c) ? (self::CLASS_RANK[$c] ?? 2) : 2;
    }

    /** The stricter of the server's class (null = none) and the signed one: 'reversible', 'rate_limited' or 'irreversible'. */
    public static function effectiveReversibility(?string $serverClass, mixed $signedClass): string
    {
        $rank = max($serverClass === null ? 0 : self::rank($serverClass), self::rank($signedClass));
        return $rank >= 2 ? 'irreversible' : ($rank === 1 ? 'rate_limited' : 'reversible');
    }

    /** The maximum age (ms) of revocation state the policy allows for an action of class `$cls`. */
    public static function maxAgeMs(RevocationStalenessPolicy $p, string $cls): float
    {
        $max = $p->maxRevocationAgeMs ?? (float)self::EPOCH_VALIDITY_MS;
        // NaN anywhere stays NaN (min() would drop it), so the age check then fails closed
        $pick = static function (?float $w, float $def) use ($max): float {
            $w ??= $def;
            return is_nan($w) || is_nan($max) ? NAN : min($max, $w);
        };
        return match ($cls) {
            'irreversible' => $pick($p->staleness['irreversible'] ?? null, (float)self::IRREVERSIBLE_MAX_AGE_MS),
            'costly', 'rate_limited' => $pick($p->staleness['rate_limited'] ?? $p->staleness['costly'] ?? null, $max),
            default => $max,
        };
    }

    /**
     * verifyNonMembership: true iff `$proof` (an Obj `{size, lo?, hi?}` of leaf proofs) shows `$id` is NOT in the sorted
     * revocation set the size-bound `$root` commits to. A revoked id has no valid proof. Total.
     */
    public static function verifyNonMembership(mixed $root, mixed $proof, mixed $id): bool
    {
        try {
            return is_string($root) && is_string($id) && $proof instanceof Obj && Mesh::nonMembership($root, $proof, $id);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function ms(float $v): string
    {
        return IntentV2::jsNumStr($v);
    }

    /**
     * Age check of revocation state issued at `$issuedAt` (null or non-finite: unknown, denied). `$what` names the state in the
     * reason. A time more than 60 s in the future denies.
     * @return array{ok:bool, reason?:string}
     */
    public static function checkAge(?float $issuedAt, float $now, float $maxAgeMs, string $what = 'revocation state'): array
    {
        if ($issuedAt === null || !is_finite($issuedAt)) {
            return ['ok' => false, 'reason' => "$what age is unknown (unverifiable revocation state)"];
        }
        if (!($issuedAt <= $now + self::SKEW_MS)) {
            return ['ok' => false, 'reason' => "$what issued in the future"];
        }
        if (!($now - $issuedAt <= $maxAgeMs)) {
            return ['ok' => false, 'reason' => "$what is " . self::ms($now - $issuedAt) . " ms old, over the verifier's maximum of "
                . self::ms($maxAgeMs) . ' ms (stale revocation state)'];
        }
        return ['ok' => true];
    }

    /** A JSON number (Num or native) as a safe integer value, else null. */
    private static function safeInt(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) && floor($v) === $v && abs($v) <= self::MAX_SAFE ? $v : null;
    }

    private static function fnum(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    /**
     * Verify a guardian-signed revocation epoch: the guardian, a registered suite, shape, signature, grant binding,
     * `not_after`, issue time, the verifier's age cap, rollback and the PCActn's freshness. Never throws.
     *
     * @param array{guardianPublic:string, now:float|int, pins?:mixed, grantRef?:?string, lastAcceptedEpoch?:?float,
     *              pcactnEpoch?:?float, maxAgeMs?:?float} $o `pins` pins the post-quantum key of a PQ / hybrid guardian
     *              ({Ed25519 b64u => ML-DSA public key b64u}); `now` is REQUIRED (no implicit clock)
     * @return array{ok:bool, reason?:string}
     */
    public static function checkEpoch(mixed $ep, array $o): array
    {
        try {
            $notSigned = ['ok' => false, 'reason' => 'revocation epoch not signed by the pinned guardian'];
            if (!($ep instanceof Obj) || $ep->get('guardian') !== ($o['guardianPublic'] ?? null)) {
                return $notSigned;
            }
            if ($ep->has('alg') && !in_array($ep->get('alg'), Pca::REGISTERED_SUITES, true)) {
                return $notSigned;
            }
            $epoch = self::safeInt($ep->get('epoch'));
            $setSize = self::safeInt($ep->get('set_size'));
            $issued = self::safeInt($ep->get('issued_at'));
            $notAfter = self::safeInt($ep->get('not_after'));
            if ($epoch === null || $epoch < 0 || $setSize === null || $setSize < 0 || $issued === null || $notAfter === null) {
                return ['ok' => false, 'reason' => 'malformed revocation epoch'];
            }
            $body = new Obj();
            foreach (self::BODY_KEYS as $k) {
                if (!$ep->has($k)) {
                    return ['ok' => false, 'reason' => 'revocation epoch check error']; // the reference throws on an absent member
                }
                $body->set($k, $ep->get($k));
            }
            if (!Ledger::signed(self::EPOCH_DOMAIN, $body, $o['guardianPublic'], $ep, $o['pins'] ?? null)) {
                return ['ok' => false, 'reason' => 'revocation epoch signature invalid'];
            }
            $now = (float)$o['now'];
            if (($o['grantRef'] ?? null) !== null && $ep->get('grant_ref') !== $o['grantRef']) {
                return ['ok' => false, 'reason' => 'revocation epoch is for a different grant'];
            }
            if (!($now <= $notAfter)) {
                return ['ok' => false, 'reason' => 'revocation epoch expired (stale revocation root)'];
            }
            if (!($issued <= $now + self::SKEW_MS)) {
                return ['ok' => false, 'reason' => 'revocation epoch issued in the future'];
            }
            if (($o['maxAgeMs'] ?? null) !== null) {
                $age = self::checkAge($issued, $now, (float)$o['maxAgeMs'], 'revocation epoch');
                if (!$age['ok']) {
                    return $age;
                }
            }
            $last = $o['lastAcceptedEpoch'] ?? null;
            if ($last !== null && $epoch < $last) {
                return ['ok' => false, 'reason' => 'revocation epoch ' . self::ms($epoch) . ' is older than the last accepted '
                    . self::ms((float)$last) . ' (rollback)'];
            }
            $pe = $o['pcactnEpoch'] ?? null;
            if ($pe !== null && !($pe >= $epoch)) {
                return ['ok' => false, 'reason' => 'PCActn freshness.epoch ' . self::ms((float)$pe) . ' predates the revocation epoch '
                    . self::ms($epoch)];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'revocation epoch check error'];
        }
    }

    /**
     * Sign an Ed25519 revocation epoch with the guardian's 32-byte seed, in the wire form {@see checkEpoch} verifies (a PQ or
     * hybrid guardian signs with its own tooling).
     * @param array{instance_id:string, grant_ref:string, epoch:int, set_size:int, root:string, issued_at:int, not_after:int} $b
     */
    public static function signEpoch(string $guardianSeed, array $b): Obj
    {
        if (strlen($guardianSeed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('signEpoch: the guardian seed must be ' . SODIUM_CRYPTO_SIGN_SEEDBYTES . ' bytes');
        }
        $body = new Obj();
        foreach (self::BODY_KEYS as $k) {
            if (!array_key_exists($k, $b)) {
                throw new \InvalidArgumentException("signEpoch: missing $k");
            }
            $body->set($k, is_int($b[$k]) ? new Num((string)$b[$k]) : $b[$k]);
        }
        $kp = sodium_crypto_sign_seed_keypair($guardianSeed);
        $out = new Obj();
        foreach (self::BODY_KEYS as $k) {
            $out->set($k, $body->get($k));
        }
        $out->set('guardian', Pca::b64u(sodium_crypto_sign_publickey($kp)));
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::EPOCH_DOMAIN . Json::canonicalizeStrict($body), sodium_crypto_sign_secretkey($kp))));
        return $out;
    }

    /**
     * Decide whether the revocation state is fresh enough: the staleness branch of the reference revocation checker, then (when
     * `ids` is given) that every one of those capability ids has a valid non-membership proof against the state's root. Fail
     * closed: a missing signed epoch, an unverifiable one, a mismatching root, no root, a missing proof or a revoked id is a refusal.
     *
     * @param array{policy:RevocationStalenessPolicy, now:float|int, guardianPublic?:?string, pins?:mixed, grantRef?:?string,
     *              pcactnEpoch?:?float, serverClass?:?string, signedClass?:mixed, epochSource?:bool, epoch?:?Obj,
     *              lastAcceptedEpoch?:?float, root?:?string, rootIssuedAt?:?float, ids?:?array, proofs?:?callable} $in
     *        `epochSource` says a signed epoch is the expected source (`epoch` is the one presented); `root` is a bare root (with
     *        an epoch source it must equal the epoch's root), `rootIssuedAt` the time your trusted source issued it;
     *        `ids` are the capability ids to prove (null: none) and `proofs` a `(string $id): mixed` source (null: none supplied)
     * @return array{ok:bool, reason?:string, root?:string}
     */
    public static function gate(array $in): array
    {
        try {
            $policy = $in['policy'];
            $now = (float)$in['now'];
            if (($why = $policy->validate()) !== null) {
                return ['ok' => false, 'reason' => "revocation staleness policy invalid: $why"];
            }
            $staleness = $policy->on();
            $root = $in['root'] ?? null;
            $maxAge = null;
            $cls = null;
            if ($staleness) {
                $cls = self::effectiveReversibility($in['serverClass'] ?? null, $in['signedClass'] ?? null);
                $maxAge = self::maxAgeMs($policy, $cls);
            }
            if (($in['epochSource'] ?? false) === true) {
                $ep = $in['epoch'] ?? null;
                $guardian = $in['guardianPublic'] ?? null;
                if (!($ep instanceof Obj) || !is_string($guardian) || $guardian === '') {
                    return ['ok' => false, 'reason' => 'no signed revocation epoch'];
                }
                $chk = self::checkEpoch($ep, ['guardianPublic' => $guardian, 'pins' => $in['pins'] ?? null, 'now' => $now,
                    'grantRef' => $in['grantRef'] ?? null, 'lastAcceptedEpoch' => $in['lastAcceptedEpoch'] ?? null,
                    'pcactnEpoch' => $in['pcactnEpoch'] ?? null, 'maxAgeMs' => $maxAge]);
                if (!$chk['ok']) {
                    return ['ok' => false, 'reason' => $chk['reason']];
                }
                $epRoot = $ep->get('root');
                if ($root !== null && $root !== '' && $root !== $epRoot) {
                    return ['ok' => false, 'reason' => 'revocation root does not match the signed epoch'];
                }
                $root = is_string($epRoot) ? $epRoot : null;
            } elseif ($staleness) {
                if ($cls === 'irreversible' && !$policy->allowUnsignedRootForIrreversible) {
                    return ['ok' => false, 'reason' => 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)'];
                }
                $age = self::checkAge($in['rootIssuedAt'] ?? null, $now, (float)$maxAge, 'revocation root');
                if (!$age['ok']) {
                    return $age;
                }
            }
            if ($root === null || $root === '') {
                return ['ok' => false, 'reason' => 'no revocation root'];
            }
            foreach ($in['ids'] ?? [] as $id) {
                if (!is_string($id)) {
                    return ['ok' => false, 'reason' => 'capability id is not a string (fail closed)'];
                }
                $proof = isset($in['proofs']) ? ($in['proofs'])($id) : null;
                if ($proof === null) {
                    return ['ok' => false, 'reason' => "no non-membership proof for $id"];
                }
                if (!self::verifyNonMembership($root, $proof, $id)) {
                    return ['ok' => false, 'reason' => "capability $id is revoked or proof invalid"];
                }
            }
            return ['ok' => true, 'root' => $root];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'revocation staleness check error (fail closed)'];
        }
    }

    /**
     * The gate for one {@see Authorize} decision (policy on). `$state` may be null (the source had nothing). Returns the reason
     * it was refused, or null when the revocation state is fresh enough.
     */
    public static function freshness(RevocationStalenessPolicy $policy, ?string $guardianPublic, mixed $pins, Obj $pcactn,
                                     ?string $serverClass, float $now, ?RevocationState $state): ?string
    {
        $action = $pcactn->get('action');
        $signed = $action instanceof Obj ? $action->get('reversibility_class') : null;
        if ($state === null || ($state->epoch === null && ($state->root ?? '') === '')) {
            return self::effectiveReversibility($serverClass, $signed) === 'irreversible' && !$policy->allowUnsignedRootForIrreversible
                ? 'no verifiable (guardian-signed) revocation state for an irreversible action'
                : 'no signed revocation epoch';
        }
        $fr = $pcactn->get('freshness');
        try {
            if ($policy->ids !== null) {
                $ids = ($policy->ids)($pcactn);
            } else {
                $chain = $pcactn->get('cap_chain');
                $ids = array_map(static fn($c) => $c instanceof Obj ? $c->get('id') : null, is_array($chain) ? $chain : []);
            }
            if (!is_array($ids)) {
                return 'the revocation proof source failed (fail closed)';
            }
            $src = $policy->proofs;
            $proofs = is_callable($src) ? static fn(string $id): mixed => $src($id, $pcactn)
                : (is_array($src) ? static fn(string $id): mixed => $src[$id] ?? null : null);
        } catch (\Throwable) {
            return 'the revocation proof source failed (fail closed)';
        }
        $r = self::gate(['policy' => $policy, 'now' => $now, 'guardianPublic' => $guardianPublic, 'pins' => $pins,
            'grantRef' => is_string($pcactn->get('grant_ref')) ? $pcactn->get('grant_ref') : null,
            'pcactnEpoch' => $fr instanceof Obj ? self::fnum($fr->get('epoch')) : null,
            'serverClass' => $serverClass, 'signedClass' => $signed, 'epochSource' => $state->epoch !== null, 'epoch' => $state->epoch,
            'lastAcceptedEpoch' => $state->lastAcceptedEpoch, 'root' => $state->root, 'rootIssuedAt' => $state->rootIssuedAt,
            'ids' => $ids, 'proofs' => $proofs]);
        return $r['ok'] ? null : ($r['reason'] ?? 'revocation state refused');
    }
}
