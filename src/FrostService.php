<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Frost.php';
require_once __DIR__ . '/FrostNet.php';
require_once __DIR__ . '/FrostNonceStore.php';
require_once __DIR__ . '/Jsx.php';

/**
 * One guardian's networked FROST signer: it holds a single signing share, answers round 1 (a fresh commitment plus its proof of possession) and round 2
 * (a signature share) and refuses everything it cannot verify. Round 2 is ONE-SHOT per session: the nonces are spent (in the durable store first, when one
 * is configured) before the share is computed, a repeat is refused, and a signing set that omits or alters this signer's own commitment is refused. A round-2
 * request is honoured only with a policy allow token signed by the trusted authority for exactly this action and group key. Every refusal is a value.
 * `$opts`: identifier, share (32 raw bytes), groupPublicKey, threshold, policyAuthorityPublicKey, sessionTtlMs?, now? (closure returning ms), nonceStore?
 * (any object with create/load/spend/drop/isSpent), random? (closure returning 32 bytes: the nonce-randomness seam used by tests; random_bytes when absent).
 */
final class GuardianSignerService
{
    public readonly int $identifier;
    public readonly string $verificationShare;
    private readonly string $share;
    private readonly string $groupPublicKey;
    private readonly int $threshold;
    private readonly string $policyAuthorityPublicKey;
    private readonly int|float|null $sessionTtlMs;
    private readonly \Closure $now;
    private readonly mixed $store;
    private readonly ?\Closure $random;
    private readonly Obj $pop;
    /** @var array<string,array{nonces:FrostNonces,commitment:array,createdAt:mixed}> */
    private array $sessions = [];
    /** @var array<string,true> */
    private array $spent = [];

    public function __construct(array $opts)
    {
        $idn = Js::num($opts['identifier'] ?? null);
        if ($idn === null || !is_finite($idn) || $idn != floor($idn) || abs($idn) > 9007199254740991.0 || $idn <= 0) {
            throw new \RuntimeException('GuardianSignerService: identifier must be a positive integer');
        }
        $bytes32 = static fn(mixed $x): bool => is_string($x) && strlen($x) === 32;
        if (!$bytes32($opts['share'] ?? null)) {
            throw new \RuntimeException('GuardianSignerService: share must be 32 bytes');
        }
        if (!$bytes32($opts['groupPublicKey'] ?? null)) {
            throw new \RuntimeException('GuardianSignerService: groupPublicKey must be 32 bytes');
        }
        $t = Js::num($opts['threshold'] ?? null);
        if ($t === null || !is_finite($t) || $t != floor($t) || abs($t) > 9007199254740991.0 || $t < 1) {
            throw new \RuntimeException('GuardianSignerService: threshold must be a positive integer');
        }
        if (!$bytes32($opts['policyAuthorityPublicKey'] ?? null)) {
            throw new \RuntimeException('GuardianSignerService: policyAuthorityPublicKey must be 32 bytes');
        }
        $ttl = $opts['sessionTtlMs'] ?? null;
        if ($ttl !== null) {
            $tn = Js::num($ttl);
            if ($tn === null || !is_finite($tn) || $tn <= 0) {
                throw new \RuntimeException('GuardianSignerService: sessionTtlMs must be a positive finite number');
            }
        }
        $store = $opts['nonceStore'] ?? null;
        if ($store !== null) {
            foreach (['create', 'load', 'spend', 'drop', 'isSpent'] as $m) {
                if (!is_object($store) || !method_exists($store, $m)) {
                    throw new \RuntimeException("GuardianSignerService: nonceStore.$m must be a function");
                }
            }
        }
        $this->identifier = (int)$idn;
        $this->share = $opts['share'];
        $this->groupPublicKey = $opts['groupPublicKey'];
        $this->threshold = (int)$t;
        $this->policyAuthorityPublicKey = $opts['policyAuthorityPublicKey'];
        $this->sessionTtlMs = $ttl === null ? null : Js::num($ttl);
        $this->now = $opts['now'] ?? static fn(): int|float => (int)(microtime(true) * 1000);
        $this->store = $store;
        $this->random = $opts['random'] ?? null;
        $this->verificationShare = Frost::verifyingShare($this->share);
        $this->pop = FrostNet::createSignerPoP($this->identifier, $this->share, ['groupPublicKey' => $this->groupPublicKey,
            'nonce' => $this->random !== null ? ($this->random)() : null]);
    }

    public function proofOfPossession(): Obj
    {
        return $this->pop;
    }

    /** `{identifier, publicKey (raw), pop}` for a coordinator's enrollment list. */
    public function enrollment(): array
    {
        return ['identifier' => $this->identifier, 'publicKey' => $this->verificationShare, 'pop' => $this->pop];
    }

    private function now(): mixed
    {
        return ($this->now)();
    }

    private static function wire(array $c): Obj
    {
        return Obj::of(['identifier' => $c['identifier'], 'hiding' => Pca::b64u($c['hiding']), 'binding' => Pca::b64u($c['binding'])]);
    }

    private function no1(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'identifier' => $this->identifier, 'reason' => $reason]);
    }

    private function no2(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'identifier' => $this->identifier, 'refused' => true, 'reason' => $reason]);
    }

    /** Round 1: a fresh commitment for a session (one live commitment per session id). */
    public function round1(mixed $req): Obj
    {
        try {
            $sid = Jsx::get($req, 'session_id');
            if (!Jsx::truthy($req) || Jsx::get($req, 'typ') !== 'pca.frost.round1.v1' || !is_string($sid) || $sid === '') {
                return $this->no1('malformed round-1 request');
            }
            if (isset($this->spent[$sid]) || ($this->store !== null && $this->store->isSpent($sid))) {
                return $this->no1('session already signed');
            }
            if (isset($this->sessions[$sid]) || ($this->store !== null && $this->store->load($sid) !== null)) {
                return $this->no1('duplicate round-1 for session');
            }
            $hr = $this->random !== null ? ($this->random)() : null;
            $br = $this->random !== null ? ($this->random)() : null;
            $c = Frost::commit(['identifier' => $this->identifier, 'share' => $this->share, 'publicKey' => $this->verificationShare], $hr, $br);
            $createdAt = $this->now();
            $this->store?->create($sid, new NonceRecord($c['hidingNonce'], $c['bindingNonce'], $c['commitment']['hiding'], $c['commitment']['binding'], $createdAt));
            $this->sessions[$sid] = ['nonces' => new FrostNonces($c['hidingNonce'], $c['bindingNonce']), 'commitment' => $c['commitment'], 'createdAt' => $createdAt];
            return Obj::of(['ok' => true, 'identifier' => $this->identifier, 'commitment' => self::wire($c['commitment']), 'pop' => $this->pop]);
        } catch (\Throwable $e) {
            return $this->no1($e->getMessage() === '' ? 'round-1 error' : $e->getMessage());
        }
    }

    /** Round 2: the signature share, or a refusal. */
    public function round2(mixed $req): Obj
    {
        try {
            $sid = Jsx::get($req, 'session_id');
            if (!Jsx::truthy($req) || Jsx::get($req, 'typ') !== 'pca.frost.round2.v1' || !is_string($sid)) {
                return $this->no2('malformed round-2 request');
            }
            if (isset($this->spent[$sid]) || ($this->store !== null && $this->store->isSpent($sid))) {
                return $this->no2('session already signed (one-shot)');
            }
            $state = $this->sessions[$sid] ?? null;
            if ($state === null && $this->store !== null) {
                $rec = $this->store->load($sid);
                if ($rec !== null) {
                    $state = ['nonces' => new FrostNonces($rec->hiding, $rec->binding),
                        'commitment' => ['identifier' => $this->identifier, 'hiding' => $rec->hidingCommitment, 'binding' => $rec->bindingCommitment], 'createdAt' => $rec->createdAt];
                    $this->sessions[$sid] = $state;
                }
            }
            if ($state === null) {
                return $this->no2('no round-1 state for this session');
            }
            if ($this->sessionTtlMs !== null && Jsx::toNum($this->now()) - Jsx::toNum($state['createdAt']) > $this->sessionTtlMs) {
                unset($this->sessions[$sid]);
                $this->store?->drop($sid);
                return $this->no2("session expired (stale-session guard: round-1 older than " . Jsx::str($this->sessionTtlMs) . 'ms)');
            }
            $message = Pca::decodeB64uStrict(Jsx::get($req, 'message'));
            if ($message === null) {
                return $this->no2('message not canonical base64url');
            }
            if (Jsx::get($req, 'group_pk') !== Pca::b64u($this->groupPublicKey)) {
                return $this->no2('request names a different group key');
            }
            $allow = FrostNet::verifyAllowToken(Jsx::get($req, 'allow'), ['policyAuthorityPublicKey' => $this->policyAuthorityPublicKey,
                'groupPublicKey' => $this->groupPublicKey, 'message' => $message, 'now' => $this->now()]);
            if (!$allow['ok']) {
                return $this->no2('policy authorization failed: ' . ($allow['reason'] ?? ''));
            }
            $wc = Jsx::get($req, 'commitments');
            $commitments = FrostNet::decodeCommitments($wc instanceof Undef || $wc === null ? [] : $wc);
            if (count($commitments) < $this->threshold) {
                return $this->no2("signing set below threshold t={$this->threshold}");
            }
            $own = null;
            foreach ($commitments as $c) {
                if ($c['identifier'] === $this->identifier) {
                    $own = $c;
                    break;
                }
            }
            if ($own === null) {
                return $this->no2('our commitment is not in the signing set');
            }
            if ($own['hiding'] !== $state['commitment']['hiding'] || $own['binding'] !== $state['commitment']['binding']) {
                return $this->no2('equivocation detected: our commitment in the signing set differs from our round-1 commitment');
            }
            $vss = FrostNet::decodeVerificationShares(Jsx::get($req, 'verification_shares'));
            $this->store?->spend($sid);
            $sig = Frost::sign($this->identifier, $this->share, $this->groupPublicKey, $state['nonces'], $message, $commitments,
                ['threshold' => $this->threshold, 'verificationShare' => $this->verificationShare, 'verificationShares' => $vss]);
            unset($this->sessions[$sid]);
            $this->spent[$sid] = true;
            return Obj::of(['ok' => true, 'identifier' => $this->identifier, 'sig_share' => Pca::b64u($sig['sigShare'])]);
        } catch (\Throwable $e) {
            return $this->no2($e->getMessage() === '' ? 'round-2 error' : $e->getMessage());
        }
    }
}

/** A signer as the coordinator sees it (in process or over a wire). Both rounds return the JSON response object; a transport that cannot answer throws. */
interface SignerTransport
{
    public function identifier(): mixed;

    public function round1(Obj $req): mixed;

    public function round2(Obj $req): mixed;
}

/** The transport of a service in the same process. */
final class InProcessTransport implements SignerTransport
{
    public function __construct(private readonly GuardianSignerService $service)
    {
    }

    public function identifier(): int
    {
        return $this->service->identifier;
    }

    public function round1(Obj $req): Obj
    {
        return $this->service->round1($req);
    }

    public function round2(Obj $req): Obj
    {
        return $this->service->round2($req);
    }
}

class CoordinatorError extends \RuntimeException
{
    /** @param list<Obj> $refusals `{identifier, reason}` per refused signer */
    public function __construct(string $message, public readonly array $refusals = [])
    {
        parent::__construct($message);
    }
}

final class CoordinatorTimeoutError extends CoordinatorError
{
    public function __construct(string $message, public readonly mixed $timeoutMs, array $refusals = [])
    {
        parent::__construct($message, $refusals);
    }
}

/**
 * Drives a t-of-n FROST signing session over signer transports: round 1 (commit), the coordinator's checks (a known verification share, a valid proof of
 * possession, no second different commitment), round 2 (sign) and an aggregate that re-verifies every share. Refusals are collected; only a threshold of
 * valid shares yields a signature. `$opts`: groupPublicKey, threshold, signers (SignerTransport[]), verificationShares? (`[{identifier, publicKey}]`) or
 * enroll? (proof-of-possession enrollments), newSessionId? (closure), timeoutMs?, clock? (closure returning ms; the deadline is measured on it).
 * shortcut: transports are synchronous (signers are asked one after another), so a deadline is checked after the session returns, not enforced mid-call;
 * move to async transports when a real network is wired.
 */
final class NetworkCoordinator
{
    private readonly string $groupPublicKey;
    private readonly int $threshold;
    /** @var list<SignerTransport> */
    private readonly array $signers;
    /** @var list<array{identifier:int,publicKey:string}> */
    private readonly array $verificationShares;
    /** @var array<int,string> */
    private readonly array $pkById;
    private readonly EquivocationGuard $equivocation;
    private readonly \Closure $newSessionId;
    private readonly \Closure $clock;
    private readonly mixed $timeoutMs;

    public function __construct(array $opts)
    {
        $gpk = $opts['groupPublicKey'] ?? null;
        if (!is_string($gpk) || strlen($gpk) !== 32) {
            throw new \RuntimeException('NetworkCoordinator: groupPublicKey must be 32 bytes');
        }
        $t = Js::num($opts['threshold'] ?? null);
        if ($t === null || !is_finite($t) || $t != floor($t) || abs($t) > 9007199254740991.0 || $t < 1) {
            throw new \RuntimeException('NetworkCoordinator: threshold must be a positive integer');
        }
        $to = $opts['timeoutMs'] ?? null;
        if ($to !== null) {
            $tn = Js::num($to);
            if ($tn === null || !is_finite($tn) || $tn <= 0) {
                throw new \RuntimeException('NetworkCoordinator: timeoutMs must be a positive finite number');
            }
        }
        $this->groupPublicKey = $gpk;
        $this->threshold = (int)$t;
        $this->signers = array_values($opts['signers']);
        if (array_key_exists('enroll', $opts) && $opts['enroll'] !== null) {
            $this->verificationShares = FrostNet::enrollVerificationShares($opts['enroll'], Obj::of(['groupPublicKey' => $gpk]));
        } elseif (array_key_exists('verificationShares', $opts) && $opts['verificationShares'] !== null) {
            $this->verificationShares = array_values($opts['verificationShares']);
        } else {
            throw new \RuntimeException('NetworkCoordinator: provide verificationShares or enroll');
        }
        $pk = [];
        foreach ($this->verificationShares as $v) {
            $pk[(int)Js::num($v['identifier'])] = Pca::b64u($v['publicKey']);
        }
        $this->pkById = $pk;
        $this->equivocation = new EquivocationGuard();
        $this->newSessionId = $opts['newSessionId'] ?? static fn(): string => Pca::b64u(random_bytes(32));
        $this->clock = $opts['clock'] ?? static fn(): int|float => hrtime(true) / 1e6;
        $this->timeoutMs = $to;
    }

    private static function refusal(mixed $identifier, mixed $reason): Obj
    {
        $o = new Obj();
        foreach (['identifier' => $identifier, 'reason' => $reason] as $k => $v) {
            if (!($v instanceof Undef)) {
                $o->set($k, $v);
            }
        }
        return $o;
    }

    /** The id as the map key when it is a whole JS number, else null. */
    private static function key(mixed $x): ?int
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 ? (int)$f : null;
    }

    private static function same(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) === Js::num($b);
        }
        return ($a instanceof Undef && $b instanceof Undef) || (!Js::isNum($a) && !Js::isNum($b) && $a === $b);
    }

    /**
     * Sign `$message` (bytes) under the group key: `$allow` is the policy allow token every signer verifies. `$opts`: `signerIds?` (a list of identifiers; the
     * first t signers by default), `timeoutMs?` (overrides the constructor's; NaN or a non-positive value means no deadline).
     * @return array{signature:string,sessionId:string,signers:list<mixed>}
     */
    public function sign(mixed $message, mixed $allow, array $opts = []): array
    {
        $window = $opts['timeoutMs'] ?? $this->timeoutMs;
        $start = ($this->clock)();
        $err = null;
        try {
            $res = $this->drive($message, $allow, $opts);
        } catch (\Throwable $e) {
            $err = $e;
        }
        $w = $window === null ? null : Js::num($window);
        if ($w !== null && is_finite($w) && $w > 0 && ($this->clock)() - $start > $w) {
            throw new CoordinatorTimeoutError("coordinator: signing session did not reach threshold within " . Jsx::str($window) . 'ms', $window);
        }
        if ($err !== null) {
            throw $err;
        }
        return $res;
    }

    private function drive(mixed $message, mixed $allow, array $opts): array
    {
        if (!is_string($message)) {
            throw new \RuntimeException('coordinator.sign: message must be bytes');
        }
        $ids = $opts['signerIds'] ?? null;
        if ($ids !== null) {
            $chosen = array_values(array_filter($this->signers, static function (SignerTransport $s) use ($ids): bool {
                foreach ($ids as $i) {
                    if (self::same($i, $s->identifier())) {
                        return true;
                    }
                }
                return false;
            }));
        } else {
            $chosen = array_slice($this->signers, 0, $this->threshold);
        }
        if (count($chosen) < $this->threshold) {
            throw new CoordinatorError('coordinator: only ' . count($chosen) . " signer(s) selected, need t={$this->threshold}");
        }
        $sessionId = ($this->newSessionId)();
        $r1 = [];
        foreach ($chosen as $s) {
            try {
                $r1[] = [$s, $s->round1(Obj::of(['typ' => 'pca.frost.round1.v1', 'session_id' => $sessionId]))];
            } catch (\Throwable $e) {
                $r1[] = [$s, Obj::of(['ok' => false, 'identifier' => $s->identifier(), 'reason' => $e->getMessage() === '' ? 'unreachable' : $e->getMessage()])];
            }
        }
        $refusals = [];
        $committed = [];
        foreach ($r1 as [$s, $resp]) {
            if (!Jsx::truthy(Jsx::get($resp, 'ok'))) {
                $refusals[] = self::refusal(Jsx::get($resp, 'identifier'), Jsx::get($resp, 'reason'));
                continue;
            }
            $rid = Jsx::get($resp, 'identifier');
            $k = self::key($rid);
            $expectedPk = $k === null ? null : ($this->pkById[$k] ?? null);
            if ($expectedPk === null) {
                $refusals[] = self::refusal($rid, 'no verification share on record for this signer');
                continue;
            }
            $pop = Jsx::get($resp, 'pop');
            if ($pop === null) {
                throw new \TypeError("Cannot read properties of null (reading 'identifier')");
            }
            if ($pop instanceof Undef || !self::same(Jsx::get($pop, 'identifier'), $rid) || Jsx::get($pop, 'publicKey') !== $expectedPk
                || !FrostNet::verifySignerPoP($pop, Obj::of(['groupPublicKey' => $this->groupPublicKey]))) {
                $refusals[] = self::refusal($rid, 'invalid or missing proof-of-possession (rogue-key defense)');
                continue;
            }
            try {
                $this->equivocation->observe($sessionId, 1, $rid, Jsx::get($resp, 'commitment'));
            } catch (\Throwable $e) {
                $refusals[] = self::refusal($rid, $e instanceof EquivocationError ? $e->getMessage() : 'equivocation check failed');
                continue;
            }
            $committed[] = [$s, Jsx::get($resp, 'commitment')];
        }
        if (count($committed) < $this->threshold) {
            throw new CoordinatorError('coordinator: round 1 produced ' . count($committed) . " commitment(s), need t={$this->threshold}", $refusals);
        }
        $set = array_slice($committed, 0, $this->threshold);
        $commitments = array_map(static fn(array $c): mixed => $c[1], $set);
        $setIds = [];
        foreach ($commitments as $c) {
            $setIds[] = Jsx::get($c, 'identifier');
        }
        $vss = [];
        $vssRaw = [];
        foreach ($this->verificationShares as $v) {
            foreach ($setIds as $i) {
                if (self::same($i, $v['identifier'])) {
                    $vss[] = Obj::of(['identifier' => $v['identifier'], 'publicKey' => Pca::b64u($v['publicKey'])]);
                    $vssRaw[] = $v;
                    break;
                }
            }
        }
        if (count($vss) !== count($set)) {
            throw new CoordinatorError('coordinator: missing a verification share for a signer in the set');
        }
        $r2 = [];
        foreach ($set as [$transport]) {
            $req = Obj::of(['typ' => 'pca.frost.round2.v1', 'session_id' => $sessionId, 'message' => Pca::b64u($message), 'group_pk' => Pca::b64u($this->groupPublicKey),
                'commitments' => $commitments, 'verification_shares' => $vss, 'allow' => $allow]);
            try {
                $r2[] = $transport->round2($req);
            } catch (\Throwable $e) {
                $r2[] = Obj::of(['ok' => false, 'identifier' => $transport->identifier(), 'refused' => true, 'reason' => $e->getMessage() === '' ? 'unreachable' : $e->getMessage()]);
            }
        }
        $shares = [];
        foreach ($r2 as $resp) {
            $rid = Jsx::get($resp, 'identifier');
            if (!Jsx::truthy(Jsx::get($resp, 'ok'))) {
                $refusals[] = self::refusal($rid, Jsx::get($resp, 'reason'));
                continue;
            }
            $ss = Jsx::get($resp, 'sig_share');
            try {
                if ($ss instanceof Undef) { // the observed payload canonicalizes its members, and an undefined one has no canonical form
                    throw new \TypeError('canonicalize: unsupported type undefined');
                }
                $this->equivocation->observe($sessionId, 2, $rid, Obj::of(['sig_share' => $ss]));
            } catch (\Throwable $e) {
                $refusals[] = self::refusal($rid, $e instanceof EquivocationError ? $e->getMessage() : 'equivocation check failed');
                continue;
            }
            $sb = Pca::decodeB64uStrict($ss, 32);
            if ($sb === null) {
                $refusals[] = self::refusal($rid, 'malformed signature share');
            } else {
                $k = self::key($rid);
                $shares[] = ['identifier' => $k ?? $rid, 'sigShare' => $sb];
            }
        }
        if (count($shares) < $this->threshold) {
            throw new CoordinatorError('coordinator: round 2 produced ' . count($shares) . " share(s), need t={$this->threshold}", $refusals);
        }
        $agg = array_map(FrostNet::decodeCommitment(...), $commitments);
        $sig = Frost::aggregate($message, $agg, $shares, $this->groupPublicKey, $this->threshold, $vssRaw);
        return ['signature' => $sig, 'sessionId' => $sessionId, 'signers' => $setIds];
    }
}
