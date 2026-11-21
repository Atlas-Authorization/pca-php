<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletOmega.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentV2Acc.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentPolicy.php';

/**
 * Portable, revocable intent profiles: the principal's signed, versioned record of standing rules and prior answers, append-only
 * succession, scoped use (deny wins, permit is explicit, negative observations veto) and revocation. Profiles are Obj trees (parsed JSON);
 * signing is Ed25519 (a suite-agile profile verifies under the verifier's pin).
 */
final class IntentProfile
{
    public const KIND = 'pca-intent-profile';
    public const SIG_DOMAIN = "atlas-pca/intent-profile/v1\0";
    public const REF_DOMAIN = 'atlas-pca/intent-profile-ref/v1';
    public const MAX_RULES = 256;
    public const MAX_OBSERVATIONS = 2000;
    private const KEYS = ['v', 'kind', 'profile_id', 'version', 'owner', 'scope', 'standing', 'prior', 'expires_at', 'revocation', 'prev', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    private const BODY_KEYS = ['v', 'kind', 'profile_id', 'version', 'owner', 'scope', 'standing', 'prior', 'expires_at', 'revocation'];

    private static function g(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    /** JS === over JSON values. */
    private static function seq(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) === Js::num($b);
        }
        return !($a instanceof Obj) && !is_array($a) && $a === $b && !Jsx::isUndef($a);
    }

    private static function strList(mixed $v, int $mx = 256): bool
    {
        if (!is_array($v) || !array_is_list($v) || count($v) > $mx) {
            return false;
        }
        foreach ($v as $x) {
            if (!is_string($x) || $x === '') {
                return false;
            }
        }
        return true;
    }

    private static function predOk(mixed $p): bool
    {
        if (!($p instanceof Obj)) {
            return false;
        }
        $v = self::g($p, 'verb');
        return is_string($v) || (is_array($v) && array_is_list($v) && count(array_filter($v, static fn($x) => !is_string($x))) === 0);
    }

    private static function sortedKeys(Obj $o): string
    {
        $k = IntentV2::jsKeys($o);
        usort($k, static fn($a, $b) => strcmp(AnalyzerJs::u16key($a), AnalyzerJs::u16key($b)));
        return implode(',', $k);
    }

    private static function b32(mixed $x): bool
    {
        return Wallet::isB64u32($x);
    }

    private static function safeNonNeg(mixed $x, int $min = 0): bool
    {
        return IntentWb::isSafeInt($x) && Js::num($x) >= $min;
    }

    private static function suiteKnownError(mixed $alg): ?string
    {
        if (Jsx::isUndef($alg)) {
            return null;
        }
        if (!is_string($alg)) {
            return 'alg must be a string';
        }
        return in_array($alg, Pca::REGISTERED_SUITES, true) ? null : IntentV2::UNSUPPORTED_SUITE . ": '$alg'";
    }

    /** None when the profile is well-formed (closed, strictly typed); else the first problem. */
    public static function intentProfileShapeError(mixed $p, bool $signed = true): ?string
    {
        try {
            if (!($p instanceof Obj)) {
                return 'profile is not an object';
            }
            foreach (IntentV2::jsKeys($p) as $k) {
                if (!in_array($k, self::KEYS, true)) {
                    return "profile: unknown member '$k'";
                }
            }
            if (!self::seq(self::g($p, 'v'), 1) || self::g($p, 'kind') !== self::KIND) {
                return 'not a pca-intent-profile v1';
            }
            $pid = self::g($p, 'profile_id');
            if (!is_string($pid) || preg_match('/\A[A-Za-z0-9_.-]{1,128}\z/', $pid) !== 1) {
                return 'profile_id must match [A-Za-z0-9_.-]{1,128}';
            }
            $ver = self::g($p, 'version');
            if (!self::safeNonNeg($ver, 1)) {
                return 'version must be a safe integer >= 1';
            }
            if (!self::b32(self::g($p, 'owner'))) {
                return 'owner must be canonical base64url (32 bytes)';
            }
            $scope = self::g($p, 'scope');
            if (!($scope instanceof Obj)) {
                return 'scope must be {sites?, verbs?, semantic_types?}';
            }
            foreach (IntentV2::jsKeys($scope) as $k) {
                if (!in_array($k, ['sites', 'verbs', 'semantic_types'], true)) {
                    return 'scope must be {sites?, verbs?, semantic_types?}';
                }
            }
            foreach (['sites', 'verbs', 'semantic_types'] as $k) {
                if (!Jsx::isUndef(self::g($scope, $k)) && !self::strList(self::g($scope, $k))) {
                    return "scope.$k must be a list of strings";
                }
            }
            $standing = self::g($p, 'standing');
            if (!($standing instanceof Obj) || self::sortedKeys($standing) !== 'deny,permit') {
                return 'standing must be {deny, permit}';
            }
            foreach (['deny', 'permit'] as $k) {
                $r = $standing->get($k);
                if (!is_array($r) || !array_is_list($r) || count($r) > self::MAX_RULES || count(array_filter($r, static fn($x) => !self::predOk($x))) > 0) {
                    return "standing.$k must be at most " . self::MAX_RULES . ' predicates';
                }
            }
            $prior = self::g($p, 'prior');
            if (!($prior instanceof Obj) || self::sortedKeys($prior) !== 'maps,observations') {
                return 'prior must be {observations, maps}';
            }
            $obs = $prior->get('observations');
            if (!is_array($obs) || !array_is_list($obs) || count($obs) > self::MAX_OBSERVATIONS) {
                return 'prior.observations must be at most ' . self::MAX_OBSERVATIONS;
            }
            foreach ($obs as $o) {
                if (!($o instanceof Obj) || self::sortedKeys($o) !== 'at,values,verb,y' || !is_string($o->get('verb')) || !($o->get('values') instanceof Obj)
                    || !(self::seq($o->get('y'), 0) || self::seq($o->get('y'), 1)) || !self::safeNonNeg($o->get('at'))) {
                    return 'prior.observations entries are {verb, values, y, at}';
                }
            }
            $maps = $prior->get('maps');
            if (!is_array($maps) || !array_is_list($maps) || count(array_filter($maps, static fn($m) => !self::b32($m))) > 0) {
                return 'prior.maps must be 32-byte digests';
            }
            if (!self::safeNonNeg(self::g($p, 'expires_at'))) {
                return 'expires_at must be a non-negative safe integer';
            }
            $rev = self::g($p, 'revocation');
            if (!($rev instanceof Obj) || count(array_filter(IntentV2::jsKeys($rev), static fn($k) => !in_array($k, ['epoch_uri', 'key'], true))) > 0
                || !is_string(self::g($rev, 'epoch_uri')) || $rev->get('epoch_uri') === '') {
                return 'revocation must be {epoch_uri, key?}';
            }
            if (!Jsx::isUndef(self::g($rev, 'key')) && !self::b32($rev->get('key'))) {
                return 'revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)';
            }
            $prev = self::g($p, 'prev');
            if (self::seq($ver, 1) !== Jsx::isUndef($prev)) {
                return 'prev is required exactly when version > 1';
            }
            if (!Jsx::isUndef($prev) && !self::b32($prev)) {
                return 'prev must be canonical base64url (32 bytes)';
            }
            if ($signed) {
                $alg = self::g($p, 'alg');
                if (!Jsx::isUndef($alg) && !is_string($alg)) {
                    return 'alg must be a string';
                }
                $se = self::suiteKnownError($alg);
                if ($se !== null) {
                    return 'alg: ' . $se;
                }
                if ((Jsx::isUndef($alg) || $alg === 'ed25519') && (!Jsx::isUndef(self::g($p, 'pq_pk')) || !Jsx::isUndef(self::g($p, 'pq_sig')))) {
                    return 'an ed25519 profile must not carry pq_pk / pq_sig';
                }
                if (!is_string(self::g($p, 'sig'))) {
                    return 'sig must be a string';
                }
            }
            Json::canonicalizeNative(self::profileBody($p));
            return null;
        } catch (\Throwable $e) {
            return 'malformed profile: ' . $e->getMessage();
        }
    }

    private static function profileBody(Obj $p): Obj
    {
        $b = new Obj();
        foreach (self::BODY_KEYS as $k) {
            if ($p->has($k)) {
                $b->set($k, $p->get($k));
            }
        }
        if ($p->has('prev') && !Jsx::isUndef($p->get('prev'))) {
            $b->set('prev', $p->get('prev'));
        }
        return $b;
    }

    private static function message(Obj $body): string
    {
        return self::SIG_DOMAIN . Json::canonicalizeNative($body);
    }

    /** Sign a profile version as its owner (the owner identity must be the signer's Ed25519 key); `$ownerSeed` is the 32-byte seed. */
    public static function signIntentProfile(Obj $body, string $ownerSeed, mixed $suite = null): Obj
    {
        if ($suite !== null && !in_array(Js::opt($suite, 'alg'), [null, 'ed25519'], true)) {
            throw new \InvalidArgumentException('signIntentProfile: only Ed25519 signing is supported natively');
        }
        $kp = sodium_crypto_sign_seed_keypair($ownerSeed);
        $owner = Pca::b64u(sodium_crypto_sign_publickey($kp));
        if ($body->has('owner') && $body->get('owner') !== $owner) {
            throw new \InvalidArgumentException('signIntentProfile: owner does not match the signing key');
        }
        $with = new Obj();
        foreach ($body->keys() as $k) {
            $with->set($k, $body->get($k));
        }
        $with->set('owner', $owner);
        $b = self::profileBody($with);
        $bad = self::intentProfileShapeError($b, false);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signIntentProfile: $bad");
        }
        $out = self::profileBody($b);
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::message($b), sodium_crypto_sign_secretkey($kp))));
        return $out;
    }

    private static function pinsOf(mixed $pin): mixed
    {
        $pq = Js::opt($pin, 'pqPins');
        return Js::isObj($pq) ? $pq : null;
    }

    /** @return array{ok:bool,reason?:string} */
    public static function verifyIntentProfile(mixed $p, mixed $pin = null): array
    {
        try {
            $bad = self::intentProfileShapeError($p);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => $bad];
            }
            $alg = self::g($p, 'alg');
            $pqPk = self::g($p, 'pq_pk');
            $suite = Jsx::isUndef($alg) ? 'ed25519' : $alg;
            $body = self::profileBody($p);
            $pinPq = null;
            if ($suite !== 'ed25519' && Pca::suiteAvailable($suite)) {
                if (Jsx::isUndef($pqPk)) {
                    throw new \TypeError('canonicalize: unsupported type undefined');
                }
                $body->set('alg', $suite);
                $body->set('pq_pk', $pqPk);
            }
            $owner = $p->get('owner');
            if ($suite !== 'ed25519') {
                $pins = self::pinsOf($pin);
                $v = $pins !== null ? Js::opt($pins, $owner) : null;
                $pinPq = is_string($v) ? $v : null;
            }
            $sig = $p->get('sig');
            $pqSig = self::g($p, 'pq_sig');
            $ok = Pca::verifyPinnedSuite($suite, $owner, Jsx::isUndef($pqPk) ? null : $pqPk, self::message($body), $sig, Jsx::isUndef($pqSig) ? null : $pqSig, $pinPq);
            return $ok === true ? ['ok' => true] : ['ok' => false, 'reason' => 'profile signature invalid'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'malformed profile: ' . $e->getMessage()];
        }
    }

    /** The content address of a signed profile version. */
    public static function intentProfileDigest(mixed $p): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::REF_DOMAIN, 'p' => $p]));
    }

    /** Append-only succession: same id and owner, version + 1, prev = digest(previous). @return array{ok:bool,reason?:string} */
    public static function verifyProfileSuccession(mixed $prev, mixed $next): array
    {
        foreach ([[$prev, 'previous'], [$next, 'next']] as [$x, $n]) {
            $v = self::verifyIntentProfile($x);
            if (!$v['ok']) {
                return ['ok' => false, 'reason' => "$n version: " . $v['reason']];
            }
        }
        if ($next->get('profile_id') !== $prev->get('profile_id') || $next->get('owner') !== $prev->get('owner')) {
            return ['ok' => false, 'reason' => 'a profile version cannot change its id or owner'];
        }
        if (Js::num($next->get('version')) !== Js::num($prev->get('version')) + 1) {
            return ['ok' => false, 'reason' => 'versions are append-only: next.version must be previous + 1'];
        }
        if (self::g($next, 'prev') !== self::intentProfileDigest($prev)) {
            return ['ok' => false, 'reason' => 'next.prev is not the digest of the previous version'];
        }
        return ['ok' => true];
    }

    private static function lt(mixed $a, mixed $b): bool
    {
        return Js::isNum($a) && Js::isNum($b) && is_finite(Js::num($a)) && is_finite(Js::num($b)) && Js::num($a) < Js::num($b);
    }

    private static function present(mixed $x): bool
    {
        return !Jsx::isUndef($x) && $x !== null;
    }

    private static function anyEq(array $xs, mixed $y): bool
    {
        foreach ($xs as $x) {
            if (self::seq($x, $y)) {
                return true;
            }
        }
        return false;
    }

    /** Is the profile in scope (and unexpired) for this action? */
    public static function profileApplies(mixed $p, mixed $u): bool
    {
        if (!self::lt(self::g($u, 'now'), $p->get('expires_at'))) {
            return false;
        }
        $scope = $p->get('scope');
        $sites = self::g($scope, 'sites');
        $verbs = self::g($scope, 'verbs');
        $sem = self::g($scope, 'semantic_types');
        if (self::present($sites) && !self::anyEq($sites, self::g($u, 'aud'))) {
            return false;
        }
        if (self::present($verbs) && !self::anyEq($verbs, self::g($u, 'verb'))) {
            return false;
        }
        if (self::present($sem)) {
            $sems = self::g($u, 'semantics');
            $sems = (Jsx::isUndef($sems) || $sems === null) ? [] : $sems;
            $any = false;
            foreach ($sems as $s) {
                if (self::anyEq($sem, $s)) {
                    $any = true;
                    break;
                }
            }
            if (!$any) {
                return false;
            }
        }
        return true;
    }

    private static function anyMatch(array $rules, mixed $action): bool
    {
        foreach ($rules as $r) {
            if (Predicates::predicateMatches($r, $action)) {
                return true;
            }
        }
        return false;
    }

    /** G^std membership: an in-scope action is outside the standing layer iff a deny rule matches it (deny wins). */
    public static function standingAdmits(mixed $p, mixed $u, mixed $action): bool
    {
        if (!self::profileApplies($p, $u)) {
            return true;
        }
        return !self::anyMatch($p->get('standing')->get('deny'), $action);
    }

    /** The explicit standing-permission layer: an in-scope permit rule matches (the only positive import). */
    public static function standingPermits(mixed $p, mixed $u, mixed $action): bool
    {
        return self::profileApplies($p, $u) && self::anyMatch($p->get('standing')->get('permit'), $action);
    }

    /** The cells that the profile's negative observations veto. @return list<array{verb:string,cell:list<int>}> */
    public static function profileVetoCells(mixed $p, mixed $omega): array
    {
        $out = [];
        $seen = [];
        foreach ($p->get('prior')->get('observations') as $o) {
            if (Js::num($o->get('y')) != 0) {
                continue;
            }
            $vs = null;
            foreach (Js::opt($omega, 'verbs') as $v) {
                if (Js::opt($v, 'verb') === $o->get('verb')) {
                    $vs = $v;
                    break;
                }
            }
            $cell = $vs !== null ? WalletOmega::cellOf($vs, Obj::of(['verb' => $o->get('verb'), 'values' => $o->get('values')])) : null;
            if ($vs === null || $cell === null) {
                continue;
            }
            $k = $o->get('verb') . '|' . implode(',', $cell);
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = ['verb' => $o->get('verb'), 'cell' => $cell];
            }
        }
        return $out;
    }

    /** A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes: Closure(vs, outcome): bool. */
    public static function profileCeiling(mixed $p, mixed $u): \Closure
    {
        return static function (mixed $vs, mixed $o) use ($p, $u): bool {
            $a = IntentPolicy::outcomeToAction($vs, $o);
            $ctx = Obj::of(['action' => Obj::of(['verb' => $a->get('verb'), 'resource' => $a->get('resource'), 'params' => $a->get('params')])]);
            foreach (['env', 'subject'] as $k) {
                $x = $a->get($k);
                if ($x instanceof Obj && $x->keys() !== []) {
                    $ctx->set($k, $x);
                }
            }
            $u2 = new Obj();
            foreach (Js::isObj($u) ? ($u instanceof Obj ? $u->keys() : array_keys($u)) : [] as $k) {
                $u2->set((string)$k, Js::opt($u, (string)$k));
            }
            $u2->set('verb', Js::opt($o, 'verb'));
            return self::standingAdmits($p, $u2, $ctx);
        };
    }

    /**
     * Is this profile version usable now: signed, unexpired, and not revoked per a fresh epoch of its revocation authority.
     * @return array{ok:bool,reason?:string}
     */
    public static function profileUsable(mixed $p, mixed $c): array
    {
        $v = self::verifyIntentProfile($p, Js::opt($c, 'pin'));
        if (!$v['ok']) {
            return $v;
        }
        if (!self::lt(Js::opt($c, 'now'), $p->get('expires_at'))) {
            return ['ok' => false, 'reason' => 'the profile has expired'];
        }
        $rev = $p->get('revocation');
        $authority = !Jsx::isUndef(self::g($rev, 'key')) && $rev->get('key') !== null ? $rev->get('key') : $p->get('owner');
        $pins = self::pinsOf(Js::opt($c, 'pin'));
        $pinPq = $pins !== null ? Js::opt($pins, $authority) : null;
        $args = ['session' => $p->get('profile_id'), 'scope' => 'pca-intent-profile:' . Js::str($p->get('profile_id')), 'authority' => $authority,
            'ids' => ['pca-intent:profile:' . Js::str($p->get('profile_id')) . '@' . Js::str($p->get('version'))],
            'now' => Js::has($c, 'now') ? Js::opt($c, 'now') : null, 'maxAgeMs' => Js::has($c, 'maxAgeMs') ? Js::opt($c, 'maxAgeMs') : null,
            'pqPin' => is_string($pinPq) ? $pinPq : null];
        if (Js::has($c, 'last')) {
            $args['last'] = Js::opt($c, 'last');
        }
        $r = IntentV2::checkSessionRevocation(Js::has($c, 'revocation') ? Js::opt($c, 'revocation') : null, $args);
        return $r['ok'] ? ['ok' => true] : ['ok' => false, 'reason' => 'profile revocation: ' . ($r['reason'] ?? '')];
    }
}
