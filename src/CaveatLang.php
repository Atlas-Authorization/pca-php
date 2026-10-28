<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/StateStore.php';

/**
 * Caveat language v2 (track K1): a port of caveat-lang.ts (security contract C-220..C-229). Six verifier-side features, all
 * of them restrictions: `needs_discharge` (a third-party caveat satisfied by a discharge signed by a key the VERIFIER pinned),
 * `sealed`, the holder-signed `narrow` block, `max_uses` (n first-use slots in the replay store), `derive` (bounded derived
 * facts in Kleene three-valued logic) and `spiffe_bound`. Everything is total: any exception is a refusal, never an allow.
 *
 * Values are the SDK's JSON model: Obj, list arrays, string, Num (or a native int / float), bool, null. Results are PHP
 * arrays: `['ok' => true, ...]` / `['ok' => false, 'reason' => ...]`; a `*Error` function returns null when the input is valid.
 */
final class CaveatLang
{
    public const CAVEAT_NEEDS_DISCHARGE = 'needs_discharge';
    public const CAVEAT_SEALED = 'sealed';
    public const CAVEAT_MAX_USES = 'max_uses';
    public const CAVEAT_DERIVE = 'derive';
    public const CAVEAT_SPIFFE_BOUND = 'spiffe_bound';
    /** Caveat types this module evaluates (the stock evaluators refuse them). */
    public const K1_CAVEAT_TYPES = [self::CAVEAT_NEEDS_DISCHARGE, self::CAVEAT_SEALED, self::CAVEAT_MAX_USES, self::CAVEAT_DERIVE, self::CAVEAT_SPIFFE_BOUND];

    public const DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\0";
    public const DISCHARGE_REF_DOMAIN = 'atlas-pca/discharge-ref/v1';
    public const DISCHARGE_ACTION_DOMAIN = 'atlas-pca/discharge-action/v1';
    public const NARROW_DOMAIN = "atlas-pca/narrow/v1\0";
    public const MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\0";
    /** A discharge or narrow block lives at most 24 hours. */
    public const MAX_LIFETIME_MS = 86_400_000;
    public const MAX_USES_LIMIT = 256;
    public const NARROW_MAX_CAVEATS = 16;
    public const DERIVE_MAX_DEFS = 8;
    public const DERIVE_MAX_NODES = 32;
    public const DERIVE_MAX_DEPTH = 4;
    public const DERIVE_MAX_WINDOW_MS = 30 * 86_400_000;
    public const DERIVE_MAX_HISTORY = 10_000;
    public const SPIFFE_MAX_ID_BYTES = 2048;

    private const NAME_RE = '/\A[a-z][a-z0-9_]{0,63}\z/D';
    private const ID_RE = '/\A[a-z0-9][a-z0-9_.-]{0,63}\z/D';
    private const ISSUER_CLASSES = ['human', 'org', 'workload', 'model', 'artifact'];
    private const OPS = ['eq', 'neq', 'gte', 'lte', 'in'];
    private const NARROW_FORBIDDEN = ['envelope', self::CAVEAT_SEALED, 'budget_alloc', 'intent_session'];
    private const D_REQUIRED = ['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'claims', 'iat', 'not_after', 'nonce', 'sig'];
    private const D_OPTIONAL = ['action_digest', 'alg', 'pq_pk', 'pq_sig'];
    private const N_REQUIRED = ['v', 'kind', 'cap_hash', 'holder', 'caveats', 'iat', 'not_after', 'nonce', 'sig'];
    private const N_OPTIONAL = ['action_digest', 'alg', 'pq_pk', 'pq_sig'];

    // ---- shared helpers --------------------------------------------------------------------------------------------

    /** A JSON number as a float (Num, int, float), else null. */
    private static function nv(mixed $v): ?float
    {
        return match (true) {
            $v instanceof Num => $v->float(),
            is_int($v) => (float)$v,
            is_float($v) => $v,
            default => null,
        };
    }

    /** The float of a value already checked with isSafeInt. */
    private static function f(mixed $v): float
    {
        return self::nv($v) ?? NAN;
    }

    private static function isOne(mixed $v): bool
    {
        return self::nv($v) === 1.0;
    }

    private static function safe(mixed $v): bool
    {
        return IntentWb::isSafeInt($v);
    }

    /** Non-empty string of at most `$max` UTF-8 bytes. */
    private static function bounded(mixed $v, int $max): bool
    {
        return is_string($v) && $v !== '' && strlen($v) <= $max;
    }

    private static function isScalarClaim(mixed $v): bool
    {
        return (is_string($v) || is_bool($v) || self::safe($v)) && (!is_string($v) || self::bounded($v, 256));
    }

    private static function isDigest(mixed $v): bool
    {
        return Pca::unb64u($v, 32) !== null;
    }

    private static function matches(string $re, mixed $v): bool
    {
        return is_string($v) && preg_match($re, $v) === 1;
    }

    /** A member of an Obj or a string-keyed array; null when absent. */
    private static function field(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null;
    }

    private static function has(mixed $o, string $k): bool
    {
        if ($o instanceof Obj) {
            return $o->has($k);
        }
        return is_array($o) && !array_is_list($o) && array_key_exists($k, $o);
    }

    private static function closedMembers(Obj $o, array $required, array $optional, string $where): ?string
    {
        foreach (IntentWb::jsKeys($o) as $k) {
            if (!in_array($k, $required, true) && !in_array($k, $optional, true)) {
                return "unknown member '$where.$k'";
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return "missing member '$where.$k'";
            }
        }
        return null;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    public static function isK1Caveat(mixed $c): bool
    {
        return $c instanceof Obj && is_string($c->get('type')) && in_array($c->get('type'), self::K1_CAVEAT_TYPES, true);
    }

    // ---- SPIFFE ID syntax ------------------------------------------------------------------------------------------

    /** Null when `$s` is a valid SPIFFE ID (trust domain, optional path of safe segments, no trailing slash, at most 2048 bytes). */
    public static function spiffeIdError(mixed $s): ?string
    {
        if (!is_string($s) || $s === '') {
            return 'SPIFFE ID must be a non-empty string';
        }
        if (strlen($s) > self::SPIFFE_MAX_ID_BYTES) {
            return 'SPIFFE ID is too long';
        }
        if (!str_starts_with($s, 'spiffe://')) {
            return 'SPIFFE ID must begin with spiffe://';
        }
        $rest = substr($s, 9);
        $slash = strpos($rest, '/');
        $td = $slash === false ? $rest : substr($rest, 0, $slash);
        $path = $slash === false ? '' : substr($rest, $slash);
        if ($td === '' || strlen($td) > 255 || preg_match('/\A[a-z0-9._-]+\z/D', $td) !== 1) {
            return 'invalid trust domain';
        }
        if ($path === '') {
            return null;
        }
        if (str_ends_with($path, '/')) {
            return 'path must not end with a slash';
        }
        foreach (array_slice(explode('/', $path), 1) as $seg) {
            if ($seg === '' || $seg === '.' || $seg === '..' || preg_match('/\A[A-Za-z0-9._-]+\z/D', $seg) !== 1) {
                return 'invalid path segment';
            }
        }
        return null;
    }

    // ---- hop analysis ----------------------------------------------------------------------------------------------

    /** The hops the policy layer sees: the chain (root first), else the grant alone. */
    private static function hopsOf(mixed $grant, mixed $chain): array
    {
        return self::isList($chain) && count($chain) > 0 ? $chain : [$grant];
    }

    /**
     * Every caveat of the leaf hop with the hop that introduced it: a list of `['caveat' => , 'hop' => int, 'cap_hash' => string]`
     * (the caveat at position p was introduced by the first hop whose list is longer than p). Null for a malformed chain.
     */
    public static function boundCaveats(mixed $grant, mixed $chain = null): ?array
    {
        try {
            $hops = self::hopsOf($grant, $chain);
            $leaf = $hops[count($hops) - 1];
            $lc = $leaf instanceof Obj ? $leaf->get('caveats') : null;
            if (!self::isList($lc)) {
                return null;
            }
            $out = [];
            $hashes = [];
            foreach ($lc as $p => $caveat) {
                $h = -1;
                foreach ($hops as $i => $x) {
                    $xc = $x instanceof Obj ? $x->get('caveats') : null;
                    if (self::isList($xc) && count($xc) > $p) {
                        $h = $i;
                        break;
                    }
                }
                if ($h < 0) {
                    $h = count($hops) - 1;
                }
                $hashes[$h] ??= Pca::capHash($hops[$h]);
                $out[] = ['caveat' => $caveat, 'hop' => $h, 'cap_hash' => $hashes[$h]];
            }
            return $out;
        } catch (\Throwable) {
            return null;
        }
    }

    // ---- needs_discharge -------------------------------------------------------------------------------------------

    private static function requireError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'requirement must be an object';
        }
        $e = self::closedMembers($r, ['claim', 'op', 'value'], [], 'require');
        if ($e !== null) {
            return $e;
        }
        if (!self::matches(self::NAME_RE, $r->get('claim'))) {
            return 'claim name is malformed';
        }
        $op = $r->get('op');
        if (!in_array($op, self::OPS, true)) {
            return 'op must be eq, neq, gte, lte or in';
        }
        $v = $r->get('value');
        if ($op === 'in') {
            if (!self::isList($v) || count($v) === 0 || count($v) > 16) {
                return "'in' needs 1..16 scalar values";
            }
            foreach ($v as $x) {
                if (!self::isScalarClaim($x)) {
                    return "'in' needs 1..16 scalar values";
                }
            }
        } elseif ($op === 'gte' || $op === 'lte') {
            if (!self::safe($v)) {
                return "'$op' needs a safe integer";
            }
        } elseif (!self::isScalarClaim($v)) {
            return 'value must be a scalar';
        }
        return null;
    }

    /** Null when the caveat is well-formed: closed members, canonical names, bounded sizes. */
    public static function needsDischargeError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'caveat must be an object';
        }
        $e = self::closedMembers($c, ['type', 'id', 'issuer', 'issuer_class', 'bind', 'ttl_ms', 'require'], ['issuer_spiffe'], 'needs_discharge');
        if ($e !== null) {
            return $e;
        }
        if ($c->get('type') !== self::CAVEAT_NEEDS_DISCHARGE) {
            return 'not a needs_discharge caveat';
        }
        if (!self::matches(self::ID_RE, $c->get('id'))) {
            return 'id is malformed';
        }
        if (!self::matches(self::ID_RE, $c->get('issuer'))) {
            return 'issuer label is malformed';
        }
        if (!in_array($c->get('issuer_class'), self::ISSUER_CLASSES, true)) {
            return 'issuer_class must be human, org, workload, model or artifact';
        }
        if ($c->get('bind') !== 'chain_hop' && $c->get('bind') !== 'action') {
            return "bind must be 'chain_hop' or 'action'";
        }
        $ttl = $c->get('ttl_ms');
        if (!(self::safe($ttl) && self::f($ttl) >= 1 && self::f($ttl) <= self::MAX_LIFETIME_MS)) {
            return 'ttl_ms must be 1..86400000';
        }
        $req = $c->get('require');
        if (!self::isList($req) || count($req) > 16) {
            return 'require must be an array of at most 16 requirements';
        }
        foreach ($req as $r) {
            $re = self::requireError($r);
            if ($re !== null) {
                return $re;
            }
        }
        if ($c->has('issuer_spiffe')) {
            $se = self::spiffeIdError($c->get('issuer_spiffe'));
            if ($se !== null) {
                return "issuer_spiffe: $se";
            }
        }
        return null;
    }

    /** The digest of the exact PCActn (counter and signature included): a bind-`action` discharge authorises that one action. */
    public static function dischargeActionDigest(mixed $pcactn): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::DISCHARGE_ACTION_DOMAIN, 'pcactn' => $pcactn]));
    }

    /** Content address of a discharge (signature included); what a revocation list names. */
    public static function dischargeDigest(mixed $d): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::DISCHARGE_REF_DOMAIN, 'discharge' => $d]));
    }

    /** Null = well-formed. */
    public static function dischargeShapeError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'not an object';
        }
        $e = self::closedMembers($a, self::D_REQUIRED, self::D_OPTIONAL, 'discharge');
        if ($e !== null) {
            return $e;
        }
        if (!self::isOne($a->get('v')) || $a->get('kind') !== 'pca-discharge') {
            return 'not a pca-discharge v1';
        }
        if (!self::matches(self::ID_RE, $a->get('caveat_id'))) {
            return 'caveat_id is malformed';
        }
        if (!self::matches(self::ID_RE, $a->get('issuer'))) {
            return 'issuer label is malformed';
        }
        if (!self::isDigest($a->get('cap_hash'))) {
            return 'cap_hash must be canonical base64url (32 bytes)';
        }
        $bind = $a->get('bind');
        if ($bind !== 'chain_hop' && $bind !== 'action') {
            return "bind must be 'chain_hop' or 'action'";
        }
        if ($bind === 'action' ? !self::isDigest($a->get('action_digest')) : $a->has('action_digest')) {
            return 'action_digest is required for bind action and forbidden for chain_hop';
        }
        $claims = $a->get('claims');
        if (!($claims instanceof Obj) || count(IntentWb::jsKeys($claims)) > 16) {
            return 'claims must be an object of at most 16 members';
        }
        foreach (IntentWb::jsKeys($claims) as $k) {
            if (preg_match(self::NAME_RE, $k) !== 1 || !self::isScalarClaim($claims->get($k))) {
                return "claim '$k' is malformed";
            }
        }
        $iat = $a->get('iat');
        $na = $a->get('not_after');
        if (!(self::safe($iat) && self::f($iat) >= 0) || !(self::safe($na) && self::f($na) >= 0)) {
            return 'iat and not_after must be non-negative safe integers';
        }
        if (!(self::f($na) > self::f($iat))) {
            return 'not_after must be greater than iat';
        }
        if (self::f($na) - self::f($iat) > self::MAX_LIFETIME_MS) {
            return 'a discharge lives at most ' . self::MAX_LIFETIME_MS . ' ms';
        }
        $nonce = $a->get('nonce');
        $nb = is_string($nonce) ? Pca::unb64u($nonce) : null;
        if ($nb === null || strlen($nb) < 16) {
            return 'nonce must be canonical base64url of at least 16 bytes';
        }
        if (!is_string($a->get('sig'))) {
            return 'sig must be a string';
        }
        return IntentWb::artifactSuiteError($a);
    }

    /** Whether claim `$name` of `$claims` satisfies requirement `$r` (an absent claim fails). */
    private static function claimHolds(Obj $r, Obj $claims): bool
    {
        $name = $r->get('claim');
        if (!$claims->has($name)) {
            return false;
        }
        $v = $claims->get($name);
        $want = $r->get('value');
        switch ($r->get('op')) {
            case 'eq':
                return IntentWb::scalarEq($v, $want);
            case 'neq':
                return !IntentWb::scalarEq($v, $want);
            case 'gte':
                return self::safe($v) && self::f($v) >= self::f($want);
            case 'lte':
                return self::safe($v) && self::f($v) <= self::f($want);
            case 'in':
                foreach ($want as $x) {
                    if (IntentWb::scalarEq($v, $x)) {
                        return true;
                    }
                }
                return false;
        }
        return false;
    }

    /**
     * Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop carrying
     * the caveat (and for `action` to the PCActn); it must be inside its window and within the caveat's `ttl_ms`; its claims must
     * satisfy every requirement. `$bind`: `cap_hash`, `action_digest?`, `pins` (list of `{label, class, pk, pq_pk?, spiffe_id?}`),
     * `now`, `revoked?` (array or Obj). Total.
     *
     * @return array{ok: bool, reason?: string, digest?: string, claims?: Obj}
     */
    public static function verifyDischarge(mixed $discharge, mixed $caveat, mixed $bind): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $now = self::field($bind, 'now');
            if (!self::safe($now)) {
                return $no('the verifier clock is not a safe integer (fail closed)');
            }
            $nowF = self::f($now);
            $ce = self::needsDischargeError($caveat);
            if ($ce !== null) {
                return $no("malformed needs_discharge caveat: $ce");
            }
            /** @var Obj $c */
            $c = $caveat;
            $de = self::dischargeShapeError($discharge);
            if ($de !== null) {
                return $no("malformed discharge: $de");
            }
            /** @var Obj $d */
            $d = $discharge;
            if ($d->get('caveat_id') !== $c->get('id')) {
                return $no('the discharge is for another caveat');
            }
            if ($d->get('issuer') !== $c->get('issuer')) {
                return $no('the discharge names another issuer');
            }
            $allPins = self::field($bind, 'pins');
            if (!self::isList($allPins)) {
                return $no('no issuer is pinned');
            }
            $pins = [];
            foreach ($allPins as $p) {
                if ($p instanceof Obj && $p->get('label') === $c->get('issuer')) {
                    $pins[] = $p;
                }
            }
            if (count($pins) === 0) {
                return $no('the issuer is not pinned by this verifier');
            }
            if (count($pins) > 1) {
                return $no('the issuer label is pinned more than once (ambiguous)');
            }
            $pin = $pins[0];
            if ($pin->get('class') !== $c->get('issuer_class')) {
                return $no('the pinned issuer is not of the class the caveat requires');
            }
            if ($c->has('issuer_spiffe') && $pin->get('spiffe_id') !== $c->get('issuer_spiffe')) {
                return $no('the pinned issuer does not carry the SPIFFE ID the caveat requires');
            }
            $sp = Obj::of(['pk' => $pin->get('pk')]);
            if ($pin->has('pq_pk')) {
                $sp->set('pq_pk', $pin->get('pq_pk'));
            }
            if (!IntentWb::verifyArtifactSig(self::DISCHARGE_DOMAIN, $d, $sp)) {
                return $no('discharge signature invalid');
            }
            if ($d->get('bind') !== $c->get('bind')) {
                return $no('the discharge binds differently than the caveat requires');
            }
            if ($d->get('cap_hash') !== self::field($bind, 'cap_hash')) {
                return $no('the discharge is bound to another hop');
            }
            if ($c->get('bind') === 'action' && $d->get('action_digest') !== self::field($bind, 'action_digest')) {
                return $no('the discharge is bound to another action');
            }
            if ($nowF < self::f($d->get('iat'))) {
                return $no('the discharge is from the future');
            }
            if ($nowF > self::f($d->get('not_after'))) {
                return $no('the discharge has expired');
            }
            if (self::f($d->get('not_after')) - self::f($d->get('iat')) > self::f($c->get('ttl_ms'))) {
                return $no('the discharge lives longer than the caveat allows');
            }
            $digest = self::dischargeDigest($d);
            $revoked = self::field($bind, 'revoked');
            if (self::isList($revoked) && in_array($digest, $revoked, true)) {
                return $no('the discharge is revoked');
            }
            foreach ($c->get('require') as $r) {
                if (!self::claimHolds($r, $d->get('claims'))) {
                    return $no("claim '" . $r->get('claim') . "' does not satisfy the caveat");
                }
            }
            return ['ok' => true, 'digest' => $digest, 'claims' => $d->get('claims')];
        } catch (\Throwable $err) {
            return $no('discharge error (fail closed): ' . $err->getMessage());
        }
    }

    // ---- narrow ----------------------------------------------------------------------------------------------------

    /** Null = well-formed. */
    public static function narrowShapeError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'not an object';
        }
        $e = self::closedMembers($a, self::N_REQUIRED, self::N_OPTIONAL, 'narrow');
        if ($e !== null) {
            return $e;
        }
        if (!self::isOne($a->get('v')) || $a->get('kind') !== 'pca-narrow') {
            return 'not a pca-narrow v1';
        }
        if (!self::isDigest($a->get('cap_hash'))) {
            return 'cap_hash must be canonical base64url (32 bytes)';
        }
        if (!self::bounded($a->get('holder'), 64) || Pca::unb64u($a->get('holder'), 32) === null) {
            return 'holder must be canonical base64url (32 bytes)';
        }
        $cs = $a->get('caveats');
        if (!self::isList($cs) || count($cs) < 1 || count($cs) > self::NARROW_MAX_CAVEATS) {
            return 'caveats must be 1..' . self::NARROW_MAX_CAVEATS . ' caveats';
        }
        foreach ($cs as $c) {
            if (!($c instanceof Obj) || !is_string($c->get('type'))) {
                return 'every caveat must be an object with a string type';
            }
            if (in_array($c->get('type'), self::NARROW_FORBIDDEN, true)) {
                return "a narrow block cannot carry a '" . $c->get('type') . "' caveat";
            }
        }
        if ($a->has('action_digest') && !self::isDigest($a->get('action_digest'))) {
            return 'action_digest must be canonical base64url (32 bytes)';
        }
        $iat = $a->get('iat');
        $na = $a->get('not_after');
        if (!(self::safe($iat) && self::f($iat) >= 0) || !(self::safe($na) && self::f($na) >= 0)) {
            return 'iat and not_after must be non-negative safe integers';
        }
        if (!(self::f($na) > self::f($iat))) {
            return 'not_after must be greater than iat';
        }
        if (self::f($na) - self::f($iat) > self::MAX_LIFETIME_MS) {
            return 'a narrow block lives at most ' . self::MAX_LIFETIME_MS . ' ms';
        }
        $nonce = $a->get('nonce');
        $nb = is_string($nonce) ? Pca::unb64u($nonce) : null;
        if ($nb === null || strlen($nb) < 16) {
            return 'nonce must be canonical base64url of at least 16 bytes';
        }
        if (!is_string($a->get('sig'))) {
            return 'sig must be a string';
        }
        return IntentWb::artifactSuiteError($a);
    }

    /**
     * Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key the
     * leaf's `holder_pq` commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window. `$bind`:
     * `now`, `action_digest?`. Total.
     *
     * @return array{ok: bool, reason?: string, caveats?: list<mixed>}
     */
    public static function verifyNarrow(mixed $narrow, mixed $grant, mixed $chain, mixed $bind): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $now = self::field($bind, 'now');
            if (!self::safe($now)) {
                return $no('the verifier clock is not a safe integer (fail closed)');
            }
            $nowF = self::f($now);
            $e = self::narrowShapeError($narrow);
            if ($e !== null) {
                return $no("malformed narrow block: $e");
            }
            /** @var Obj $n */
            $n = $narrow;
            $hops = self::hopsOf($grant, $chain);
            $leaf = $hops[count($hops) - 1];
            if (!($leaf instanceof Obj)) {
                return $no('malformed capability chain');
            }
            if ($n->get('holder') !== $leaf->get('holder')) {
                return $no('the narrow block is not signed by the leaf holder');
            }
            if ($n->get('cap_hash') !== Pca::capHash($leaf)) {
                return $no('the narrow block is bound to another hop');
            }
            $sp = Obj::of(['pk' => $n->get('holder')]);
            if ($n->has('pq_pk') && $leaf->has('holder_pq') && Pca::holderPqCommitment($n->get('pq_pk')) === $leaf->get('holder_pq')) {
                $sp->set('pq_pk', $n->get('pq_pk'));
            }
            if (!IntentWb::verifyArtifactSig(self::NARROW_DOMAIN, $n, $sp)) {
                return $no('narrow signature invalid');
            }
            if ($n->has('action_digest') && $n->get('action_digest') !== self::field($bind, 'action_digest')) {
                return $no('the narrow block is bound to another action');
            }
            if ($nowF < self::f($n->get('iat'))) {
                return $no('the narrow block is from the future');
            }
            if ($nowF > self::f($n->get('not_after'))) {
                return $no('the narrow block has expired');
            }
            return ['ok' => true, 'caveats' => $n->get('caveats')];
        } catch (\Throwable $err) {
            return $no('narrow error (fail closed): ' . $err->getMessage());
        }
    }

    // ---- max_uses --------------------------------------------------------------------------------------------------

    public static function maxUsesError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'caveat must be an object';
        }
        $e = self::closedMembers($c, ['type', 'id', 'n', 'until'], [], 'max_uses');
        if ($e !== null) {
            return $e;
        }
        if ($c->get('type') !== self::CAVEAT_MAX_USES) {
            return 'not a max_uses caveat';
        }
        if (!self::matches(self::ID_RE, $c->get('id'))) {
            return 'id is malformed';
        }
        $n = $c->get('n');
        if (!(self::safe($n) && self::f($n) >= 1 && self::f($n) <= self::MAX_USES_LIMIT)) {
            return 'n must be 1..' . self::MAX_USES_LIMIT;
        }
        $u = $c->get('until');
        if (!(self::safe($u) && self::f($u) >= 0)) {
            return 'until must be a non-negative safe integer';
        }
        return null;
    }

    /** The store key of use slot `$i` of caveat `$id` carried by hop `$capHashOfHop`: b64u(sha256(domain NUL cap NUL id NUL i)). */
    public static function maxUsesSlotKey(string $capHashOfHop, string $id, int $i): string
    {
        return Pca::b64u(hash('sha256', self::MAX_USES_DOMAIN . $capHashOfHop . "\0" . $id . "\0" . $i, true));
    }

    /**
     * Spend one use of every `max_uses` caveat in `$bound` (a list of `['caveat' =>, 'cap_hash' =>]`), in order, after the rest of
     * the decision allows. Each caveat takes the first free slot of its `n`: slot `i` is claimed in the replay store with counter
     * 1 (the SDK's atomic claim succeeds only for a counter above the stored one, so the first claim wins and every later one
     * fails). The first exhausted, expired or malformed caveat refuses; slots already taken stay spent (fail closed). A
     * store with `consumeOnce` ({@see ConsumeOnceStore}) keeps a slot until `until` only; a claim-only store keeps it forever.
     *
     * @param object $store a {@see ConsumeOnceStore}, or any object with `claim(string, int)` (a {@see StateStore})
     * @return array{ok: bool, reason?: string, spent?: int}
     */
    public static function reserveMaxUses(object $store, mixed $bound, mixed $now): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            if (!self::safe($now)) {
                return $no('the verifier clock is not a safe integer (fail closed)');
            }
            $nowF = self::f($now);
            if (!self::isList($bound)) {
                return $no('max_uses error (fail closed): bound caveats are not a list');
            }
            $spent = 0;
            $ids = [];
            foreach ($bound as $b) {
                $caveat = self::field($b, 'caveat');
                $cap = self::field($b, 'cap_hash');
                if (!($caveat instanceof Obj) || $caveat->get('type') !== self::CAVEAT_MAX_USES) {
                    continue;
                }
                $err = self::maxUsesError($caveat);
                if ($err !== null) {
                    return $no("malformed max_uses caveat: $err");
                }
                if (!is_string($cap)) {
                    return $no('max_uses error (fail closed): cap_hash is not a string');
                }
                $id = $caveat->get('id');
                if (isset($ids["$cap\0$id"])) {
                    return $no("duplicate max_uses id '$id'");
                }
                $ids["$cap\0$id"] = true;
                if ($nowF >= self::f($caveat->get('until'))) {
                    return $no("max_uses '$id' has expired");
                }
                $took = false;
                $n = (int)self::f($caveat->get('n'));
                for ($i = 0; $i < $n && !$took; $i++) {
                    $slot = self::maxUsesSlotKey($cap, $id, $i);
                    // the slot is remembered until `until` when the store can expire it, forever otherwise
                    $took = $store instanceof ConsumeOnceStore || method_exists($store, 'consumeOnce')
                        ? $store->consumeOnce($slot, (int)self::f($caveat->get('until')), (int)$nowF) === true
                        : $store->claim($slot, 1)->ok === true;
                }
                if (!$took) {
                    return $no("max_uses '$id' is exhausted");
                }
                $spent++;
            }
            return ['ok' => true, 'spent' => $spent];
        } catch (\Throwable $err) {
            return $no('max_uses error (fail closed): ' . $err->getMessage());
        }
    }

    // ---- derive ----------------------------------------------------------------------------------------------------

    private static function exprError(mixed $x, array $names, int $depth, int &$count): ?string
    {
        if ($depth > self::DERIVE_MAX_DEPTH) {
            return 'expression nests deeper than ' . self::DERIVE_MAX_DEPTH;
        }
        if (++$count > self::DERIVE_MAX_NODES) {
            return 'more than ' . self::DERIVE_MAX_NODES . ' expression nodes';
        }
        if (!($x instanceof Obj)) {
            return 'expression must be an object';
        }
        if ($x->has('ref')) {
            $e = self::closedMembers($x, ['ref'], [], 'ref');
            if ($e !== null) {
                return $e;
            }
            return is_string($x->get('ref')) && isset($names[$x->get('ref')]) ? null : 'ref names no earlier def';
        }
        if ($x->has('const')) {
            $e = self::closedMembers($x, ['const'], [], 'const');
            if ($e !== null) {
                return $e;
            }
            return self::isScalarClaim($x->get('const')) ? null : 'const must be a scalar';
        }
        $op = $x->get('op');
        if ($op === 'and' || $op === 'or') {
            $e = self::closedMembers($x, ['op', 'args'], [], $op);
            if ($e !== null) {
                return $e;
            }
            $args = $x->get('args');
            if (!self::isList($args) || count($args) < 1 || count($args) > 8) {
                return "$op needs 1..8 arguments";
            }
            foreach ($args as $a) {
                $r = self::exprError($a, $names, $depth + 1, $count);
                if ($r !== null) {
                    return $r;
                }
            }
            return null;
        }
        if ($op === 'not') {
            return self::closedMembers($x, ['op', 'arg'], [], 'not') ?? self::exprError($x->get('arg'), $names, $depth + 1, $count);
        }
        if (in_array($op, ['eq', 'neq', 'lt', 'lte', 'gt', 'gte'], true)) {
            return self::closedMembers($x, ['op', 'a', 'b'], [], $op)
                ?? self::exprError($x->get('a'), $names, $depth + 1, $count)
                ?? self::exprError($x->get('b'), $names, $depth + 1, $count);
        }
        return 'unknown expression';
    }

    /** Null when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it). */
    public static function deriveError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'caveat must be an object';
        }
        $e = self::closedMembers($c, ['type', 'id', 'defs', 'check'], [], 'derive');
        if ($e !== null) {
            return $e;
        }
        if ($c->get('type') !== self::CAVEAT_DERIVE) {
            return 'not a derive caveat';
        }
        if (!self::matches(self::ID_RE, $c->get('id'))) {
            return 'id is malformed';
        }
        $defs = $c->get('defs');
        if (!self::isList($defs) || count($defs) > self::DERIVE_MAX_DEFS) {
            return 'defs must be an array of at most ' . self::DERIVE_MAX_DEFS;
        }
        $names = [];
        $count = 0;
        foreach ($defs as $d) {
            if (!($d instanceof Obj) || !self::matches(self::NAME_RE, $d->get('name'))) {
                return 'def name is malformed';
            }
            $name = $d->get('name');
            if (isset($names[$name])) {
                return "def '$name' is defined twice";
            }
            $de = match ($d->get('kind')) {
                'count' => self::countDefError($d),
                'param' => self::paramDefError($d),
                'action' => self::closedMembers($d, ['name', 'kind', 'field'], [], 'action')
                    ?? ($d->get('field') === 'verb' || $d->get('field') === 'resource' ? null : "field must be 'verb' or 'resource'"),
                'claim' => self::closedMembers($d, ['name', 'kind', 'caveat_id', 'claim'], [], 'claim')
                    ?? (self::matches(self::ID_RE, $d->get('caveat_id')) && self::matches(self::NAME_RE, $d->get('claim')) ? null : 'claim reference is malformed'),
                'expr' => self::closedMembers($d, ['name', 'kind', 'expr'], [], 'expr') ?? self::exprError($d->get('expr'), $names, 1, $count),
                default => 'unknown def kind',
            };
            if ($de !== null) {
                return "def '$name': $de";
            }
            $names[$name] = true;
        }
        return self::exprError($c->get('check'), $names, 1, $count);
    }

    private static function countDefError(Obj $d): ?string
    {
        $e = self::closedMembers($d, ['name', 'kind', 'window_ms'], ['verb', 'resource_prefix'], 'count');
        if ($e !== null) {
            return $e;
        }
        $w = $d->get('window_ms');
        if (!(self::safe($w) && self::f($w) >= 1 && self::f($w) <= self::DERIVE_MAX_WINDOW_MS)) {
            return 'window_ms out of range';
        }
        if ($d->has('verb') && !self::bounded($d->get('verb'), 256)) {
            return 'verb must be a non-empty string';
        }
        if ($d->has('resource_prefix') && !self::bounded($d->get('resource_prefix'), 256)) {
            return 'resource_prefix must be a non-empty string';
        }
        return null;
    }

    private static function paramDefError(Obj $d): ?string
    {
        $e = self::closedMembers($d, ['name', 'kind', 'path'], [], 'param');
        if ($e !== null) {
            return $e;
        }
        $p = $d->get('path');
        if (is_string($p)) {
            $segs = explode('.', $p);
            if (count($segs) <= 4) {
                $all = true;
                foreach ($segs as $s) {
                    $all = $all && IntentWb::isPathSegment($s);
                }
                if ($all) {
                    return null;
                }
            }
        }
        return 'param path is malformed';
    }

    /** A Kleene value: a scalar, or null for unknown. */
    private static function evalExpr(Obj $x, array $env): mixed
    {
        if ($x->has('ref')) {
            return $env[$x->get('ref')] ?? null;
        }
        if ($x->has('const')) {
            return $x->get('const');
        }
        $op = $x->get('op');
        if ($op === 'not') {
            $v = self::evalExpr($x->get('arg'), $env);
            return is_bool($v) ? !$v : null;
        }
        if ($op === 'and' || $op === 'or') {
            $stop = $op === 'or';
            $unknown = false;
            foreach ($x->get('args') as $a) {
                $v = self::evalExpr($a, $env);
                if (!is_bool($v)) {
                    $unknown = true;
                } elseif ($v === $stop) {
                    return $stop;
                }
            }
            return $unknown ? null : !$stop;
        }
        $a = self::evalExpr($x->get('a'), $env);
        $b = self::evalExpr($x->get('b'), $env);
        if ($a === null || $b === null) {
            return null;
        }
        if ($op === 'eq') {
            return IntentWb::scalarEq($a, $b);
        }
        if ($op === 'neq') {
            return !IntentWb::scalarEq($a, $b);
        }
        if (!self::safe($a) || !self::safe($b)) {
            return null;
        }
        $fa = self::f($a);
        $fb = self::f($b);
        return match ($op) {
            'lt' => $fa < $fb,
            'lte' => $fa <= $fb,
            'gt' => $fa > $fb,
            default => $fa >= $fb,
        };
    }

    /**
     * Evaluate a well-formed derive caveat: true only when `check` is exactly true (false and unknown both refuse; null = unknown).
     * `$inp`: `now`, `action?` (Obj {verb, resource, params}), `history?` (list of {t, verb, resource}), `claims` (Obj: caveat id
     * -> Obj of the claims of the discharge that verified in this evaluation, the only claim source).
     */
    public static function evaluateDerive(Obj $c, array $inp): ?bool
    {
        $env = [];
        $act = $inp['action'] ?? null;
        $now = self::f($inp['now']);
        foreach ($c->get('defs') as $d) {
            $v = null;
            switch ($d->get('kind')) {
                case 'count':
                    $h = $inp['history'] ?? null;
                    if (!self::isList($h) || count($h) > self::DERIVE_MAX_HISTORY) {
                        break;
                    }
                    $n = 0;
                    $bad = false;
                    foreach ($h as $e) {
                        if (!($e instanceof Obj) || !self::safe($e->get('t')) || !is_string($e->get('verb')) || !is_string($e->get('resource'))) {
                            $bad = true;
                            break;
                        }
                        $t = self::f($e->get('t'));
                        if ($t > $now - self::f($d->get('window_ms')) && $t <= $now
                            && (!$d->has('verb') || $e->get('verb') === $d->get('verb'))
                            && (!$d->has('resource_prefix') || str_starts_with($e->get('resource'), $d->get('resource_prefix')))) {
                            $n++;
                        }
                    }
                    $v = $bad ? null : new Num((string)$n);
                    break;
                case 'param':
                    $r = IntentWb::resolveParamPath($act instanceof Obj ? $act->get('params') : null, 'action.params.' . $d->get('path'));
                    $v = $r['found'] && self::isScalarClaim($r['value']) ? $r['value'] : null;
                    break;
                case 'action':
                    $f = $act instanceof Obj ? $act->get($d->get('field')) : null;
                    $v = self::bounded($f, 256) ? $f : null;
                    break;
                case 'claim':
                    $cl = $inp['claims']->has($d->get('caveat_id')) ? $inp['claims']->get($d->get('caveat_id')) : null;
                    $v = $cl instanceof Obj && $cl->has($d->get('claim')) ? $cl->get($d->get('claim')) : null;
                    break;
                case 'expr':
                    $v = self::evalExpr($d->get('expr'), $env);
                    break;
            }
            $env[$d->get('name')] = $v;
        }
        $r = self::evalExpr($c->get('check'), $env);
        return is_bool($r) ? $r : null;
    }

    // ---- spiffe_bound ----------------------------------------------------------------------------------------------

    public static function spiffeBoundError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'caveat must be an object';
        }
        $e = self::closedMembers($c, ['type'], ['spiffe_id', 'spiffe_prefix'], 'spiffe_bound');
        if ($e !== null) {
            return $e;
        }
        if ($c->get('type') !== self::CAVEAT_SPIFFE_BOUND) {
            return 'not a spiffe_bound caveat';
        }
        if ($c->has('spiffe_id') === $c->has('spiffe_prefix')) {
            return 'exactly one of spiffe_id and spiffe_prefix';
        }
        return self::spiffeIdError($c->get('spiffe_id') ?? $c->get('spiffe_prefix'));
    }

    /** `spiffe_id`: the peer must equal it. `spiffe_prefix`: the peer must equal it or lie below it (`prefix + "/"`). */
    private static function spiffeSatisfied(Obj $c, mixed $peer): bool
    {
        if (self::spiffeBoundError($c) !== null || self::spiffeIdError($peer) !== null) {
            return false;
        }
        if ($c->has('spiffe_id')) {
            return $peer === $c->get('spiffe_id');
        }
        $pre = $c->get('spiffe_prefix');
        return $peer === $pre || str_starts_with($peer, "$pre/");
    }

    /** A copy of the K1 input (Obj or string-keyed array) whose `action_digest` is the verifier's own; anything else gives only the digest. */
    public static function withActionDigest(mixed $k1, string $digest): Obj
    {
        $o = new Obj();
        if ($k1 instanceof Obj) {
            foreach ($k1->keys() as $k) {
                $o->set($k, $k1->get($k));
            }
        } elseif (is_array($k1) && !array_is_list($k1)) {
            foreach ($k1 as $k => $v) {
                $o->set((string)$k, $v);
            }
        }
        $o->set('action_digest', $digest);
        return $o;
    }

    // ---- presented headers -----------------------------------------------------------------------------------------

    /** One header value, names case-insensitive; null when absent, empty, not a string, or present with differing spellings. */
    private static function headerValue(mixed $headers, string $name): ?string
    {
        $pairs = [];
        if ($headers instanceof Obj) {
            foreach ($headers->keys() as $k) {
                $pairs[$k] = $headers->get($k);
            }
        } elseif (is_array($headers) && !array_is_list($headers)) {
            $pairs = $headers;
        }
        $found = null;
        foreach ($pairs as $k => $v) {
            if (strtolower((string)$k) !== $name) {
                continue;
            }
            $v = is_array($v) && count($v) === 1 ? $v[array_key_first($v)] : $v;
            if (!is_string($v) || ($found !== null && $found !== $v)) {
                return null; // ambiguous or unreadable credential = absent
            }
            $found = $v;
        }
        return $found === '' ? null : $found;
    }

    /**
     * The discharges / narrow block a caller presented in the `PCA-Discharges` (a JSON array) and `PCA-Narrow` (any JSON value)
     * headers: strict unpadded base64url of UTF-8, then the strict JSON parser. An empty value is absent.
     *
     * @return array{ok: true, value: Obj}|array{ok: false, reason: string}
     */
    public static function presentedK1(mixed $headers): array
    {
        $out = new Obj();
        try {
            $d = self::headerValue($headers, 'pca-discharges');
            if ($d !== null) {
                $raw = Pca::decodePcaHeader($d);
                $arr = $raw === null ? null : Json::parseStrict($raw);
                if (!is_array($arr) || !array_is_list($arr)) {
                    return ['ok' => false, 'reason' => 'PCA-Discharges must be a base64url JSON array'];
                }
                $out->set('discharges', $arr);
            }
            $n = self::headerValue($headers, 'pca-narrow');
            if ($n !== null) {
                $raw = Pca::decodePcaHeader($n);
                if ($raw === null) {
                    return ['ok' => false, 'reason' => 'PCA-Narrow is not valid base64url'];
                }
                $out->set('narrow', Json::parseStrict($raw));
            }
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'presented K1 headers are unreadable: ' . $e->getMessage()];
        }
        return ['ok' => true, 'value' => $out];
    }

    /** `{...presented, ...own}`: the K1 input a guard passes on (the host's own members win). Unreadable headers add nothing. */
    public static function mergePresentedK1(mixed $headers, mixed $own): Obj
    {
        $p = self::presentedK1($headers);
        $out = $p['ok'] ? $p['value'] : new Obj();
        if ($own instanceof Obj) {
            foreach ($own->keys() as $k) {
                $out->set($k, $own->get($k));
            }
        } elseif (is_array($own) && !array_is_list($own)) {
            foreach ($own as $k => $v) {
                $out->set((string)$k, $v);
            }
        }
        return $out;
    }

    // ---- the K1 evaluator ------------------------------------------------------------------------------------------

    /**
     * Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Two passes: `needs_discharge` first (derive
     * reads their claims), then sealed / max_uses / derive / spiffe_bound. Ids of needs_discharge, max_uses and derive must be
     * unique over the chain and narrow block (a duplicate fails every caveat sharing it). `max_uses` is only checked for
     * well-formedness and expiry here; {@see reserveMaxUses} spends it.
     *
     * `$k1`: `pins?`, `discharges?`, `narrow?`, `action_digest?`, `revoked_discharges?`, `spiffe_id?`, `history?` (Obj or array).
     * `$ctx`: `now`, `action?` (Obj {verb, resource, params}).
     *
     * @return array{ok: bool, failed: list<string>, reasons: list<string>, plain: list<mixed>, bound: list<array>}
     */
    public static function evaluateK1(mixed $grant, mixed $chain, mixed $k1, mixed $ctx): array
    {
        $failed = [];
        $reasons = [];
        $fail = static function (mixed $c, string $why) use (&$failed, &$reasons): void {
            $failed[] = $c instanceof Obj && is_string($c->get('type')) ? $c->get('type') : '<malformed>';
            $reasons[] = $why;
        };
        $result = static function (array $plain, array $bound) use (&$failed, &$reasons): array {
            return ['ok' => $failed === [], 'failed' => $failed, 'reasons' => $reasons, 'plain' => $plain, 'bound' => $bound];
        };
        try {
            $base = self::boundCaveats($grant, $chain);
            $nowV = self::field($ctx, 'now');
            if ($base === null || !self::safe($nowV)) {
                $fail(Obj::of(['type' => '<malformed>']), $base === null ? 'malformed capability chain' : 'the verifier clock is not a safe integer (fail closed)');
                return $result([], []);
            }
            // No K1 input at all (not even an empty object): every K1 caveat is refused, whatever its type.
            if (!($k1 instanceof Obj) && !(is_array($k1) && ($k1 === [] || !array_is_list($k1)))) {
                $mine = array_values(array_filter($base, static fn(array $b): bool => self::isK1Caveat($b['caveat'])));
                foreach ($mine as $b) {
                    $fail($b['caveat'], 'the caveat language is not configured (no k1 input)');
                }
                return $result([], $mine);
            }
            $hops = self::hopsOf($grant, $chain);
            $leafIndex = count($hops) - 1;
            $bound = $base;
            $plain = [];
            $adigest = self::has($k1, 'action_digest') ? self::field($k1, 'action_digest') : null;
            if (self::has($k1, 'narrow')) {
                $nv = self::verifyNarrow(self::field($k1, 'narrow'), $grant, $chain, ['now' => $nowV, 'action_digest' => $adigest]);
                if (!$nv['ok']) {
                    $fail(Obj::of(['type' => 'narrow']), $nv['reason']);
                    return $result([], array_values(array_filter($bound, static fn(array $b): bool => self::isK1Caveat($b['caveat']))));
                }
                $leafHash = Pca::capHash($hops[$leafIndex]);
                foreach ($nv['caveats'] as $caveat) {
                    $bound[] = ['caveat' => $caveat, 'hop' => $leafIndex, 'cap_hash' => $leafHash];
                    if (!self::isK1Caveat($caveat)) {
                        $plain[] = $caveat;
                    }
                }
            }
            $k1Bound = array_values(array_filter($bound, static fn(array $b): bool => self::isK1Caveat($b['caveat'])));
            // ids are unique per type across the chain and narrow block
            $seen = [];
            foreach ($k1Bound as $b) {
                if (is_string($b['caveat']->get('id'))) {
                    $key = $b['caveat']->get('type') . "\0" . $b['caveat']->get('id');
                    $seen[$key] = ($seen[$key] ?? 0) + 1;
                }
            }
            $claims = new Obj();
            // pass 1: discharges (derive reads their claims)
            foreach ($k1Bound as $b) {
                $c = $b['caveat'];
                if ($c->get('type') !== self::CAVEAT_NEEDS_DISCHARGE) {
                    continue;
                }
                $bad = self::needsDischargeError($c);
                if ($bad !== null) {
                    $fail($c, $bad);
                    continue;
                }
                if (($seen[self::CAVEAT_NEEDS_DISCHARGE . "\0" . $c->get('id')] ?? 0) > 1) {
                    $fail($c, "duplicate needs_discharge id '" . $c->get('id') . "'");
                    continue;
                }
                $why = 'no discharge presented';
                $okd = null;
                $ds = self::field($k1, 'discharges');
                foreach (self::isList($ds) ? $ds : [] as $d) {
                    if (!($d instanceof Obj) || $d->get('caveat_id') !== $c->get('id')) {
                        continue;
                    }
                    $pins = self::field($k1, 'pins');
                    $v = self::verifyDischarge($d, $c, [
                        'cap_hash' => $b['cap_hash'], 'action_digest' => $adigest, 'pins' => $pins ?? [], 'now' => $nowV,
                        'revoked' => self::field($k1, 'revoked_discharges'),
                    ]);
                    if ($v['ok']) {
                        $okd = $v;
                        break;
                    }
                    $why = $v['reason'];
                }
                if ($okd !== null) {
                    $claims->set($c->get('id'), $okd['claims']);
                } else {
                    $fail($c, $why);
                }
            }
            // pass 2: everything else, in order
            $now = self::f($nowV);
            foreach ($k1Bound as $b) {
                $c = $b['caveat'];
                switch ($c->get('type')) {
                    case self::CAVEAT_SEALED:
                        $e = self::closedMembers($c, ['type'], [], 'sealed');
                        if ($e !== null) {
                            $fail($c, $e);
                        } elseif ($b['hop'] !== $leafIndex) {
                            $fail($c, 'a hop was appended below a sealed hop');
                        }
                        break;
                    case self::CAVEAT_MAX_USES:
                        $e = self::maxUsesError($c);
                        if ($e !== null) {
                            $fail($c, $e);
                        } elseif (($seen[self::CAVEAT_MAX_USES . "\0" . $c->get('id')] ?? 0) > 1) {
                            $fail($c, "duplicate max_uses id '" . $c->get('id') . "'");
                        } elseif ($now >= self::f($c->get('until'))) {
                            $fail($c, "max_uses '" . $c->get('id') . "' has expired");
                        }
                        break;
                    case self::CAVEAT_DERIVE:
                        $e = self::deriveError($c);
                        if ($e !== null) {
                            $fail($c, $e);
                        } elseif (($seen[self::CAVEAT_DERIVE . "\0" . $c->get('id')] ?? 0) > 1) {
                            $fail($c, "duplicate derive id '" . $c->get('id') . "'");
                        } else {
                            $inp = ['now' => $nowV, 'claims' => $claims];
                            if (self::has($ctx, 'action')) {
                                $inp['action'] = self::field($ctx, 'action');
                            }
                            if (self::has($k1, 'history')) {
                                $inp['history'] = self::field($k1, 'history');
                            }
                            $r = self::evaluateDerive($c, $inp);
                            if ($r !== true) {
                                $fail($c, $r === null ? 'derive check is unknown (a fact is missing)' : 'derive check is false');
                            }
                        }
                        break;
                    case self::CAVEAT_SPIFFE_BOUND:
                        if (!self::spiffeSatisfied($c, self::field($k1, 'spiffe_id'))) {
                            $fail($c, 'the presenting workload does not carry the required SPIFFE ID');
                        }
                        break;
                }
            }
            return $result($plain, $k1Bound);
        } catch (\Throwable $err) {
            $fail(Obj::of(['type' => '<malformed>']), 'caveat language error (fail closed): ' . $err->getMessage());
            return $result([], []);
        }
    }

    /**
     * The whole caveat decision for a grant and chain: K1 types by {@see evaluateK1}, every other caveat of
     * Pca::policyCaveats($grant, $chain) plus the verified narrow block's plain caveats by the agent-native evaluator. `$context`
     * (Obj): `now`, `delegation_depth?`, `action {verb, resource, params}`, `recent_action_times?`, ...
     *
     * @return array{0: bool, 1: list<string>} [allow, failed (sorted)]
     */
    public static function evaluateCaveatsK1(mixed $grant, mixed $chain, mixed $k1, mixed $context): array
    {
        try {
            $k = self::evaluateK1($grant, $chain, $k1, $context);
            $pc = Pca::policyCaveats($grant, $chain);
            $stock = self::isList($pc) ? array_merge(array_values(array_filter($pc, static fn(mixed $c): bool => !self::isK1Caveat($c))), $k['plain']) : $pc;
            $action = self::field($context, 'action');
            $s = Authorize::evaluateAgentCaveats($stock, $context, Obj::of($action === null ? [] : ['action' => $action]));
            $failed = array_merge($s['failed'], $k['failed']);
            sort($failed, SORT_STRING);
            return [$failed === [], $failed];
        } catch (\Throwable) {
            return [false, ['<evaluation error>']];
        }
    }
}
