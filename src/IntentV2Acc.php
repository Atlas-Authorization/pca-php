<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Part of {@see IntentV2} (a trait so the 3800-line class is split into mutation-testable files): rules 15 (accumulators, monitors, receipts) and 13 step 7 (session revocation).
 * Members are used through IntentV2 only; constants and shared helpers stay in IntentV2.
 */
trait IntentV2Acc
{
    // ==== rule 15: accumulators, monitors, receipts ===================================================================

    /** ω ∈ sel_ψ (action selectors only): the verb is listed, or the schema's verb entry has a parameter feeding the unit. */
    public static function accSelects(mixed $a, mixed $verb, mixed $schema): bool
    {
        $sel = self::m($a, 'sel');
        if ($sel instanceof Obj && $sel->has('event')) {
            return false;
        }
        $verbs = self::m($sel, 'verbs');
        if (self::isList($verbs) && in_array($verb, $verbs, true)) {
            return true;
        }
        $ai = self::m($sel, 'accumulates_into');
        if (!self::isU($ai) && $schema instanceof Obj) {
            $v = self::schemaVerb($schema, $verb);
            return !self::isU($v) && count(self::accumulationParams($v, $ai)) > 0;
        }
        return false;
    }

    /** The canonical key of a `distinct` value: the strict canonical JSON text of a string or a safe integer. */
    public static function distinctKey(mixed $x): ?string
    {
        if (is_string($x) || self::isInt($x)) {
            try {
                return self::canonicalize($x);
            } catch (\Throwable) {
                return null;
            }
        }
        return null;
    }

    /** val(ω) for a selected action. @return array{ok:bool, val?:int, key?:string, reason?:string} */
    public static function accValueOf(mixed $a, mixed $verb, Obj $params, mixed $schema): array
    {
        $read = fn(string $path) => self::m($params, self::paramName($path));
        $agg = self::m($a, 'agg');
        $val = self::m($a, 'val');
        if ($agg === 'count') {
            return ['ok' => true, 'val' => 1];
        }
        if ($agg === 'distinct') {
            $k = is_string($val) ? self::distinctKey($read($val)) : null;
            return $k === null ? self::bad(self::txt($val) . ' must be a string or a safe integer') : ['ok' => true, 'val' => 1, 'key' => $k];
        }
        if (is_string($val)) {
            $x = $read($val);
            return self::isNonNeg($x) ? ['ok' => true, 'val' => self::iv($x)] : self::bad("$val must be a non-negative safe integer");
        }
        $v = $schema instanceof Obj ? self::schemaVerb($schema, $verb) : self::undef();
        if (self::isU($v)) {
            return self::bad("no schema entry for '" . self::txt($verb) . "' to read accumulates_into");
        }
        $s = 0;
        foreach (self::accumulationParams($v, self::m(self::m($a, 'sel'), 'accumulates_into')) as $p) {
            $x = $read($p);
            if (self::isU($x)) {
                continue;
            }
            if (!self::isNonNeg($x)) {
                return self::bad("$p must be a non-negative safe integer");
            }
            $s += self::iv($x);
            if ($s > self::MAX_SAFE) {
                return self::bad('accumulated value exceeds 2^53-1');
            }
        }
        return ['ok' => true, 'val' => $s];
    }

    /** The pre-state shape of an accumulator group: {sum} / {count} / {max} (safe integers >= 0) or {values} (distinct strings). */
    public static function preStateError(mixed $a, mixed $s): ?string
    {
        if (!($s instanceof Obj)) {
            return 'pre-state must be an object';
        }
        $agg = self::m($a, 'agg');
        $want = $agg === 'sum' ? 'sum' : ($agg === 'count' ? 'count' : ($agg === 'max' ? 'max' : 'values'));
        if (implode(',', self::jsKeys($s)) !== $want) {
            return 'pre-state of a ' . self::txt($agg) . " accumulator is {{$want}}";
        }
        if ($want === 'values') {
            $vs = $s->get('values');
            if (!self::isList($vs) || count(array_filter($vs, 'is_string')) !== count($vs)) {
                return 'pre-state values must be strings';
            }
            if (!self::distinct($vs)) {
                return 'pre-state values must be distinct';
            }
            return null;
        }
        return self::isNonNeg($s->get($want)) ? null : "pre-state $want must be a non-negative safe integer";
    }

    /** The post-action value from a well-formed pre-state (null when it would leave the safe-integer range). */
    public static function combineAcc(mixed $a, Obj $pre, array $v): ?int
    {
        $post = match (self::m($a, 'agg')) {
            'sum' => self::iv($pre->get('sum')) + $v['val'],
            'count' => self::iv($pre->get('count')) + 1,
            'max' => max(self::iv($pre->get('max')), $v['val']),
            default => count($pre->get('values')) + (in_array($v['key'] ?? null, $pre->get('values'), true) ? 0 : 1),
        };
        return abs($post) <= self::MAX_SAFE ? $post : null;
    }

    /** The value of a group this action does NOT feed (post = pre). */
    public static function preValue(mixed $a, Obj $pre): int
    {
        return match (self::m($a, 'agg')) {
            'sum' => self::iv($pre->get('sum')),
            'count' => self::iv($pre->get('count')),
            'max' => self::iv($pre->get('max')),
            default => count($pre->get('values')),
        };
    }

    /** The digest a reservation binds: the PCActn without sig, pq_sig, threshold and intent_session. */
    public static function pcactnReservationDigest(Obj $p): string
    {
        return self::hashCanonical(Obj::of(['d' => self::ACC_RESERVE_DOMAIN, 'b' => $p->without('sig', 'pq_sig', 'threshold', 'intent_session')]));
    }

    public static function accReceiptShapeError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'receipt is not an object';
        }
        foreach (self::jsKeys($r) as $k) {
            if (!in_array($k, self::RECEIPT_KEYS, true)) {
                return "receipt: unknown member '$k'";
            }
        }
        if (!self::eq(self::m($r, 'v'), 1) || self::m($r, 'kind') !== 'pca-acc-receipt') {
            return 'not a pca-acc-receipt v1';
        }
        if (Pca::unb64u(self::m($r, 'session'), 32) === null) {
            return 'receipt.session is not canonical base64url (32 bytes)';
        }
        $acc = self::m($r, 'acc');
        if (!is_string($acc) || preg_match(self::ACC_ID_RE, $acc) !== 1) {
            return 'receipt.acc is not an accumulator id';
        }
        $seq = self::m($r, 'seq');
        if (!(self::isInt($seq) && self::f($seq) >= 1)) {
            return 'receipt.seq must be a safe integer >= 1';
        }
        if (!self::isNonNeg(self::m($r, 'pre')) || !self::isNonNeg(self::m($r, 'delta')) || !self::isNonNeg(self::m($r, 'post'))) {
            return 'receipt pre / delta / post must be non-negative safe integers';
        }
        if (Pca::unb64u(self::m($r, 'pcactn_digest'), 32) === null) {
            return 'receipt.pcactn_digest is not canonical base64url (32 bytes)';
        }
        $aud = self::m($r, 'aud');
        if (!is_string($aud) || $aud === '') {
            return 'receipt.aud must be a non-empty string';
        }
        if (!self::isNonNeg(self::m($r, 'issued_at')) || !self::isNonNeg(self::m($r, 'expires_at'))) {
            return 'receipt.issued_at / expires_at must be non-negative safe integers';
        }
        $life = self::iv($r->get('expires_at')) - self::iv($r->get('issued_at'));
        if (!($life >= 0 && $life <= self::MAX_RECEIPT_LIFETIME_MS)) {
            return 'receipt.expires_at must be within ' . self::MAX_RECEIPT_LIFETIME_MS . ' ms after issued_at';
        }
        $kid = self::m($r, 'kid');
        if (!is_string($kid) || preg_match(self::KID_RE, $kid) !== 1) {
            return 'receipt.kid must match [A-Za-z0-9_.:-]{1,64}';
        }
        $l = self::m($r, 'ledger');
        if (!($l instanceof Obj) || self::sortedJoin($l) !== 'head,index' || !self::isNonNeg(self::m($l, 'index'))
            || Pca::unb64u(self::m($l, 'head'), 32) === null) {
            return 'receipt.ledger must be {index, head}';
        }
        if (Pca::unb64u(self::m($r, 'signer'), 32) === null) {
            return 'receipt.signer is not canonical base64url (32 bytes)';
        }
        if (($se = self::suiteError(self::m($r, 'alg'))) !== null) {
            return "receipt.alg: $se";
        }
        if (self::suiteOf(self::m($r, 'alg')) === 'ed25519' && ($r->has('pq_pk') || $r->has('pq_sig'))) {
            return 'an ed25519 receipt must not carry pq_pk / pq_sig';
        }
        if (!is_string(self::m($r, 'sig'))) {
            return 'receipt.sig must be a string';
        }
        return null;
    }

    private static function receiptBody(Obj $r): Obj
    {
        $o = new Obj();
        foreach (['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at', 'expires_at', 'kid'] as $k) {
            $o->set($k, $r->get($k));
        }
        $l = $r->get('ledger');
        $o->set('ledger', Obj::of(['index' => $l->get('index'), 'head' => $l->get('head')]));
        $o->set('signer', $r->get('signer'));
        return $o;
    }

    /** verifyAccReceiptSignature: shape, `signer == expectedSigner`, suite signature (PQ only as pinned). Never throws. */
    public static function verifyAccReceiptSignature(mixed $r, mixed $expectedSigner, ?string $pinKey = null, mixed $pinPq = null): bool
    {
        try {
            if (self::accReceiptShapeError($r) !== null || $r->get('signer') !== $expectedSigner) {
                return false;
            }
            $msg = self::ACC_RECEIPT_DOMAIN . self::canonicalize(self::bindSuite(self::receiptBody($r), self::m($r, 'alg'), self::m($r, 'pq_pk')));
            return self::verifyPinned(self::m($r, 'alg'), $r->get('signer'), self::m($r, 'pq_pk'), $msg, $r->get('sig'),
                self::m($r, 'pq_sig'), $pinKey, $pinPq);
        } catch (\Throwable) {
            return false;
        }
    }

    /** The receipt's content address (what `intent_session.acc[].receipt` carries). */
    public static function accReceiptDigest(mixed $r): string
    {
        return self::hashCanonical(Obj::of(['d' => self::ACC_RECEIPT_REF_DOMAIN, 'r' => $r]));
    }

    public static function sequencerKeySetShapeError(mixed $k): ?string
    {
        if (!($k instanceof Obj)) {
            return 'key set is not an object';
        }
        foreach (self::jsKeys($k) as $x) {
            if (!in_array($x, ['v', 'kind', 'sequencer', 'version', 'issued_at', 'keys', 'alg', 'pq_pk', 'sig', 'pq_sig'], true)) {
                return "key set: unknown member '$x'";
            }
        }
        if (!self::eq(self::m($k, 'v'), 1) || self::m($k, 'kind') !== 'pca-sequencer-keys') {
            return 'not a pca-sequencer-keys v1';
        }
        if (Pca::unb64u(self::m($k, 'sequencer'), 32) === null) {
            return 'sequencer is not canonical base64url (32 bytes)';
        }
        if (!(self::isNonNeg(self::m($k, 'version')) && self::f($k->get('version')) >= 1)) {
            return 'version must be a safe integer >= 1';
        }
        if (!self::isNonNeg(self::m($k, 'issued_at'))) {
            return 'issued_at must be a non-negative safe integer';
        }
        $keys = self::m($k, 'keys');
        if (!self::isList($keys) || count($keys) === 0 || count($keys) > 256) {
            return 'keys must be 1..256 entries';
        }
        $kids = [];
        foreach ($keys as $e) {
            $ok = $e instanceof Obj;
            foreach ($ok ? self::jsKeys($e) : [] as $x) {
                if (!in_array($x, ['kid', 'pk', 'alg', 'pq_pk', 'not_before', 'not_after'], true)) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return 'keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}';
            }
            $kid = self::m($e, 'kid');
            if (!is_string($kid) || preg_match(self::KID_RE, $kid) !== 1 || isset($kids['k' . $kid])) {
                return 'key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct';
            }
            $kids['k' . $kid] = true;
            if (Pca::unb64u(self::m($e, 'pk'), 32) === null) {
                return 'key pk is not canonical base64url (32 bytes)';
            }
            if (($se = self::suiteError(self::m($e, 'alg'))) !== null) {
                return "key alg: $se";
            }
            if ($e->has('pq_pk') && Pca::unb64u($e->get('pq_pk')) === null) {
                return 'key pq_pk is not canonical base64url';
            }
            $nb = self::m($e, 'not_before');
            $na = self::m($e, 'not_after');
            if (!self::isNonNeg($nb) || (!self::isU($na) && !(self::isNonNeg($na) && self::f($na) >= self::f($nb)))) {
                return 'key validity must be 0 <= not_before <= not_after';
            }
        }
        if (($se = self::suiteError(self::m($k, 'alg'))) !== null) {
            return "alg: $se";
        }
        if (self::suiteOf(self::m($k, 'alg')) === 'ed25519' && ($k->has('pq_pk') || $k->has('pq_sig'))) {
            return 'an ed25519 key set must not carry pq_pk / pq_sig';
        }
        if (!is_string(self::m($k, 'sig'))) {
            return 'sig must be a string';
        }
        return null;
    }

    /** Verify a `pca-sequencer-keys` set under the session's pinned root (and the root's pinned PQ key). Never throws. */
    public static function verifySequencerKeySet(mixed $k, mixed $root, mixed $rootPqPk = null): bool
    {
        try {
            if (self::sequencerKeySetShapeError($k) !== null || !is_string($root) || $k->get('sequencer') !== $root) {
                return false;
            }
            $body = Obj::of(['v' => $k->get('v'), 'kind' => $k->get('kind'), 'sequencer' => $k->get('sequencer'),
                'version' => $k->get('version'), 'issued_at' => $k->get('issued_at'), 'keys' => $k->get('keys')]);
            $msg = self::SEQUENCER_KEYS_DOMAIN . self::canonicalize(self::bindSuite($body, self::m($k, 'alg'), self::m($k, 'pq_pk')));
            $pinned = $rootPqPk !== null && !self::isU($rootPqPk);
            return self::verifyPinned(self::m($k, 'alg'), $root, self::m($k, 'pq_pk'), $msg, $k->get('sig'), self::m($k, 'pq_sig'),
                $pinned ? $root : null, $pinned ? $rootPqPk : null);
        } catch (\Throwable) {
            return false;
        }
    }

    /** A key set's content address: b64u(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set}))), signature fields included. */
    public static function sequencerKeySetDigest(mixed $ks): string
    {
        return self::hashCanonical(Obj::of(['d' => self::SEQUENCER_KEYS_REF_DOMAIN, 'k' => $ks]));
    }

    /** `acc.keyset_versions[root]` is exactly {version, digest}: version a safe integer >= 1, digest 32-byte base64url. Null = well-formed. */
    public static function trackedKeySetError(mixed $t): ?string
    {
        if (!($t instanceof Obj)) {
            return 'a tracked key set must be an object {version, digest}';
        }
        foreach (self::jsKeys($t) as $k) {
            if ($k !== 'version' && $k !== 'digest') {
                return "a tracked key set has the unknown member '$k'";
            }
        }
        if (!self::isInt(self::m($t, 'version')) || self::f($t->get('version')) < 1) {
            return 'a tracked key set version must be a safe integer >= 1';
        }
        if (!is_string(self::m($t, 'digest')) || !self::b32($t->get('digest'))) {
            return 'a tracked key set digest must be canonical base64url (32 bytes)';
        }
        return null;
    }

    /**
     * Rule 15 (sequenced holder; intent-acc.ts verifyReceiptAgainstHolder). 'valid' only when ALL hold:
     *   - `now` is a safe integer and every bound is a non-negative safe integer; the key-set list is an array;
     *   - the receipt is well-formed (`issued_at <= expires_at <= issued_at + 15 min`), `issued_at <= now + 60 s` and
     *     `now - issued_at <= $maxReceiptAgeMs` (default 900000);
     *   - SOME presented key set verifies under `holder.root` (PQ: `holder.root_pq_pk`); when the verifier tracks
     *     `$tracked` = {version, digest} for the root, `version >= tracked.version` (no rollback) and, at an equal version,
     *     `sequencerKeySetDigest(set) == tracked.digest` (EQUIVOCATION otherwise); `version >= $minKeySetVersion` when a bare
     *     floor is given (version-only replayers); `issued_at <= now + 60 s` and `now - issued_at <= $maxKeySetAgeMs` (default 3600000), and lists
     *     `receipt.kid` with `pk == receipt.signer`, `not_before <= receipt.issued_at`, and, when `not_after` is set,
     *     `receipt.issued_at <= not_after` AND `not_after >= now - 60 s` (a retired key stops verifying once retired), the
     *     entry's suite equal to the receipt's;
     *   - the receipt verifies under that entry (PQ pinned by the entry's `pq_pk`).
     * 'unsupported' when it is not valid and the receipt or a presented key set names a suite this verifier does not
     * implement; else 'invalid'. Never throws.
     */
    public static function verifyReceiptAgainstHolder(mixed $r, mixed $holder, mixed $keySets, mixed $now, mixed $maxReceiptAgeMs = null,
                                                      mixed $maxKeySetAgeMs = null, mixed $minKeySetVersion = null, mixed $tracked = null): string
    {
        try {
            $maxAge = $maxReceiptAgeMs ?? self::DEFAULT_MAX_RECEIPT_AGE_MS;
            $maxSetAge = $maxKeySetAgeMs ?? self::DEFAULT_MAX_KEYSET_AGE_MS;
            if (!self::isInt($now) || !self::isNonNeg($maxAge) || !self::isNonNeg($maxSetAge)
                || ($tracked !== null && self::trackedKeySetError($tracked) !== null)
                || ($minKeySetVersion !== null && !self::isNonNeg($minKeySetVersion))) {
                return 'invalid';
            }
            if (!self::isList($keySets)) {
                return 'invalid';
            }
            $rs = self::accReceiptShapeError($r);
            if ($rs !== null) {
                return str_contains($rs, self::UNSUPPORTED_SUITE) ? 'unsupported' : 'invalid';
            }
            $now = self::iv($now);
            $ia = self::iv($r->get('issued_at'));
            if (!($ia <= $now + self::RECEIPT_SKEW_MS) || !($now - $ia <= self::iv($maxAge))) {
                return 'invalid';
            }
            $unsupported = false;
            foreach ($keySets as $k) {
                $ke = self::sequencerKeySetShapeError($k);
                if ($ke !== null && str_contains($ke, self::UNSUPPORTED_SUITE)) {
                    $unsupported = true;
                }
                if (!self::verifySequencerKeySet($k, self::m($holder, 'root'), self::m($holder, 'root_pq_pk'))) {
                    continue;
                }
                if ($minKeySetVersion !== null && self::iv($k->get('version')) < self::iv($minKeySetVersion)) {
                    continue;
                }
                if ($tracked !== null) {
                    $tv = self::iv($tracked->get('version'));
                    $kv = self::iv($k->get('version'));
                    if ($kv < $tv || ($kv === $tv && self::sequencerKeySetDigest($k) !== $tracked->get('digest'))) {
                        continue; // rollback, or two different sets under one version (equivocation)
                    }
                }
                $ksAt = self::iv($k->get('issued_at'));
                if (!($ksAt <= $now + self::RECEIPT_SKEW_MS) || !($now - $ksAt <= self::iv($maxSetAge))) {
                    continue;
                }
                $e = null;
                foreach ($k->get('keys') as $x) {
                    if ($x->get('kid') === $r->get('kid')) {
                        $e = $x;
                        break;
                    }
                }
                if ($e === null || $e->get('pk') !== $r->get('signer') || $ia < self::iv($e->get('not_before'))) {
                    continue;
                }
                if ($e->has('not_after') && ($ia > self::iv($e->get('not_after')) || self::iv($e->get('not_after')) < $now - self::RECEIPT_SKEW_MS)) {
                    continue;
                }
                if (self::suiteOf(self::m($e, 'alg')) !== self::suiteOf(self::m($r, 'alg'))) {
                    continue;
                }
                $pinned = $e->has('pq_pk');
                if (self::verifyAccReceiptSignature($r, $e->get('pk'), $pinned ? $e->get('pk') : null, $pinned ? $e->get('pq_pk') : null)) {
                    return 'valid';
                }
            }
            return $unsupported ? 'unsupported' : 'invalid';
        } catch (\Throwable) {
            return 'invalid';
        }
    }

    /** The arithmetic a receipt must satisfy for its accumulator (rule 15 step 5d). */
    public static function receiptArithmeticOk(mixed $a, Obj $r, int $val): bool
    {
        $pre = self::iv($r->get('pre'));
        $delta = self::iv($r->get('delta'));
        $post = self::iv($r->get('post'));
        return match (self::m($a, 'agg')) {
            'sum' => $delta === $val && $post === $pre + $delta,
            'count' => $delta === 1 && $post === $pre + 1,
            'max' => $delta === $val && $post === max($pre, $delta),
            'distinct' => ($delta === 0 || $delta === 1) && $post === $pre + $delta,
            default => false,
        };
    }

    // ==== rule 13 step 7: session revocation (dedicated authority, full revoked list, append-only) ======================

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    /** revset_root(L): b64u(SHA-256("pca-revset/v1\0" || canonical({size, tree}))), tree the RFC 6962 root (empty: SHA-256("")). */
    public static function revsetRoot(array $ids): string
    {
        $tree = count($ids) === 0 ? Pca::b64u(self::sha('')) : Pca::merkleRoot($ids);
        return Pca::b64u(self::sha(self::REVSET_DOMAIN . self::canonicalize(Obj::of(['size' => count($ids), 'tree' => $tree]))));
    }

    /** Strict shape of a revocation epoch (intent-revocation.ts revocationEpochShapeError). */
    public static function revocationEpochShapeError(mixed $ep): ?string
    {
        if (!($ep instanceof Obj)) {
            return 'the revocation epoch must be an object';
        }
        foreach (['instance_id', 'grant_ref', 'root', 'guardian', 'sig'] as $k) {
            if (!is_string(self::m($ep, $k))) {
                return "revocation epoch $k must be a string";
            }
        }
        foreach (['epoch', 'set_size', 'issued_at', 'not_after'] as $k) {
            if (!self::isNonNeg(self::m($ep, $k))) {
                return "revocation epoch $k must be a non-negative safe integer";
            }
        }
        if ($ep->has('guardian_epoch') && !self::isNonNeg($ep->get('guardian_epoch'))) {
            return 'revocation epoch guardian_epoch must be a non-negative safe integer';
        }
        if (($se = self::suiteError(self::m($ep, 'alg'))) !== null) {
            return "revocation epoch alg: $se";
        }
        if ($ep->has('pq_pk') && !is_string($ep->get('pq_pk'))) {
            return 'revocation epoch pq_pk must be a string';
        }
        if ($ep->has('pq_sig') && !is_string($ep->get('pq_sig'))) {
            return 'revocation epoch pq_sig must be a string';
        }
        return null;
    }

    /**
     * checkRevocationEpoch of revocation.ts over a shape-checked epoch: guardian, suite signature over
     * "atlas-pca/revepoch/v1\0" || strictCanonical(body + bound suite fields) (a PQ epoch only under the pin `$pinPq` for
     * the guardian), grant_ref, now <= not_after, issued_at <= now + 60 s. @return array{ok:bool, reason?:string}
     */
    public static function checkRevocationEpoch(Obj $ep, string $guardian, int $now, mixed $grantRef, mixed $pinPq = null): array
    {
        try {
            if ($ep->get('guardian') !== $guardian) {
                return self::bad('revocation epoch not signed by the pinned guardian');
            }
            $body = new Obj();
            foreach (['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'] as $k) {
                $body->set($k, $ep->get($k));
            }
            $alg = self::m($ep, 'alg');
            $pq = self::m($ep, 'pq_pk');
            $msg = self::REVEPOCH_DOMAIN . self::canonicalize(self::bindSuite($body, $alg, $pq));
            if (!self::verifyPinned($alg, $guardian, $pq, $msg, $ep->get('sig'), self::m($ep, 'pq_sig'),
                $pinPq !== null ? $guardian : null, $pinPq)) {
                return self::bad('revocation epoch signature invalid');
            }
            if (!self::isU($grantRef) && $ep->get('grant_ref') !== $grantRef) {
                return self::bad('revocation epoch is for a different grant');
            }
            if (!($now <= self::iv($ep->get('not_after')))) {
                return self::bad('revocation epoch expired (stale revocation root)');
            }
            if (!(self::iv($ep->get('issued_at')) <= $now + self::REVOCATION_SKEW_MS)) {
                return self::bad('revocation epoch issued in the future');
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return self::bad('revocation epoch check error');
        }
    }

    public static function sessionRevocationId(string $session): string
    {
        return 'pca-intent:session:' . $session;
    }

    public static function sessionRevocationScope(string $session): string
    {
        return 'pca-intent-session:' . $session;
    }

    /**
     * The revoked list is well-formed and is exactly what the epoch signs (intent-revocation.ts revokedListError): an array
     * of strings, strictly ascending in UTF-8 byte order, `length == set_size == epoch`, and its revset root == `root`.
     * `$ev` holds a shape-checked epoch.
     */
    private static function revokedListError(Obj $ev): ?string
    {
        $r = self::m($ev, 'revoked');
        if (!self::isList($r) || count(array_filter($r, 'is_string')) !== count($r)) {
            return 'revoked must be an array of ids';
        }
        for ($i = 1; $i < count($r); $i++) {
            if (!(self::compareUtf8($r[$i - 1], $r[$i]) < 0)) {
                return 'revoked must be sorted by UTF-8 bytes and distinct';
            }
        }
        $ep = $ev->get('epoch');
        $size = self::iv($ep->get('set_size'));
        if (count($r) !== $size || self::iv($ep->get('epoch')) !== $size) {
            return 'the epoch must be numbered by its set size and list exactly set_size ids';
        }
        if (self::revsetRoot($r) !== $ep->get('root')) {
            return 'the revoked list is not the signed set (root mismatch)';
        }
        return null;
    }

    /** The evidence is CLOSED (intent-revocation.ts closedEvidenceError): the first member, in key order, that is neither `epoch` nor `revoked`. */
    private static function closedEvidenceError(Obj $ev): ?string
    {
        foreach (self::jsKeys($ev) as $k) {
            if ($k !== 'epoch' && $k !== 'revoked') {
                return "has the unknown member '$k' (it is exactly {epoch, revoked})";
            }
        }
        return null;
    }

    /**
     * checkSessionRevocation (rule 13 step 7; intent-revocation.ts), first failure wins:
     *   a. `maxAgeMs` a safe integer >= 0, `now` a safe integer, `ids` an array, `authority` a string;
     *   b. the evidence is an object with no member but `epoch` and `revoked` (closed; so is `last`); the epoch is strictly
     *      typed and its `guardian` is the authority (a missing `revoked` fails at e);
     *   c. it verifies under the authority (a PQ epoch only under `pqPin`), `grant_ref` == the scope (`scope` ??
     *      "pca-intent-session:" + session), now <= not_after, issued_at <= now + 60 s;
     *   d. now - issued_at <= maxAgeMs;
     *   e. `revoked` is the full signed set (revokedListError);
     *   f. APPEND-ONLY when `last` (the tracked last accepted evidence) is given: itself well-formed, epoch >= last.epoch,
     *      every id of last.revoked is in revoked, epoch == last.epoch implies root == last.root;
     *   g. no id of `ids` is in `revoked`.
     * Never throws.
     * @param array{session:mixed, authority:mixed, ids:mixed, now:mixed, maxAgeMs:mixed, pqPin?:mixed, scope?:mixed, last?:mixed} $c
     *   (`pqPin` / `scope` / `last` absent = none; a `scope` of null takes the default like the reference's `??`)
     * @return array{ok:bool, reason?:string}
     */
    public static function checkSessionRevocation(mixed $ev, array $c): array
    {
        try {
            if (!self::isNonNeg($c['maxAgeMs'] ?? null)) {
                return self::bad('revocation max age misconfigured (fail closed)');
            }
            if (!self::isInt($c['now'] ?? null)) {
                return self::bad('the verifier clock is not a safe integer (fail closed)');
            }
            $now = self::iv($c['now']);
            $maxAge = self::iv($c['maxAgeMs']);
            $ids = $c['ids'] ?? null;
            $authority = $c['authority'] ?? null;
            if (!self::isList($ids) || !is_string($authority)) {
                return self::bad('ids must be an array and the authority a key');
            }
            if (!($ev instanceof Obj)) {
                return self::bad('no session revocation epoch supplied');
            }
            // the evidence is CLOSED: an extra member is malformed (a missing one fails at the epoch / revoked-list steps)
            if (($ce = self::closedEvidenceError($ev)) !== null) {
                return self::bad("the revocation evidence $ce");
            }
            $ep = self::m($ev, 'epoch');
            if (($shape = self::revocationEpochShapeError($ep)) !== null) {
                return self::bad($shape);
            }
            /** @var Obj $ep */
            if ($ep->get('guardian') !== $authority) {
                return self::bad('the revocation epoch is not signed by the session revocation authority');
            }
            $scope = array_key_exists('scope', $c) && $c['scope'] !== null && !self::isU($c['scope'])
                ? $c['scope'] : self::sessionRevocationScope(self::txt($c['session'] ?? ''));
            $pin = $c['pqPin'] ?? null;
            $r = self::checkRevocationEpoch($ep, $authority, $now, $scope, $pin);
            if (!$r['ok']) {
                return self::bad($r['reason'] ?? 'revocation epoch rejected');
            }
            if (!($now - self::iv($ep->get('issued_at')) <= $maxAge)) {
                return self::bad("the session revocation epoch is older than $maxAge ms");
            }
            if (($le = self::revokedListError($ev)) !== null) {
                return self::bad($le);
            }
            $revoked = [];
            foreach ($ev->get('revoked') as $id) {
                $revoked['k' . $id] = true;
            }
            if (array_key_exists('last', $c) && !self::isU($c['last'])) {
                $L = $c['last'];
                if (!($L instanceof Obj) || self::closedEvidenceError($L) !== null || self::revocationEpochShapeError(self::m($L, 'epoch')) !== null
                    || self::revokedListError($L) !== null) {
                    return self::bad('the tracked last epoch is malformed (fail closed)');
                }
                $le = $L->get('epoch');
                if (self::iv($ep->get('epoch')) < self::iv($le->get('epoch'))) {
                    return self::bad('revocation epoch rollback (older than the last accepted)');
                }
                foreach ($L->get('revoked') as $id) {
                    if (!isset($revoked['k' . $id])) {
                        return self::bad("the epoch drops '$id', revoked in the last accepted epoch (not append-only)");
                    }
                }
                if (self::iv($ep->get('epoch')) === self::iv($le->get('epoch')) && $ep->get('root') !== $le->get('root')) {
                    return self::bad('two different revocation sets under one epoch number (equivocation)');
                }
            }
            foreach ($ids as $id) {
                if (!is_string($id) || isset($revoked['k' . $id])) {
                    return self::bad("'" . self::txt($id) . "' is revoked");
                }
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('session revocation check error (fail closed): ' . $e->getMessage());
        }
    }
}
