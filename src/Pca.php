<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Mldsa.php';

/**
 * Verifier for the CORE PCActn checks, wire format v2 (strict): wire, version, audience, validity, chain,
 * plan_inclusion, leaf_signature, counter. Values are Json::parse* trees (Obj / list / string / Num / bool / null).
 */
final class Pca
{
    public const SIG_DOMAIN = "atlas-pca/actn/v2\0";
    public const CAP_DOMAIN = "atlas-pca/cap/v1\0";
    public const DEFAULT_REV = 'reversible';
    public const MAX_CHAIN = 16;
    public const MAX_LIFETIME_MS = 3600000;
    public const MAX_SKEW_MS = 60000;
    public const MAX_AUD_LEN = 256;
    public const MAX_NONCE_LEN = 128;

    private const REQUIRED = ['ver', 'action', 'grant_ref', 'cap_chain', 'plan', 'attestation', 'provenance',
        'freshness', 'counter', 'risk_claim', 'aud', 'iat', 'exp', 'sig'];
    private const OPTIONAL = ['nonce', 'caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence',
        'tool_binding', 'threshold', 'zk_compliance', 'bond_ref',
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        'alg', 'pq_pk', 'pq_sig'];

    // B4 post-quantum suites (mirrors packages/pca/src/pq.ts). alg name => [sig bytes, needs pq_pk, needs pq_sig].
    public const ED25519_SIGNATURE_BYTES = 64;
    private const SIG_SUITES = [
        'ed25519' => [self::ED25519_SIGNATURE_BYTES, false, false],
        'ml-dsa-65' => [Mldsa::SIGNATURE_BYTES, true, false],
        'hybrid-ed25519-ml-dsa-65' => [self::ED25519_SIGNATURE_BYTES, true, true],
    ];

    // ---- helpers ------------------------------------------------------------------------

    public static function b64u(string $raw): string
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Strict base64url (RFC 4648 s5, no padding, alphabet only, len%4 != 1, zero trailing bits, optional exact
     * decoded byte length). Null when invalid.
     */
    public static function unb64u(mixed $s, ?int $len = null): ?string
    {
        if (!is_string($s) || preg_match('/\A[A-Za-z0-9_-]*\z/D', $s) !== 1 || strlen($s) % 4 === 1) {
            return null;
        }
        if ($len !== null && strlen($s) !== (int)ceil($len * 4 / 3)) {
            return null;
        }
        try {
            $raw = sodium_base642bin($s, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\Throwable) {
            return null;
        }
        if (self::b64u($raw) !== $s || ($len !== null && strlen($raw) !== $len)) {
            return null;
        }
        return $raw;
    }

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    public static function hashCanonical(mixed $v): string
    {
        return self::b64u(self::sha(Json::canonicalizeStrict($v)));
    }

    private static function get(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj && $o->has($k);
    }

    private static function isInt(mixed $v): bool
    {
        return $v instanceof Num && $v->isInt() && $v->strictError() === null;
    }

    private static function isNum(mixed $v): bool
    {
        return $v instanceof Num && $v->strictError() === null;
    }

    // ---- Merkle -------------------------------------------------------------------------

    private static function leafHash(mixed $leaf): string
    {
        return self::sha("\x00" . Json::canonicalizeStrict($leaf));
    }

    private static function nodeHash(string $l, string $r): string
    {
        return self::sha("\x01" . $l . $r);
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    private static function build(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = self::split(count($hs));
        return self::nodeHash(self::build(array_slice($hs, 0, $k)), self::build(array_slice($hs, $k)));
    }

    public static function merkleRoot(array $leaves): string
    {
        if (count($leaves) === 0) {
            throw new \InvalidArgumentException('empty leaf set');
        }
        return self::b64u(self::build(array_map([self::class, 'leafHash'], array_values($leaves))));
    }

    /** Sibling sides (leaf -> root) determined by index/size (RFC 6962 split). */
    private static function pathShape(int $index, int $size): array
    {
        $out = [];
        $idx = $index;
        $n = $size;
        while ($n > 1) {
            $k = self::split($n);
            if ($idx < $k) {
                $out[] = 'R';
                $n = $k;
            } else {
                $out[] = 'L';
                $idx -= $k;
                $n -= $k;
            }
        }
        return array_reverse($out);
    }

    /** Never throws; malformed proofs return false. Index/size are bound to the path shape. */
    public static function verifyInclusion(string $root, mixed $proof, mixed $leaf): bool
    {
        try {
            $path = self::get($proof, 'path');
            if (!is_array($path) || !array_is_list($path)) {
                return false;
            }
            $index = self::get($proof, 'index');
            $size = self::get($proof, 'size');
            if (!self::isInt($index) || !self::isInt($size)) {
                return false;
            }
            $index = $index->int();
            $size = $size->int();
            if ($size < 1 || $index < 0 || $index >= $size) {
                return false;
            }
            $shape = self::pathShape($index, $size);
            if (count($shape) !== count($path)) {
                return false;
            }
            $h = self::leafHash($leaf);
            foreach ($path as $i => $step) {
                if (!($step instanceof Obj) || self::get($step, 'side') !== $shape[$i]) {
                    return false;
                }
                $sib = self::unb64u(self::get($step, 'hash'), 32);
                if ($sib === null) {
                    return false;
                }
                $h = $shape[$i] === 'L' ? self::nodeHash($sib, $h) : self::nodeHash($h, $sib);
            }
            return self::b64u($h) === $root;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function paramsDigest(mixed $params = null): string
    {
        return self::hashCanonical($params ?? new Obj());
    }

    private static function conditionsDigest(mixed $pre, mixed $post): string
    {
        return self::hashCanonical(Obj::of(['pre' => $pre, 'post' => $post]));
    }

    private static function planLeaf(mixed $nodeId, mixed $action, string $cond): Obj
    {
        $pd = self::get($action, 'params_digest') ?? self::paramsDigest();
        $rc = self::get($action, 'reversibility_class') ?? self::DEFAULT_REV;
        return Obj::of([
            'node_id' => $nodeId, 'verb' => self::get($action, 'verb'), 'resource' => self::get($action, 'resource'),
            'params_digest' => $pd, 'reversibility_class' => $rc, 'conditions' => $cond,
        ]);
    }

    // ---- Ed25519 (strict RFC 8032) -----------------------------------------------------

    /**
     * True iff the 32-byte encoding is a point of the PRIME-ORDER subgroup (rejects small-order, mixed-order /
     * torsioned and off-curve points). PHP exposes no raw Ed25519 scalar-mult, but libsodium's
     * crypto_sign_ed25519_pk_to_curve25519 refuses exactly: small-order points, undecodable points, and any
     * point not on the main subgroup.
     */
    private static function primeOrderPoint(string $p): bool
    {
        try {
            return strlen(sodium_crypto_sign_ed25519_pk_to_curve25519($p)) === 32;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function verifyB64u(mixed $pub, string $msg, mixed $sig): bool
    {
        $pk = self::unb64u($pub, 32);
        $sg = self::unb64u($sig, 64);
        if ($pk === null || $sg === null) {
            return false;
        }
        if (!self::primeOrderPoint($pk) || !self::primeOrderPoint(substr($sg, 0, 32))) {
            return false;
        }
        try {
            // libsodium additionally rejects non-canonical S (S >= L) and small-order/non-canonical A
            return sodium_crypto_sign_verify_detached($sg, $msg, $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- B4 crypto-agility: suite resolution, wire validation, leaf seam -----------------

    /** @return array{0:?string,1:?string} [suite name (null = fail-closed), error reason] */
    private static function resolveSuite(Obj $p): array
    {
        if (!$p->has('alg')) {
            return ['ed25519', null];
        }
        $alg = $p->get('alg');
        if (!is_string($alg)) {
            return [null, "'alg' must be a string"];
        }
        if (!isset(self::SIG_SUITES[$alg])) {
            return [null, "unknown signature alg '$alg'"];
        }
        return [$alg, null];
    }

    /** Validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. null when well-formed, else a short reason. */
    private static function validateSignatureWire(Obj $p): ?string
    {
        [$suite, $err] = self::resolveSuite($p);
        if ($suite === null) {
            return $err;
        }
        [$sigBytes, $needsPk, $needsSig] = self::SIG_SUITES[$suite];
        if (!self::b($p->get('sig'), $sigBytes)) {
            return "'sig' is not canonical base64url ($sigBytes bytes) for alg '$suite'";
        }
        if ($needsPk) {
            if (!self::b($p->get('pq_pk'), Mldsa::PUBLIC_KEY_BYTES)) {
                return "'pq_pk' is not canonical base64url (" . Mldsa::PUBLIC_KEY_BYTES . ' bytes)';
            }
        } elseif ($p->has('pq_pk')) {
            return "'pq_pk' must be absent for alg '$suite'";
        }
        if ($needsSig) {
            if (!self::b($p->get('pq_sig'), Mldsa::SIGNATURE_BYTES)) {
                return "'pq_sig' is not canonical base64url (" . Mldsa::SIGNATURE_BYTES . ' bytes)';
            }
        } elseif ($p->has('pq_sig')) {
            return "'pq_sig' must be absent for alg '$suite'";
        }
        return null;
    }

    private static function mldsaVerifyB64u(mixed $pk, string $msg, mixed $sig): bool
    {
        $pkRaw = self::unb64u($pk, Mldsa::PUBLIC_KEY_BYTES);
        $sgRaw = self::unb64u($sig, Mldsa::SIGNATURE_BYTES);
        if ($pkRaw === null || $sgRaw === null) {
            return false;
        }
        return Mldsa::verify($pkRaw, $msg, $sgRaw);
    }

    /** Verify the leaf signature under the PCActn's suite. FAIL-CLOSED. */
    private static function verifyLeafSuite(Obj $p, mixed $holder, string $msg): bool
    {
        [$suite] = self::resolveSuite($p);
        if ($suite === null) {
            return false;
        }
        $sig = $p->get('sig');
        return match ($suite) {
            'ed25519' => self::verifyB64u($holder, $msg, $sig),
            'ml-dsa-65' => self::mldsaVerifyB64u($p->get('pq_pk'), $msg, $sig),
            'hybrid-ed25519-ml-dsa-65' =>
                self::verifyB64u($holder, $msg, $sig) && self::mldsaVerifyB64u($p->get('pq_pk'), $msg, $p->get('pq_sig')),
            default => false,
        };
    }

    // ---- capability chain ---------------------------------------------------------------

    public static function capHash(mixed $c): string
    {
        return self::hashCanonical($c);
    }

    private static function bodyOf(Obj $c): Obj
    {
        return Obj::of([
            'issuer' => $c->get('issuer'), 'holder' => $c->get('holder'),
            'caveats' => $c->get('caveats'), 'parent' => $c->get('parent'),
        ]);
    }

    /**
     * bodyOf + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
     * key-swap breaks the hop digest), byte-identical to bodyOf for ed25519. Mirrors signableBody in
     * capability.ts.
     * @return array{0:?Obj,1:?string} [body (null => unknown alg, fail-closed), error reason]
     */
    private static function signableHopBody(Obj $c): array
    {
        [$suite, $err] = self::resolveSuite($c);
        if ($suite === null) {
            return [null, $err];
        }
        $body = self::bodyOf($c);
        if ($suite !== 'ed25519') {
            $body->set('alg', $suite);
            [, $needsPk] = self::SIG_SUITES[$suite];
            if ($needsPk && is_string($c->get('pq_pk'))) {
                $body->set('pq_pk', $c->get('pq_pk'));
            }
        }
        return [$body, null];
    }

    private static function checkSig(Obj $c, mixed $signer, string $label): string
    {
        // Unknown suite => fail-closed (before any hashing), mirroring capability.ts checkSig.
        [$body, $err] = self::signableHopBody($c);
        if ($body === null) {
            return "$label: $err";
        }
        $digest = self::hashCanonical($body);
        $bd = $c->get('body_digest');
        $id = $c->get('id');
        if (!is_string($bd) || $digest !== $bd || $id !== $bd) {
            return $label . ': body digest mismatch';
        }
        $d = self::unb64u($bd, 32);
        // Suite-agile hop verification: ed25519 == verifyB64u(signer, msg, sig); hybrid requires BOTH the
        // Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`); pure ml-dsa-65 verifies
        // `sig` under `pq_pk`. verifyLeafSuite dispatches on the hop's `alg` (signer = expected Ed25519 key).
        if ($d === null || !self::verifyLeafSuite($c, $signer, self::CAP_DOMAIN . $d)) {
            return $label . ': bad signature (not signed by expected key)';
        }
        return '';
    }

    /** @return array{0:string,1:bool} [reason, ok] */
    public static function verifyChain(array $chain, mixed $expectedRootIssuer, bool $haveIssuer): array
    {
        if (count($chain) === 0) {
            return ['empty chain', false];
        }
        if (count($chain) > self::MAX_CHAIN) { // before any signature work
            return ['chain too long', false];
        }
        foreach ($chain as $i => $c) {
            if (!($c instanceof Obj) || !is_array($c->get('caveats'))) {
                return ["hop $i: malformed capability", false];
            }
        }
        $root = $chain[0];
        if ($root->has('parent')) {
            return ['hop 0: root must not have a parent', false];
        }
        if ($haveIssuer && $root->get('issuer') !== $expectedRootIssuer) {
            return ['hop 0: root issuer is not the expected principal', false];
        }
        if (($e = self::checkSig($root, $root->get('issuer'), 'hop 0')) !== '') {
            return [$e, false];
        }
        for ($i = 1; $i < count($chain); $i++) {
            $parent = $chain[$i - 1];
            $c = $chain[$i];
            $label = "hop $i";
            if ($c->get('parent') !== self::capHash($parent)) {
                return [$label . ': broken parent link', false];
            }
            if ($c->get('issuer') !== $parent->get('holder')) {
                return [$label . ': issuer is not the parent\'s bound holder', false];
            }
            if (($e = self::checkSig($c, $parent->get('holder'), $label)) !== '') {
                return [$e, false];
            }
            $pc = $parent->get('caveats');
            $cc = $c->get('caveats');
            if (count($cc) < count($pc)) {
                return [$label . ': drops parent caveat(s)', false];
            }
            foreach ($pc as $j => $pcv) {
                if (self::hashCanonical($cc[$j]) !== self::hashCanonical($pcv)) {
                    return ["$label: caveat $j altered or reordered", false];
                }
            }
        }
        return ['', true];
    }

    // ---- wire format v2 -----------------------------------------------------------------

    private static function b(mixed $v, int $len): bool
    {
        return self::unb64u($v, $len) !== null;
    }

    private static function closed(Obj $o, array $allowed): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        return true;
    }

    /** null when well-formed, else a short reason. Never throws. */
    public static function validateWire(mixed $p): ?string
    {
        try {
            if (!($p instanceof Obj)) {
                return 'PCActn is not an object';
            }
            foreach ($p->keys() as $k) {
                if (!in_array($k, self::REQUIRED, true) && !in_array($k, self::OPTIONAL, true)) {
                    return "unknown field '$k'";
                }
            }
            foreach (self::REQUIRED as $k) {
                if (!$p->has($k)) {
                    return "missing field '$k'";
                }
            }
            try {
                Json::canonicalizeStrict($p->without('sig', 'threshold', 'pq_sig'));
            } catch (JsonError $e) {
                return $e->getMessage();
            }
            foreach (['ver', 'counter', 'iat', 'exp'] as $k) {
                if (!self::isInt($p->get($k))) {
                    return "'$k' must be a safe integer";
                }
            }
            $aud = $p->get('aud');
            if (!is_string($aud) || $aud === '' || strlen($aud) > self::MAX_AUD_LEN) {
                return "'aud' must be a non-empty string";
            }
            if ($p->has('nonce')) {
                $n = $p->get('nonce');
                if (!is_string($n) || $n === '' || strlen($n) > self::MAX_NONCE_LEN) {
                    return "'nonce' must be a non-empty string";
                }
            }
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (absent `alg` == classical 64-byte sig).
            $sigErr = self::validateSignatureWire($p);
            if ($sigErr !== null) {
                return $sigErr;
            }
            if (!self::b($p->get('grant_ref'), 32)) {
                return "'grant_ref' is not canonical base64url (32 bytes)";
            }

            $a = $p->get('action');
            if (!($a instanceof Obj)) {
                return "'action' must be an object";
            }
            if (!self::closed($a, ['verb', 'resource', 'params_digest', 'reversibility_class'])) {
                return 'unknown field in action';
            }
            foreach (['verb', 'resource', 'reversibility_class'] as $k) {
                if (!is_string($a->get($k))) {
                    return 'action.verb/resource/reversibility_class must be strings';
                }
            }
            if (!self::b($a->get('params_digest'), 32)) {
                return "'action.params_digest' is not canonical base64url (32 bytes)";
            }

            $pl = $p->get('plan');
            if (!($pl instanceof Obj)) {
                return "'plan' must be an object";
            }
            if (!self::closed($pl, ['root', 'inclusion_proof', 'node_id', 'conditions_digest'])) {
                return 'unknown field in plan';
            }
            if (!self::b($pl->get('root'), 32)) {
                return "'plan.root' is not canonical base64url (32 bytes)";
            }
            if (!is_string($pl->get('node_id'))) {
                return "'plan.node_id' must be a string";
            }
            if ($pl->has('conditions_digest') && !self::b($pl->get('conditions_digest'), 32)) {
                return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)";
            }
            $ip = $pl->get('inclusion_proof');
            if (!($ip instanceof Obj)) {
                return "'plan.inclusion_proof' must be an object";
            }
            if (!self::closed($ip, ['index', 'size', 'path'])) {
                return 'unknown field in plan.inclusion_proof';
            }
            if (!self::isInt($ip->get('index')) || !self::isInt($ip->get('size'))) {
                return "'plan.inclusion_proof.index/size' must be safe integers";
            }
            $path = $ip->get('path');
            if (!is_array($path)) {
                return "'plan.inclusion_proof.path' must be an array";
            }
            foreach ($path as $i => $st) {
                if (!($st instanceof Obj)) {
                    return "proof step $i must be an object";
                }
                if (!self::closed($st, ['side', 'hash'])) {
                    return "unknown field in path[$i]";
                }
                if ($st->get('side') !== 'L' && $st->get('side') !== 'R') {
                    return "proof step $i: side must be 'L' or 'R'";
                }
                if (!self::b($st->get('hash'), 32)) {
                    return "proof step $i: hash is not canonical base64url (32 bytes)";
                }
            }

            $chain = $p->get('cap_chain');
            if (!is_array($chain)) {
                return "'cap_chain' must be an array";
            }
            foreach ($chain as $i => $c) {
                if (!($c instanceof Obj)) {
                    return "cap_chain[$i] must be an object";
                }
                if (!self::closed($c, ['id', 'issuer', 'holder', 'body_digest', 'caveats', 'sig', 'parent', 'alg', 'pq_pk', 'pq_sig'])) {
                    return "unknown field in cap_chain[$i]";
                }
                foreach (['id', 'issuer', 'holder', 'body_digest'] as $k) {
                    if (!self::b($c->get($k), 32)) {
                        return "cap_chain[$i].$k is not canonical base64url (32 bytes)";
                    }
                }
                // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the
                // leaf. Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical).
                $hopSigErr = self::validateSignatureWire($c);
                if ($hopSigErr !== null) {
                    return "cap_chain[$i]: $hopSigErr";
                }
                if ($c->has('parent') && !self::b($c->get('parent'), 32)) {
                    return "cap_chain[$i].parent is not canonical base64url (32 bytes)";
                }
                $cv = $c->get('caveats');
                if (!is_array($cv)) {
                    return "cap_chain[$i].caveats must be an array of {type,...} objects";
                }
                foreach ($cv as $x) {
                    if (!($x instanceof Obj) || !is_string($x->get('type'))) {
                        return "cap_chain[$i].caveats must be an array of {type,...} objects";
                    }
                }
            }

            $at = $p->get('attestation');
            if (!($at instanceof Obj) || !self::isInt($at->get('epoch'))) {
                return "'attestation' must be an object with an integer 'epoch'";
            }
            foreach (['quote_digest', 'model_id', 'measurement', 'operator'] as $k) {
                if (!is_string($at->get($k))) {
                    return 'attestation string fields must be strings';
                }
            }
            $pv = $p->get('provenance');
            if (!($pv instanceof Obj) || !is_string($pv->get('causal_hash')) || !self::isNum($pv->get('taint_level'))
                || !is_array($pv->get('trusted_refs'))) {
                return "'provenance' is malformed";
            }
            foreach ($pv->get('trusted_refs') as $r) {
                if (!is_string($r)) {
                    return "'provenance' is malformed";
                }
            }
            $fr = $p->get('freshness');
            if (!($fr instanceof Obj) || !self::isInt($fr->get('epoch')) || !is_string($fr->get('beacon_ref'))
                || !is_string($fr->get('accumulator_witness'))) {
                return "'freshness' is malformed";
            }
            $rc = $p->get('risk_claim');
            if (!($rc instanceof Obj) || !self::isNum($rc->get('r')) || !($rc->get('inputs') instanceof Obj)) {
                return "'risk_claim' is malformed";
            }

            if ($p->has('caution')) {
                $c = $p->get('caution');
                if (!self::isNum($c) || $c->float() < 0 || $c->float() > 1) {
                    return "'caution' must be a number in [0,1]";
                }
            }
            foreach (['rationale_commitment', 'tool_binding'] as $k) {
                if ($p->has($k) && !self::b($p->get($k), 32)) {
                    return "'$k' is not canonical base64url (32 bytes)";
                }
            }
            if ($p->has('progress_step') && !($p->get('progress_step') instanceof Obj)) {
                return "'progress_step' must be an object";
            }
            if ($p->has('prohibition_evidence')) {
                $pe = $p->get('prohibition_evidence');
                if (!($pe instanceof Obj) && !is_array($pe)) {
                    return "'prohibition_evidence' must be an object or array";
                }
            }
            if ($p->has('threshold')) {
                $th = $p->get('threshold');
                if (!($th instanceof Obj) || !is_array($th->get('shares'))) {
                    return "'threshold' must be {shares:[...]}";
                }
                foreach ($th->get('shares') as $i => $s) {
                    if (!($s instanceof Obj) || !is_string($s->get('role'))) {
                        return "threshold.shares[$i] is malformed";
                    }
                    if (!self::b($s->get('publicKey'), 32) || !self::b($s->get('sig'), 64)) {
                        return "threshold.shares[$i] has a non-canonical key/signature";
                    }
                }
            }
            return null;
        } catch (\Throwable $e) {
            return 'malformed: ' . $e->getMessage();
        }
    }

    // ---- PCActn -------------------------------------------------------------------------

    /** SIG_DOMAIN || sha256(strictCanonical(pcactn without `sig` and `threshold`)). */
    public static function thresholdMessage(Obj $p): string
    {
        // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
        return self::SIG_DOMAIN . self::sha(Json::canonicalizeStrict($p->without('sig', 'threshold', 'pq_sig')));
    }

    /**
     * Verify a signed PCActn supplied as RAW JSON text (strict profile first; a parse failure is a wire failure).
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     */
    public static function verifyJson(string $text, mixed $grant, int $now, string $audience): array
    {
        try {
            $p = Json::parseStrict($text, true);
        } catch (JsonError $e) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . $e->getMessage()];
        }
        return self::verifyPcactnCore($p, $grant, $now, $audience);
    }

    /**
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     * A wire failure is terminal: checks == ['wire' => false].
     */
    public static function verifyPcactnCore(mixed $p, mixed $grant, int $now, string $audience): array
    {
        $wire = self::validateWire($p);
        if ($wire !== null) {
            return ['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . $wire];
        }
        $checks = ['wire' => true, 'version' => false, 'audience' => false, 'validity' => false, 'chain' => false,
            'plan_inclusion' => false, 'leaf_signature' => false, 'counter' => false];
        $reason = '';
        $fail = function (string $name, string $why) use (&$reason): void {
            if ($reason === '') {
                $reason = $name . ': ' . $why;
            }
        };
        /** @var Obj $p */
        $ver = $p->get('ver')->int();
        $iat = $p->get('iat')->int();
        $exp = $p->get('exp')->int();

        if ($ver === 2) {
            $checks['version'] = true;
        } else {
            $fail('version', "unsupported ver $ver");
        }
        if ($p->get('aud') === $audience) {
            $checks['audience'] = true;
        } else {
            $fail('audience', 'aud does not match this verifier');
        }
        if (!($exp > $iat)) {
            $fail('validity', 'exp must be greater than iat');
        } elseif ($exp - $iat > self::MAX_LIFETIME_MS) {
            $fail('validity', 'lifetime too long');
        } elseif ($iat > $now + self::MAX_SKEW_MS) {
            $fail('validity', 'iat is in the future');
        } elseif ($now > $exp) {
            $fail('validity', 'expired');
        } else {
            $checks['validity'] = true;
        }

        $chain = $p->get('cap_chain');
        try {
            if (count($chain) === 0) {
                $fail('chain', 'empty chain');
            } elseif (count($chain) > self::MAX_CHAIN) {
                $fail('chain', 'chain too long');
            } elseif (self::capHash($chain[0]) !== self::capHash($grant)) {
                $fail('chain', 'chain root is not the grant');
            } else {
                $gi = self::get($grant, 'issuer');
                [$why, $ok] = self::verifyChain($chain, $gi, is_string($gi));
                if ($ok) {
                    $checks['chain'] = true;
                } else {
                    $fail('chain', $why);
                }
            }
        } catch (\Throwable $e) {
            $fail('chain', 'malformed: ' . $e->getMessage());
        }

        try {
            $plan = $p->get('plan');
            $cond = $plan->has('conditions_digest') ? $plan->get('conditions_digest') : self::conditionsDigest(null, null);
            $leaf = self::planLeaf($plan->get('node_id'), $p->get('action'), $cond);
            if (self::verifyInclusion($plan->get('root'), $plan->get('inclusion_proof'), $leaf)) {
                $checks['plan_inclusion'] = true;
            } else {
                $fail('plan_inclusion', 'action is not a node of the committed plan');
            }
        } catch (\Throwable $e) {
            $fail('plan_inclusion', 'malformed: ' . $e->getMessage());
        }

        try {
            if (count($chain) > 0
                && self::verifyLeafSuite($p, $chain[count($chain) - 1]->get('holder'), self::thresholdMessage($p))) {
                $checks['leaf_signature'] = true;
            } else {
                $fail('leaf_signature', 'signature does not verify under the leaf holder key');
            }
        } catch (\Throwable $e) {
            $fail('leaf_signature', 'malformed: ' . $e->getMessage());
        }

        if ($p->get('counter')->int() >= 0) {
            $checks['counter'] = true;
        } else {
            $fail('counter', 'not a non-negative safe integer');
        }

        return ['allow' => !in_array(false, $checks, true), 'checks' => $checks, 'reason' => $reason];
    }

    // ---- suite introspection (for suite-aware conformance driving) ----------------------

    public const SIGNERSET_DOMAIN = "atlas-pca/signerset/v1\0";
    public const SHARE_DOMAIN_PREFIX = 'atlas-pca/share/';

    /** The signature suites wired into this verifier (ed25519 + the ML-DSA cross-impl suites via OpenSSL FFI). */
    public static function supportedSuites(): array
    {
        return array_keys(self::SIG_SUITES);
    }

    /** True iff a genuine signature verdict under `$alg` is available (ML-DSA suites need OpenSSL >= 3.5). */
    public static function suiteAvailable(string $alg): bool
    {
        if (!isset(self::SIG_SUITES[$alg])) {
            return false;
        }
        [, $needsPk, $needsSig] = self::SIG_SUITES[$alg];
        return ($needsPk || $needsSig) ? Mldsa::available() : true;
    }

    // ---- v2.1 threshold-share binding ----------------------------------------------------

    /**
     * signerSetHash = sha256(SIGNERSET_DOMAIN || canonical(sort_by(role, publicKey)[{publicKey, role}])).
     * Returns the raw 32-byte digest, or null (fail-closed) when the set is malformed.
     */
    public static function signerSetHashRaw(mixed $signerSet): ?string
    {
        if (!is_array($signerSet) || !array_is_list($signerSet)) {
            return null;
        }
        $entries = [];
        foreach ($signerSet as $e) {
            if (!($e instanceof Obj)) {
                return null;
            }
            $role = $e->get('role');
            $pk = $e->get('publicKey');
            if (!is_string($role) || self::unb64u($pk, 32) === null) {
                return null;
            }
            $entries[] = [$role, $pk];
        }
        usort($entries, fn($a, $b) => $a[0] !== $b[0] ? strcmp($a[0], $b[0]) : strcmp($a[1], $b[1]));
        $list = array_map(fn($x) => Obj::of(['publicKey' => $x[1], 'role' => $x[0]]), $entries);
        return self::sha(self::SIGNERSET_DOMAIN . Json::canonicalizeStrict($list));
    }

    /**
     * Verify a threshold share against the v2.1 role/signerSetHash/t-bound share message:
     *   "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte)
     * where `signerSetHash` and `sha256(thresholdMessage)` are RECOMPUTED here (never trusted from the vector).
     * The pre-v2.1 bare-threshold-message agent share and any cross-signer-set replay therefore fail-closed.
     * FAIL-CLOSED: any missing/malformed field returns false. Corpus shares are Ed25519 (64-byte `sig`,
     * 32-byte `publicKey`); a share carrying a PQ `alg` routes through the same suite seam as the leaf.
     */
    public static function verifyThresholdShare(mixed $s): bool
    {
        try {
            if (!($s instanceof Obj)) {
                return false;
            }
            $role = $s->get('role');
            if (!is_string($role) || $role === '') {
                return false;
            }
            $t = $s->get('t');
            if (!self::isInt($t)) {
                return false;
            }
            $tv = $t->int();
            if ($tv < 1 || $tv > 3) {
                return false;
            }
            $ssh = self::signerSetHashRaw($s->get('signer_set'));
            if ($ssh === null) {
                return false;
            }
            $tmsg = self::unb64u($s->get('threshold_message'));
            if ($tmsg === null) {
                return false;
            }
            $share = $s->get('share');
            if (!($share instanceof Obj)) {
                return false;
            }
            $message = self::SHARE_DOMAIN_PREFIX . $role . "\0" . self::sha($tmsg) . $ssh . chr($tv);
            $alg = $share->has('alg') ? $share->get('alg') : 'ed25519';
            if ($alg === 'ed25519') {
                return self::verifyB64u($share->get('publicKey'), $message, $share->get('sig'));
            }
            // PQ-suite share (not exercised by the current corpus): reuse the leaf seam, fail-closed on unknown.
            return self::verifyLeafSuite($share, $share->get('publicKey'), $message);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- non-leaf PQ artifacts (transparency / authority surfaces) ------------------------

    /**
     * Verify a `primitives.pq_artifact[]` signature over the raw `$message` bytes under the artifact's suite
     * (`alg`), via the SAME agility seam as the leaf: Ed25519 under `ed_pub`, ML-DSA under `pq_pk`, hybrid
     * requires BOTH. FAIL-CLOSED: unknown suite / malformed input returns false.
     */
    public static function verifyArtifact(mixed $a, string $message): bool
    {
        try {
            if (!($a instanceof Obj)) {
                return false;
            }
            return self::verifyLeafSuite($a, $a->get('ed_pub'), $message);
        } catch (\Throwable) {
            return false;
        }
    }
}
