<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentMapKit.php';
require_once __DIR__ . '/Ledger.php';

/**
 * The Intent Map attestation (the signer's statement that a map with this digest belongs to this intent) and the intent anchor
 * receipt (an artifact digest included under a signed head of the instance's intent log). Verification is total: any odd shape
 * is a refusal with a reason. A post-quantum suite verifies only under a key pinned for the signer (`pqPins`).
 */
final class IntentAttest
{
    public const INTENT_MAP_SIG_DOMAIN = "atlas-pca/intent-map-sig/v1\0";
    public const INTENT_ANCHOR_DOMAIN = 'atlas-pca/intent-anchor/v1';
    public const INTENT_ANCHOR_LOG = 'pca-intent:v1';
    public const INTENT_ANCHOR_KINDS = ['statement', 'map', 'observation', 'schema', 'session', 'delta', 'receipt', 'profile', 'evidence'];
    /** "No map given" for {@see verifyIntentMapAttestation} (a null map is a malformed map). */
    public const NO_MAP = "\0no-map";

    /** A JSON safe integer that is not -0. */
    private static function isInt(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0 && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function b32(mixed $v): bool
    {
        return Pca::unb64u($v, 32) !== null;
    }

    /** The value as JSON would carry it: -0 is 0 and a non-finite number is null (the reference digests the JSON round trip of the map). */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::plain($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_is_list($v) ? array_map(self::plain(...), $v) : self::plain(Obj::of($v));
        }
        if (Js::isNum($v)) {
            $f = Js::num($v);
            return !is_finite($f) ? null : ($f === 0.0 ? new Num('0') : ($v instanceof Num ? $v : Sign::n($v)));
        }
        return $v;
    }

    /** Null when `$m` is an Intent Map v1 with well-formed `intent_ref` and metrics, else the reason. */
    public static function intentMapShapeError(mixed $m): ?string
    {
        if (!($m instanceof Obj) || Js::num($m->get('v')) !== 1.0 || $m->get('kind') !== 'pca-intent-map') {
            return 'not an intent map v1';
        }
        if (!($m->has('intent_ref') && $m->get('intent_ref') === null) && !self::b32($m->get('intent_ref'))) {
            return 'intent_ref must be null or canonical base64url (32 bytes)';
        }
        $mt = $m->get('metrics');
        if (!($mt instanceof Obj)) {
            return 'metrics must be an object';
        }
        $fid = Js::num($mt->get('fidelity_est_ppm'));
        if (!self::isInt($mt->get('fidelity_est_ppm')) || $fid < 0 || $fid > 1_000_000) {
            return 'metrics.fidelity_est_ppm must be an integer in [0, 1e6]';
        }
        if (!self::isInt($mt->get('residual_risk_ppm')) || Js::num($mt->get('residual_risk_ppm')) < 0) {
            return 'metrics.residual_risk_ppm must be a non-negative integer';
        }
        return null;
    }

    private static function body(Obj $a): Obj
    {
        return Obj::of(['v' => $a->get('v'), 'map_digest' => $a->get('map_digest'), 'intent_ref' => $a->get('intent_ref'), 'signer' => $a->get('signer'), 'signed_at' => $a->get('signed_at')]);
    }

    /**
     * Sign the attestation `{v, map_digest, intent_ref, signer, signed_at}` of an Intent Map (`$signedAt` in epoch ms). Throws for a
     * malformed map or time.
     */
    public static function signIntentMapAttestation(mixed $map, KeyPair $signer, mixed $signedAt, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $m = is_array($map) && $map !== [] && !array_is_list($map) ? Sign::n($map) : $map;
        $bad = self::intentMapShapeError($m);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signIntentMapAttestation: $bad");
        }
        if (!self::isInt($signedAt) || Js::num($signedAt) < 0) {
            throw new \InvalidArgumentException('signIntentMapAttestation: signedAt must be a non-negative safe integer');
        }
        $body = Obj::of(['v' => new Num('1'), 'map_digest' => IntentMapKit::intentMapDigest(self::plain($m)), 'intent_ref' => $m->get('intent_ref'),
            'signer' => $signer->public, 'signed_at' => Sign::n($signedAt)]);
        return Sign::signArtifact(self::INTENT_MAP_SIG_DOMAIN, $body, $signer, $alg, $pq);
    }

    /**
     * Verify an attestation: shape, the expected signer (`$opts['expectedSigner']`), the suite fields, the map it is about (when
     * `$map` is given: its shape, digest and intent_ref) and the signature (a PQ suite only under `$opts['pqPins'][signer]`).
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyIntentMapAttestation(mixed $a, mixed $map = self::NO_MAP, mixed $opts = null): array
    {
        $no = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!($a instanceof Obj) || Js::num($a->get('v')) !== 1.0) {
                return $no('not an intent map attestation v1');
            }
            if (!self::b32($a->get('map_digest'))) {
                return $no('map_digest is not canonical base64url (32 bytes)');
            }
            if (!($a->has('intent_ref') && $a->get('intent_ref') === null) && !self::b32($a->get('intent_ref'))) {
                return $no('intent_ref must be null or canonical base64url (32 bytes)');
            }
            if (!self::b32($a->get('signer'))) {
                return $no('signer is not canonical base64url (32 bytes)');
            }
            if (!self::isInt($a->get('signed_at')) || Js::num($a->get('signed_at')) < 0) {
                return $no('signed_at must be a non-negative safe integer');
            }
            $signer = (string) $a->get('signer');
            if (Js::has($opts, 'expectedSigner') && $signer !== Js::opt($opts, 'expectedSigner')) {
                return $no('signer mismatch');
            }
            $alg = $a->has('alg') ? $a->get('alg') : 'ed25519';
            if (!is_string($alg) || !in_array($alg, Pca::REGISTERED_SUITES, true)) {
                return $no('unknown signature suite');
            }
            if ($alg === 'ed25519' && ($a->has('pq_pk') || $a->has('pq_sig'))) {
                return $no('an ed25519 artifact must not carry pq_pk / pq_sig');
            }
            if ($map !== self::NO_MAP) {
                $bad = self::intentMapShapeError($map);
                if ($bad !== null) {
                    return $no($bad);
                }
                if (IntentMapKit::intentMapDigest(self::plain($map)) !== $a->get('map_digest')) {
                    return $no('map digest mismatch');
                }
                if ($map->get('intent_ref') !== $a->get('intent_ref')) {
                    return $no('intent_ref mismatch');
                }
            }
            $body = self::body($a);
            if ($alg !== 'ed25519') {
                if (!$a->has('pq_pk')) {
                    throw new \InvalidArgumentException('pq_pk is missing');
                }
                $body->set('alg', $alg);
                $body->set('pq_pk', $a->get('pq_pk'));
            }
            $pins = Js::opt($opts, 'pqPins');
            $pin = Js::has($pins, $signer) ? (is_string(Js::opt($pins, $signer)) ? Js::opt($pins, $signer) : "\0\0not-a-string") : null;
            $ok = Pca::verifyPinnedSuite($a->has('alg') ? $alg : null, $signer, $a->has('pq_pk') ? $a->get('pq_pk') : null,
                self::INTENT_MAP_SIG_DOMAIN . Json::canonicalizeNative($body), $a->has('sig') ? $a->get('sig') : null, $a->has('pq_sig') ? $a->get('pq_sig') : null, $pin);
            return $ok === true ? ['ok' => true] : $no('bad signature');
        } catch (\Throwable $e) {
            return $no('malformed intent map attestation: ' . $e->getMessage());
        }
    }

    /** The leaf an artifact of `$kind` with content address `$digest` has in the intent log. */
    public static function intentAnchorCommit(mixed $kind, mixed $digest): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_ANCHOR_DOMAIN, 'kind' => $kind, 'digest' => $digest]));
    }

    /**
     * Verify an anchor receipt `{kind, digest, index, proof, signed_tree_head}`: a known kind, a 32-byte digest, a head of this
     * instance's intent log signed by `$guardianPublic` (a PQ suite only under `$pin['pqPins'][guardian]`), a proof for that head
     * and index, and the artifact's leaf included under the head.
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyIntentAnchor(mixed $r, mixed $guardianPublic, mixed $instanceId, mixed $pin = null): array
    {
        $no = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!in_array(Js::get($r, 'kind'), self::INTENT_ANCHOR_KINDS, true)) {
                return $no('unknown anchor kind');
            }
            if (!self::b32(Js::opt($r, 'digest'))) {
                return $no('digest is not canonical base64url (32 bytes)');
            }
            $h = Js::opt($r, 'signed_tree_head');
            if ($h === null) {
                throw new \TypeError('the receipt has no signed tree head');
            }
            if (Js::opt($h, 'principal') !== self::INTENT_ANCHOR_LOG || Js::opt($h, 'instance_id') !== $instanceId) {
                return $no('not a head of this instance intent log');
            }
            if (!Ledger::verifyTreeHead($h, $guardianPublic, null, Js::opt($pin, 'pqPins'))) {
                return $no('tree head signature invalid');
            }
            $proof = Js::opt($r, 'proof');
            if ($proof === null) {
                throw new \TypeError('the receipt has no proof');
            }
            $eq = static fn(mixed $x, mixed $y): bool => Js::isNum($x) && Js::isNum($y) ? Js::num($x) === Js::num($y) : (!Js::isNum($x) && !Js::isNum($y) && $x === $y);
            if (!$eq(Js::opt($proof, 'index'), Js::opt($r, 'index')) || !$eq(Js::opt($proof, 'size'), Js::opt($h, 'size'))) {
                return $no('proof does not match the head');
            }
            if (!Ledger::verifyInclusion(Js::opt($h, 'root'), $proof, self::intentAnchorCommit(Js::opt($r, 'kind'), Js::opt($r, 'digest')))) {
                return $no('artifact is not included under the signed head');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return $no('malformed anchor receipt: ' . $e->getMessage());
        }
    }
}
