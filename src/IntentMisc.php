<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/SemanticThreshold.php';
require_once __DIR__ . '/SignersMore.php';

/**
 * The small strict-artifact helpers (JS semantics of a parsed-JSON value: numbers by value, no coercion), the RFC 9457 problem of an intent-required refusal,
 * the shape check of the signed or unsigned intent-required body, the clock-checked verifier, the classifier attestation gate and the accumulator monitor
 * helpers that the intent modules share.
 */
final class IntentMisc
{
    public const PROBLEM_BASE = 'https://atlasauth.net/pca/problems/';
    public const INTENT_PROBLEM_KINDS = ['intent-required', 'intent-denied', 'schema-violation', 'ceiling'];
    public const FRICTIONS = ['tap', 'hold', 'typed', 'device'];
    private const TITLES = ['intent-required' => 'Principal confirmation required for this action', 'intent-denied' => 'The principal does not intend this action',
        'schema-violation' => 'The action does not conform to the site action schema', 'ceiling' => 'The action is outside a ceiling the principal cannot widen'];
    private const ERRORS = ['intent-required' => 'intent_required', 'intent-denied' => 'intent_denied', 'schema-violation' => 'schema_violation', 'ceiling' => 'ceiling'];

    /** A JSON object (not an array, not null): native JSON has no prototypes. */
    public static function isPlainObject(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    /** A safe integer that is not negative zero. */
    public static function isSafeInt(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 && !($f == 0.0 && fdiv(1, $f) < 0);
    }

    public static function utf8Len(mixed $s): int
    {
        return strlen((string)$s);
    }

    /** A non-empty string of at most `$max` UTF-8 bytes. */
    public static function isBoundedString(mixed $v, mixed $max): bool
    {
        $m = Js::num($max);
        return is_string($v) && $v !== '' && $m !== null && (float)strlen($v) <= $m;
    }

    /** A wire scalar: a string, a safe integer or a boolean. */
    public static function isScalar(mixed $v): bool
    {
        return is_string($v) || is_bool($v) || self::isSafeInt($v);
    }

    /** Same JSON type and value, no coercion (`1 != "1"`, `true != 1`; NaN is never equal). */
    public static function scalarEq(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && Js::num($a) === Js::num($b);
        }
        return is_string($a) ? $a === $b : (is_bool($a) ? $a === $b : $a === null && $b === null);
    }

    public static function isClock(mixed $v): bool
    {
        return self::isSafeInt($v);
    }

    /** The own member of a JSON object, or null. */
    public static function ownGet(mixed $o, mixed $k): mixed
    {
        return $o instanceof Obj && is_string($k) && $o->has($k) ? $o->get($k) : null;
    }

    public static function nullRecord(): Obj
    {
        return new Obj();
    }

    /** The base64url public key of an Ed25519 secret. */
    public static function publicKeyB64u(string $secret): string
    {
        return (new KeyPair($secret))->public;
    }

    /**
     * The shape check of a `pca-intent-required` body: `$opts['signed']` false checks the unsigned body (a `sig` member is refused), anything else the signed one
     * (`sig = {alg, kid, value, pq_value?}`). Null = well-formed.
     */
    public static function intentRequiredShapeError(mixed $b, mixed $opts = null): ?string
    {
        $signed = Jsx::get($opts, 'signed') !== false;
        if (!$signed) {
            return SignersMore::intentRequiredShapeError($b);
        }
        $e = SignersMore::intentRequiredShapeError($b instanceof Obj ? $b->without('sig') : $b);
        if ($e !== null) {
            return $e;
        }
        $s = $b->get('sig');
        if ($s instanceof Obj) {
            $se = IntentV2::suiteError($s->get('alg'));
            if ($s->has('alg') && $se !== null) {
                return "sig.alg: $se";
            }
            if ($s->has('pq_value') && !is_string($s->get('pq_value'))) {
                return 'sig.pq_value must be a string';
            }
        }
        $bad = !($s instanceof Obj);
        if (!$bad) {
            foreach ($s->keys() as $k) {
                $bad = $bad || !in_array($k, ['alg', 'kid', 'value', 'pq_value'], true);
            }
            $alg = $s->has('alg') ? $s->get('alg') : null;
            $bad = $bad || ($s->has('alg') && !in_array($alg, Pca::REGISTERED_SUITES, true)) || !is_string($s->get('kid')) || !is_string($s->get('value'));
        }
        return $bad ? 'sig must be {alg, kid, value, pq_value?}' : null;
    }

    /** {@see IntentV2::verifyIntentRequired} (which requires a safe-integer clock: expiry is never skipped). */
    public static function verifyIntentRequiredAt(mixed $b, mixed $keys, mixed $now): array
    {
        return IntentV2::verifyIntentRequired($b, $keys, $now);
    }

    /**
     * The 403 problem response of an intent refusal: `{status, headers, body}`. `$opts`: `detail?`, `body?` (the signed intent-required body; required for the
     * `intent-required` kind). An unknown kind still yields a response (error `undefined`, no title) so a caller never loses the refusal.
     */
    public static function intentProblem(mixed $kind, mixed $opts = null): Obj
    {
        $known = is_string($kind) && isset(self::ERRORS[$kind]);
        $body = Jsx::get($opts, 'body');
        $params = ['error="' . ($known ? self::ERRORS[$kind] : 'undefined') . '"'];
        if ($kind === 'intent-required') {
            if (!Jsx::truthy($body)) {
                throw new \RuntimeException('intentProblem: intent-required needs the signed body');
            }
            $params[] = 'session="' . Jsx::str(Jsx::get($body, 'session')) . '"';
            $params[] = 'question="' . Jsx::str(Jsx::get($body, 'question_id')) . '"';
        }
        $out = Obj::of(['type' => self::PROBLEM_BASE . Jsx::str($kind)]);
        if ($known) {
            $out->set('title', self::TITLES[$kind]);
        }
        $out->set('status', 403);
        $detail = Jsx::get($opts, 'detail');
        if (!($detail instanceof Undef)) {
            $out->set('detail', $detail);
        }
        if (Jsx::truthy($body)) {
            $out->set('pca', $body);
        }
        return Obj::of(['status' => 403, 'headers' => Obj::of(['WWW-Authenticate' => 'PCA ' . implode(', ', $params), 'Content-Type' => 'application/problem+json']), 'body' => $out]);
    }

    /** The content digest a classifier verdict binds: b64u(sha256(strict canonical JSON of the value)). */
    public static function classifierContentDigest(mixed $value): string
    {
        return IntentWb::contentDigest($value);
    }

    /**
     * Bind a verdict's signed `measurement` to a verified TEE exactly as a judge is bound; fail closed. `$attestation` null means none presented.
     * @return array{ok:bool,reason?:string,measured?:mixed}
     */
    public static function verifyClassifierAttestation(mixed $v, mixed $attestation = null, mixed $approved = null): array
    {
        if (!($v instanceof Obj)) {
            return ['ok' => false, 'reason' => 'verdict must be an object'];
        }
        try {
            return SemanticThreshold::verifyJudgeAttestation($v->has('measurement') ? $v->get('measurement') : Jsx::$U, $attestation ?? Jsx::$U, $approved);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'attestation check error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())];
        }
    }

    /** A monitor's state before any event: `unmet` (requires_prior, precedes), `clean` (never), `ok` (always), else `idle`. */
    public static function monitorInitialState(mixed $m): string
    {
        $k = Jsx::get($m, 'kind');
        return $k === 'requires_prior' || $k === 'precedes' ? 'unmet' : ($k === 'never' ? 'clean' : ($k === 'always' ? 'ok' : 'idle'));
    }

    /**
     * Distinct keys in canonical (UTF-8 byte) order, the order-independent form hosts exchange.
     * @param list<string> $keys @return list<string>
     */
    public static function sortedDistinct(array $keys): array
    {
        $u = array_values(array_unique($keys));
        sort($u, SORT_STRING);
        return $u;
    }
}
