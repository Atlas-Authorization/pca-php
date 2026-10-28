<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Escalation on the wire: a port of escalation.ts (security contract C-51). A verifier decision of `escalate` is admitted
 * only with a principal-signed answer bound to (policy digest, action digest, history head), spent by the replay counter,
 * never upgrading a deny. Answers are signed under any suite this SDK verifies (Ed25519 always; a post-quantum or hybrid
 * suite only under a pin that carries the principal's `pq_pk`; a suite it cannot verify is refused with `unsupported_suite`).
 * Total: every function returns a result, never throws (the builders return null on a non-canonical input).
 */
final class Escalation
{
    public const ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\0";
    public const POLICY_DOMAIN = 'atlas-pca/escalation-policy/v1';
    public const ACTION_DOMAIN = 'atlas-pca/escalation-action/v1';
    public const HISTORY_DOMAIN = 'atlas-pca/escalation-history/v1';
    /** An answer lives at most 24 hours. */
    public const MAX_LIFETIME_MS = 86_400_000;

    private const REQUIRED = ['v', 'kind', 'principal', 'policy_digest', 'action_digest', 'history_head', 'decision', 'iat',
        'expires_at', 'nonce', 'sig'];
    private const OPTIONAL = ['alg', 'pq_pk', 'pq_sig', 'render_digest'];

    public static function policyDigest(Obj $grant): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::POLICY_DOMAIN, 'grant' => $grant]));
    }

    /** The digest of the exact PCActn (counter and signature included): one answer, one action. */
    public static function actionDigest(Obj $pcactn): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::ACTION_DOMAIN, 'pcactn' => $pcactn]));
    }

    /** The head of the holder's history: its highest admitted replay counter (null = none yet). */
    public static function historyHead(?int $lastCounter): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::HISTORY_DOMAIN,
            'last_counter' => $lastCounter === null ? null : new Num((string)$lastCounter)]));
    }

    /**
     * The request a refused `escalate` carries for the principal.
     * @param list<string> $reasons
     */
    public static function buildRequest(mixed $aud, Obj $grant, Obj $pcactn, ?int $lastCounter, array $reasons, int $now,
                                        int $ttlMs = 3_600_000, ?string $renderDigest = null): Obj
    {
        $action = $pcactn->get('action');
        $verb = $action instanceof Obj ? $action->get('verb') : null;
        $resource = $action instanceof Obj ? $action->get('resource') : null;
        $rs = [];
        foreach (array_slice($reasons, 0, 16) as $r) {
            $s = (string)$r;
            $rs[] = SafeRegex::utf16Len($s) > 512 ? self::headUnits($s, 512) : $s;
        }
        $req = Obj::of([
            'v' => new Num('1'),
            'kind' => 'pca-escalation-request',
            'aud' => is_string($aud) ? $aud : '',
            'policy_digest' => self::policyDigest($grant),
            'action_digest' => self::actionDigest($pcactn),
            'history_head' => self::historyHead($lastCounter),
            'verb' => IntentWb::jsStr($verb),
            'resource' => IntentWb::jsStr($resource),
            'reasons' => $rs,
            'expires_at' => new Num((string)($now + $ttlMs)),
        ]);
        if ($renderDigest !== null) {
            $req->set('render_digest', $renderDigest);
        }
        return $req;
    }

    /**
     * First `$n` UTF-16 code units (`String.slice(0, n)`). A cut inside a surrogate pair keeps the LONE high surrogate, as the
     * reference does, as its three WTF-8 bytes ({@see reasonsWire} writes it as `\\udXXX`).
     */
    private static function headUnits(string $s, int $n): string
    {
        $out = '';
        $units = 0;
        foreach (preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
            $u = SafeRegex::utf16Len($ch);
            if ($units + $u > $n) {
                if ($u === 2 && $units + 1 === $n) {
                    $cp = mb_ord($ch, 'UTF-8') - 0x10000;
                    $hi = 0xD800 + ($cp >> 10);
                    $out .= chr(0xE0 | ($hi >> 12)) . chr(0x80 | (($hi >> 6) & 0x3F)) . chr(0x80 | ($hi & 0x3F));
                }
                break;
            }
            $out .= $ch;
            $units += $u;
        }
        return $out;
    }

    /** `JSON.stringify(request.reasons)`: quote, backslash and controls escaped, a lone surrogate as `\\udXXX`, all else raw. */
    public static function reasonsWire(Obj $request): string
    {
        $short = ['"' => '\\"', '\\' => '\\\\', "\x08" => '\\b', "\x0c" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t'];
        $one = static function (string $r) use ($short): string {
            $o = '';
            $len = strlen($r);
            for ($i = 0; $i < $len; $i++) {
                $c = $r[$i];
                $b = ord($c);
                if (isset($short[$c])) {
                    $o .= $short[$c];
                } elseif ($b < 0x20) {
                    $o .= sprintf('\\u%04x', $b);
                } elseif ($b === 0xED && $i + 2 < $len && ord($r[$i + 1]) >= 0xA0) {
                    $o .= sprintf('\\u%04x', (($b & 0x0F) << 12) | ((ord($r[$i + 1]) & 0x3F) << 6) | (ord($r[$i + 2]) & 0x3F));
                    $i += 2;
                } else {
                    $o .= $c;
                }
            }
            return '"' . $o . '"';
        };
        return '[' . implode(',', array_map($one, $request->get('reasons'))) . ']';
    }

    private static function numEq(mixed $x, int $v): bool
    {
        return IntentWb::isSafeInt($x) && self::f($x) === (float)$v;
    }

    /** A JSON number (Num or native) as a float. */
    private static function f(mixed $x): float
    {
        return $x instanceof Num ? $x->float() : (float)$x;
    }

    /** Null = well-formed (closed members, canonical digests, safe-integer times, sane lifetime, usable suite members). */
    public static function answerShapeError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'not an object';
        }
        foreach (IntentWb::jsKeys($a) as $k) {
            if (!in_array($k, self::REQUIRED, true) && !in_array($k, self::OPTIONAL, true)) {
                return "unknown member 'answer.$k'";
            }
        }
        foreach (self::REQUIRED as $k) {
            if (!$a->has($k)) {
                return "missing member 'answer.$k'";
            }
        }
        if (!self::numEq($a->get('v'), 1) || $a->get('kind') !== 'pca-escalation-answer') {
            return 'not a pca-escalation-answer v1';
        }
        $pr = $a->get('principal');
        if (!is_string($pr) || $pr === '' || strlen($pr) > 64 || Pca::unb64u($pr, 32) === null) {
            return 'principal must be canonical base64url (32 bytes)';
        }
        foreach (['policy_digest', 'action_digest', 'history_head'] as $k) {
            if (Pca::unb64u($a->get($k), 32) === null) {
                return "$k must be canonical base64url (32 bytes)";
            }
        }
        if ($a->get('decision') !== 'allow' && $a->get('decision') !== 'deny') {
            return "decision must be 'allow' or 'deny'";
        }
        $iat = $a->get('iat');
        $exp = $a->get('expires_at');
        if (!(IntentWb::isSafeInt($iat) && self::f($iat) >= 0) || !(IntentWb::isSafeInt($exp) && self::f($exp) >= 0)) {
            return 'iat and expires_at must be non-negative safe integers';
        }
        if (!(self::f($exp) > self::f($iat))) {
            return 'expires_at must be greater than iat';
        }
        if (self::f($exp) - self::f($iat) > self::MAX_LIFETIME_MS) {
            return 'an answer lives at most ' . self::MAX_LIFETIME_MS . ' ms';
        }
        if ($a->has('render_digest') && Pca::unb64u($a->get('render_digest'), 32) === null) {
            return 'render_digest must be canonical base64url (32 bytes)';
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
     * Sign an answer body with an Ed25519 secret key (64-byte libsodium secret key). A principal on another suite signs
     * with its own tooling (the signed message is {@see IntentWb::artifactMessage}). Null on a malformed body.
     */
    public static function signAnswer(Obj $body, string $secretKey): ?Obj
    {
        try {
            $msg = IntentWb::artifactMessage(self::ANSWER_DOMAIN, $body);
            $signed = $body->without('sig', 'pq_sig');
            $signed->set('sig', Pca::b64u(sodium_crypto_sign_detached($msg, $secretKey)));
            return self::answerShapeError($signed) === null ? $signed : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Verify an answer against the verifier's pinned principals and the binding of THIS decision. Total; every failure is
     * `['ok' => false, 'reason' => ...]`. A valid `deny` answer is `ok` with `decision` `'deny'`: the caller must not admit it.
     *
     * @param mixed $principals list of b64u Ed25519 keys or pin Objs `{pk, pq_pk?}`
     * @param mixed $bind       `['policy_digest' =>, 'action_digest' =>, 'history_head' =>]` (array or Obj)
     * @return array{ok: bool, reason?: string, principal?: string, decision?: string}
     */
    public static function verifyAnswer(mixed $answer, mixed $principals, mixed $bind, mixed $now): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            if (!IntentWb::isSafeInt($now)) {
                return $no('the verifier clock is not a safe integer (fail closed)');
            }
            $nowI = (int)self::f($now);
            $e = self::answerShapeError($answer);
            if ($e !== null) {
                return $no("malformed escalation answer: $e");
            }
            /** @var Obj $a */
            $a = $answer;
            if (!is_array($principals) || !array_is_list($principals) || $principals === []) {
                return $no('no principal is pinned for escalation answers');
            }
            $pin = null;
            foreach ($principals as $p) {
                $pk = is_string($p) ? $p : ($p instanceof Obj ? $p->get('pk') : null);
                if ($pk !== null && $pk === $a->get('principal')) {
                    $pin = $p;
                    break;
                }
            }
            if ($pin === null) {
                return $no('the answering principal is not pinned by this verifier');
            }
            if (!IntentWb::verifyArtifactSig(self::ANSWER_DOMAIN, $a, $pin)) {
                return $no('escalation answer signature invalid');
            }
            $get = static fn(string $k): mixed => $bind instanceof Obj ? $bind->get($k) : (is_array($bind) ? ($bind[$k] ?? null) : null);
            if ($a->get('policy_digest') !== $get('policy_digest')) {
                return $no('the answer is bound to another policy');
            }
            if ($a->get('action_digest') !== $get('action_digest')) {
                return $no('the answer is bound to another action');
            }
            if ($a->get('history_head') !== $get('history_head')) {
                return $no('the answer is bound to another state of the history');
            }
            $wantRender = $get('render_digest');
            if ($wantRender !== null) {
                if (!$a->has('render_digest')) {
                    return $no('the answer is not bound to the canonical approval render');
                }
                if ($a->get('render_digest') !== $wantRender) {
                    return $no('the answer was given for another approval render');
                }
            } elseif ($a->has('render_digest')) {
                return $no('the answer carries an approval render this verifier did not recompute');
            }
            if ($nowI < (int)self::f($a->get('iat'))) {
                return $no('the answer is from the future');
            }
            if ($nowI > (int)self::f($a->get('expires_at'))) {
                return $no('the answer has expired');
            }
            return ['ok' => true, 'principal' => $a->get('principal'), 'decision' => $a->get('decision')];
        } catch (\Throwable $err) {
            return $no('escalation answer error (fail closed): ' . $err->getMessage());
        }
    }
}
