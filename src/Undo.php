<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Agent.php';

/**
 * UNDO WINDOWS (0.5), the pure layer: reversible actions execute at once and the principal gets a veto window in which they can
 * undo them. This is what any language needs to verify the artifacts of an undo ledger (the coordinator that admits, records,
 * compensates and notifies is the TypeScript `createUndoCoordinator` or the hosted ledger):
 *
 *   - the compensation digest every token and receipt binds;
 *   - the signed one-click undo TOKEN (one record, one compensation, one render, valid through the window end);
 *   - the signed, hash-chained audit RECEIPTS of a record's transitions, and the whole-chain check;
 *   - the record STATE MACHINE (open -> vetoed -> compensated | compensation_failed -> retry; open -> finalized; abort);
 *   - the window clamp.
 *
 * Values are the SDK's JSON model (Obj, list arrays, Num, string, bool, null; PHP ints are accepted wherever a number is).
 * Signatures are plain Ed25519 over utf8(domain) || strict canonical JSON of the body. Every function is total (never throws)
 * except the two signers, which refuse a malformed body.
 */
final class Undo
{
    public const TOKEN_DOMAIN = "atlas-pca/undo-token/v1\0";
    public const RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\0";
    public const COMPENSATION_DOMAIN = 'atlas-pca/undo-compensation/v1';
    public const RECEIPT_REF_DOMAIN = 'atlas-pca/undo-receipt-ref/v1';
    public const TOKEN_REF_DOMAIN = 'atlas-pca/undo-token-ref/v1';
    public const TOKEN_KIND = 'pca-undo-token';
    public const RECEIPT_KIND = 'pca-undo-receipt';
    /** The floor of a veto window: a human must be able to react. */
    public const MIN_WINDOW_MS = 30000;
    public const DEFAULT_WINDOW_MS = 900000;
    public const MAX_WINDOW_MS = 86400000;
    public const STATES = ['open', 'vetoed', 'compensated', 'compensation_failed', 'finalized'];
    public const EVENTS = ['opened', 'vetoed', 'compensated', 'compensation_failed', 'finalized', 'aborted', 'retried', 'effect'];
    public const VETO_VIAS = ['token', 'operator', 'fraud_proof', 'revocation'];
    private const ID_MAX = 256;
    private const MAX_ENCODED_TOKEN = 4096;
    private const TOKEN_FIELDS = ['v', 'kind', 'record', 'aud', 'principal', 'compensation_digest', 'render_digest', 'exp', 'signer', 'sig'];
    private const RECEIPT_FIELDS = ['v', 'kind', 'record', 'event', 'state', 'at', 'compensation_digest', 'prev', 'note', 'signer', 'sig'];

    // ---- helpers ------------------------------------------------------------------------------------------------------

    /** `o[k]` of an Obj or a PHP array (null when absent). */
    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : (is_array($o) ? ($o[$k] ?? null) : null);
    }

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj ? $o->has($k) : is_array($o) && array_key_exists($k, $o);
    }

    /** A JSON number's value (Num, int or float), else null. */
    private static function num(mixed $v): ?float
    {
        return $v instanceof Num ? $v->float() : (is_int($v) || is_float($v) ? (float)$v : null);
    }

    /** A record id: a string of 1..256 characters (UTF-16 units) with no control character. */
    public static function idOk(mixed $s): bool
    {
        return is_string($s) && $s !== '' && K3Sig::utf16Len($s) <= self::ID_MAX && preg_match('/[\x00-\x1f]/', $s) !== 1;
    }

    private static function isOne(mixed $v): bool
    {
        return self::num($v) === 1.0;
    }

    /** The signed message: utf8(domain) || strict canonical JSON of the body (the JS value). Throws JsonError. */
    private static function message(string $domain, Obj $body): string
    {
        return $domain . IntentWb::canon($body);
    }

    // ---- digests ------------------------------------------------------------------------------------------------------

    /** hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?}) of a compensation. Throws JsonError. */
    public static function compensationDigest(mixed $c): string
    {
        $o = Obj::of(['d' => self::COMPENSATION_DOMAIN, 'verb' => self::g($c, 'verb'), 'resource' => self::g($c, 'resource'),
            'params' => Sign::n(self::g($c, 'params')), 'undo_of' => self::g($c, 'undo_of'), 'def_digest' => self::g($c, 'def_digest')]);
        if (self::has($c, 'target_param')) {
            $o->set('target_param', self::g($c, 'target_param'));
        }
        return IntentWb::valueDigest($o);
    }

    // ---- the one-click undo token -------------------------------------------------------------------------------------

    /**
     * Sign the undo token of a record (`id`, `aud`, `principal`, `compensation_digest`, `render_digest`?, `window_end`) under
     * the undo service key. Throws on a body that is not strictly canonical.
     */
    public static function signToken(mixed $rec, KeyPair $key): Obj
    {
        $rd = self::g($rec, 'render_digest');
        $body = Obj::of(['v' => new Num('1'), 'kind' => self::TOKEN_KIND, 'record' => self::g($rec, 'id'), 'aud' => self::g($rec, 'aud'),
            'principal' => self::g($rec, 'principal'), 'compensation_digest' => self::g($rec, 'compensation_digest'),
            'render_digest' => $rd ?? '', 'exp' => Sign::n(self::g($rec, 'window_end')), 'signer' => $key->public]);
        $body->set('sig', Pca::b64u($key->sign(self::message(self::TOKEN_DOMAIN, $body))));
        return $body;
    }

    /**
     * Check a token against the pinned undo service key and the stored record at `now`. Returns the FIRST failing check:
     * `malformed`, `signer`, `signature`, `record`, `binding` (aud, principal, compensation, render, window end), `expired`
     * (`now > exp`: valid through `exp` inclusive), else `ok`. Never throws.
     */
    public static function tokenCheck(mixed $token, mixed $expectedSigner, mixed $rec, mixed $now): string
    {
        try {
            if (!($token instanceof Obj) || count($token->keys()) !== count(self::TOKEN_FIELDS)) {
                return 'malformed';
            }
            foreach (self::TOKEN_FIELDS as $k) {
                if (!$token->has($k)) {
                    return 'malformed';
                }
            }
            $t = static fn(string $k): mixed => $token->get($k);
            if (!self::isOne($t('v')) || $t('kind') !== self::TOKEN_KIND || !self::idOk($t('record')) || !is_string($t('aud'))
                || !is_string($t('principal')) || !is_string($t('compensation_digest')) || !is_string($t('render_digest'))
                || !IntentWb::isSafeInt($t('exp')) || !is_string($t('signer')) || Pca::unb64u($t('sig'), 64) === null) {
                return 'malformed';
            }
            if ($t('signer') !== $expectedSigner) {
                return 'signer';
            }
            if (!Pca::verifyEd25519B64u($expectedSigner, self::message(self::TOKEN_DOMAIN, $token->without('sig')), $t('sig'))) {
                return 'signature';
            }
            if ($t('record') !== self::g($rec, 'id')) {
                return 'record';
            }
            $we = self::num(self::g($rec, 'window_end'));
            if ($t('aud') !== self::g($rec, 'aud') || $t('principal') !== self::g($rec, 'principal')
                || $t('compensation_digest') !== self::g($rec, 'compensation_digest')
                || $t('render_digest') !== (self::g($rec, 'render_digest') ?? '') || $we === null || self::num($t('exp')) !== $we) {
                return 'binding';
            }
            if (!IntentWb::isSafeInt($now) || self::num($now) > self::num($t('exp'))) {
                return 'expired';
            }
            return 'ok';
        } catch (\Throwable) {
            return 'malformed';
        }
    }

    /** The token as a URL-safe string (base64url of its strict canonical JSON) for a one-click link. Throws JsonError. */
    public static function encodeToken(Obj $t): string
    {
        return Pca::b64u(IntentWb::canon($t));
    }

    /** Inverse of {@see encodeToken}: a non-empty string of at most 4096 characters, strict base64url, UTF-8, a JSON object; else null. */
    public static function decodeToken(mixed $s): ?Obj
    {
        try {
            if (!is_string($s) || $s === '' || strlen($s) > self::MAX_ENCODED_TOKEN) {
                return null;
            }
            $raw = Pca::unb64u($s);
            if ($raw === null || preg_match('//u', $raw) !== 1) {
                return null;
            }
            $x = Json::parseLax($raw);
            return $x instanceof Obj ? $x : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** hashCanonical({d: "atlas-pca/undo-token-ref/v1", t}). Throws JsonError. */
    public static function tokenDigest(mixed $t): string
    {
        return IntentWb::valueDigest(Obj::of(['d' => self::TOKEN_REF_DOMAIN, 't' => $t]));
    }

    // ---- receipts -----------------------------------------------------------------------------------------------------

    /** hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r}) (the receipt WITH its signature). Throws JsonError. */
    public static function receiptDigest(mixed $r): string
    {
        return IntentWb::valueDigest(Obj::of(['d' => self::RECEIPT_REF_DOMAIN, 'r' => $r]));
    }

    /** Sign one transition receipt (`record`, `event`, `state`, `at`, `compensation_digest`, `prev`, `note`) under the undo service key. */
    public static function signReceipt(mixed $body, KeyPair $key): Obj
    {
        $b = Obj::of(['v' => new Num('1'), 'kind' => self::RECEIPT_KIND, 'record' => self::g($body, 'record'), 'event' => self::g($body, 'event'),
            'state' => self::g($body, 'state'), 'at' => Sign::n(self::g($body, 'at')), 'compensation_digest' => self::g($body, 'compensation_digest'),
            'prev' => self::g($body, 'prev'), 'note' => self::g($body, 'note'), 'signer' => $key->public]);
        $b->set('sig', Pca::b64u($key->sign(self::message(self::RECEIPT_DOMAIN, $b))));
        return $b;
    }

    /** True iff `$r` is a well-formed receipt (exactly its 11 members) signed by `$expectedSigner` over exactly its content. */
    public static function verifyReceipt(mixed $r, mixed $expectedSigner): bool
    {
        try {
            if (!($r instanceof Obj) || IntentWb::closedMembers($r, self::RECEIPT_FIELDS) !== null) {
                return false;
            }
            if (!self::isOne($r->get('v')) || $r->get('kind') !== self::RECEIPT_KIND || !self::idOk($r->get('record'))
                || !in_array($r->get('event'), self::EVENTS, true) || !in_array($r->get('state'), self::STATES, true)
                || !IntentWb::isSafeInt($r->get('at')) || !is_string($r->get('compensation_digest')) || !is_string($r->get('prev'))
                || !is_string($r->get('note')) || !is_string($expectedSigner) || $r->get('signer') !== $expectedSigner
                || Pca::unb64u($r->get('sig'), 64) === null) {
                return false;
            }
            return Pca::verifyEd25519B64u($expectedSigner, self::message(self::RECEIPT_DOMAIN, $r->without('sig')), $r->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify a record's receipt chain (`id`, `compensation_digest`, `state`, `receipts`): non-empty, every receipt verifies,
     * names this record and its compensation, links `prev` to the previous receipt's digest ('' for the first), the first is
     * `opened`, `at` never decreases, and the last receipt states the record's state. Null when sound, else the reason.
     */
    public static function receiptChainError(mixed $rec, mixed $expectedSigner): ?string
    {
        try {
            $rs = self::g($rec, 'receipts');
            if (!is_array($rs) || !array_is_list($rs) || $rs === []) {
                return 'no receipts';
            }
            $prev = '';
            $at = -INF;
            foreach ($rs as $i => $r) {
                if (!self::verifyReceipt($r, $expectedSigner)) {
                    return "receipt $i does not verify";
                }
                if ($r->get('record') !== self::g($rec, 'id') || $r->get('compensation_digest') !== self::g($rec, 'compensation_digest')) {
                    return "receipt $i is for another record";
                }
                if ($r->get('prev') !== $prev) {
                    return "receipt $i does not link to the previous one";
                }
                if ($i === 0 && $r->get('event') !== 'opened') {
                    return 'the first receipt is not opened';
                }
                if (self::num($r->get('at')) < $at) {
                    return "receipt $i goes back in time";
                }
                $prev = self::receiptDigest($r);
                $at = self::num($r->get('at'));
            }
            return $rs[count($rs) - 1]->get('state') === self::g($rec, 'state') ? null : 'the last receipt does not state the record state';
        } catch (\Throwable) {
            return 'evaluation error (fail closed)';
        }
    }

    // ---- the pure transitions -----------------------------------------------------------------------------------------

    /** @return array{outcome: 'refused', code: string, reason: string} */
    private static function refused(string $code, string $reason): array
    {
        return ['outcome' => 'refused', 'code' => $code, 'reason' => $reason];
    }

    /** JS `String(x).slice(0, n)`. shortcut: slices code points where JS slices UTF-16 units (differs only for astral characters at the cut). */
    private static function note(mixed $x, int $n): string
    {
        return mb_substr(IntentWb::jsStr($x), 0, $n, 'UTF-8');
    }

    /**
     * The record state machine, pure: `$rec` is not modified. `$ev` is `{kind: veto, veto: {at, via, by}}`, `{kind: finalize}`,
     * `{kind: abort, reason}`, `{kind: effect, result?}`, `{kind: compensated, result?}`, `{kind: compensation_failed, reason}` or
     * `{kind: retry}`; `$now` is the trusted server clock. Returns `['outcome' => 'applied', 'record' => Obj (ver + 1),
     * 'receipt' => ['event', 'note']]` (the receipt is signed and linked by the store layer), `['outcome' => 'replayed',
     * 'record' => $rec]` (the same transition already happened) or `['outcome' => 'refused', 'code', 'reason']`. Never throws.
     *
     * @return array<string,mixed>
     */
    public static function transition(mixed $rec, mixed $ev, mixed $now): array
    {
        try {
            if (!($rec instanceof Obj) || !in_array($rec->get('state'), self::STATES, true) || !IntentWb::isSafeInt($rec->get('window_end'))
                || !IntentWb::isSafeInt($rec->get('ver'))) {
                return self::refused('invalid', 'malformed record');
            }
            if (!IntentWb::isSafeInt($now)) {
                return self::refused('invalid', 'now must be a safe integer');
            }
            $state = $rec->get('state');
            $t = (int)self::num($now);
            $we = (int)self::num($rec->get('window_end'));
            $next = static function (array $patch, string $event, string $note = '') use ($rec): array {
                $r = $rec->without();
                foreach ($patch as $k => $v) {
                    $r->set((string)$k, $v);
                }
                $r->set('ver', new Num((string)((int)self::num($rec->get('ver')) + 1)));
                return ['outcome' => 'applied', 'record' => $r, 'receipt' => ['event' => $event, 'note' => $note]];
            };
            $kind = $ev instanceof Obj ? $ev->get('kind') : null;
            $outcome = static fn(array $o): Obj => Obj::of(['at' => new Num((string)$t)] + $o);
            switch ($kind) {
                case 'veto':
                    $v = $ev->get('veto');
                    if (!($v instanceof Obj) || !IntentWb::isSafeInt($v->get('at')) || !in_array($v->get('via'), self::VETO_VIAS, true)
                        || !is_string($v->get('by')) || $v->get('by') === '') {
                        return self::refused('invalid', 'malformed veto');
                    }
                    if (in_array($state, ['vetoed', 'compensated', 'compensation_failed'], true)) {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state === 'finalized') {
                        return self::refused('finalized', 'the window is closed and the action is final');
                    }
                    if ($t > $we) {
                        return self::refused('window_closed', "the veto window closed at $we");
                    }
                    return $next(['state' => 'vetoed', 'veto' => $v->without()], 'vetoed', $v->get('via'));
                case 'finalize':
                    if ($state === 'finalized') {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state !== 'open') {
                        return self::refused('vetoed', "a $state record is not finalized");
                    }
                    if ($t <= $we) {
                        return self::refused('window_open', "the veto window is open until $we");
                    }
                    return $next(['state' => 'finalized', 'outcome' => $outcome(['status' => 'finalized'])], 'finalized');
                case 'abort':
                    $o = $rec->get('outcome');
                    if ($state === 'finalized' && $o instanceof Obj && $o->get('status') === 'aborted') {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state !== 'open' && $state !== 'vetoed') {
                        return self::refused('finalized', "a $state record cannot be aborted");
                    }
                    if ($rec->has('effect')) {
                        return self::refused('effect_recorded', 'the effect ran: it can only be compensated or finalized');
                    }
                    $why = self::reasonOf($ev);
                    return $next(['state' => 'finalized', 'outcome' => $outcome(['status' => 'aborted', 'reason' => self::note($why, 512)])],
                        'aborted', self::note($why, 128));
                case 'effect':
                    if ($rec->has('effect')) {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state !== 'open' && $state !== 'vetoed') {
                        return self::refused('finalized', "a $state record takes no effect report");
                    }
                    $eff = Obj::of(['at' => new Num((string)$t)]);
                    if ($ev->has('result')) {
                        $eff->set('result', $ev->get('result'));
                    }
                    return $next(['effect' => $eff], 'effect');
                case 'compensated':
                    if ($state === 'compensated') {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state !== 'vetoed' && $state !== 'compensation_failed') {
                        return self::refused('not_vetoed', "a $state record is not being compensated");
                    }
                    $out = $outcome(['status' => 'compensated']);
                    if ($ev->has('result')) {
                        $out->set('result', $ev->get('result'));
                    }
                    return $next(['state' => 'compensated', 'outcome' => $out], 'compensated');
                case 'compensation_failed':
                    if ($state === 'compensation_failed') {
                        return ['outcome' => 'replayed', 'record' => $rec];
                    }
                    if ($state !== 'vetoed') {
                        return self::refused('not_vetoed', "a $state record is not being compensated");
                    }
                    $why = self::reasonOf($ev);
                    return $next(['state' => 'compensation_failed', 'outcome' => $outcome(['status' => 'compensation_failed', 'reason' => self::note($why, 512)])],
                        'compensation_failed', self::note($why, 128));
                case 'retry':
                    if ($state !== 'compensation_failed') {
                        return self::refused('not_failed', "a $state record is not retried");
                    }
                    if (!IntentWb::isSafeInt($rec->get('attempt'))) {
                        return self::refused('invalid', 'malformed record');
                    }
                    return $next(['state' => 'vetoed', 'attempt' => new Num((string)((int)self::num($rec->get('attempt')) + 1))], 'retried');
                default:
                    return self::refused('invalid', 'unknown event');
            }
        } catch (\Throwable) {
            return self::refused('invalid', 'evaluation error (fail closed)');
        }
    }

    /** The event's `reason` (JsUndefined when absent, so it reads "undefined" as `String(undefined)` does). */
    private static function reasonOf(Obj $ev): mixed
    {
        return $ev->has('reason') ? $ev->get('reason') : JsUndefined::U;
    }

    /**
     * Clamp a requested window (ms) into [max(30 s, minMs), min(maxMs, 24 h)]; absent or non-finite = the default (15 min, or
     * `defaultMs`). `$policy` holds optional `minMs`, `maxMs`, `defaultMs` (an Obj or a PHP array). Never throws.
     */
    public static function resolveWindow(mixed $requested, mixed $policy = null): int
    {
        $p = static fn(string $k): ?float => self::num(self::g($policy, $k));
        $min = max((float)self::MIN_WINDOW_MS, $p('minMs') ?? (float)self::MIN_WINDOW_MS);
        $max = max($min, min($p('maxMs') ?? (float)self::MAX_WINDOW_MS, (float)self::MAX_WINDOW_MS));
        $r = self::num($requested);
        $want = $r !== null && is_finite($r) ? $r : ($p('defaultMs') ?? (float)self::DEFAULT_WINDOW_MS);
        return (int)floor(min($max, max($min, $want)));
    }

    // ---- the authorize admission hook ---------------------------------------------------------------------------------

    /**
     * Validate what an undo admission hook returned: `{id, window_end, compensation: {verb, resource}}` with an id usable in the
     * `undo_window` obligation (a record id of at most 128 characters) and a non-negative safe-integer window end. Null = usable;
     * an unusable admission is no admission (the escalation stands).
     */
    public static function admissionError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'an undo admission must be an object';
        }
        if (!self::idOk($a->get('id')) || !K3Sig::isStr($a->get('id'), 128)) {
            return 'an undo admission needs the record id (1..128 characters, no control characters)';
        }
        if (!K3Sig::isSafeInt($a->get('window_end'))) {
            return 'an undo admission needs window_end (a non-negative safe integer)';
        }
        $c = $a->get('compensation');
        if (!($c instanceof Obj) || !is_string($c->get('verb')) || $c->get('verb') === '' || !is_string($c->get('resource'))) {
            return 'an undo admission needs the compensation {verb, resource}';
        }
        return null;
    }

    /** The `undo_window` obligation an admitted action carries: `{kind, params: {id, window_end}, due: window_end}`. */
    public static function obligation(Obj $admission): Obj
    {
        $we = Sign::n($admission->get('window_end'));
        return Obj::of(['kind' => 'undo_window', 'params' => Obj::of(['id' => $admission->get('id'), 'window_end' => $we]), 'due' => $we]);
    }
}
