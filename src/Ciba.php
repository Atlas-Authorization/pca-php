<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/WhatwgUrl.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Approval.php';

/**
 * A CIBA (OpenID Client-Initiated Backchannel Authentication) on-ramp for PCA's step-up: the canonical action and the
 * one-line binding message the person approves, the backchannel auth request, the risk gate (only a tier-3 step-up
 * interrupts a human), the budget effect of a settled decision, and the brokers / stores / network client in the classes
 * below. Everything here authorises nothing on its own: the verifier and the threshold cosigners stay the authority.
 *
 * Values are the parsed-JSON model (Obj, lists, scalars) or PHP assoc arrays keyed by the reference's field names.
 */
final class Ciba
{
    public const DEFAULT_EXPIRY_SEC = 300;
    public const DEFAULT_INTERVAL_SEC = 5;
    public const PAYEE_KEYS = ['payee', 'to', 'recipient', 'beneficiary', 'destination'];
    private const DISPLAYED_PARAM_KEYS = ['amount', 'currency', 'payee', 'to', 'recipient', 'beneficiary', 'destination'];
    private const MIN_AUTH_REQ_ID_LEN = 22;
    private const MAX_GOAL_CHARS = 100;
    private const MAX_PAYEE_CHARS = 64;
    /** The JavaScript \s / String.prototype.trim white-space set. */
    private const WS = '\x{9}-\x{d}\x{20}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}';
    private const SCRIPT_GROUPS = [
        'latin' => '/\p{sc:Latin}/u',
        'cyrillic' => '/\p{sc:Cyrillic}/u',
        'greek' => '/\p{sc:Greek}/u',
        'armenian' => '/\p{sc:Armenian}/u',
        'hebrew' => '/\p{sc:Hebrew}/u',
        'arabic' => '/\p{sc:Arabic}/u',
        'cjk' => '/[\p{sc:Han}\p{sc:Hiragana}\p{sc:Katakana}\p{sc:Hangul}\p{sc:Bopomofo}]/u',
        'indic-thai' => '/[\p{sc:Devanagari}\p{sc:Bengali}\p{sc:Tamil}\p{sc:Thai}\p{sc:Georgian}]/u',
    ];

    // ---- JS string helpers ------------------------------------------------------------------------------------------------

    /** The code points of a (WTF-8) string; a lone surrogate is one code point, as Array.from sees it. @return list<string> */
    public static function codePoints(string $s): array
    {
        preg_match_all('/[\x00-\x7F]|[\xC0-\xFF][\x80-\xBF]*/', $s, $m);
        return $m[0];
    }

    /** String(x) of a JSON value. */
    public static function jsStr(mixed $v): string
    {
        return Js::str($v);
    }

    private static function safeInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0;
    }

    /**
     * Run a /u regex operation over a string that may hold lone surrogates (WTF-8): they are swapped for plane-16 private-use
     * stand-ins for the call and back afterwards.
     * shortcut: input that already holds U+10F800..U+10FFFF would come back as lone surrogates; upgrade if such text is real.
     */
    private static function shielded(string $s, callable $f): mixed
    {
        $in = (string)preg_replace_callback('/\xED([\xA0-\xBF])([\x80-\xBF])/', static fn(array $m): string => mb_chr(0x10F800 + ((ord($m[1]) - 0xA0) << 6) + (ord($m[2]) - 0x80), 'UTF-8'), $s);
        $out = $f($in);
        if (!is_string($out)) {
            return $out;
        }
        return (string)preg_replace_callback('/\xF4\x8F[\xA0-\xBF][\x80-\xBF]/', static function (array $m): string {
            $o = mb_ord($m[0], 'UTF-8') - 0x10F800;
            return "\xED" . chr(0xA0 + ($o >> 6)) . chr(0x80 + ($o & 0x3F));
        }, $out);
    }

    /** Control / format characters and line breaks become spaces, white-space runs collapse, the ends are trimmed. */
    private static function plainText(string $v): string
    {
        return self::shielded($v, static function (string $s): string {
            $s = (string)preg_replace('/[\p{Cc}\p{Cf}\x{2028}\x{2029}]/u', ' ', $s);
            $s = (string)preg_replace('/[' . self::WS . ']+/u', ' ', $s);
            return (string)preg_replace('/\A[' . self::WS . ']+|[' . self::WS . ']+\z/u', '', $s);
        });
    }

    private static function clip(string $v, int $max): string
    {
        $c = self::codePoints($v);
        return count($c) <= $max ? $v : implode('', array_slice($c, 0, max(0, $max - 1))) . '…';
    }

    /** s.slice(0, n) in UTF-16 code units: an astral character cut in half leaves its high surrogate. */
    private static function slice16(string $s, int $n): string
    {
        $out = '';
        $u = 0;
        foreach (self::codePoints($s) as $c) {
            $w = strlen($c) === 4 ? 2 : 1;
            if ($u + $w > $n) {
                if ($w === 2 && $u < $n) {
                    $hi = 0xD800 + ((mb_ord($c, 'UTF-8') - 0x10000) >> 10);
                    $out .= chr(0xE0 | ($hi >> 12)) . chr(0x80 | (($hi >> 6) & 0x3F)) . chr(0x80 | ($hi & 0x3F));
                }
                break;
            }
            $out .= $c;
            $u += $w;
        }
        return $out;
    }

    private static function forged(string $s): bool
    {
        return (bool)self::shielded(strtolower($s), static fn(string $t): bool => preg_match('/because[' . self::WS . ']+you[' . self::WS . ']+asked/u', $t) === 1);
    }

    // ---- the canonical action -----------------------------------------------------------------------------------------------

    private static function identifier(mixed $value, string $what): string
    {
        if (!is_string($value) || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._:\/#@+-]{0,63}\z/', $value) !== 1) {
            throw new \RangeException("ciba: the step-up $what must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message");
        }
        if (self::forged($value)) {
            throw new \RangeException("ciba: the step-up $what contains an approval-explanation clause");
        }
        return $value;
    }

    private static function payeeText(mixed $value): string
    {
        if (!is_string($value)) {
            throw new \RangeException('ciba: the payee must be a string (a nested value cannot be shown to the approver)');
        }
        $undisplayable = 'ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed';
        if (Json::hasLoneSurrogate($value) || !mb_check_encoding($value, 'UTF-8')) {
            throw new \RangeException($undisplayable);
        }
        $t = \Normalizer::normalize($value, \Normalizer::FORM_C);
        if (!is_string($t)) {
            throw new \RangeException($undisplayable);
        }
        $ws = self::WS;
        if ($t === '' || preg_replace("/\\A[$ws]+|[$ws]+\\z/u", '', $t) !== $t || preg_match("/[$ws]{2,}/u", $t) === 1) {
            throw new \RangeException('ciba: the payee must be non-empty without leading, trailing or repeated whitespace');
        }
        if (preg_match('/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\x{2028}\x{2029}\x{FFF9}-\x{FFFD}]/u', $t) === 1) {
            throw new \RangeException($undisplayable);
        }
        if (strpbrk($t, '"\\') !== false) {
            throw new \RangeException('ciba: the payee must not contain quote or backslash characters');
        }
        if (count(self::codePoints($t)) > self::MAX_PAYEE_CHARS) {
            throw new \RangeException('ciba: the payee is longer than ' . self::MAX_PAYEE_CHARS . ' characters; refusing to truncate what the person approves');
        }
        if (self::forged($t)) {
            throw new \RangeException('ciba: the payee contains an approval-explanation clause');
        }
        // lookalikes: a leftover combining mark, a compatibility form, or a mix of writing systems is refused
        if (preg_match('/\p{M}/u', $t) === 1) {
            throw new \RangeException('ciba: the payee contains combining marks and cannot be shown unambiguously');
        }
        if (\Normalizer::normalize($t, \Normalizer::FORM_KC) !== $t) {
            throw new \RangeException('ciba: the payee contains compatibility/fullwidth characters that imitate plain ones');
        }
        if (count(self::scriptsOf($t)) > 1) {
            throw new \RangeException('ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike');
        }
        return $t;
    }

    /** @return array<string,true> the writing-system groups of the letters of `$t` */
    private static function scriptsOf(string $t): array
    {
        $found = [];
        foreach (self::codePoints($t) as $ch) {
            if (preg_match('/\p{L}/u', $ch) !== 1) {
                continue;
            }
            $g = null;
            foreach (self::SCRIPT_GROUPS as $name => $re) {
                if (preg_match($re, $ch) === 1) {
                    $g = $name;
                    break;
                }
            }
            $found[$g ?? 'other:' . $ch] = true;
        }
        return $found;
    }

    /** Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or \u{..} escapes when IDNA refuses). */
    public static function asciiForm(string $payee): string
    {
        $ascii = static fn(string $w): bool => preg_match('/\A[\x20-\x7E]*\z/', $w) === 1;
        if ($ascii($payee)) {
            return $payee;
        }
        $out = [];
        foreach (explode(' ', $payee) as $w) {
            if ($ascii($w)) {
                $out[] = $w;
                continue;
            }
            $a = WhatwgUrl::domainToASCII($w);
            if ($a === '') {
                foreach (self::codePoints($w) as $c) {
                    $cp = strlen($c) === 1 ? ord($c) : (mb_check_encoding($c, 'UTF-8') ? mb_ord($c, 'UTF-8') : self::wtf8Ord($c));
                    $a .= $cp > 0x7e ? sprintf('\\u{%x}', $cp) : $c;
                }
            }
            $out[] = $a;
        }
        return implode(' ', $out);
    }

    private static function wtf8Ord(string $c): int
    {
        return ((ord($c[0]) & 0x0F) << 12) | ((ord($c[1]) & 0x3F) << 6) | (ord($c[2] ?? "\x80") & 0x3F);
    }

    /**
     * The canonical action shown to the approver {verb, resource, amount?, currency?, payee?}. Fails loud: unknown params keys,
     * a nested or malformed amount, a missing currency or payee next to an amount, two payee fields and non-identifier verb /
     * resource all throw.
     * @return array<string,string>
     */
    public static function cibaActionFromStepUp(mixed $stepUp): array
    {
        $params = Js::get($stepUp, 'params') ?? new Obj();
        if (is_array($params) && $params !== [] && !array_is_list($params)) {
            $params = Obj::of($params);
        }
        if (!($params instanceof Obj)) {
            throw new \RangeException('ciba: step-up params must be an object');
        }
        $unknown = array_values(array_filter($params->keys(), static fn(string $k): bool => !in_array($k, self::DISPLAYED_PARAM_KEYS, true)));
        if ($unknown !== []) {
            throw new \RangeException('ciba: step-up params field(s) ' . implode(', ', $unknown) . ' are not displayed in the approval message (displayable: amount, currency, '
                . implode('/', self::PAYEE_KEYS) . '); refusing so the person never approves a hidden field');
        }
        $action = ['verb' => self::identifier(Js::get($stepUp, 'verb'), 'verb'), 'resource' => self::identifier(Js::get($stepUp, 'resource'), 'resource')];
        $payeeKeys = array_values(array_filter(self::PAYEE_KEYS, static fn(string $k): bool => $params->get($k) !== null));
        if (count($payeeKeys) > 1) {
            throw new \RangeException('ciba: more than one payee field (' . implode(', ', $payeeKeys) . ') in params; the approver would see only one');
        }
        $amt = $params->get('amount');
        if ($amt !== null) {
            $f = Js::num($amt);
            $text = $f !== null && is_finite($f) ? Js::stringify($amt) : (is_string($amt) ? $amt : '');
            if (preg_match('/\A(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\z/', $text) !== 1) {
                throw new \RangeException('ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)');
            }
            $cur = $params->get('currency');
            if (!is_string($cur) || preg_match('/\A[A-Za-z]{3}\z/', $cur) !== 1) {
                throw new \RangeException('ciba: the binding message needs a 3-letter currency code next to the amount');
            }
            if ($payeeKeys === []) {
                throw new \RangeException('ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it');
            }
            $action['amount'] = $text;
            $action['currency'] = strtoupper($cur);
        } elseif ($params->get('currency') !== null) {
            throw new \RangeException('ciba: a currency without an amount cannot be displayed');
        }
        if (count($payeeKeys) === 1) {
            $action['payee'] = self::payeeText($params->get($payeeKeys[0]));
        }
        return $action;
    }

    private static function tooLong(int $need, mixed $maxChars): \RangeException
    {
        return new \RangeException("ciba: the binding message needs $need characters but bindingMessage.maxChars is " . self::jsStr($maxChars) . '; refusing to truncate what the person approves');
    }

    /** `Approve <verb> <amount> <CUR> to "<payee>" on <resource>`; only the goal clause may shrink or drop to fit. */
    private static function bindingMessage(mixed $stepUp, string $actsFor, int|float|null $maxChars): string
    {
        $a = self::cibaActionFromStepUp($stepUp);
        $head = "Approve {$a['verb']}" . (isset($a['amount']) ? " {$a['amount']} {$a['currency']}" : '');
        if (isset($a['payee'])) {
            $p = $a['payee'];
            $head .= " to \"$p\"" . (preg_match('/\A[\x20-\x7E]*\z/', $p) === 1 ? '' : ' [non-ASCII name; ASCII form: ' . self::asciiForm($p) . ']');
        }
        $head .= " on {$a['resource']}";
        $limit = $maxChars ?? INF;
        $hl = count(self::codePoints($head));
        if ($hl > $limit) {
            throw self::tooLong($hl, $maxChars);
        }
        $plainGoal = '';
        if (Js::has($stepUp, 'goal')) {
            $g = Js::get($stepUp, 'goal');
            if (!is_string($g)) {
                throw new \TypeError('value.replace is not a function');
            }
            $plainGoal = str_replace(["'", "\u{2018}", "\u{2019}"], "\u{2032}", self::plainText($g));
        }
        $goalText = null;
        if ($plainGoal !== '') {
            $goalText = self::clip($plainGoal, self::MAX_GOAL_CHARS);
        } else {
            $gc = Js::get($stepUp, 'goalCommit');
            if ($gc === null) {
                throw new \TypeError("Cannot read properties of undefined (reading 'length')");
            }
            if (is_string($gc) && $gc !== '') {
                $goalText = 'goal ' . self::slice16($gc, 10) . '…';
            } elseif (is_array($gc) && array_is_list($gc) && $gc !== []) {
                // shortcut: a non-empty array commitment would render as its JS join; refused instead (never a real commitment)
                throw new \RangeException('ciba: the goal commitment must be a string');
            }
        }
        if ($goalText === null) {
            return $head;
        }
        $prefix = " — because you asked $actsFor to '";
        $room = $limit - count(self::codePoints($head . $prefix)) - 1;
        if ($room >= count(self::codePoints($goalText))) {
            return "$head$prefix$goalText'";
        }
        if ($room >= 8) {
            return $head . $prefix . self::clip($goalText, (int)$room) . "'";
        }
        return $head;
    }

    private static function tokenise(string $v): string
    {
        $v = (string)preg_replace('/[^A-Za-z0-9._-]+/', '-', $v);
        $v = (string)preg_replace('/-{2,}/', '-', $v);
        return (string)preg_replace('/\A[-.]+|[-.]+\z/', '', $v);
    }

    /** `Approve-<verb>-<amount>-<CUR>-to-<payee>-<resource>`, all-or-nothing within `$maxChars`. */
    private static function compactBindingMessage(mixed $stepUp, int|float $maxChars): string
    {
        $a = self::cibaActionFromStepUp($stepUp);
        if (isset($a['payee']) && preg_match('/\A[\x20-\x7E]+\z/', $a['payee']) !== 1) {
            throw new \RangeException('ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)');
        }
        $raw = ['Approve', $a['verb']];
        if (isset($a['amount'])) {
            array_push($raw, $a['amount'], $a['currency']);
        }
        if (isset($a['payee'])) {
            array_push($raw, 'to', $a['payee']);
        }
        $raw[] = $a['resource'];
        $parts = array_map(self::tokenise(...), $raw);
        if (in_array('', $parts, true)) {
            throw new \RangeException('ciba: tokenOnly binding message cannot represent the verb, payee or resource');
        }
        $out = implode('-', $parts);
        if (strlen($out) > $maxChars) {
            throw self::tooLong(strlen($out), $maxChars);
        }
        return $out;
    }

    /**
     * Map a PCA step-up to a CIBA backchannel auth request. Pure: a stable auth_req_id derived from the step-up id (NOT secret;
     * a broker supplies a random one), the binding message, scope, expiry and poll interval. Options (reference names):
     * expiresInSec, authReqId, stepUpScope, loginHint, bindingMessage {maxChars, tokenOnly}, interval, actsFor.
     * @return array<string,mixed>
     */
    public static function toCibaAuthRequest(mixed $stepUp, mixed $opts = []): array
    {
        if ($opts === null) {
            throw new \TypeError("Cannot read properties of null (reading 'actsFor')");
        }
        $actsFor = 'your agent';
        if (Js::has($opts, 'actsFor')) {
            $af = Js::opt($opts, 'actsFor');
            if (!is_string($af)) {
                throw new \TypeError('value.replace is not a function');
            }
            $p = self::plainText($af);
            if ($p !== '') {
                $actsFor = self::clip($p, 40);
            }
        }
        $expiry = Js::has($opts, 'expiresInSec') ? Js::opt($opts, 'expiresInSec') : self::DEFAULT_EXPIRY_SEC;
        if (!self::safeInt($expiry) || Js::num($expiry) <= 0) {
            throw new \RangeException('ciba: requested_expiry must be a positive integer number of seconds, got ' . self::jsStr($expiry));
        }
        $verb = Js::get($stepUp, 'verb');
        $stepUpScope = 'urn:atlas:pca:stepup:' . (Js::has($stepUp, 'verb') ? self::jsStr($verb) : 'undefined');
        if (preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+\z/', $stepUpScope) !== 1) {
            throw new \RangeException('ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)');
        }
        $scope = Js::opt($opts, 'stepUpScope') === false ? 'openid' : "openid $stepUpScope";
        $interval = Js::has($opts, 'interval') ? Js::opt($opts, 'interval') : self::DEFAULT_INTERVAL_SEC;
        if (!self::safeInt($interval) || Js::num($interval) <= 0) {
            throw new \RangeException('ciba: interval must be a positive integer number of seconds, got ' . self::jsStr($interval));
        }
        $id = Js::opt($opts, 'authReqId');
        if ($id === null) {
            if (!Js::has($stepUp, 'id')) {
                throw new JsonError('canonicalize: unsupported type undefined');
            }
            $id = IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/ciba/auth_req_id/v1', 'stepUp' => Js::get($stepUp, 'id')]));
        }
        // the reference tests String(id) against the charset and reads .length (undefined for a non-string)
        $re = '/\A[A-Za-z0-9._-]+\z/';
        $okId = is_string($id) ? preg_match($re, $id) === 1 && Js::len($id) >= self::MIN_AUTH_REQ_ID_LEN && Js::len($id) <= 1024
            : ((is_bool($id) || Js::isNum($id)) && preg_match($re, self::jsStr($id)) === 1);
        if (!$okId) {
            throw new \RangeException('ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)');
        }
        $bm = Js::opt($opts, 'bindingMessage');
        $hasMax = Js::has($bm, 'maxChars');
        if ($hasMax && (!self::safeInt(Js::opt($bm, 'maxChars')) || Js::num(Js::opt($bm, 'maxChars')) < 1)) {
            throw new \RangeException('ciba: bindingMessage.maxChars must be a positive integer');
        }
        $maxChars = $hasMax ? (int)Js::num(Js::opt($bm, 'maxChars')) : 50;
        $hasR = Js::has($stepUp, 'render');
        $hasD = Js::has($stepUp, 'renderDigest');
        $words = null;
        if ($hasR || $hasD) {
            if (!$hasR || !$hasD || Approval::renderDigest(Js::get($stepUp, 'render')) !== Js::get($stepUp, 'renderDigest')) {
                throw new \RangeException('ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else');
            }
            $words = Approval::bindingWords(Js::get($stepUp, 'renderDigest'));
        }
        $reserve = $words === null ? 0 : strlen($words) + 14;
        $tokenOnly = Js::opt($bm, 'tokenOnly') === true;
        $msg = $tokenOnly ? self::compactBindingMessage($stepUp, $maxChars - $reserve)
            : self::bindingMessage($stepUp, $actsFor, $hasMax ? $maxChars - $reserve : null);
        if ($words !== null) {
            $msg = $tokenOnly ? "$msg-match-$words" : "$msg [match code $words]";
        }
        $out = ['auth_req_id' => $id, 'binding_message' => $msg, 'scope' => $scope, 'requested_expiry' => $expiry, 'interval' => $interval];
        if (Js::has($opts, 'loginHint')) {
            $out['login_hint'] = Js::opt($opts, 'loginHint');
        }
        if (Js::has($stepUp, 'id')) {
            $out['stepUpId'] = Js::get($stepUp, 'id');
        }
        if (Js::has($stepUp, 'tier')) {
            $out['tier'] = Js::get($stepUp, 'tier');
        }
        if ($hasR && $hasD) {
            $rd = Js::get($stepUp, 'renderDigest');
            $out['authorization_details'] = [['type' => 'pca_approval', 'render' => Js::get($stepUp, 'render'), 'render_digest' => $rd]];
            $out['render_digest'] = $rd;
        }
        return $out;
    }

    /** The gate: only a tier-3 step-up (human required) needs a CIBA round trip; tier 2 and auto / deny never notify a person. */
    public static function requiresCiba(mixed $review): bool
    {
        if (Js::get($review, 'kind') !== 'step_up') {
            return false;
        }
        $r = Js::get($review, 'request');
        if ($r === null) {
            throw new \TypeError("Cannot read properties of undefined (reading 'tier')");
        }
        $t = Js::opt($r, 'tier');
        return Js::isNum($t) && Js::num($t) === 3.0;
    }

    /**
     * Fold a settled decision into the trust budget: approve recharges (rho, or bMax with {full: true}), anything else leaves the
     * budget unchanged. Budget-level only: the threshold cosign that authorises a tier-3 action is verified elsewhere.
     * @return array{budget:mixed,cosigned:bool}
     */
    public static function cibaDecisionToCosign(mixed $decision, mixed $budget, mixed $policy, mixed $now, mixed $opts = []): array
    {
        if ($decision !== 'approve') {
            return ['budget' => $budget, 'cosigned' => false];
        }
        $nz = static fn(mixed $x): float => ($f = Js::num($x)) !== null && is_finite($f) && $f > 0 ? $f : 0.0;
        $bMax = $nz(Js::get($policy, 'bMax'));
        if (Js::truthy(Js::get($opts, 'full'))) {
            $b = $bMax;
        } else {
            $sum = (Js::num(Js::get($budget, 'B')) ?? NAN) + $nz(Js::get($policy, 'rho'));
            $b = is_nan($sum) ? NAN : min($bMax, $sum); // Math.min: NaN wins
        }
        return ['budget' => ['B' => $b, 'tau' => $now, 'asOf' => $now], 'cosigned' => true];
    }

    /** A fresh client_notification_token: 256 random bits, base64url. */
    public static function newClientNotificationToken(): string
    {
        return Pca::b64u(random_bytes(32));
    }

    /** A network client for an OpenID Provider's CIBA endpoints (see CibaClient). */
    public static function createCibaClient(mixed $cfg): CibaClient
    {
        return new CibaClient($cfg);
    }

    /**
     * Validate a PING callback (CIBA Core 10.2): `Authorization: Bearer <client_notification_token>` (constant-time compare) and
     * a JSON body {auth_req_id} naming this flow. Returns the auth_req_id; throws otherwise. Carries no decision: poll next.
     */
    public static function verifyPingCallback(mixed $input, mixed $flow): string
    {
        if (!Js::has($flow, 'clientNotificationToken')) {
            throw new \RuntimeException('ciba: flow was not started in ping mode');
        }
        // RegExp.exec coerces a non-string header with String(); a lone surrogate fails the /u match (refused)
        $auth = self::jsStr(Js::get($input, 'authorization') ?? '');
        if (preg_match('/\\Abearer +([^' . self::WS . ']+)\\z/iu', $auth, $m) !== 1) {
            throw new \RuntimeException('ciba: ping callback lacks a bearer token');
        }
        $tok = Js::get($flow, 'clientNotificationToken');
        if (!is_string($tok)) {
            throw new \TypeError('ciba: the flow client_notification_token is not a string');
        }
        if (!hash_equals(hash('sha256', Js::utf8($tok), true), hash('sha256', Js::utf8($m[1]), true))) {
            throw new \RuntimeException('ciba: ping callback bearer does not match the client_notification_token');
        }
        $body = Js::get($input, 'body');
        $id = Js::isObj($body) ? Js::opt($body, 'auth_req_id') : null;
        if (!is_string($id) || $id !== Js::opt($flow, 'authReqId')) {
            throw new \RuntimeException('ciba: ping callback auth_req_id does not match this flow');
        }
        return $id;
    }

    /** A fresh random auth_req_id (160 bits, base64url; CIBA Core 7.3). */
    public static function randomAuthReqId(): string
    {
        return Pca::b64u(random_bytes(20));
    }

    /** Copy request options and set the broker's random auth_req_id. */
    public static function withAuthReqId(mixed $opts, string $id): Obj
    {
        $o = new Obj();
        if ($opts instanceof Obj) {
            foreach ($opts->keys() as $k) {
                $o->set($k, $opts->get($k));
            }
        } elseif (is_array($opts) && !array_is_list($opts)) {
            foreach ($opts as $k => $v) {
                $o->set((string)$k, $v);
            }
        }
        $o->set('authReqId', $id);
        return $o;
    }
}

// ---- persistence ----------------------------------------------------------------------------------------------------------

/**
 * A JSON key-value store with compare-and-set. `get` returns ['version' => int, 'value' => mixed] or null (absent = version
 * 0); `cas` writes only when the stored version equals `$expectedVersion` and bumps it by one. Back it with a row version
 * (`UPDATE ... WHERE version = ?`) for several processes.
 */
interface ApprovalStore
{
    public function get(string $key): ?array;

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool;
}

/** A durable string KV with an atomic compare-and-swap (`$expected` null = the key must be absent); any failure must throw. */
interface DurableKv
{
    public function get(string $key): ?string;

    public function putIfEquals(string $key, ?string $expected, string $next): bool;
}

/** Thrown by the store implementations: code corrupt_record | lock_timeout | bad_key. */
final class ApprovalStoreError extends \RuntimeException
{
    public readonly string $errorCode;

    public function __construct(string $code, string $message)
    {
        parent::__construct($message);
        $this->errorCode = $code;
        $this->code = $code;
    }
}

/** Deep copy of a JSON value (structuredClone for the JSON model). */
function ciba_clone(mixed $v): mixed
{
    return $v === null || is_scalar($v) ? $v : Js::parse(Js::stringify($v));
}

/** Single-process ApprovalStore test double. Not durable. */
final class MemoryApprovalStore implements ApprovalStore
{
    /** @var array<string,array{version:int|float,value:mixed}> */
    private array $m = [];

    public function get(string $key): ?array
    {
        $v = $this->m[$key] ?? null;
        return $v === null ? null : ['version' => $v['version'], 'value' => ciba_clone($v['value'])];
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        if (($this->m[$key]['version'] ?? 0) != $expectedVersion) {
            return false;
        }
        $this->m[$key] = ['version' => $expectedVersion + 1, 'value' => ciba_clone($value)];
        return true;
    }
}

/** Single-process DurableKv test double. Not durable. */
final class MemoryKv implements DurableKv
{
    /** @var array<string,string> */
    private array $m = [];

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function putIfEquals(string $key, ?string $expected, string $next): bool
    {
        if (($this->m[$key] ?? null) !== $expected) {
            return false;
        }
        $this->m[$key] = $next;
        return true;
    }
}

/** One JSON file, rewritten atomically (temp file + rename) on each write. Correct for ONE process at a time. */
final class FileApprovalStore implements ApprovalStore
{
    public function __construct(private readonly string $path)
    {
    }

    private function load(): Obj
    {
        if (!file_exists($this->path)) {
            return new Obj();
        }
        $raw = file_get_contents($this->path);
        $p = $raw === false ? null : Js::parse($raw); // a corrupt file throws: fail closed
        if (!($p instanceof Obj)) {
            throw new \RuntimeException('ciba: approval store file is corrupt');
        }
        return $p;
    }

    public function get(string $key): ?array
    {
        $v = $this->load()->get($key);
        return $v === null ? null : ['version' => Js::num(Js::opt($v, 'version')) ?? 0, 'value' => Js::opt($v, 'value')];
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        $all = $this->load();
        if ((Js::num(Js::opt($all->get($key), 'version')) ?? 0) != $expectedVersion) {
            return false;
        }
        $all->set($key, Obj::of(['version' => $expectedVersion + 1, 'value' => $value]));
        $tmp = $this->path . '.' . getmypid() . '.tmp';
        if (PrivateFile::write($tmp, Js::stringify($all)) === false || !rename($tmp, $this->path)) {
            throw new \RuntimeException('ciba: could not write the approval store file');
        }
        return true;
    }
}

/**
 * An ApprovalStore over a DurableKv: each key holds {"version","value"} as JSON; `cas` swaps only when the raw text is still
 * the one it read, so two processes racing on one version cannot both win. A value that is not a versioned record throws
 * corrupt_record.
 */
final class KvApprovalStore implements ApprovalStore
{
    public function __construct(private readonly DurableKv $kv)
    {
    }

    private static function decode(string $raw): array
    {
        try {
            $r = Js::parse($raw);
        } catch (\Throwable) {
            throw new ApprovalStoreError('corrupt_record', 'ciba: stored approval record is not valid JSON');
        }
        $v = $r instanceof Obj ? $r->get('version') : null;
        $f = Js::num($v);
        if (!($r instanceof Obj) || $f === null || !is_finite($f) || floor($f) !== $f || $f < 1 || !$r->has('value')) {
            throw new ApprovalStoreError('corrupt_record', 'ciba: stored approval record has no valid version');
        }
        return ['version' => abs($f) < 9.0e15 ? (int)$f : $f, 'value' => $r->get('value')];
    }

    public function get(string $key): ?array
    {
        $raw = $this->kv->get($key);
        return $raw === null ? null : self::decode($raw);
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        $raw = $this->kv->get($key);
        $current = $raw === null ? 0 : self::decode($raw)['version'];
        if ($current != $expectedVersion) {
            return false;
        }
        return $this->kv->putIfEquals($key, $raw, Js::stringify(Obj::of(['version' => $expectedVersion + 1, 'value' => $value]))) === true;
    }
}

/**
 * A DurableKv on a directory, safe for several processes on ONE host: one file per key (the key is hashed into the name), a
 * per-key lock file (exclusive create), compare, fsync'd temp file, rename. A stale lock left by a dead process makes every
 * later swap on that key throw lock_timeout (fail closed) until an operator removes the .lock file.
 */
final class DirectoryKv implements DurableKv
{
    private readonly int|float $timeoutMs;

    public function __construct(private readonly string $dir, mixed $opts = [])
    {
        $t = Js::opt($opts, 'lockTimeoutMs') ?? 5000;
        $f = Js::num($t);
        if ($f === null || !is_finite($f) || $f <= 0) {
            throw new \InvalidArgumentException('createDirectoryKv: lockTimeoutMs must be a positive number');
        }
        $this->timeoutMs = $f;
        if (!PrivateFile::mkdir($dir, true)) {
            throw new \RuntimeException('ciba: could not create the store directory');
        }
    }

    private function fileOf(string $key): string
    {
        if ($key === '') {
            throw new ApprovalStoreError('bad_key', 'ciba: store key must be a non-empty string');
        }
        return $this->dir . DIRECTORY_SEPARATOR . hash('sha256', $key);
    }

    public function get(string $key): ?string
    {
        $f = $this->fileOf($key);
        if (!file_exists($f)) {
            return null;
        }
        $raw = file_get_contents($f);
        if ($raw === false) {
            throw new \RuntimeException('ciba: could not read the store');
        }
        return $raw;
    }

    public function putIfEquals(string $key, ?string $expected, string $next): bool
    {
        $f = $this->fileOf($key);
        $lock = "$f.lock";
        $deadline = self::clock() * 1000 + $this->timeoutMs;
        while (($fd = PrivateFile::open($lock, 'x')) === false) {
            if (!file_exists($lock)) {
                throw new \RuntimeException('ciba: could not take the store lock');
            }
            if (self::clock() * 1000 >= $deadline) {
                throw new ApprovalStoreError('lock_timeout', 'ciba: could not take the store lock in time');
            }
            usleep(2000);
        }
        try {
            $current = file_exists($f) ? file_get_contents($f) : null;
            if ($current === false) {
                throw new \RuntimeException('ciba: could not read the store');
            }
            if ($current !== $expected) {
                return false;
            }
            $tmp = "$f." . getmypid() . '.tmp';
            $t = PrivateFile::open($tmp, 'w');
            if ($t === false) {
                throw new \RuntimeException('ciba: could not write the store');
            }
            try {
                if (fwrite($t, $next) !== strlen($next) || !fflush($t) || !fsync($t)) { // durable before the rename publishes it
                    throw new \RuntimeException('ciba: could not write the store');
                }
            } finally {
                fclose($t);
            }
            if (!rename($tmp, $f)) {
                throw new \RuntimeException('ciba: could not write the store');
            }
            return true;
        } finally {
            fclose($fd);
            unlink($lock);
        }
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}

// ---- brokers ----------------------------------------------------------------------------------------------------------------

/** The broker contract (CIBA lifecycle): start, poll (status read), token (CIBA Core 11 semantics), resolve, get. */
interface CibaBrokerInterface
{
    /** @return array<string,mixed> the CIBA auth request */
    public function start(mixed $stepUp, mixed $opts = null): array;

    /** @return array{status:string} */
    public function poll(string $authReqId): array;

    /** @return array<string,mixed> {ok: true, session} | {ok: false, error, interval} */
    public function token(string $authReqId): array;

    /** @return array<string,mixed> the session after the decision */
    public function resolve(string $authReqId, mixed $decision, mixed $by): array;

    /** @return ?array<string,mixed> */
    public function get(string $authReqId): ?array;
}

/** Shared record logic of both brokers: records are JSON objects (Obj). */
abstract class CibaBrokerBase implements CibaBrokerInterface
{
    /** @var \Closure():(int|float) */
    protected \Closure $clock;
    /** @var ?\Closure(array):mixed */
    protected ?\Closure $onComplete;

    protected function __construct(mixed $opts)
    {
        $now = Js::opt($opts, 'now');
        $this->clock = $now !== null ? \Closure::fromCallable($now) : static fn(): int => (int)floor(microtime(true) * 1000);
        $oc = Js::opt($opts, 'onComplete');
        $this->onComplete = $oc !== null ? \Closure::fromCallable($oc) : null;
    }

    protected static function n(mixed $r, string $k): float
    {
        return Js::num(Js::opt($r, $k)) ?? NAN;
    }

    abstract protected function status(Obj $r, int|float $now): string;

    /** @return array<string,mixed> */
    protected function snap(Obj $r, int|float $now): array
    {
        $req = $r->get('request');
        $s = ['auth_req_id' => Js::opt($req, 'auth_req_id'), 'request' => $req, 'status' => $this->status($r, $now), 'createdAt' => $r->get('createdAt'), 'expiresAt' => $r->get('expiresAt')];
        if ($r->has('decidedBy')) {
            $s['decidedBy'] = $r->get('decidedBy');
        }
        if ($r->has('decidedAt')) {
            $s['decidedAt'] = $r->get('decidedAt');
        }
        return $s;
    }

    protected static function newRecord(array $request, int|float $now): Obj
    {
        return Obj::of(['request' => $request, 'createdAt' => $now, 'expiresAt' => $now + Js::num($request['requested_expiry']) * 1000, 'interval' => $request['interval']]);
    }

    /** CIBA Core 11 token-endpoint step on a loaded record (mutates it). @return array<string,mixed> */
    protected function tokenStep(Obj $r, int|float $now): array
    {
        $interval = self::n($r, 'interval');
        if (Js::truthy($r->get('consumed'))) {
            return ['ok' => false, 'error' => 'invalid_grant', 'interval' => $r->get('interval')];
        }
        $tooSoon = $r->has('lastPollAt') && $now - self::n($r, 'lastPollAt') < $interval * 1000;
        $r->set('lastPollAt', $now);
        if ($tooSoon) {
            $r->set('interval', $interval + 5);
            return ['ok' => false, 'error' => 'slow_down', 'interval' => $interval + 5];
        }
        $st = $this->status($r, $now);
        $err = ['pending' => 'authorization_pending', 'denied' => 'access_denied', 'expired' => 'expired_token'][$st] ?? null;
        if ($err !== null) {
            return ['ok' => false, 'error' => $err, 'interval' => $r->get('interval')];
        }
        $r->set('consumed', true); // single use: a replayed approval gets invalid_grant
        return ['ok' => true, 'session' => $this->snap($r, $now)];
    }
}

/**
 * The in-memory CIBA broker (a single-process test double: loses everything on restart). POLL (the caller drives poll / token)
 * and PING/PUSH (onComplete fires synchronously on resolution; a throwing notifier propagates). An approval never expires here.
 */
final class CibaBroker extends CibaBrokerBase
{
    /** @var array<string,Obj> */
    private array $sessions = [];
    /** @var array<string,string> step-up id -> auth_req_id of its live flow */
    private array $live = [];

    public function __construct(mixed $opts = [])
    {
        parent::__construct($opts);
    }

    protected function status(Obj $r, int|float $now): string
    {
        $d = $r->get('decision');
        if ($d === 'approve') {
            return 'approved';
        }
        if ($d === 'deny') {
            return 'denied';
        }
        return !(is_finite($now) && $now < self::n($r, 'expiresAt')) ? 'expired' : 'pending';
    }

    public function start(mixed $stepUp, mixed $opts = null): array
    {
        $now = ($this->clock)();
        $sid = Ciba::jsStr(Js::get($stepUp, 'id'));
        $ex = isset($this->live[$sid]) ? ($this->sessions[$this->live[$sid]] ?? null) : null;
        if ($ex !== null && in_array($this->status($ex, $now), ['pending', 'approved'], true)) {
            return $ex->get('request');
        }
        $request = Ciba::toCibaAuthRequest($stepUp, Ciba::withAuthReqId($opts, Ciba::randomAuthReqId()));
        $this->sessions[$request['auth_req_id']] = self::newRecord($request, $now);
        $this->live[$sid] = $request['auth_req_id'];
        return $request;
    }

    private function must(string $id): Obj
    {
        return $this->sessions[$id] ?? throw new \RuntimeException("ciba: unknown auth_req_id $id");
    }

    public function poll(string $authReqId): array
    {
        return ['status' => $this->status($this->must($authReqId), ($this->clock)())];
    }

    public function token(string $authReqId): array
    {
        $s = $this->sessions[$authReqId] ?? null;
        return $s === null ? ['ok' => false, 'error' => 'invalid_grant', 'interval' => Ciba::DEFAULT_INTERVAL_SEC] : $this->tokenStep($s, ($this->clock)());
    }

    public function resolve(string $authReqId, mixed $decision, mixed $by): array
    {
        $s = $this->must($authReqId);
        $now = ($this->clock)();
        $cur = $this->status($s, $now);
        if ($cur !== 'pending') {
            throw new \RuntimeException("ciba: cannot resolve $authReqId — already $cur");
        }
        $s->set('decision', $decision);
        $s->set('decidedBy', $by);
        $s->set('decidedAt', $now);
        $snap = $this->snap($s, $now);
        if ($this->onComplete !== null) {
            ($this->onComplete)($snap);
        }
        return $snap;
    }

    public function get(string $authReqId): ?array
    {
        $s = $this->sessions[$authReqId] ?? null;
        return $s === null ? null : $this->snap($s, ($this->clock)());
    }
}

/**
 * The durable approval broker: state behind an ApprovalStore (compare-and-set), so a restart or a second process cannot lose,
 * double-apply or replay a decision. Options: store (required), now, decisionTtlSec (default 300: an approval stays redeemable
 * that long, then reads expired), onComplete (a throw does not undo the decision).
 */
final class DurableCibaBroker extends CibaBrokerBase
{
    private const MAX_CAS_TRIES = 8;
    private readonly ApprovalStore $store;
    private readonly float $ttlMs;

    public function __construct(mixed $opts)
    {
        $store = Js::opt($opts, 'store');
        if (!($store instanceof ApprovalStore)) {
            throw new \InvalidArgumentException('createDurableCibaBroker: `store` is required');
        }
        parent::__construct($opts);
        $this->store = $store;
        $ttl = Js::opt($opts, 'decisionTtlSec') ?? 300;
        $f = Js::num($ttl);
        $ttlMs = $f === null ? NAN : $f * 1000;
        if (!is_finite($ttlMs) || $ttlMs <= 0) {
            throw new \InvalidArgumentException('createDurableCibaBroker: decisionTtlSec must be a positive number');
        }
        $this->ttlMs = $ttlMs;
    }

    protected function status(Obj $r, int|float $now): string
    {
        $d = $r->get('decision');
        if ($d === 'deny') {
            return 'denied';
        }
        if ($d === 'approve') {
            return !(is_finite($now) && $now < self::n($r, 'decidedAt') + $this->ttlMs) ? 'expired' : 'approved';
        }
        return !(is_finite($now) && $now < self::n($r, 'expiresAt')) ? 'expired' : 'pending';
    }

    private static function asRec(mixed $v): Obj
    {
        $fin = static fn(mixed $x): bool => Js::isNum($x) && is_finite(Js::num($x));
        if (!($v instanceof Obj) || !is_string(Js::opt($v->get('request'), 'auth_req_id')) || !$fin($v->get('createdAt')) || !$fin($v->get('expiresAt')) || !$fin($v->get('interval'))) {
            throw new \RuntimeException('ciba: stored approval record is malformed');
        }
        return $v;
    }

    /** @return ?array{rec:Obj,version:int|float} */
    private function load(string $id): ?array
    {
        $v = $this->store->get("a:$id");
        return $v === null ? null : ['rec' => self::asRec(ciba_clone($v['value'])), 'version' => $v['version']];
    }

    /** Read-modify-write with CAS retry; `$fn(?Obj, now)` returns [next record or null for no write, result]. */
    private function mutate(string $id, callable $fn): mixed
    {
        for ($i = 0; $i < self::MAX_CAS_TRIES; $i++) {
            $cur = $this->load($id);
            [$next, $out] = $fn($cur['rec'] ?? null, ($this->clock)());
            if ($next === null || $this->store->cas("a:$id", $cur['version'] ?? 0, $next)) {
                return $out;
            }
        }
        throw new \RuntimeException('ciba: approval store contention, gave up');
    }

    public function start(mixed $stepUp, mixed $opts = null): array
    {
        $liveKey = 's:' . (Js::has($stepUp, 'id') ? Ciba::jsStr(Js::get($stepUp, 'id')) : 'undefined');
        for ($i = 0; $i < self::MAX_CAS_TRIES; $i++) {
            $now = ($this->clock)();
            $idx = $this->store->get($liveKey);
            if ($idx !== null) {
                $ex = $this->load(Ciba::jsStr($idx['value']));
                // never reset a flow that is still waiting or already approved: that would discard a decision
                if ($ex !== null && in_array($this->status($ex['rec'], $now), ['pending', 'approved'], true) && !Js::truthy($ex['rec']->get('consumed'))) {
                    return self::plain($ex['rec']->get('request'));
                }
            }
            $request = Ciba::toCibaAuthRequest($stepUp, Ciba::withAuthReqId($opts, Ciba::randomAuthReqId()));
            if (!$this->store->cas('a:' . $request['auth_req_id'], 0, self::newRecord($request, $now))) {
                continue;
            }
            if ($this->store->cas($liveKey, $idx['version'] ?? 0, $request['auth_req_id'])) {
                return $request;
            }
        }
        throw new \RuntimeException('ciba: approval store contention, gave up');
    }

    /** A stored request (Obj) as the assoc array start() returns. */
    private static function plain(mixed $v): array
    {
        $a = [];
        foreach ($v instanceof Obj ? $v->keys() : array_keys((array)$v) as $k) {
            $a[$k] = Js::opt($v, (string)$k);
        }
        return $a;
    }

    public function poll(string $authReqId): array
    {
        $c = $this->load($authReqId) ?? throw new \RuntimeException("ciba: unknown auth_req_id $authReqId");
        return ['status' => $this->status($c['rec'], ($this->clock)())];
    }

    public function token(string $authReqId): array
    {
        return $this->mutate($authReqId, function (?Obj $r, int|float $now): array {
            if ($r === null) {
                return [null, ['ok' => false, 'error' => 'invalid_grant', 'interval' => Ciba::DEFAULT_INTERVAL_SEC]];
            }
            if (Js::truthy($r->get('consumed'))) {
                return [null, ['ok' => false, 'error' => 'invalid_grant', 'interval' => $r->get('interval')]];
            }
            return [$r, $this->tokenStep($r, $now)];
        });
    }

    public function resolve(string $authReqId, mixed $decision, mixed $by): array
    {
        if ($decision !== 'approve' && $decision !== 'deny') {
            throw new \InvalidArgumentException('ciba: decision must be "approve" or "deny"');
        }
        if (!is_string($by) || $by === '') {
            throw new \InvalidArgumentException('ciba: `by` (the authenticated decider) is required');
        }
        $session = $this->mutate($authReqId, function (?Obj $r, int|float $now) use ($authReqId, $decision, $by): array {
            if ($r === null) {
                throw new \RuntimeException("ciba: unknown auth_req_id $authReqId");
            }
            $cur = $this->status($r, $now);
            if ($cur !== 'pending') {
                throw new \RuntimeException("ciba: cannot resolve $authReqId — already $cur");
            }
            $r->set('decision', $decision);
            $r->set('decidedBy', $by);
            $r->set('decidedAt', $now);
            return [$r, $this->snap($r, $now)];
        });
        if ($this->onComplete !== null) {
            try {
                ($this->onComplete)($session);
            } catch (\Throwable) {
                // the decision is already recorded; a failing notifier must not undo or hide it
            }
        }
        return $session;
    }

    public function get(string $authReqId): ?array
    {
        $c = $this->load($authReqId);
        return $c === null ? null : $this->snap($c['rec'], ($this->clock)());
    }
}

// ---- the network client -------------------------------------------------------------------------------------------------

/** An error answer from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed / failed reply (`retryable`). */
final class CibaProviderError extends \RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $error,
        public readonly ?string $errorDescription = null,
        public readonly bool $retryable = false,
    ) {
        parent::__construct("ciba: provider returned $status $error" . ($errorDescription !== null ? " ($errorDescription)" : ''));
    }
}

/**
 * The relying-party side of CIBA against a real OP: initiate a backchannel request and wait for the decision by POLL or PING.
 * Config (reference names): backchannelAuthenticationEndpoint, tokenEndpoint, clientId, clientSecret (client_secret_basic),
 * fetch (callable(string $url, array $init{method, headers, body, timeoutMs}): array{status:int, body:string}; default: PHP
 * streams), sleep (callable(int|float $ms)), now (ms clock), timeoutMs (default 30000), allowInsecureHttp (local tests only).
 * The returned tokens are the OP's answer, unverified: verify the ID token before relying on it.
 */
final class CibaClient
{
    public const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';
    private const MIN_NOTIFICATION_TOKEN_CHARS = 22;
    private const MAX_NOTIFICATION_TOKEN_CHARS = 1024;

    /** @var \Closure(string,array):array */
    private \Closure $fetch;
    /** @var \Closure(int|float):void */
    public readonly \Closure $sleep;
    /** @var \Closure():(int|float) */
    public readonly \Closure $clock;
    private readonly int|float $timeoutMs;
    private readonly string $basic;
    private readonly string $bcEndpoint;
    private readonly string $tokenEndpoint;

    public function __construct(mixed $cfg)
    {
        $f = Js::opt($cfg, 'fetch');
        $this->fetch = $f !== null ? \Closure::fromCallable($f) : self::streamFetch(...);
        $s = Js::opt($cfg, 'sleep');
        $this->sleep = $s !== null ? \Closure::fromCallable($s) : static function (int|float $ms): void {
            usleep((int)max(0, $ms * 1000));
        };
        $n = Js::opt($cfg, 'now');
        $this->clock = $n !== null ? \Closure::fromCallable($n) : static fn(): int => (int)floor(microtime(true) * 1000);
        $t = Js::opt($cfg, 'timeoutMs') ?? 30000;
        if (!Js::isNum($t) || !is_finite(Js::num($t)) || Js::num($t) <= 0) {
            throw new \RangeException('ciba: timeoutMs must be a positive number');
        }
        $this->timeoutMs = Js::num($t);
        $insecure = Js::opt($cfg, 'allowInsecureHttp') === true;
        $this->bcEndpoint = self::checkEndpoint('backchannelAuthenticationEndpoint', Js::opt($cfg, 'backchannelAuthenticationEndpoint'), $insecure);
        $this->tokenEndpoint = self::checkEndpoint('tokenEndpoint', Js::opt($cfg, 'tokenEndpoint'), $insecure);
        $enc = static fn(string $k): string => Js::encodeURIComponent(Js::has($cfg, $k) ? Ciba::jsStr(Js::opt($cfg, $k)) : 'undefined');
        $this->basic = 'Basic ' . base64_encode($enc('clientId') . ':' . $enc('clientSecret'));
    }

    private static function checkEndpoint(string $name, mixed $value, bool $allowInsecure): string
    {
        $u = is_string($value) ? WhatwgUrl::parse($value) : null;
        if ($u === null) {
            throw new \RangeException("ciba: $name is not a valid URL");
        }
        if ($u['scheme'] === 'https' || ($u['scheme'] === 'http' && $allowInsecure)) {
            return $value;
        }
        throw new \RangeException("ciba: $name must be an https:// URL (set allowInsecureHttp only for a local test provider)");
    }

    /** The default transport (PHP streams, no redirects, the timeout as the stream timeout). */
    private static function streamFetch(string $url, array $init): array
    {
        $hdr = '';
        foreach ($init['headers'] as $k => $v) {
            $hdr .= "$k: $v\r\n";
        }
        $ctx = stream_context_create(['http' => ['method' => $init['method'], 'header' => $hdr, 'content' => $init['body'], 'ignore_errors' => true,
            'follow_location' => 0, 'timeout' => $init['timeoutMs'] / 1000]]);
        $body = @file_get_contents($url, false, $ctx);
        $line = $http_response_header[0] ?? '';
        if ($body === false || preg_match('#\AHTTP/\S+ ([0-9]{3})#', $line, $m) !== 1) {
            throw new \RuntimeException('request failed');
        }
        return ['status' => (int)$m[1], 'body' => $body];
    }

    /** application/x-www-form-urlencoded (URLSearchParams) of ordered [name, value] pairs. @param list<array{0:string,1:string}> $pairs */
    public static function form(array $pairs): string
    {
        $e = static fn(string $s): string => strtr(urlencode(Js::utf8($s)), ['%2A' => '*']);
        return implode('&', array_map(static fn(array $p): string => $e($p[0]) . '=' . $e($p[1]), $pairs));
    }

    /** One POST to the OP; a transport failure becomes a retryable network_error. @return array{status:int,body:string} */
    public function post(string $url, array $pairs): array
    {
        try {
            $r = ($this->fetch)($url, ['method' => 'POST', 'headers' => ['authorization' => $this->basic, 'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json'],
                'body' => self::form($pairs), 'timeoutMs' => $this->timeoutMs]);
        } catch (\Throwable $e) {
            throw new CibaProviderError(0, 'network_error', $e->getMessage(), true);
        }
        return ['status' => (int)Js::num(Js::opt($r, 'status') ?? 0), 'body' => Ciba::jsStr(Js::opt($r, 'body') ?? '')];
    }

    public static function ok(array $res): bool
    {
        return $res['status'] >= 200 && $res['status'] <= 299;
    }

    public static function readJson(array $res): Obj
    {
        try {
            $p = Js::parse($res['body']);
        } catch (\Throwable) {
            throw new CibaProviderError($res['status'], 'invalid_response', 'the provider reply was not JSON', true);
        }
        if (!($p instanceof Obj)) {
            throw new CibaProviderError($res['status'], 'invalid_response', 'the provider reply was not a JSON object');
        }
        return $p;
    }

    public static function providerError(int $status, Obj $body): CibaProviderError
    {
        $e = $body->get('error');
        $d = $body->get('error_description');
        return new CibaProviderError($status, is_string($e) ? $e : 'invalid_response', is_string($d) ? $d : null);
    }

    private static function positiveInt(mixed $v, string $name, int $status): int|float
    {
        $f = Js::num($v);
        if ($f === null || !is_finite($f) || floor($f) !== $f || abs($f) > 9007199254740991.0 || $f <= 0) {
            throw new CibaProviderError($status, 'invalid_response', "$name must be a positive integer");
        }
        return $f < 9.0e15 ? (int)$f : $f;
    }

    /**
     * Start a backchannel request. Exactly one hint (loginHint | loginHintToken | idTokenHint); delivery 'poll' (default) or
     * 'ping' (sends a client_notification_token, generated unless given); acrValues, userCode; plus the toCibaAuthRequest options.
     * @return array<string,mixed> the flow {authReqId, expiresInSec, intervalSec, startedAt, delivery, clientNotificationToken?, request}
     */
    public function initiate(mixed $stepUp, mixed $opts = []): array
    {
        if ($opts === null) {
            throw new \TypeError("Cannot read properties of null (reading 'loginHint')");
        }
        $hints = array_filter(['loginHint', 'loginHintToken', 'idTokenHint'], static fn(string $k): bool => Js::has($opts, $k));
        if (count($hints) !== 1) {
            throw new \RangeException('ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)');
        }
        $delivery = Js::opt($opts, 'delivery') ?? 'poll';
        $given = Js::opt($opts, 'clientNotificationToken');
        $nt = $delivery === 'ping' ? ($given ?? Ciba::newClientNotificationToken()) : null;
        if (Js::has($opts, 'clientNotificationToken')) {
            if (!is_string($given) || Js::len($given) < self::MIN_NOTIFICATION_TOKEN_CHARS || Js::len($given) > self::MAX_NOTIFICATION_TOKEN_CHARS || preg_match('/\A[\x21-\x7E]+\z/', $given) !== 1) {
                throw new \RangeException('ciba: clientNotificationToken must be ' . self::MIN_NOTIFICATION_TOKEN_CHARS . '..' . self::MAX_NOTIFICATION_TOKEN_CHARS . ' printable characters (>= 128 bits, CIBA Core 7.1)');
            }
        }
        $request = Ciba::toCibaAuthRequest($stepUp, $opts);
        $pairs = [['scope', $request['scope']], ['binding_message', $request['binding_message']], ['requested_expiry', Ciba::jsStr($request['requested_expiry'])]];
        foreach (['loginHint' => 'login_hint', 'loginHintToken' => 'login_hint_token', 'idTokenHint' => 'id_token_hint', 'acrValues' => 'acr_values', 'userCode' => 'user_code'] as $k => $p) {
            if (Js::has($opts, $k)) {
                $pairs[] = [$p, Ciba::jsStr(Js::opt($opts, $k))];
            }
        }
        if ($nt !== null) {
            $pairs[] = ['client_notification_token', Ciba::jsStr($nt)];
        }
        $res = $this->post($this->bcEndpoint, $pairs);
        $body = self::readJson($res);
        if (!self::ok($res)) {
            throw self::providerError($res['status'], $body);
        }
        $id = $body->get('auth_req_id');
        if (!is_string($id) || $id === '') {
            throw new CibaProviderError($res['status'], 'invalid_response', 'auth_req_id missing');
        }
        $expires = self::positiveInt($body->get('expires_in'), 'expires_in', $res['status']);
        // CIBA Core 7.3: interval is optional and defaults to 5 seconds
        $interval = $body->has('interval') ? self::positiveInt($body->get('interval'), 'interval', $res['status']) : 5;
        $flow = ['authReqId' => $id, 'expiresInSec' => $expires, 'intervalSec' => $interval, 'startedAt' => ($this->clock)(), 'delivery' => $delivery];
        if ($nt !== null) {
            $flow['clientNotificationToken'] = $nt;
        }
        $flow['request'] = $request;
        return $flow;
    }

    public function poller(mixed $flow): CibaPoller
    {
        return new CibaPoller($this, $this->tokenEndpoint, $flow);
    }
}

/**
 * Poll discipline (CIBA Core 7.3 / 11): never faster than the interval, +5 s on every slow_down, stop at expires_in, back off
 * on transient failures; a terminal answer is cached so a settled flow is never re-sent (an approved auth_req_id is single use).
 * Synchronous: notify() (a PING arrived) lets the next poll() go out at once.
 */
final class CibaPoller
{
    private const SLOW_DOWN_STEP_SEC = 5;
    private const MAX_BACKOFF_MS = 60000;
    private const MAX_CONSECUTIVE_TRANSIENT = 5;

    private int|float $intervalMs;
    private int|float $nextAt;
    private readonly int|float $deadline;
    private readonly string $authReqId;
    private ?array $settled = null;
    private int $failures = 0;

    public function __construct(private readonly CibaClient $client, private readonly string $tokenEndpoint, mixed $flow)
    {
        $this->intervalMs = Js::num(Js::get($flow, 'intervalSec')) * 1000;
        $start = Js::num(Js::get($flow, 'startedAt'));
        $this->nextAt = $start + $this->intervalMs;
        $this->deadline = $start + Js::num(Js::get($flow, 'expiresInSec')) * 1000;
        $this->authReqId = Ciba::jsStr(Js::get($flow, 'authReqId'));
    }

    public function intervalSec(): int|float
    {
        return $this->intervalMs / 1000;
    }

    public function notify(): void
    {
        $this->nextAt = ($this->client->clock)();
    }

    private function backoff(): void
    {
        $this->failures++;
        $this->nextAt = ($this->client->clock)() + min(self::MAX_BACKOFF_MS, $this->intervalMs * 2 ** min($this->failures, 6));
    }

    /** Sleep until the interval allows it, then ask the token endpoint once. @return array<string,mixed> */
    public function poll(): array
    {
        if ($this->settled !== null) {
            return $this->settled;
        }
        $wait = $this->nextAt - ($this->client->clock)();
        if ($wait > 0) {
            ($this->client->sleep)($wait);
        }
        if (($this->client->clock)() >= $this->deadline) {
            return $this->settled = ['status' => 'expired'];
        }
        try {
            $res = $this->client->post($this->tokenEndpoint, [['grant_type', CibaClient::CIBA_GRANT], ['auth_req_id', $this->authReqId]]);
            if ($res['status'] >= 500) {
                throw new CibaProviderError($res['status'], 'server_error', 'the provider answered with a server error', true);
            }
            $body = CibaClient::readJson($res);
        } catch (CibaProviderError $e) {
            if ($e->retryable) {
                $this->backoff();
            }
            throw $e;
        }
        $this->failures = 0;
        $this->nextAt = ($this->client->clock)() + $this->intervalMs;
        if (CibaClient::ok($res)) {
            if (!is_string($body->get('access_token')) || !is_string($body->get('token_type'))) {
                throw new CibaProviderError($res['status'], 'invalid_response', 'token response lacks access_token / token_type');
            }
            return $this->settled = ['status' => 'approved', 'tokens' => $body];
        }
        $err = CibaClient::providerError($res['status'], $body);
        switch ($err->error) {
            case 'authorization_pending':
                return ['status' => 'pending', 'intervalSec' => $this->intervalMs / 1000];
            case 'slow_down':
                $this->intervalMs += self::SLOW_DOWN_STEP_SEC * 1000;
                $this->nextAt = ($this->client->clock)() + $this->intervalMs;
                return ['status' => 'pending', 'intervalSec' => $this->intervalMs / 1000];
            case 'access_denied':
                return $this->settled = ['status' => 'denied', 'error' => $err->error];
            case 'expired_token':
                return $this->settled = ['status' => 'expired'];
            default:
                throw $err;
        }
    }

    /** Poll until the flow settles; up to 5 consecutive transient failures are retried. @return array<string,mixed> */
    public function wait(): array
    {
        $transient = 0;
        for (;;) {
            try {
                $r = $this->poll();
                $transient = 0;
                if ($r['status'] !== 'pending') {
                    return $r;
                }
            } catch (CibaProviderError $e) {
                if (!$e->retryable || ++$transient >= self::MAX_CONSECUTIVE_TRANSIENT) {
                    throw $e;
                }
            }
        }
    }
}

// ---- store conformance --------------------------------------------------------------------------------------------------

/**
 * Conformance cases for an ApprovalStore (and broker cases over it). Each case is ['name' => string, 'run' => Closure] and
 * throws \LogicException when the store breaks the contract: absent = version 0, cas writes only at the expected version and
 * bumps it by one, values are snapshots, a retry loop loses no increment, and (with $reopen) records survive a restart.
 * shortcut: the reference's concurrent cases run their writers one after another here (one PHP thread); a store shared by
 * several processes needs its own concurrency test.
 */
final class CibaStoreConformance
{
    private static function eq(mixed $want, mixed $have, string $what): void
    {
        $c = static fn(mixed $v): string => Js::stringify(ciba_clone($v));
        if ($c($want) !== $c($have)) {
            throw new \LogicException("$what: want " . $c($want) . ', have ' . $c($have));
        }
    }

    /** @return list<array{name:string,run:\Closure}> */
    public static function approvalStoreCases(callable $make, ?callable $reopen = null): array
    {
        $cases = [
            ['name' => 'an absent key reads undefined', 'run' => static function () use ($make): void {
                self::eq(null, $make()->get('nope'), 'get');
            }],
            ['name' => 'cas at version 0 creates the key at version 1 with the whole value', 'run' => static function () use ($make): void {
                $s = $make();
                $v = ['a' => 1, 'nested' => ['b' => ['x', 2, null]]];
                self::eq(true, $s->cas('k', 0, $v), 'cas');
                self::eq(['version' => 1, 'value' => $v], $s->get('k'), 'get');
            }],
            ['name' => 'cas at version 0 on an existing key is refused and changes nothing', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('k', 0, 'first');
                self::eq(false, $s->cas('k', 0, 'second'), 'cas');
                self::eq(['version' => 1, 'value' => 'first'], $s->get('k'), 'get');
            }],
            ['name' => 'cas succeeds only at the current version and bumps it by exactly one', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('k', 0, 1);
                self::eq(true, $s->cas('k', 1, 2), 'cas');
                self::eq(false, $s->cas('k', 1, 3), 'stale cas');
                self::eq(false, $s->cas('k', 5, 4), 'future cas');
                self::eq(true, $s->cas('k', 2, 5), 'cas');
                self::eq(['version' => 3, 'value' => 5], $s->get('k'), 'get');
            }],
            ['name' => 'cas on a key that does not exist at a non-zero version is refused and creates nothing', 'run' => static function () use ($make): void {
                $s = $make();
                self::eq(false, $s->cas('k', 1, 'x'), 'cas');
                self::eq(null, $s->get('k'), 'get');
            }],
            ['name' => 'keys are independent', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('a', 0, 'A');
                $s->cas('b', 0, 'B');
                $s->cas('a', 1, 'A2');
                self::eq(['version' => 2, 'value' => 'A2'], $s->get('a'), 'get a');
                self::eq(['version' => 1, 'value' => 'B'], $s->get('b'), 'get b');
            }],
            ['name' => 'a read is a snapshot: changing the returned value does not change the store', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('k', 0, Obj::of(['list' => [1]]));
                $got = $s->get('k');
                if ($got !== null && $got['value'] instanceof Obj) {
                    $got['value']->set('list', [1, 2]);
                }
                self::eq(['version' => 1, 'value' => ['list' => [1]]], $s->get('k'), 'get');
            }],
            ['name' => 'a written value is a snapshot: changing it after cas does not change the store', 'run' => static function () use ($make): void {
                $s = $make();
                $v = Obj::of(['list' => [1]]);
                $s->cas('k', 0, $v);
                $v->set('list', [1, 2]);
                self::eq(['version' => 1, 'value' => ['list' => [1]]], $s->get('k'), 'get');
            }],
            ['name' => 'exactly one of many concurrent creates wins', 'run' => static function () use ($make): void {
                $s = $make();
                $results = array_map(static fn(int $i): bool => $s->cas('k', 0, $i), range(0, 31));
                self::eq(1, count(array_filter($results)), 'winners');
                self::eq(['version' => 1, 'value' => array_search(true, $results, true)], $s->get('k'), 'get');
            }],
            ['name' => 'exactly one of many concurrent updates at the same version wins', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('k', 0, 'base');
                $results = array_map(static fn(int $i): bool => $s->cas('k', 1, $i), range(0, 31));
                self::eq(1, count(array_filter($results)), 'winners');
                self::eq(['version' => 2, 'value' => array_search(true, $results, true)], $s->get('k'), 'get');
            }],
            ['name' => 'a retry loop over concurrent writers loses no increment', 'run' => static function () use ($make): void {
                $s = $make();
                $s->cas('n', 0, 0);
                for ($i = 0; $i < 24; $i++) {
                    for ($try = 0; $try < 100; $try++) {
                        $cur = $s->get('n');
                        if ($cur !== null && $s->cas('n', $cur['version'], (int)Js::num($cur['value']) + 1)) {
                            break;
                        }
                    }
                }
                self::eq(['version' => 25, 'value' => 24], $s->get('n'), 'get');
            }],
        ];
        if ($reopen !== null) {
            $cases[] = ['name' => 'records and their versions survive reopening the store', 'run' => static function () use ($make, $reopen): void {
                $s = $make();
                $s->cas('k', 0, ['v' => 1]);
                $s->cas('k', 1, ['v' => 2]);
                $again = $reopen($s);
                self::eq(['version' => 2, 'value' => ['v' => 2]], $again->get('k'), 'get');
                self::eq(false, $again->cas('k', 1, ['v' => 'stale']), 'stale cas');
                self::eq(true, $again->cas('k', 2, ['v' => 3]), 'cas');
            }];
        }
        return $cases;
    }

    /** Broker-level cases over a store: exactly one decision wins and an approval redeems once. @return list<array{name:string,run:\Closure}> */
    public static function approvalBrokerCases(callable $make): array
    {
        $stepUp = static fn(): array => ['id' => 'su-conformance', 'verb' => 'stripe.payout', 'resource' => 'acct:1', 'params' => ['amount' => 80, 'currency' => 'USD', 'payee' => 'bob'],
            'tier' => 3, 'reason' => 'conformance', 'goalCommit' => 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq', 'goal' => 'pay suppliers', 'r' => 0.9, 'requestedAt' => 1];
        $brokers = static function (int $n) use ($make): array {
            $store = $make();
            return array_map(static fn(): DurableCibaBroker => new DurableCibaBroker(['store' => $store]), range(1, $n));
        };
        return [
            ['name' => 'concurrent resolves through separate brokers: exactly one wins and its decision stands', 'run' => static function () use ($brokers, $stepUp): void {
                $bs = $brokers(8);
                $req = $bs[0]->start($stepUp());
                $won = [];
                foreach ($bs as $i => $b) {
                    try {
                        $b->resolve($req['auth_req_id'], $i % 2 === 0 ? 'approve' : 'deny', "user-$i");
                        $won[] = $i;
                    } catch (\RuntimeException|\InvalidArgumentException) {
                    }
                }
                self::eq(1, count($won), 'winners');
                $final = $bs[0]->get($req['auth_req_id']);
                self::eq("user-{$won[0]}", $final['decidedBy'] ?? null, 'decidedBy');
                self::eq($won[0] % 2 === 0 ? 'approved' : 'denied', $final['status'] ?? null, 'status');
            }],
            ['name' => 'an approval redeems once even when many brokers redeem at the same time', 'run' => static function () use ($brokers, $stepUp): void {
                $bs = $brokers(8);
                $req = $bs[0]->start($stepUp());
                $bs[0]->resolve($req['auth_req_id'], 'approve', 'owner');
                $outs = array_map(static fn(DurableCibaBroker $b): array => $b->token($req['auth_req_id']), $bs);
                self::eq(1, count(array_filter($outs, static fn(array $o): bool => $o['ok'] === true)), 'redemptions');
            }],
            ['name' => 'a second broker over the same store sees the decision of the first', 'run' => static function () use ($brokers, $stepUp): void {
                [$a, $b] = $brokers(2);
                $req = $a->start($stepUp());
                self::eq('pending', $b->poll($req['auth_req_id'])['status'], 'status');
                $a->resolve($req['auth_req_id'], 'approve', 'owner');
                self::eq('approved', $b->poll($req['auth_req_id'])['status'], 'status');
                try {
                    $b->resolve($req['auth_req_id'], 'deny', 'late');
                } catch (\RuntimeException) {
                    return;
                }
                throw new \LogicException('expected a rejection');
            }],
        ];
    }
}
