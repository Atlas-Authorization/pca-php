<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Signals.php';

/**
 * Receiver-side health of one Shared Signals Framework stream. All times are epoch SECONDS passed in (no hidden clock). A verification
 * state is single-use, expiring, and only valid if THIS tracker issued it. Unhealthy means "ask the caller to refresh", never allow.
 */
final class StreamHealth
{
    private string $statusV = 'enabled';
    private ?float $lastEvent = null;
    private ?float $lastVerified = null;
    private ?float $lastRequested = null;
    private int $fails = 0;
    private int $rejected = 0;
    /** @var array<string,float> 'k'.state => expiry */
    private array $pending = [];

    /** @param mixed $config the stream config (min_verification_interval is read); $o: verifyTimeoutSec, verifiedWithinSec, failAfter, maxPending */
    public function __construct(public readonly mixed $config, private readonly mixed $o = null)
    {
    }

    private static function n(mixed $v): float
    {
        return (float) (Js::num($v) ?? NAN);
    }

    private static function max(?float $a, float $b): float
    {
        $a ??= 0.0;
        return is_nan($a) || is_nan($b) ? NAN : max($a, $b);
    }

    private function opt(string $k, float $default): float
    {
        $v = Js::opt($this->o, $k);
        return $v === null ? $default : self::n($v);
    }

    public function setStatus(mixed $s): void
    {
        if (!in_array($s, SsfStream::STREAM_STATUSES, true)) {
            throw new \RangeException('unknown stream status');
        }
        $this->statusV = $s;
    }

    /** Any valid SET arrived on this stream. */
    public function recordEvent(mixed $nowSec): void
    {
        $this->lastEvent = self::max($this->lastEvent, self::n($nowSec));
    }

    /**
     * Start a verification: the `state` to send to the transmitter's verification endpoint, or null when the transmitter's
     * `min_verification_interval` has not elapsed (it would answer 429), the stream is not enabled or too many are outstanding.
     */
    public function requestVerification(mixed $nowSec): ?string
    {
        $now = self::n($nowSec);
        if (!is_finite($now)) {
            return null;
        }
        if ($this->statusV !== 'enabled') {
            return null;
        }
        $min = Js::opt($this->config, 'min_verification_interval');
        if ($this->lastRequested !== null && !($now - $this->lastRequested >= ($min === null ? 0.0 : self::n($min)))) {
            return null;
        }
        $this->expire($now);
        if (!(count($this->pending) < $this->opt('maxPending', 16.0))) {
            return null;
        }
        $state = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $exp = $now + $this->opt('verifyTimeoutSec', 60.0);
        if (!is_finite($exp)) {
            return null; // a NaN or infinite timeout would leave the request pending forever
        }
        $this->pending['k' . $state] = $exp;
        $this->lastRequested = $now;
        return $state;
    }

    /** A verification SET came back carrying `state`. True iff it matches an outstanding, unexpired request (single use). */
    public function ackVerification(mixed $state, mixed $nowSec): bool
    {
        $now = self::n($nowSec);
        if (!is_finite($now)) {
            $this->rejected++;
            return false;
        }
        $this->expire($now);
        $key = is_string($state) ? 'k' . $state : null;
        if ($key === null || !isset($this->pending[$key])) {
            $this->rejected++;
            return false;
        }
        unset($this->pending[$key]);
        $this->lastVerified = $now;
        $this->lastEvent = self::max($this->lastEvent, $now);
        $this->fails = 0;
        return true;
    }

    private function expire(float $now): void
    {
        foreach ($this->pending as $k => $exp) {
            if ($now > $exp) {
                unset($this->pending[$k]);
                $this->fails++;
            }
        }
    }

    /** @return array<string,mixed> */
    public function report(mixed $nowSec): array
    {
        $now = self::n($nowSec);
        $this->expire($now);
        $reasons = [];
        $within = $this->opt('verifiedWithinSec', 300.0);
        if ($this->statusV === 'disabled') {
            $state = 'disabled';
            $reasons[] = 'stream is disabled: no events are transmitted or held';
        } elseif ($this->statusV === 'paused') {
            $state = 'paused';
            $reasons[] = 'stream is paused: events may be delayed';
        } elseif (!($this->fails < $this->opt('failAfter', 3.0))) {
            $state = 'failing';
            $reasons[] = "{$this->fails} consecutive verification requests timed out";
        } elseif ($this->lastVerified === null) {
            $state = 'unverified';
            $reasons[] = 'no verification round trip has completed';
        } elseif (!(is_finite($now) && $now - $this->lastVerified <= $within)) {
            $state = 'degraded';
            $reasons[] = 'last verified ' . Js::str($now - $this->lastVerified) . 's ago, over ' . Js::str($within) . 's';
        } else {
            $state = 'healthy';
        }
        $out = [
            'state' => $state, 'status' => $this->statusV, 'reasons' => $reasons, 'pending_verifications' => count($this->pending),
            'consecutive_verification_failures' => $this->fails, 'rejected_verifications' => $this->rejected,
        ];
        if ($this->lastEvent !== null) {
            $out['last_event_at'] = $this->lastEvent;
        }
        if ($this->lastVerified !== null) {
            $out['last_verified_at'] = $this->lastVerified;
        }
        return $out;
    }

    /**
     * May the verifier assume no pushed revocation was missed in the last `maxAgeSec`? Only if the stream is enabled and a verified
     * round trip completed inside that window. Otherwise fall back to the signed epoch pull bound.
     */
    public function revocationFreshWithin(mixed $maxAgeSec, mixed $nowSec): bool
    {
        return $this->statusV === 'enabled' && $this->lastVerified !== null && is_finite(self::n($nowSec)) && self::n($nowSec) - $this->lastVerified <= self::n($maxAgeSec);
    }
}

/** RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors. */
final class PollQueue
{
    /** @var array<string,array{0:string,1:mixed}> 'k'.jti => [jti, set] */
    private array $q = [];
    /** @var list<Obj> */
    public array $errors = [];

    public function enqueue(string $jti, mixed $set): void
    {
        $this->q['k' . $jti] = [$jti, $set];
    }

    public function depth(): int
    {
        return count($this->q);
    }

    /** @return array{sets:Obj,moreAvailable?:true} */
    public function poll(mixed $req): array
    {
        if ($req === null) {
            throw new \TypeError("Cannot read properties of null (reading 'maxEvents')");
        }
        $me = Js::opt($req, 'maxEvents');
        if (Js::has($req, 'maxEvents') && !SsfStream::isSafeNonNegInt($me)) {
            throw new \RangeException('maxEvents must be a non-negative integer');
        }
        foreach (Js::spread(Js::opt($req, 'ack') ?? []) as $j) {
            if (is_string($j)) {
                unset($this->q['k' . $j]);
            }
        }
        // An errored SET is released too: retransmitting a SET the receiver found invalid cannot help.
        foreach (Signals::entries(Js::opt($req, 'setErrs') ?? new Obj()) as [$jti, $e]) {
            if (isset($this->q['k' . $jti])) {
                unset($this->q['k' . $jti]);
                $row = Obj::of(['jti' => $jti]);
                Signals::prop($e, 'err'); // a null entry throws here, after the SET was released
                foreach (['err', 'description'] as $f) {
                    if (Js::has($e, $f)) {
                        $row->set($f, Js::opt($e, $f));
                    }
                }
                $this->errors[] = $row;
            }
        }
        $max = $me === null ? INF : (float) Js::num($me);
        $sets = new Obj();
        $n = 0;
        foreach ($this->q as [$jti, $set]) {
            if ($n >= $max) {
                break;
            }
            $sets->set($jti, $set);
            $n++;
        }
        $out = ['sets' => $sets];
        if (count($this->q) > $n) {
            $out['moreAvailable'] = true;
        }
        return $out;
    }
}

/** SSF stream configuration, verification and push / poll delivery bookkeeping (OpenID SSF 1.0, RFC 8935, RFC 8936). */
final class SsfStream
{
    public const DELIVERY_PUSH = 'urn:ietf:rfc:8935';
    public const DELIVERY_POLL = 'urn:ietf:rfc:8936';
    public const STREAM_STATUSES = ['enabled', 'paused', 'disabled'];

    /** `^https://[^\s]+$` with the JS whitespace set (byte-level so a lone surrogate in WTF-8 is still just text). */
    public static function isHttpsUrl(mixed $u): bool
    {
        return is_string($u) && preg_match('/\Ahttps:\/\/(?:(?!\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF|[\t\n\x0B\f\r ])[\x00-\xFF])+\z/', $u) === 1;
    }

    /** Number.isSafeInteger(x) && x >= 0 && !Object.is(x, -0) */
    public static function isSafeNonNegInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0 && $f >= 0 && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function strs(mixed $x): bool
    {
        if (!is_array($x) || !array_is_list($x)) {
            return false;
        }
        foreach ($x as $s) {
            if (!is_string($s) || $s === '') {
                return false;
            }
        }
        return true;
    }

    /**
     * SSF 8.1.1 shape checks. Returns the problems found (empty = valid).
     *
     * @return list<string>
     */
    public static function validateStreamConfig(mixed $c): array
    {
        if (!Js::isObj($c)) {
            return ['not an object'];
        }
        $e = [];
        $nonEmpty = static fn(mixed $x): bool => is_string($x) && $x !== '';
        if (!$nonEmpty(Js::opt($c, 'stream_id'))) {
            $e[] = 'stream_id is required';
        }
        if (!$nonEmpty(Js::opt($c, 'iss'))) {
            $e[] = 'iss is required';
        }
        $aud = Js::opt($c, 'aud');
        if (!($nonEmpty($aud) || (is_array($aud) && array_is_list($aud) && $aud !== [] && self::strs($aud)))) {
            $e[] = 'aud must be a non-empty string or array';
        }
        $delivered = Js::opt($c, 'events_delivered');
        $supported = Js::opt($c, 'events_supported');
        $requested = Js::opt($c, 'events_requested');
        if (!self::strs($delivered) || $delivered === []) {
            $e[] = 'events_delivered must be a non-empty array of event type URIs';
        }
        if (Js::has($c, 'events_supported') && !self::strs($supported)) {
            $e[] = 'events_supported must be an array of URIs';
        }
        if (Js::has($c, 'events_requested') && (!self::strs($requested) || $requested === [])) {
            $e[] = 'events_requested must be a non-empty array of URIs';
        }
        if (self::strs($delivered) && self::strs($supported)) {
            foreach ($delivered as $x) {
                if (!in_array($x, $supported, true)) {
                    $e[] = 'events_delivered must be a subset of events_supported';
                    break;
                }
            }
        }
        $d = Js::opt($c, 'delivery');
        $method = Js::opt($d, 'method');
        if (!Js::truthy($d) || ($method !== self::DELIVERY_PUSH && $method !== self::DELIVERY_POLL)) {
            $e[] = 'delivery.method must be the RFC 8935 or RFC 8936 URI';
        } elseif (!self::isHttpsUrl(Js::opt($d, 'endpoint_url'))) {
            $e[] = 'delivery.endpoint_url must be an https URL';
        }
        if (Js::has($c, 'min_verification_interval') && !self::isSafeNonNegInt(Js::opt($c, 'min_verification_interval'))) {
            $e[] = 'min_verification_interval must be a non-negative integer (seconds)';
        }
        return $e;
    }

    /**
     * SSF 8.1.4.2: handle a verification request for a stream. 404 unknown stream, 400 malformed, 429 inside the stream's
     * `min_verification_interval`; otherwise 204 plus the signed verification SET to deliver on the stream. `$streams` maps a stream id
     * to a {@see VerificationStream}; its lastVerification is updated BEFORE the SET is built (a signing failure still counts).
     *
     * @param array<string|int,VerificationStream> $streams
     * @return array{status:int,error?:string,set?:string}
     */
    public static function handleVerificationRequest(array $streams, mixed $req, mixed $nowSec, mixed $key): array
    {
        $id = Js::opt($req, 'stream_id');
        if (!Js::isObj($req) || !is_string($id) || (Js::has($req, 'state') && !is_string(Js::opt($req, 'state')))) {
            return ['status' => 400, 'error' => 'stream_id (string) is required; state must be a string'];
        }
        $s = $streams[$id] ?? null;
        if ($s === null) {
            return ['status' => 404, 'error' => 'no such stream'];
        }
        $now = (float) (Js::num($nowSec) ?? NAN);
        $min = Signals::prop($s->config, 'min_verification_interval') ?? 0;
        if ($s->lastVerification !== null && $now - $s->lastVerification < (float) Js::num($min)) {
            return ['status' => 429, 'error' => 'verification requested too soon'];
        }
        $s->lastVerification = $now;
        $ev = Js::has($req, 'state') ? Obj::of(['state' => Js::opt($req, 'state')]) : new Obj();
        $set = Signals::buildSET(Obj::of([Signals::EVENT_TYPES['verification'] => $ev]), Js::opt($s->config, 'iss'), Js::opt($s->config, 'aud'), $key, Js::opt($s->config, 'stream_id'));
        return ['status' => 204, 'set' => $set];
    }

    /**
     * RFC 8935 receiver status for a `receiveSET` outcome: 202 on success, 400 + {err, description} otherwise.
     *
     * @return array{status:int,body?:Obj}
     */
    public static function pushResponse(mixed $r): array
    {
        if (Js::truthy(Signals::prop($r, 'ok'))) {
            return ['status' => 202];
        }
        $code = Js::opt($r, 'code');
        $err = match (true) {
            $code === 'verify_failed' => 'invalid_key',
            $code === 'misconfigured', $code === 'replay_store_error' => 'access_denied',
            default => 'invalid_request',
        };
        $body = Obj::of(['err' => $err]);
        if (Js::has($r, 'reason')) {
            $body->set('description', Js::opt($r, 'reason'));
        }
        return ['status' => 400, 'body' => $body];
    }
}

/** A stream as the verification handler sees it: its config and when a verification was last requested (epoch seconds). */
final class VerificationStream
{
    public function __construct(public mixed $config, public ?float $lastVerification = null)
    {
    }
}
