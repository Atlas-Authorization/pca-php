<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Events.php';

/**
 * One-time-use guard for a verified PCActn: the anti-replay primitive the token vault spends an action with. A store is any object
 * with `consumeOnce(string $key, int|float $retainUntilMs, int|float $nowMs): bool` (true on first sight) and, for counters,
 * `advance(string $streamKey, int $counter): bool`; both throw when they cannot decide. Run the guard only AFTER the PCActn verified.
 */
final class ConnectReplay
{
    public const MAX_REPLAY_COMPONENT_LEN = 512;
    public const PCACTN_MAX_LIFETIME_MS = 3_600_000;
    public const PCACTN_MAX_SKEW_MS = 60_000;
    private const MAX_AUD_LEN = 256;
    private const MAX_NONCE_LEN = 128;
    private const MAX_SAFE = 9007199254740991.0;

    /** Length-prefixed, injective encoding of the parts, hashed to a fixed-size key. */
    public static function replayKey(string $namespace, string ...$parts): string
    {
        return Events::replayKey($namespace, ...$parts);
    }

    private static function lone(string $s): bool
    {
        return Json::hasLoneSurrogate($s);
    }

    /** JS Number.isSafeInteger over a JSON number (no -0 rule). */
    private static function safeInt(mixed $n): bool
    {
        $f = Js::num($n);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE;
    }

    private static function safeNonNeg(mixed $n): bool
    {
        $f = Js::num($n);
        if ($f === null || !is_finite($f) || floor($f) !== $f || $f > self::MAX_SAFE || $f < 0) {
            return false;
        }
        return !($f === 0.0 && fdiv(1.0, $f) < 0); // JS Object.is(-0): a negative zero is refused
    }

    /** An integral float as an int (so a typed store accepts it), anything else unchanged. */
    private static function num(float $f): int|float
    {
        return floor($f) === $f && abs($f) <= self::MAX_SAFE ? (int)$f : $f;
    }

    /** @return array{ok:true}|array{ok:false,code:string,reason:string} */
    private static function deny(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /**
     * Decide whether a (signature-verified) PCActn may be accepted ONCE. Never throws: every failure, including a store failure, is a denial.
     *
     * @return array{ok:true}|array{ok:false,code:string,reason:string}
     */
    public static function guardPcactnReplay(mixed $store, mixed $p, mixed $aud, mixed $now, mixed $clockSkewMs = null, bool $requireNonce = true, mixed $counters = null): array
    {
        $sk0 = Js::num($clockSkewMs);
        $fin = $sk0 !== null && is_finite($sk0);
        $skew = min($fin && $sk0 >= 0 ? $sk0 : (float)self::PCACTN_MAX_SKEW_MS, (float)self::PCACTN_MAX_SKEW_MS);
        $objOk = $p instanceof Obj;
        $chain = $objOk ? $p->get('cap_chain') : null;
        $leaf = is_array($chain) && array_is_list($chain) && $chain !== [] ? $chain[count($chain) - 1] : null;
        $leafOk = $leaf instanceof Obj && is_string($leaf->get('holder')) && $objOk && is_string($p->get('grant_ref'));
        $compsOk = $leafOk;
        if ($leafOk) {
            foreach ([$p->get('grant_ref'), $leaf->get('holder')] as $c) {
                if ($c === '' || self::lone($c) || strlen($c) > self::MAX_REPLAY_COMPONENT_LEN) {
                    $compsOk = false;
                }
            }
        }
        $hasNonce = $objOk && $p->has('nonce');
        $nonce = $objOk ? $p->get('nonce') : null;
        $nonceOk = $hasNonce && is_string($nonce) && $nonce !== '' && strlen($nonce) <= self::MAX_NONCE_LEN && !self::lone($nonce);
        $nowOk = self::safeInt($now);
        $audOk = is_string($aud) && $aud !== '' && strlen($aud) <= self::MAX_AUD_LEN && !self::lone($aud);
        $audMatches = $objOk && is_string($p->get('aud')) && $p->get('aud') === $aud;
        $iatOk = $objOk && self::safeNonNeg($p->get('iat'));
        $expOk = $objOk && self::safeNonNeg($p->get('exp'));
        $iat = $iatOk ? (float)Js::num($p->get('iat')) : 0.0;
        $exp = $expOk ? (float)Js::num($p->get('exp')) : 0.0;
        $counterOk = $objOk && self::safeNonNeg($p->get('counter'));
        $nowF = $nowOk ? (float)Js::num($now) : 0.0;
        $sk = floor($skew);
        $windowOk = $iatOk && $expOk && $exp > $iat && $exp - $iat <= self::PCACTN_MAX_LIFETIME_MS;
        $code = null;
        if (!$nowOk || !$audOk || !$objOk) {
            $code = 'malformed';
        } elseif (!$audMatches) {
            $code = 'audience';
        } elseif (!$windowOk) {
            $code = 'malformed';
        } elseif ($iat > $nowF + $sk) {
            $code = 'not_yet_valid';
        } elseif ($nowF > $exp) {
            $code = 'expired';
        } elseif (!$leafOk || !$compsOk || !$counterOk) {
            $code = 'malformed';
        }
        if ($code !== null) {
            $reasons = ['audience' => 'the PCActn is for another audience', 'not_yet_valid' => 'iat is in the future beyond the clock-skew allowance',
                'expired' => 'the PCActn has expired'];
            if (isset($reasons[$code])) {
                return self::deny($code, $reasons[$code]);
            }
            return self::deny($code, match (true) {
                !$nowOk => 'verifier clock is not an integer epoch-ms',
                !$audOk => 'verifier audience is invalid',
                !$objOk => 'not a PCActn',
                !$windowOk => 'iat / exp are not a valid bounded window',
                !$leafOk => 'no leaf holder / grant',
                !$compsOk => 'grant / holder is not a bounded string',
                default => 'counter is not a non-negative safe integer',
            });
        }
        if ($exp + ceil($skew) > self::MAX_SAFE) {
            return self::deny('malformed', 'exp + clock skew exceeds the safe-integer range (retention horizon not representable)');
        }
        $retainUntil = $exp + $skew;
        try {
            if ($hasNonce) {
                if (!$nonceOk) {
                    return self::deny('malformed', 'nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes');
                }
                $consumed = $store->consumeOnce(self::replayKey('pca-nonce/v1', $aud, $p->get('grant_ref'), $leaf->get('holder'), $nonce), self::num($retainUntil), self::num($nowF));
                if (!$consumed) {
                    return self::deny('replay', 'nonce already consumed');
                }
            } elseif ($requireNonce) {
                return self::deny('malformed', 'a nonce is required');
            }
            if ($counters !== null) {
                $advanced = $counters->advance(self::replayKey('pca-counter/v1', $aud, $p->get('grant_ref'), $leaf->get('holder')), (int)Js::num($p->get('counter')));
                if (!$advanced) {
                    return self::deny('replay', 'counter is not greater than the last accepted');
                }
            }
        } catch (\Throwable $e) { // a store that cannot decide fails closed
            return self::deny('store_unavailable', 'replay store failed closed: ' . ($e->getMessage() !== '' ? $e->getMessage() : 'error'));
        }
        return ['ok' => true];
    }
}

/** Reference store: correct only for a single verifier process whose lifetime covers the action lifetime. */
final class InMemoryReplayStore
{
    /** @var array<string,int|float> */
    private array $seen = [];
    /** @var array<string,int> */
    private array $streams = [];

    public function __construct(private readonly int $maxEntries = 100_000)
    {
    }

    public function size(): int
    {
        return count($this->seen);
    }

    public function prune(mixed $nowMs): int
    {
        if (!self::finite($nowMs)) {
            return 0; // an infinite clock must not expire live replay keys
        }
        $n = 0;
        foreach ($this->seen as $k => $until) {
            if ($until < $nowMs) {
                unset($this->seen[$k]);
                $n++;
            }
        }
        return $n;
    }

    private static function finite(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f);
    }

    public function consumeOnce(mixed $key, mixed $retainUntilMs, mixed $nowMs): bool
    {
        if (!is_string($key) || $key === '' || !self::finite($retainUntilMs) || !self::finite($nowMs) || Js::num($retainUntilMs) < Js::num($nowMs)) {
            throw new \InvalidArgumentException('consumeOnce: invalid key or retention horizon');
        }
        $retain = (float)Js::num($retainUntilMs);
        $now = (float)Js::num($nowMs);
        $until = $this->seen[$key] ?? null;
        if ($until !== null && !($until < $now)) {
            return false;
        }
        if ($until === null && count($this->seen) >= $this->maxEntries) {
            $this->prune($now);
            if (count($this->seen) >= $this->maxEntries) {
                throw new \RuntimeException('replay store full of live entries');
            }
        }
        $this->seen[$key] = max($retain, $until ?? 0);
        return true;
    }

    public function advance(mixed $streamKey, mixed $counter): bool
    {
        $f = Js::num($counter);
        if (!is_string($streamKey) || $streamKey === '' || $f === null || !is_finite($f) || floor($f) !== $f || $f < 0 || $f > 9007199254740991.0) {
            throw new \InvalidArgumentException('advance: invalid stream or counter');
        }
        $last = $this->streams[$streamKey] ?? null;
        if ($last !== null && !($f > $last)) {
            return false;
        }
        $this->streams[$streamKey] = (int)$f;
        return true;
    }
}
