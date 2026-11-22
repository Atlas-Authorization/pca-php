<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Dead-man liveness beacons v2 (packages/pca/src/beacons.ts: verify, accept, ref, acceptor; and the beacon decision of the verdict
 * combinator). A beacon is `{v, instance, scope, epoch, seq, issued_at, not_after, issuer, sig}` (plus `alg` / `pq_pk` / `pq_sig` for
 * a post-quantum suite) signed by a pinned issuer: the grant's principal or the operator / guardian. Authority is live only while a
 * valid beacon covers the moment; a PCActn binds one through its signed `freshness.beacon_ref` (= {@see beaconRef}). Verification
 * never throws: any failure is a refusal. `$pqPins` maps an issuer to its pinned ML-DSA key (a pure-PQ / hybrid beacon needs one).
 */
final class Beacons
{
    public const GLOBAL_SCOPE = '*';
    public const EPOCH_MS = 60000;
    public const MAX_VALIDITY_MS = 3600000; // no issuer can mint a longer-lived beacon
    public const CLOCK_SKEW_MS = 30000;
    public const DOMAIN = "atlas-pca/beacon/v2\x00";

    public static function beaconRef(Obj $b): string
    {
        return Pca::hashCanonical($b);
    }

    private static function numF(mixed $x): ?float
    {
        if ($x instanceof Num) {
            return $x->float();
        }
        return is_int($x) || is_float($x) ? (float)$x : null;
    }

    private static function intF(mixed $x): ?float
    {
        $f = self::numF($x);
        return $f !== null && is_finite($f) && $f === floor($f) ? $f : null;
    }

    /** @return array{ok: bool, reason?: string} */
    public static function verify(mixed $b, array $issuers, int|float $now, string $instance, ?string $scope = null, mixed $pqPins = null): array
    {
        try {
            $suiteOk = $b instanceof Obj && (!$b->has('alg') || Pca::suiteImplemented($b->get('alg')));
            if (!($b instanceof Obj) || self::numF($b->get('v')) !== 2.0 || !$suiteOk) {
                return ['ok' => false, 'reason' => 'malformed beacon'];
            }
            if ($b->get('instance') !== $instance) {
                return ['ok' => false, 'reason' => 'wrong instance'];
            }
            if (!in_array($b->get('issuer'), $issuers, true)) {
                return ['ok' => false, 'reason' => 'issuer not pinned'];
            }
            $body = new Obj();
            foreach (['v', 'instance', 'scope', 'epoch', 'seq', 'issued_at', 'not_after', 'issuer'] as $k) {
                if ($b->has($k)) {
                    $body->set($k, $b->get($k));
                }
            }
            if (!Ledger::signed(self::DOMAIN, $body, $b->get('issuer'), $b, $pqPins)) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            $epoch = self::intF($b->get('epoch'));
            $seq = self::intF($b->get('seq'));
            $iat = self::intF($b->get('issued_at'));
            $naf = self::intF($b->get('not_after'));
            if ($epoch === null || $seq === null || $iat === null || $naf === null || $seq < 0) {
                return ['ok' => false, 'reason' => 'malformed window'];
            }
            if ($naf <= $iat || $naf - $iat > self::MAX_VALIDITY_MS) {
                return ['ok' => false, 'reason' => 'validity exceeds the hard maximum'];
            }
            if ($epoch !== floor($iat / self::EPOCH_MS)) {
                return ['ok' => false, 'reason' => 'epoch does not match issued_at'];
            }
            if ($now + self::CLOCK_SKEW_MS < $iat) {
                return ['ok' => false, 'reason' => 'not yet valid'];
            }
            if ($now > $naf) {
                return ['ok' => false, 'reason' => 'expired'];
            }
            if ($scope !== null && $b->get('scope') !== self::GLOBAL_SCOPE && $b->get('scope') !== $scope) {
                return ['ok' => false, 'reason' => 'scope not covered'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'malformed beacon'];
        }
    }

    /** Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher `seq`. @return array{ok: bool, reason?: string} */
    public static function accept(mixed $prev, mixed $next): array
    {
        $sq = $next instanceof Obj ? self::intF($next->get('seq')) : null;
        if ($sq === null || $sq < 0 || $sq > 9007199254740991.0 || ($sq === 0.0 && $next->get('seq') instanceof Num && str_starts_with($next->get('seq')->lexeme, '-'))) {
            return ['ok' => false, 'reason' => 'malformed beacon'];
        }
        if ($prev !== null && $prev !== false) {
            $ps = $prev instanceof Obj ? self::numF($prev->get('seq')) : null;
            if ($ps === null || !($sq > $ps)) {
                return ['ok' => false, 'reason' => 'replayed beacon: seq ' . (int)$sq . ' <= ' . ($ps === null ? 'undefined' : IntentV2::jsNumStr($ps))];
            }
        }
        return ['ok' => true];
    }

    /** Frozen unless at least one beacon verifies for (instance, scope, now); absence is a freeze. */
    public static function isFrozen(array $beacons, array $check): bool
    {
        foreach ($beacons as $b) {
            if (self::verify($b, ...$check)['ok']) {
                return false;
            }
        }
        return true;
    }

    /** The beacon decision of the verdict combinator: 'not-enforced' | 'rejected' | 'replayed' | 'unbound' | 'pass'. */
    public static function decision(bool $supplied, bool $verifierOk, bool $replayed, bool $refBinds): string
    {
        if (!$supplied) {
            return 'not-enforced';
        }
        if (!$verifierOk) {
            return 'rejected';
        }
        if ($replayed) {
            return 'replayed';
        }
        return $refBinds ? 'pass' : 'unbound';
    }
}

/**
 * Durable replay protection: the highest accepted `seq` per (instance, scope, issuer) in an atomic kv, under one atomic
 * read-modify-write. A store that cannot decide refuses the beacon with `beacon state unavailable`.
 */
final class BeaconAcceptor
{
    public function __construct(private readonly AtomicKv $kv)
    {
    }

    /** @param array{issuers: list<string>, now: int|float, instance: string, scope?: ?string, pqPins?: mixed} $check @return array{ok: bool, reason?: string} */
    public function accept(mixed $b, array $check): array
    {
        $v = Beacons::verify($b, ...$check);
        if (!$v['ok']) {
            return $v;
        }
        $seq = $b->get('seq') instanceof Num ? $b->get('seq')->float() : (float)$b->get('seq');
        $seqText = IntentV2::jsNumStr($seq);
        $replayOf = null;
        try {
            $key = 'beacon-seq/v1/' . json_encode([$b->get('instance'), $b->get('scope'), $b->get('issuer')], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $this->kv->update($key, static function (?string $prev) use ($seq, $seqText, &$replayOf): ?string {
                if ($prev === null) {
                    return $seqText;
                }
                if (!preg_match('/^(0|[1-9][0-9]{0,15})$/', $prev) || (float)$prev > 9007199254740991.0) {
                    throw new \UnexpectedValueException('junk');
                }
                if (!($seq > (float)$prev)) {
                    $replayOf = $prev;
                    return null;
                }
                return $seqText;
            });
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'beacon state unavailable'];
        }
        return $replayOf === null ? ['ok' => true] : ['ok' => false, 'reason' => "replayed beacon: seq $seqText <= $replayOf"];
    }
}
