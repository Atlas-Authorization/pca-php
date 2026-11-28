<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pq.php';

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

    private static function isInteger(mixed $x): bool
    {
        return self::intF($x) !== null;
    }

    /** `bindSuiteFields`: a non-Ed25519 suite binds `alg` and `pq_pk` (possibly an undefined member, which has no canonical form) into the body. */
    private static function bindSuite(Obj $base, mixed $alg, mixed $pqPk): Obj
    {
        $suite = $alg instanceof Undef ? Pq::resolveSigAlg(null) : ($alg === null ? null : Pq::resolveSigAlg($alg));
        if ($suite === null || $suite['alg'] === 'ed25519') {
            return $base;
        }
        $base->set('alg', $suite['alg']);
        $base->set('pq_pk', $pqPk);
        return $base;
    }

    /** The signed bytes of a beacon body: the domain, then the strict canonical JSON of the eight body members (an absent one throws) with the suite bound in. */
    public static function message(mixed $b): string
    {
        Jsx::rd($b, 'v');
        $base = new Obj();
        foreach (['v', 'instance', 'scope', 'epoch', 'seq', 'issued_at', 'not_after', 'issuer'] as $k) {
            $base->set($k, Jsx::get($b, $k));
        }
        return self::DOMAIN . Json::canonicalizeNative(self::bindSuite($base, Jsx::get($b, 'alg'), Jsx::get($b, 'pq_pk')));
    }

    /**
     * A signed beacon. `$a`: `{issuerSecret (32 bytes), instance, scope? (default "*"), seq, issuedAt, validityMs? (default 5 epochs)}`; `$suite`:
     * `['alg' => ?string, 'pq' => ?PqKeyPair]`. Throws outside the bounds (seq and issuedAt non-negative integers, validity in (0, 1 h]) or on an unknown suite.
     */
    public static function issue(mixed $a, ?array $suite = null): Obj
    {
        $vm = Jsx::get($a, 'validityMs');
        $validity = $vm instanceof Undef || $vm === null ? 5 * self::EPOCH_MS : $vm;
        $seq = Jsx::get($a, 'seq');
        $iat = Jsx::get($a, 'issuedAt');
        if (!self::isInteger($seq) || Js::num($seq) < 0) {
            throw new \RangeException('issueLivenessBeacon: seq must be a non-negative integer');
        }
        if (!self::isInteger($iat) || Js::num($iat) < 0) {
            throw new \RangeException('issueLivenessBeacon: issuedAt must be an integer');
        }
        if (!self::isInteger($validity) || Js::num($validity) <= 0 || Js::num($validity) > self::MAX_VALIDITY_MS) {
            throw new \RangeException('issueLivenessBeacon: validity must be in (0, ' . self::MAX_VALIDITY_MS . '] ms');
        }
        $alg = $suite['alg'] ?? null;
        $pq = $suite['pq'] ?? null;
        $pqPk = Pq::suitePqPublicKey($alg, $pq);
        $ed = new KeyPair((string)Jsx::get($a, 'issuerSecret'));
        $scope = Jsx::get($a, 'scope');
        $body = Obj::of(['v' => Sign::n(2), 'instance' => Jsx::get($a, 'instance'), 'scope' => $scope instanceof Undef || $scope === null ? self::GLOBAL_SCOPE : $scope,
            'epoch' => Sign::n(floor(Js::num($iat) / self::EPOCH_MS)), 'seq' => $seq, 'issued_at' => $iat, 'not_after' => Sign::n(Js::num($iat) + Js::num($validity)),
            'issuer' => $ed->public]);
        self::bindSuite($body, $alg ?? Jsx::$U, $pqPk ?? Jsx::$U);
        $fields = Pq::signSuiteArtifact($alg, $ed, $pq, self::message($body));
        foreach ($fields as $k => $x) {
            $body->set($k, $x);
        }
        return $body;
    }

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
    public static function verify(mixed $b, mixed $issuers, mixed $now, mixed $instance, ?string $scope = null, mixed $pqPins = null): array
    {
        try {
            $suiteOk = $b instanceof Obj && (!$b->has('alg') || Pca::suiteImplemented($b->get('alg')));
            if (!($b instanceof Obj) || self::numF($b->get('v')) !== 2.0 || !$suiteOk) {
                return ['ok' => false, 'reason' => 'malformed beacon'];
            }
            if ($b->get('instance') !== $instance) {
                return ['ok' => false, 'reason' => 'wrong instance'];
            }
            // JavaScript `issuers.includes(issuer)`: a list is searched, a string is a substring test, anything else throws (a malformed beacon)
            if (is_string($issuers)) {
                $pinnedIssuer = is_string($b->get('issuer')) && str_contains($issuers, $b->get('issuer'));
            } elseif (is_array($issuers)) {
                $pinnedIssuer = in_array($b->get('issuer'), $issuers, true);
            } else {
                return ['ok' => false, 'reason' => 'malformed beacon'];
            }
            if (!$pinnedIssuer) {
                return ['ok' => false, 'reason' => 'issuer not pinned'];
            }
            // the signed bytes are built first, as in the reference: a body member that has no canonical form is a malformed beacon, not a bad signature
            $msg = self::message($b);
            $issuer = $b->get('issuer');
            $pinned = Ledger::pinFor($pqPins, $issuer);
            $pk = $b->has('pq_pk') ? $b->get('pq_pk') : null;
            $ps = $b->has('pq_sig') ? $b->get('pq_sig') : null;
            if (!is_string($issuer) || Pca::verifyPinnedSuite($b->has('alg') ? $b->get('alg') : null, $issuer, $pk, $msg, $b->get('sig'), $ps, $pinned) !== true) {
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
            // JavaScript arithmetic on whatever `now` is: a string concatenates with the skew, an absent or NaN value makes both comparisons false
            $nowSkew = is_string($now) ? Jsx::toNum($now . self::CLOCK_SKEW_MS) : Jsx::toNum($now) + self::CLOCK_SKEW_MS;
            if ($nowSkew < $iat) {
                return ['ok' => false, 'reason' => 'not yet valid'];
            }
            if (!(Jsx::toNum($now) <= $naf)) {
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
            $ps = $prev instanceof Obj ? (is_string($prev->get('seq')) ? Jsx::toNum($prev->get('seq')) : self::numF($prev->get('seq'))) : null;
            if ($ps === null || !($sq > $ps)) {
                $shown = $ps === null ? 'undefined' : ($prev->get('seq') !== null && is_string($prev->get('seq')) ? $prev->get('seq') : IntentV2::jsNumStr($ps)); // a template literal prints a string seq as is
                return ['ok' => false, 'reason' => 'replayed beacon: seq ' . (int)$sq . ' <= ' . $shown];
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
