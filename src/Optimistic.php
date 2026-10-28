<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Ledger.php';

/**
 * Optimistic-path wire verification: bonded claims, the challenge window, fraud proofs (wire level) and settlement records.
 * Verdicts match the shared extension-layer vectors (optimistic-vectors.json). A fraud proof that passes
 * {@see fraudProofWireCheck} is well-formed and self-consistent only; recomputing the policy decision it asserts is the
 * settlement layer's job. The signatures cover the LENIENT canonical form ({@see Json::canonicalizeLenient}). Total: every
 * function answers, none throws. Inputs are the library's JSON values (Obj, lists, strings, Num).
 */
final class Optimistic
{
    public const IRREVERSIBLE_CLASS = 'irreversible';
    public const CLAIM_DOMAIN = "atlas-pca/optimistic/v1\0";
    public const SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\0";
    private const FRAUD_KINDS = ['policy-denied', 'risk-understated', 'optimistic-not-allowed', 'irreversible'];
    private const DEFAULT_R_MARGIN = 1e-9;
    private const MAX_SAFE = 9007199254740991;
    /** minWindowMs, maxWindowMs, defaultWindowMs, maxSkewMs */
    public const DEFAULT_WINDOW_POLICY = ['minWindowMs' => 1000, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000, 'maxSkewMs' => 5000];

    /** A finite JSON number (Num or native) as a float, else null (a bool or string is never a number). */
    private static function n(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    /** JS strict equality for JSON scalars (numbers by value; objects and arrays never equal). */
    private static function same(mixed $a, mixed $b): bool
    {
        $x = self::n($a);
        $y = self::n($b);
        if ($x !== null || $y !== null || $a instanceof Num || $b instanceof Num) {
            return $x !== null && $y !== null && $x === $y;
        }
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        return is_string($a) && is_string($b) && $a === $b;
    }

    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    private static function nonempty(mixed $x): bool
    {
        return is_string($x) && $x !== '';
    }

    private static function nonneg(mixed $x): bool
    {
        $v = self::n($x);
        return $v !== null && $v >= 0;
    }

    private static function safeInt(mixed $x): bool
    {
        $v = self::n($x);
        return $v !== null && floor($v) === $v && abs($v) <= self::MAX_SAFE;
    }

    /** The window policy as floats (an Obj as in the vector file, or a PHP array). */
    private static function policy(mixed $p): array
    {
        $out = self::DEFAULT_WINDOW_POLICY;
        foreach (array_keys($out) as $k) {
            $v = $p instanceof Obj ? $p->get($k) : (is_array($p) ? ($p[$k] ?? null) : null);
            $f = self::n($v);
            if ($f === null) {
                if ($p !== null) {
                    throw new \InvalidArgumentException("window policy $k");
                }
                continue;
            }
            $out[$k] = $f;
        }
        return $out;
    }

    private static function windowError(mixed $issuedAt, mixed $windowMs, mixed $serverNow, array $policy): ?string
    {
        if (self::n($serverNow) === null) {
            return 'server time is not finite';
        }
        $i = self::n($issuedAt);
        $w = self::n($windowMs);
        if ($i === null || $w === null) {
            return 'malformed challenge window';
        }
        if (abs($i - self::n($serverNow)) > $policy['maxSkewMs']) {
            return 'issued_at is outside the allowed skew of server time';
        }
        if ($w < $policy['minWindowMs']) {
            return 'challenge window is below the minimum';
        }
        if ($w > $policy['maxWindowMs']) {
            return 'challenge window exceeds the maximum';
        }
        return null;
    }

    /**
     * First failing check of a bonded claim: malformed, irreversible, digest, claimed_r, window, signature; else `ok`.
     * @param mixed $windowPolicy Obj|array|null (minWindowMs, maxWindowMs, defaultWindowMs, maxSkewMs); null = the defaults
     */
    public static function claimCheck(mixed $claim, mixed $expectedPcactnDigest, mixed $signerPublic, mixed $serverNow, mixed $windowPolicy = null): string
    {
        try {
            if (!($claim instanceof Obj)) {
                return 'malformed';
            }
            if ($claim->get('reversibility_class') === self::IRREVERSIBLE_CLASS) {
                return 'irreversible';
            }
            if (!$claim->has('pcactn_digest') || !self::same($claim->get('pcactn_digest'), $expectedPcactnDigest)) {
                return 'digest';
            }
            if (self::n($claim->get('claimed_r')) === null) {
                return 'claimed_r';
            }
            if (self::windowError($claim->get('issued_at'), $claim->get('challenge_window_ms'), $serverNow, self::policy($windowPolicy)) !== null) {
                return 'window';
            }
            $sig = $claim->get('sig');
            if (!is_string($sig) || !is_string($signerPublic)
                || !Pca::verifyEd25519B64u($signerPublic, self::CLAIM_DOMAIN . Json::canonicalizeLenient($claim->without('sig')), $sig)) {
                return 'signature';
            }
            return 'ok';
        } catch (\Throwable) {
            return 'malformed';
        }
    }

    /** The last instant (epoch ms) a challenge is accepted: issued_at + challenge_window_ms. */
    public static function challengeWindowEnd(Obj $claim): float
    {
        return (float)self::n($claim->get('issued_at')) + (float)self::n($claim->get('challenge_window_ms'));
    }

    /** True while challenges are accepted (inclusive end). */
    public static function withinChallengeWindow(Obj $claim, mixed $now): bool
    {
        $x = self::n($now);
        return $x !== null && $x <= self::challengeWindowEnd($claim);
    }

    /** `open` while challenges are accepted, else `finalized`. */
    public static function claimStatus(Obj $claim, mixed $now): string
    {
        return self::withinChallengeWindow($claim, $now) ? 'open' : 'finalized';
    }

    /** First failing wire check of a fraud proof: malformed, digest, bond, claimed_r, kind, consistency; else `ok`. */
    public static function fraudProofWireCheck(mixed $claim, mixed $proof): string
    {
        try {
            if (!($proof instanceof Obj) || !($claim instanceof Obj)) {
                return 'malformed';
            }
            $d = $proof->get('decision');
            if (!($d instanceof Obj) || !is_bool($d->get('releaseGuardianShare')) || !is_bool($d->get('optimisticAllowed'))
                || self::n($d->get('r')) === null) {
                return 'malformed';
            }
            foreach (['pcactn_digest', 'bond_ref', 'reason'] as $k) {
                if (!is_string($proof->get($k))) {
                    return 'malformed';
                }
            }
            if (!$claim->has('pcactn_digest') || !self::same($proof->get('pcactn_digest'), $claim->get('pcactn_digest'))) {
                return 'digest';
            }
            if (!$claim->has('bond_ref') || !self::same($proof->get('bond_ref'), $claim->get('bond_ref'))) {
                return 'bond';
            }
            if (!$proof->has('claimed_r') || !$claim->has('claimed_r') || !self::same($proof->get('claimed_r'), $claim->get('claimed_r'))) {
                return 'claimed_r';
            }
            $kind = $proof->get('kind');
            if (!is_string($kind) || !in_array($kind, self::FRAUD_KINDS, true)) {
                return 'kind';
            }
            $m = self::n($proof->get('r_margin'));
            $margin = $m !== null ? max(0.0, $m) : self::DEFAULT_R_MARGIN;
            $ev = self::g(self::g(self::g($proof->get('evidence'), 'action'), 'action'), 'reversibility_class');
            $rel = $d->get('releaseGuardianShare');
            $allowed = $d->get('optimisticAllowed');
            if ($kind === 'irreversible') {
                $holds = $claim->get('reversibility_class') === self::IRREVERSIBLE_CLASS || $ev === self::IRREVERSIBLE_CLASS;
            } elseif ($kind === 'policy-denied') {
                $holds = !$rel;
            } elseif ($kind === 'optimistic-not-allowed') {
                $holds = $rel && !$allowed;
            } else {
                $cr = self::n($claim->get('claimed_r'));
                if ($cr === null) {
                    return 'malformed';
                }
                $holds = $rel && $allowed && (float)self::n($d->get('r')) > $cr + $margin;
            }
            return $holds ? 'ok' : 'consistency';
        } catch (\Throwable) {
            return 'malformed';
        }
    }

    /** First failing check of a settlement record: malformed, suite, shape, split, signature; else `ok`. */
    public static function settlementWireCheck(mixed $record, mixed $guardianPublic, mixed $pins = null): string
    {
        try {
            if (!($record instanceof Obj)) {
                return 'malformed';
            }
            if ($record->has('alg') && !Pca::suiteImplemented($record->get('alg'))) { // a suite this runtime lacks is `suite`, never accepted
                return 'suite';
            }
            $r = $record;
            $slash = $r->get('action') === 'slash';
            $ev = $r->get('evidenceDigest');
            $amount = self::n($r->get('amount'));
            if (!self::nonempty($r->get('claimId')) || !in_array($r->get('action'), ['open', 'release', 'slash'], true)
                || $amount === null || $amount <= 0
                || !self::nonempty($r->get('from')) || !self::nonempty($r->get('to')) || self::n($r->get('at')) === null
                || !is_string($ev) || ($slash ? $ev === '' : $ev !== '')
                || ($slash ? !($r->get('split') instanceof Obj) : $r->has('split'))
                || !is_string($r->get('sig'))
                || ($r->has('guardian_epoch') && !(self::safeInt($r->get('guardian_epoch')) && self::n($r->get('guardian_epoch')) >= 0))) {
                return 'shape';
            }
            if ($slash) {
                $sp = $r->get('split');
                $c = $sp->get('challengerReward');
                $v = $sp->get('victimCompensation');
                $t = $sp->get('treasuryRemainder');
                $ok = self::same($sp->get('amount'), $r->get('amount')) && self::nonneg($c) && self::nonneg($v) && self::nonneg($t)
                    && ((float)self::n($c) + (float)self::n($v)) + (float)self::n($t) === $amount
                    && self::nonempty($sp->get('victimAccount')) && self::same($sp->get('treasuryAccount'), $r->get('to'));
                if ($ok) {
                    if ($sp->has('challengerAccount') && $sp->get('challengerAccount') === null) {
                        $ok = self::n($c) === 0.0 && self::n($v) === 0.0 && self::n($t) === $amount;
                    } else {
                        $ok = $sp->has('challengerAccount') && self::nonempty($sp->get('challengerAccount'));
                    }
                }
                if (!$ok) {
                    return 'split';
                }
            }
            $body = $r->without('sig', 'pq_sig');
            $alg = $r->has('alg') ? $r->get('alg') : null;
            return is_string($guardianPublic)
                && Pca::verifyPinnedSuite($alg, $guardianPublic, $r->get('pq_pk'), self::SETTLEMENT_DOMAIN . Json::canonicalizeLenient($body),
                    $r->get('sig'), $r->get('pq_sig'), Ledger::pinFor($pins, $guardianPublic)) === true
                ? 'ok' : 'signature';
        } catch (\Throwable) {
            return 'malformed';
        }
    }
}
