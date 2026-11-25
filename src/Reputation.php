<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/BondSettlement.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';

/**
 * Explainable reputation and coverage pricing (the TypeScript reference reputation.ts and reputation-evidence.ts are authoritative):
 * a score from observed outcomes (deny rate, step-up rate, slashed disputes), a coverage price from that score, a quote signed by
 * the underwriter, and disputes derived only from guardian-signed settlement records.
 *
 * Values are the parsed-JSON model (Obj, list arrays, string, Num, bool, null); a number may also be a PHP int or float.
 */
final class Reputation
{
    public const MAX_REPUTATION_RECORDS = 100000;
    public const COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\0";
    private const OUTCOMES = ['auto', 'step_up', 'deny', 'executed'];

    /** The double of a JSON or PHP number (NaN and the infinities included), else null. */
    private static function d(mixed $x): ?float
    {
        return $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
    }

    private static function fin(mixed $x): ?float
    {
        $v = self::d($x);
        return $v !== null && is_finite($v) ? $v : null;
    }

    private static function list(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** Why `{subject, events?, disputes?}` is not a reputation input, or null. */
    public static function validateReputationInput(mixed $input): ?string
    {
        $subject = $input instanceof Obj ? $input->get('subject') : null;
        if (!is_string($subject) || $subject === '') {
            return 'subject must be a non-empty string';
        }
        $events = $input->has('events') ? $input->get('events') : [];
        $disputes = $input->has('disputes') ? $input->get('disputes') : [];
        if (!self::list($events) || !self::list($disputes)) {
            return 'events and disputes must be arrays';
        }
        if (count($events) > self::MAX_REPUTATION_RECORDS || count($disputes) > self::MAX_REPUTATION_RECORDS) {
            return 'too many records';
        }
        foreach ($events as $e) {
            if (!($e instanceof Obj) || !in_array($e->get('outcome'), self::OUTCOMES, true)) {
                return 'event with an unknown outcome';
            }
        }
        foreach ($disputes as $d) {
            if (!($d instanceof Obj) || !is_string($d->get('id')) || $d->get('id') === '') {
                return 'dispute without an id';
            }
            if ($d->get('subject') !== $subject) {
                return 'dispute for another subject';
            }
            if (!is_bool($d->get('slashed'))) {
                return 'dispute.slashed must be a boolean';
            }
            if (($at = self::fin($d->get('at'))) === null || $at < 0) {
                return 'dispute.at must be finite and >= 0';
            }
            if ($d->has('amount') && (($amount = self::fin($d->get('amount'))) === null || $amount < 0)) {
                return 'dispute.amount must be finite and >= 0';
            }
        }
        return null;
    }

    /**
     * The reputation of a subject. An invalid input never throws: the score is 0 with the factor `invalid input: <reason>`. No
     * history is 0.5 (unproven). Disputes are counted once per id.
     *
     * @return array{subject: string, actions: int, autos: int, stepUps: int, denies: int, slashes: int, disputes: int, score: float, factors: list<string>}
     */
    public static function reputation(mixed $input): array
    {
        $row = static fn(string $subject, array $n, float $score, array $factors): array => ['subject' => $subject, 'actions' => $n[0], 'autos' => $n[1], 'stepUps' => $n[2],
            'denies' => $n[3], 'slashes' => $n[4], 'disputes' => $n[5], 'score' => $score, 'factors' => $factors];
        $bad = self::validateReputationInput($input);
        if ($bad !== null) {
            $s = $input instanceof Obj ? $input->get('subject') : null;
            return $row($s === null ? '' : IntentWb::jsStr($s), [0, 0, 0, 0, 0, 0], 0.0, ["invalid input: $bad"]);
        }
        $n = ['auto' => 0, 'step_up' => 0, 'deny' => 0, 'executed' => 0];
        $events = $input->has('events') ? $input->get('events') : [];
        foreach ($events as $e) {
            $n[$e->get('outcome')]++;
        }
        $seen = [];
        $slashes = 0;
        foreach ($input->has('disputes') ? $input->get('disputes') : [] as $d) {
            if (!isset($seen['k' . $d->get('id')])) {
                $seen['k' . $d->get('id')] = true;
                $slashes += $d->get('slashed') ? 1 : 0;
            }
        }
        $actions = count($events);
        $counts = [$actions, $n['auto'], $n['step_up'], $n['deny'], $slashes, count($seen)];
        if ($actions === 0 && $seen === []) {
            return $row($input->get('subject'), $counts, 0.5, ['unproven (no history)']);
        }
        $score = 1.0;
        $factors = [];
        if ($actions > 0) {
            $denyRate = $n['deny'] / $actions;
            $stepUpRate = $n['step_up'] / $actions;
            if ($denyRate > 0) {
                $score -= 0.6 * $denyRate;
                $factors[] = 'deny rate ' . AnalyzerJs::toFixed($denyRate * 100, 0) . '%';
            }
            if ($stepUpRate > 0) {
                $score -= 0.15 * $stepUpRate;
                $factors[] = 'step-up rate ' . AnalyzerJs::toFixed($stepUpRate * 100, 0) . '%';
            }
        }
        if ($slashes > 0) {
            $score -= min(0.8, 0.3 * $slashes);
            $factors[] = "$slashes slashed dispute" . ($slashes > 1 ? 's' : '');
        }
        return $row($input->get('subject'), $counts, max(0.0, min(1.0, $score)), $factors === [] ? ['clean history'] : $factors);
    }

    /**
     * Price coverage of `$exposure` for a reputation `{score}`. `$opts` (an Obj or an array) may carry `baseRate` (default 0.01),
     * `riskLoad` (4) and `minScore` (0.25, the underwriting floor). A score outside [0, 1] or below the floor is declined.
     *
     * @return array{declined: bool, premium: float, coverage: float, rationale: string}
     */
    public static function priceCoverage(mixed $rep, mixed $exposure, mixed $opts = null): array
    {
        $baseRate = self::d(Js::opt($opts, 'baseRate')) ?? 0.01;
        $riskLoad = self::d(Js::opt($opts, 'riskLoad')) ?? 4.0;
        $minScore = self::d(Js::opt($opts, 'minScore')) ?? 0.25;
        $score = self::fin(Js::opt($rep, 'score'));
        if ($score === null || $score < 0 || $score > 1) {
            return ['declined' => true, 'premium' => 0.0, 'coverage' => 0.0, 'rationale' => 'invalid reputation score'];
        }
        $e = self::fin($exposure);
        $exp = $e !== null && $e > 0 ? $e : 0.0;
        if ($score < $minScore) {
            return ['declined' => true, 'premium' => 0.0, 'coverage' => 0.0,
                'rationale' => 'reputation ' . AnalyzerJs::toFixed($score, 2) . ' below underwriting floor ' . IntentWb::jsNumStr($minScore)];
        }
        $load = 1 + $riskLoad * (1 - $score);
        return ['declined' => false, 'premium' => $baseRate * $exp * $load, 'coverage' => $exp, 'rationale' => 'base ' . IntentWb::jsNumStr($baseRate) . ' × exposure '
            . IntentWb::jsNumStr($exp) . ' × load ' . AnalyzerJs::toFixed($load, 2) . ' (score ' . AnalyzerJs::toFixed($score, 2) . ')'];
    }

    private static function quoteMessage(Obj $claim): string
    {
        return self::COVERAGE_QUOTE_DOMAIN . Json::canonicalizeLenient($claim);
    }

    /**
     * A coverage quote for `$rep` (`{subject, score}`) signed by the underwriter, valid from `$now` for `$ttlMs` milliseconds. Throws
     * on a negative or non-finite exposure, a non-finite `$now`, a `$ttlMs` that is not a positive finite number, a score outside
     * [0, 1] or a reputation without a subject.
     */
    public static function issueCoverageQuote(mixed $rep, mixed $exposure, KeyPair $underwriter, mixed $now, mixed $ttlMs, mixed $opts = null): Obj
    {
        $exp = self::fin($exposure);
        if ($exp === null || $exp < 0) {
            throw new \InvalidArgumentException('issueCoverageQuote: exposure must be finite and >= 0');
        }
        $t = self::fin($now);
        $ttl = self::fin($ttlMs);
        if ($t === null || $ttl === null || !($ttl > 0)) {
            throw new \InvalidArgumentException('issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0');
        }
        $score = self::fin(Js::opt($rep, 'score'));
        if ($score === null || $score < 0 || $score > 1) {
            throw new \InvalidArgumentException('issueCoverageQuote: invalid reputation score');
        }
        if (!Js::has($rep, 'subject')) {
            throw new \InvalidArgumentException('issueCoverageQuote: the reputation has no subject');
        }
        $o = ['baseRate' => self::d(Js::opt($opts, 'baseRate')) ?? 0.01, 'riskLoad' => self::d(Js::opt($opts, 'riskLoad')) ?? 4.0, 'minScore' => self::d(Js::opt($opts, 'minScore')) ?? 0.25];
        $p = self::priceCoverage($rep, $exp, $o);
        $claim = Sign::n(['v' => 1, 'subject' => Js::opt($rep, 'subject'), 'score' => $score, 'exposure' => $exp] + $o + ['declined' => $p['declined'], 'premium' => $p['premium'],
            'coverage' => $p['coverage'], 'issued_at' => $t, 'expires_at' => $t + $ttl, 'underwriter' => $underwriter->public]);
        $claim->set('sig', Pca::b64u($underwriter->sign(self::quoteMessage($claim))));
        return $claim;
    }

    /**
     * Verify a coverage quote under the pinned `$underwriter` key at `$now`: shape, key, signature, validity window, and that the
     * stated price is what the stated inputs give. Never throws.
     *
     * @return array{ok: bool, reason?: string} reason: malformed, underwriter, signature, not-yet-valid, expired or price-mismatch
     */
    public static function verifyCoverageQuote(mixed $q, mixed $underwriter, mixed $now): array
    {
        $no = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!($q instanceof Obj) || self::d($q->get('v')) !== 1.0 || !is_string($q->get('sig')) || !is_bool($q->get('declined')) || !is_string($q->get('subject'))) {
                return $no('malformed');
            }
            $n = [];
            foreach (['score', 'exposure', 'baseRate', 'riskLoad', 'minScore', 'premium', 'coverage', 'issued_at', 'expires_at'] as $k) {
                if (($n[$k] = self::fin($q->get($k))) === null) {
                    return $no('malformed');
                }
            }
            if (!is_string($underwriter) || $underwriter !== $q->get('underwriter')) {
                return $no('underwriter');
            }
            if (!Pca::verifyEd25519B64u($underwriter, self::quoteMessage($q->without('sig')), $q->get('sig'))) {
                return $no('signature');
            }
            $t = self::fin($now);
            if ($t === null || $t < $n['issued_at']) {
                return $no('not-yet-valid');
            }
            if ($t >= $n['expires_at']) {
                return $no('expired');
            }
            $p = self::priceCoverage(['score' => $n['score']], $n['exposure'], ['baseRate' => $n['baseRate'], 'riskLoad' => $n['riskLoad'], 'minScore' => $n['minScore']]);
            return $p['declined'] !== $q->get('declined') || $p['premium'] !== $n['premium'] || $p['coverage'] !== $n['coverage'] ? $no('price-mismatch') : ['ok' => true];
        } catch (\Throwable) {
            return $no('malformed');
        }
    }

    /**
     * Disputes derived ONLY from settlement records the guardian signed. `$subjectOf` maps a claim id to its subject (null: unknown);
     * a record that is unsigned, tampered or of an unknown claim is rejected and counted; an `open` record is not an outcome.
     *
     * @param callable(string): ?string $subjectOf
     * @return array{disputes: list<Obj>, rejected: int}
     */
    public static function disputesFromSettlements(mixed $records, mixed $guardianPublicKey, callable $subjectOf, mixed $pin = null): array
    {
        $disputes = [];
        $rejected = 0;
        foreach (self::list($records) ? $records : throw new \InvalidArgumentException('disputesFromSettlements: records is not a list') as $r) {
            $subject = $r instanceof Obj && is_string($r->get('claimId')) ? $subjectOf($r->get('claimId')) : null;
            if ($subject === null || !BondSettlement::verifySettlement($r, $guardianPublicKey, $pin)) {
                $rejected++;
                continue;
            }
            if ($r->get('action') === 'open') {
                continue;
            }
            $d = Obj::of(['id' => BondSettlement::settlementRecordDigest($r), 'subject' => $subject, 'slashed' => $r->get('action') === 'slash', 'at' => $r->get('at')]);
            if ($r->has('amount')) {
                $d->set('amount', $r->get('amount'));
            }
            $disputes[] = $d;
        }
        return ['disputes' => $disputes, 'rejected' => $rejected];
    }
}
