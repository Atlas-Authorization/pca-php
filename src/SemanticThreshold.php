<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Attestation.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';

/**
 * The semantic-judge threshold: an ensemble of independently keyed judges each sign a verdict (faithful, score) bound to the action digest and the
 * goal commitment; the action passes when at least `k` DISTINCT trusted judges agree it is faithful at one quantised score, optionally above a
 * conformally calibrated cutoff, and (optionally) only judges with a verified hardware attestation count. Scores are quantised to parts per million
 * before they are signed or counted, so every language computes the same integers. Fails closed; the legacy unbound-PQ opt-out is not offered (a PQ or
 * hybrid verdict counts only under a pinned key). A verdict is `{judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?, pq_pk?, pq_sig?}`.
 */
final class SemanticThreshold
{
    public const DOMAIN = "atlas-pca/semantic-judge/v1\0";
    public const SCORE_SCALE = 1000000;

    /** The registered suite of `$alg` as the reference resolves it: an absent alg is ed25519, a JSON null or any unknown value is null. */
    private static function suiteOf(mixed $alg): ?array
    {
        if ($alg instanceof Undef) {
            return Pq::resolveSigAlg(null);
        }
        return $alg === null ? null : Pq::resolveSigAlg($alg);
    }

    private static function finite(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f);
    }

    /** Math.round: halves go toward +Infinity. */
    private static function jsRound(float $x): float
    {
        $f = floor($x);
        return $x - $f >= 0.5 ? $f + 1 : $f;
    }

    /** The score in parts per million, clamped to [0, 1e6]; a non-finite or non-number score is 0. */
    public static function quantizeScore(mixed $score): int
    {
        if (!self::finite($score)) {
            return 0;
        }
        $q = self::jsRound(Js::num($score) * self::SCORE_SCALE);
        return $q < 0 ? 0 : ($q > self::SCORE_SCALE ? self::SCORE_SCALE : (int)$q);
    }

    /**
     * The signed statement of a verdict: the digests (an absent member stays an undefined member, which has no canonical form), `faithful` (=== true),
     * the quantised score and the judge measurement; `alg` and `pq_pk` are bound in for a non-Ed25519 suite.
     */
    public static function statementOf(mixed $v): Obj
    {
        $jm = Jsx::rd($v, 'judgeMeasurement');
        $base = Obj::of(['v' => 1, 'actionDigest' => Jsx::get($v, 'actionDigest'), 'goalCommitment' => Jsx::get($v, 'goalCommitment'),
            'faithful' => Jsx::get($v, 'faithful') === true, 'score_ppm' => self::quantizeScore(Jsx::get($v, 'score')),
            'judgeMeasurement' => $jm instanceof Undef || $jm === null ? '' : Jsx::str($jm)]);
        $suite = self::suiteOf(Jsx::get($v, 'alg'));
        if ($suite === null || $suite['alg'] === 'ed25519') {
            return $base;
        }
        $base->set('alg', $suite['alg']);
        $base->set('pq_pk', Jsx::get($v, 'pq_pk'));
        return $base;
    }

    /** The signed bytes: the domain, then the strict canonical JSON of the statement (a non-canonical member throws). */
    public static function message(mixed $statement): string
    {
        return self::DOMAIN . Json::canonicalizeNative($statement);
    }

    public static function actionDigest(mixed $action): string
    {
        return Pca::hashCanonical($action);
    }

    public static function verdictDigest(mixed $v): string
    {
        return Pca::hashCanonical(Sign::n($v));
    }

    /**
     * A judge's signed verdict. `$suite`: `['alg' => ?string, 'pq' => ?PqKeyPair]`. Throws on an unknown alg, missing key material or a member with no canonical form.
     * @param string $secretKey the 32-byte Ed25519 seed
     */
    public static function signJudgeVerdict(string $secretKey, mixed $v, ?array $suite = null): Obj
    {
        $jm = Jsx::get($v, 'judgeMeasurement');
        $jm = $jm instanceof Undef || $jm === null ? '' : Jsx::str($jm);
        $alg = $suite['alg'] ?? null;
        $resolved = Pq::resolveSigAlg($alg);
        if ($resolved === null) {
            throw new \RangeException("signJudgeVerdict: unknown signature alg '" . Jsx::str($alg) . "'");
        }
        $pq = $suite['pq'] ?? null;
        $pqPk = Pq::suitePqPublicKey($alg, $pq);
        $nv = Jsx::spread($v);
        $nv->set('judgeMeasurement', $jm);
        if ($resolved['alg'] !== 'ed25519') {
            $nv->set('alg', $resolved['alg']);
            $nv->set('pq_pk', $pqPk ?? Jsx::$U);
        } else {
            $nv->set('alg', Jsx::$U);
            $nv->set('pq_pk', Jsx::$U);
        }
        $ed = new KeyPair($secretKey);
        $fields = Pq::signSuiteArtifact($alg, $ed, $pq, self::message(self::statementOf($nv)));
        $out = Obj::of(['judge' => $ed->public, 'actionDigest' => Jsx::get($v, 'actionDigest'), 'goalCommitment' => Jsx::get($v, 'goalCommitment'),
            'faithful' => Jsx::get($v, 'faithful') === true, 'score' => Jsx::get($v, 'score'), 'judgeMeasurement' => $jm]);
        foreach ($fields as $k => $x) {
            $out->set($k, $x);
        }
        return $out;
    }

    /**
     * One verdict: the judge key, the bindings to the expected action and goal (`$expected`: `{actionDigest, goalCommitment}`), the typed members, and
     * the signature under its suite (a PQ or hybrid suite only under `$pin->pqPins[judge]`). Total: anything malformed is false.
     */
    public static function verifyJudgeVerdict(mixed $v, mixed $expected, mixed $pin = null): bool
    {
        try {
            if (!($v instanceof Obj)) {
                return false;
            }
            $judge = $v->get('judge');
            if (!is_string($judge) || Pca::decodeB64uStrict($judge, 32) === null) {
                return false;
            }
            $ad = Jsx::get($v, 'actionDigest');
            $gc = Jsx::get($v, 'goalCommitment');
            if (!is_string($ad) || !is_string($gc)) {
                return false;
            }
            if ($ad !== Jsx::get($expected, 'actionDigest') || $gc !== Jsx::get($expected, 'goalCommitment')) {
                return false;
            }
            if (!is_bool(Jsx::get($v, 'faithful'))) {
                return false;
            }
            $s = Jsx::get($v, 'score');
            if (!self::finite($s) || Js::num($s) < 0 || Js::num($s) > 1) {
                return false;
            }
            $sig = Jsx::get($v, 'sig');
            if (!is_string(Jsx::get($v, 'judgeMeasurement')) || !is_string($sig)) {
                return false;
            }
            $suite = self::suiteOf(Jsx::get($v, 'alg'));
            if ($suite === null) {
                return false;
            }
            $msg = self::message(self::statementOf($v));
            $pins = Jsx::get($pin, 'pqPins');
            $pinned = Jsx::get($pins, $judge);
            $pq = Jsx::get($v, 'pq_pk');
            $ps = Jsx::get($v, 'pq_sig');
            return Pca::verifyPinnedSuite($suite['alg'], $judge, $pq instanceof Undef ? null : $pq, $msg, $sig, $ps instanceof Undef ? null : $ps,
                is_string($pinned) ? $pinned : null) === true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * A judge's hardware attestation: verified, bound to a TEE report, carrying a measured identity whose runtime measurement equals the signed
     * `judgeMeasurement` and satisfying the approved agent binding. @return array{ok:bool,reason?:mixed,measured?:mixed}
     */
    public static function verifyJudgeAttestation(mixed $judgeMeasurement, mixed $attestation, mixed $approved = null): array
    {
        if (Jsx::get($attestation, 'ok') !== true) {
            $r = Jsx::get($attestation, 'reason');
            return ['ok' => false, 'reason' => $r instanceof Undef || $r === null ? 'no verified attestation for this judge (fail-closed)' : $r];
        }
        if (Jsx::get($attestation, 'bound') !== true) {
            return ['ok' => false, 'reason' => 'judge attestation not bound to a TEE report (report_data binding unconfirmed)'];
        }
        $measured = Jsx::get($attestation, 'measured');
        if (!($measured instanceof Obj) && !(is_array($measured))) {
            return ['ok' => false, 'reason' => 'judge attestation carries no measured identity'];
        }
        if (!is_string($judgeMeasurement) || $judgeMeasurement === '') {
            return ['ok' => false, 'reason' => 'verdict carries no judgeMeasurement to bind to the attested identity'];
        }
        if (Jsx::get($measured, 'runtime_measurement') !== $judgeMeasurement) {
            return ['ok' => false, 'reason' => 'attested enclave measurement does not match the signed judgeMeasurement'];
        }
        $appraisal = Attestation::matchAgentBinding($measured, $approved);
        if ($appraisal !== null && $appraisal !== '') {
            return ['ok' => false, 'reason' => $appraisal];
        }
        return ['ok' => true, 'measured' => $measured];
    }

    private static function clampAlpha(mixed $alpha): float
    {
        if (!self::finite($alpha)) {
            return 1.0;
        }
        $a = (float)Js::num($alpha);
        return $a <= 0 ? 5e-324 : ($a > 1 ? 1.0 : $a);
    }

    /** @return list<float> the scores of the unfaithful samples */
    private static function unfaithful(mixed $samples): array
    {
        $out = [];
        foreach (is_array($samples) && array_is_list($samples) ? $samples : [] as $s) {
            if (Jsx::truthy($s) && Jsx::get($s, 'faithful') === false && self::finite(Jsx::get($s, 'score'))) {
                $out[] = (float)Js::num(Jsx::get($s, 'score'));
            }
        }
        return $out;
    }

    /** The cutoff a score must EXCEED: the (1 - alpha) conformal quantile of the unfaithful samples' scores; +Infinity when there are too few. */
    public static function conformalThreshold(mixed $calibration): float
    {
        $alpha = self::clampAlpha(Jsx::get($calibration, 'alpha'));
        $u = self::unfaithful(Jsx::get($calibration, 'samples'));
        $m = count($u);
        if ($m === 0) {
            return INF;
        }
        $rank = (int)ceil(($m + 1) * (1 - $alpha));
        if ($rank > $m) {
            return INF;
        }
        sort($u, SORT_NUMERIC);
        return $u[max($rank, 1) - 1];
    }

    /** The fraction of unfaithful samples whose score exceeds `$cutoff` (0 with none). */
    public static function empiricalFalseAllowRate(mixed $samples, mixed $cutoff): int|float
    {
        $u = self::unfaithful($samples);
        if ($u === []) {
            return 0;
        }
        $allowed = 0;
        foreach ($u as $s) {
            $allowed += Jsx::gt($s, $cutoff) ? 1 : 0;
        }
        return $allowed / count($u);
    }

    /**
     * `{ok, agreeCount, aggregateScore, cutoff?, reason?}`. `$opts`: `{judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?, attestation?: {resolve:
     * callable(verdict), require, approved?}}`. A judge counts once, only when every one of its verdicts verifies and they all agree (faithful at one quantised score).
     * @return array<string,mixed>
     */
    public static function verifyThreshold(mixed $verdicts, mixed $opts): array
    {
        $k = Jsx::get($opts, 'k');
        $allow = [];
        $jk = Jsx::get($opts, 'judgeKeys');
        foreach (is_array($jk) && array_is_list($jk) ? $jk : [] as $key) {
            if (is_string($key) && Pca::decodeB64uStrict($key, 32) !== null) {
                $allow[$key] = true;
            }
        }
        $ad = Jsx::get($opts, 'actionDigest');
        $gc = Jsx::get($opts, 'goalCommitment');
        if (!is_string($ad) || !is_string($gc)) {
            return ['ok' => false, 'agreeCount' => 0, 'aggregateScore' => 0, 'reason' => 'missing action/goal binding'];
        }
        if (!Js::isNum($k) || !self::finite($k) || Js::num($k) != floor(Js::num($k)) || Js::num($k) < 1) {
            return ['ok' => false, 'agreeCount' => 0, 'aggregateScore' => 0, 'reason' => 'invalid quorum k=' . Jsx::str($k)];
        }
        $att = Jsx::get($opts, 'attestation');
        $by = [];
        foreach (is_array($verdicts) && array_is_list($verdicts) ? $verdicts : [] as $v) {
            $j = Jsx::get($v, 'judge');
            if (!Jsx::truthy($v) || !is_string($j) || !isset($allow[$j])) {
                continue;
            }
            if (!self::verifyJudgeVerdict($v, Obj::of(['actionDigest' => $ad, 'goalCommitment' => $gc]), $opts)) {
                continue;
            }
            if (Jsx::truthy($att) && Jsx::get($att, 'require') === true) {
                $resolve = Jsx::get($att, 'resolve');
                if (!self::verifyJudgeAttestation(Jsx::get($v, 'judgeMeasurement'), $resolve($v), Jsx::get($att, 'approved'))['ok']) {
                    continue;
                }
            }
            $by[$j]['faithful'][Jsx::get($v, 'faithful') === true ? 't' : 'f'] = true;
            $by[$j]['score'][self::quantizeScore(Jsx::get($v, 'score'))] = true;
        }
        $agreeing = [];
        foreach ($by as $j => $g) {
            if (array_keys($g['faithful']) === ['t'] && count($g['score']) === 1) {
                $agreeing[] = [(string)$j, (int)array_key_first($g['score'])];
            }
        }
        usort($agreeing, static fn(array $a, array $b): int => IntentWb::compareUtf8($a[0], $b[0]));
        $n = count($agreeing);
        $acc = 0.0;
        foreach ($agreeing as [, $q]) {
            $acc = $acc + $q / self::SCORE_SCALE;
        }
        $aggregate = $n === 0 ? 0 : $acc / $n;
        if ($n < Js::num($k)) {
            return ['ok' => false, 'agreeCount' => $n, 'aggregateScore' => $aggregate, 'reason' => "only $n distinct trusted judge(s) agree, need " . Jsx::str($k)];
        }
        $cal = Jsx::get($opts, 'calibration');
        if (Jsx::truthy($cal)) {
            $cutoff = self::conformalThreshold($cal);
            if (!($aggregate > $cutoff)) {
                return ['ok' => false, 'agreeCount' => $n, 'aggregateScore' => $aggregate, 'cutoff' => $cutoff,
                    'reason' => 'aggregateScore ' . Js::str($aggregate) . ' does not exceed calibrated cutoff ' . Js::str($cutoff)];
            }
            return ['ok' => true, 'agreeCount' => $n, 'aggregateScore' => $aggregate, 'cutoff' => $cutoff];
        }
        return ['ok' => true, 'agreeCount' => $n, 'aggregateScore' => $aggregate];
    }

    /**
     * The semantic hook: `hook(ctx)` -> `{enforced, ok?, reason?}`. `$opts`: `{judgeKeys, k, calibration?, verdicts: callable(ctx), goalCommitment: callable(ctx),
     * actionDigest?: callable(ctx) (default: the content hash of ctx.pcactn.action), optionalWhenAbsent?, attestation?: callable(ctx)}`. With no ensemble
     * the hook is closed unless `optionalWhenAbsent`.
     * @return \Closure(mixed):array<string,mixed>
     */
    public static function createVerifier(mixed $opts): \Closure
    {
        $verdictsOf = Jsx::get($opts, 'verdicts');
        $goalOf = Jsx::get($opts, 'goalCommitment');
        $digestOf = Jsx::get($opts, 'actionDigest');
        $attOf = Jsx::get($opts, 'attestation');
        return static function (mixed $ctx) use ($opts, $verdictsOf, $goalOf, $digestOf, $attOf): array {
            $goal = $goalOf($ctx);
            $verdicts = $verdictsOf($ctx);
            if (!is_string($goal) || $verdicts instanceof Undef) {
                return Jsx::truthy(Jsx::get($opts, 'optionalWhenAbsent')) ? ['enforced' => false]
                    : ['enforced' => true, 'ok' => false, 'reason' => 'no semantic ensemble available for this action (fail-closed)'];
            }
            $att = is_callable($attOf) ? $attOf($ctx) : Jsx::$U;
            $o = Obj::of(['judgeKeys' => Jsx::get($opts, 'judgeKeys'), 'k' => Jsx::get($opts, 'k'), 'goalCommitment' => $goal,
                'actionDigest' => is_callable($digestOf) ? $digestOf($ctx) : self::actionDigest(Jsx::rd(Jsx::rd($ctx, 'pcactn'), 'action')),
                'calibration' => Jsx::get($opts, 'calibration')]);
            if (Jsx::truthy($att)) {
                $o->set('attestation', $att);
            }
            $res = self::verifyThreshold($verdicts, $o);
            return $res['ok'] ? ['enforced' => true, 'ok' => true]
                : ['enforced' => true, 'ok' => false, 'reason' => $res['reason'] ?? 'semantic threshold not met'];
        };
    }

    /** The risk the semantic ensemble contributes: `1 - aggregateScore` clamped to [0, 1]; a non-finite score is the worst case, 1. */
    public static function riskContribution(mixed $aggregateScore): int|float
    {
        if (!self::finite($aggregateScore)) {
            return 1;
        }
        $r = 1 - Js::num($aggregateScore);
        return $r < 0 ? 0 : ($r > 1 ? 1 : $r);
    }
}
