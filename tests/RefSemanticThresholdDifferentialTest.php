<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SemanticThreshold.php';

use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\SemanticThreshold;
use Atlas\Pca\Undef;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The semantic-judge threshold against the TS reference: every case of test-data/ref-semantic-threshold.json.gz (the signed statement and message, verdict
 * signing under three suites, verdict and attestation verification, the k-of-n threshold with calibration, pins and the hardware gate, the hook, the risk
 * contribution) and the five semantic functions of ref-intent-routing.json.gz. A non-finite number is `{"$num": ...}` in the first corpus and "inf" in the
 * second. RULING: `allowUnboundPq` is not ported, so the cases the reference accepts only through it must be REFUSED (counted).
 */
final class RefSemanticThresholdDifferentialTest extends TestCase
{
    private const FILE = 'ref-semantic-threshold.json.gz';
    private const ROUTING = 'ref-intent-routing.json.gz';
    private const FNS = ['quantizeScore' => 26, 'statementOf' => 21, 'semanticJudgeMessage' => 11, 'signJudgeVerdict' => 13, 'verdictDigest' => 4, 'verifyJudgeVerdict' => 27,
        'verifyJudgeAttestation' => 18, 'verifySemanticThreshold' => 39, 'semanticVerifier' => 12, 'semanticRiskContribution' => 14, 'constants' => 1];
    private const ROUTING_FNS = ['quantizeScore' => 15, 'verifyJudgeVerdict' => 74, 'conformalThreshold' => 18, 'empiricalFalseAllowRate' => 36, 'verifySemanticThreshold' => 345];

    public static function provide(): array
    {
        $out = Base::datasets(self::FILE);
        foreach (Base::datasets(self::ROUTING) as $k => $v) {
            if (isset(self::ROUTING_FNS[$v[1]])) {
                $out["routing $k"] = $v;
            }
        }
        return $out;
    }

    private static function secret(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    /** `{"$num": ...}` to the double. */
    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    /** A native result in the corpus's form: undefined members dropped, non-finite numbers as the corpus writes them. */
    private static function form(mixed $x, bool $routing): mixed
    {
        if (is_float($x) && !is_finite($x)) {
            return $routing ? 'inf' : Obj::of(['$num' => is_nan($x) ? 'NaN' : ($x > 0 ? 'Infinity' : '-Infinity')]);
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                if (!($x->get($k) instanceof Undef)) {
                    $o->set($k, self::form($x->get($k), $routing));
                }
            }
            return $o;
        }
        if (is_array($x)) {
            return array_map(static fn($e) => self::form($e, $routing), $x);
        }
        return $x;
    }

    private static function att(mixed $a): mixed
    {
        if (!($a instanceof Obj)) {
            return Jsx::$U;
        }
        $o = Obj::of(['require' => $a->get('require'), 'resolve' => static function ($v) use ($a) {
            $by = $a->get('byJudge');
            $j = Jsx::get($v, 'judge');
            return is_string($j) && $by instanceof Obj && $by->has($j) ? $by->get($j) : Jsx::$U;
        }]);
        if ($a->has('approved')) {
            $o->set('approved', $a->get('approved'));
        }
        return $o;
    }

    private static function opts(mixed $o): mixed
    {
        $o = self::conv($o);
        if ($o instanceof Obj && $o->has('attestation')) {
            $o->set('attestation', self::att($o->get('attestation')));
        }
        return $o;
    }

    private static function unbound(mixed $x): bool
    {
        return $x instanceof Obj && $x->get('allowUnboundPq') === true;
    }

    private static function accepted(mixed $out): bool
    {
        return $out === true || ($out instanceof Obj && $out->get('ok') === true);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Jsx::init();
        $r = $file === self::ROUTING;
        Base::run($file, $fn, $k, [
            'quantizeScore' => static fn(array $a) => SemanticThreshold::quantizeScore(self::conv($a[0])),
            'statementOf' => static fn(array $a) => self::form(SemanticThreshold::statementOf(self::conv($a[0])), $r),
            'semanticJudgeMessage' => static fn(array $a) => Base::outBytes(SemanticThreshold::message(self::conv($a[0]))),
            'signJudgeVerdict' => static function (array $a) use ($r) {
                $su = $a[2];
                $suite = null;
                if ($su instanceof Obj) {
                    $suite = ['alg' => $su->get('alg'), 'pq' => $su->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed'))) : null];
                }
                return self::form(SemanticThreshold::signJudgeVerdict(self::secret($a[0]), self::conv($a[1]), $suite), $r);
            },
            'verdictDigest' => static fn(array $a) => SemanticThreshold::verdictDigest(self::conv($a[0])),
            'verifyJudgeVerdict' => static function (array $a, Obj $c) {
                $have = SemanticThreshold::verifyJudgeVerdict($a[0], $a[1], $a[2]);
                if (self::unbound($a[2]) && self::accepted($c->get('out'))) {
                    Assert::assertFalse($have, 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
                    return [Base::SKIP, 'allowUnboundPq ruling'];
                }
                return $have;
            },
            'verifyJudgeAttestation' => static fn(array $a) => self::form(SemanticThreshold::verifyJudgeAttestation($a[0], $a[1], $a[2]), $r),
            'verifySemanticThreshold' => static function (array $a, Obj $c) use ($r) {
                $have = self::form(SemanticThreshold::verifyThreshold($a[0], self::opts($a[1])), $r);
                if (self::unbound($a[1]) && self::accepted($c->get('out'))) {
                    Assert::assertFalse($have['ok'], 'allowUnboundPq is not ported: the native threshold refuses what only that opt-out accepts');
                    return [Base::SKIP, 'allowUnboundPq ruling'];
                }
                return $have;
            },
            'conformalThreshold' => static fn(array $a) => self::form(SemanticThreshold::conformalThreshold(self::conv($a[0])), $r),
            'empiricalFalseAllowRate' => static fn(array $a) => self::form(SemanticThreshold::empiricalFalseAllowRate(self::conv($a[0]), self::conv($a[1])), $r),
            'semanticVerifier' => static function (array $a) use ($r) {
                $o = $a[0];
                $cfg = Obj::of(['judgeKeys' => $o->get('judgeKeys'), 'k' => $o->get('k'),
                    'verdicts' => static fn($c) => $c->has('verdicts') ? $c->get('verdicts') : Jsx::$U,
                    'goalCommitment' => static fn($c) => $c->has('goal') ? $c->get('goal') : Jsx::$U,
                    'attestation' => static fn($c) => self::att($c->has('attestation') ? $c->get('attestation') : null)]);
                foreach (['calibration', 'optionalWhenAbsent'] as $m) {
                    if ($o->has($m)) {
                        $cfg->set($m, $o->get($m));
                    }
                }
                $mode = $o->has('actionDigestMode') ? $o->get('actionDigestMode') : null;
                if (is_string($mode) && str_starts_with($mode, 'fixed:')) {
                    $cfg->set('actionDigest', static fn() => substr($mode, 6));
                }
                $hook = SemanticThreshold::createVerifier($cfg);
                return array_map(static fn($c) => self::form($hook($c), $r), $a[1]);
            },
            'semanticRiskContribution' => static fn(array $a) => SemanticThreshold::riskContribution(self::conv($a[0])),
            'constants' => static fn(array $a) => ['SEMANTIC_JUDGE_DOMAIN' => SemanticThreshold::DOMAIN, 'SCORE_SCALE' => SemanticThreshold::SCORE_SCALE],
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        foreach ([self::FILE => self::FNS, self::ROUTING => self::ROUTING_FNS] as $file => $fns) {
            $have = array_fill_keys(array_keys($fns), 0);
            $unbound = 0;
            foreach (gzfile(Base::path($file)) as $line) {
                foreach ($have as $fn => $_) {
                    if (str_starts_with($line, '{"fn":"' . $fn . '"')) {
                        $have[$fn]++;
                        $unbound += $fn === 'verifyJudgeVerdict' || $fn === 'verifySemanticThreshold' ? (int)(str_contains($line, '"allowUnboundPq":true') && (str_contains($line, '"out":true') || str_contains($line, '"out":{"ok":true'))) : 0;
                    }
                }
            }
            $this->assertSame($fns, array_intersect_key($have, $fns), $file);
            $this->assertSame($file === self::FILE ? 2 : 0, $unbound, "the cases of $file refused for allowUnboundPq");
        }
    }
}
