<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicyDebug.php';

use Atlas\Pca\Audience;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyDebug;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The policy debugger against the TS reference: every case of test-data/ref-policy-debug.json.gz (explainRisk, explainDecision, applyDelta,
 * counterfactual, auditPCActn). {"$num": ...} is a non-finite double, in arguments and in results.
 */
final class RefPolicyDebugDifferentialTest extends TestCase
{
    private const FILE = 'ref-policy-debug.json.gz';
    private const FNS = ['explainRisk' => 315, 'explainDecision' => 140, 'applyDelta' => 63, 'counterfactual' => 26, 'auditPCActn' => 9];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$num"} to the double; everything else as parsed. */
    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    /** A non-finite double back to {"$num"}. */
    private static function out(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::out($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return is_float($v) && !is_finite($v) ? Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]) : $v;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'explainRisk' => static fn(array $a) => self::out(PolicyDebug::explainRisk(self::un($a[0]), self::un($a[1]), self::un($a[2]) ?? 0)),
            'explainDecision' => static fn(array $a) => self::out(PolicyDebug::explainDecision(self::un($a[0]))),
            'applyDelta' => static fn(array $a) => self::out(PolicyDebug::applyDelta(self::un($a[0]), self::un($a[1]))),
            'counterfactual' => static fn(array $a) => self::out(PolicyDebug::counterfactual(self::un($a[0]), self::un($a[1]))),
            'auditPCActn' => static function (array $a) {
                $o = $a[2];
                // opts.audience: absent = not given, null = the explicit opt-out, a string = the audience
                $aud = !$o->has('audience') ? null : ($o->get('audience') === null ? Audience::Any : $o->get('audience'));
                $r = PolicyDebug::auditPCActn($a[0], $a[1], $o->get('grant'), $o->get('nowEpoch')->int(), $aud, $o->get('insecureSkipPlanRootCheck') === true);
                return self::out(Obj::of(['verify' => $r['verify'], 'explanation' => $r['explanation']]));
            },
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
