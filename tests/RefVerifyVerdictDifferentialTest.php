<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/VerifyVerdict.php';

use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\VerifyVerdict;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The full verdict of the resource-server verifier against the TS reference: every case of test-data/ref-verify-verdict.json.gz (allow, r, requiredThreshold,
 * every check with its status, the reasons in order, budget, assurance). Hooks are constant data in the corpus: {enforced:false} | {enforced:true, ok, reason?, t?} |
 * {throws} | {raw}; a `replay` hook is not a hook of the verifier and is ignored. Counted deviations (asserted, never skipped silently):
 *  - a verifier error of the reference carries a JavaScript engine message; the native fails closed in the same shape (`malformed: fail`, r 1, worst threshold)
 *    with its own message;
 *  - a wire text that does not parse is described by the native strict parser in its own words (the prefix `undecodable PCActn:` is compared);
 *  - allowUnboundPq is never ported: a case the reference admits only through it must be refused here.
 */
final class RefVerifyVerdictDifferentialTest extends TestCase
{
    private const FILE = 'ref-verify-verdict.json.gz';

    /** @var array<string,int> */
    private static array $dev = [];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function hook(mixed $h): \Closure
    {
        return static function () use ($h): mixed {
            if ($h instanceof Obj && $h->has('throws')) {
                throw new \RuntimeException((string) $h->get('throws'));
            }
            if ($h instanceof Obj && $h->has('raw')) {
                return $h->get('raw');
            }
            $a = [];
            foreach ($h->keys() as $k) {
                $a[$k] = $h->get($k);
            }
            return $a;
        };
    }

    private static function opts(Obj $j): Obj
    {
        $o = new Obj();
        foreach ($j->keys() as $k) {
            if ($k !== 'hooks' && $k !== 'enforce') {
                $o->set($k, $j->get($k));
            }
        }
        if ($j->get('hooks') instanceof Obj) {
            $hooks = [];
            foreach ($j->get('hooks')->keys() as $n) {
                if ($n !== 'replay') {
                    $hooks[$n] = self::hook($j->get('hooks')->get($n));
                }
            }
            $o->set('hooks', $hooks);
        }
        if ($j->get('enforce') instanceof Obj) {
            $e = $j->get('enforce');
            $enf = [];
            if ($e->get('freshness') !== null) {
                $enf['freshness'] = $e->get('freshness');
            }
            if ($e->get('attestation') instanceof Obj) {
                $enf['attestation'] = ['verifier' => self::hook($e->get('attestation')->get('verifier'))]
                    + ($e->get('attestation')->has('required') ? ['required' => $e->get('attestation')->get('required')] : []);
            }
            $o->set('enforce', $enf);
        }
        return $o;
    }

    private static function f(mixed $x): float
    {
        return $x instanceof Num ? $x->float() : (float) $x;
    }

    private static function close(float $a, float $b): bool
    {
        return $a === $b || abs($a - $b) <= 1e-12 * max(abs($a), abs($b));
    }

    /** The differences between the native verdict and the reference's, as a list of texts. */
    private static function diff(array $have, Obj $want): array
    {
        $bad = [];
        if ($have['allow'] !== $want->get('allow')) {
            $bad[] = 'allow ' . var_export($have['allow'], true) . ' want ' . var_export($want->get('allow'), true);
        }
        if (!self::close(self::f($have['r']), self::f($want->get('r')))) {
            $bad[] = 'r ' . $have['r'] . ' want ' . Base::canon($want->get('r'));
        }
        $rt = $want->get('requiredThreshold');
        if (Base::canon($have['requiredThreshold']) !== Base::canon($rt)) {
            $bad[] = 'requiredThreshold ' . Base::canon($have['requiredThreshold']) . ' want ' . Base::canon($rt);
        }
        $wc = [];
        foreach ($want->get('checks')->keys() as $k) {
            $wc[$k] = $want->get('checks')->get($k);
        }
        $hc = $have['checks'];
        ksort($wc);
        ksort($hc);
        if ($hc !== $wc) {
            $bad[] = 'checks ' . json_encode($hc) . ' want ' . json_encode($wc);
        }
        if ($have['reasons'] !== $want->get('reasons')) {
            $bad[] = 'reasons ' . json_encode($have['reasons']) . ' want ' . json_encode($want->get('reasons'));
        }
        $wb = $want->get('budget');
        $hb = $have['budget'] ?? null;
        if (($wb === null) !== ($hb === null)) {
            $bad[] = 'budget ' . json_encode($hb) . ' want ' . ($wb === null ? 'none' : Base::canon($wb));
        } elseif ($wb instanceof Obj) {
            foreach ($wb->keys() as $k) {
                if (!isset($hb[$k]) || !self::close(self::f($hb[$k]), self::f($wb->get($k)))) {
                    $bad[] = "budget.$k " . json_encode($hb[$k] ?? null) . ' want ' . Base::canon($wb->get($k));
                }
            }
        }
        $wa = $want->get('assurance');
        $ha = $have['assurance'] ?? null;
        if (($wa === null) !== ($ha === null) || ($wa !== null && Base::canon($ha) !== Base::canon($wa))) {
            $bad[] = 'assurance ' . ($ha === null ? 'none' : Base::canon($ha)) . ' want ' . ($wa === null ? 'none' : Base::canon($wa));
        }
        return $bad;
    }

    private static function countWhy(string $why): void
    {
        self::$dev[$why] = (self::$dev[$why] ?? 0) + 1;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $bad = [];
        $ran = 0;
        $skipped = 0;
        foreach (Base::cases($file, $fn, $k) as $c) {
            if (OracleData::pqMissing() && OracleData::mentionsPq($c)) {
                $skipped++;
                continue;
            }
            $ran++;
            $name = (string) $c->get('name');
            [$pcactn, $j] = $c->get('args');
            $want = $c->get('out');
            $have = VerifyVerdict::verify($pcactn, self::opts($j));
            $d = self::diff($have, $want);
            if ($d === []) {
                continue;
            }
            $wr = $want->get('reasons');
            if (is_string($wr[0] ?? null) && str_starts_with($wr[0], 'verifier error (fail closed)')) {
                // the reference's own JavaScript message cannot be reproduced; the shape is
                $ok = $have['allow'] === false && $have['checks'] === ['malformed' => 'fail'] && count($have['reasons']) === 1
                    && str_starts_with($have['reasons'][0], 'verifier error (fail closed)') && $have['r'] === 1;
                if ($ok) {
                    self::countWhy('verifier error: engine message');
                    continue;
                }
            } elseif (is_string($wr[0] ?? null) && str_starts_with($wr[0], 'undecodable PCActn: strict JSON')) {
                if ($have['allow'] === false && str_starts_with($have['reasons'][0] ?? '', 'undecodable PCActn:') && $have['checks'] === ['malformed' => 'fail']) {
                    self::countWhy('undecodable: parser wording');
                    continue;
                }
            } elseif (Js::opt($j, 'allowUnboundPq') === true) {
                if ($have['allow'] === false) {
                    self::countWhy('allowUnboundPq refused (never ported)');
                    continue;
                }
            }
            $bad[] = $name . "\n   " . implode("\n   ", $d);
        }
        Assert::assertSame([], array_slice($bad, 0, 25), count($bad) . " mismatches; $file $fn #$k ran $ran skipped $skipped deviations " . json_encode(self::$dev));
    }
}
