<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalExamples.php';

use Atlas\Pca\GoalExamples as E;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The boundary examples against the TS reference: test-data/ref-goal-examples.json.gz (decision cells, boundary examples, goal
 * tests and the policy pin). A signing key travels as a {"$seed": label} member; the key is derived here from that label.
 */
final class RefGoalExamplesDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-examples.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function kp(mixed $seed): KeyPair
    {
        if ($seed instanceof Obj && $seed->has('$seed')) {
            return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $seed->get('$seed'), true));
        }
        return new KeyPair((string)Pca::unb64u($seed, 32));
    }

    private static function nonEmpty(mixed $x): bool
    {
        return is_array($x) && $x !== [];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'buildSpace' => fn(array $a) => E::buildSpace($a[0], $a[1] ?? null),
            'cellKey' => fn(array $a) => E::cellKey(E::buildSpace($a[0], $a[1] ?? null), $a[2]),
            'cells' => fn(array $a) => E::cells(E::buildSpace($a[0], $a[1] ?? null), ($a[2] ?? null) === null ? null : Obj::of(['verbs' => $a[2]])),
            'decideCase' => fn(array $a) => E::decideCase($a[0], $a[1], $a[2]),
            'replay' => fn(array $a) => E::replay($a[0], $a[1], $a[2], $a[3]),
            'allowWitness' => fn(array $a) => E::allowWitness($a[0], $a[0]->get('grants')[(int)Js::num($a[1])], $a[2]),
            'boundaryExamples' => function (array $a): Obj {
                $opts = Obj::of(['ont' => $a[1]]);
                if (self::nonEmpty($a[2] ?? null)) {
                    $opts->set('extra', $a[2]);
                }
                if (self::nonEmpty($a[3] ?? null)) {
                    $opts->set('verbs', $a[3]);
                }
                return E::boundaryExamples($a[0], $opts);
            },
            'reviewSet' => fn(array $a) => E::reviewSet($a[0], $a[1]),
            'testsDigest' => fn(array $a) => E::testsDigest($a[0]),
            'makeGoalTests' => fn(array $a) => E::makeGoalTests($a[0], $a[1]),
            'signGoalTestsSeed' => fn(array $a) => E::signGoalTests($a[0], self::kp($a[1])),
            'checkGoalTests' => function (array $a): Obj {
                [$signed, $pins, $mode, $g, $ont] = $a;
                $decide = $mode === 'ref'
                    ? static fn($t) => E::decideCase($g, $ont, $t)->get('decision')
                    : static fn($t) => (is_string($mode) ? ['allow' => 'allow', 'deny' => 'deny'][$mode] ?? null : null) ?? 'escalate';
                return E::checkGoalTests($signed, $pins, $decide);
            },
            'signPinSeed' => fn(array $a) => E::signPin($a[0], self::kp($a[1])),
            'checkPin' => fn(array $a) => E::checkPin($a[0], $a[1], $a[2]),
        ]);
    }

    public function testEveryFunctionIsMapped(): void
    {
        $fns = [];
        foreach (self::provide() as $d) {
            $fns[$d[1]] = true;
        }
        $have = array_keys($fns);
        sort($have);
        $want = ['allowWitness', 'boundaryExamples', 'buildSpace', 'cellKey', 'cells', 'checkGoalTests', 'checkPin', 'decideCase', 'makeGoalTests', 'replay',
            'reviewSet', 'signGoalTestsSeed', 'signPinSeed', 'testsDigest'];
        $this->assertSame($want, $have);
    }
}
