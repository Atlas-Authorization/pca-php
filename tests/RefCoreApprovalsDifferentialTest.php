<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Approvals;
use Atlas\Pca\Facade;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The agent-facing half of approvals (review, goal lineage, batch review, time-boxing) against the TS reference: test-data/ref-core-approvals-java.json.gz.
 * Keys are sha256("atlas-pca-conformance/approvals/" + label) seeds.
 */
final class RefCoreApprovalsDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-approvals-java.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/approvals/' . $label, true));
    }

    /** A parsed JSON value as the PHP arrays the facade takes: objects become associative arrays, numbers ints or floats. */
    private static function php(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::php($v->get($k));
            }
            return $o;
        }
        if ($v instanceof Num) {
            return $v->isInt() ? $v->int() : $v->float();
        }
        return is_array($v) ? array_map(self::php(...), $v) : $v;
    }

    /** A corpus number as the int it is when whole (exact at any size), else the float. */
    private static function numOf(Num $n): int|float
    {
        $f = $n->float();
        return $f == floor($f) && abs($f) <= 9007199254740991.0 && !str_starts_with($n->lexeme, '-0') ? (int)$f : $f;
    }

    private static function intOf(mixed $v): ?int
    {
        return $v instanceof Num ? (int)$v->float() : null;
    }

    private static function build(Obj $spec): AgentHandle
    {
        $obj = static fn(string $k) => $spec->get($k) instanceof Obj ? self::php($spec->get($k)) : null;
        return Facade::createAgent(self::key($spec->get('principal')), $spec->get('goal'), self::php($spec->get('permissions')), $obj('limits'), self::key($spec->get('holder')), null,
            $obj('riskPolicy'), $spec->get('budgetModel'), null, $spec->get('aud'), self::intOf($spec->get('now')), $spec->get('goalSalt'));
    }

    private static function render(string $mode, string $verb, string $resource): Obj
    {
        if ($mode === 'throw') {
            throw new \RuntimeException('boom');
        }
        if ($mode === 'badshape') {
            return Obj::of(['v' => new Num('2')]);
        }
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-approval-render', 'verb' => $verb, 'def_digest' => str_repeat('A', 43), 'unreviewed' => true,
            'fields' => [Obj::of(['id' => 'resource', 'class' => 'param', 'value' => $resource])]]);
    }

    /** @return array<string,mixed> the named arguments of reviewAction / batchReview */
    private static function opts(Obj $o): array
    {
        $out = [];
        if ($o->get('now') instanceof Num) {
            $out['now'] = self::intOf($o->get('now'));
        }
        if (is_string($o->get('goal'))) {
            $out['goal'] = $o->get('goal');
        }
        if (is_array($o->get('standing'))) {
            $out['standing'] = self::php($o->get('standing'));
        }
        if (is_string($o->get('renderer'))) {
            $mode = $o->get('renderer');
            $out['renderer'] = static fn(string $verb, string $resource, mixed $params = null): Obj => self::render($mode, $verb, $resource);
        }
        $out['insecureUnboundApproval'] = $o->get('insecure') === true;
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'reviewAction' => fn(array $a) => Approvals::reviewAction(self::build($a[0]), $a[1], $a[2], $a[3], ...self::opts($a[4])),
            'batchReview' => fn(array $a) => Approvals::batchReview(self::build($a[0]), self::php($a[1]), self::opts($a[2])),
            'buildGoalLineage' => fn(array $a) => Approvals::buildGoalLineage(self::build($a[0]), $a[1], $a[2], $a[3], $a[4]->get('goal')),
            'describeGoalLineage' => fn(array $a) => Approvals::describeGoalLineage(self::php($a[0])),
            'timeBox' => fn(array $a) => Approvals::timeBox($a[0], self::key($a[1]), self::numOf($a[2]), $a[3] instanceof Num ? self::numOf($a[3]) : null),
        ]);
    }
}
