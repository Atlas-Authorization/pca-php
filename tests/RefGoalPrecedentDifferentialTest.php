<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalPrecedent.php';
require_once __DIR__ . '/../src/GoalPrecedentLog.php';
require_once __DIR__ . '/../src/GoalExamples.php';
require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\GoalExamples;
use Atlas\Pca\GoalPrecedent;
use Atlas\Pca\GoalPrecedentLog;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The hash-chained precedent log over principal-signed escalation answers against the TS reference:
 * test-data/ref-goal-precedent.json.gz. The log is stateful, so it is driven through a step script exactly as the reference's
 * generator drives it.
 */
final class RefGoalPrecedentDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-precedent.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function flow(array $a): array
    {
        [$goal, $ont, $grant, $principals, $steps] = $a;
        $log = new GoalPrecedentLog($principals);
        $space = GoalExamples::buildSpace([$goal]);
        $out = [];
        foreach ($steps as $s) {
            switch ($s->get('op')) {
                case 'append':
                    $r = $log->append($s->get('answer'), $s->get('answered'), $grant, $space, $s->get('now'));
                    $e = $r->get('entry');
                    $out[] = $r->get('ok') === true ? Obj::of(['ok' => true, 'digest' => $e->get('digest'), 'cell' => $e->get('cell'), 'seq' => $e->get('seq')]) : $r;
                    break;
                case 'revoke':
                    $r = $log->revoke($s->get('rev'));
                    $e = $r->get('entry');
                    $out[] = $r->get('ok') === true ? Obj::of(['ok' => true, 'digest' => $e->get('digest'), 'seq' => $e->get('seq')]) : $r;
                    break;
                case 'verifyChain':
                    $out[] = $log->verifyChain($space);
                    break;
                case 'lookup':
                    $h = $log->lookup($s->get('policyDigest'), $space, $s->get('case'), $s->get('now'));
                    $out[] = $h === null ? null : Obj::of(['decision' => $h->get('decision'), 'digest' => $h->get('entry')->get('digest')]);
                    break;
                case 'authorize':
                    $r = GoalPrecedent::authorizeWithPrecedents($goal, $ont, $s->get('policyDigest'), $log, $s->get('case'), $s->get('now'));
                    $o = Obj::of(['decision' => $r->get('decision'), 'via' => $r->get('via')]);
                    if ($r->has('precedent')) {
                        $o->set('digest', $r->get('precedent')->get('digest'));
                    }
                    $out[] = $o;
                    break;
                case 'tamper':
                    $i = (int)\Atlas\Pca\Js::num($s->get('index'));
                    $log->entries[$i] = $s->get('del') === true ? $log->entries[$i]->without((string)$s->get('key')) : self::with($log->entries[$i], (string)$s->get('key'), $s->get('value'));
                    $out[] = true;
                    break;
                default:
                    $out[] = $log->head();
            }
        }
        return $out;
    }

    private static function with(Obj $e, string $k, mixed $v): Obj
    {
        $c = new Obj();
        foreach ($e->keys() as $x) {
            $c->set($x, $e->get($x));
        }
        $c->set($k, $v);
        return $c;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'flow' => fn(array $a) => self::flow($a),
            'ceilingsOf' => fn(array $a) => GoalPrecedent::ceilingsOf($a[0]),
            'answerBodyFor' => fn(array $a) => GoalPrecedent::answerBodyFor($a[0], $a[1]),
            'signRevocationSeed' => fn(array $a) => GoalPrecedent::signRevocation($a[0], KeyPair::fromSeedB64u((string)Base::unseed($a[1]))),
        ]);
    }
}
