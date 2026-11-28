<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Console.php';
require_once __DIR__ . '/../src/Session.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Authorize;
use Atlas\Pca\Console;
use Atlas\Pca\Facade;
use Atlas\Pca\Immune;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Session;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The agent console, the kill-switch set and sessions against the TS reference: the console, freeze and session cases of
 * test-data/ref-core-research-java.json.gz, plus the immune read side that file also carries (observe, assess, updateBaseline,
 * validateImmuneState, baselineStd; the corpus is shared by several modules, each replays its own functions and asserts their counts).
 * Session cases are op scripts; their keys are the seeds "research/<label>".
 */
final class RefConsoleSessionDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-research-java.json.gz';
    private const FNS = ['buildConsole' => 13, 'anomalies' => 7, 'eventFromPCActn' => 12, 'freezeAgent' => 72, 'unfreezeAgent' => 72,
        'isFrozen' => 72, 'session' => 5, 'observe' => 126, 'assess' => 57, 'updateBaseline' => 35, 'validateImmuneState' => 28, 'baselineStd' => 5];

    public static function provide(): array
    {
        $out = [];
        foreach (Base::datasets(self::FILE) as $k => $v) {
            if (isset(self::FNS[$v[1]])) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    private static function key(mixed $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/research/' . $label, true));
    }

    private static function session(array $ops): array
    {
        $agents = [];
        $sess = [];
        $out = [];
        $get = static fn(array $m, mixed $name): mixed => $m[$name] ?? throw new \LogicException("unknown $name");
        foreach ($ops as $op) {
            try {
                $out[] = match ($op[0]) {
                    'agent' => (function () use ($op, &$agents): string {
                        $sp = $op[2];
                        $a = Facade::createAgent(self::key($sp->get('principal')), $sp->get('goal'), $sp->get('permissions'), null, self::key($sp->get('holder')),
                            null, null, null, null, null, (int)$sp->get('now')->float(), $sp->get('goalSalt'));
                        $agents[$op[1]] = $a;
                        return $a->holder->public;
                    })(),
                    'start' => ($sess[$op[1]] = Session::start($get($agents, $op[2])))->goalCommit,
                    'mk' => (function () use ($op, $get, $agents, &$sess): string {
                        $ms = array_map(static fn($n) => $get($agents, $n), $op[2]);
                        $g = $op[3] ?? (isset($ms[0]) ? Authorize::readEnvelope($ms[0]->grant)?->get('goal_commit') ?? '' : '');
                        $sess[$op[1]] = new Session($ms[0] ?? null, $ms, $g);
                        return $g;
                    })(),
                    'add' => (function () use ($op, $get, &$sess): string {
                        $cav = $op[4];
                        $r = $get($sess, $op[2])->addMember($op[3] === null ? null : self::key($op[3]),
                            $cav === null ? [] : (is_string($cav) ? (preg_split('//u', $cav, -1, PREG_SPLIT_NO_EMPTY) ?: []) : $cav)); // a string spreads into its characters
                        $sess[$op[1]] = $r['session'];
                        return $r['member']->holder->public;
                    })(),
                    'agents' => $get($sess, $op[1])->agents(),
                    'depth' => $get($sess, $op[1])->depth(),
                    'shares' => $get($sess, $op[1])->sharesGoal(),
                    'goal' => $get($sess, $op[1])->goalCommit,
                    'console' => $get($sess, $op[1])->console($op[2]),
                    default => throw new \LogicException('op'),
                };
            } catch (\Throwable) {
                $out[] = Obj::of(['$err' => 'Error']);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'buildConsole' => static fn(array $a) => Console::buildConsole($a[0]),
            'anomalies' => static fn(array $a) => Console::anomalies(Console::buildConsole($a[0])),
            'eventFromPCActn' => static fn(array $a) => Console::eventFromPCActn($a[0], $a[1], $a[2]),
            'freezeAgent' => static fn(array $a) => Console::freezeAgent($a[0], $a[1]),
            'unfreezeAgent' => static fn(array $a) => Console::unfreezeAgent($a[0], $a[1]),
            'isFrozen' => static fn(array $a) => Console::isFrozen($a[0], $a[1]),
            'session' => static fn(array $a) => self::session($a[0]),
            'observe' => static fn(array $a) => Immune::observe($a[0], $a[1]),
            'assess' => static fn(array $a) => Immune::assess($a[0]),
            'updateBaseline' => static fn(array $a) => Immune::updateBaseline($a[0], $a[1]),
            'validateImmuneState' => static fn(array $a) => Immune::validateImmuneState($a[0]),
            'baselineStd' => static fn(array $a) => Immune::baselineStd($a[0]),
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

    public function testEmptyFreezeAndTheSessionDepthLimit(): void
    {
        $this->assertSame([], Console::emptyFreeze()->get('frozen'));
        $this->assertSame(32, Session::MAX_DEPTH);
    }
}
