<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AgentNative.php';

use Atlas\Pca\AgentNative;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The agent-native surface against the TS reference: test-data/ref-agent-native.json.gz (1632 cases): caution attestation, rationale
 * binding, the tool-schema firewall, envelope introspection and the authority lease. Every fn of the corpus must have a handler (an
 * unhandled fn fails Base::run). Encodings: {"$num": "NaN" | "Infinity" | "-Infinity"} in args; {"$bytes": {"$seed": label}} is the
 * 32-byte Ed25519 secret sha256("atlas-pca-conformance/" + label); an out of {"$throws": ...} must be a native throw (the message is
 * not compared); every other reason string is compared exactly.
 */
final class RefAgentNativeDifferentialTest extends TestCase
{
    private const FILE = 'ref-agent-native.json.gz';
    private const TOTAL = 1632;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, self::map());
    }

    public function testEveryCaseOfTheCorpusIsInSomeDatasetAndEveryHandlerIsExercised(): void
    {
        $fns = [];
        foreach (self::provide() as [, $fn]) {
            $fns[$fn] = true;
        }
        $this->assertSame([], array_values(array_diff(array_keys($fns), array_keys(self::map()))), 'a corpus fn without a handler');
        $this->assertSame([], array_values(array_diff(array_keys(self::map()), array_keys($fns))), 'a handler without cases');
        $n = 0;
        foreach (self::provide() as [$file, $fn, $k]) {
            $n += count(Base::cases($file, $fn, $k));
        }
        $this->assertSame(self::TOTAL, $n);
    }

    /** {"$num": ...} -> the non-finite float (anywhere in the arguments) */
    private static function dnum(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN,
                    'Infinity' => INF,
                    '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $key) {
                $o->set($key, self::dnum($v->get($key)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::dnum(...), $v) : $v;
    }

    private static function key(mixed $v): KeyPair
    {
        $seed = $v->get('$bytes')->get('$seed');
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $seed, true));
    }

    private static function judge(string $spec): callable
    {
        if ($spec === 'true') {
            return static fn(string $r, mixed $a): bool => true;
        }
        if ($spec === 'false') {
            return static fn(string $r, mixed $a): bool => false;
        }
        if ($spec === 'throw') {
            return static function (string $r, mixed $a): bool {
                throw new \RuntimeException('judge');
            };
        }
        if ($spec === 'truthy') {
            return static fn(string $r, mixed $a): string => 'yes';
        }
        if (str_starts_with($spec, 'contains:')) {
            $s = substr($spec, 9);
            return static fn(string $r, mixed $a): bool => str_contains($r, $s);
        }
        if (str_starts_with($spec, 'action-verb:')) {
            $want = substr($spec, 12);
            return static function (string $r, mixed $a) use ($want): bool {
                if ($a === null) {
                    throw new \TypeError('action is null');
                }
                return $a instanceof Obj && $a->get('verb') === $want;
            };
        }
        throw new \LogicException("unknown judge spec $spec");
    }

    private static function constants(): Obj
    {
        $o = new Obj();
        foreach ((new \ReflectionClass(AgentNative::class))->getReflectionConstants() as $c) {
            if ($c->isPublic()) {
                $o->set($c->getName(), $c->getValue());
            }
        }
        return $o;
    }

    /** @return array<string,callable> fn => (list $args, Obj $case) => the native result in the oracle's out form */
    private static function map(): array
    {
        return [
            'signCaution' => static fn(array $a): mixed => AgentNative::signCaution(self::dnum($a[0]), self::key($a[1])),
            'verifyCaution' => static fn(array $a): mixed => AgentNative::verifyCaution(self::dnum($a[0]), $a[1] ?? null, $a[2] ?? null),
            'combineCaution' => static fn(array $a): mixed => AgentNative::combineCaution(self::dnum($a[0]), self::dnum($a[1])),
            'combineSignedCaution' => static fn(array $a): mixed => AgentNative::combineSignedCaution(self::dnum($a[0]), $a[1], self::dnum($a[2]), $a[3] ?? null),
            'checkCautionMonotone' => static fn(array $a): mixed => AgentNative::checkCautionMonotone(self::dnum($a[0])),
            'isStrongSalt' => static fn(array $a): mixed => AgentNative::isStrongSalt($a[0]),
            'bindRationale' => static fn(array $a): mixed => AgentNative::bindRationale(...self::dnum($a)),
            'verifyRationale' => static fn(array $a): mixed => AgentNative::verifyRationale(...self::dnum($a)), // 2 args = no action; a given null is hashed as null
            'auditRationale' => static fn(array $a): mixed => AgentNative::auditRationale(self::dnum($a[0]), self::dnum($a[1]), self::dnum($a[2]), self::judge($a[3])),
            'validateArgSchema' => static fn(array $a): mixed => AgentNative::validateArgSchema(self::dnum($a[0])),
            'toolSchemaCaveat' => static fn(array $a): mixed => AgentNative::toolSchemaCaveat(self::dnum($a[0]), self::dnum($a[1])),
            'evaluateToolSchema' => static fn(array $a): mixed => AgentNative::evaluateToolSchema(self::dnum($a[0]), self::dnum($a[1])),
            'toolSchemaEvaluator' => static fn(array $a): mixed => AgentNative::toolSchemaEvaluator(self::dnum($a[0]), self::dnum($a[1])),
            'predicatesCaveat' => static fn(array $a): mixed => AgentNative::predicatesCaveat(self::dnum($a[0])),
            'actionSpendUsd' => static fn(array $a): mixed => AgentNative::actionSpendUsd(self::dnum($a[0])),
            'agentNativeCaveatEvaluator' => static fn(array $a): mixed => AgentNative::agentNativeCaveatEvaluator(self::dnum($a[0]), self::dnum($a[1])),
            'describeEnvelope' => static fn(array $a): mixed => AgentNative::describeEnvelope($a[0], self::dnum($a[1] ?? null), $a[2] ?? null, $a[3] ?? null),
            'envelopePermits' => static fn(array $a): mixed => AgentNative::envelopePermits(self::dnum($a[0]), $a[1], $a[2], self::dnum($a[3] ?? null), self::dnum($a[4] ?? null)),
            'envelopePermitsToolCall' => static fn(array $a): mixed => AgentNative::envelopePermitsToolCall($a[0], self::dnum($a[1])),
            'grantLease' => static fn(array $a): mixed => AgentNative::grantLease(self::dnum($a[0])),
            'leaseState' => static fn(array $a): mixed => AgentNative::leaseState(self::dnum($a[0]), self::dnum($a[1])),
            'signHeartbeat' => static fn(array $a): mixed => AgentNative::signHeartbeat(self::dnum($a[0]), self::key($a[1])),
            'renewLease' => static fn(array $a): mixed => AgentNative::renewCapabilityLease(self::dnum($a[0]), self::dnum($a[1]), self::dnum($a[2])),
            'constants' => static fn(array $a): mixed => self::constants(),
        ];
    }
}
