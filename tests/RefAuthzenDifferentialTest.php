<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authzen;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The AuthZEN PDP, handler and search APIs against the TS reference: test-data/ref-authzen.json.gz. The PDP config and the
 * search-provider tables below are the ones the generator names. The verify-stage cases (pc17 / pc18) compare decision + stage:
 * the verifier's own check map / reason text is language-specific.
 */
final class RefAuthzenDifferentialTest extends TestCase
{
    private const FILE = 'ref-authzen.json.gz';
    private const NOW = 1000000;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function cfg(string $c): array
    {
        $now = static fn(): int => self::NOW;
        $boom = static function (): never {
            throw new \RuntimeException('boom');
        };
        $none = static fn(): mixed => null;
        $ctx = static fn(): array => ['grant' => new Obj(), 'policy' => new Obj()];
        return match ($c) {
            'none' => ['resolve' => $none, 'now' => $now],
            'throws' => ['resolve' => $boom, 'now' => $now],
            'noauth' => ['resolve' => $ctx, 'now' => $now],
            'auth' => ['resolve' => $ctx, 'authorizer' => static fn(): array => ['allow' => true], 'now' => $now],
            'max2' => ['resolve' => $none, 'maxEvaluations' => 2, 'now' => $now],
            'toolmap' => ['resolve' => $none, 'toolCapability' => static fn(string $n): string => 'cap.' . $n, 'now' => $now],
            'toolthrow' => ['resolve' => $none, 'toolCapability' => static function (): never {
                throw new \RuntimeException('bad tool');
            }, 'now' => $now],
        };
    }

    private static function u(string $id, array $extra = []): array
    {
        return ['type' => 'user', 'id' => $id] + $extra;
    }

    private static function prov(string $p): array
    {
        $boom = static function (): never {
            throw new \RuntimeException('boom');
        };
        $echo = static fn(mixed $r): array => ['results' => [], 'context' => ['saw' => $r]];
        return match ($p) {
            'none' => [],
            'full' => [
                'searchSubject' => static fn(): array => ['results' => [self::u('a'), self::u('b'), ['type' => 'group', 'id' => 'g'], self::u('a'), ['id' => 'a', 'type' => 'user']],
                    'page' => ['next_token' => '', 'total' => 3, 'properties' => ['k' => 1]], 'context' => ['c' => 1]],
                'searchResource' => static fn(): array => ['results' => [['type' => 'doc', 'id' => '1'], ['type' => 'doc', 'id' => '2'], ['type' => 'user', 'id' => 'x']], 'page' => ['next_token' => 'n1']],
                'searchAction' => static fn(): array => ['results' => [['name' => 'read'], ['name' => 'write'], ['name' => 'read'], ['name' => 'read', 'properties' => ['p' => 1]]]],
            ],
            'nopage' => ['searchSubject' => static fn(): array => ['results' => [self::u('a'), self::u('b')]],
                'searchResource' => static fn(): array => ['results' => []], 'searchAction' => static fn(): array => ['results' => []]],
            'emptyprops' => ['searchSubject' => static fn(): array => ['results' => [self::u('a')], 'page' => ['next_token' => 'z', 'properties' => new Obj()], 'context' => new Obj()]],
            'bad' => ['searchSubject' => static fn(): array => ['results' => [null]], 'searchResource' => static fn(): array => ['results' => [5]],
                'searchAction' => static fn(): array => ['results' => [null, 5]]],
            'notarray' => ['searchSubject' => static fn(): array => ['results' => 'x'], 'searchResource' => static fn(): Obj => new Obj(),
                'searchAction' => static fn(): array => ['results' => null]],
            'throws' => ['searchSubject' => $boom, 'searchResource' => $boom, 'searchAction' => $boom],
            'echo' => ['searchSubject' => $echo, 'searchResource' => $echo, 'searchAction' => $echo],
            'partial' => ['searchResource' => static fn(): array => ['results' => []]],
        };
    }

    /** pc17 / pc18: keep decision + reason_admin.stage only, on both sides (the case's expectation is narrowed in place). */
    private static function verifyStage(Obj $c, array $got): array
    {
        $name = (string)$c->get('name');
        if (!str_ends_with($name, '/pc17') && !str_ends_with($name, '/pc18')) {
            return $got;
        }
        $out = $c->get('out');
        $stage = $out->get('context')->get('reason_admin')->get('stage');
        $c->set('out', Obj::of(['decision' => $out->get('decision'), 'stage' => $stage]));
        return ['decision' => $got['decision'], 'stage' => $got['context']['reason_admin']['stage'] ?? null];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'isAccessEvaluationRequest' => fn(array $a) => Authzen::isAccessEvaluationRequest($a[0] ?? null),
            'isAccessEvaluationsRequest' => fn(array $a) => Authzen::isAccessEvaluationsRequest($a[0] ?? null),
            'isCoazToolAuthorizationRequest' => fn(array $a) => Authzen::isCoazToolAuthorizationRequest($a[0] ?? null),
            'isAuthzenSubject' => fn(array $a) => Authzen::isAuthzenSubject($a[0] ?? null),
            'isAuthzenAction' => fn(array $a) => Authzen::isAuthzenAction($a[0] ?? null),
            'isAuthzenResource' => fn(array $a) => Authzen::isAuthzenResource($a[0] ?? null),
            'isSubjectSearch' => fn(array $a) => Authzen::isSubjectSearch($a[0] ?? null),
            'isResourceSearch' => fn(array $a) => Authzen::isResourceSearch($a[0] ?? null),
            'isActionSearch' => fn(array $a) => Authzen::isActionSearch($a[0] ?? null),
            'defaultToAction' => fn(array $a) => Authzen::defaultToAction($a[0]),
            'approvalOf' => fn(array $a) => Authzen::approvalOf($a[0] ?? null),
            'isApprovalRequired' => fn(array $a) => Authzen::isApprovalRequired($a[0] ?? null),
            'pdp.evaluate' => fn(array $a, Obj $c) => self::verifyStage($c, Authzen::evaluate(self::cfg($a[0]), $a[1])),
            'pdp.evaluations' => fn(array $a) => Authzen::evaluations(self::cfg($a[0]), $a[1]),
            'pdp.evaluateTool' => fn(array $a) => Authzen::evaluateTool(self::cfg($a[0]), $a[1]),
            'authzenHandler' => fn(array $a) => (Authzen::handler(self::cfg($a[0])))($a[1]),
            'authzenSearchHandler' => fn(array $a) => (Authzen::searchHandler(self::prov($a[0])))($a[1]),
            'searchMetadata' => fn(array $a) => Authzen::searchMetadata($a[0], self::prov($a[1])),
        ]);
    }
}
