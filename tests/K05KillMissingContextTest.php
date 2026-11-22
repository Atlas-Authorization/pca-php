<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/MissingContext.php';

use Atlas\Pca\Json;
use Atlas\Pca\MissingContext;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Missing context / stored-wins merge edges (mutation kills; the vectors cover the documented cases). */
final class K05KillMissingContextTest extends TestCase
{
    private static function o(string $json): mixed
    {
        return Json::parseLax($json);
    }

    private static function canon(mixed $v): string
    {
        return Json::canonicalizeStrict($v);
    }

    /** @return array{context: mixed, conflicts: list<string>, dropped: list<string>} */
    private static function bind(string $bound, string $supplied, ?string $table = null): array
    {
        return MissingContext::bindContext(self::o($bound), self::o($supplied), $table === null ? null : self::o($table));
    }

    private const ACT = '"action":{"verb":"v","resource":"r"}';

    public function testSupplierHelpers(): void
    {
        self::assertSame('principal', MissingContext::supplierOf('env.x', new Obj()));
        self::assertSame('5', MissingContext::supplierOf('env.x', Obj::of(['env' => 5])));
        self::assertSame('rs_observation', MissingContext::supplierOf('env.x.y', self::o('{"env":"principal","env.x":"rs_observation","env.xy":"discharge_issuer"}')));
        self::assertSame('the supplier table must be an object', MissingContext::supplierTableError('x'));
        self::assertNull(MissingContext::supplierTableError(new Obj()));
    }

    public function testBindCopiesAndNeverAliases(): void
    {
        $bound = self::o('{' . self::ACT . ',"env":{}}');
        $supplied = self::o('{"env":{"x":[{"a":1}]}}');
        $r = MissingContext::bindContext($bound, $supplied);
        self::assertFalse($bound->get('env')->has('x'));
        self::assertNotSame($bound, $r['context']);
        self::assertNotSame($supplied->get('env')->get('x')[0], $r['context']->get('env')->get('x')[0]);
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":{"x":[{"a":1}]}}', self::canon($r['context']));
        self::assertSame(['context' => 5, 'conflicts' => [], 'dropped' => []], MissingContext::bindContext(5, self::o('{"env":{"x":1}}')));
    }

    public function testLeafDepthLimit(): void
    {
        $chain = static function (string $leaf): string {
            $s = $leaf;
            for ($i = 17; $i >= 1; $i--) {
                $s = "{\"a$i\":$s}";
            }
            return $s;
        };
        $r = self::bind('{' . self::ACT . ',"env":' . $chain('{"z":1}') . '}', '{"env":' . $chain('{"z":2}') . '}');
        $path = 'env.' . implode('.', array_map(static fn(int $i): string => "a$i", range(1, 17)));
        self::assertSame([$path], $r['conflicts']);
        self::assertSame([], $r['dropped']);
    }

    public function testBindMergeEdges(): void
    {
        $r = self::bind('{' . self::ACT . ',"env":{}}', '{"env":{"a":1,"b":2}}', '{"env.a":"agent_declared_untrusted"}');
        self::assertSame(['env.a'], $r['dropped']);
        self::assertSame([], $r['conflicts']);
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":{"b":2}}', self::canon($r['context']));

        $r = self::bind('{' . self::ACT . ',"env":{"a":{"b":1}}}', '{"env":{"a":{"c":2}}}');
        self::assertSame([], $r['conflicts']);
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":{"a":{"b":1,"c":2}}}', self::canon($r['context']));

        $r = self::bind('{' . self::ACT . ',"env":{"a":5}}', '{"env":{"a":{"x":1},"b":2}}');
        self::assertSame(['env.a.x'], $r['conflicts']);
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":{"a":5,"b":2}}', self::canon($r['context']));

        // a bound non-object root is a bound value: a supplied path under it conflicts, it is never replaced
        $r = self::bind('{' . self::ACT . ',"env":5}', '{"env":{"x":1}}');
        self::assertSame(['env.x'], $r['conflicts']);
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":5}', self::canon($r['context']));
        $r = self::bind('{"action":5}', '{"action":{"params":{"x":1}}}');
        self::assertSame(['action.params.x'], $r['conflicts']);
        self::assertSame('{"action":5}', self::canon($r['context']));

        $r = self::bind('{' . self::ACT . '}', '{"env":{"x":1}}');
        self::assertSame('{"action":{"resource":"r","verb":"v"},"env":{"x":1}}', self::canon($r['context']));

        $r = self::bind('{"subject":{}}', '{"action":{"params":{"x":1}}}');
        self::assertSame([], $r['conflicts']);
        self::assertSame('{"action":{"params":{"x":1},"resource":"","verb":""},"subject":{}}', self::canon($r['context']));

        $r = self::bind('{"action":{"verb":"v","resource":"r","params":{"y":1}}}', '{"action":{"params":{"x":2}}}');
        self::assertSame([], $r['conflicts']);
        self::assertSame('{"action":{"params":{"x":2,"y":1},"resource":"r","verb":"v"}}', self::canon($r['context']));
    }

    private static function decide(string $where, string $bound): array
    {
        return MissingContext::decide(self::o($where), self::o($bound));
    }

    public function testDecideCollectEdges(): void
    {
        $ill = ['decision' => 'deny', 'reason' => 'ill_typed_context', 'missing' => []];
        $b = '{' . self::ACT . ',"env":{}}';
        $wrap = static function (int $n): string {
            $s = '{"field":"env.x","op":"eq","value":1}';
            for ($i = 0; $i < $n; $i++) {
                $s = '{"all_of":[' . $s . ']}';
            }
            return "[$s]";
        };
        $envx = ['decision' => 'escalate', 'reason' => 'escalate: missing_context principal:env.x', 'missing' => [['path' => 'env.x', 'supplier' => 'principal']]];
        self::assertSame($envx, self::decide($wrap(64), $b));
        self::assertSame($ill, self::decide($wrap(65), $b));

        $leafY = '{"field":"env.y","op":"eq","value":1}';
        self::assertSame($ill, self::decide('[{"field":"env.x","op":5},' . $leafY . ']', '{' . self::ACT . ',"env":{"x":1}}'));
        self::assertSame($ill, self::decide('[5,' . $leafY . ']', $b));
        self::assertSame($ill, self::decide('[{"all_of":[]},' . $leafY . ']', $b));
        self::assertSame($ill, self::decide('[{"field":5,"op":"eq","value":1}]', $b));

        self::assertSame(['decision' => 'escalate', 'reason' => 'escalate: missing_context principal:action.params', 'missing' => [['path' => 'action.params', 'supplier' => 'principal']]],
            self::decide('[{"field":"action.params","op":"eq","value":1}]', '{"action":{"verb":"v","resource":"r","params":5}}'));
        self::assertSame($ill, self::decide('[{"field":"action.params","op":5}]', '{"action":{"verb":"v","resource":"r","params":{"a":1}}}'));
        self::assertSame(['decision' => 'escalate', 'reason' => 'escalate: missing_context principal:5', 'missing' => [['path' => '5', 'supplier' => 'principal']]],
            self::decide('[{"field":"5","op":"eq","value":1}]', $b));
    }
}
