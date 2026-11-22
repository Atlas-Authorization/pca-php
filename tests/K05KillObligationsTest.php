<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Obligations.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Obligations;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Obligations: parameter bounds, the exact refusal messages, merge cap, gate deny shape, outcome. */
final class K05KillObligationsTest extends TestCase
{
    private static function ob(string $kind, ?array $params = null): Obj
    {
        $o = Obj::of(['kind' => $kind]);
        $params === null || $o->set('params', Obj::of($params));
        return $o;
    }

    public function testParamBounds(): void
    {
        $sink = 'log.sink must be a non-empty string of at most 128 characters';
        self::assertNull(Obligations::error(self::ob('log', ['sink' => str_repeat('s', 128)])));
        self::assertSame($sink, Obligations::error(self::ob('log', ['sink' => str_repeat('s', 129)])));
        self::assertSame($sink, Obligations::error(self::ob('log', ['sink' => ''])));
        self::assertNull(Obligations::error(self::ob('log')));

        $to = 'notify.to is required (a non-empty string of at most 256 characters)';
        self::assertNull(Obligations::error(self::ob('notify', ['to' => str_repeat('t', 256)])));
        self::assertSame($to, Obligations::error(self::ob('notify', ['to' => str_repeat('t', 257)])));

        $wm = 'watermark.id is required (a non-empty string of at most 128 characters)';
        self::assertNull(Obligations::error(self::ob('watermark', ['id' => str_repeat('w', 128)])));
        self::assertSame($wm, Obligations::error(self::ob('watermark', ['id' => str_repeat('w', 129)])));

        $fields = array_map(static fn (int $i): string => "f$i", range(0, 31));
        self::assertNull(Obligations::error(self::ob('redact', ['fields' => $fields])));
        self::assertSame('redact.fields must be 1..32 dotted field paths',
            Obligations::error(self::ob('redact', ['fields' => [...$fields, 'f32']])));
    }

    public function testErrorMessages(): void
    {
        self::assertSame('an obligation must be an object', Obligations::error('x'));
        self::assertSame("unknown obligation kind 'zap'", Obligations::error(Obj::of(['kind' => 'zap'])));
        self::assertSame("unknown obligation kind ''", Obligations::error(Obj::of(['kind' => 5])));
        self::assertSame('params must be an object', Obligations::error(Obj::of(['kind' => 'log', 'params' => 5])));
        self::assertSame('more than 16 obligations', Obligations::listError(array_fill(0, 17, 'x')));
    }

    public function testKeyIsPublic(): void
    {
        self::assertSame('{"kind":"log","params":{}}', Obligations::key(self::ob('log')));
    }

    public function testMergeCap(): void
    {
        $sixteen = array_map(static fn (int $i): Obj => self::ob('notify', ['to' => "a$i"]), range(1, 16));
        $m = Obligations::merge($sixteen);
        self::assertTrue($m['ok']);
        self::assertCount(16, $m['obligations']);
        self::assertSame(['ok' => false, 'reason' => 'more than 16 obligations after merging'],
            Obligations::merge($sixteen, [self::ob('notify', ['to' => 'a17'])]));
    }

    public function testGateDenyShape(): void
    {
        self::assertSame(['decision' => 'deny', 'perform' => [], 'unsupported' => [], 'reason' => 'malformed obligations: obligations must be an array'],
            Obligations::gate('allow', false, 'x', []));
        self::assertSame(['decision' => 'deny', 'perform' => [], 'unsupported' => ['log', 'notify'],
            'reason' => 'the enforcement point does not support obligation(s) log, notify'],
            Obligations::gate('allow', false, [self::ob('notify', ['to' => 'a']), self::ob('log')], []));
    }

    public function testOutcomeBadFulfilled(): void
    {
        self::assertSame(['outcome' => 'escalate', 'overdue' => [], 'status' => 'obligation_unmet'],
            Obligations::outcome([], ['x'], new Num('0')));
        self::assertSame(['outcome' => 'ok', 'overdue' => []], Obligations::outcome([], [new Num('0')], new Num('0')));
    }

    public function testMergeFailsClosedOnAThrow(): void
    {
        Obligations::$mergeHook = static function (): void {
            throw new \RuntimeException('boom');
        };
        try {
            self::assertSame(['ok' => false, 'reason' => 'evaluation error (fail closed)'], Obligations::merge([self::ob('log', ['sink' => 's'])]));
        } finally {
            Obligations::$mergeHook = null;
        }
    }
}
