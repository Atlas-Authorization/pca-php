<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Adapters.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\Adapters;
use Atlas\Pca\ArgProvenance;
use Atlas\Pca\IntentWb;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaHeaderError;
use Atlas\Pca\PolicyTemplates;
use Atlas\Pca\ProvenanceRecorder;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of adapters.ts: header bound, message roles and shapes, what the record helpers put in the provenance chain. */
final class MathSurvivorKill31AdaptersTest extends TestCase
{
    private static function rec(): ProvenanceRecorder
    {
        return new ProvenanceRecorder('m', 'k1', new KeyPair(str_repeat("\1", 32)), Pca::b64u(str_repeat("\2", 32)), static fn(): int => 1000);
    }

    /** @return list<array{0:mixed,1:mixed,2:mixed}> [origin, source, content_digest] of every receipt */
    private static function log(ProvenanceRecorder $r): array
    {
        return array_map(fn(Obj $x) => [$x->get('origin'), $x->get('source'), $x->get('content_digest')], $r->receipts());
    }

    private static function p(string $text): array
    {
        return ['principal', 'user', IntentWb::valueDigest($text)];
    }

    private static function u(string $text): array
    {
        return ['role' => 'user', 'content' => $text];
    }

    /** Runs $f and asserts it raised no PHP warning or notice. */
    private static function quiet(callable $f): mixed
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $w);
        return $r;
    }

    /** A header error carries its message. */
    public function testHeaderErrorMessage(): void
    {
        $this->expectException(PcaHeaderError::class);
        $this->expectExceptionMessage('PCA-Action header is empty');
        Adapters::decodePcaHeader('');
    }

    /** A bundle of exactly PROV_HEADER_MAX base64url characters still goes in the header; one byte more does not. */
    public function testProvenanceHeaderBoundIsInclusive(): void
    {
        $fit = Obj::of(['x' => str_repeat('a', 6136)]);
        $h = Adapters::provenanceHeaders($fit);
        self::assertSame(8192, strlen($h[ArgProvenance::HEADER]));
        self::assertSame([], Adapters::provenanceHeaders(Obj::of(['x' => str_repeat('a', 6137)])));
    }

    /** A recorder passed directly is used; a missing target records nothing and never fails. */
    public function testRecorderTargets(): void
    {
        $r = self::rec();
        Adapters::recordPrincipal($r, 'x');
        Adapters::recordToolResult(null, 't', 'out');
        Adapters::recordToolResult($r, 't', 'out');
        self::assertSame([self::p('x'), ['tool', 't', IntentWb::valueDigest('out')]], self::log($r));
    }

    /** Roles come from an Obj, a plain object's members, a getType() method, case-insensitively. */
    public function testMessageRolesAndShapes(): void
    {
        $seg = fn(string $c) => [['origin' => 'principal', 'source' => 'user', 'content' => $c]];
        self::assertSame($seg('hello'), Adapters::messageSegments(Obj::of(['role' => 'user', 'content' => 'hello'])));
        self::assertSame($seg('hi'), Adapters::messageSegments((object)['role' => 'user', 'content' => 'hi']));
        self::assertSame($seg(''), self::quiet(fn() => Adapters::messageSegments((object)['role' => 'user'])));
        $typed = new class {
            public string $content = 'hi';

            public function getType(): string
            {
                return 'human';
            }
        };
        self::assertSame($seg('hi'), Adapters::messageSegments($typed));
        self::assertSame($seg('x'), Adapters::messageSegments(['role' => 'USER', 'content' => 'x']));
        $img = ['type' => 'image', 'url' => 'u'];
        self::assertSame([['origin' => 'principal', 'source' => 'user', 'content' => $img]], Adapters::messageSegments(['role' => 'user', 'content' => [$img]]));
    }

    /** New messages are recorded once; a shorter list starts over from its first message; the same list again records nothing. */
    public function testRecordMessagesProgress(): void
    {
        $r = self::rec();
        Adapters::recordMessages($r, [self::u('a'), self::u('b'), self::u('c')]);
        self::quiet(fn() => Adapters::recordMessages($r, [self::u('d'), self::u('e')]));
        Adapters::recordMessages($r, [self::u('d'), self::u('e')]);
        self::assertSame([self::p('a'), self::p('b'), self::p('c'), self::p('d'), self::p('e')], self::log($r));
        $t = self::rec();
        Adapters::recordMessages($t, [['role' => 'tool', 'name' => 'search', 'content' => 'r']]);
        self::assertSame([['tool', 'search', IntentWb::valueDigest('r')]], self::log($t));
    }

    /** A non-string principal part is recorded as its JSON text: a plain object and an Obj alike; one json_encode cannot encode is null. */
    public function testObjectPrincipalContent(): void
    {
        foreach ([(object)['a' => 1], Obj::of(['a' => 1])] as $part) {
            $r = self::rec();
            Adapters::recordMessages($r, [['role' => 'user', 'content' => [$part]]]);
            self::assertSame([self::p('{"a":1}')], self::log($r));
        }
        $r = self::rec();
        Adapters::recordMessages($r, [['role' => 'user', 'content' => [(object)['v' => NAN]]]]);
        self::assertSame([self::p('null')], self::log($r));
    }

    /** recordInput: a message list, an Obj / array / object map (messages, input and its aliases, a string or a list), and nothing for a scalar. */
    public function testRecordInputShapes(): void
    {
        $cases = [
            [[self::u('x')], [self::p('x')]],
            [Obj::of(['prompt' => 'x']), [self::p('x')]],
            [['prompt' => 'x'], [self::p('x')]],
            [(object)['prompt' => 'x'], [self::p('x')]],
            [5, []],
            [['messages' => [self::u('m')]], [self::p('m')]],
            [['input' => 'i'], [self::p('i')]],
            [['input' => [self::u('l')]], [self::p('l')]],
        ];
        foreach ($cases as $k => [$in, $want]) {
            $r = self::rec();
            Adapters::recordInput($r, $in);
            self::assertSame($want, self::log($r), "case $k");
        }
        $r = self::rec();
        self::assertSame('ran a', Adapters::withPrincipalInput($r, static fn(string $q): string => "ran $q")('a', 'b'));
        self::assertSame([self::p('a')], self::log($r));
    }

    /** A mapping without a resource declines the call (null), with no warning. */
    public function testBridgeNeedsVerbAndResource(): void
    {
        $a = PolicyTemplates::fromTemplate('read-only', new KeyPair(str_repeat("\1", 32)), 'look', 'rs', null, 1800000000000);
        self::assertNull(self::quiet(fn() => Adapters::bridgeToolCall($a, ['name' => 'x', 'arguments' => []], static fn() => ['verb' => 'github.read'])));
    }
}
