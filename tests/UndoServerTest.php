<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/UndoServer.php';

use Atlas\Pca\ApprovalChannels;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryUndoStore;
use Atlas\Pca\Obj;
use Atlas\Pca\UndoError;
use Atlas\Pca\UndoServer;
use PHPUnit\Framework\TestCase;

/** server/undo.ts support: signer public key, configuration check, effect report, notifier over the approval channels, hosted veto relay. */
final class UndoServerTest extends TestCase
{
    public function testSignerPublicAndMissingComponents(): void
    {
        $k = new KeyPair(str_repeat("\1", 32));
        self::assertSame($k->public, UndoServer::undoSignerPublic($k));
        self::assertSame($k->public, UndoServer::undoSignerPublic(str_repeat("\1", 32)));
        self::assertSame(60000, UndoServer::UNDO_RELAY_GRACE_MS);
        self::assertSame(['store', 'engine', 'signerSecret', 'audience', 'resolveGrant', 'compensate', 'operations', 'notifier', 'alert'], UndoServer::missingUndoComponents(null));
        $engine = new class { public function plan(): void {} };
        $ops = new class { public function create(): void {} public function get(): void {} public function transition(): void {} };
        $ok = ['store' => new MemoryUndoStore(), 'engine' => $engine, 'signerSecret' => str_repeat("\1", 32), 'audience' => 'rs', 'resolveGrant' => fn() => null,
            'compensate' => fn() => null, 'operations' => $ops, 'notifier' => UndoServer::undoNotifierFromDispatcher(ApprovalChannels::createApprovalDispatcher([]), ['undoUrl' => fn() => 'u']),
            'alert' => fn() => null];
        self::assertSame([], UndoServer::missingUndoComponents($ok));
        self::assertSame(['signerSecret'], UndoServer::missingUndoComponents(['signerSecret' => 'short'] + $ok));
    }

    public function testReportUndoEffect(): void
    {
        $calls = [];
        $rec = Json::parseLax('{"id":"r1"}');
        $co = new class ($calls, $rec) {
            public function __construct(private array &$calls, private Obj $rec) {}
            public function recordEffect(string $id, mixed $r): Obj { $this->calls[] = ['effect', $id, $r]; return $this->rec; }
            public function abort(string $id, string $why): Obj { $this->calls[] = ['abort', $id, $why]; return $this->rec; }
            public function get(string $id): ?Obj { $this->calls[] = ['get', $id]; return $id === 'r1' ? $this->rec : null; }
        };
        UndoServer::reportUndoEffect($co, 'r1', ['status' => 'committed', 'result' => 'x']);
        UndoServer::reportUndoEffect($co, 'r1', ['status' => 'failed']);
        UndoServer::reportUndoEffect($co, 'r1', ['status' => 'refused']);
        self::assertSame($rec, UndoServer::reportUndoEffect($co, 'r1', ['status' => 'uncertain']));
        self::assertSame([['effect', 'r1', 'x'], ['abort', 'r1', 'effect_failed'], ['abort', 'r1', 'effect_refused'], ['get', 'r1']], $calls);
        $this->expectException(UndoError::class);
        UndoServer::reportUndoEffect($co, 'nope', ['status' => 'pending']);
    }

    public function testNotifierOverTheChannels(): void
    {
        $sent = [];
        $d = ApprovalChannels::createApprovalDispatcher([ApprovalChannels::textApprovalChannel('email', static function (array $b) use (&$sent): void {
            $sent[] = $b;
        })]);
        $n = UndoServer::undoNotifierFromDispatcher($d, ['undoUrl' => static fn(string $t, string $id): string => "https://u/undo/$id?t=$t", 'inboxUrl' => 'https://u/inbox']);
        $rec = Json::parseLax('{"id":"r1","opened_at":1000,"window_end":1800000000123,"action":{"verb":"gmail.send","resource":"m1"},"compensation":{"verb":"gmail.delete"}}');
        $r = $n->notify(['kind' => 'opened', 'record' => $rec, 'token' => 'tok']);
        self::assertSame(['delivered' => true], $r);
        self::assertStringContainsString('You can undo it until 2027-01-15T08:00:00.123Z.', $sent[0]['text']);
        self::assertStringContainsString('https://u/undo/r1?t=tok&stepup=undo%3Ar1%3Aopened', $sent[0]['text']);
        $n->notify(['kind' => 'finalized', 'record' => $rec]);
        self::assertStringContainsString('Final: gmail.send on m1 can no longer be undone.', $sent[1]['text']);
        $none = UndoServer::undoNotifierFromDispatcher(ApprovalChannels::createApprovalDispatcher([]), ['undoUrl' => fn() => 'u']);
        self::assertSame(['delivered' => false, 'reason' => 'no enabled channel'], $none->notify(['kind' => 'vetoed', 'record' => $rec]));
    }

    public function testHostedRelay(): void
    {
        $seen = null;
        $ok = UndoServer::hostedUndoVetoRelay('https://api.x//', 'sk_1', static function (string $url, array $init) use (&$seen): array {
            $seen = [$url, $init];
            return ['ok' => true, 'status' => 200, 'body' => '{"data":[{"record_id":"r1","veto":{"token":"t","at":1700000000000}}]}'];
        }, 500);
        self::assertSame([['id' => 'r1', 'token' => 't', 'at' => 1700000000000]], $ok->pending());
        self::assertSame('https://api.x/v1/pca/undo/vetoes?limit=200', $seen[0]);
        self::assertSame('Bearer sk_1', $seen[1]['headers']['authorization']);
        foreach ([['ok' => false, 'status' => 503, 'body' => ''], ['ok' => true, 'status' => 200, 'body' => '{}'],
            ['ok' => true, 'status' => 200, 'body' => '{"data":[{"record_id":1}]}']] as $bad) {
            try {
                UndoServer::hostedUndoVetoRelay('https://x', 'k', static fn() => $bad)->pending();
                self::fail('a relay that cannot be read must throw');
            } catch (UndoError) {
                self::assertTrue(true);
            }
        }
    }
}
