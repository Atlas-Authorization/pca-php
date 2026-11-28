<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/UndoServer.php';

use Atlas\Pca\ApprovalChannel;
use Atlas\Pca\ApprovalChannels;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\UndoError;
use Atlas\Pca\UndoServer;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/UndoServer.php: the component check, the notifier's exact message and request, and the veto relay's limits and parsing. */
final class PolicySurvivorKill24UndoServerTest extends TestCase
{
    private const UNTIL = '2027-01-15T08:00:00.123Z';

    /** The coordinator factory is public and refuses an incomplete configuration. */
    public function testCreateIsPublicAndRefusesIncompleteConfig(): void
    {
        $this->expectException(UndoError::class);
        $this->expectExceptionMessage('config: undo coordinator: missing required component(s)');
        UndoServer::createUndoCoordinator([]);
    }

    /** An object that lacks the needed method is missing; a KeyPair signer is accepted. */
    public function testMissingComponentsMethodChecks(): void
    {
        $noCreate = new class {
            public function get(): void
            {
            }

            public function transition(): void
            {
            }
        };
        $m = UndoServer::missingUndoComponents(['engine' => new \stdClass(), 'operations' => $noCreate, 'notifier' => new \stdClass(),
            'signerSecret' => new KeyPair(str_repeat("\2", 32))]);
        $this->assertContains('engine', $m);
        $this->assertContains('operations', $m);
        $this->assertContains('notifier', $m);
        $this->assertNotContains('signerSecret', $m);
    }

    /** @return array{0:\Atlas\Pca\UndoNotifier,1:\ArrayObject} a notifier over one capturing channel, and the captured [request, ctx] list */
    private static function capture(bool $delivered = true): array
    {
        $seen = new \ArrayObject();
        $ch = new ApprovalChannel('cap', true, static function (array $req, array $ctx) use ($seen, $delivered): array {
            $seen->append([$req, $ctx]);
            return ['kind' => 'cap', 'delivered' => $delivered];
        });
        $n = UndoServer::undoNotifierFromDispatcher(ApprovalChannels::createApprovalDispatcher([$ch]),
            ['undoUrl' => static fn(string $t, string $id): string => "https://u/undo/$id?t=$t", 'inboxUrl' => 'https://u/inbox']);
        return [$n, $seen];
    }

    private static function rec(string $extra = ''): Obj
    {
        return Json::parseLax('{"id":"r1","opened_at":1000,"window_end":1800000000123,"action":{"verb":"v","resource":"res"},"compensation":{"verb":"c"}' . $extra . '}');
    }

    /** Every notice kind has its own exact message. */
    public function testEveryKindHasItsMessage(): void
    {
        [$n, $seen] = self::capture();
        $want = [
            'opened' => 'Already done: v on res. You can undo it until ' . self::UNTIL . '.',
            'vetoed' => 'Undo started for v on res.',
            'compensated' => 'Undone: v on res.',
            'revoked' => "The agent's grant was revoked. v on res can still be undone until " . self::UNTIL . '.',
            'finalized' => 'Final: v on res can no longer be undone.',
        ];
        foreach ($want as $kind => $text) {
            $this->assertSame(['delivered' => true], $n->notify(['kind' => $kind, 'record' => self::rec()]));
            $this->assertSame($text, $seen[count($seen) - 1][0]['reason'], $kind);
        }
    }

    /** A failed compensation names the outcome's reason, or 'unknown' without one. */
    public function testCompensationFailedReason(): void
    {
        [$n, $seen] = self::capture();
        $n->notify(['kind' => 'compensation_failed', 'record' => self::rec(',"outcome":{"reason":"boom"}')]);
        $this->assertSame('UNDO FAILED for v on res: boom. An operator has been alerted.', $seen[0][0]['reason']);
        $n->notify(['kind' => 'compensation_failed', 'record' => self::rec()]);
        $this->assertSame('UNDO FAILED for v on res: unknown. An operator has been alerted.', $seen[1][0]['reason']);
        $n->notify(['kind' => 'compensation_failed', 'record' => self::rec(',"outcome":{"reason":null}')]);
        $this->assertSame('UNDO FAILED for v on res: unknown. An operator has been alerted.', $seen[2][0]['reason']);
    }

    /** The request is step-up shaped: tier 3, the lineage, r = 0, the opening time as an int; the render only with its digest. */
    public function testTheRequestShape(): void
    {
        [$n, $seen] = self::capture();
        $render = Obj::of(['text' => 'x']);
        $n->notify(['kind' => 'vetoed', 'record' => self::rec(',"render_digest":"rd"'), 'render' => $render, 'token' => 'tok']);
        [$req, $ctx] = $seen[0];
        $reason = 'Undo started for v on res.';
        $this->assertSame(['id' => 'undo:r1:vetoed', 'verb' => 'v', 'resource' => 'res', 'tier' => 3, 'reason' => $reason, 'goalCommit' => '',
            'lineage' => ['goalCommit' => '', 'goalVerified' => false, 'chain' => [['kind' => 'action', 'label' => 'v res', 'detail' => 'undo: c']], 'because' => $reason],
            'r' => 0, 'requestedAt' => 1000, 'render' => $render, 'renderDigest' => 'rd'], $req);
        // not 'opened': the inbox link, even with a token
        $this->assertSame(['inboxUrl' => 'https://u/inbox'], $ctx);
        $n->notify(['kind' => 'vetoed', 'record' => self::rec(',"render_digest":"rd"')]);
        $this->assertArrayNotHasKey('renderDigest', $seen[1][0]);
        $n->notify(['kind' => 'vetoed', 'record' => self::rec(), 'render' => $render]);
        $this->assertArrayNotHasKey('render', $seen[2][0]);
    }

    /** A fractional window end is truncated by an explicit cast (no implicit float-to-int conversion). */
    public function testFractionalWindowEndRaisesNoDeprecation(): void
    {
        [$n, $seen] = self::capture();
        $errs = [];
        set_error_handler(static function (int $no, string $msg) use (&$errs): bool {
            $errs[] = $msg;
            return true;
        });
        try {
            $r = $n->notify(['kind' => 'opened', 'record' => Json::parseLax('{"id":"r1","opened_at":1000,"window_end":1800000000123.5,"action":{"verb":"v","resource":"res"},"compensation":{"verb":"c"}}')]);
        } finally {
            restore_error_handler();
        }
        $this->assertSame(['delivered' => true], $r);
        $this->assertSame([], $errs);
        $this->assertSame('Already done: v on res. You can undo it until ' . self::UNTIL . '.', $seen[0][0]['reason']);
    }

    /** Undelivered: every channel's kind and reason ('not delivered' without one). */
    public function testUndeliveredReasons(): void
    {
        $a = new ApprovalChannel('a', true, static fn(array $r, array $c): array => ['kind' => 'a', 'delivered' => false, 'reason' => 'r1']);
        $b = new ApprovalChannel('b', true, static fn(array $r, array $c): array => ['kind' => 'b', 'delivered' => false]);
        $n = UndoServer::undoNotifierFromDispatcher(ApprovalChannels::createApprovalDispatcher([$a, $b]), ['undoUrl' => static fn() => 'u']);
        $this->assertSame(['delivered' => false, 'reason' => 'a: r1; b: not delivered'], $n->notify(['kind' => 'vetoed', 'record' => self::rec()]));
    }

    /** notify never throws: an error becomes an undelivered result with its message, or 'notify error' for an empty one. */
    public function testNotifyNeverThrows(): void
    {
        foreach (['chan down' => 'chan down', '' => 'notify error'] as $msg => $want) {
            $c = new ApprovalChannel('x', true, static fn(array $r, array $ctx): array => throw new \RuntimeException((string)$msg));
            $n = UndoServer::undoNotifierFromDispatcher(ApprovalChannels::createApprovalDispatcher([$c]), ['undoUrl' => static fn() => 'u']);
            $this->assertSame(['delivered' => false, 'reason' => $want], $n->notify(['kind' => 'vetoed', 'record' => self::rec()]));
        }
    }

    /** @return array{0:\Atlas\Pca\UndoVetoRelay,1:\ArrayObject} */
    private static function relay(array $res, ?int $limit = null): array
    {
        $seen = new \ArrayObject();
        $r = UndoServer::hostedUndoVetoRelay('https://api.x', 'sk', static function (string $url, array $init) use ($seen, $res): array {
            $seen->append([$url, $init]);
            return $res;
        }, $limit);
        return [$r, $seen];
    }

    private const OK = ['ok' => true, 'status' => 200, 'body' => '{"data":[]}'];

    /** The page size: default 200, at least 1, at most 200. */
    public function testRelayLimit(): void
    {
        foreach ([[null, 200], [5, 5], [0, 1], [1, 1], [-3, 1]] as [$lim, $want]) {
            [$r, $seen] = self::relay(self::OK, $lim);
            $this->assertSame([], $r->pending());
            $this->assertSame("https://api.x/v1/pca/undo/vetoes?limit=$want", $seen[0][0]);
            $this->assertSame(['method' => 'GET', 'headers' => ['authorization' => 'Bearer sk', 'accept' => 'application/json']], $seen[0][1]);
        }
    }

    private function assertRelayError(array $res, string $msg): void
    {
        [$r] = self::relay($res);
        try {
            $r->pending();
            $this->fail($msg);
        } catch (UndoError $e) {
            $this->assertSame($msg, $e->getMessage());
        }
    }

    /** An answer that is not ok (or does not say ok) throws with its status (0 when absent); a non-string body is no data list. */
    public function testRelayAnswerErrors(): void
    {
        $this->assertRelayError(['status' => 200, 'body' => '{"data":[]}'], 'invalid: the veto relay answered 200');
        $this->assertRelayError(['ok' => false, 'status' => 503, 'body' => '{"data":[]}'], 'invalid: the veto relay answered 503');
        $this->assertRelayError(['ok' => false], 'invalid: the veto relay answered 0');
        $this->assertRelayError(['ok' => true, 'status' => 200, 'body' => 5], 'invalid: the veto relay answered without a data list');
    }

    /** Entry validation: the record id, the token and a numeric time are each required; a float time is truncated; every entry is returned. */
    public function testRelayEntries(): void
    {
        $this->assertRelayError(['ok' => true, 'status' => 200, 'body' => '{"data":[{"record_id":1,"veto":{"token":"t","at":1}}]}'],
            'invalid: the veto relay answered a malformed entry');
        $this->assertRelayError(['ok' => true, 'status' => 200, 'body' => '{"data":[{"record_id":"r","veto":{"token":"t","at":"x"}}]}'],
            'invalid: the veto relay answered a malformed entry');
        [$r] = self::relay(['ok' => true, 'status' => 200,
            'body' => '{"data":[{"record_id":"r1","veto":{"token":"t1","at":1700000000000.5}},{"record_id":"r2","veto":{"token":"t2","at":7}}]}']);
        $this->assertSame([['id' => 'r1', 'token' => 't1', 'at' => 1700000000000], ['id' => 'r2', 'token' => 't2', 'at' => 7]], $r->pending());
    }

    /** The default transport: an answer without an HTTP 2xx status (a data: URL has none) is not ok. */
    public function testDefaultTransportNeedsA2xxStatus(): void
    {
        $r = UndoServer::hostedUndoVetoRelay('data:application/json,{"data":[]}', 'sk');
        try {
            $r->pending();
            $this->fail('a statusless answer was accepted');
        } catch (UndoError $e) {
            $this->assertSame('invalid: the veto relay answered 0', $e->getMessage());
        }
    }
}
