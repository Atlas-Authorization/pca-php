<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ApprovalChannels.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\ApprovalChannels;
use Atlas\Pca\Approvals;
use Atlas\Pca\KeyPair;
use Atlas\Pca\PolicyTemplates;
use PHPUnit\Framework\TestCase;

/** approval-channels.ts: the Slack / webhook / text bodies, the channel gates and the dispatcher. */
final class ApprovalChannelsTest extends TestCase
{
    private const NOW = 1800000000000;

    /** @return array<string,mixed> */
    private function request(): array
    {
        $a = PolicyTemplates::fromTemplate('finance-bot', new KeyPair(str_repeat("\1", 32)), 'refund orders', 'rs', null, self::NOW);
        return Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, 'refund orders', null, null, true)['request'];
    }

    public function testSummaryAndLinesCarryTheLineage(): void
    {
        $r = $this->request();
        self::assertSame('stripe.refund on ch_12345678 (tier 2, risk 0.50)', ApprovalChannels::actionSummary($r));
        $lines = ApprovalChannels::lineageLines($r);
        self::assertSame($r['lineage']['because'], $lines[0]);
        self::assertCount(4, $lines);
        self::assertSame([], ApprovalChannels::renderLines($r));
    }

    public function testSlackMessageWithAndWithoutInbox(): void
    {
        $r = $this->request();
        $m = ApprovalChannels::buildSlackMessage($r, ['inboxUrl' => 'https://app.example/inbox#tok']);
        self::assertSame('Approval needed: stripe.refund on ch_12345678 (tier 2, risk 0.50)', $m['text']);
        self::assertSame(['header', 'section', 'section', 'actions'], array_column($m['blocks'], 'type'));
        $b = $m['blocks'][3]['elements'];
        self::assertSame('https://app.example/inbox?stepup=' . $r['id'] . '&decision=approve#tok', $b[0]['url']);
        self::assertSame('danger', $b[1]['style']);
        $plain = ApprovalChannels::buildSlackMessage($r);
        self::assertSame('context', $plain['blocks'][3]['type']);
    }

    public function testWebhookAndTextBodies(): void
    {
        $r = $this->request();
        $w = ApprovalChannels::buildWebhookBody($r, ['inboxUrl' => 'https://x/inbox?a=1']);
        self::assertSame(['type', 'stepup', 'summary', 'lineage', 'inbox_url'], array_keys($w));
        self::assertSame(['type', 'stepup', 'summary', 'lineage'], array_keys(ApprovalChannels::buildWebhookBody($r, ['inboxUrl' => ''])));
        $t = ApprovalChannels::buildTextBody($r, ['inboxUrl' => 'https://x/inbox?a=1']);
        self::assertSame('Approval needed: stripe.refund on ch_12345678', $t['subject']);
        self::assertStringEndsWith('Approve or deny: https://x/inbox?a=1&stepup=' . $r['id'], $t['text']);
    }

    public function testChannelsGateDeliverAndReportFailures(): void
    {
        $r = $this->request();
        $off = ApprovalChannels::slackApprovalChannel();
        self::assertFalse($off->enabled);
        $d = $off->notify($r);
        self::assertFalse($d['delivered']);
        self::assertSame('slack channel not configured', $d['reason']);
        $seen = [];
        $ok = ApprovalChannels::webhookApprovalChannel('https://hook', static function (string $url, array $init) use (&$seen): array {
            $seen = [$url, $init];
            return ['ok' => true, 'status' => 204];
        }, ['x-sig' => 'abc']);
        $d = $ok->notify($r);
        self::assertTrue($d['delivered']);
        self::assertSame(204, $d['status']);
        self::assertSame('https://hook', $seen[0]);
        self::assertSame(['content-type' => 'application/json', 'x-sig' => 'abc'], $seen[1]['headers']);
        self::assertSame('pca.step_up.created', json_decode($seen[1]['body'], true)['type']);
        self::assertStringNotContainsString('https://hook', json_encode($d));
        $bad = ApprovalChannels::slackApprovalChannel('https://hook', static fn() => ['ok' => false, 'status' => 500]);
        self::assertSame('slack webhook returned 500', $bad->notify($r)['reason']);
        $boom = ApprovalChannels::slackApprovalChannel('https://hook', static fn() => throw new \RuntimeException('down'));
        self::assertSame('down', $boom->notify($r)['reason']);
        $sent = [];
        $mail = ApprovalChannels::textApprovalChannel('email', static function (array $b) use (&$sent): void {
            $sent[] = $b;
        });
        self::assertTrue($mail->notify($r)['delivered']);
        self::assertCount(1, $sent);
        self::assertFalse(ApprovalChannels::textApprovalChannel('sms')->enabled);
        $this->expectException(\InvalidArgumentException::class);
        ApprovalChannels::textApprovalChannel('fax');
    }

    public function testDispatcherSkipsDisabledChannels(): void
    {
        $r = $this->request();
        $d = ApprovalChannels::createApprovalDispatcher([
            ApprovalChannels::slackApprovalChannel(),
            ApprovalChannels::webhookApprovalChannel('https://hook', static fn() => ['ok' => true, 'status' => 200]),
            ApprovalChannels::textApprovalChannel('push', static fn() => null),
        ]);
        self::assertCount(3, $d->channels);
        $out = $d->notifyAll($r);
        self::assertSame(['webhook', 'push'], array_column($out, 'kind'));
    }
}
