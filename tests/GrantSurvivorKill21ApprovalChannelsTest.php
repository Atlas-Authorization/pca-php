<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ApprovalChannels.php';

use Atlas\Pca\Approval;
use Atlas\Pca\ApprovalChannels;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** approval-channels.ts: exact Slack / webhook / text bodies, the canonical render lines, every channel outcome and the default HTTP transport. */
final class GrantSurvivorKill21ApprovalChannelsTest extends TestCase
{
    /** @return array<string,mixed> */
    private static function request(array $over = []): array
    {
        return $over + ['id' => 'su_1', 'verb' => 'stripe.refund', 'resource' => 'ch_1', 'tier' => 2, 'r' => 0.5, 'reason' => 'over cap',
            'lineage' => ['because' => 'because you asked to refund', 'chain' => [['label' => 'goal', 'detail' => 'refund orders'], ['label' => 'auth']]]];
    }

    private const LINEAGE = ['because you asked to refund', 'goal — refund orders', 'auth'];
    private const SUMMARY = 'stripe.refund on ch_1 (tier 2, risk 0.50)';

    private static function render(bool $unreviewed): Obj
    {
        return Obj::of(['unreviewed' => $unreviewed, 'fields' => [
            Obj::of(['id' => 'amount', 'class' => 'money', 'value' => 250, 'unit' => Obj::of(['kind' => 'money', 'ccy' => 'USD', 'exp' => 2])]),
            Obj::of(['id' => 'note', 'class' => 'text', 'value' => "a\u{200E}b\x7f", 'unit' => Obj::of(['kind' => 'count'])]),
            Obj::of(['id' => 'to', 'class' => 'id', 'value' => 'x', 'unit' => null]),
        ]]);
    }

    /** A numeric-string risk is formatted like a number. */
    public function testSummaryFormatsRisk(): void
    {
        $this->assertSame('stripe.refund on ch_1 (tier 2, risk 0.50)', ApprovalChannels::actionSummary(self::request(['r' => '0.5'])));
    }

    /** Every field renders on its own line (control and format characters escaped by code point), then the match code; the banner only when unreviewed. */
    public function testRenderLines(): void
    {
        $digest = Pca::b64u(str_repeat("\x07", 32));
        $fields = ['amount [money]: 250 USD (minor units, exponent 2)', 'note [text]: "a\u{200e}b\u{7f}"', 'to [id]: "x"',
            'Match code: ' . Approval::bindingWords($digest)];
        $banner = 'UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.';
        $this->assertSame([$banner, ...$fields], ApprovalChannels::renderLines(self::request(['render' => self::render(true), 'renderDigest' => $digest])));
        $this->assertSame($fields, ApprovalChannels::renderLines(self::request(['render' => self::render(false), 'renderDigest' => $digest])));
        $this->assertSame([...self::LINEAGE, ...$fields], ApprovalChannels::lineageLines(self::request(['render' => self::render(false), 'renderDigest' => $digest])));
        // no render without both an Obj render and a digest
        $this->assertSame([], ApprovalChannels::renderLines(self::request(['render' => ['fields' => []], 'renderDigest' => $digest])));
        $this->assertSame([], ApprovalChannels::renderLines(self::request(['render' => self::render(true)])));
    }

    private static function slackHead(): array
    {
        return [
            ['type' => 'header', 'text' => ['type' => 'plain_text', 'text' => 'Approval needed · tier 2', 'emoji' => true]],
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => "*stripe.refund* on `ch_1`\n_over cap_"]],
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => "*Why this is requested*\n• because you asked to refund\n• goal — refund orders\n• auth"]],
        ];
    }

    private static function button(string $label, string $url, string $style, string $id): array
    {
        return ['type' => 'button', 'text' => ['type' => 'plain_text', 'text' => $label, 'emoji' => true], 'url' => $url, 'style' => $style, 'action_id' => $id];
    }

    /** The Slack message, exactly, with an inbox (links keep the fragment last) and without. */
    public function testSlackMessageExact(): void
    {
        $in = 'https://app.example/inbox?x=1#tok';
        $this->assertSame(['text' => 'Approval needed: ' . self::SUMMARY, 'blocks' => [...self::slackHead(), ['type' => 'actions', 'elements' => [
            self::button('Approve', 'https://app.example/inbox?x=1&stepup=su_1&decision=approve#tok', 'primary', 'pca_approve'),
            self::button('Deny', 'https://app.example/inbox?x=1&stepup=su_1&decision=deny#tok', 'danger', 'pca_deny'),
        ]]]], ApprovalChannels::buildSlackMessage(self::request(), ['inboxUrl' => $in]));
        $this->assertSame(['text' => 'Approval needed: ' . self::SUMMARY, 'blocks' => [...self::slackHead(),
            ['type' => 'context', 'elements' => [['type' => 'mrkdwn', 'text' => 'Approve or deny step-up `su_1` in your Atlas inbox.']]]]],
            ApprovalChannels::buildSlackMessage(self::request(), ['inboxUrl' => '']));
    }

    /** The text body, exactly. */
    public function testTextBodyExact(): void
    {
        $this->assertSame(['subject' => 'Approval needed: stripe.refund on ch_1', 'text' => implode("\n", [self::SUMMARY, '', ...self::LINEAGE])],
            ApprovalChannels::buildTextBody(self::request()));
        $this->assertSame(implode("\n", [self::SUMMARY, '', ...self::LINEAGE, '', 'Approve or deny: https://i.example/?stepup=su_1']),
            ApprovalChannels::buildTextBody(self::request(), ['inboxUrl' => 'https://i.example/'])['text']);
    }

    private static function recorder(array &$calls, mixed $result): \Closure
    {
        return static function (string $url, array $init) use (&$calls, $result): array {
            $calls[] = [$url, $init];
            return $result instanceof \Throwable ? throw $result : $result;
        };
    }

    /** Every Slack outcome, exactly, and the request it hands the transport. */
    public function testSlackOutcomes(): void
    {
        $r = self::request();
        $msg = ApprovalChannels::buildSlackMessage($r);
        $base = ['kind' => 'slack', 'requestId' => 'su_1', 'payload' => $msg];
        $calls = [];
        $this->assertSame($base + ['delivered' => true, 'status' => 200], ApprovalChannels::slackApprovalChannel('https://h', self::recorder($calls, ['ok' => true, 'status' => 200]))->notify($r));
        $this->assertSame([['https://h', ['method' => 'POST', 'headers' => ['content-type' => 'application/json'], 'body' => Js::stringify(Sign::n($msg))]]], $calls);
        $this->assertSame($base + ['delivered' => false, 'status' => 503, 'reason' => 'slack webhook returned 503'],
            ApprovalChannels::slackApprovalChannel('https://h', self::recorder($calls, ['ok' => false, 'status' => 503]))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'slack transport error'],
            ApprovalChannels::slackApprovalChannel('https://h', self::recorder($calls, new \RuntimeException('')))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'down'],
            ApprovalChannels::slackApprovalChannel('https://h', self::recorder($calls, new \RuntimeException('down')))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'slack channel not configured'], ApprovalChannels::slackApprovalChannel('')->notify($r));
    }

    /** Every webhook outcome, exactly; a null or empty URL is not configured. */
    public function testWebhookOutcomes(): void
    {
        $r = self::request();
        $body = ApprovalChannels::buildWebhookBody($r);
        $base = ['kind' => 'webhook', 'requestId' => 'su_1', 'payload' => $body];
        $calls = [];
        $this->assertSame($base + ['delivered' => true, 'status' => 201],
            ApprovalChannels::webhookApprovalChannel('https://h', self::recorder($calls, ['ok' => true, 'status' => 201]), ['x-sig' => 's'])->notify($r));
        $this->assertSame([['https://h', ['method' => 'POST', 'headers' => ['content-type' => 'application/json', 'x-sig' => 's'], 'body' => Js::stringify(Sign::n($body))]]], $calls);
        $this->assertSame($base + ['delivered' => false, 'status' => 300, 'reason' => 'webhook returned 300'],
            ApprovalChannels::webhookApprovalChannel('https://h', self::recorder($calls, ['ok' => false, 'status' => 300]))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'webhook transport error'],
            ApprovalChannels::webhookApprovalChannel('https://h', self::recorder($calls, new \RuntimeException('')))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'gone'],
            ApprovalChannels::webhookApprovalChannel('https://h', self::recorder($calls, new \RuntimeException('gone')))->notify($r));
        $this->assertSame($base + ['delivered' => false, 'reason' => 'webhook channel not configured'], ApprovalChannels::webhookApprovalChannel(null)->notify($r));
        $this->assertSame([false, false, true], [ApprovalChannels::webhookApprovalChannel(null)->enabled, ApprovalChannels::webhookApprovalChannel('')->enabled,
            ApprovalChannels::webhookApprovalChannel('x')->enabled]);
    }

    /** Every text-channel outcome, exactly. */
    public function testTextOutcomes(): void
    {
        $r = self::request();
        $body = ApprovalChannels::buildTextBody($r);
        $this->assertSame(['kind' => 'sms', 'requestId' => 'su_1', 'payload' => $body, 'delivered' => false, 'reason' => 'sms channel not configured'],
            ApprovalChannels::textApprovalChannel('sms')->notify($r));
        $this->assertSame(['kind' => 'push', 'requestId' => 'su_1', 'payload' => $body, 'delivered' => false, 'reason' => 'push send error'],
            ApprovalChannels::textApprovalChannel('push', static fn() => throw new \RuntimeException(''))->notify($r));
        $this->assertSame(['kind' => 'email', 'requestId' => 'su_1', 'payload' => $body, 'delivered' => false, 'reason' => 'bounced'],
            ApprovalChannels::textApprovalChannel('email', static fn() => throw new \RuntimeException('bounced'))->notify($r));
    }

    // ---- the default transport, against a local child server ------------------------------------------------------------

    /** Child server: prints its port, then for each canned response reads one full request, prints it (base64, one line) and answers. */
    private const SERVER = <<<'SRV'
$s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($s === false) {
    fwrite(STDERR, $errstr);
    exit(1);
}
$name = (string) stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, (int) strrpos($name, ':') + 1) . "\n");
fflush(STDOUT);
foreach ($responses as $resp) {
    $c = @stream_socket_accept($s, 30);
    if ($c === false) {
        break;
    }
    $req = '';
    while (!str_contains($req, "\r\n\r\n")) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    $want = preg_match('/\r\ncontent-length:\s*(\d+)/i', $req, $m) === 1 ? (int) $m[1] : 0;
    while (strlen($req) - (strpos($req, "\r\n\r\n") + 4) < $want) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    fwrite(STDOUT, base64_encode($req) . "\n");
    fflush(STDOUT);
    fwrite($c, $resp);
    fclose($c);
}
SRV;

    /** @return array{0:resource,1:array,2:int} */
    private static function serve(array $responses): array
    {
        $code = '$responses = ' . var_export($responses, true) . ";\n" . self::SERVER;
        $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        $port = (int) trim((string) fgets($pipes[1]));
        self::assertGreaterThan(0, $port);
        return [$p, $pipes, $port];
    }

    private static function stop(array $srv): void
    {
        proc_terminate($srv[0]);
        fclose($srv[1][1]);
        fclose($srv[1][2]);
        proc_close($srv[0]);
    }

    private static function resp(string $statusLine, string $extra = ''): string
    {
        return "$statusLine\r\n{$extra}Content-Length: 0\r\nConnection: close\r\n\r\n";
    }

    /**
     * The default transport POSTs the JSON with every header, reads the status from the status line only (never a header that looks like one),
     * delivers on exactly 200..299, never follows a redirect, and reads an unparseable status as 0.
     */
    public function testDefaultTransport(): void
    {
        $srv = self::serve([
            self::resp('HTTP/1.1 200 OK'),
            self::resp('HTTP/1.1 299 Fine'),
            self::resp('HTTP/1.1 300 Multiple'),
            self::resp('HTTP/1.1 500 Bad', "X-Note: HTTP/1.1 204 ok\r\n"),
            self::resp('HTTP/1.1 20 Short'),
            self::resp('HTTP/1.1 302 Found', "Location: /next\r\n"),
            self::resp('HTTP/1.1 200 OK'),
        ]);
        $r = self::request();
        $out = [];
        $reqs = [];
        try {
            $hook = ApprovalChannels::webhookApprovalChannel("http://127.0.0.1:{$srv[2]}/hook", null, ['x-sig' => 'abc', 'x-two' => '2']);
            for ($i = 0; $i < 6; $i++) {
                $d = $hook->notify($r);
                $out[] = [$d['delivered'], $d['status'] ?? null, $d['reason'] ?? null];
                $reqs[] = (string) base64_decode(trim((string) fgets($srv[1][1])), true);
            }
        } finally {
            self::stop($srv);
        }
        $this->assertSame([[true, 200, null], [true, 299, null], [false, 300, 'webhook returned 300'], [false, 500, 'webhook returned 500'],
            [false, 0, 'webhook returned 0'], [false, 302, 'webhook returned 302']], $out);
        $body = Js::stringify(Sign::n(ApprovalChannels::buildWebhookBody($r)));
        $head = explode("\r\n", explode("\r\n\r\n", $reqs[0])[0]);
        $this->assertMatchesRegularExpression('#^POST /hook HTTP/1\.[01]$#', $head[0]);
        $this->assertContains('content-type: application/json', $head);
        $this->assertContains('x-sig: abc', $head);
        $this->assertContains('x-two: 2', $head);
        $this->assertStringEndsWith("\r\n\r\n" . $body, $reqs[0]);
    }

    /** A refused connection is undelivered with status 0. */
    public function testDefaultTransportRefused(): void
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        $this->assertIsResource($s);
        $name = (string) stream_socket_get_name($s, false);
        fclose($s);
        $port = (int) substr($name, (int) strrpos($name, ':') + 1);
        $d = ApprovalChannels::slackApprovalChannel("http://127.0.0.1:$port/")->notify(self::request());
        $this->assertSame([false, 0, 'slack webhook returned 0'], [$d['delivered'], $d['status'], $d['reason']]);
    }
}
