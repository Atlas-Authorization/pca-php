<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Approvals.php';
require_once __DIR__ . '/Approval.php';

/**
 * Approval-notification channels for PCA step-ups (approval-channels.ts). {@see Approvals} is the HEADLESS core; this is the channel layer: given a
 * pending step-up request (an array from {@see Approvals::reviewAction}, carrying its goal lineage) each channel FORMATS a human-readable notification
 * (action summary, the "because you asked to ..." lineage, an approve / deny affordance or a link to the inbox) and DISPATCHES it over an injected
 * transport. A channel only REPORTS a step-up the verifier already produced; it authorizes nothing. An unconfigured channel is `enabled: false` and
 * never dispatches; a delivery never carries the webhook URL, token or signing secret.
 *
 * Transport: `callable(string $url, array{method:string,headers:array<string,string>,body:string}): array{ok:bool,status:int}`; the default is a plain
 * HTTP request with a 5 second timeout that follows no redirect.
 */
final class ApprovalChannels
{
    /** Seconds the default transport waits for the webhook. */
    public const HTTP_TIMEOUT_S = 5;

    /** One-line action summary: `verb on resource (tier N, risk R)`. @param array<string,mixed> $request */
    public static function actionSummary(array $request): string
    {
        return $request['verb'] . ' on ' . $request['resource'] . ' (tier ' . $request['tier'] . ', risk ' . number_format((float)$request['r'], 2, '.', '') . ')';
    }

    /**
     * The goal-lineage lines a human reads to understand WHY: the "because you asked to ..." sentence, then the goal, authority, action chain, then
     * the canonical render lines when the request carries one.
     * @param array<string,mixed> $request
     * @return list<string>
     */
    public static function lineageLines(array $request): array
    {
        return array_merge([$request['lineage']['because']], Approvals::describeGoalLineage($request['lineage']), self::renderLines($request));
    }

    /**
     * K7: the canonical render, one line per field (nothing omitted), the banner for an unreviewed action, and the speakable binding words of H(R).
     * Empty when the request carries no render.
     * @param array<string,mixed> $request
     * @return list<string>
     */
    public static function renderLines(array $request): array
    {
        $r = $request['render'] ?? null;
        if (!($r instanceof Obj) || !isset($request['renderDigest'])) {
            return [];
        }
        $out = [];
        if ($r->get('unreviewed') === true) {
            $out[] = 'UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.';
        }
        foreach ($r->get('fields') as $f) {
            $u = $f->get('unit');
            $unit = $u instanceof Obj && $u->get('kind') === 'money' ? ' ' . $u->get('ccy') . ' (minor units, exponent ' . Js::str($u->get('exp')) . ')' : '';
            $json = preg_replace_callback('/[\p{Cc}\p{Cf}\x{2028}\x{2029}]/u', static fn(array $m): string => '\\u{' . dechex(mb_ord($m[0], 'UTF-8')) . '}', Js::stringify($f->get('value'))) ?? '';
            $out[] = $f->get('id') . ' [' . $f->get('class') . ']: ' . $json . $unit;
        }
        $out[] = 'Match code: ' . Approval::bindingWords($request['renderDigest']);
        return $out;
    }

    /** Add query parameters before any `#fragment` (an approval link may carry its token in the fragment, which must stay last). @param array<string,string> $params */
    private static function appendQuery(string $url, array $params): string
    {
        $q = [];
        foreach ($params as $k => $v) {
            $q[] = Js::encodeURIComponent((string)$k) . '=' . Js::encodeURIComponent($v);
        }
        $hash = strpos($url, '#');
        $base = $hash === false ? $url : substr($url, 0, $hash);
        $fragment = $hash === false ? '' : substr($url, $hash);
        return $base . (str_contains($base, '?') ? '&' : '?') . implode('&', $q) . $fragment;
    }

    private static function inbox(array $ctx): ?string
    {
        $u = $ctx['inboxUrl'] ?? null;
        return is_string($u) && $u !== '' ? $u : null;
    }

    /**
     * The Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance. `$ctx`: `inboxUrl`.
     * @param array<string,mixed> $request
     * @param array<string,mixed> $ctx
     * @return array{text:string,blocks:list<array<string,mixed>>}
     */
    public static function buildSlackMessage(array $request, array $ctx = []): array
    {
        $blocks = [
            ['type' => 'header', 'text' => ['type' => 'plain_text', 'text' => 'Approval needed · tier ' . $request['tier'], 'emoji' => true]],
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => '*' . $request['verb'] . '* on `' . $request['resource'] . "`\n_" . $request['reason'] . '_']],
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => "*Why this is requested*\n" . implode("\n", array_map(static fn(string $l): string => "• $l", self::lineageLines($request)))]],
        ];
        $inbox = self::inbox($ctx);
        if ($inbox !== null) {
            $blocks[] = ['type' => 'actions', 'elements' => [
                ['type' => 'button', 'text' => ['type' => 'plain_text', 'text' => 'Approve', 'emoji' => true], 'url' => self::appendQuery($inbox, ['stepup' => $request['id'], 'decision' => 'approve']),
                    'style' => 'primary', 'action_id' => 'pca_approve'],
                ['type' => 'button', 'text' => ['type' => 'plain_text', 'text' => 'Deny', 'emoji' => true], 'url' => self::appendQuery($inbox, ['stepup' => $request['id'], 'decision' => 'deny']),
                    'style' => 'danger', 'action_id' => 'pca_deny'],
            ]];
        } else {
            $blocks[] = ['type' => 'context', 'elements' => [['type' => 'mrkdwn', 'text' => 'Approve or deny step-up `' . $request['id'] . '` in your Atlas inbox.']]];
        }
        return ['text' => 'Approval needed: ' . self::actionSummary($request), 'blocks' => $blocks];
    }

    /**
     * The webhook JSON body: the step-up plus its pre-formatted human summary and lineage.
     * @param array<string,mixed> $request
     * @param array<string,mixed> $ctx
     * @return array<string,mixed>
     */
    public static function buildWebhookBody(array $request, array $ctx = []): array
    {
        $b = ['type' => 'pca.step_up.created', 'stepup' => $request, 'summary' => self::actionSummary($request), 'lineage' => self::lineageLines($request)];
        $inbox = self::inbox($ctx);
        return $inbox !== null ? $b + ['inbox_url' => $inbox] : $b;
    }

    /**
     * The plain-text body (subject and text) shared by the email / sms / push surfaces.
     * @param array<string,mixed> $request
     * @param array<string,mixed> $ctx
     * @return array{subject:string,text:string}
     */
    public static function buildTextBody(array $request, array $ctx = []): array
    {
        $lines = array_merge([self::actionSummary($request), ''], self::lineageLines($request));
        $inbox = self::inbox($ctx);
        if ($inbox !== null) {
            array_push($lines, '', 'Approve or deny: ' . self::appendQuery($inbox, ['stepup' => $request['id']]));
        }
        return ['subject' => 'Approval needed: ' . $request['verb'] . ' on ' . $request['resource'], 'text' => implode("\n", $lines)];
    }

    /** @return \Closure(string,array):array{ok:bool,status:int} */
    private static function defaultFetch(): \Closure
    {
        return static function (string $url, array $init): array {
            $headers = [];
            foreach ($init['headers'] as $k => $v) {
                $headers[] = "$k: $v";
            }
            $ctx = stream_context_create(['http' => ['method' => $init['method'], 'header' => implode("\r\n", $headers), 'content' => $init['body'], 'timeout' => self::HTTP_TIMEOUT_S,
                'follow_location' => 0, 'ignore_errors' => true]]);
            $body = @file_get_contents($url, false, $ctx);
            $status = 0;
            foreach (function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []) as $h) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m) === 1) {
                    $status = (int)$m[1];
                }
            }
            return ['ok' => $body !== false && $status >= 200 && $status < 300, 'status' => $status];
        };
    }

    /** Slack incoming-webhook channel. Disabled (and a no-op) unless a webhook URL is configured. @param ?callable $fetch the transport */
    public static function slackApprovalChannel(?string $webhookUrl = null, ?callable $fetch = null): ApprovalChannel
    {
        $enabled = is_string($webhookUrl) && $webhookUrl !== '';
        $transport = $fetch ?? self::defaultFetch();
        return new ApprovalChannel('slack', $enabled, static function (array $request, array $ctx) use ($enabled, $webhookUrl, $transport): array {
            $message = self::buildSlackMessage($request, $ctx);
            $base = ['kind' => 'slack', 'requestId' => $request['id'], 'payload' => $message];
            if (!$enabled) {
                return $base + ['delivered' => false, 'reason' => 'slack channel not configured'];
            }
            try {
                $res = $transport($webhookUrl, ['method' => 'POST', 'headers' => ['content-type' => 'application/json'], 'body' => Js::stringify(Sign::n($message))]);
                return $res['ok'] ? $base + ['delivered' => true, 'status' => $res['status']]
                    : $base + ['delivered' => false, 'status' => $res['status'], 'reason' => 'slack webhook returned ' . $res['status']];
            } catch (\Throwable $e) {
                return $base + ['delivered' => false, 'reason' => $e->getMessage() !== '' ? $e->getMessage() : 'slack transport error'];
            }
        });
    }

    /** Generic signed-JSON webhook channel (the one Slack mirrors). `$headers` are extra request headers (never logged). @param array<string,string> $headers */
    public static function webhookApprovalChannel(?string $url = null, ?callable $fetch = null, array $headers = []): ApprovalChannel
    {
        $enabled = is_string($url) && $url !== '';
        $transport = $fetch ?? self::defaultFetch();
        $hdr = ['content-type' => 'application/json'] + $headers;
        return new ApprovalChannel('webhook', $enabled, static function (array $request, array $ctx) use ($enabled, $url, $transport, $hdr): array {
            $body = self::buildWebhookBody($request, $ctx);
            $base = ['kind' => 'webhook', 'requestId' => $request['id'], 'payload' => $body];
            if (!$enabled) {
                return $base + ['delivered' => false, 'reason' => 'webhook channel not configured'];
            }
            try {
                $res = $transport($url, ['method' => 'POST', 'headers' => $hdr, 'body' => Js::stringify(Sign::n($body))]);
                return $res['ok'] ? $base + ['delivered' => true, 'status' => $res['status']]
                    : $base + ['delivered' => false, 'status' => $res['status'], 'reason' => 'webhook returned ' . $res['status']];
            } catch (\Throwable $e) {
                return $base + ['delivered' => false, 'reason' => $e->getMessage() !== '' ? $e->getMessage() : 'webhook transport error'];
            }
        });
    }

    /**
     * A text-formatter channel (`email`, `sms` or `push`) over an injected sender `callable(array{subject:string,text:string}): mixed`; no sender
     * means disabled.
     */
    public static function textApprovalChannel(string $kind, ?callable $send = null): ApprovalChannel
    {
        if (!in_array($kind, ['email', 'sms', 'push'], true)) {
            throw new \InvalidArgumentException("textApprovalChannel: kind is email, sms or push, not '$kind'");
        }
        $enabled = $send !== null;
        return new ApprovalChannel($kind, $enabled, static function (array $request, array $ctx) use ($kind, $enabled, $send): array {
            $body = self::buildTextBody($request, $ctx);
            $base = ['kind' => $kind, 'requestId' => $request['id'], 'payload' => $body];
            if (!$enabled) {
                return $base + ['delivered' => false, 'reason' => "$kind channel not configured"];
            }
            try {
                $send($body);
                return $base + ['delivered' => true];
            } catch (\Throwable $e) {
                return $base + ['delivered' => false, 'reason' => $e->getMessage() !== '' ? $e->getMessage() : "$kind send error"];
            }
        });
    }

    /** Register a set of channels behind one dispatcher. Disabled channels are skipped at `notifyAll`. @param list<ApprovalChannel> $channels */
    public static function createApprovalDispatcher(array $channels): ApprovalDispatcher
    {
        return new ApprovalDispatcher($channels);
    }
}

/** The common channel contract: `kind`, whether it is configured enough to deliver (`enabled`), and `notify` (never throws). */
final class ApprovalChannel
{
    /** @param \Closure(array,array):array $deliver */
    public function __construct(public readonly string $kind, public readonly bool $enabled, private readonly \Closure $deliver)
    {
    }

    /**
     * Format the step-up for this channel and dispatch it. Returns the outcome `['kind', 'requestId', 'delivered', 'payload', 'status'?, 'reason'?]`.
     * @param array<string,mixed> $request
     * @param array<string,mixed> $ctx `inboxUrl`
     * @return array<string,mixed>
     */
    public function notify(array $request, array $ctx = []): array
    {
        return ($this->deliver)($request, $ctx);
    }
}

/** One dispatcher over many channels. */
final class ApprovalDispatcher
{
    /** @param list<ApprovalChannel> $channels */
    public function __construct(public readonly array $channels)
    {
    }

    /** Fan a step-up out to every ENABLED channel; one delivery per channel. @param array<string,mixed> $request @param array<string,mixed> $ctx @return list<array<string,mixed>> */
    public function notifyAll(array $request, array $ctx = []): array
    {
        $out = [];
        foreach ($this->channels as $c) {
            if ($c->enabled) {
                $out[] = $c->notify($request, $ctx);
            }
        }
        return $out;
    }
}
