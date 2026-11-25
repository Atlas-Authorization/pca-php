<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletCard.php';

/** One delivery channel: `kind`, `enabled` and `notify(notice) -> delivery`. */
final class QuestionChannel
{
    /** @param \Closure(mixed):Obj $notifyFn */
    public function __construct(public readonly string $kind, public readonly bool $enabled, private readonly \Closure $notifyFn)
    {
    }

    public function notify(mixed $notice): Obj
    {
        return ($this->notifyFn)($notice);
    }
}

/** Fan a notice out to every enabled channel (disabled channels are skipped). */
final class QuestionDispatcher
{
    /** @param list<QuestionChannel> $channels */
    public function __construct(public readonly array $channels)
    {
    }

    /** @return list<Obj> */
    public function notifyAll(mixed $notice): array
    {
        $out = [];
        foreach ($this->channels as $c) {
            if ($c->enabled) {
                $out[] = $c->notify($notice);
            }
        }
        return $out;
    }
}

/**
 * Question delivery over the existing approval-channel transports (a webhook with an injected fetch, and email / sms / push through an
 * injected sender). A delivery only tells the principal's device that a question is waiting and hands it the SIGNED question: never a
 * rendered card, agent text, the map or p. Text surfaces use one fixed template. The transports are injected sync Closures:
 * `fetch(url, init) -> ['ok' => bool, 'status' => int]` (init is an Obj {method, headers, body}) and `send(Obj {subject, text})`; with no
 * fetch configured a webhook delivery reports "no fetch available" instead of touching the network.
 */
final class WalletDelivery
{
    /** A notice for a site-signed question. Throws when the signature or expiry does not verify (nothing unsigned leaves). */
    public static function siteQuestionNotice(mixed $ir, mixed $ctx): Obj
    {
        $v = IntentV2::verifyIntentRequired($ir, Js::opt($ctx, 'keys'), Js::opt($ctx, 'now'));
        if (!$v['ok']) {
            throw new \InvalidArgumentException('siteQuestionNotice: ' . ($v['reason'] ?? ''));
        }
        $out = Obj::of(['type' => 'pca.intent.question', 'session' => Wallet::req($ir, 'session'), 'question_id' => Wallet::req($ir, 'question_id'),
            'site' => Js::opt($ctx, 'site'), 'friction' => Wallet::req($ir, 'friction'), 'expires_at' => Wallet::req($ir, 'expires_at'), 'intent_required' => $ir]);
        $inbox = Js::opt($ctx, 'inboxUrl');
        if (Jsx::truthy($inbox)) {
            $out->set('inbox_url', $inbox);
        }
        return $out;
    }

    /** A notice for a wallet-originated question (clarification): ids only. */
    public static function clarificationNotice(mixed $session, mixed $questionId, mixed $inboxUrl = null): Obj
    {
        $out = Obj::of(['type' => 'pca.intent.clarification', 'session' => $session, 'question_id' => $questionId]);
        if (Jsx::truthy($inboxUrl)) {
            $out->set('inbox_url', $inboxUrl);
        }
        return $out;
    }

    /** The fixed text of a text-surface notice: Obj {subject, text}. */
    public static function questionText(mixed $notice, mixed $siteName): Obj
    {
        $isQ = Wallet::req($notice, 'type') === 'pca.intent.question';
        if ($isQ) {
            $who = WalletCard::cleanText($siteName, 64);
            $who = $who === '' ? 'A site' : $who;
        } else {
            $who = 'Your agent';
        }
        $subject = $isQ ? "$who has a question about your request" : "$who needs a decision about your request";
        $inbox = Js::opt($notice, 'inbox_url');
        $link = null;
        if (Jsx::truthy($inbox)) {
            if (!is_string($inbox)) {
                throw new \TypeError('inbox_url must be a string');
            }
            $qid = Wallet::req($notice, 'question_id');
            if (!is_string($qid)) {
                throw new \TypeError('question_id must be a string');
            }
            $link = $inbox . (str_contains($inbox, '?') ? '&' : '?') . 'question=' . Js::encodeURIComponent($qid);
        }
        return Obj::of(['subject' => $subject, 'text' => implode("\n", [$subject, '', $link !== null ? "Open your wallet to answer: $link" : 'Open your wallet to answer.'])]);
    }

    /**
     * Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included.
     * `$config`: url, headers (Obj / assoc), fetch (Closure).
     */
    public static function webhookChannel(mixed $config = null): QuestionChannel
    {
        $url = Js::opt($config, 'url');
        $enabled = is_string($url) && $url !== '';
        $fetch = Js::opt($config, 'fetch');
        $transport = $fetch instanceof \Closure ? $fetch : static function (mixed $u, mixed $init): never {
            throw new \RuntimeException('no fetch available: pass a FetchLike transport');
        };
        $headers = Obj::of(['content-type' => 'application/json']);
        $extra = Js::opt($config, 'headers');
        if (Jsx::truthy($extra)) {
            foreach (Wallet::entries($extra) as [$k, $v]) {
                $headers->set($k, $v);
            }
        }
        $notify = static function (mixed $notice) use ($enabled, $url, $transport, $headers): Obj {
            $base = Obj::of(['kind' => 'webhook', 'questionId' => Wallet::req($notice, 'question_id'), 'payload' => $notice]);
            $put = static function (array $more) use ($base): Obj {
                $o = new Obj();
                foreach ($base->keys() as $k) {
                    $o->set($k, $base->get($k));
                }
                foreach ($more as $k => $v) {
                    $o->set((string)$k, $v);
                }
                return $o;
            };
            if (!$enabled || $url === null) {
                return $put(['delivered' => false, 'reason' => 'webhook channel not configured']);
            }
            try {
                $res = $transport($url, Obj::of(['method' => 'POST', 'headers' => $headers, 'body' => Js::stringify($notice)]));
                $status = Js::opt($res, 'status');
                if (Jsx::truthy(Js::opt($res, 'ok'))) {
                    return $put(['delivered' => true, 'status' => $status]);
                }
                return $put(['delivered' => false, 'status' => $status, 'reason' => 'webhook returned ' . Jsx::str($status)]);
            } catch (\Throwable $err) { // a transport failure is a failed delivery, not an exception
                $m = $err->getMessage();
                return $put(['delivered' => false, 'reason' => $m !== '' ? $m : 'webhook transport error']);
            }
        };
        return new QuestionChannel('webhook', $enabled, $notify);
    }

    /** Email / SMS / push delivery through the per-instance sender port (fixed text only). `$config`: siteName, send (Closure(Obj)). */
    public static function textChannel(string $kind, mixed $config): QuestionChannel
    {
        $send = Js::opt($config, 'send');
        $enabled = $send instanceof \Closure;
        $notify = static function (mixed $notice) use ($kind, $config, $send, $enabled): Obj {
            $body = self::questionText($notice, Wallet::req($config, 'siteName'));
            $base = ['kind' => $kind, 'questionId' => Wallet::req($notice, 'question_id'), 'payload' => $body];
            if (!$enabled) {
                return Obj::of($base + ['delivered' => false, 'reason' => "$kind channel not configured"]);
            }
            try {
                $send($body);
                return Obj::of($base + ['delivered' => true]);
            } catch (\Throwable $err) {
                $m = $err->getMessage();
                return Obj::of($base + ['delivered' => false, 'reason' => $m !== '' ? $m : "$kind send error"]);
            }
        };
        return new QuestionChannel($kind, $enabled, $notify);
    }

    /** @param list<QuestionChannel> $channels */
    public static function createQuestionDispatcher(array $channels): QuestionDispatcher
    {
        return new QuestionDispatcher($channels);
    }
}

/**
 * Framework-neutral handlers for the two wallet endpoints named in the session root: the question endpoint (a site delivers, or an
 * agent relays unchanged, a site-signed intent_required plus the raw action) and the clarification endpoint. The HTTP routes live with
 * the session store of the host; these Closures are what such a route calls, so the wire behaviour is fixed here. Neither response
 * carries p or any map content. Each handler returns ['status' => int, 'body' => Obj].
 */
final class WalletHandlers
{
    private const STATUS_OF_REFUSAL = [
        'bad_site_signature' => 401, 'wrong_session' => 409, 'stale_map' => 409, 'action_mismatch' => 422, 'cell_mismatch' => 422, 'not_uncertain' => 409,
        'already_asked' => 409, 'frozen' => 429, 'cap_session' => 429, 'cap_hour' => 429, 'cell_too_large' => 422, 'bad_request' => 400, 'render_failed' => 422,
    ];

    private static function actionOf(mixed $v): ?Obj
    {
        if (!Wallet::isObj($v) || !is_string(Js::opt($v, 'verb')) || !is_string(Js::opt($v, 'resource')) || !is_string(Js::opt($v, 'reversibility_class'))
            || !Wallet::isObj(Js::opt($v, 'params'))) {
            return null;
        }
        foreach (Wallet::dictKeys($v) as $k) {
            if (!in_array($k, ['verb', 'resource', 'params', 'reversibility_class'], true)) {
                return null;
            }
        }
        return Obj::of(['verb' => Js::opt($v, 'verb'), 'resource' => Js::opt($v, 'resource'), 'params' => Js::opt($v, 'params'),
            'reversibility_class' => Js::opt($v, 'reversibility_class')]);
    }

    private static function reply(int $status, array $body): array
    {
        return ['status' => $status, 'body' => Obj::of($body)];
    }

    /**
     * The question endpoint. @param \Closure(mixed):?WalletChannel $resolve @return \Closure(mixed, mixed):array{status:int,body:Obj}
     */
    public static function questionHandler(\Closure $resolve): \Closure
    {
        return static function (mixed $sessionId, mixed $body) use ($resolve): array {
            $ch = $resolve($sessionId);
            if ($ch === null) {
                return self::reply(404, ['error' => 'unknown_session']);
            }
            if (!Wallet::isObj($body)) {
                return self::reply(400, ['error' => 'bad_request']);
            }
            foreach (Wallet::dictKeys($body) as $k) {
                if ($k !== 'intent_required' && $k !== 'action') {
                    return self::reply(400, ['error' => 'bad_request', 'detail' => "unknown member \"$k\""]);
                }
            }
            $action = self::actionOf(Js::opt($body, 'action'));
            if ($action === null || !Wallet::isObj(Js::opt($body, 'intent_required'))) {
                return self::reply(400, ['error' => 'bad_request']);
            }
            $r = $ch->receive(Js::opt($body, 'intent_required'), Obj::of(['action' => $action]));
            if ($r['ok']) {
                return self::reply(202, ['question_id' => $r['questionId'], 'friction' => $r['friction']]);
            }
            return self::reply(self::STATUS_OF_REFUSAL[$r['code']] ?? 400, ['error' => $r['code']]);
        };
    }

    /** The clarification endpoint. @param \Closure(mixed):?WalletChannel $resolve @return \Closure(mixed, mixed):array{status:int,body:Obj} */
    public static function clarifyHandler(\Closure $resolve): \Closure
    {
        return static function (mixed $sessionId, mixed $body) use ($resolve): array {
            $ch = $resolve($sessionId);
            if ($ch === null) {
                return self::reply(404, ['error' => 'unknown_session']);
            }
            $r = $ch->clarify($body);
            if (($r['error'] ?? null) !== null) {
                return self::reply(400, ['error' => 'bad_request', 'detail' => $r['error']]);
            }
            $out = ['verdicts' => $r['verdicts']];
            if (($r['questionId'] ?? null) !== null) {
                $out['question_id'] = $r['questionId'];
            }
            if (($r['refused'] ?? null) !== null) {
                $out['refused'] = $r['refused'];
            }
            return self::reply($r['status'], $out);
        };
    }
}
