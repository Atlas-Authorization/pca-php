<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/UndoCoordinator.php';

require_once __DIR__ . '/UndoStore.php';
require_once __DIR__ . '/ApprovalChannels.php';

/**
 * The undo-coordinator support of server/undo.ts: the veto relay over a hosted ledger, the completeness check of a coordinator configuration, the
 * effect report, the notifier over the approval channels and the signer's public key. A coordinator is any object with `recordEffect(id, result)`,
 * `abort(id, reason)` and `get(id)` (the TypeScript `createUndoCoordinator`, or yours).
 */
final class UndoServer
{
    /** With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands). */
    public const UNDO_RELAY_GRACE_MS = 60000;

    /**
     * Build the undo-window coordinator (admission, the durable ledger, the one-click veto, the real rollback): see {@see UndoCoordinatorFactory::create} for the
     * options. Throws UndoError `config` for a missing component and `not_durable` for a volatile store.
     *
     * @param array<string,mixed> $o
     */
    public static function createUndoCoordinator(array $o): UndoCoordinator
    {
        return UndoCoordinatorFactory::create($o);
    }

    /** The undo service key's public half (base64url), for verifying tokens and receipts elsewhere. `$key` is the KeyPair or its 32-byte seed. */
    public static function undoSignerPublic(KeyPair|string $key): string
    {
        return ($key instanceof KeyPair ? $key : new KeyPair($key))->public;
    }

    /**
     * Names of the required components a coordinator configuration lacks (empty = complete): store, engine, signerSecret, audience, resolveGrant,
     * compensate, operations, notifier, alert.
     * @param array<string,mixed>|null $o
     * @return list<string>
     */
    public static function missingUndoComponents(?array $o): array
    {
        $x = $o ?? [];
        $m = [];
        if (!UndoStores::isUndoStore($x['store'] ?? null)) {
            $m[] = 'store';
        }
        $engine = $x['engine'] ?? null;
        if (!is_object($engine) || !is_callable([$engine, 'plan'])) {
            $m[] = 'engine';
        }
        $sk = $x['signerSecret'] ?? null;
        if (!($sk instanceof KeyPair) && !(is_string($sk) && strlen($sk) === 32)) {
            $m[] = 'signerSecret';
        }
        if (!is_string($x['audience'] ?? null) || $x['audience'] === '') {
            $m[] = 'audience';
        }
        if (!is_callable($x['resolveGrant'] ?? null)) {
            $m[] = 'resolveGrant';
        }
        if (!is_callable($x['compensate'] ?? null)) {
            $m[] = 'compensate';
        }
        $ops = $x['operations'] ?? null;
        if (!is_object($ops) || !is_callable([$ops, 'create']) || !is_callable([$ops, 'get']) || !is_callable([$ops, 'transition'])) {
            $m[] = 'operations';
        }
        $n = $x['notifier'] ?? null;
        if (!is_object($n) || !is_callable([$n, 'notify'])) {
            $m[] = 'notifier';
        }
        if (!is_callable($x['alert'] ?? null)) {
            $m[] = 'alert';
        }
        return $m;
    }

    /**
     * Report the outcome of executing an allowed `authorize()` result that carries an undo window: a committed effect is recorded (its result names
     * the compensation target), an effect that failed, aborted or was refused aborts the window (nothing to undo; held budget released); a pending
     * or uncertain one is unknown, the window keeps running. `$outcome`: `['status' => string, 'result'? => mixed]`.
     * @param array{status:string,result?:mixed} $outcome
     */
    public static function reportUndoEffect(object $undo, string $id, array $outcome): Obj
    {
        $status = $outcome['status'];
        if ($status === 'committed') {
            return $undo->recordEffect($id, $outcome['result'] ?? null);
        }
        if (in_array($status, ['failed', 'aborted', 'refused'], true)) {
            return $undo->abort($id, "effect_$status");
        }
        $r = $undo->get($id);
        return $r ?? throw new UndoError('invalid', "no undo record $id");
    }

    /**
     * A notifier over the existing approval channels. The notice becomes a step-up-shaped message whose link is the one-click undo URL and whose render is
     * the WYSIWYS render of the action. `$cfg`: `undoUrl` (callable(string $token, string $id): string) and optional `inboxUrl`. The returned object's
     * `notify(array $notice)` resolves with `['delivered' => bool, 'reason'? => string]` and never throws; `$notice`: `kind`, `record` (Obj), `token?`, `render?`.
     * @param array{undoUrl:callable,inboxUrl?:string} $cfg
     */
    public static function undoNotifierFromDispatcher(ApprovalDispatcher $dispatcher, array $cfg): UndoNotifier
    {
        return new UndoNotifier($dispatcher, $cfg);
    }

    /**
     * The veto relay over a hosted undo ledger: `GET {baseUrl}/v1/pca/undo/vetoes` with the instance secret key. Pass `->pending(...)` as the coordinator's
     * relay. A non-2xx answer or a malformed body throws (and so finalizes nothing). `$fetch`: `callable(string $url, array{method:string,headers:array}): array{ok:bool,status:int,body:string}`.
     */
    public static function hostedUndoVetoRelay(string $baseUrl, string $secretKey, ?callable $fetch = null, ?int $limit = null): UndoVetoRelay
    {
        return new UndoVetoRelay(rtrim($baseUrl, '/'), $secretKey, $fetch, $limit);
    }
}

/** See {@see UndoServer::undoNotifierFromDispatcher}. */
final class UndoNotifier
{
    /** @param array{undoUrl:callable,inboxUrl?:string} $cfg */
    public function __construct(private readonly ApprovalDispatcher $dispatcher, private readonly array $cfg)
    {
    }

    /**
     * @param array{kind:string,record:Obj,token?:string,render?:Obj} $n
     * @return array{delivered:bool,reason?:string}
     */
    public function notify(array $n): array
    {
        try {
            $r = $n['record'];
            $act = $r->get('action');
            [$verb, $resource] = [$act->get('verb'), $act->get('resource')];
            $until = gmdate('Y-m-d\TH:i:s', intdiv((int)Js::num($r->get('window_end')), 1000)) . sprintf('.%03dZ', (int)Js::num($r->get('window_end')) % 1000);
            $outcome = $r->get('outcome');
            $reason = match ($n['kind']) {
                'opened' => "Already done: $verb on $resource. You can undo it until $until.",
                'vetoed' => "Undo started for $verb on $resource.",
                'compensated' => "Undone: $verb on $resource.",
                'compensation_failed' => "UNDO FAILED for $verb on $resource: " . ($outcome instanceof Obj && $outcome->get('reason') !== null ? $outcome->get('reason') : 'unknown') . '. An operator has been alerted.',
                'revoked' => "The agent's grant was revoked. $verb on $resource can still be undone until $until.",
                default => "Final: $verb on $resource can no longer be undone.",
            };
            $req = [
                'id' => 'undo:' . $r->get('id') . ':' . $n['kind'], 'verb' => $verb, 'resource' => $resource, 'tier' => 3, 'reason' => $reason, 'goalCommit' => '',
                'lineage' => ['goalCommit' => '', 'goalVerified' => false, 'chain' => [['kind' => 'action', 'label' => "$verb $resource", 'detail' => 'undo: ' . $r->get('compensation')->get('verb')]], 'because' => $reason],
                'r' => 0, 'requestedAt' => (int)Js::num($r->get('opened_at')),
            ];
            if (isset($n['render']) && $r->get('render_digest') !== null) {
                $req += ['render' => $n['render'], 'renderDigest' => $r->get('render_digest')];
            }
            $link = $n['kind'] === 'opened' && isset($n['token']) ? ($this->cfg['undoUrl'])($n['token'], $r->get('id')) : ($this->cfg['inboxUrl'] ?? null);
            $out = $this->dispatcher->notifyAll($req, $link !== null ? ['inboxUrl' => $link] : []);
            foreach ($out as $d) {
                if ($d['delivered'] === true) {
                    return ['delivered' => true];
                }
            }
            return ['delivered' => false, 'reason' => $out === [] ? 'no enabled channel'
                : implode('; ', array_map(static fn(array $d): string => $d['kind'] . ': ' . ($d['reason'] ?? 'not delivered'), $out))];
        } catch (\Throwable $e) {
            return ['delivered' => false, 'reason' => $e->getMessage() !== '' ? $e->getMessage() : 'notify error'];
        }
    }
}

/** See {@see UndoServer::hostedUndoVetoRelay}. */
final class UndoVetoRelay
{
    public function __construct(private readonly string $base, private readonly string $secretKey, private readonly ?\Closure $fetch, private readonly ?int $limit)
    {
    }

    /** @return list<array{id:string,token:string,at:int}> the vetoes the relay holds; throws UndoError when it cannot be read */
    public function pending(): array
    {
        $f = $this->fetch ?? static function (string $url, array $init): array {
            $h = [];
            foreach ($init['headers'] as $k => $v) {
                $h[] = "$k: $v";
            }
            $ctx = stream_context_create(['http' => ['method' => $init['method'], 'header' => implode("\r\n", $h), 'timeout' => 5, 'follow_location' => 0, 'ignore_errors' => true]]);
            $body = @file_get_contents($url, false, $ctx);
            $status = 0;
            foreach (function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []) as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                    $status = (int)$m[1];
                }
            }
            return ['ok' => $body !== false && $status >= 200 && $status < 300, 'status' => $status, 'body' => $body === false ? '' : $body];
        };
        $n = min(200, max(1, (int)($this->limit ?? 200)));
        $res = $f($this->base . '/v1/pca/undo/vetoes?limit=' . $n, ['method' => 'GET', 'headers' => ['authorization' => 'Bearer ' . $this->secretKey, 'accept' => 'application/json']]);
        if (($res['ok'] ?? false) !== true) {
            throw new UndoError('invalid', 'the veto relay answered ' . ($res['status'] ?? 0));
        }
        $body = json_decode((string)($res['body'] ?? ''), true);
        if (!is_array($body) || !isset($body['data']) || !is_array($body['data']) || !array_is_list($body['data'])) {
            throw new UndoError('invalid', 'the veto relay answered without a data list');
        }
        $out = [];
        foreach ($body['data'] as $row) {
            if (!is_array($row) || !is_string($row['record_id'] ?? null) || !is_string($row['veto']['token'] ?? null) || !(is_int($row['veto']['at'] ?? null) || is_float($row['veto']['at'] ?? null))) {
                throw new UndoError('invalid', 'the veto relay answered a malformed entry');
            }
            $out[] = ['id' => $row['record_id'], 'token' => $row['veto']['token'], 'at' => (int)$row['veto']['at']];
        }
        return $out;
    }
}
