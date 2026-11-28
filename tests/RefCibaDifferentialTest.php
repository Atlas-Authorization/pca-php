<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ApprovalStoreError;
use Atlas\Pca\Ciba;
use Atlas\Pca\CibaBroker;
use Atlas\Pca\CibaClient;
use Atlas\Pca\CibaProviderError;
use Atlas\Pca\CibaStoreConformance;
use Atlas\Pca\DurableCibaBroker;
use Atlas\Pca\Js;
use Atlas\Pca\KvApprovalStore;
use Atlas\Pca\MemoryApprovalStore;
use Atlas\Pca\MemoryKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The CIBA on-ramp against the TS reference: test-data/ref-ciba.json.gz (bridge + scripted broker lifecycles) and
 * ref-ciba-java.json.gz (binding message corner cases, broker / KV / client scenarios with scripted clocks and transports).
 * Random auth_req_ids are masked the way each generator masks them (ID, <ID1>.., <NTOKEN>).
 */
final class RefCibaDifferentialTest extends TestCase
{
    /** The generator's default step-up of the bridge corpus lifecycles. */
    private const SU = ['id' => 'su1', 'verb' => 'stripe.payout', 'resource' => 'acct:1', 'params' => ['amount' => 80, 'currency' => 'USD', 'payee' => 'bob'], 'tier' => 3,
        'reason' => 'r', 'goalCommit' => 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq', 'goal' => 'pay suppliers', 'lineage' => [], 'r' => 0.5, 'requestedAt' => 1];
    private const T0 = 1800000000000;

    public static function provide(): array
    {
        return Base::datasets('ref-ciba.json.gz') + Base::datasets('ref-ciba-java.json.gz');
    }

    /** Every string equal to / containing one of `$ids` replaced by its mask. */
    private static function walk(mixed $v, callable $s): mixed
    {
        if (is_string($v)) {
            return $s($v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::walk($v->get($k), $s));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(static fn($x) => self::walk($x, $s), $v);
        }
        return $v;
    }

    private static function stepUp(mixed $su): mixed
    {
        if ($su === null) {
            $o = Obj::of(self::SU);
            $o->set('params', Obj::of(self::SU['params']));
            $o->set('lineage', new Obj());
            return $o;
        }
        return $su;
    }

    /** ciba.mts lifecycle(kind, ops) */
    private static function lifecycle(string $kind, array $ops): array
    {
        $t = 1000000;
        $now = static function () use (&$t): int {
            return $t;
        };
        $b = $kind === 'memory' ? new CibaBroker(['now' => $now, 'onComplete' => static function (): void {
        }]) : new DurableCibaBroker(['store' => new MemoryApprovalStore(), 'now' => $now, 'decisionTtlSec' => 100]);
        $id = null;
        $out = [];
        foreach ($ops as $op) {
            $o = $op->get('op');
            if ($o === 'now') {
                $t = (int)Js::num($op->get('t'));
                $out[] = null;
                continue;
            }
            try {
                $v = match ($o) {
                    'start' => $b->start(self::stepUp($op->get('stepUp')), $op->get('opts')),
                    'poll' => $b->poll((string)$id),
                    'token' => $b->token((string)$id),
                    'resolve' => $b->resolve((string)$id, $op->get('decision'), $op->get('by')),
                    'get' => $b->get((string)$id),
                    'unknown' => match ($op->get('fn')) {
                        'poll' => $b->poll('nope'),
                        'token' => $b->token('nope'),
                        'resolve' => $b->resolve('nope', 'approve', 'x'),
                        default => $b->get('nope'),
                    },
                };
                if ($o === 'start') {
                    $id = $v['auth_req_id'];
                    $v['auth_req_id'] = 'ID';
                }
                $out[] = ['ok' => true, 'value' => self::walk($v, static fn(string $s): string => $id !== null && $s === $id ? 'ID' : $s)];
            } catch (\Throwable) {
                $out[] = ['ok' => false];
            }
        }
        return $out;
    }

    /** ciba-java.mts brokerScenario({kind, opts, steps}) */
    private static function brokerScenario(Obj $s): array
    {
        $clock = self::T0;
        $completes = [];
        $mode = Js::opt($s->get('opts'), 'onComplete');
        $onComplete = $mode === 'record' || $mode === 'throws' ? static function (array $sess) use (&$completes, $mode): void {
            $completes[] = $sess;
            if ($mode === 'throws') {
                throw new \RuntimeException('notifier down');
            }
        } : null;
        $now = static function () use (&$clock): int|float {
            return $clock;
        };
        $kv = null;
        $store = null;
        if ($s->get('kind') === 'memory') {
            $broker = new CibaBroker(['now' => $now, 'onComplete' => $onComplete]);
        } else {
            if ($s->get('kind') === 'durable-kv') {
                $kv = new MemoryKv();
                $store = new KvApprovalStore($kv);
            } else {
                $store = new MemoryApprovalStore();
            }
            $o = ['store' => $store, 'now' => $now, 'onComplete' => $onComplete];
            if (Js::has($s->get('opts'), 'decisionTtlSec')) {
                $o['decisionTtlSec'] = Js::opt($s->get('opts'), 'decisionTtlSec');
            }
            $broker = new DurableCibaBroker($o);
        }
        $ids = [];
        $sub = static function (mixed $x) use (&$ids): mixed {
            if (!is_string($x) || !str_starts_with($x, '$id')) {
                return $x;
            }
            $v = $x === '$id' ? ($ids[count($ids) - 1] ?? null) : ($ids[(int)substr($x, 3) - 1] ?? null);
            return $v ?? $x;
        };
        $trace = [];
        foreach ($s->get('steps') as $st) {
            $entry = ['op' => $st->get('op')];
            try {
                $key = static fn(): string => preg_replace('/\$id/', str_replace(['\\', '$'], ['\\\\', '\\$'], $ids[count($ids) - 1] ?? ''), (string)$st->get('key'), 1);
                $value = match ($st->get('op')) {
                    'start' => $broker->start($st->get('stepUp'), $st->get('opts')),
                    'poll' => $broker->poll(Ciba::jsStr($sub($st->get('id')))),
                    'token' => $broker->token(Ciba::jsStr($sub($st->get('id')))),
                    'resolve' => $broker->resolve(Ciba::jsStr($sub($st->get('id'))), $st->get('decision'), $st->get('by')),
                    'get' => $broker->get(Ciba::jsStr($sub($st->get('id')))),
                    'advance' => $clock += Js::num($st->get('ms')),
                    'storeSet' => (function () use ($store, $key, $st): bool {
                        $k = $key();
                        $cur = $store->get($k);
                        return $store->cas($k, $cur['version'] ?? 0, $st->get('value'));
                    })(),
                    'kvRaw' => (function () use ($kv, $key, $st): bool {
                        $k = $key();
                        return $kv->putIfEquals($k, $kv->get($k), (string)$st->get('raw'));
                    })(),
                };
                if ($st->get('op') === 'start' && !in_array($value['auth_req_id'], $ids, true)) {
                    $ids[] = $value['auth_req_id'];
                }
                $entry['ok'] = true;
                $entry['value'] = $value;
            } catch (\Throwable $e) {
                $entry['ok'] = false;
                $entry['msg'] = $e->getMessage();
                if ($e instanceof ApprovalStoreError) {
                    $entry['code'] = $e->errorCode;
                }
            }
            if ($completes !== []) {
                $entry['complete'] = $completes;
                $completes = [];
            }
            $trace[] = $entry;
        }
        return self::walk($trace, static function (string $x) use ($ids): string {
            foreach ($ids as $i => $id) {
                $x = str_replace($id, '<ID' . ($i + 1) . '>', $x);
            }
            return $x;
        });
    }

    /** ciba-java.mts kvScenario({steps}) */
    private static function kvScenario(Obj $s): array
    {
        $kv = new MemoryKv();
        $store = new KvApprovalStore($kv);
        $trace = [];
        foreach ($s->get('steps') as $st) {
            $k = (string)$st->get('key');
            try {
                $value = match ($st->get('op')) {
                    'get' => $store->get($k),
                    'cas' => $store->cas($k, Js::num($st->get('expected')), $st->get('value')),
                    'kvSet' => $kv->putIfEquals($k, $kv->get($k), (string)$st->get('raw')),
                    'kvGet' => $kv->get($k),
                };
                $trace[] = ['op' => $st->get('op'), 'ok' => true, 'value' => $value];
            } catch (\Throwable $e) {
                $trace[] = ['op' => $st->get('op'), 'ok' => false, 'code' => $e instanceof ApprovalStoreError ? $e->errorCode : 'other'];
            }
        }
        return $trace;
    }

    /** ciba-java.mts clientScenario({cfg, responses, steps}) */
    private static function clientScenario(Obj $s): array
    {
        $clock = self::T0;
        $reqs = [];
        $sleeps = [];
        $queue = $s->get('responses');
        $cfg = [];
        foreach ($s->get('cfg')->keys() as $k) {
            $cfg[$k] = $s->get('cfg')->get($k);
        }
        $cfg['fetch'] = static function (string $url, array $init) use (&$reqs, &$queue): array {
            $reqs[] = ['url' => $url, 'method' => $init['method'], 'headers' => $init['headers'], 'body' => $init['body']];
            $r = array_shift($queue);
            if ($r === null || $r->get('fail') === true) {
                throw new \RuntimeException($r === null ? 'no scripted response' : 'connection reset');
            }
            $b = $r->get('body');
            return ['status' => (int)Js::num($r->get('status')), 'body' => is_string($b) ? $b : Js::stringify($b)];
        };
        $cfg['sleep'] = static function (int|float $ms) use (&$sleeps, &$clock): void {
            $sleeps[] = $ms;
            $clock += $ms;
        };
        $cfg['now'] = static function () use (&$clock): int|float {
            return $clock;
        };
        $client = new CibaClient($cfg);
        $poller = null;
        $trace = [];
        $nt = '';
        foreach ($s->get('steps') as $st) {
            $entry = ['op' => $st->get('op')];
            try {
                switch ($st->get('op')) {
                    case 'initiate':
                        $flow = $client->initiate($st->get('stepUp'), $st->has('opts') ? $st->get('opts') : []);
                        $poller = $client->poller($flow);
                        $value = $flow;
                        if (isset($flow['clientNotificationToken']) && !Js::has($st->get('opts'), 'clientNotificationToken')) {
                            $nt = $flow['clientNotificationToken'];
                        }
                        break;
                    case 'poll':
                        $value = $poller->poll();
                        break;
                    case 'wait':
                        $value = $poller->wait();
                        break;
                    case 'notify':
                        $poller->notify();
                        $value = null;
                        break;
                    case 'advance':
                        $clock += Js::num($st->get('ms'));
                        $value = $clock;
                        break;
                    default:
                        $value = $poller->intervalSec();
                }
                $entry['ok'] = true;
                $entry['value'] = $value;
            } catch (\Throwable $e) {
                $entry['ok'] = false;
                if ($e instanceof CibaProviderError) {
                    $entry += ['error' => $e->error, 'status' => $e->status, 'retryable' => $e->retryable, 'errorDescription' => $e->errorDescription];
                } else {
                    $entry['other'] = true;
                }
            }
            $entry['requests'] = $reqs;
            $entry['sleeps'] = $sleeps;
            $reqs = [];
            $sleeps = [];
            $trace[] = $nt === '' ? $entry : self::walk($entry, static fn(string $x): string => str_replace($nt, '<NTOKEN>', $x));
        }
        return $trace;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'cibaActionFromStepUp' => fn(array $a) => Ciba::cibaActionFromStepUp($a[0] ?? null),
            'asciiForm' => fn(array $a) => Ciba::asciiForm((string)$a[0]),
            'toCibaAuthRequest' => fn(array $a) => Ciba::toCibaAuthRequest($a[0] ?? null, array_key_exists(1, $a) ? $a[1] : []),
            'requiresCiba' => fn(array $a) => Ciba::requiresCiba($a[0] ?? null),
            'cibaDecisionToCosign' => fn(array $a) => Ciba::cibaDecisionToCosign($a[0] ?? null, $a[1] ?? null, $a[2] ?? null, $a[3] ?? null, array_key_exists(4, $a) ? $a[4] : []),
            'verifyPingCallback' => fn(array $a) => Ciba::verifyPingCallback($a[0] ?? null, $a[1] ?? null),
            'createCibaClientConfig' => function (array $a): bool {
                $cfg = ['fetch' => static fn(): array => ['status' => 200, 'body' => '{}']];
                foreach ($a[0]->keys() as $key) {
                    $cfg[$key] = $a[0]->get($key);
                }
                new CibaClient($cfg);
                return true;
            },
            'durableBrokerConfig' => function (array $a): string {
                $c = $a[0];
                try {
                    new DurableCibaBroker($c->get('noStore') === true ? [] : ['store' => new MemoryApprovalStore()] + ($c->has('decisionTtlSec') ? ['decisionTtlSec' => $c->get('decisionTtlSec')] : []));
                    return 'ok';
                } catch (\Throwable) {
                    return 'throws';
                }
            },
            'lifecycle' => fn(array $a) => self::lifecycle((string)$a[0], $a[1]),
            'brokerScenario' => fn(array $a) => self::brokerScenario($a[0]),
            'kvScenario' => fn(array $a) => self::kvScenario($a[0]),
            'clientScenario' => fn(array $a) => self::clientScenario($a[0]),
        ]);
    }

    public function testStoreConformance(): void
    {
        $dir = sys_get_temp_dir() . '/ciba-' . bin2hex(random_bytes(6));
        $n = 0;
        $stores = [
            'memory' => [static fn() => new MemoryApprovalStore(), null],
            'kv' => [static fn() => new KvApprovalStore(new MemoryKv()), null],
            'directory' => [static function () use ($dir, &$n) {
                $n++;
                return new KvApprovalStore(new \Atlas\Pca\DirectoryKv("$dir/$n"));
            }, static function () use ($dir, &$n) { // by reference: an arrow function would freeze $n at 0 and reopen a different, empty directory
                return new KvApprovalStore(new \Atlas\Pca\DirectoryKv("$dir/$n"));
            }],
        ];
        foreach ($stores as $label => [$make, $reopen]) {
            foreach ([...CibaStoreConformance::approvalStoreCases($make, $reopen), ...CibaStoreConformance::approvalBrokerCases($make)] as $c) {
                ($c['run'])();
                $this->addToAssertionCount(1);
            }
        }
    }
}
