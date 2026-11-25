<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\MemoryStreamStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\PollQueue;
use Atlas\Pca\SignalsRevocationState;
use Atlas\Pca\Signals;
use Atlas\Pca\SignalsError;
use Atlas\Pca\SsfManage;
use Atlas\Pca\SsfStream;
use Atlas\Pca\StreamHealth;
use Atlas\Pca\VerificationStream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Shared Signals / CAEP against the TS reference: test-data/ref-signals.json.gz (SET build / verify, revocation state, replay store,
 * receiveSET, standard revocations, authorize() adapters, snapshot / restore, SSF stream config / health / verification / poll / push,
 * the stream management API). The oracle's signer is Ed25519 with a seed derived from a label, so keys are rebuilt here, never stored.
 * Function-valued options cross by NAME and are rebuilt below (mapper / agentOf / replay stores / the management host callbacks).
 *
 * Deliberate native-specific rules (each is a reported equivalence, not a skipped case):
 *  - A verifySET failure the reference reports with a JOSE `code` is rethrown carrying that code, derived from the message the native
 *    JOSE layer shares with the reference; an unusable key (ERR_CRYPTO_INVALID_JWK, a Node KeyObject error) only has to be refused.
 *  - The reference's SET is built with a random jti and the wall clock: compared decoded, jti as "<uuid>", iat as "<now>", plus a
 *    signature check under the public key.
 */
final class RefSignalsDifferentialTest extends TestCase
{
    private const FILE = 'ref-signals.json.gz';
    private const LABEL = 'atlas-pca-conformance/ref-signals/tx';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    // ---- fixtures ------------------------------------------------------------------------------------------------------

    private static function seed(): string
    {
        return hash('sha256', self::LABEL, true);
    }

    private static function pubRaw(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function privJwk(): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u(self::pubRaw()), 'd' => Pca::b64u(self::seed())]);
    }

    private static function pubJwk(): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u(self::pubRaw())]);
    }

    private static function cfg(): Obj
    {
        $g = Signals::EVENT_TYPES['grantRevoked'];
        return Obj::of([
            'stream_id' => 's1', 'iss' => 'https://tx.example', 'aud' => 'rx', 'events_supported' => [$g, Signals::EVENT_TYPES['killSwitch']],
            'events_delivered' => [$g], 'delivery' => Obj::of(['method' => SsfStream::DELIVERY_POLL, 'endpoint_url' => 'https://tx.example/poll/s1']),
            'min_verification_interval' => 30, 'description' => 'd',
        ]);
    }

    // ---- shared mappers ------------------------------------------------------------------------------------------------------

    /** The oracle's error form: {"$err": true} plus the reference's own code when it has one. */
    private static function err(\Throwable $e): array
    {
        return $e instanceof SignalsError ? ['$err' => true, 'code' => $e->errorCode] : ['$err' => true];
    }

    /** @return array<string,mixed> */
    private static function state(SignalsRevocationState $st): array
    {
        return [
            'grants' => array_values($st->revokedGrants), 'agents' => array_values($st->killedAgents),
            'intents' => $st->revokedIntentIds === null ? null : array_values($st->revokedIntentIds),
        ];
    }

    /** A SET as the oracle prints it: header + payload with jti "<uuid>" / a fresh iat "<now>", and whether the signature checks. */
    private static function shape(string $set): array
    {
        [$h, $p, $s] = explode('.', $set);
        $header = (new Parser((string) Pca::unb64u($h), PHP_INT_MAX))->run();
        $payload = (new Parser((string) Pca::unb64u($p), PHP_INT_MAX))->run();
        $iat = $payload->get('iat');
        if (Js::isNum($iat) && (abs((float) Js::num($iat) * 1000 - microtime(true) * 1000) < 120000 || abs((float) Js::num($iat) * 1000 - Base::clockMs(self::FILE)) < 120000)) {
            $payload->set('iat', '<now>');
        }
        $jti = $payload->get('jti');
        if (is_string($jti) && preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $jti) === 1) {
            $payload->set('jti', '<uuid>');
        }
        $sig = Pca::unb64u($s);
        return ['header' => $header, 'payload' => $payload, 'sigOk' => $sig !== null && sodium_crypto_sign_verify_detached($sig, "$h.$p", self::pubRaw())];
    }

    /** The result of verifySET / receiveSET in the oracle's form. @return array<string,mixed> */
    private static function parsedOut(array $r): array
    {
        $o = ['events' => $r['events'], 'iss' => $r['iss'], 'jti' => $r['jti']];
        if (isset($r['sub'])) {
            $o['sub'] = $r['sub'];
        }
        $o['payload'] = $r['payload'];
        return $o;
    }

    /** The JOSE code the reference reports for a native JOSE message (the two layers share the library's messages). */
    private static function joseCode(\Throwable $e): ?string
    {
        $m = $e->getMessage();
        return match (true) {
            $m === 'signature verification failed' => 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
            $m === '"exp" claim timestamp check failed' => 'ERR_JWT_EXPIRED',
            $m === '"alg" (Algorithm) Header Parameter value not allowed' => 'ERR_JOSE_ALG_NOT_ALLOWED',
            $m === 'JWS "alg" (Algorithm) Header Parameter missing or invalid' => 'ERR_JWS_INVALID',
            str_ends_with($m, 'is not recognized') => 'ERR_JOSE_NOT_SUPPORTED',
            str_contains($m, ' claim') || str_starts_with($m, 'unexpected "typ"') => 'ERR_JWT_CLAIM_VALIDATION_FAILED',
            default => null,
        };
    }

    private static function verifySet(array $a, Obj $c): array
    {
        try {
            return self::parsedOut(Signals::verifySET($a[0], $a[1], $a[2] ?? null));
        } catch (\Throwable $e) {
            $want = $c->get('out');
            $code = $want instanceof Obj ? $want->get('code') : null;
            if (is_string($code)) {
                // an unusable key is refused by the runtime's key class; the native only has to refuse it
                $mapped = $code === 'ERR_CRYPTO_INVALID_JWK' ? $code : (self::joseCode($e) ?? 'unmapped');
                throw new SignalsError($mapped, $e->getMessage());
            }
            throw $e;
        }
    }

    // ---- function-valued options, by name ---------------------------------------------------------------------------------

    private static function mapper(string $name): \Closure
    {
        return match ($name) {
            'email' => static fn(mixed $s): ?string => Js::opt($s, 'format') === 'email' && is_string(Js::opt($s, 'email')) ? Js::opt($s, 'email') : null,
            'throws' => static function (mixed $s): never {
                throw new \RuntimeException('x');
            },
            'empty' => static fn(mixed $s): string => '',
            'num' => static fn(mixed $s): int => 5,
            'id' => static fn(mixed $s): ?string => is_string(Js::opt($s, 'id')) ? Js::opt($s, 'id') : null,
            'prefixed' => static fn(mixed $s): ?string => is_string(Js::opt($s, 'id')) ? 'agent:' . Js::opt($s, 'id') : null,
        };
    }

    private static function stdOpts(mixed $sp): ?Obj
    {
        if ($sp === null) {
            return null;
        }
        $o = new Obj();
        $m = Js::opt($sp, 'mapper');
        if ($m !== null && $m !== 'default') {
            $o->set('subjectToAgent', self::mapper($m));
        }
        if (Js::has($sp, 'fail')) {
            $o->set('failOnUnmapped', Js::opt($sp, 'fail'));
        }
        return $o;
    }

    private static function agentOf(mixed $name): ?\Closure
    {
        if ($name === null || $name === 'leaf') {
            return null;
        }
        if (is_string($name) && str_starts_with($name, 'const:')) {
            return static fn(mixed $ctx): string => substr($name, 6);
        }
        return match ($name) {
            'throws' => static function (mixed $ctx): never {
                throw new \RuntimeException('x');
            },
            'empty' => static fn(mixed $ctx): string => '',
            'num' => static fn(mixed $ctx): int => 5,
            'grantId' => static fn(mixed $ctx): mixed => Signals::optProp($ctx['grant'] ?? null, 'id'),
        };
    }

    private static function store(string $kind): object
    {
        return match ($kind) {
            'throws' => new class {
                public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                {
                    throw new \RuntimeException('boom');
                }
            },
            'false' => new class {
                public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                {
                    return false;
                }
            },
            'mem1' => Signals::createInMemorySetReplayStore(Obj::of(['maxEntries' => 1])),
            default => Signals::createInMemorySetReplayStore(),
        };
    }

    // ---- scenarios ---------------------------------------------------------------------------------------------------------------

    private static function stateScenario(Obj $spec): array
    {
        $st = Signals::createRevocationState();
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                $target = Js::truthy($s->get('badState')) ? new Obj() : $st;
                $r = match ($s->get('op')) {
                    'apply' => (static function () use ($st, $s): array {
                        Signals::applySET($st, $s->get('parsed'));
                        return self::state($st);
                    })(),
                    'applyStd' => (static function () use ($st, $target, $s): array {
                        $plan = Signals::applyStandardRevocations($target, $s->get('parsed'), self::stdOpts($s->get('std')));
                        return ['plan' => $plan, 'state' => self::state($st)];
                    })(),
                    'plan' => Signals::planStandardRevocations($s->get('parsed'), self::stdOpts($s->get('std'))),
                    'isRevoked' => Signals::isRevoked($st, $s->get('grant'), $s->get('agent')),
                    'isIntentRevoked' => Signals::isIntentRevoked($st, $s->get('id')),
                    'stream' => self::state(Signals::streamProcessor($s->get('sets'), Js::truthy($s->get('useState')) ? $st : null)),
                    'snapshot' => Signals::snapshotRevocationState($target),
                    'restore' => self::state(
                        Js::truthy($s->get('fresh'))
                            ? Signals::restoreRevocationState($s->get('snapshot'))
                            : Signals::restoreRevocationState($s->get('snapshot'), Js::truthy($s->get('nullInto')) ? null : $target),
                    ),
                    default => throw new \RuntimeException('bad op'),
                };
                $out[] = $r;
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        $out[] = self::state($st);
        return $out;
    }

    private static function replayScenario(Obj $spec): array
    {
        try {
            $store = Signals::createInMemorySetReplayStore($spec->has('opts') ? $spec->get('opts') : new Obj());
        } catch (\Throwable $e) {
            return [self::err($e)];
        }
        $out = [];
        foreach ($spec->get('ops') as [$jti, $exp, $now]) {
            try {
                $out[] = $store->addIfAbsent($jti, $exp, $now);
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        return $out;
    }

    private static function replayConformance(Obj $spec): array
    {
        $kind = $spec->get('store');
        $make = static function () use ($kind, $spec): object {
            return match ($kind) {
                'alwaysTrue' => new class {
                    public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                    {
                        return true;
                    }
                },
                'alwaysFalse' => new class {
                    public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                    {
                        return false;
                    }
                },
                'noExpiry' => new class {
                    /** @var array<string,true> */
                    private array $seen = [];

                    public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                    {
                        if (isset($this->seen['k' . $jti])) {
                            return false;
                        }
                        $this->seen['k' . $jti] = true;
                        return true;
                    }
                },
                default => $spec->has('opts') ? Signals::createInMemorySetReplayStore($spec->get('opts')) : Signals::createInMemorySetReplayStore(),
            };
        };
        return Signals::runSetReplayStoreConformance($make);
    }

    private static function receiveScenario(Obj $spec): array
    {
        $st = Signals::createRevocationState();
        $store = self::store($spec->get('store'));
        $key = self::pubJwk();
        $out = [];
        foreach ($spec->get('deliveries') as $d) {
            $op = new Obj();
            $given = $d->get('opts');
            foreach ($given instanceof Obj ? $given->keys() : [] as $k) {
                $op->set($k, $given->get($k));
            }
            if (!Js::truthy($d->get('noStore'))) {
                $op->set('replayStore', $store);
            }
            if (!Js::truthy($d->get('noState'))) {
                $op->set('state', $st);
            }
            if ($d->has('std')) {
                $op->set('standardRevocations', self::stdOpts($d->get('std')));
            }
            try {
                $r = Signals::receiveSET($d->get('set'), $d->has('key') ? $d->get('key') : $key, Js::truthy($d->get('noOpts')) ? null : $op);
                if ($r['ok'] === false && $r['code'] === 'verify_failed' && !str_starts_with($r['reason'], 'SET invalid:')) {
                    $r['reason'] = '<jose>';
                }
                $out[] = $r['ok'] === true ? ['ok' => true, 'parsed' => self::parsedOut($r['parsed'])] : $r;
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        $out[] = self::state($st);
        return $out;
    }

    private static function adapterScenario(Obj $spec): array
    {
        try {
            $bad = $spec->get('badState');
            $st = Js::truthy($bad)
                ? ($bad === 'null' ? null : new Obj())
                : Signals::restoreRevocationState(Obj::of(['v' => 1, 'grants' => $spec->get('grants') ?? [], 'agents' => $spec->get('agents') ?? [], 'intents' => []]));
            $o = Obj::of(['agentOf' => self::agentOf($spec->get('agentOf'))]);
            $hook = Signals::createRevocationHook($st, $o);
            $isRev = Signals::createIsRevoked($st, $o);
        } catch (\Throwable $e) {
            return [self::err($e)];
        }
        $out = [];
        foreach ($spec->get('calls') as $c) {
            try {
                $a = $hook(Obj::of(['pcactn' => $c->get('pcactn'), 'grant' => $c->get('grant')]));
            } catch (\Throwable) {
                $a = ['$err' => true];
            }
            try {
                $b = $isRev($c->get('grant'), $c->get('pcactn'));
            } catch (\Throwable) {
                $b = ['$err' => true];
            }
            $out[] = ['hook' => $a, 'isRevoked' => $b];
        }
        return $out;
    }

    private static function healthScenario(Obj $spec): array
    {
        $h = new StreamHealth($spec->has('config') ? $spec->get('config') : self::cfg(), $spec->get('opts'));
        $issued = [];
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                switch ($s->get('op')) {
                    case 'status':
                        $h->setStatus($s->get('v'));
                        $r = null;
                        break;
                    case 'event':
                        $h->recordEvent($s->get('now'));
                        $r = null;
                        break;
                    case 'request':
                        $r = $h->requestVerification($s->get('now'));
                        if (is_string($r)) {
                            $issued[] = $r;
                            $r = '<state:' . (count($issued) - 1) . '>';
                        }
                        break;
                    case 'ack':
                        $r = $h->ackVerification($s->has('ref') ? ($issued[(int) Js::num($s->get('ref'))] ?? null) : $s->get('state'), $s->get('now'));
                        break;
                    case 'report':
                        $r = $h->report($s->get('now'));
                        break;
                    case 'fresh':
                        $r = $h->revocationFreshWithin($s->get('max'), $s->get('now'));
                        break;
                    default:
                        throw new \RuntimeException('bad op');
                }
                $out[] = $r;
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        return $out;
    }

    private static function verificationScenario(Obj $spec): array
    {
        $streams = [];
        $given = $spec->get('streams');
        foreach ($given instanceof Obj ? $given->keys() : [] as $k) {
            $v = $given->get($k);
            $lv = Js::opt($v, 'lastVerification');
            $streams[$k] = new VerificationStream(Js::opt($v, 'config'), $lv === null ? null : (float) Js::num($lv));
        }
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                $key = Js::truthy($s->get('noKey')) ? null : self::privJwk();
                $r = SsfStream::handleVerificationRequest($streams, $s->get('req'), $s->get('now'), $key);
                if ($r['status'] === 204) {
                    $r = ['status' => 204, 'set' => self::shape($r['set'])];
                }
            } catch (\Throwable) {
                $r = ['$err' => true];
            }
            $out[] = $r;
        }
        $last = [];
        foreach ($streams as $k => $v) {
            $last[$k] = $v->lastVerification;
        }
        $out[] = $last;
        return $out;
    }

    private static function pollScenario(Obj $spec): array
    {
        $q = new PollQueue();
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                if ($s->has('enqueue')) {
                    $q->enqueue($s->get('enqueue')[0], $s->get('enqueue')[1]);
                    $r = null;
                } elseif (Js::truthy($s->get('depth'))) {
                    $r = $q->depth();
                } else {
                    $r = $q->poll($s->get('poll'));
                }
                $out[] = $r;
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        $out[] = ['depth' => $q->depth(), 'errors' => $q->errors];
        return $out;
    }

    private static function caepSet(Obj $a): array
    {
        $o = new Obj();
        foreach ($a->keys() as $k) {
            if ($k !== 'kind' && $k !== 'keyJwk') {
                $o->set($k, $a->get($k));
            }
        }
        $o->set('key', $a->get('keyJwk'));
        return self::shape($a->get('kind') === 'risk' ? Signals::riskLevelChangeSET($o) : Signals::assuranceLevelChangeSET($o));
    }

    private static function manageScenario(Obj $spec): array
    {
        $store = new MemoryStreamStore();
        $delivered = [];
        $ids = 0;
        $cur = ['now' => 1000, 'rcv' => null];
        $so = $spec->get('options');
        $es = $spec->has('eventsSupported') ? $spec->get('eventsSupported') : [Signals::EVENT_TYPES['grantRevoked'], Signals::EVENT_TYPES['killSwitch'], Signals::EVENT_TYPES['sessionRevoked']];
        $o = [
            'store' => $store, 'issuer' => 'https://tx.example', 'eventsSupported' => $es,
            'pollEndpoint' => static fn(string $id): string => "https://tx.example/poll/$id", 'signingKey' => self::privJwk(),
            'deliver' => static function ($stream, string $set) use (&$delivered): void {
                $delivered[] = ['stream' => $stream->copy(), 'set' => self::shape($set)];
            },
            'now' => static function () use (&$cur) {
                return $cur['now'];
            },
            'newId' => static function () use (&$ids): string {
                return 's' . (++$ids);
            },
        ];
        foreach ($so instanceof Obj ? $so->keys() : [] as $k) {
            $o[$k] = $so->get($k);
        }
        $h = SsfManage::ssfManagementHandler($o, static function ($req) use (&$cur) {
            if ($cur['rcv'] === 'throws') {
                throw new \RuntimeException('auth');
            }
            return $cur['rcv'];
        });
        $out = [];
        foreach ($spec->get('steps') as $st) {
            $cur = ['now' => $st->has('now') ? $st->get('now') : 1000, 'rcv' => $st->has('rcv') ? $st->get('rcv') : Obj::of(['id' => 'rx1', 'aud' => 'rx'])];
            try {
                $out[] = $h($st->get('req'));
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        $dump = [];
        $rids = $spec->has('receivers') ? $spec->get('receivers') : ['rx1', 'rx2'];
        foreach ($rids as $rid) {
            $dump[$rid] = $store->listByReceiver($rid);
        }
        $out[] = ['delivered' => $delivered, 'store' => $dump];
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => [
                'SET_TYP' => Signals::SET_TYP, 'SET_ALG' => Signals::SET_ALG, 'EVENT_TYPES' => Signals::EVENT_TYPES, 'RISC_EVENT_TYPES' => Signals::RISC_EVENT_TYPES,
                'SET_INMEMORY_MAX_ENTRIES' => Signals::SET_INMEMORY_MAX_ENTRIES, 'DELIVERY_PUSH' => SsfStream::DELIVERY_PUSH, 'DELIVERY_POLL' => SsfStream::DELIVERY_POLL,
                'STREAM_STATUSES' => SsfStream::STREAM_STATUSES,
            ],
            'verifySET' => fn(array $a, Obj $c) => self::verifySet($a, $c),
            'buildSETShape' => function (array $a, Obj $c): array {
                $x = $a[0];
                try {
                    return self::shape(Signals::buildSET($x->get('events'), $x->get('issuer'), $x->get('audience'), $x->get('keyJwk'), $x->get('subject')));
                } catch (\Throwable $e) {
                    $want = $c->get('out');
                    // an unusable signing key is refused by the runtime's key class (ERR_CRYPTO_INVALID_JWK); the native only has to refuse it
                    if ($want instanceof Obj && $want->get('code') === 'ERR_CRYPTO_INVALID_JWK') {
                        throw new SignalsError('ERR_CRYPTO_INVALID_JWK', $e->getMessage());
                    }
                    throw $e;
                }
            },
            'stateScenario' => fn(array $a) => self::stateScenario($a[0]),
            'replayScenario' => fn(array $a) => self::replayScenario($a[0]),
            'replayConformance' => fn(array $a) => self::replayConformance($a[0]),
            'receiveScenario' => fn(array $a) => self::receiveScenario($a[0]),
            'adapterScenario' => fn(array $a) => self::adapterScenario($a[0]),
            'validateStreamConfig' => fn(array $a) => SsfStream::validateStreamConfig($a[0]),
            'healthScenario' => fn(array $a) => self::healthScenario($a[0]),
            'verificationScenario' => fn(array $a) => self::verificationScenario($a[0]),
            'pollScenario' => fn(array $a) => self::pollScenario($a[0]),
            'pushResponse' => fn(array $a) => SsfStream::pushResponse($a[0]),
            'caepSET' => fn(array $a) => self::caepSet($a[0]),
            'transmitterMetadata' => fn(array $a) => SsfManage::transmitterMetadata($a[0], $a[1], $a[2] ?? null),
            'manageScenario' => fn(array $a) => self::manageScenario($a[0]),
        ]);
    }
}
