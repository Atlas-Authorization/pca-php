<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostService.php';

use Atlas\Pca\CoordinatorError;
use Atlas\Pca\CoordinatorTimeoutError;
use Atlas\Pca\EquivocationError;
use Atlas\Pca\Frost;
use Atlas\Pca\GuardianSignerService;
use Atlas\Pca\InProcessTransport;
use Atlas\Pca\Js;
use Atlas\Pca\MemoryFrostNonceStore;
use Atlas\Pca\NetworkCoordinator;
use Atlas\Pca\NonceRecord;
use Atlas\Pca\NonceStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PoPError;
use Atlas\Pca\SignerTransport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A memory nonce store whose one method throws "store down". */
final class FailingNonceStore implements NonceStore
{
    private MemoryFrostNonceStore $inner;

    public function __construct(private readonly string $method)
    {
        $this->inner = new MemoryFrostNonceStore();
    }

    private function gate(string $m): void
    {
        if ($this->method === $m) {
            throw new \RuntimeException('store down');
        }
    }

    public function create(string $sessionId, NonceRecord $record): void
    {
        $this->gate('create');
        $this->inner->create($sessionId, $record);
    }

    public function load(string $sessionId): ?NonceRecord
    {
        $this->gate('load');
        return $this->inner->load($sessionId);
    }

    public function spend(string $sessionId): void
    {
        $this->gate('spend');
        $this->inner->spend($sessionId);
    }

    public function drop(string $sessionId): void
    {
        $this->gate('drop');
        $this->inner->drop($sessionId);
    }

    public function isSpent(string $sessionId): bool
    {
        $this->gate('isSpent');
        return $this->inner->isSpent($sessionId);
    }
}

/** A signer transport for the corpus: a real service or canned replies, with a scripted delay, an unreachable round and a hostile rewrite of the reply. */
final class ScriptedTransport implements SignerTransport
{
    private array $n = [1 => 0, 2 => 0];

    public function __construct(private readonly mixed $id, private readonly ?GuardianSignerService $service, private readonly Obj $spec, private readonly \Closure $advance)
    {
    }

    public function identifier(): mixed
    {
        return $this->id;
    }

    public function round1(Obj $req): mixed
    {
        return $this->respond(1, $req);
    }

    public function round2(Obj $req): mixed
    {
        return $this->respond(2, $req);
    }

    private function respond(int $round, Obj $req): mixed
    {
        $key = $round === 1 ? 'r1' : 'r2';
        $n = $this->n[$round]++;
        $delay = $this->spec->get('delay');
        if ($delay instanceof Obj && $delay->has($key) && Js::num($delay->get($key)) > 0) {
            ($this->advance)(Js::num($delay->get($key)));
        }
        $throws = $this->spec->get('throws');
        if ($throws instanceof Obj && $throws->get($key) === true) {
            throw new \RuntimeException('unreachable');
        }
        if ($this->spec->has('canned')) {
            $list = $this->spec->get('canned')->get($round === 1 ? 'round1' : 'round2');
            $c = $list[$n] ?? 'throw';
            if ($c === 'throw') {
                throw new \RuntimeException('unreachable');
            }
            $resp = $c;
        } else {
            $resp = $round === 1 ? $this->service->round1($req) : $this->service->round2($req);
        }
        return self::edit($resp, $this->spec->get('edits') ?? [], $round);
    }

    private static function flip(mixed $s): mixed
    {
        $raw = Pca::unb64u($s);
        $raw[0] = chr(ord($raw[0]) ^ 1);
        return Pca::b64u($raw);
    }

    private static function edit(mixed $resp, array $edits, int $round): mixed
    {
        foreach ($edits as $e) {
            if (Js::num($e->get('round')) !== (float)$round) {
                continue;
            }
            $path = $e->get('path');
            $op = $e->get('op');
            $apply = static function (Obj $o, string $k) use ($op, $e): Obj {
                if ($op === 'delete') {
                    return $o->without($k);
                }
                $c = $o->without();
                $c->set($k, $op === 'set' ? $e->get('value') : self::flip($o->get($k)));
                return $c;
            };
            if (count($path) === 1) {
                $resp = $apply($resp, $path[0]);
            } else {
                $parent = $resp->get($path[0]);
                if ($parent instanceof Obj) {
                    $c = $resp->without();
                    $c->set($path[0], $apply($parent, $path[1]));
                    $resp = $c;
                }
            }
        }
        return $resp;
    }
}

/**
 * The networked FROST signer service and coordinator against the TS reference: the signer-service and coordinator cases of test-data/ref-frost-net.json.gz.
 * The reference's randomness is a queue of fixed values (the proof-of-possession nonce, then the hiding and binding randomness of each round 1), fed here
 * through the service's randomness seam. A refusal reason flagged `reasonOpen` wraps an inner primitive's text and is compared by presence only; the text of a
 * thrown error nested in a scenario result is informative, its class and fields are exact. Transport delays are virtual time on the coordinator's clock.
 */
final class RefFrostServiceDifferentialTest extends TestCase
{
    private const FILE = 'ref-frost-net.json.gz';
    private const FNS = ['signerService' => 95, 'coordinator' => 86];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    private static function seed(mixed $v): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    private static function b(Obj $v): string
    {
        return $v->get('$bytes') instanceof Obj ? self::seed($v->get('$bytes')) : Base::bytes($v);
    }

    private static function share(Obj $d): string
    {
        $coeffs = $d->get('coefficients');
        $kg = Frost::trustedDealerKeygen((int)Js::num($d->get('t')), (int)Js::num($d->get('n')), self::seed($d->get('secret')->get('$bytes')),
            $coeffs === null ? null : array_map(static fn($c) => self::seed($c->get('$bytes')), $coeffs),
            $d->get('identifiers') === null ? null : array_map(static fn($x) => (int)Js::num($x), $d->get('identifiers')));
        foreach ($kg['participantShares'] as $p) {
            if ($p['identifier'] === (int)Js::num($d->get('id'))) {
                return $p['share'];
            }
        }
        throw new \LogicException('no such share');
    }

    /** `$bytes`, `$share` and `$num` forms resolved throughout. */
    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $ks = $v->keys();
            if ($ks === ['$bytes']) {
                return self::b($v);
            }
            if ($ks === ['$share']) {
                return self::share($v->get('$share'));
            }
            if ($ks === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($ks as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    /** Wire form of a result value: raw bytes become `{"$bytes"}`. */
    private static function err(\Throwable $e): Obj
    {
        $o = Obj::of(['$throws' => $e->getMessage()]);
        if ($e instanceof PoPError) {
            $o->set('class', 'PoPError');
            if ($e->identifier !== null) {
                $o->set('identifier', $e->identifier);
            }
        } elseif ($e instanceof EquivocationError) {
            foreach (['class' => 'EquivocationError', 'session_id' => $e->sessionId, 'round' => $e->round, 'identifier' => $e->identifier,
                'previousDigest' => $e->previousDigest, 'offendingDigest' => $e->offendingDigest] as $k => $v) {
                $o->set($k, $v);
            }
        } elseif ($e instanceof CoordinatorError) {
            $o->set('class', $e instanceof CoordinatorTimeoutError ? 'CoordinatorTimeoutError' : 'CoordinatorError');
            $o->set('refusals', $e->refusals);
            if ($e instanceof CoordinatorTimeoutError) {
                $o->set('timeoutMs', $e->timeoutMs);
            }
        }
        return $o;
    }

    /** Both sides without the open reasons and without the informative text of a nested error. */
    private static function norm(mixed $w, mixed $h): array
    {
        if ($w instanceof Obj && $h instanceof Obj) {
            $nw = new Obj();
            $nh = new Obj();
            $open = $w->get('reasonOpen') === true;
            foreach ($w->keys() as $k) {
                if ($open && ($k === 'reason' || $k === 'reasonOpen')) {
                    continue;
                }
                if ($k === '$throws') {
                    $nw->set($k, '');
                    if ($h->has($k)) {
                        $nh->set($k, '');
                    }
                    continue;
                }
                if ($h->has($k)) {
                    [$a, $b] = self::norm($w->get($k), $h->get($k));
                    $nw->set($k, $a);
                    $nh->set($k, $b);
                } else {
                    $nw->set($k, $w->get($k));
                }
            }
            foreach ($h->keys() as $k) {
                if (!$nh->has($k) && !($open && $k === 'reason') && !$w->has($k)) {
                    $nh->set($k, $h->get($k));
                }
            }
            return [$nw, $nh];
        }
        if (is_array($w) && is_array($h) && count($w) === count($h)) {
            $a = [];
            $b = [];
            foreach (array_keys($w) as $i) {
                [$a[], $b[]] = self::norm($w[$i], $h[$i]);
            }
            return [$a, $b];
        }
        return [$w, $h];
    }

    private static function mkStore(mixed $k): mixed
    {
        if ($k === null || $k === 'none') {
            return null;
        }
        if ($k === 'memory') {
            return new MemoryFrostNonceStore();
        }
        if ($k === 'invalid-no-spend') {
            return new class {
                public function create(): void
                {
                }

                public function load(): void
                {
                }

                public function drop(): void
                {
                }

                public function isSpent(): void
                {
                }
            };
        }
        return new FailingNonceStore(substr($k, 5));
    }

    private static function signerService(Obj $cfg, array $steps, array $queue): Obj
    {
        $clock = $cfg->has('clock') && $cfg->get('clock') !== null ? Js::num($cfg->get('clock')) : 1000000.0;
        $store = self::mkStore($cfg->get('store'));
        $draw = static function () use (&$queue): string {
            return array_shift($queue) ?? throw new \LogicException('randomness draw beyond the script');
        };
        $opts = [];
        foreach (['identifier', 'share', 'groupPublicKey', 'threshold', 'policyAuthorityPublicKey'] as $k) {
            if ($cfg->has($k)) {
                $opts[$k] = $cfg->get($k);
            }
        }
        $opts['sessionTtlMs'] = $cfg->get('sessionTtlMs');
        $opts['now'] = static function () use (&$clock) {
            return $clock;
        };
        $opts['nonceStore'] = $store;
        $opts['random'] = $draw;
        $out = Obj::of(['ctor' => null, 'steps' => []]);
        $res = [];
        try {
            $svc = new GuardianSignerService($opts);
            $out->set('ctor', Obj::of(['verificationShare' => Base::outBytes($svc->verificationShare), 'pop' => $svc->proofOfPossession(),
                'enrollment' => Obj::of(['identifier' => $svc->identifier, 'publicKey' => Base::outBytes($svc->verificationShare), 'pop' => $svc->enrollment()['pop']])]));
        } catch (\Throwable $e) {
            $out->set('ctor', self::err($e));
            return $out;
        }
        foreach ($steps as $st) {
            try {
                switch ($st->get('op')) {
                    case 'round1':
                        $res[] = $svc->round1($st->get('req'));
                        break;
                    case 'round2':
                        $res[] = $svc->round2($st->get('req'));
                        break;
                    case 'clock':
                        $clock += Js::num($st->get('ms'));
                        $res[] = Obj::of(['clock' => $clock]);
                        break;
                    case 'restart':
                        $svc = new GuardianSignerService($opts);
                        $res[] = Obj::of(['restarted' => true, 'pop' => $svc->proofOfPossession()]);
                        break;
                    case 'storeLoad':
                        $res[] = Obj::of(['live' => $store->load($st->get('sid')) !== null]);
                        break;
                    case 'storeIsSpent':
                        $res[] = Obj::of(['spent' => $store->isSpent($st->get('sid'))]);
                        break;
                    default:
                        throw new \RuntimeException('bad step');
                }
            } catch (\Throwable $e) {
                $res[] = self::err($e);
            }
        }
        $out->set('steps', $res);
        return $out;
    }

    private static function coordinator(Obj $cfg): Obj
    {
        $cfg = self::conv($cfg);
        $vt = 0.0;
        $advance = static function (float $ms) use (&$vt): void {
            $vt += $ms;
        };
        $transports = [];
        foreach ($cfg->get('signers') as $s) {
            $id = $s->get('identifier');
            $service = null;
            if (!$s->has('canned')) {
                $queue = new \ArrayObject($s->get('rng')); // one queue per signer (a by-reference capture in a loop shares one variable)
                $service = new GuardianSignerService(['identifier' => $id, 'share' => $s->get('share'), 'groupPublicKey' => $s->get('groupPublicKey'),
                    'threshold' => $s->get('threshold'), 'policyAuthorityPublicKey' => $s->get('policyAuthorityPublicKey'), 'sessionTtlMs' => $s->get('sessionTtlMs'),
                    'now' => static fn(): int => 1000000, 'nonceStore' => self::mkStore($s->get('store')),
                    'random' => static function () use ($queue): string {
                        $v = $queue->count() > 0 ? $queue->offsetGet(0) : null;
                        $all = $queue->getArrayCopy();
                        $queue->exchangeArray(array_slice($all, 1));
                        return $v ?? throw new \LogicException('randomness draw beyond the script');
                    }]);
            }
            $transports[] = new ScriptedTransport($id, $service, $s, $advance);
        }
        $sids = $cfg->get('sessionIds') ?? [];
        $opts = ['groupPublicKey' => $cfg->get('groupPublicKey'), 'threshold' => $cfg->get('threshold'), 'signers' => $transports,
            'timeoutMs' => $cfg->get('timeoutMs'), 'clock' => static function () use (&$vt): float { // by reference: an arrow function would freeze the virtual time at its creation
                return $vt;
            },
            'newSessionId' => static function () use (&$sids): string {
                return array_shift($sids) ?? throw new \RuntimeException('no more scripted session ids');
            }];
        if ($cfg->has('verificationShares')) {
            $opts['verificationShares'] = array_map(static fn(Obj $v): array => ['identifier' => (int)Js::num($v->get('identifier')), 'publicKey' => $v->get('publicKey')],
                $cfg->get('verificationShares'));
        }
        if ($cfg->has('enroll')) {
            $opts['enroll'] = $cfg->get('enroll');
        }
        $out = Obj::of(['calls' => []]);
        try {
            $coord = new NetworkCoordinator($opts);
        } catch (\Throwable $e) {
            $out->set('ctor', self::err($e));
            return $out;
        }
        $calls = [];
        foreach ($cfg->get('calls') as $c) {
            try {
                $ids = $c->get('signerIds');
                $r = $coord->sign($c->get('message'), $c->get('allow'), ['signerIds' => $ids, 'timeoutMs' => $c->get('timeoutMs')]);
                $calls[] = Obj::of(['signature' => Base::outBytes($r['signature']), 'sessionId' => $r['sessionId'], 'signers' => $r['signers']]);
            } catch (\Throwable $e) {
                $calls[] = self::err($e);
            }
        }
        $out->set('calls', $calls);
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $norm = static function (Obj $c, Obj $have): Obj {
            [$w, $h] = self::norm($c->get('out'), $have);
            $c->set('out', $w);
            return $h;
        };
        Base::run($file, $fn, $k, [
            'signerService' => static function (array $a, Obj $c) use ($norm) {
                $cfg = self::conv($a[0]);
                $queue = array_map(static fn($b) => self::b($b), $a[2]->get('$rng') ?? []);
                return $norm($c, self::signerService($cfg, self::conv($a[1]), $queue));
            },
            'coordinator' => static fn(array $a, Obj $c) => $norm($c, self::coordinator($a[0])),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
