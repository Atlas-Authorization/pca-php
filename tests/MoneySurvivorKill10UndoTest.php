<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\IntentV2;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryUndoStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\OperationStore;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\Undo;
use Atlas\Pca\UndoCoordinator;
use Atlas\Pca\UndoCoordinatorFactory;
use Atlas\Pca\UndoError;
use Atlas\Pca\UndoStore;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/UndoCoordinator.php';

/** Captures what is written to a stream (STDERR) instead of letting it through. */
final class Money10StderrCapture extends \php_user_filter
{
    public static string $buf = '';

    public function filter($in, $out, &$consumed, bool $closing): int
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            self::$buf .= $bucket->data;
            $consumed = (int)$consumed + $bucket->datalen;
        }
        return PSFS_PASS_ON;
    }
}

/** A durable-declaring undo store over the memory store that can refuse every replace and counts them. */
final class Money10UndoStore implements UndoStore
{
    public MemoryUndoStore $m;
    public bool $failReplace = false;
    public int $replaces = 0;

    public function __construct()
    {
        $this->m = new MemoryUndoStore();
    }

    public function durable(): bool
    {
        return true;
    }

    public function get(string $id): ?Obj
    {
        return $this->m->get($id);
    }

    public function create(Obj $rec): array
    {
        return $this->m->create($rec);
    }

    public function replace(string $id, int $expectedVer, Obj $next): bool
    {
        $this->replaces++;
        return $this->failReplace ? false : $this->m->replace($id, $expectedVer, $next);
    }

    public function list(array $q): array
    {
        return $this->m->list($q);
    }
}

/** An operation store whose claim of the executing state can be lost to another worker. */
final class Money10Ops implements OperationStore
{
    public MemoryOperationStore $m;
    public ?\Closure $onExecuting = null;

    public function __construct()
    {
        $this->m = new MemoryOperationStore();
    }

    public function create(OperationRecord $rec): array
    {
        return $this->m->create($rec);
    }

    public function get(string $id): ?OperationRecord
    {
        return $this->m->get($id);
    }

    public function transition(string $id, string $from, OperationRecord $next): bool
    {
        if ($next->state === 'executing' && $this->onExecuting !== null) {
            ($this->onExecuting)();
            return false;
        }
        return $this->m->transition($id, $from, $next);
    }
}

final class Money10Undo
{
    public mixed $now = 1000;
    public array $calls = [];
    public array $alerts = [];
    public array $notices = [];
    public ?\Closure $onNotify = null;
    public ?\Closure $onCompensate = null;
    public ?\Closure $onResolve = null;
    public mixed $grant = null;
    public int $resolves = 0;
    public Money10UndoStore $store;
    public Money10Ops $ops;

    public function __construct()
    {
        $this->store = new Money10UndoStore();
        $this->ops = new Money10Ops();
    }
}

final class Money10Notifier
{
    public function __construct(private readonly Money10Undo $h)
    {
    }

    public function notify(array $n): mixed
    {
        $this->h->notices[] = $n;
        return $this->h->onNotify !== null ? ($this->h->onNotify)($n) : ['delivered' => true];
    }
}

final class Money10Engine
{
    public array $ctxs = [];

    public function __construct(private readonly ?Obj $plan)
    {
    }

    public function plan(Obj $op, array $ctx): ?Obj
    {
        $this->ctxs[] = $ctx;
        return $this->plan;
    }
}

final class Money10UndoLedger
{
    public array $log = [];
    public ?\Closure $answer = null;

    public function commit(string $key, string $id): mixed
    {
        $this->log[] = ['commit', $key, $id];
        return $this->answer !== null ? ($this->answer)() : ['outcome' => 'settled'];
    }

    public function release(string $key, string $id, mixed $ev = null): mixed
    {
        $this->log[] = ['release', $key, $id, $ev];
        return $this->answer !== null ? ($this->answer)() : ['outcome' => 'settled'];
    }
}

final class Money10Relay
{
    public mixed $p = [];
    public ?\Throwable $fail = null;

    public function pending(): mixed
    {
        if ($this->fail !== null) {
            throw $this->fail;
        }
        return $this->p;
    }
}

final class Money10Bonds
{
    public array $slashed = [];

    public function slashBond(array $params): Obj
    {
        $this->slashed[] = $params;
        return Obj::of(['slashed' => true, 'claim' => $params['claimId']]);
    }
}

/**
 * Group 10 survivors of the undo coordinator: every refusal keeps its exact code and reason, every alert its exact shape, the clock,
 * the CAS bound, the budget settlement, the effect timeout, the stale operation recovery and the relay / revocation / slash paths.
 */
final class MoneySurvivorKill10UndoTest extends TestCase
{
    private const D43 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    private const WE = 901000; // opened at 1000 with the default 15 min window

    // ---- fixtures ----

    private static function seed(int $b): string
    {
        return str_repeat(chr($b), 32);
    }

    private static function grant(?array $predicates = null): Obj
    {
        $env = ['predicates' => $predicates ?? [['verb' => 'pay', 'resource' => 'invoice:*'], ['verb' => 'pay.refund', 'resource' => 'invoice:*']],
            'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant(new KeyPair(self::seed(1)), (new KeyPair(self::seed(2)))->public, $env, 'pay invoices', 's')['grant'];
    }

    private static function op(bool $params = true): Obj
    {
        return $params ? Obj::of(['verb' => 'pay', 'resource' => 'invoice:1', 'params' => Obj::of(['amount' => new Num('5')])])
            : Obj::of(['verb' => 'pay', 'resource' => 'invoice:1']);
    }

    private static function act(Obj $grant, ?string $class = null): Obj
    {
        $params = Obj::of(['amount' => new Num('5')]);
        if ($class === null) {
            return (new Agent(new KeyPair(self::seed(2)), $grant, 'rs', null, 0, static fn() => 1000))->act('pay', 'invoice:1', $params)->pcactn;
        }
        $node = ['id' => 'n1', 'verb' => 'pay', 'resource' => 'invoice:1', 'params_digest' => Pca::paramsDigest(Sign::n($params)), 'reversibility_class' => $class];
        return Sign::buildPcactn($grant, [$grant], [$node], 'n1', 1, new KeyPair(self::seed(2)), 'rs', $params, 1000, null, Sign::DEFAULT_TTL_MS,
            ['nonce' => Pca::b64u(random_bytes(16))]);
    }

    private static function planT(array $extra = []): Obj
    {
        return Obj::of(['def_digest' => self::D43, 'compensation' => Obj::of(['verb' => 'pay.refund', 'params' => new Obj(), 'def_digest' => self::D43, 'target_param' => 'payment'])] + $extra);
    }

    private static function planN(?Obj $params = null): Obj
    {
        return Obj::of(['def_digest' => self::D43, 'compensation' => Obj::of(['verb' => 'pay.refund', 'params' => $params ?? new Obj(), 'def_digest' => self::D43])]);
    }

    private static function mk(Money10Undo $h, array $extra = [], ?Obj $plan = null): UndoCoordinator
    {
        $h->grant ??= self::grant();
        return UndoCoordinatorFactory::create($extra + ['store' => $h->store, 'engine' => new Money10Engine($plan ?? self::planT()), 'signerSecret' => self::seed(9),
            'audience' => 'rs', 'resolveGrant' => static function ($ref, $pc) use ($h) {
                $h->resolves++;
                if ($h->onResolve !== null) {
                    $f = $h->onResolve;
                    $h->onResolve = null;
                    return $f();
                }
                return $h->grant;
            }, 'compensate' => static function (array $call) use ($h) {
                $h->calls[] = $call;
                return $h->onCompensate !== null ? ($h->onCompensate)($call) : Obj::of(['refund' => 'r1']);
            }, 'operations' => $h->ops, 'notifier' => new Money10Notifier($h),
            'alert' => static function (array $a) use ($h): void {
                $h->alerts[] = $a;
            }, 'now' => static fn() => $h->now, 'insecureVolatileStore' => true]);
    }

    /** @return array{0:array,1:array} admission and open info */
    private static function opened(UndoCoordinator $c, Money10Undo $h, bool $converted = false, ?array $bond = null): array
    {
        $adm = $c->admit(self::act($h->grant), self::op(), $converted, $h->grant);
        self::assertArrayNotHasKey('refused', $adm);
        return [$adm, $c->open($adm, $bond)];
    }

    /** Move a stored record behind the coordinator's back (another worker). */
    private static function force(Money10Undo $h, string $id, array $patch): void
    {
        $cur = $h->store->m->get($id);
        $n = $cur->without();
        foreach ($patch as $k => $v) {
            $n->set($k, $v);
        }
        $ver = (int)$cur->get('ver')->lexeme;
        $n->set('ver', new Num((string)($ver + 1)));
        self::assertTrue($h->store->m->replace($id, $ver, $n));
    }

    private static function opId(string $id, int $attempt): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/undo-compensation-op/v1', 'record' => $id, 'attempt' => new Num((string)$attempt)]));
    }

    /** @return array{0:mixed,1:list<string>} the result and every PHP warning/notice raised meanwhile */
    private static function quiet(callable $f): array
    {
        $errs = [];
        set_error_handler(static function (int $no, string $str) use (&$errs): bool {
            $errs[] = $str;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        return [$r, $errs];
    }

    private static function kinds(Money10Undo $h): array
    {
        return array_column($h->notices, 'kind');
    }

    // ---- the factory and the constructor ----

    /** A configuration that lacks components names each of them, in order, after the fixed prefix. */
    public function testMissingComponentsAreNamedInTheMessage(): void
    {
        $h = new Money10Undo();
        try {
            UndoCoordinatorFactory::create(['engine' => new Money10Engine(null), 'signerSecret' => self::seed(9), 'audience' => 'rs', 'resolveGrant' => static fn() => null,
                'compensate' => static fn() => null, 'operations' => new MemoryOperationStore(), 'notifier' => new Money10Notifier($h)]);
            self::fail('missing components must be refused');
        } catch (UndoError $e) {
            self::assertSame('config', $e->errorCode);
            self::assertSame('config: undo coordinator: missing required component(s): store, alert', $e->getMessage());
        }
    }

    /** A closure engine is accepted and called with the operation and its operation id. */
    public function testAClosureEngineIsWrappedAndReceivesTheOperationId(): void
    {
        $h = new Money10Undo();
        $seen = [];
        $c = self::mk($h, ['engine' => static function (Obj $op, array $ctx) use (&$seen): ?Obj {
            $seen[] = [$op->get('verb'), $ctx];
            return self::planT();
        }]);
        $adm = $c->admit(self::act($h->grant), self::op(), false, $h->grant);
        self::assertArrayNotHasKey('refused', $adm);
        self::assertSame([['pay', ['operationId' => $adm['id']]]], $seen);
    }

    /** A KeyPair given as the signer secret is refused with the config error, not a type error. */
    public function testAKeyPairSignerSecretIsAConfigError(): void
    {
        $h = new Money10Undo();
        try {
            self::mk($h, ['signerSecret' => new KeyPair(self::seed(9))]);
            self::fail('a KeyPair secret must be refused');
        } catch (UndoError $e) {
            self::assertSame('config: signerSecret is the 32-byte seed', $e->getMessage());
        }
    }

    // ---- the clock ----

    /** Without a clock seam the coordinator reads wall time in milliseconds. */
    public function testTheDefaultClockIsWallTimeInMilliseconds(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, ['now' => null]);
        $before = microtime(true) * 1000;
        $adm = $c->admit(self::act($h->grant), self::op(), false, $h->grant);
        $after = microtime(true) * 1000;
        self::assertIsInt($adm['opened_at']);
        self::assertGreaterThanOrEqual($before - 1000, $adm['opened_at']);
        self::assertLessThanOrEqual($after + 1000, $adm['opened_at']);
    }

    /** A fractional clock is floored; a NaN clock refuses admission with the exact reason. */
    public function testAFloatClockIsFlooredAndANanClockFailsClosed(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $h->now = 1500.7;
        $adm = $c->admit(self::act($h->grant), self::op(), false, $h->grant);
        self::assertSame(1500, $adm['opened_at']);
        self::assertSame(1500 + 900000, $adm['window_end']);
        $h->now = NAN;
        self::assertSame(['refused' => 'undo admission error (fail closed): invalid: the clock returned a non-finite time'],
            $c->admit(self::act($h->grant), self::op(), false, $h->grant));
    }

    // ---- admission ----

    /** An operation without a string resource is no operation. */
    public function testAnOperationWithoutAResourceIsRefused(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        self::assertSame(['refused' => 'no operation'], $c->admit(self::act($h->grant), Obj::of(['verb' => 'pay']), false, $h->grant));
    }

    /** An explicit grant is used as given (the resolver is not consulted); an unresolvable grant is refused. */
    public function testGrantResolution(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $g = $h->grant;
        self::assertArrayNotHasKey('refused', $c->admit(self::act($g), self::op(), false, $g));
        self::assertSame(0, $h->resolves);
        $h->grant = null;
        self::assertSame(['refused' => 'unknown grant'], $c->admit(self::act($g), self::op(), false));
        self::assertSame(1, $h->resolves);
    }

    /** A policy returned as an Obj is read member by member (every member, not only the first). */
    public function testAPolicyObjIsReadInFull(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, ['policy' => static fn() => Obj::of(['windowMs' => new Num('60000'), 'mode' => 'off'])]);
        self::assertSame(['refused' => 'policy: undo windows are off'], $c->admit(self::act($h->grant), self::op(), false, $h->grant));
        $w = self::mk($h, ['policy' => static fn() => Obj::of(['windowMs' => new Num('60000')])]);
        $adm = $w->admit(self::act($h->grant), self::op(), false, $h->grant);
        self::assertSame(1000 + 60000, $adm['window_end']);
    }

    /** Only the reversible class gets a window: rate_limited and costly are refused with the class named; an action with no action member reads null. */
    public function testOnlyTheReversibleClassIsAdmitted(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        foreach (['rate_limited', 'costly'] as $cls) {
            self::assertSame(['refused' => "the signed class is $cls"], $c->admit(self::act($h->grant, $cls), self::op(), false, $h->grant));
        }
        self::assertSame(['refused' => 'the signed class is null'], $c->admit(self::act($h->grant)->without('action'), self::op(), false, $h->grant));
    }

    /** A compensation the grant does not permit is refused with the policy VM's first non-risk reason. */
    public function testAnUnauthorizedCompensationNamesTheReason(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, [], Obj::of(['def_digest' => self::D43, 'compensation' => Obj::of(['verb' => 'admin.delete', 'params' => new Obj(), 'def_digest' => self::D43])]));
        self::assertSame(['refused' => 'the compensating action is not authorized under the grant: no predicate permits admin.delete on invoice:1'],
            $c->admit(self::act($h->grant), self::op(), false, $h->grant));
    }

    /** The original action's chain is part of the decision: an empty chain refuses the compensation. */
    public function testTheChainIsDecidedOn(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $pc = self::act($h->grant)->without();
        $pc->set('cap_chain', []);
        self::assertSame(['refused' => 'the compensating action is not authorized under the grant: delegation chain is empty or malformed'],
            $c->admit($pc, self::op(), false, $h->grant));
    }

    /** The configured PQ pins reach the decision: a pin that disagrees with the stored PQ root refuses the compensation. */
    public function testPqPinsReachTheDecision(): void
    {
        $h = new Money10Undo();
        $h->grant = self::grant();
        $g2 = $h->grant->without();
        $g2->set('alg', 'hybrid-ed25519-ml-dsa-65');
        $g2->set('pq_pk', 'PK');
        $pc = self::act($h->grant)->without();
        $pc->set('cap_chain', [$g2]);
        $c = self::mk($h, ['pqPins' => Obj::of([$h->grant->get('issuer') => 'OTHER'])]);
        self::assertSame(['refused' => 'the compensating action is not authorized under the grant: capability chain unverified: '
            . sprintf(Pca::ROOT_PQ_PIN_MISMATCH_REASON, 'hybrid-ed25519-ml-dsa-65')], $c->admit($pc, self::op(), false, $g2));
    }

    /** The compensation's params are decided on: a grant that permits the refund only for mode=full admits a full refund. */
    public function testTheCompensationParamsAreDecidedOn(): void
    {
        $h = new Money10Undo();
        $h->grant = self::grant([['verb' => 'pay', 'resource' => 'invoice:*'], ['verb' => 'pay.refund', 'resource' => 'invoice:*',
            'where' => [['field' => 'action.params.mode', 'op' => 'eq', 'value' => 'full']]]]);
        $c = self::mk($h, [], self::planN(Obj::of(['mode' => 'full'])));
        self::assertArrayNotHasKey('refused', $c->admit(self::act($h->grant), self::op(), false, $h->grant));
        $part = self::mk($h, [], self::planN(Obj::of(['mode' => 'part'])));
        self::assertStringStartsWith('the compensating action is not authorized under the grant: ', $part->admit(self::act($h->grant), self::op(), false, $h->grant)['refused']);
    }

    /** An engine that throws refuses admission, naming the error (or "unknown"). */
    public function testAnEngineErrorFailsClosed(): void
    {
        $h = new Money10Undo();
        foreach (['engine down' => 'engine down', '' => 'unknown'] as $msg => $want) {
            $c = self::mk($h, ['engine' => static function () use ($msg): ?Obj {
                throw new \RuntimeException((string)$msg);
            }]);
            self::assertSame(['refused' => "undo admission error (fail closed): $want"], $c->admit(self::act($h->grant), self::op(), false, $h->grant));
        }
    }

    /** The admission carries every member, the operation with its verb, resource and params (an absent params is {}). */
    public function testTheAdmissionShape(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $pc = self::act($h->grant);
        $adm = $c->admit($pc, self::op(), true, $h->grant);
        self::assertSame(['id', 'opened_at', 'window_end', 'converted', 'plan', 'compensation', 'pcactn', 'grant', 'operation'], array_keys($adm));
        self::assertSame(IntentV2::hashCanonical($pc), $adm['id']);
        self::assertSame([1000, self::WE, true], [$adm['opened_at'], $adm['window_end'], $adm['converted']]);
        self::assertSame($pc, $adm['pcactn']);
        self::assertSame($h->grant, $adm['grant']);
        self::assertSame(['verb', 'resource', 'params'], $adm['operation']->keys());
        self::assertSame(['pay', 'invoice:1', '5'], [$adm['operation']->get('verb'), $adm['operation']->get('resource'), $adm['operation']->get('params')->get('amount')->lexeme]);
        self::assertSame(['verb', 'resource', 'params', 'undo_of', 'def_digest', 'target_param'], $adm['compensation']->keys());
        $bare = $c->admit(self::act($h->grant), self::op(false), false, $h->grant);
        self::assertSame([], $bare['operation']->get('params')->keys());
    }

    // ---- open ----

    /** The open info: id, window end, converted, the compensation, a token for this record and the undo_window obligation. */
    public function testTheOpenInfoShape(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm, $info] = self::opened($c, $h);
        self::assertSame(['id', 'window_end', 'converted', 'compensation', 'token', 'obligation'], array_keys($info));
        self::assertSame($adm['id'], $info['id']);
        self::assertSame((string)self::WE, $info['window_end']->lexeme);
        self::assertFalse($info['converted']);
        self::assertSame(['verb' => 'pay.refund', 'resource' => 'invoice:1'], $info['compensation']);
        self::assertSame($adm['id'], Undo::decodeToken($info['token'])->get('record'));
        $ob = $info['obligation'];
        self::assertSame(['kind', 'params', 'due'], array_keys($ob));
        self::assertSame('undo_window', $ob['kind']);
        self::assertSame([$adm['id'], (string)self::WE], [$ob['params']->get('id'), $ob['params']->get('window_end')->lexeme]);
        self::assertSame((string)self::WE, $ob['due']->lexeme);
    }

    /** The stored record carries every signed member with its value, starts at ver 0 / attempt 0, and its opened receipt notes a conversion. */
    public function testTheStoredRecord(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm] = self::opened($c, $h, true);
        $r = $c->get($adm['id']);
        $pc = $adm['pcactn'];
        $chain = $pc->get('cap_chain');
        self::assertSame('1', $r->get('v')->lexeme);
        self::assertSame([$adm['id'], 'rs', $pc->get('grant_ref'), $chain[count($chain) - 1]->get('holder'), $h->grant->get('issuer')],
            [$r->get('id'), $r->get('aud'), $r->get('grant_ref'), $r->get('holder'), $r->get('principal')]);
        $a = $r->get('action');
        self::assertSame(['pay', 'invoice:1', $pc->get('action')->get('params_digest'), self::D43],
            [$a->get('verb'), $a->get('resource'), $a->get('params_digest'), $a->get('def_digest')]);
        self::assertSame(Undo::compensationDigest($adm['compensation']), $r->get('compensation_digest'));
        self::assertSame(['1000', (string)self::WE, true, 'open', '0', '0'], [$r->get('opened_at')->lexeme, $r->get('window_end')->lexeme, $r->get('converted'),
            $r->get('state'), $r->get('ver')->lexeme, $r->get('attempt')->lexeme]);
        self::assertSame(IntentV2::canonicalize($pc), $r->get('pcactn'));
        self::assertFalse($r->has('bond_ref'));
        self::assertFalse($r->has('render_digest'));
        self::assertCount(1, $r->get('receipts'));
        self::assertSame(['opened', 'converted'], [$r->get('receipts')[0]->get('event'), $r->get('receipts')[0]->get('note')]);
        [$adm2] = self::opened($c, $h);
        self::assertSame('', $c->get($adm2['id'])->get('receipts')[0]->get('note'));
        self::assertSame(['kind', 'record', 'token'], array_keys($h->notices[0]));
        self::assertSame('opened', $h->notices[0]['kind']);
    }

    /** A bond's challenge end extends the window (floored) and is recorded as the bond reference. */
    public function testABondExtendsTheWindow(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm, $info] = self::opened($c, $h, false, ['ref' => 'bond-1', 'challengeEndsAt' => self::WE + 1000.6]);
        $r = $c->get($adm['id']);
        self::assertSame((string)(self::WE + 1000), $r->get('window_end')->lexeme);
        self::assertSame((string)(self::WE + 1000), $info['window_end']->lexeme);
        self::assertSame('bond-1', $r->get('bond_ref'));
    }

    /** A plan's render digest is stored and its render is sent with the notice. */
    public function testRenderAndRenderDigestFlowThrough(): void
    {
        $h = new Money10Undo();
        $render = Obj::of(['text' => 'Pay 5']);
        $c = self::mk($h, [], self::planT(['render_digest' => 'RD', 'render' => $render]));
        [$adm] = self::opened($c, $h);
        self::assertSame('RD', $c->get($adm['id'])->get('render_digest'));
        self::assertSame(['kind', 'record', 'token', 'render'], array_keys($h->notices[0]));
        self::assertSame($render, $h->notices[0]['render']);
    }

    /** Re-opening the same admission returns the same window without a second notice; other terms or another state are refused. */
    public function testReopenIsIdempotentOnlyForTheSameOpenWindow(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm, $info] = self::opened($c, $h);
        $again = $c->open($adm);
        self::assertSame([$info['id'], $info['token']], [$again['id'], $again['token']]);
        self::assertCount(1, $h->notices);
        $other = $adm;
        $other['compensation'] = $adm['compensation']->without();
        $other['compensation']->set('params', Obj::of(['x' => 'y']));
        try {
            $c->open($other);
            self::fail('other terms must be refused');
        } catch (UndoError $e) {
            self::assertSame('invalid: undo record ' . $adm['id'] . ' already exists with other terms or state open', $e->getMessage());
        }
        $h->now = self::WE + 1;
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        self::assertSame([$adm['id']], $c->finalizeDue());
        try {
            $c->open($adm);
            self::fail('a finalized window is not reopened');
        } catch (UndoError $e) {
            self::assertSame('invalid: undo record ' . $adm['id'] . ' already exists with other terms or state finalized', $e->getMessage());
        }
    }

    /** A failed notice aborts the window, raises the critical alert and throws, each naming the channel's reason or the default. */
    public function testAFailedNoticeNamesItsReason(): void
    {
        $cases = [
            'reason' => [static fn() => ['delivered' => false, 'reason' => 'sms down'], 'sms down'],
            'no reason' => [static fn() => ['delivered' => false], 'no channel delivered the notice'],
            'not an array' => [static fn() => 'yes', 'no channel delivered the notice'],
            'throws' => [static function (): never {
                throw new \RuntimeException('smtp down');
            }, 'smtp down'],
            'throws blank' => [static function (): never {
                throw new \RuntimeException('');
            }, 'notifier error'],
        ];
        foreach ($cases as $label => [$answer, $why]) {
            $h = new Money10Undo();
            $c = self::mk($h);
            $h->onNotify = $answer;
            $adm = $c->admit(self::act($h->grant), self::op(), false, $h->grant);
            [$err, $warn] = self::quiet(static function () use ($c, $adm) {
                try {
                    $c->open($adm);
                    return null;
                } catch (UndoError $e) {
                    return $e->getMessage();
                }
            });
            self::assertSame("invalid: notify_failed: the undo window could not be announced ($why)", $err, $label);
            self::assertSame([], $warn, $label);
            self::assertSame([['level' => 'critical', 'code' => 'notify_failed', 'record' => $adm['id'],
                'reason' => "the principal could not be told about the undo window: $why"]], $h->alerts, $label);
            $r = $c->get($adm['id']);
            self::assertSame(['finalized', 'aborted', 'notify_failed'], [$r->get('state'), $r->get('outcome')->get('status'), $r->get('outcome')->get('reason')], $label);
        }
    }

    /** An alert sink that throws does not hide the alert: it is written to stderr in full. */
    public function testAThrowingAlertSinkWritesTheAlertToStderr(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, ['alert' => static function (): void {
            throw new \RuntimeException('sink down');
        }]);
        $h->onNotify = static fn() => ['delivered' => false, 'reason' => 'no channel'];
        $adm = $c->admit(self::act($h->grant), self::op(), false, $h->grant);
        if (!in_array('money10.capture', stream_get_filters(), true)) {
            stream_filter_register('money10.capture', Money10StderrCapture::class);
        }
        Money10StderrCapture::$buf = '';
        $f = stream_filter_append(STDERR, 'money10.capture', STREAM_FILTER_WRITE);
        try {
            try {
                $c->open($adm);
                self::fail('open must refuse');
            } catch (UndoError) {
            }
        } finally {
            stream_filter_remove($f);
        }
        self::assertSame('pca undo alert (notify_failed) for ' . $adm['id'] . ": the principal could not be told about the undo window: no channel\n",
            Money10StderrCapture::$buf);
    }

    // ---- the CAS loop and the ledger plumbing ----

    /** A store that keeps changing is retried exactly 64 times, then conflict_exhausted (apply and holdBudget). */
    public function testTheCasLoopIsBoundedAt64(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm] = self::opened($c, $h);
        $id = $adm['id'];
        $h->store->failReplace = true;
        $h->store->replaces = 0;
        try {
            $c->abort($id, 'x');
            self::fail('must exhaust');
        } catch (UndoError $e) {
            self::assertSame("conflict_exhausted: undo record $id kept changing", $e->getMessage());
        }
        self::assertSame(64, $h->store->replaces);
        $h->store->replaces = 0;
        try {
            $c->holdBudget($id, [['key' => 'k', 'id' => 'r']]);
            self::fail('must exhaust');
        } catch (UndoError $e) {
            self::assertSame("conflict_exhausted: undo record $id kept changing", $e->getMessage());
        }
        self::assertSame(64, $h->store->replaces);
    }

    /** Operations on an unknown record are refused with the record named. */
    public function testAnUnknownRecordIsRefusedEverywhere(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $cases = [[static fn() => $c->recordEffect('nope'), 'invalid: unknown: no undo record nope'], [static fn() => $c->holdBudget('nope', []), 'invalid: no undo record nope'],
            [static fn() => $c->compensate('nope'), 'invalid: no undo record nope']];
        foreach ($cases as [$f, $want]) {
            try {
                $f();
                self::fail($want);
            } catch (UndoError $e) {
                self::assertSame($want, $e->getMessage());
            }
        }
        self::assertSame(['ok' => false, 'code' => 'unknown', 'reason' => 'no undo record nope'], $c->veto('nope', null, null, 'ops'));
    }

    /** A refused transition through the public API throws "code: reason". */
    public function testARefusedTransitionThrowsCodeAndReason(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm] = self::opened($c, $h);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        $c->finalizeDue();
        try {
            $c->abort($adm['id'], 'late');
            self::fail('a finalized record is not aborted');
        } catch (UndoError $e) {
            self::assertSame('invalid: finalized: a finalized record cannot be aborted', $e->getMessage());
        }
    }

    // ---- budget ----

    /** holdBudget appends {key, id} objects, bumps ver, works on a vetoed record and refuses a closed one. */
    public function testHoldBudget(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm] = self::opened($c, $h);
        $id = $adm['id'];
        $one = $c->holdBudget($id, [['key' => 'k1', 'id' => 'r1']]);
        self::assertSame('1', $one->get('ver')->lexeme);
        self::assertInstanceOf(Obj::class, $one->get('budget')[0]);
        self::assertSame(['k1', 'r1'], [$one->get('budget')[0]->get('key'), $one->get('budget')[0]->get('id')]);
        $two = $c->holdBudget($id, [['key' => 'k2', 'id' => 'r2']]);
        self::assertSame('2', $two->get('ver')->lexeme);
        self::assertSame([['k1', 'r1'], ['k2', 'r2']], array_map(static fn(Obj $r): array => [$r->get('key'), $r->get('id')], $c->get($id)->get('budget')));
        $h->now = 2000;
        $c->veto($id, null, null, 'ops'); // no effect yet: the record waits vetoed
        self::assertSame('vetoed', $c->get($id)->get('state'));
        self::assertCount(3, $c->holdBudget($id, [['key' => 'k3', 'id' => 'r3']])->get('budget'));
        [$adm2] = self::opened($c, $h);
        $c->abort($adm2['id'], 'x');
        try {
            $c->holdBudget($adm2['id'], []);
            self::fail('a finalized record holds no budget');
        } catch (UndoError $e) {
            self::assertSame('invalid: a finalized record holds no budget', $e->getMessage());
        }
    }

    /** A plain ledger object is the ledger: finalization commits every reservation, settled and replayed are both fine. */
    public function testFinalizeCommitsEveryReservation(): void
    {
        $h = new Money10Undo();
        $l = new Money10UndoLedger();
        $n = 0;
        $l->answer = static function () use (&$n): array {
            return ['outcome' => $n++ === 0 ? 'settled' : 'replayed'];
        };
        $c = self::mk($h, ['budget' => $l]);
        [$adm] = self::opened($c, $h);
        $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1'], ['key' => 'k2', 'id' => 'r2']]);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        [$out, $warn] = self::quiet(static fn() => $c->finalizeDue());
        self::assertSame([$adm['id']], $out);
        self::assertSame([['commit', 'k1', 'r1'], ['commit', 'k2', 'r2']], $l->log);
        self::assertSame([], $h->alerts);
        self::assertSame([], $warn);
        self::assertSame(['opened', 'finalized'], self::kinds($h));
    }

    /** An abort releases with the caller's evidence (effect_not_run) once; a replayed abort releases nothing. */
    public function testAbortReleasesWithEvidenceOnce(): void
    {
        $h = new Money10Undo();
        $l = new Money10UndoLedger();
        $c = self::mk($h, ['budget' => ['ledger' => $l, 'evidence' => static fn(Obj $r, string $how): string => "ev:$how:" . $r->get('id')]]);
        [$adm] = self::opened($c, $h);
        $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1']]);
        $r = $c->abort($adm['id'], 'user cancelled');
        self::assertSame(['finalized', 'aborted', 'user cancelled'], [$r->get('state'), $r->get('outcome')->get('status'), $r->get('outcome')->get('reason')]);
        self::assertSame([['release', 'k1', 'r1', 'ev:effect_not_run:r1']], $l->log);
        $c->abort($adm['id'], 'user cancelled');
        self::assertCount(1, $l->log);
    }

    /** A compensation releases the reservation (rollback) and tells the principal; without an evidence hook the release carries none. */
    public function testCompensationReleasesTheReservation(): void
    {
        $h = new Money10Undo();
        $l = new Money10UndoLedger();
        $c = self::mk($h, ['budget' => ['ledger' => $l, 'evidence' => static fn(Obj $r, string $how): string => "ev:$how:" . $r->get('id')]]);
        [$adm, $info] = self::opened($c, $h);
        $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1']]);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'pay_1']));
        self::assertSame('compensated', $c->veto($adm['id'], $info['token'])['record']->get('state'));
        self::assertSame([['release', 'k1', 'r1', 'ev:rollback:r1']], $l->log);
        self::assertSame(['opened', 'vetoed', 'compensated'], self::kinds($h));

        $h2 = new Money10Undo();
        $l2 = new Money10UndoLedger();
        $c2 = self::mk($h2, ['budget' => ['ledger' => $l2]]);
        [$adm2] = self::opened($c2, $h2);
        $c2->holdBudget($adm2['id'], [['key' => 'k1', 'id' => 'r1']]);
        [, $warn] = self::quiet(static fn() => $c2->abort($adm2['id'], 'x'));
        self::assertSame([['release', 'k1', 'r1', null]], $l2->log);
        self::assertSame([], $warn);
        self::assertSame([], $h2->alerts);
    }

    /** A settlement that is not settled/replayed, or that throws, raises the exact budget_settle_failed alert. */
    public function testAFailedSettlementAlerts(): void
    {
        $cases = [
            [static fn() => ['outcome' => 'refused'], 'commit of k1/r1: refused'],
            [static fn() => 'nope', 'commit of k1/r1: null'],
            [static function (): never {
                throw new \RuntimeException('ledger down');
            }, 'commit of k1/r1: ledger down'],
            [static function (): never {
                throw new \RuntimeException('');
            }, 'commit of k1/r1: error'],
        ];
        foreach ($cases as [$answer, $why]) {
            $h = new Money10Undo();
            $l = new Money10UndoLedger();
            $l->answer = $answer;
            $c = self::mk($h, ['budget' => $l]);
            [$adm] = self::opened($c, $h);
            $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1']]);
            $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
            $h->now = self::WE + 1;
            [, $warn] = self::quiet(static fn() => $c->finalizeDue());
            self::assertSame([['level' => 'warning', 'code' => 'budget_settle_failed', 'record' => $adm['id'], 'reason' => $why]], $h->alerts, $why);
            self::assertSame([], $warn, $why);
        }
    }

    /** No ledger configured, a record with no reservation, or an array option without a ledger: each settles exactly as configured. */
    public function testSettlementGuards(): void
    {
        // no budget option: held reservations are simply not settled
        $h = new Money10Undo();
        $c = self::mk($h);
        [$adm] = self::opened($c, $h);
        $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1']]);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        [$out, $warn] = self::quiet(static fn() => $c->finalizeDue());
        self::assertSame([[$adm['id']], [], []], [$out, $warn, $h->alerts]);

        // a ledger but no reservation on the record: the ledger is not called
        $h = new Money10Undo();
        $l = new Money10UndoLedger();
        $c = self::mk($h, ['budget' => $l]);
        [$adm] = self::opened($c, $h);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        [$out, $warn] = self::quiet(static fn() => $c->finalizeDue());
        self::assertSame([[$adm['id']], [], [], []], [$out, $warn, $h->alerts, $l->log]);

        // an array without a ledger member is itself taken as the ledger (and fails loudly)
        $h = new Money10Undo();
        $c = self::mk($h, ['budget' => ['nonsense' => 1]]);
        [$adm] = self::opened($c, $h);
        $c->holdBudget($adm['id'], [['key' => 'k1', 'id' => 'r1']]);
        $c->recordEffect($adm['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        [, $warn] = self::quiet(static fn() => $c->finalizeDue());
        self::assertSame([], $warn);
        self::assertSame([['level' => 'warning', 'code' => 'budget_settle_failed', 'record' => $adm['id'],
            'reason' => 'commit of k1/r1: Call to a member function commit() on array']], $h->alerts);
    }

    // ---- effect and veto ----

    /** recordEffect stores a result only when one is given (an explicit null counts); a veto that waited is acted on. */
    public function testRecordEffect(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a1] = self::opened($c, $h);
        self::assertFalse($c->recordEffect($a1['id'])->get('effect')->has('result'));
        [$a2] = self::opened($c, $h);
        self::assertSame('p2', $c->recordEffect($a2['id'], Obj::of(['id' => 'p2']))->get('effect')->get('result')->get('id'));
        [$a3] = self::opened($c, $h);
        $e3 = $c->recordEffect($a3['id'], null, true)->get('effect');
        self::assertTrue($e3->has('result'));
        self::assertNull($e3->get('result'));
        [$a4] = self::opened($c, $h);
        $h->now = 2000;
        self::assertSame('vetoed', $c->veto($a4['id'], null, null, 'ops')['record']->get('state'));
        self::assertSame([], $h->calls);
        self::assertSame('compensated', $c->recordEffect($a4['id'], Obj::of(['id' => 'pay_4']))->get('state'));
        self::assertCount(1, $h->calls);
    }

    /** A relayed veto is judged as of when the principal made it, which must lie between the opening and now (both ends inclusive). */
    public function testARelayedVetoTime(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $bad = ['ok' => false, 'code' => 'malformed', 'reason' => 'a relayed veto time must lie between the opening of the window and now'];
        [$a, $i] = self::opened($c, $h);
        $h->now = self::WE + 10;
        $v = $c->veto($a['id'], $i['token'], 900000); // the window closed, but the veto was made inside it
        self::assertTrue($v['ok']);
        self::assertSame('900000', $c->get($a['id'])->get('veto')->get('at')->lexeme);
        $h->now = 5000;
        [$a, $i] = self::opened($c, $h);
        self::assertSame($bad, $c->veto($a['id'], $i['token'], 5001));
        self::assertSame($bad, $c->veto($a['id'], $i['token'], 4999));
        self::assertTrue($c->veto($a['id'], $i['token'], 5000)['ok']);
        [$b, $j] = self::opened($c, $h);
        $h->now = 6000;
        self::assertTrue($c->veto($b['id'], $j['token'], 6000)['ok']);
    }

    /** An operator veto names the operator and is stamped now; a late one is refused with the window end; a replay sends no notice. */
    public function testOperatorVeto(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        self::assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'an operator veto names the operator'], $c->veto($a['id'], null, null, ''));
        $h->now = 3000;
        $v = $c->veto($a['id'], null, null, 'ops');
        self::assertTrue($v['ok']);
        self::assertFalse($v['replayed']);
        $veto = $c->get($a['id'])->get('veto');
        self::assertSame(['3000', 'operator', 'ops'], [$veto->get('at')->lexeme, $veto->get('via'), $veto->get('by')]);
        self::assertSame(['opened', 'vetoed'], self::kinds($h));
        self::assertTrue($c->veto($a['id'], null, null, 'ops')['replayed']);
        self::assertSame(['opened', 'vetoed'], self::kinds($h));
        [$b] = self::opened($c, $h);
        $h->now = 3000 + 900000 + 1;
        self::assertSame(['ok' => false, 'code' => 'window_closed', 'reason' => 'the veto window closed at ' . (3000 + 900000)], $c->veto($b['id'], null, null, 'ops'));
    }

    /** An error while vetoing fails closed with its message (or "unknown"). */
    public function testAVetoErrorFailsClosed(): void
    {
        foreach (['grant store down' => 'grant store down', '' => 'unknown'] as $msg => $want) {
            $h = new Money10Undo();
            $c = self::mk($h);
            [$a] = self::opened($c, $h);
            $c->recordEffect($a['id'], Obj::of(['id' => 'p']));
            $h->onResolve = static function () use ($msg): never {
                throw new \RuntimeException((string)$msg);
            };
            self::assertSame(['ok' => false, 'code' => 'malformed', 'reason' => "veto error (fail closed): $want"], $c->veto($a['id'], null, null, 'ops'));
        }
    }

    // ---- compensation ----

    /** Without an effect report the compensation waits exactly effectTimeoutMs (default 300000) after the veto. */
    public function testTheEffectTimeout(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, [], self::planN());
        [$a] = self::opened($c, $h);
        $h->now = 2000;
        $c->veto($a['id'], null, null, 'ops');
        $h->now = 2000 + 299999;
        self::assertSame('vetoed', $c->compensate($a['id'])->get('state'));
        self::assertSame([], $h->calls);
        $h->now = 2000 + 300000;
        self::assertSame('compensated', $c->compensate($a['id'])->get('state'));
        self::assertCount(1, $h->calls);

        $h = new Money10Undo();
        $c = self::mk($h, ['effectTimeoutMs' => 10], self::planN());
        [$a] = self::opened($c, $h);
        $h->now = 2000;
        $c->veto($a['id'], null, null, 'ops');
        $h->now = 2009;
        self::assertSame('vetoed', $c->compensate($a['id'])->get('state'));
        $h->now = 2010;
        self::assertSame('compensated', $c->compensate($a['id'])->get('state'));
    }

    /** A vetoed record with no veto stamp (a foreign store) waits for the effect instead of failing. */
    public function testAVetoedRecordWithoutAVetoWaits(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $h->store->m->create(Obj::of(['v' => new Num('1'), 'id' => 'crafted', 'state' => 'vetoed', 'ver' => new Num('0'), 'receipts' => []]));
        self::assertSame('vetoed', $c->compensate('crafted')->get('state'));
        self::assertSame([], $h->calls);
    }

    /** The compensator gets the operation, the idempotency key of this attempt, the record (no pcactn) and the original result. */
    public function testTheCompensatorCall(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a, $i] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $c->veto($a['id'], $i['token']);
        $call = $h->calls[0];
        self::assertSame(['operation', 'idempotencyKey', 'undoOf', 'record', 'originalResult'], array_keys($call));
        self::assertSame(self::opId($a['id'], 0), $call['idempotencyKey']);
        self::assertSame($a['id'], $call['undoOf']);
        self::assertFalse($call['record']->has('pcactn'));
        self::assertSame([$a['id'], 'vetoed'], [$call['record']->get('id'), $call['record']->get('state')]);
        self::assertSame('pay_1', $call['originalResult']->get('id'));
        self::assertSame('pay_1', $call['operation']->get('params')->get('payment'));
        $op = $h->ops->get(self::opId($a['id'], 0));
        self::assertSame(['committed', 'r1', 1000], [$op->state, $op->result->get('refund'), $op->finishedAt]);
        self::assertSame('r1', $c->get($a['id'])->get('outcome')->get('result')->get('refund'));
    }

    /** No effect (timed out) or a null effect result: the compensator gets no originalResult. */
    public function testNoOriginalResultWithoutOne(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, ['effectTimeoutMs' => 0], self::planN());
        [$a] = self::opened($c, $h);
        self::assertSame('compensated', $c->veto($a['id'], null, null, 'ops')['record']->get('state'));
        self::assertSame(['operation', 'idempotencyKey', 'undoOf', 'record'], array_keys($h->calls[0]));
        [$b] = self::opened($c, $h);
        $c->recordEffect($b['id'], null, true);
        $c->veto($b['id'], null, null, 'ops');
        self::assertSame(['operation', 'idempotencyKey', 'undoOf', 'record'], array_keys($h->calls[1]));
    }

    /** A compensator that returns null leaves no result on the outcome. */
    public function testANullCompensationResultIsNotRecorded(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $h->onCompensate = static fn() => null;
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame('compensated', $r->get('state'));
        self::assertFalse($r->get('outcome')->has('result'));
    }

    /** A target nobody names fails the compensation with the exact alert and notice; a string result names nothing. */
    public function testAnUnknownTargetFailsLoudly(): void
    {
        $why = "the target 'payment' of the compensation is unknown (no effect result names it)";
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], 'pay_1');
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame(['compensation_failed', $why], [$r->get('state'), $r->get('outcome')->get('reason')]);
        self::assertSame([['level' => 'critical', 'code' => 'compensation_failed', 'record' => $a['id'], 'reason' => $why]], $h->alerts);
        self::assertSame(['opened', 'vetoed', 'compensation_failed'], self::kinds($h));
        self::assertSame([], $h->calls);

        $h = new Money10Undo();
        $c = self::mk($h, ['effectTimeoutMs' => 0]);
        [$a] = self::opened($c, $h);
        $v = $c->veto($a['id'], null, null, 'ops');
        self::assertTrue($v['ok']);
        self::assertSame(['compensation_failed', $why], [$v['record']->get('state'), $v['record']->get('outcome')->get('reason')]);
    }

    /** A failure whose record moved on meanwhile raises nothing and returns the current record (refused or replayed). */
    public function testAFailureOnARecordThatMovedOn(): void
    {
        foreach (['compensated', 'compensation_failed'] as $state) {
            $h = new Money10Undo();
            $c = self::mk($h);
            [$a] = self::opened($c, $h);
            $c->recordEffect($a['id'], 'pay_1');
            $h->onResolve = static function () use ($h, $a, $state) {
                self::force($h, $a['id'], ['state' => $state]);
                return $h->grant;
            };
            [$v, $warn] = self::quiet(static fn() => $c->veto($a['id'], null, null, 'ops'));
            self::assertTrue($v['ok'], $state);
            self::assertSame($state, $v['record']->get('state'));
            self::assertSame([[], []], [$h->alerts, $warn], $state);
            self::assertSame(['opened', 'vetoed'], self::kinds($h), $state);
        }
    }

    /** A grant that no longer authorizes the compensation denies it with the VM's reason. */
    public function testADeniedCompensationAtRuntime(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->onResolve = static fn() => new Obj();
        $why = 'the compensating action is not authorized under the grant: grant carries no valid envelope';
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame(['compensation_failed', $why], [$r->get('state'), $r->get('outcome')->get('reason')]);
        self::assertSame([['level' => 'critical', 'code' => 'compensation_denied', 'record' => $a['id'], 'reason' => $why]], $h->alerts);
        self::assertSame([], $h->calls);
    }

    /** A compensator that throws marks the operation failed and the record compensation_failed; a retry runs attempt 1. */
    public function testAThrowingCompensatorThenRetry(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->onCompensate = static function (): never {
            throw new \RuntimeException('refund down');
        };
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame(['compensation_failed', 'the compensating action failed: refund down'], [$r->get('state'), $r->get('outcome')->get('reason')]);
        $op = $h->ops->get(self::opId($a['id'], 0));
        self::assertSame(['failed', 'refund down', 1000], [$op->state, $op->error, $op->finishedAt]);
        self::assertSame(['compensation_failed'], array_column($h->alerts, 'code'));
        $h->onCompensate = null;
        $again = $c->retry($a['id']);
        self::assertSame(['compensated', '1'], [$again->get('state'), $again->get('attempt')->lexeme]);
        self::assertCount(2, $h->calls);
        self::assertSame(self::opId($a['id'], 1), $h->calls[1]['idempotencyKey']);
    }

    /** A committed earlier attempt is adopted with its result: the compensator never runs twice. */
    public function testACommittedAttemptIsAdopted(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->ops->m->create(new OperationRecord(self::opId($a['id'], 0), 'committed', 'pay.refund', 'invoice:1', 'pd', 'irreversible', 5, 5, 6, Obj::of(['refund' => 'prior'])));
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame('compensated', $r->get('state'));
        self::assertSame('prior', $r->get('outcome')->get('result')->get('refund'));
        self::assertSame([], $h->calls);
        self::assertSame(['opened', 'vetoed', 'compensated'], self::kinds($h));
    }

    /** A failed or uncertain earlier attempt fails the compensation, naming the attempt, the state and its error. */
    public function testAFailedOrUncertainAttemptFails(): void
    {
        foreach ([['failed', 'boom', 'compensation attempt 0 failed: boom'], ['uncertain', null, 'compensation attempt 0 uncertain: ']] as [$state, $err, $why]) {
            $h = new Money10Undo();
            $c = self::mk($h);
            [$a] = self::opened($c, $h);
            $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
            $h->ops->m->create(new OperationRecord(self::opId($a['id'], 0), $state, 'pay.refund', 'invoice:1', 'pd', 'irreversible', 5, 5, 6, null, $err));
            $r = $c->veto($a['id'], null, null, 'ops')['record'];
            self::assertSame(['compensation_failed', $why], [$r->get('state'), $r->get('outcome')->get('reason')], $state);
            self::assertSame([['level' => 'critical', 'code' => 'compensation_failed', 'record' => $a['id'], 'reason' => $why]], $h->alerts, $state);
            self::assertSame([], $h->calls);
        }
    }

    /** An aborted (never started) attempt is failed and retried as the next attempt, which then runs. */
    public function testAnAbortedAttemptIsRetried(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->ops->m->create(new OperationRecord(self::opId($a['id'], 0), 'aborted', 'pay.refund', 'invoice:1', 'pd', 'irreversible', 5, null, 6, null, 'never started'));
        $r = $c->veto($a['id'], null, null, 'ops')['record'];
        self::assertSame(['compensated', '1'], [$r->get('state'), $r->get('attempt')->lexeme]);
        self::assertSame(['opened', 'effect', 'vetoed', 'compensation_failed', 'retried', 'compensated'], array_map(static fn(Obj $x) => $x->get('event'), $r->get('receipts')));
        self::assertSame('attempt never started', $r->get('receipts')[3]->get('note'));
        self::assertCount(1, $h->calls);
        self::assertSame(self::opId($a['id'], 1), $h->calls[0]['idempotencyKey']);
        self::assertSame([], $h->alerts);
    }

    /** A pending attempt older than the timeout is settled aborted and retried; exactly at the timeout it is left alone. */
    public function testAStalePendingAttempt(): void
    {
        foreach ([301000 => false, 301001 => true] as $at => $stale) {
            $h = new Money10Undo();
            $c = self::mk($h);
            [$a] = self::opened($c, $h);
            $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
            $op0 = self::opId($a['id'], 0);
            $h->ops->m->create(new OperationRecord($op0, 'pending', 'pay.refund', 'invoice:1', 'pd', 'irreversible', 1000));
            $h->now = $at;
            $r = $c->veto($a['id'], null, null, 'ops')['record'];
            if (!$stale) {
                self::assertSame('vetoed', $r->get('state'));
                self::assertSame('pending', $h->ops->get($op0)->state);
                self::assertSame([], $h->calls);
                continue;
            }
            self::assertSame(['compensated', '1'], [$r->get('state'), $r->get('attempt')->lexeme]);
            $p = $h->ops->get($op0);
            self::assertSame(['aborted', 'never started', $at], [$p->state, $p->error, $p->finishedAt]);
            self::assertCount(1, $h->calls);
        }
    }

    /** An executing attempt is judged by when it started executing: stale ones become uncertain and fail; recent ones are left alone. */
    public function testAnExecutingAttempt(): void
    {
        $why = 'compensation attempt 0 uncertain: no outcome recorded: the compensation may or may not have run';
        foreach ([1000 => true, 200000 => false] as $execAt => $stale) {
            $h = new Money10Undo();
            $c = self::mk($h);
            [$a] = self::opened($c, $h);
            $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
            $op0 = self::opId($a['id'], 0);
            $h->ops->m->create(new OperationRecord($op0, 'executing', 'pay.refund', 'invoice:1', 'pd', 'irreversible', 0, $execAt));
            $h->now = 301001;
            $r = $c->veto($a['id'], null, null, 'ops')['record'];
            if (!$stale) {
                self::assertSame('vetoed', $r->get('state'));
                self::assertSame('executing', $h->ops->get($op0)->state);
                continue;
            }
            self::assertSame(['compensation_failed', $why], [$r->get('state'), $r->get('outcome')->get('reason')]);
            self::assertSame(['uncertain', 'no outcome recorded: the compensation may or may not have run', 301001],
                [$h->ops->get($op0)->state, $h->ops->get($op0)->error, $h->ops->get($op0)->finishedAt]);
            self::assertSame([], $h->calls);
        }
    }

    /** After settling a stale attempt the compensation resumes from the stored record, not the stale copy. */
    public function testAfterSettlingTheStoredRecordWins(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->ops->m->create(new OperationRecord(self::opId($a['id'], 0), 'pending', 'pay.refund', 'invoice:1', 'pd', 'irreversible', 1000));
        $h->now = 301001;
        $h->onResolve = static function () use ($h, $a) {
            self::force($h, $a['id'], ['state' => 'compensated']);
            return $h->grant;
        };
        self::assertSame('compensated', $c->veto($a['id'], null, null, 'ops')['record']->get('state'));
        self::assertSame([], $h->calls);
    }

    /** A record that moved on after the attempt was claimed aborts the claim and never runs the compensator. */
    public function testARecordThatMovedOnAbortsTheClaim(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->now = 4000;
        $h->onResolve = static function () use ($h, $a) {
            self::force($h, $a['id'], ['state' => 'compensated']);
            return $h->grant;
        };
        self::assertSame('compensated', $c->veto($a['id'], null, null, 'ops')['record']->get('state'));
        self::assertSame([], $h->calls);
        $op = $h->ops->get(self::opId($a['id'], 0));
        self::assertSame(['aborted', 'the undo record moved on', 4000], [$op->state, $op->error, $op->finishedAt]);
    }

    /** Losing the executing claim to another worker returns the stored record and runs nothing. */
    public function testALostClaimReturnsTheStoredRecord(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->ops->onExecuting = static function () use ($h, $a): void {
            $h->ops->onExecuting = null;
            self::force($h, $a['id'], ['state' => 'compensated']);
        };
        self::assertSame('compensated', $c->veto($a['id'], null, null, 'ops')['record']->get('state'));
        self::assertSame([], $h->calls);
    }

    /** A record that moved on while the compensator ran is returned as stored. */
    public function testARecordThatMovedOnDuringTheCompensator(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'pay_1']));
        $h->onCompensate = static function () use ($h, $a): Obj {
            self::force($h, $a['id'], ['state' => 'finalized']);
            return Obj::of(['refund' => 'r1']);
        };
        self::assertSame('finalized', $c->veto($a['id'], null, null, 'ops')['record']->get('state'));
        self::assertCount(1, $h->calls);
    }

    // ---- relay, finalize, recover ----

    /** Without a relay the window closes one ms after its end; with one, only after the grace too. */
    public function testFinalizeBoundaries(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE;
        self::assertSame([], $c->finalizeDue());
        $h->now = self::WE + 1;
        self::assertSame([$a['id']], $c->finalizeDue());

        $h = new Money10Undo();
        $c = self::mk($h, ['relay' => new Money10Relay()]);
        [$a] = self::opened($c, $h);
        $c->recordEffect($a['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + UndoCoordinator::RELAY_GRACE_MS;
        self::assertSame([], $c->finalizeDue());
        $h->now = self::WE + UndoCoordinator::RELAY_GRACE_MS + 1;
        self::assertSame([$a['id']], $c->finalizeDue());
    }

    /** Every due window is finalized (a replayed one skipped, the rest still done), with its effect_unknown alert and notice. */
    public function testFinalizeLoop(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $ids = [];
        for ($i = 0; $i < 3; $i++) {
            [$a] = self::opened($c, $h);
            $ids[] = $a['id'];
        }
        sort($ids, SORT_STRING);
        $h->notices = [];
        $done = false;
        $h->onNotify = static function (array $n) use ($h, $ids, &$done): array {
            if ($n['kind'] === 'finalized' && !$done) {
                $done = true;
                self::force($h, $ids[1], ['state' => 'finalized']);
            }
            return ['delivered' => true];
        };
        $h->now = self::WE + 1;
        [$out, $warn] = self::quiet(static fn() => $c->finalizeDue());
        self::assertSame([$ids[0], $ids[2]], $out);
        self::assertSame([], $warn);
        $reason = 'the window closed without an effect report: reconcile the original operation';
        self::assertSame([['level' => 'warning', 'code' => 'effect_unknown', 'record' => $ids[0], 'reason' => $reason],
            ['level' => 'warning', 'code' => 'effect_unknown', 'record' => $ids[2], 'reason' => $reason]], $h->alerts);
        self::assertSame(['finalized', 'finalized'], self::kinds($h));
        self::assertSame([$ids[0], $ids[2]], array_map(static fn(array $n) => $n['record']->get('id'), $h->notices));
    }

    /** syncRelay applies every well-formed pending veto (arrays only) and refuses a relay that returns no list. */
    public function testSyncRelay(): void
    {
        $h = new Money10Undo();
        self::assertSame([], self::mk($h)->syncRelay());
        $relay = new Money10Relay();
        $c = self::mk($h, ['relay' => $relay]);
        [$a, $i] = self::opened($c, $h);
        [$b, $j] = self::opened($c, $h);
        [$d, $k] = self::opened($c, $h);
        $relay->p = [['id' => $a['id'], 'token' => $i['token'], 'at' => null], ['id' => $b['id'], 'token' => $j['token'], 'at' => null],
            new \ArrayObject(['id' => $d['id'], 'token' => $k['token'], 'at' => null]), ['id' => 5, 'token' => 'x', 'at' => null]];
        $out = $c->syncRelay();
        self::assertCount(2, $out);
        self::assertSame([true, true], array_column($out, 'ok'));
        self::assertSame(['vetoed', 'vetoed', 'open'], [$c->get($a['id'])->get('state'), $c->get($b['id'])->get('state'), $c->get($d['id'])->get('state')]);
        foreach ([['a' => 1], 'x'] as $bad) {
            $relay->p = $bad;
            try {
                $c->syncRelay();
                self::fail('no list must be refused');
            } catch (UndoError $e) {
                self::assertSame('invalid: the veto relay returned no list', $e->getMessage());
            }
        }
    }

    /** finalizeDue applies the relay first: a relayed veto made in the window keeps it from being finalized. */
    public function testFinalizeAppliesTheRelayFirst(): void
    {
        $h = new Money10Undo();
        $relay = new Money10Relay();
        $c = self::mk($h, ['relay' => $relay]);
        [$a, $i] = self::opened($c, $h);
        $relay->p = [['id' => $a['id'], 'token' => $i['token'], 'at' => self::WE - 5]];
        $h->now = self::WE + UndoCoordinator::RELAY_GRACE_MS + 1;
        self::assertSame([], $c->finalizeDue());
        self::assertSame('vetoed', $c->get($a['id'])->get('state'));
    }

    /** An unreadable relay finalizes nothing and raises the critical alert with its error (or "error"). */
    public function testAnUnreadableRelayFinalizesNothing(): void
    {
        foreach (['relay down' => 'relay down', '' => 'error'] as $msg => $want) {
            $h = new Money10Undo();
            $relay = new Money10Relay();
            $relay->fail = new \RuntimeException((string)$msg);
            $c = self::mk($h, ['relay' => $relay]);
            [$a] = self::opened($c, $h);
            $h->now = self::WE + UndoCoordinator::RELAY_GRACE_MS + 1;
            self::assertSame([], $c->finalizeDue());
            self::assertSame('open', $c->get($a['id'])->get('state'));
            self::assertSame([['level' => 'critical', 'code' => 'veto_relay_failed', 'record' => '*',
                'reason' => "the veto relay could not be read; no window was finalized: $want"]], $h->alerts);
        }
    }

    /** recover resumes the vetoed records whose wait is over (only those) and then finalizes what is due. */
    public function testRecover(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h, ['effectTimeoutMs' => 1000], self::planN());
        [$r1] = self::opened($c, $h);
        [$r2] = self::opened($c, $h);
        [$r3] = self::opened($c, $h);
        $c->recordEffect($r3['id'], Obj::of(['id' => 'p']));
        $h->now = 899000;
        $c->veto($r1['id'], null, null, 'ops');
        $h->now = 900500;
        $c->veto($r2['id'], null, null, 'ops');
        $h->now = self::WE + 1;
        self::assertSame([$r1['id'], $r3['id']], $c->recover());
        self::assertSame(['compensated', 'vetoed', 'finalized'], [$c->get($r1['id'])->get('state'), $c->get($r2['id'])->get('state'), $c->get($r3['id'])->get('state')]);
    }

    // ---- revocation and slashing ----

    /** A revocation policy of veto vetoes every open window of the grant (stamped now, at first); the policy sees the action. */
    public function testRevocationVetoes(): void
    {
        $h = new Money10Undo();
        $seen = [];
        $c = self::mk($h, ['policy' => static function (Obj $op) use (&$seen): array {
            $seen[] = [$op->get('verb'), $op->get('resource'), $op->has('params')];
            return ['onRevocation' => 'veto'];
        }]);
        [$a] = self::opened($c, $h);
        [$b] = self::opened($c, $h);
        $ids = [$a['id'], $b['id']];
        sort($ids, SORT_STRING);
        $ref = $a['pcactn']->get('grant_ref');
        $seen = [];
        $h->notices = [];
        $h->now = 7000;
        self::assertSame([], $c->onRevocation('another-grant'));
        self::assertSame($ids, $c->onRevocation($ref));
        self::assertSame([['pay', 'invoice:1', false], ['pay', 'invoice:1', false]], $seen);
        foreach ($ids as $id) {
            $v = $c->get($id)->get('veto');
            self::assertSame(['7000', 'revocation', $ref], [$v->get('at')->lexeme, $v->get('via'), $v->get('by')]);
        }
        self::assertSame(['vetoed', 'vetoed'], self::kinds($h));
        self::assertSame(['at', 'via', 'by'], $h->notices[0]['record']->get('veto')->keys());
    }

    /** Without a veto policy a revocation keeps the window, alerts and tells the principal. */
    public function testRevocationKeepsTheWindowByDefault(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        [$a] = self::opened($c, $h);
        $ref = $a['pcactn']->get('grant_ref');
        $h->notices = [];
        self::assertSame([], $c->onRevocation($ref));
        self::assertSame([['level' => 'warning', 'code' => 'revoked_open_window', 'record' => $a['id'],
            'reason' => "grant $ref was revoked while this window is open; the principal can still undo it"]], $h->alerts);
        self::assertSame(['revoked'], self::kinds($h));
        self::assertSame($a['id'], $h->notices[0]['record']->get('id'));
        self::assertSame('open', $c->get($a['id'])->get('state'));
    }

    /** A slash needs a bond ledger, from the coordinator or the call. */
    public function testSlashNeedsABondLedger(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        try {
            $c->rollbackOnSlash(['claimId' => 'x']);
            self::fail('no bond ledger must be refused');
        } catch (UndoError $e) {
            self::assertSame('config: rollbackOnSlash needs a bond ledger (pass bonds to the coordinator or to this call)', $e->getMessage());
        }
    }

    /** A slash vetoes the open window holding that bond (before one whose id is the claim) with the settlement digest as evidence. */
    public function testSlashVetoesTheBondedWindow(): void
    {
        $h = new Money10Undo();
        $c = self::mk($h);
        $bonds = new Money10Bonds();
        [$x] = self::opened($c, $h);
        [$y] = self::opened($c, $h, false, ['ref' => $x['id'], 'challengeEndsAt' => 0]);
        $h->notices = [];
        $h->now = 8000;
        $res = $c->rollbackOnSlash(['claimId' => $x['id']], $bonds);
        self::assertSame(['settlement', 'veto'], array_keys($res));
        self::assertSame([['claimId' => $x['id']]], $bonds->slashed);
        self::assertTrue($res['veto']['ok']);
        self::assertSame(['open', 'vetoed'], [$c->get($x['id'])->get('state'), $c->get($y['id'])->get('state')]);
        $v = $c->get($y['id'])->get('veto');
        self::assertSame(['8000', 'fraud_proof', $x['id'], IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/undo-slash-ref/v1', 'settlement' => $res['settlement']]))],
            [$v->get('at')->lexeme, $v->get('via'), $v->get('by'), $v->get('evidence')]);
        self::assertSame(['at', 'via', 'by', 'evidence'], $h->notices[0]['record']->get('veto')->keys());
        self::assertSame([], $h->alerts);
    }

    /** A slash with no record reports unknown; one whose window is closed alerts that the effect could not be rolled back. */
    public function testSlashWithoutARollback(): void
    {
        $h = new Money10Undo();
        $bonds = new Money10Bonds();
        $c = self::mk($h, ['bonds' => $bonds]);
        $res = $c->rollbackOnSlash(['claimId' => 'nobody']);
        self::assertSame(['ok' => false, 'code' => 'unknown', 'reason' => 'no undo record for bond nobody'], $res['veto']);
        self::assertTrue($res['settlement']->get('slashed'));
        [$z] = self::opened($c, $h);
        $c->recordEffect($z['id'], Obj::of(['id' => 'p']));
        $h->now = self::WE + 1;
        $c->finalizeDue();
        $res = $c->rollbackOnSlash(['claimId' => $z['id']]);
        self::assertFalse($res['veto']['ok']);
        self::assertSame([['level' => 'critical', 'code' => 'slash_after_window', 'record' => $z['id'],
            'reason' => 'the bond was slashed but the effect could not be rolled back: the window is closed and the action is final']], $h->alerts);
    }
}
