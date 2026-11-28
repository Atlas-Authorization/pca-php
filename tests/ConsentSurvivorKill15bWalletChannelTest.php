<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\HarmModel;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SignersMore;
use Atlas\Pca\SlidingWindowCounter;
use Atlas\Pca\Wallet;
use Atlas\Pca\WalletChannel;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\TestCase;

/**
 * group 15b mutation kills for src/WalletChannel.php (the trusted question channel). Own fixture: the outcome space A of
 * ref-wallet.json.gz plus small purpose-built verbs, site questions signed here with the conformance site key, a scripted clock and
 * random source, and a grant view whose p / veto / ceiling are plain maps.
 */
final class ConsentSurvivorKill15bWalletChannelTest extends TestCase
{
    private const SESSION = 'ZOKE4PNj8SR5mKihSA9uaPYt89NkEDL5jQr7jKBK4_w';
    private const MAP = 'JULAYu_0cmFDp_HxbwU8OnSkluwhXEM_41PqrLXvw9Q';
    private const SCHEMA = 'uWFeZ-VptGJi8L1HRflPb-dF5XD0jIQkICZAsUpVaOo';
    private const PCACTN = 'F4bqUUPgMmSOkJkjyKiCsL2AsmRizye1wxF6g7EEQSc';
    private const T0 = 1800000000000;
    /** noise-free (no double confirmation) and never frozen by load */
    private const FAT0 = ['betaF' => 0.005, 'etaStop' => 0.99, 'deltaC' => 0.05, 'freezeOn' => 'mean', 'assumeNoiseFree' => true, 'delta' => 0.05];
    /** under estimated noise (an irreversible yes needs a second confirmation), never frozen */
    private const FATN = ['betaF' => 0.005, 'etaStop' => 0.99, 'deltaC' => 0.05, 'freezeOn' => 'mean', 'assumeNoiseFree' => false, 'delta' => 0.05];
    private const MAX_SAFE = 9007199254740991;

    private Obj $omega;
    private int $t = self::T0;
    private mixed $counts = Wallet::EMPTY_NOISE;
    /** @var list<mixed> */
    private array $rands = [];
    private int $ri = 0;
    /** @var array<string,float> */
    private array $p = [];
    /** @var array<string,true> */
    private array $veto = [];
    /** @var array<string,true> */
    private array $ceil = [];
    /** @var list<array{verb:string,idx:list<int>}> */
    private array $confirmed = [];
    /** @var array<string,Obj> */
    private array $lifts = [];

    protected function setUp(): void
    {
        class_exists(WalletChannel::class); // loads the wallet modules (HarmModel and SlidingWindowCounter live in them)
        $this->omega = self::omega();
    }

    // ---- fixture ---------------------------------------------------------------------------------------------------------------

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    /** @param list<array{0:string,1:string}> $values */
    private static function cat(string $path, array $values): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => $path, 'values' => array_map(static fn(array $v): Obj => Obj::of(['kind' => $v[0], 'value' => $v[1]]), $values)]);
    }

    /** @return list<array{0:string,1:string}> exact values plus the other cell */
    private static function ex(string ...$v): array
    {
        return [...array_map(static fn(string $s): array => ['exact', $s], $v), ['other', WalletOmega::OTHER]];
    }

    private static function verb(string $name, string $rev, int|float $weight, array $dims): Obj
    {
        return Obj::of(['verb' => $name, 'reversibility' => $rev, 'weight' => $weight, 'dims' => $dims]);
    }

    /** Outcome space A (stripe.refund, files.read, http.post) and the verbs the kills need. */
    private static function omega(): Obj
    {
        $amount = Obj::of(['kind' => 'num', 'path' => 'action.params.amount', 'lo' => 0, 'hi' => 100000, 'cuts' => [100, 1000, 10000], 'dist' => 'loguniform']);
        $verbs = RefWalletDifferentialTest::omegas()['A']->get('verbs');
        $verbs[] = self::verb('tiny.op', 'reversible', 0.1, [self::cat('action.resource', self::ex('x1', 'x2'))]);
        $verbs[] = self::verb('z1', 'reversible', 0, [self::cat('action.resource', self::ex('a', 'b', 'c'))]);
        $verbs[] = self::verb('z2', 'reversible', 0, [self::cat('action.resource', self::ex('a', 'b')), self::cat('action.params.k', self::ex('a', 'b'))]);
        $verbs[] = self::verb('twin.a', 'irreversible', 0.1, [$amount]);
        $verbs[] = self::verb('twin.b', 'irreversible', 0.1, [$amount]);
        $verbs[] = self::verb('prov.op', 'reversible', 0.1, [self::cat('action.resource', self::ex('web', 'r2')),
            self::cat('env.prov.src', [['exact', 'tool|web'], ['exact', 'trusted'], ['prefix', 'first_party'], ['other', WalletOmega::OTHER]])]);
        $verbs[] = self::verb('big', 'reversible', 0.1, [self::cat('action.resource', self::ex(...array_map(static fn(int $i): string => "v$i", range(0, 63)))),
            self::cat('action.params.q', self::ex(...array_map(static fn(int $i): string => "w$i", range(0, 240))))]);
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    private function vs(string $verb): Obj
    {
        foreach ($this->omega->get('verbs') as $v) {
            if ($v->get('verb') === $verb) {
                return $v;
            }
        }
        throw new \LogicException("no verb $verb");
    }

    private static function site(): Obj
    {
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed('wallet/site')));
        return Obj::of(['origin' => 'https://shop.example.com', 'name' => 'Example Shop', 'keys' => [Obj::of(['kid' => 'site-k1', 'alg' => 'ed25519', 'pk' => Pca::b64u($pk)])]]);
    }

    private static function units(): Obj
    {
        return Obj::of(['action.params.amount' => Obj::of(['kind' => 'money', 'currency' => 'USD', 'exponent' => new Num('2')])]);
    }

    private function rand(): mixed
    {
        if ($this->rands !== []) {
            return array_shift($this->rands);
        }
        return fmod(++$this->ri * 0.6180339887498949, 1.0);
    }

    /** The default lift: a synthetic action maps to its recorded cell representative, a real one to its values plus the env facts. */
    private function lift(mixed $a): Obj
    {
        $r = Js::opt($a, 'resource');
        if (is_string($r) && isset($this->lifts[$r])) {
            return $this->lifts[$r];
        }
        $v = Wallet::actionValuesOf($a);
        $v->get('values')->set('env.acc.spend.post', new Num('1000'));
        $v->get('values')->set('env.prov.recipient', 'trusted');
        return $v;
    }

    /** @return array{p:\Closure,vetoed:\Closure,outsideCeiling:\Closure,confirmed:\Closure} */
    private function view(): array
    {
        return [
            'p' => fn(mixed $v, array $i): float => $this->p[Wallet::cellKey($v, $i)] ?? 0.5,
            'vetoed' => fn(mixed $v, array $i): bool => isset($this->veto[Wallet::cellKey($v, $i)]),
            'outsideCeiling' => fn(mixed $v, array $i): bool => isset($this->ceil[Wallet::cellKey($v, $i)]),
            'confirmed' => fn(): array => $this->confirmed,
        ];
    }

    /** @param array<string,mixed> $over a null value removes the option */
    private function chan(array $over = []): WalletChannel
    {
        $o = [
            'omega' => $this->omega, 'session' => self::SESSION, 'mapDigest' => static fn(): string => self::MAP, 'principalSecret' => self::seed('wallet/principal'),
            'site' => self::site(), 'view' => $this->view(), 'hourly' => new SlidingWindowCounter(),
            'noise' => fn(): mixed => $this->counts,
            'onNoise' => function (mixed $n): void {
                $this->counts = $n;
            },
            'rand' => fn(): mixed => $this->rand(), 'now' => fn(): int => $this->t,
            'rho' => 0, 'fatigue' => self::FAT0, 'units' => self::units(), 'lift' => fn(mixed $a): Obj => $this->lift($a),
        ];
        foreach ($over as $k => $v) {
            if ($v === null) {
                unset($o[$k]);
            } else {
                $o[$k] = $v;
            }
        }
        return new WalletChannel($o);
    }

    /** A site-signed intent_required for the box `$coords` of `$verb`. */
    private function ir(string $verb, Obj $coords, string $qid, string $digest, string $friction = 'tap', ?int $exp = null): Obj
    {
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-intent-required', 'session' => self::SESSION, 'map_digest' => self::MAP, 'schema' => self::SCHEMA,
            'pcactn_digest' => self::PCACTN, 'action_digest' => $digest, 'cell' => Obj::of(['verb' => $verb, 'coords' => $coords]), 'reason' => 'uncertain',
            'question_id' => $qid, 'friction' => $friction, 'delivered_to' => 'wallet', 'expires_at' => new Num((string)($exp ?? $this->t + 60000))]);
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed('wallet/site')));
        $b->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => 'site-k1',
            'value' => Pca::b64u(sodium_crypto_sign_detached(SignersMore::INTENT_REQUIRED_DOMAIN . Json::canonicalizeNative($b), $sk))]));
        return $b;
    }

    /** @param list<list<int>> $box @return array<string,mixed> */
    private function recv(WalletChannel $ch, Obj $action, array $box, string $qid, string $friction = 'tap', ?int $exp = null): array
    {
        $verb = (string)$action->get('verb');
        $ir = $this->ir($verb, Wallet::coordsOfBox($this->vs($verb), $box), $qid, Wallet::pcaActionDigest($action), $friction, $exp);
        return $ch->receive($ir, Obj::of(['action' => $action]));
    }

    /** A synthetic action whose lift is `$lifted` (default: the representative of the cell `$idx`). @param list<int> $idx */
    private function cellAction(string $verb, array $idx, ?Obj $lifted = null): Obj
    {
        $res = 'syn:' . count($this->lifts);
        $this->lifts[$res] = $lifted ?? WalletOmega::cellRep($this->vs($verb), $idx);
        return Obj::of(['verb' => $verb, 'resource' => $res, 'params' => new Obj(), 'reversibility_class' => 'reversible']);
    }

    /** Ask the single cell `$idx`. @param list<int> $idx @return array<string,mixed> */
    private function cell(WalletChannel $ch, string $verb, array $idx, string $qid, string $friction = 'tap'): array
    {
        return $this->recv($ch, $this->cellAction($verb, $idx), array_map(static fn(int $i): array => [$i], $idx), $qid, $friction);
    }

    private static function refund(int $amount): Obj
    {
        return Obj::of(['verb' => 'stripe.refund', 'resource' => 'charge:ch_1', 'params' => Obj::of(['amount' => new Num((string)$amount), 'currency' => 'usd']),
            'reversibility_class' => 'irreversible']);
    }

    /** The stripe.refund cell of refund($amount): amount interval, charge:ch_1, spend [1000, 5000], recipient trusted. */
    private static function refundBox(int $amount): array
    {
        $i = $amount < 100 ? 0 : ($amount < 1000 ? 1 : ($amount < 10000 ? 2 : 3));
        return [[$i], [0], [1], [3]];
    }

    private static function twin(string $verb): Obj
    {
        return Obj::of(['verb' => $verb, 'resource' => 'twin', 'params' => Obj::of(['amount' => new Num('500'), 'currency' => 'usd']), 'reversibility_class' => 'irreversible']);
    }

    private static function file(string $res): Obj
    {
        return Obj::of(['verb' => 'files.read', 'resource' => $res, 'params' => new Obj(), 'reversibility_class' => 'reversible']);
    }

    private static function yes(?string $typed = null): Obj
    {
        return $typed === null ? Obj::of(['answer' => 'yes']) : Obj::of(['answer' => 'yes', 'typed' => $typed]);
    }

    /** @return list<string> question ids of a screen */
    private static function ids(?array $screen): array
    {
        self::assertNotNull($screen);
        return array_map(static fn(array $q): string => $q['questionId'], $screen['questions']);
    }

    private static function clarifyBody(string ...$files): Obj
    {
        return Obj::of(['reason' => 'multiple_options',
            'candidates' => array_map(static fn(string $f): Obj => Obj::of(['verb' => 'files.read', 'values' => Obj::of(['action.resource' => $f])]), $files)]);
    }

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('expected a throw');
    }

    private static function assertThrown(string $class, string $message, callable $f): void
    {
        $e = self::thrown($f);
        self::assertSame($class, get_class($e), $e->getMessage());
        self::assertSame($message, $e->getMessage());
    }

    // ---- learnerView -----------------------------------------------------------------------------------------------------------

    public function testLearnerView(): void
    {
        $files = $this->vs('files.read');
        $http = $this->vs('http.post');
        $l = new IntentLearner(Obj::of(['v' => 1, 'approximate' => [], 'verbs' => [$files, $http]]));
        $l->observe(IntentOmega::cellRep($files, [0]), 1);
        $l->observe(IntentOmega::cellRep($files, [1]), 1);
        $l->observe(IntentOmega::cellRep($http, [1, 0]), 1);
        $v = WalletChannel::learnerView($l);
        self::assertSame(['p', 'vetoed', 'outsideCeiling', 'confirmed'], array_keys($v));
        // the second verb resolves to its own outcome space
        self::assertSame($l->acceptance(IntentOmega::cellRep($http, [1, 0])), $v['p']('http.post', [1, 0]));
        self::assertSame($l->acceptance(IntentOmega::cellRep($files, [2])), $v['p']('files.read', [2]));
        self::assertSame($l->isVetoed(IntentOmega::cellRep($http, [2, 1])), $v['vetoed']('http.post', [2, 1]));
        self::assertThrown(\InvalidArgumentException::class, 'learnerView: unknown verb nope', static fn() => $v['p']('nope', [0]));
        self::assertThrown(\InvalidArgumentException::class, 'learnerView: unknown verb integer', static fn() => $v['vetoed'](5, [0]));
        // no ceiling: nothing is outside
        self::assertFalse($v['outsideCeiling']('files.read', [0]));
        $want = [];
        foreach ($l->cells() as $c) {
            if ($c['inGrant']) {
                $want[] = ['verb' => $c['verb'], 'idx' => $c['cell']];
            }
        }
        self::assertGreaterThanOrEqual(2, count($want));
        self::assertLessThan(count($l->cells()), count($want));
        self::assertSame($want, $v['confirmed']());
        $in = WalletChannel::learnerView($l, ['insideCeiling' => static fn(mixed $verb, array $idx): bool => $idx === [0]]);
        self::assertFalse($in['outsideCeiling']('files.read', [0]));
        self::assertTrue($in['outsideCeiling']('files.read', [1]));
        // a non-Closure predicate is no ceiling
        self::assertFalse(WalletChannel::learnerView($l, ['insideCeiling' => 'strlen'])['outsideCeiling']('files.read', [1]));
    }

    // ---- options -----------------------------------------------------------------------------------------------------------------

    public function testMissingOption(): void
    {
        $ch = $this->chan(['now' => null]);
        self::assertThrown(\InvalidArgumentException::class, 'missing option now', fn() => $this->recv($ch, self::file('file:a'), [[0]], 'q1'));
    }

    public function testDefaultSessionCapIsSix(): void
    {
        $ch = $this->chan();
        $n = 0;
        foreach ([[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]] as $idx) {
            self::assertTrue($this->cell($ch, 'http.post', $idx, 'q' . ++$n)['ok']);
        }
        self::assertSame(['ok' => false, 'code' => 'cap_session', 'reason' => 'at most 6 questions per session'], $this->cell($ch, 'http.post', [2, 0], 'q7'));
    }

    public function testDefaultHourCapIsTwelve(): void
    {
        $hourly = new SlidingWindowCounter();
        for ($i = 0; $i < 11; $i++) {
            $hourly->tryAdd($this->t, self::MAX_SAFE);
        }
        $ch = $this->chan(['hourly' => $hourly, 'caps' => ['perSession' => 100]]);
        self::assertTrue($this->cell($ch, 'http.post', [0, 0], 'q1')['ok']);
        self::assertSame(['ok' => false, 'code' => 'cap_hour', 'reason' => 'at most 12 questions per hour'], $this->cell($ch, 'http.post', [0, 1], 'q2'));
    }

    /** newId: six random bits per character, `rand` read as a float (a non-number is 0), the index taken mod 64. */
    public function testQuestionIdAlphabet(): void
    {
        foreach ([['x', 'q_AAAAAAAAAA'], [1.0, 'q_AAAAAAAAAA'], [63 / 64, 'q__________']] as [$r, $want]) {
            $this->rands = array_fill(0, 10, $r);
            $res = $this->chan()->clarify(self::clarifyBody('file:a'));
            self::assertSame($want, $res['questionId'] ?? null);
            $this->rands = [];
        }
    }

    public function testCustomHarmAndThresholds(): void
    {
        $harm = new HarmModel(static fn(mixed $vs): float => 4.0, static fn(mixed $d, mixed $x): float => 1.0);
        $ch = $this->chan(['harm' => $harm, 'friction' => ['hTap' => 3.9, 'hDevice' => 100000]]);
        // two tiny.op cells of harm 4: E[h | box] = 4 >= h_tap, so the box is a hold question
        $r = $this->recv($ch, $this->cellAction('tiny.op', [0]), [[0, 1]], 'q1');
        self::assertSame('hold', $r['friction'] ?? null);
    }

    public function testZeroMassBox(): void
    {
        $ch = $this->chan(['friction' => ['hTap' => 0.5, 'hDevice' => 100000]]);
        // a verb of weight 0: no mass, so the mean harm is 0 (no division) and the question is a tap
        self::assertSame(['ok' => true, 'questionId' => 'q1', 'friction' => 'tap'], $this->cell($ch, 'z1', [0], 'q1'));
    }

    public function testBoxCellLimitDefault(): void
    {
        $ch = $this->chan();
        $r = $this->recv($ch, $this->cellAction('big', [0, 0]), [range(0, 63), range(0, 63)], 'q1');
        self::assertNotSame('cell_too_large', $r['code'] ?? null); // 4096 cells is the limit itself
        $r = $this->recv($this->chan(), $this->cellAction('big', [0, 0]), [range(0, 16), range(0, 240)], 'q2');
        self::assertSame(['ok' => false, 'code' => 'cell_too_large', 'reason' => 'the question covers too many cells'], $r);
    }

    /** The reversibility option (a Closure) decides the card's text and, irreversible, the friction; a typed tier with nothing to type is device. */
    public function testReversibilityOption(): void
    {
        $seen = [];
        $ch = $this->chan(['reversibility' => function (mixed $vs, array $box) use (&$seen): string {
            $seen[] = $box;
            return 'irreversible';
        }]);
        $r = $this->cell($ch, 'tiny.op', [0], 'q1');
        self::assertSame('device', $r['friction'] ?? null);
        self::assertNotSame([], $seen);
        $card = $ch->nextScreen()['questions'][0]['card'];
        self::assertStringContainsString('that cannot be undone', (string)$card->get('sentence'));
    }

    /** The irreversible flag and the friction input read the option separately: with no double confirmation the flag adds nothing. */
    public function testIrreversibleWithoutDoubleConfirmation(): void
    {
        $q = ['irreversible', 'reversible', 'reversible', 'reversible'];
        $ch = $this->chan(['reversibility' => function () use (&$q): string {
            return array_shift($q) ?? 'reversible';
        }]);
        self::assertSame('tap', $this->recv($ch, self::file('file:a'), [[0]], 'q1')['friction'] ?? null);
    }

    public function testProvenanceFriction(): void
    {
        $crit = ['src' => 'critical', 'source' => 'critical'];
        // src trusted (exact): untainted, the resource dimension is not provenance
        self::assertSame('tap', $this->cell($this->chan(['sensitivity' => $crit]), 'prov.op', [0, 1], 'q1')['friction'] ?? null);
        // src tool|web: tainted critical -> typed (nothing to type -> device)
        self::assertSame('device', $this->cell($this->chan(['sensitivity' => ['src' => 'critical']]), 'prov.op', [1, 0], 'q2')['friction'] ?? null);
        // src prefix first_party: an open-ended level is the least trusted
        self::assertSame('device', $this->cell($this->chan(['sensitivity' => ['src' => 'critical']]), 'prov.op', [1, 2], 'q3')['friction'] ?? null);
    }

    public function testIdentityWidening(): void
    {
        // a prefix value on a cat dimension that is not an identity path does not widen
        $r = $this->recv($this->chan(), self::refund(500), [[1], [0, 2], [1], [3]], 'q1');
        self::assertSame('typed', $r['friction'] ?? null);
        // exact values on an identity path do not widen
        $r = $this->recv($this->chan(['identityPaths' => ['action.resource']]), self::refund(500), self::refundBox(500), 'q2');
        self::assertSame('typed', $r['friction'] ?? null);
    }

    // ---- receive / render --------------------------------------------------------------------------------------------------------

    public function testReceiveWithoutLift(): void
    {
        self::assertSame(['ok' => true, 'questionId' => 'q1', 'friction' => 'tap'], $this->recv($this->chan(['lift' => null]), self::file('file:a'), [[0]], 'q1'));
    }

    public function testReceiveRenderFails(): void
    {
        // the lift moves the action to the twin verb: same cell index, so the box check passes, but the card refuses another verb
        $act = $this->cellAction('twin.a', [1], Obj::of(['verb' => 'twin.b', 'values' => Obj::of(['action.params.amount' => new Num('500')])]));
        self::assertSame(['ok' => false, 'code' => 'render_failed', 'reason' => 'the card could not be rendered'], $this->recv($this->chan(), $act, [[1]], 'q1'));
    }

    public function testCountRefusedIsUnreachable(): void
    {
        $hourly = new class {
            public function count(mixed $now): int
            {
                return 0;
            }

            public function tryAdd(mixed $now, mixed $cap): bool
            {
                return false;
            }
        };
        $ch = $this->chan(['hourly' => $hourly]);
        self::assertThrown(\RuntimeException::class, 'unreachable', fn() => $this->recv($ch, self::file('file:a'), [[0]], 'q1'));
    }

    // ---- canaries ------------------------------------------------------------------------------------------------------------------

    public function testCanaryVerbMustExist(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $this->ceil = ['files.read|3' => true];
        $omega = $this->omega;
        $n = 0;
        $ch = $this->chan(['rho' => 1, 'rand' => static function () use (&$n, $omega): float {
            if (++$n === 2) { // the pick is made: the outcome space loses the canary's verb
                $omega->set('verbs', array_values(array_filter($omega->get('verbs'), static fn(Obj $v): bool => $v->get('verb') !== 'files.read')));
            }
            return 0.0;
        }]);
        self::assertThrown(\InvalidArgumentException::class, 'unknown verb', fn() => $this->cell($ch, 'http.post', [0, 0], 'q1'));
    }

    /** With a high-friction real question pending the session is not low-harm: a second canary is inserted. */
    public function testCanaryHighHarmSession(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $this->ceil = ['files.read|1' => true, 'files.read|3' => true];
        $ch = $this->chan(['rho' => 1]);
        self::assertTrue($this->recv($ch, self::refund(500), self::refundBox(500), 'q1')['ok']);
        self::assertTrue($this->recv($ch, self::refund(5000), self::refundBox(5000), 'q2')['ok']);
        self::assertSame(2, $ch->summary()['canaries']);
    }

    /** Only tap / hold questions pending: one canary per low-harm session. */
    public function testCanaryLowHarmSession(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $this->ceil = ['files.read|1' => true, 'files.read|3' => true];
        $ch = $this->chan(['rho' => 1]);
        self::assertSame('tap', $this->recv($ch, self::file('file:a'), [[0]], 'q1')['friction'] ?? null);
        self::assertSame('hold', $this->cell($ch, 'http.post', [0, 0], 'q2')['friction'] ?? null);
        self::assertSame(1, $ch->summary()['canaries']);
    }

    /** A cell already used as a canary is never a canary again, even once answered. */
    public function testCanaryUsedOnce(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $this->ceil = ['files.read|3' => true];
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::file('file:a'), [[0]], 'q1');
        $ids = self::ids($ch->nextScreen());
        self::assertCount(2, $ids);
        $canary = $ids[0] === 'q1' ? $ids[1] : $ids[0];
        self::assertSame('canary', $ch->answer($canary, Obj::of(['answer' => 'no']))['kind'] ?? null);
        self::assertTrue($this->recv($ch, self::refund(500), self::refundBox(500), 'q2')['ok']);
        self::assertSame(1, $ch->summary()['canaries']);
    }

    /** A pending question's cell is never a canary (here it became a ceiling cell after it was asked). */
    public function testCanaryExcludesPendingCells(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::file('dir:x'), [[3]], 'q1');
        $this->ceil = ['files.read|3' => true];
        $this->cell($ch, 'http.post', [0, 0], 'q2');
        self::assertSame(0, $ch->summary()['canaries']);
    }

    /** A canary's friction is its own (never raised as irreversible), even under estimated noise. */
    public function testCanaryFrictionUnderNoise(): void
    {
        $this->confirmed = [['verb' => 'files.read', 'idx' => [2]]];
        $this->ceil = ['files.read|3' => true];
        $ch = $this->chan(['rho' => 1, 'fatigue' => self::FATN]);
        $this->recv($ch, self::file('file:a'), [[0]], 'q1');
        $s = $ch->nextScreen();
        self::assertCount(2, self::ids($s));
        foreach ($s['questions'] as $q) {
            self::assertSame('tap', $q['card']->get('friction'));
        }
    }

    // ---- known-yes canaries --------------------------------------------------------------------------------------------------------

    /** A verified typed yes on a single cell becomes a known-yes canary for exactly that cell. */
    public function testKnownYesCell(): void
    {
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        self::assertSame(['q1'], self::ids($ch->nextScreen()));
        self::assertSame('answer', $ch->answer('q1', self::yes('5.00'))['kind'] ?? null);
        $this->recv($ch, self::refund(5000), self::refundBox(5000), 'q2');
        self::assertSame(1, $ch->summary()['canaries']);
        $cards = [];
        foreach ([$ch->nextScreen(), $ch->nextScreen()] as $s) {
            foreach ($s['questions'] ?? [] as $q) {
                $cards[$q['questionId']] = $q['card'];
            }
        }
        unset($cards['q2']);
        self::assertCount(1, $cards);
        $want = Wallet::coordsOfCell($this->vs('stripe.refund'), [1, 0, 1, 3]);
        self::assertSame(Js::stringify(Wallet::jsPlain($want)), Js::stringify(Wallet::jsPlain(array_values($cards)[0]->get('coords'))));
    }

    /** A yes on a multi-cell box is no known-yes. */
    public function testKnownYesNeedsSingleCell(): void
    {
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::refund(500), [[1, 2], [0], [1], [3]], 'q1');
        $ch->nextScreen();
        self::assertSame('answer', $ch->answer('q1', self::yes('5.00'))['kind'] ?? null);
        $this->recv($ch, self::refund(50), self::refundBox(50), 'q2');
        self::assertSame(0, $ch->summary()['canaries']);
    }

    /** A tap yes is no known-yes (not high friction). */
    public function testKnownYesNeedsStrongTier(): void
    {
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::file('file:a'), [[0]], 'q1');
        $ch->nextScreen();
        self::assertSame('answer', $ch->answer('q1', self::yes())['kind'] ?? null);
        $this->recv($ch, self::file('file:b'), [[1]], 'q2');
        self::assertSame(0, $ch->summary()['canaries']);
    }

    /** A partly answer is no known-yes. */
    public function testKnownYesNeedsPlainYes(): void
    {
        $ch = $this->chan(['rho' => 1]);
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        $ch->nextScreen();
        $r = $ch->answer('q1', Obj::of(['answer' => 'partly', 'partial' => Obj::of(['path' => 'action.params.amount', 'upTo' => new Num('100')]), 'typed' => '5.00']));
        self::assertSame('answer', $r['kind'] ?? null);
        $this->recv($ch, self::refund(5000), self::refundBox(5000), 'q2');
        self::assertSame(0, $ch->summary()['canaries']);
    }

    // ---- clarification -----------------------------------------------------------------------------------------------------------

    /** The clarification pick weighs cells with the channel's harm model (file:b is heavier, the information gain is equal). */
    public function testClarifyUsesHarmOption(): void
    {
        $harm = new HarmModel(static fn(mixed $vs): float => 1.0, static fn(mixed $d, mixed $x): float => $x === 'file:b' ? 2.0 : 1.0);
        $ch = $this->chan(['harm' => $harm]);
        self::assertSame(200, $ch->clarify(self::clarifyBody('file:a', 'file:b'))['status']);
        self::assertSame(['file:b'], $ch->nextScreen()['questions'][0]['card']->get('coords')->get('action.resource'));
    }

    /**
     * eta+ capped at 0.5 enters the pick as 0.5 - 1e-9: the two information gains below are 9.3e-13 apart (a tie, the lower cell
     * index wins); with eta+ = 0.5 they would be 1.07e-12 apart and the higher one would win.
     */
    public function testClarifyEtaPosBelowHalf(): void
    {
        $this->counts = ['falseYes' => 50, 'correctNo' => 0, 'falseNo' => 0, 'correctYes' => 0];
        $this->p = ['files.read|0' => 0.25, 'files.read|1' => 0.7625761427677713];
        $ch = $this->chan(['fatigue' => self::FATN]);
        self::assertSame(0.5, $ch->noise()['etaPosBar']);
        self::assertSame(200, $ch->clarify(self::clarifyBody('file:a', 'file:b'))['status']);
        self::assertSame(['file:a'], $ch->nextScreen()['questions'][0]['card']->get('coords')->get('action.resource'));
    }

    /** The same for eta- (capped at 0.5 by many false noes). */
    public function testClarifyEtaNegBelowHalf(): void
    {
        $this->counts = ['falseYes' => 0, 'correctNo' => 0, 'falseNo' => 50, 'correctYes' => 0];
        $this->p = ['files.read|1' => 0.25, 'files.read|0' => 0.7369923086757778];
        $ch = $this->chan(['fatigue' => self::FATN]);
        self::assertSame(0.5, $ch->noise()['etaNegBar']);
        self::assertSame(200, $ch->clarify(self::clarifyBody('file:b', 'file:a'))['status']);
        self::assertSame(['file:a'], $ch->nextScreen()['questions'][0]['card']->get('coords')->get('action.resource'));
    }

    public function testClarifyNonClosureLiftIgnored(): void
    {
        $r = $this->chan(['liftCandidate' => 'not-a-closure'])->clarify(self::clarifyBody('file:a'));
        self::assertSame(200, $r['status']);
        self::assertIsString($r['questionId'] ?? null);
    }

    public function testClarifySingleCellOverLimit(): void
    {
        $ch = $this->chan(['maxBoxCells' => 0]);
        self::assertThrown(\RuntimeException::class, 'a single cell exceeds the box limit', static fn() => $ch->clarify(self::clarifyBody('file:a')));
    }

    public function testClarifyRenderFails(): void
    {
        $n = 0;
        $lift = static function (mixed $c) use (&$n): mixed {
            return ++$n === 1 ? $c : Obj::of(['verb' => 'http.post', 'values' => new Obj()]); // the second lift (for the card) names another verb
        };
        $r = $this->chan(['liftCandidate' => $lift])->clarify(self::clarifyBody('file:a'));
        self::assertSame(200, $r['status'] ?? null);
        self::assertSame('render_failed', $r['refused'] ?? null);
        self::assertSame(['status', 'verdicts', 'refused'], array_keys($r));
    }

    // ---- ordering and screens ------------------------------------------------------------------------------------------------------

    /** Equal friction and weight: the lower flat cell index first, across verbs of different arity. */
    public function testOrderByFlatIndex(): void
    {
        $ch = $this->chan();
        $this->cell($ch, 'z1', [2], 'qa');
        $this->cell($ch, 'z2', [0, 0], 'qb');
        self::assertSame(['qb', 'qa'], self::ids($ch->nextScreen()));
    }

    public function testExpiryBoundary(): void
    {
        $ch = $this->chan();
        $this->recv($ch, self::file('file:a'), [[0]], 'q1', 'tap', $this->t + 1000);
        $this->t += 1000; // now == expires_at: still valid
        self::assertSame(['q1'], self::ids($ch->nextScreen()));
        self::assertSame('answer', $ch->answer('q1', self::yes())['kind'] ?? null);
    }

    public function testHoldQuestionsShareAScreen(): void
    {
        $ch = $this->chan();
        $this->cell($ch, 'http.post', [0, 0], 'q1');
        $this->cell($ch, 'http.post', [0, 1], 'q2');
        self::assertCount(2, self::ids($ch->nextScreen()));
    }

    public function testDefaultThreePerScreen(): void
    {
        $ch = $this->chan();
        foreach ([0, 1, 2, 3] as $i) {
            $this->cell($ch, 'files.read', [$i], "q$i");
        }
        self::assertCount(3, self::ids($ch->nextScreen()));
    }

    /** The second confirmation waits (notBefore) while a later question is eligible: that one is shown. */
    public function testIneligibleFirstItem(): void
    {
        $ch = $this->chan(['fatigue' => self::FATN]);
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        $this->recv($ch, self::file('file:a'), [[0]], 'q2');
        self::assertSame(['q1'], self::ids($ch->nextScreen()));
        self::assertSame('pending_confirmation', $ch->answer('q1', self::yes('5.00'))['kind'] ?? null);
        self::assertSame(['q2'], self::ids($ch->nextScreen()));
    }

    public function testStateDigestSortsAskedCells(): void
    {
        $a = $this->chan();
        $this->recv($a, self::file('file:b'), [[1]], 'q2');
        $this->recv($a, self::file('file:a'), [[0]], 'q1');
        $b = $this->chan();
        $this->recv($b, self::file('file:a'), [[0]], 'q1');
        $this->recv($b, self::file('file:b'), [[1]], 'q2');
        self::assertSame($a->stateDigest(), $b->stateDigest());
    }

    // ---- answers ---------------------------------------------------------------------------------------------------------------------

    public function testResponseMustBeAnObject(): void
    {
        $ch = $this->chan();
        $this->recv($ch, self::file('file:a'), [[0]], 'q1');
        $ch->nextScreen();
        self::assertThrown(\TypeError::class, 'response is not an object', static fn() => $ch->answer('q1', 'yes'));
    }

    public function testBadPartial(): void
    {
        $ch = $this->chan();
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        $ch->nextScreen();
        $r = $ch->answer('q1', Obj::of(['answer' => 'partly', 'partial' => Obj::of(['path' => 'nope', 'upTo' => new Num('1')]), 'typed' => '5.00']));
        self::assertSame(['ok' => false, 'code' => 'bad_response', 'reason' => 'the card has no field nope'], $r);
    }

    /** A partial given as an assoc array (any dict) is signed into the answer. */
    public function testArrayPartial(): void
    {
        $ch = $this->chan();
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        $ch->nextScreen();
        $r = $ch->answer('q1', ['answer' => 'partly', 'partial' => ['path' => 'action.params.amount', 'upTo' => new Num('100')], 'typed' => '5.00']);
        self::assertTrue($r['ok']);
        self::assertSame('answer', $r['kind']);
        self::assertTrue($r['answer']->has('partial'));
    }

    /** Under noise a reversible yes needs no second confirmation. */
    public function testReversibleYesUnderNoise(): void
    {
        $ch = $this->chan(['fatigue' => self::FATN]);
        $this->recv($ch, self::file('file:a'), [[0]], 'q1');
        $ch->nextScreen();
        self::assertSame('answer', $ch->answer('q1', self::yes())['kind'] ?? null);
    }

    /**
     * Two confirmations are counted per cell. A's second confirmation is answered at a weak tier (the caller downgraded the shown card):
     * A is not double-confirmed, even though B (same verb, another cell) has a strong yes three screens after A's first one.
     */
    public function testConfirmationsArePerCellSameVerb(): void
    {
        $ch = $this->chan(['fatigue' => self::FATN]);
        $this->recv($ch, self::refund(500), self::refundBox(500), 'qa');
        $this->confirmPairScenario($ch, self::refund(5000), self::refundBox(5000), '50.00');
    }

    /** The same with B on another verb at the same coordinates. */
    public function testConfirmationsArePerCellSameCoords(): void
    {
        $ch = $this->chan(['fatigue' => self::FATN]);
        $this->recv($ch, self::twin('twin.a'), [[1]], 'qa');
        $this->confirmPairScenario($ch, self::twin('twin.b'), [[1]], '5.00');
    }

    /** @param list<list<int>> $boxB */
    private function confirmPairScenario(WalletChannel $ch, Obj $actB, array $boxB, string $typedB): void
    {
        self::assertSame(['qa'], self::ids($ch->nextScreen())); // screen 1
        self::assertSame('pending_confirmation', $ch->answer('qa', self::yes('5.00'))['kind'] ?? null);
        self::assertSame('interstitial', $ch->nextScreen()['kind'] ?? null); // screen 2
        $s3 = $ch->nextScreen(); // screen 3: A's second confirmation
        $a2 = self::ids($s3)[0];
        self::assertNotSame('qa', $a2);
        self::assertTrue($this->recv($ch, $actB, $boxB, 'qb')['ok']);
        self::assertSame(['qb'], self::ids($ch->nextScreen())); // screen 4
        self::assertSame('pending_confirmation', $ch->answer('qb', self::yes($typedB))['kind'] ?? null);
        $s3['questions'][0]['card']->set('friction', 'tap');
        $r = $ch->answer($a2, self::yes());
        self::assertTrue($r['ok']);
        self::assertSame('pending_confirmation', $r['kind']);
        self::assertSame(['ok', 'kind', 'answer'], array_keys($r));
    }

    public function testHoldAtTheMinimum(): void
    {
        $ch = $this->chan();
        $this->recv($ch, self::file('file:a'), [[0]], 'q1', 'hold');
        $ch->nextScreen();
        self::assertSame('answer', $ch->answer('q1', Obj::of(['answer' => 'yes', 'holdMs' => new Num((string)Wallet::MIN_HOLD_MS)]))['kind'] ?? null);
    }

    /** @return array{0:WalletChannel,1:Obj} a shown typed refund question and its card */
    private function shownTyped(): array
    {
        $ch = $this->chan();
        $this->recv($ch, self::refund(500), self::refundBox(500), 'q1');
        return [$ch, $ch->nextScreen()['questions'][0]['card']];
    }

    public function testTypedCardWithoutTarget(): void
    {
        [$ch, $card] = $this->shownTyped();
        $card->set('typed', null);
        self::assertSame(['ok' => false, 'code' => 'tier_evidence', 'reason' => 'type the value shown on the card'], $ch->answer('q1', self::yes('5.00')));
    }

    public function testTypedTargetPathIsAString(): void
    {
        [$ch, $card] = $this->shownTyped();
        $card->set('typed', Obj::of(['path' => 5, 'mode' => 'number', 'prompt' => 'x']));
        self::assertSame(['ok' => false, 'code' => 'typed_mismatch', 'reason' => 'the typed value does not match the card'], $ch->answer('q1', self::yes('5.00')));
    }

    public function testUnknownTier(): void
    {
        [$ch, $card] = $this->shownTyped();
        $card->set('friction', 'bogus');
        self::assertThrown(\InvalidArgumentException::class, 'unknown friction tier', static fn() => $ch->answer('q1', self::yes('5.00')));
    }

    // ---- device tier -----------------------------------------------------------------------------------------------------------------

    private static function device(?Obj $signCounts): Obj
    {
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed('wallet/device')));
        $d = Obj::of(['rpId' => 'wallet.example.com', 'origins' => ['https://wallet.example.com'],
            'credentials' => Obj::of(['cred1' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u($pk)])])]);
        if ($signCounts !== null) {
            $d->set('signCounts', $signCounts);
        }
        return $d;
    }

    private static function assertion(string $challenge, int $count): Obj
    {
        $ad = hash('sha256', 'wallet.example.com', true) . "\x05" . pack('N', $count);
        $cd = '{"type":"webauthn.get","challenge":"' . $challenge . '","origin":"https://wallet.example.com","crossOrigin":false}';
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed('wallet/device')));
        return Obj::of(['answer' => 'yes', 'webauthn' => Obj::of(['credential_id' => 'cred1', 'authenticator_data' => Pca::b64u($ad),
            'client_data_json' => Pca::b64u($cd), 'signature' => Pca::b64u(sodium_crypto_sign_detached($ad . hash('sha256', $cd, true), $sk))])]);
    }

    /** A reversible JIT question at device tier (the site's minimum): shown, its challenge does not bind the action. */
    private function deviceQuestion(?Obj $signCounts): WalletChannel
    {
        $ch = $this->chan(['device' => self::device($signCounts)]);
        self::assertSame('device', $this->recv($ch, self::file('file:a'), [[0]], 'q1', 'device')['friction'] ?? null);
        self::assertNull($ch->deviceChallengeFor('q1')); // not shown yet
        $card = $ch->nextScreen()['questions'][0]['card'];
        self::assertSame(Wallet::deviceChallenge('q1', $card->get('rendered_digest'), new Num('1'), null), $ch->deviceChallengeFor('q1'));
        return $ch;
    }

    public function testDeviceSignCountRegression(): void
    {
        $ch = $this->deviceQuestion(Obj::of(['cred1' => new Num('5')]));
        $r = $ch->answer('q1', self::assertion((string)$ch->deviceChallengeFor('q1'), 3));
        self::assertFalse($r['ok']);
        self::assertSame('tier_evidence', $r['code']);
        self::assertStringStartsWith('security key: signCount did not increase', $r['reason']);
    }

    public function testDeviceWithoutSignCounts(): void
    {
        $ch = $this->deviceQuestion(null);
        self::assertSame('answer', $ch->answer('q1', self::assertion((string)$ch->deviceChallengeFor('q1'), 1))['kind'] ?? null);
    }

    /** A stored count that is not a number reads as 0 (a credential never used). */
    public function testDeviceNonNumericStoredCount(): void
    {
        $counts = Obj::of(['cred1' => 'x']);
        $ch = $this->deviceQuestion($counts);
        self::assertSame('answer', $ch->answer('q1', self::assertion((string)$ch->deviceChallengeFor('q1'), 1))['kind'] ?? null);
        self::assertSame(1, $counts->get('cred1'));
    }
}
