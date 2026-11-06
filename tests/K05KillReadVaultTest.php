<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ReadVault.php';

use Atlas\Pca\Draws;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryVault;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\ReadSide;
use Atlas\Pca\ReadVault;
use PHPUnit\Framework\TestCase;

/** Tokenisation vault, aggregate grants and the draw source (mutation kills; the vectors cover the happy flows). */
final class K05KillReadVaultTest extends TestCase
{
    private const TWO48 = 281474976710656;

    /** @return array{0:string,1:string} [secret key, b64u public key] */
    private static function key(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x33", 32));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function p(): string
    {
        return self::key()[1];
    }

    private static function obj(mixed $a): mixed
    {
        return Json::parseLax((string)json_encode($a, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private static function signed(string $domain, Obj $b): Obj
    {
        return Obj::of(['body' => $b, 'sig' => Pca::b64u(sodium_crypto_sign_detached($domain . Json::canonicalizeStrict($b), self::key()[0]))]);
    }

    /** An object that is not an Obj but answers every Obj method (a fail-open probe for the instanceof guards). */
    private static function fake(Obj $o): object
    {
        return new class($o) {
            public function __construct(private Obj $o)
            {
            }

            public function __call(string $n, array $a): mixed
            {
                return $this->o->$n(...$a);
            }
        };
    }

    // ---- draw source --------------------------------------------------------------------------------------------------

    /** @return list<int> the first `$count` raw 48-bit values of a seed's stream (an independent reading of the stream). */
    private static function raw48(string $seed, int $count): array
    {
        $out = [];
        for ($b = 0; count($out) < $count; $b++) {
            $raw = Pca::unb64u(IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/dp-stream/v1', 'seed' => $seed, 'i' => $b])), 32);
            self::assertNotNull($raw);
            for ($k = 0; $k < 5; $k++) {
                $v = 0;
                for ($j = 0; $j < 6; $j++) {
                    $v = $v * 256 + ord($raw[$k * 6 + $j]);
                }
                $out[] = $v;
            }
        }
        return $out;
    }

    /** Reference rejection sampler over a raw stream; advances `$pos`. */
    private static function refUniform(array $raw, int &$pos, int $n): int
    {
        $limit = self::TWO48 - (self::TWO48 % $n);
        while (true) {
            $r = $raw[$pos++];
            if ($r < $limit) {
                return $r % $n;
            }
        }
    }

    public function testUniformRejectsOnlyTheTopRemainder(): void
    {
        // 2^48 mod n = 2^48 - 2n, so a third of the raw values are rejected
        $n = 93824992236886;
        $raw = self::raw48('k05-uniform-a', 300);
        $d = ReadVault::seededDraws('k05-uniform-a');
        $pos = 0;
        for ($i = 0; $i < 40; $i++) {
            self::assertSame(self::refUniform($raw, $pos, $n), $d->uniform($n), "draw $i");
        }
        self::assertGreaterThan(40, $pos); // some value was rejected
    }

    public function testUniformRejectsAValueEqualToTheLimit(): void
    {
        // a seed whose first raw value r0 is even and above 2/3 of 2^48: with n = r0/2 the acceptance limit is exactly r0
        $seed = null;
        $r0 = 0;
        for ($i = 0; $i < 2000 && $seed === null; $i++) {
            $r0 = self::raw48("k05-edge-$i", 1)[0];
            if ($r0 % 2 === 0 && 3 * $r0 > 2 * self::TWO48) {
                $seed = "k05-edge-$i";
            }
        }
        self::assertNotNull($seed);
        $n = intdiv($r0, 2);
        self::assertSame($r0, self::TWO48 - (self::TWO48 % $n));
        $raw = self::raw48($seed, 200);
        $pos = 0;
        $want = self::refUniform($raw, $pos, $n);
        self::assertGreaterThan(1, $pos);
        self::assertSame($want, ReadVault::seededDraws($seed)->uniform($n));
    }

    public function testUniformBounds(): void
    {
        foreach ([0, -1, 140737488355329] as $n) {
            $threw = false;
            try {
                ReadVault::seededDraws('s')->uniform($n);
            } catch (\RangeException) {
                $threw = true;
            }
            self::assertTrue($threw, "bound $n");
        }
        $v = ReadVault::seededDraws('s')->uniform(140737488355328);
        self::assertGreaterThanOrEqual(0, $v);
        self::assertLessThan(140737488355328, $v);
        self::assertSame(0, ReadVault::seededDraws('s')->uniform(1));
    }

    public function testLaplaceRejectsANonPositiveRate(): void
    {
        foreach ([0, -1] as $s) {
            $threw = false;
            try {
                ReadVault::discreteLaplace(ReadVault::seededDraws('s'), $s, 10);
            } catch (\RangeException) {
                $threw = true;
            }
            self::assertTrue($threw, "rate $s");
        }
    }

    public function testSecureSeedIs32Bytes(): void
    {
        $seed = (new \ReflectionProperty(Draws::class, 'seed'))->getValue(ReadVault::secureDraws());
        self::assertIsString($seed);
        self::assertNotNull(Pca::unb64u($seed, 32));
    }

    // ---- vault --------------------------------------------------------------------------------------------------------

    private static function rbody(): Obj
    {
        return self::obj(['v' => 1, 'id' => 'rg1', 'principal' => self::p(), 'issued_at' => 1000, 'expires_at' => 5000,
            'reads' => [['verb' => 'get', 'resource_prefix' => 'users/', 'purposes' => ['support'],
                'modes' => ['pii' => 'token', 'public' => 'show', 'secret' => 'hash'], 'default_mode' => 'drop']],
            'caps' => (object)[], 'sinks' => ['crm' => ['allow' => ['pii'], 'escalate' => []], 'email' => ['allow' => ['public'], 'escalate' => ['pii']]]]);
    }

    private static function rgrant(): Obj
    {
        return self::signed(ReadSide::READ_GRANT_DOMAIN, self::rbody());
    }

    private static function redactIn(array $over = []): Obj
    {
        $o = self::obj(array_merge(['principal' => self::p(), 'now' => 2000, 'verb' => 'get', 'resource' => 'users/42', 'purpose' => 'support',
            'schema' => ['fields' => ['email' => 'pii', 'h' => 'secret', 'name' => 'public'], 'required' => []],
            'record' => ['email' => 'alice@example.com', 'h' => 'hidden', 'name' => 'Alice'],
            'tighten' => (object)[], 'salt' => '0123456789abcdef', 'counts' => (object)[]], $over));
        $o->set('grant', self::rgrant());
        return $o;
    }

    public function testVaultStoresOnlyTokens(): void
    {
        $store = new MemoryVault();
        $r = ReadVault::redactReadWithVault(self::redactIn(), $store);
        self::assertSame('allow', $r['decision']);
        $tok = $r['view']->get('email');
        self::assertIsString($tok);
        self::assertStringStartsWith('tok_', $tok);
        self::assertSame(['cls' => 'pii', 'value' => 'alice@example.com', 'grant' => ReadSide::readGrantDigest(self::rbody()), 'exp' => 5000], $store->get($tok));
        $h = $r['view']->get('h');
        self::assertIsString($h);
        self::assertNull($store->get($h));
        self::assertNull($store->get('Alice'));
    }

    public function testVaultPassesADenialThroughWhole(): void
    {
        $r = ReadVault::redactReadWithVault(self::redactIn(['purpose' => 'other']), new MemoryVault());
        self::assertSame('deny', $r['decision']);
        self::assertArrayHasKey('code', $r);
        self::assertSame('no_read_scope', $r['code']);
        self::assertCount(6, $r);
    }

    private static function store(int $exp = 9999): MemoryVault
    {
        $s = new MemoryVault();
        $s->put('tok_a', ['cls' => 'pii', 'value' => 'secret-v', 'grant' => ReadSide::readGrantDigest(self::rbody()), 'exp' => $exp]);
        return $s;
    }

    private static function detIn(array $over = []): Obj
    {
        $o = Obj::of(array_merge(['grant' => self::rgrant(), 'principal' => self::p(), 'now' => 2000, 'sink' => 'crm', 'token' => 'tok_a', 'store' => self::store()], $over));
        return $o;
    }

    public function testDetokenizeEdges(): void
    {
        self::assertSame(['decision' => 'allow', 'code' => null, 'value' => 'secret-v'], ReadVault::detokenize(self::detIn()));
        self::assertSame(['decision' => 'allow', 'code' => null, 'value' => 'secret-v'], ReadVault::detokenize(self::detIn(['now' => 1000])));
        self::assertSame('not_yet', ReadVault::detokenize(self::detIn(['now' => 999]))['code']);
        self::assertSame(['decision' => 'deny', 'code' => 'expired', 'value' => null], ReadVault::detokenize(self::detIn(['now' => 5000])));
        self::assertSame('allow', ReadVault::detokenize(self::detIn(['now' => 4999]))['decision']);
        // the entry's own expiry
        self::assertSame(['decision' => 'deny', 'code' => 'expired', 'value' => null], ReadVault::detokenize(self::detIn(['now' => 3000, 'store' => self::store(3000)])));
        self::assertSame('allow', ReadVault::detokenize(self::detIn(['now' => 2999, 'store' => self::store(3000)]))['decision']);
        // grant shape
        self::assertSame('bad_grant', ReadVault::detokenize(self::detIn(['grant' => 'x']))['code']);
        $g = self::rgrant();
        $g->set('extra', 1);
        self::assertSame('bad_grant', ReadVault::detokenize(self::detIn(['grant' => $g]))['code']);
        // a store that answers like a VaultStore but is not one, and an input that answers like an Obj but is not one
        $inner = self::store();
        $notStore = new class($inner) {
            public function __construct(private MemoryVault $s)
            {
            }

            public function get(string $t): ?array
            {
                return $this->s->get($t);
            }

            public function put(string $t, array $e): void
            {
                $this->s->put($t, $e);
            }
        };
        self::assertSame(['decision' => 'deny', 'code' => 'bad_request', 'value' => null], ReadVault::detokenize(self::detIn(['store' => $notStore])));
        self::assertSame(['decision' => 'deny', 'code' => 'bad_request', 'value' => null], ReadVault::detokenize(self::fake(self::detIn())));
    }

    // ---- aggregate grants ---------------------------------------------------------------------------------------------

    private static function rule(array $over = []): array
    {
        return array_merge(['verb' => 'orders.stats', 'resource_prefix' => 'orders/', 'purposes' => ['analytics'], 'fns' => ['count', 'sum'],
            'min_group' => 2, 'clamp' => 100, 'epsilon_micro' => 0, 'dp' => false], $over);
    }

    private static function abody(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'ag1', 'principal' => self::p(), 'issued_at' => 1000, 'expires_at' => 5000,
            'rules' => [self::rule()], 'epsilon_budget_micro' => 1000, 'max_queries' => 5], $over);
    }

    private static function ab(array $over): bool
    {
        return ReadVault::validAggregateGrantBody(self::obj(self::abody($over)));
    }

    private static function ar(array $over): bool
    {
        return self::ab(['rules' => [self::rule($over)]]);
    }

    public function testAggregateRuleShape(): void
    {
        self::assertTrue(self::ar([]));
        self::assertFalse(self::ab(['rules' => ['x']]));
        self::assertFalse(self::ar(['extra' => 1]));
        self::assertTrue(self::ar(['verb' => str_repeat('v', 128)]));
        self::assertFalse(self::ar(['verb' => str_repeat('v', 129)]));
        self::assertFalse(self::ar(['verb' => '']));
        self::assertTrue(self::ar(['resource_prefix' => str_repeat('r', 512)]));
        self::assertFalse(self::ar(['resource_prefix' => str_repeat('r', 513)]));
        self::assertFalse(self::ar(['resource_prefix' => '']));
        $p16 = [];
        for ($i = 0; $i < 17; $i++) {
            $p16[] = sprintf('p%02d', $i);
        }
        $p17 = $p16;
        array_pop($p16);
        self::assertTrue(self::ar(['purposes' => $p16]));
        self::assertFalse(self::ar(['purposes' => $p17]));
        self::assertFalse(self::ar(['purposes' => []]));
        self::assertFalse(self::ar(['purposes' => ['b', 'a']]));
        self::assertTrue(self::ar(['fns' => ['sum']]));
        self::assertFalse(self::ar(['fns' => []]));
        self::assertFalse(self::ar(['fns' => ['avg']]));
        self::assertFalse(self::ar(['fns' => ['sum', 'count']]));
        self::assertTrue(self::ar(['min_group' => 1]));
        self::assertFalse(self::ar(['min_group' => 0]));
        self::assertFalse(self::ar(['min_group' => '1']));
        self::assertTrue(self::ar(['clamp' => 1000000]));
        self::assertTrue(self::ar(['clamp' => 0]));
        self::assertFalse(self::ar(['clamp' => 1000001]));
        self::assertFalse(self::ar(['clamp' => '5']));
        self::assertTrue(self::ar(['epsilon_micro' => 1073741824]));
        self::assertFalse(self::ar(['epsilon_micro' => 1073741825]));
        self::assertFalse(self::ar(['epsilon_micro' => '5']));
        self::assertFalse(self::ar(['dp' => 1]));
        self::assertTrue(self::ar(['dp' => true, 'epsilon_micro' => 1]));
        self::assertFalse(self::ar(['dp' => true, 'epsilon_micro' => 0]));
        self::assertTrue(self::ar(['dp' => false, 'epsilon_micro' => 0]));
    }

    public function testAggregateBodyShape(): void
    {
        self::assertTrue(self::ab([]));
        self::assertFalse(ReadVault::validAggregateGrantBody('x'));
        self::assertFalse(ReadVault::validAggregateGrantBody(null));
        self::assertFalse(self::ab(['extra' => 1]));
        self::assertFalse(self::ab(['v' => 2]));
        self::assertFalse(self::ab(['v' => '1']));
        self::assertFalse(self::ab(['id' => 'bad id']));
        self::assertFalse(self::ab(['principal' => 'x']));
        self::assertFalse(self::ab(['issued_at' => '1']));
        self::assertFalse(self::ab(['expires_at' => '1']));
        self::assertFalse(self::ab(['epsilon_budget_micro' => '1']));
        self::assertFalse(self::ab(['max_queries' => '1']));
        self::assertFalse(self::ab(['rules' => (object)['a' => 1]]));
        self::assertFalse(self::ab(['rules' => []]));
        self::assertTrue(self::ab(['rules' => array_fill(0, 16, self::rule())]));
        self::assertFalse(self::ab(['rules' => array_fill(0, 17, self::rule())]));
        self::assertFalse(self::ab(['rules' => [self::rule(), self::rule(['fns' => []])]]));
    }

    public function testAggregatePublicHelpers(): void
    {
        $s = ReadVault::emptyAggregateState();
        self::assertSame(['spent_micro', 'queries', 'answered'], $s->keys());
        self::assertSame(0, $s->get('spent_micro'));
        self::assertSame(0, $s->get('queries'));
        self::assertInstanceOf(Obj::class, $s->get('answered'));
        self::assertSame([], $s->get('answered')->keys());
        $b = self::obj(self::abody());
        $d = ReadVault::aggregateGrantDigest($b);
        self::assertNotNull(Pca::unb64u($d, 32));
        self::assertSame(IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/aggregate-grant-ref/v1', 'g' => $b])), $d);
    }

    // ---- aggregateRead ------------------------------------------------------------------------------------------------

    private static function agrant(array $over = []): Obj
    {
        return self::signed(ReadVault::AGGREGATE_DOMAIN, self::obj(self::abody($over)));
    }

    private static function ain(array $over = []): Obj
    {
        $o = Obj::of(array_merge(['principal' => self::p(), 'now' => 2000, 'verb' => 'orders.stats', 'resource' => 'orders/eu', 'purpose' => 'analytics',
            'fn' => 'sum', 'values' => [10, 20, 500, -900], 'salt' => 'a-per-read-secret-salt', 'noise' => 'seeded', 'state' => ReadVault::emptyAggregateState()], $over));
        if (!$o->has('grant')) {
            $o->set('grant', self::agrant());
        }
        return $o;
    }

    private static function acode(Obj $in): ?string
    {
        return ReadVault::aggregateRead($in)['code'];
    }

    public function testAggregateBaseline(): void
    {
        $r = ReadVault::aggregateRead(self::ain());
        self::assertSame('allow', $r['decision']);
        self::assertSame(30, $r['value']); // 10 + 20 + 100 - 100 (clamped)
        self::assertSame(0, $r['charged_micro']);
        self::assertSame(1, $r['state']->get('queries'));
        self::assertSame(4, ReadVault::aggregateRead(self::ain(['fn' => 'count']))['value']);
        self::assertSame(30, ReadVault::aggregateRead(self::ain(['now' => 1000]))['value']);
        self::assertSame('not_yet', self::acode(self::ain(['now' => 999])));
    }

    public function testAggregateStateChecks(): void
    {
        $st = static fn (mixed $s, mixed $q, mixed $a): Obj => Obj::of(['spent_micro' => $s, 'queries' => $q, 'answered' => $a]);
        self::assertSame('bad_request', self::acode(self::ain(['state' => $st(-1, 0, new Obj())])));
        self::assertSame('bad_request', self::acode(self::ain(['state' => $st(0, -1, new Obj())])));
        self::assertSame('bad_request', self::acode(self::ain(['state' => $st(0, 0, Obj::of(['x' => 'str']))])));
        self::assertSame('allow', ReadVault::aggregateRead(self::ain(['state' => $st(0, 0, Obj::of(['x' => 7]))]))['decision']);
        self::assertSame('bad_request', self::acode(self::ain(['state' => self::fake(ReadVault::emptyAggregateState())])));
        self::assertSame('bad_request', self::acode(self::ain(['state' => $st(0, 0, self::fake(new Obj()))])));
        $r = ReadVault::aggregateRead(self::fake(self::ain()));
        self::assertSame('bad_request', $r['code']);
        self::assertNull($r['value']);
    }

    public function testAggregateRequestChecks(): void
    {
        self::assertSame('bad_request', self::acode(self::ain(['principal' => 'x'])));
        self::assertSame('bad_grant', self::acode(self::ain(['grant' => 'x'])));
        $g = self::agrant();
        $g->set('extra', 1);
        self::assertSame('bad_grant', self::acode(self::ain(['grant' => $g])));
        self::assertSame('no_read_scope', self::acode(self::ain(['verb' => str_repeat('v', 128)])));
        self::assertSame('bad_request', self::acode(self::ain(['verb' => str_repeat('v', 129)])));
        self::assertSame('bad_request', self::acode(self::ain(['verb' => ''])));
        self::assertSame('no_read_scope', self::acode(self::ain(['resource' => str_repeat('x', 512)])));
        self::assertSame('bad_request', self::acode(self::ain(['resource' => str_repeat('x', 513)])));
        self::assertSame('bad_request', self::acode(self::ain(['resource' => ''])));
        self::assertSame('bad_request', self::acode(self::ain(['purpose' => 'bad purpose'])));
        self::assertSame('bad_request', self::acode(self::ain(['fn' => 'avg'])));
        self::assertSame('bad_request', self::acode(self::ain(['salt' => str_repeat('s', 15)])));
        self::assertSame(30, ReadVault::aggregateRead(self::ain(['salt' => str_repeat('s', 16)]))['value']);
    }

    public function testAggregateValueCountCap(): void
    {
        $r = ReadVault::aggregateRead(self::ain(['fn' => 'count', 'values' => array_fill(0, 1000000, 1)]));
        self::assertSame('allow', $r['decision']);
        self::assertSame(1000000, $r['value']);
    }

    public function testAggregateFirstMatchingRuleWins(): void
    {
        $g = self::agrant(['rules' => [self::rule(['fns' => ['count']]), self::rule()]]);
        self::assertSame('no_read_scope', self::acode(self::ain(['grant' => $g])));
        self::assertSame(4, ReadVault::aggregateRead(self::ain(['grant' => $g, 'fn' => 'count']))['value']);
    }

    /** A draw source (the Draws test seam) whose j-th 48-bit value is $f(j); a runaway past $maxBlocks blocks throws LogicException. */
    private static function scripted(\Closure $f, int $maxBlocks): Draws
    {
        $memo = [];
        return new Draws('s', static function (int $i) use ($f, $maxBlocks, &$memo): string {
            if ($i >= $maxBlocks) {
                throw new \LogicException('runaway');
            }
            $vals = [];
            for ($k = 0; $k < 5; $k++) {
                $vals[] = $f($i * 5 + $k);
            }
            $key = implode(',', $vals);
            if (!isset($memo[$key])) {
                $raw = '';
                foreach ($vals as $v) {
                    $raw .= substr(pack('J', $v), 2); // 6 bytes big-endian
                }
                $memo[$key] = Pca::b64u($raw . "\0\0");
            }
            return $memo[$key];
        });
    }

    private static function drawsUsed(Draws $d): int
    {
        $block = (new \ReflectionProperty(Draws::class, 'block'))->getValue($d);
        $pos = (new \ReflectionProperty(Draws::class, 'pos'))->getValue($d);
        return ($block - 1) * 5 + $pos;
    }

    private static function rangeMessage(\Closure $run): string
    {
        try {
            $run();
        } catch (\RangeException $e) {
            return $e->getMessage();
        }
        self::fail('no RangeException');
    }

    public function testScriptedDrawsAreReadInOrder(): void
    {
        $d = self::scripted(static fn (int $j): int => $j, 10);
        self::assertSame([0, 1, 2, 3, 4, 5, 6], array_map(static fn (int $_): int => $d->uniform(1000), range(0, 6)));
        self::assertSame(7, self::drawsUsed($d));
    }

    public function testBadBlockThrows(): void
    {
        $d = new Draws('s', static fn (int $i): string => 'not-a-digest');
        self::assertSame('draws: bad block', self::rangeMessage(static fn () => $d->uniform(2)));
    }

    /** Every draw rejected: exactly MAX_STEPS (100000) draws, then the throw. */
    public function testUniformGivesUpAfterExactlyMaxSteps(): void
    {
        $d = self::scripted(static fn (int $j): int => self::TWO48 - 1, 20002);
        self::assertSame('uniform: no draw', self::rangeMessage(static fn () => $d->uniform(3)));
        self::assertSame(100000, self::drawsUsed($d));
    }

    /** Every Bernoulli succeeds: k runs 1..100000 inclusive (one draw each), then the throw. */
    public function testBernExpSmallGivesUpAfterExactlyMaxSteps(): void
    {
        $d = self::scripted(static fn (int $j): int => 0, 20002);
        $m = new \ReflectionMethod(ReadVault::class, 'bernExpSmall');
        self::assertSame('bernoulli: no termination', self::rangeMessage(static fn () => $m->invoke(null, $d, 1, 1)));
        self::assertSame(100000, self::drawsUsed($d));
    }

    /**
     * t = 1: u = 0, bernExpSmall(0, 1) is true (1 draw), then every bernExpSmall(1, 1) is true (draws 0, 0, 1: fails first at k = 3):
     * v reaches 100001 > MAX_STEPS after 2 + 3 * 100001 draws.
     */
    public function testLaplaceInnerLoopGivesUp(): void
    {
        $d = self::scripted(static fn (int $j): int => $j >= 2 && ($j - 2) % 3 === 2 ? 1 : 0, 60003);
        self::assertSame('laplace: no termination', self::rangeMessage(static fn () => ReadVault::discreteLaplace($d, 1, 1)));
        self::assertSame(300005, self::drawsUsed($d));
    }

    /** t = 2: u = 1, bernExpSmall(1, 2) is false (draws 0, 1: fails first at k = 2), so every outer round continues: 3 draws each. */
    public function testLaplaceOuterLoopGivesUp(): void
    {
        $d = self::scripted(static fn (int $j): int => $j % 3 === 1 ? 0 : 1, 60002);
        self::assertSame('laplace: no sample', self::rangeMessage(static fn () => ReadVault::discreteLaplace($d, 1, 2)));
        self::assertSame(300000, self::drawsUsed($d));
    }
}
