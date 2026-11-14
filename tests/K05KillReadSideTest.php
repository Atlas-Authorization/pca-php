<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ReadVault.php';

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\ReadSide;
use PHPUnit\Framework\TestCase;

/** Read-side grant shape, redaction and receipt-chain boundaries (mutation kills; the vectors cover the happy flows). */
final class K05KillReadSideTest extends TestCase
{
    /** @return array{0:string,1:string} [secret key, b64u public key] */
    private static function key(string $byte): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat($byte, 32));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function p(): string
    {
        return self::key("\x11")[1];
    }

    private static function rs(): string
    {
        return self::key("\x22")[1];
    }

    private static function obj(mixed $a): mixed
    {
        return Json::parseLax((string)json_encode($a, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
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

    private static function entry(array $over = []): array
    {
        return array_merge(['verb' => 'get', 'resource_prefix' => 'users/', 'purposes' => ['support'],
            'modes' => ['num' => 'bucket:10', 'pii' => 'last4', 'public' => 'show'], 'default_mode' => 'drop'], $over);
    }

    private static function body(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'rg1', 'principal' => self::p(), 'issued_at' => 1000, 'expires_at' => 5000,
            'reads' => [self::entry()], 'caps' => (object)[], 'sinks' => ['email' => ['allow' => ['public'], 'escalate' => ['pii']]]], $over);
    }

    private static function grant(array $over = []): Obj
    {
        $b = self::obj(self::body($over));
        return Obj::of(['body' => $b, 'sig' => Pca::b64u(sodium_crypto_sign_detached(ReadSide::READ_GRANT_DOMAIN . Json::canonicalizeStrict($b), self::key("\x11")[0]))]);
    }

    private static function vb(array $over): bool
    {
        return ReadSide::validReadGrantBody(self::obj(self::body($over)));
    }

    private static function ve(array $over): bool
    {
        return self::vb(['reads' => [self::entry($over)]]);
    }

    /** @return list<string> */
    private static function seqNames(string $p, int $n): array
    {
        $o = [];
        for ($i = 0; $i < $n; $i++) {
            $o[] = $p . sprintf('%02d', $i);
        }
        return $o;
    }

    private static function map(array $keys, mixed $v): object
    {
        $o = [];
        foreach ($keys as $k) {
            $o[$k] = $v;
        }
        return (object)$o;
    }

    public function testEntryShape(): void
    {
        self::assertTrue(self::ve([]));
        self::assertFalse(self::vb(['reads' => ['x']]));
        self::assertFalse(self::ve(['extra' => 1]));
        self::assertTrue(self::ve(['verb' => str_repeat('v', 128)]));
        self::assertFalse(self::ve(['verb' => str_repeat('v', 129)]));
        self::assertFalse(self::ve(['verb' => '']));
        self::assertTrue(self::ve(['resource_prefix' => str_repeat('r', 512)]));
        self::assertFalse(self::ve(['resource_prefix' => str_repeat('r', 513)]));
        self::assertFalse(self::ve(['resource_prefix' => '']));
        self::assertTrue(self::ve(['purposes' => self::seqNames('p', 16)]));
        self::assertFalse(self::ve(['purposes' => self::seqNames('p', 17)]));
        self::assertFalse(self::ve(['purposes' => []]));
        self::assertFalse(self::ve(['purposes' => ['b', 'a']]));
        self::assertTrue(self::ve(['modes' => self::map(self::seqNames('m', 32), 'show')]));
        self::assertFalse(self::ve(['modes' => self::map(self::seqNames('m', 33), 'show')]));
        self::assertTrue(self::ve(['modes' => (object)[]]));
        self::assertFalse(self::ve(['modes' => []]));
        self::assertFalse(self::ve(['modes' => 'x']));
        self::assertFalse(self::ve(['modes' => ['Bad' => 'show']]));
        self::assertFalse(self::ve(['modes' => ['ok' => 'bogus']]));
        self::assertFalse(self::ve(['default_mode' => 'bogus']));
    }

    public function testBodyShape(): void
    {
        self::assertTrue(self::vb([]));
        self::assertFalse(ReadSide::validReadGrantBody('x'));
        self::assertFalse(ReadSide::validReadGrantBody(null));
        self::assertFalse(self::vb(['extra' => 1]));
        self::assertFalse(self::vb(['v' => 2]));
        self::assertFalse(self::vb(['v' => '1']));
        self::assertFalse(self::vb(['id' => 'bad id']));
        self::assertFalse(self::vb(['principal' => 'x']));
        self::assertFalse(self::vb(['issued_at' => '1']));
        self::assertFalse(self::vb(['expires_at' => '1']));
        self::assertFalse(self::vb(['reads' => (object)['a' => 1]]));
        self::assertFalse(self::vb(['reads' => []]));
        self::assertTrue(self::vb(['reads' => array_fill(0, 32, self::entry())]));
        self::assertFalse(self::vb(['reads' => array_fill(0, 33, self::entry())]));
        // caps
        self::assertTrue(self::vb(['caps' => self::map(self::seqNames('c', 32), 1)]));
        self::assertFalse(self::vb(['caps' => self::map(self::seqNames('c', 33), 1)]));
        self::assertFalse(self::vb(['caps' => []]));
        self::assertFalse(self::vb(['caps' => ['Bad' => 1]]));
        self::assertFalse(self::vb(['caps' => ['c' => -1]]));
        self::assertFalse(self::vb(['caps' => ['c' => '1']]));
        // sinks
        $rule = ['allow' => ['a'], 'escalate' => ['b']];
        self::assertTrue(self::vb(['sinks' => self::map(self::seqNames('s', 16), $rule)]));
        self::assertFalse(self::vb(['sinks' => self::map(self::seqNames('s', 17), $rule)]));
        self::assertTrue(self::vb(['sinks' => (object)[]]));
        self::assertFalse(self::vb(['sinks' => []]));
        self::assertFalse(self::vb(['sinks' => ['bad key' => $rule]]));
        self::assertTrue(self::vb(['sinks' => ['Upper.Sink' => $rule]]));
        self::assertFalse(self::vb(['sinks' => ['s' => []]]));
        self::assertFalse(self::vb(['sinks' => ['s' => 'x']]));
        self::assertFalse(self::vb(['sinks' => ['s' => $rule + ['extra' => []]]]));
        self::assertFalse(self::vb(['sinks' => ['s' => ['allow' => ['b', 'a'], 'escalate' => []]]]));
        self::assertFalse(self::vb(['sinks' => ['s' => ['allow' => [], 'escalate' => ['b', 'a']]]]));
        self::assertFalse(self::vb(['sinks' => ['s' => ['allow' => ['a'], 'escalate' => ['a']]]]));
        self::assertTrue(self::vb(['sinks' => ['s' => ['allow' => self::seqNames('a', 16), 'escalate' => self::seqNames('e', 16)]]]));
        self::assertFalse(self::vb(['sinks' => ['s' => ['allow' => self::seqNames('a', 17), 'escalate' => []]]]));
        self::assertFalse(self::vb(['sinks' => ['s' => ['allow' => [], 'escalate' => self::seqNames('e', 17)]]]));
    }

    public function testReceiptRefIsPublic(): void
    {
        $r = self::obj(['a' => 1]);
        $ref = ReadSide::readReceiptRef($r);
        self::assertNotNull(Pca::unb64u($ref, 32));
        self::assertSame(ReadSide::readReceiptRef(self::obj(['a' => 1])), $ref);
        self::assertNotSame(ReadSide::readReceiptRef(self::obj(['a' => 2])), $ref);
    }

    // ---- redactRead ---------------------------------------------------------------------------------------------------

    private static function rin(array $over = [], ?Obj $grant = null): Obj
    {
        $o = self::obj(array_merge(['principal' => self::p(), 'now' => 2000, 'verb' => 'get', 'resource' => 'users/42', 'purpose' => 'support',
            'schema' => ['fields' => ['email' => 'pii', 'name' => 'public'], 'required' => []],
            'record' => ['name' => 'Alice', 'email' => 'alice@example.com'],
            'tighten' => (object)[], 'salt' => '0123456789abcdef', 'counts' => (object)[]], $over));
        $o->set('grant', $grant ?? self::grant());
        return $o;
    }

    private static function code(array $r): ?string
    {
        return $r['code'];
    }

    public function testRedactBaselineAndFieldOrder(): void
    {
        $r = ReadSide::redactRead(self::rin());
        self::assertSame('allow', $r['decision']);
        self::assertNull($r['code']);
        self::assertSame(['email', 'name'], $r['fields']->keys());
        self::assertSame(['email', 'name'], $r['view']->keys());
        self::assertSame('****.com', $r['view']->get('email'));
        self::assertSame('Alice', $r['view']->get('name'));
        self::assertSame(['pii', 'public'], $r['labels']);
    }

    public function testRedactNonObjInputs(): void
    {
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::fake(self::rin()))));
        // schema / fields / tighten / counts that answer like an Obj but are not one
        $in = self::rin();
        $in->set('schema', self::fake($in->get('schema')));
        self::assertSame('bad_request', self::code(ReadSide::redactRead($in)));
        $in = self::rin();
        $sc = $in->get('schema')->without();
        $sc->set('fields', self::fake($sc->get('fields')));
        $in->set('schema', $sc);
        self::assertSame('bad_request', self::code(ReadSide::redactRead($in)));
        $in = self::rin();
        $in->set('tighten', self::fake(new Obj()));
        self::assertSame('bad_request', self::code(ReadSide::redactRead($in)));
        $in = self::rin();
        $in->set('counts', self::fake(new Obj()));
        self::assertSame('bad_request', self::code(ReadSide::redactRead($in)));
    }

    public function testRedactRequestBoundaries(): void
    {
        self::assertSame('no_read_scope', self::code(ReadSide::redactRead(self::rin(['verb' => str_repeat('v', 128)]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['verb' => str_repeat('v', 129)]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['verb' => '']))));
        self::assertSame('no_read_scope', self::code(ReadSide::redactRead(self::rin(['resource' => str_repeat('x', 512)]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['resource' => str_repeat('x', 513)]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['resource' => '']))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['purpose' => 'bad purpose']))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['salt' => 5]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['salt' => str_repeat('s', 15)]))));
        self::assertSame('allow', ReadSide::redactRead(self::rin(['salt' => str_repeat('s', 16)]))['decision']);
    }

    public function testRedactSchemaChecks(): void
    {
        $f = ['email' => 'pii', 'name' => 'public'];
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['schema' => ['fields' => $f, 'required' => 'x']]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['schema' => ['fields' => $f + ['bad key' => 'pii'], 'required' => []]]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['schema' => ['fields' => ['email' => 'PII', 'name' => 'public'], 'required' => []]]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['schema' => ['fields' => $f, 'required' => ['missing']]]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['counts' => ['Bad' => 1]]))));
        self::assertSame('bad_request', self::code(ReadSide::redactRead(self::rin(['counts' => ['pii' => -1]]))));
        self::assertSame('allow', ReadSide::redactRead(self::rin(['counts' => ['pii' => 3]]))['decision']);
    }

    public function testFirstMatchingEntryWins(): void
    {
        $g = self::grant(['reads' => [self::entry(['modes' => ['pii' => 'show']]), self::entry(['modes' => ['pii' => 'drop']])]]);
        $r = ReadSide::redactRead(self::rin([], $g));
        self::assertSame('allow', $r['decision']);
        self::assertSame('alice@example.com', $r['view']->get('email'));
    }

    public function testTightenOnlyOnStrictlyHigherRank(): void
    {
        $in = self::rin(['schema' => ['fields' => ['n' => 'num'], 'required' => []], 'record' => ['n' => 1234], 'tighten' => ['num' => 'bucket:100']]);
        $r = ReadSide::redactRead($in);
        self::assertSame('allow', $r['decision']);
        $v = $r['view']->get('n');
        self::assertInstanceOf(Num::class, $v);
        self::assertSame('1230', $v->lexeme);
    }

    public function testBucketEdges(): void
    {
        $sc = ['fields' => ['n' => 'num'], 'required' => []];
        $r = ReadSide::redactRead(self::rin(['schema' => $sc, 'record' => ['n' => 0]]));
        self::assertSame('allow', $r['decision']);
        self::assertSame('0', $r['view']->get('n')->lexeme);
        self::assertSame('masked', $r['fields']->get('n')->get('action'));
        $r = ReadSide::redactRead(self::rin(['schema' => $sc, 'record' => ['n' => 'abc']]));
        self::assertSame('allow', $r['decision']);
        self::assertFalse($r['view']->has('n'));
        self::assertSame('dropped', $r['fields']->get('n')->get('action'));
    }

    public function testLast4NeverMasksAstral(): void
    {
        $r = ReadSide::redactRead(self::rin(['schema' => ['fields' => ['email' => 'pii'], 'required' => []], 'record' => ['email' => "abcdef\u{1F600}"]]));
        self::assertSame('allow', $r['decision']);
        self::assertFalse($r['view']->has('email'));
        self::assertSame('dropped', $r['fields']->get('email')->get('action'));
        self::assertSame([], $r['labels']);
    }

    // ---- checkSink / gradeGrant ---------------------------------------------------------------------------------------

    private static function sin(array $over = []): Obj
    {
        $o = Obj::of(array_merge(['principal' => self::p(), 'rsSigner' => self::rs(), 'now' => 2000, 'sink' => 'email', 'receipts' => []], $over));
        if (!$o->has('grant')) {
            $o->set('grant', self::grant());
        }
        return $o;
    }

    public function testCheckSinkGrantGrading(): void
    {
        self::assertSame(['decision' => 'allow', 'code' => null, 'labels' => []], ReadSide::checkSink(self::sin()));
        self::assertSame(['decision' => 'allow', 'code' => null, 'labels' => []], ReadSide::checkSink(self::sin(['now' => 1000])));
        self::assertSame('not_yet', ReadSide::checkSink(self::sin(['now' => 999]))['code']);
        self::assertSame('bad_grant', ReadSide::checkSink(self::sin(['grant' => 'x']))['code']);
        $g = self::grant();
        $g->set('extra', 1);
        self::assertSame('bad_grant', ReadSide::checkSink(self::sin(['grant' => $g]))['code']);
        self::assertSame('bad_request', ReadSide::checkSink(self::fake(self::sin()))['code']);
    }

    // ---- readChainLabels ----------------------------------------------------------------------------------------------

    private static function digest(): string
    {
        return ReadSide::readGrantDigest(self::obj(self::body()));
    }

    private static function vd(): string
    {
        return self::p(); // any 32-byte b64u value
    }

    private static function rc(int $seq, ?string $prev, array $over = []): Obj
    {
        $a = array_merge(['v' => 1, 'grant' => self::digest(), 'verb' => 'get', 'resource' => 'users/42', 'purpose' => 'support', 'seq' => $seq, 'prev' => $prev,
            'fields' => ['email' => ['class' => 'pii', 'action' => 'masked', 'kind' => 'last4', 'vd' => self::vd()]], 'labels' => ['pii'],
            'issued_at' => 1500, 'signer' => self::rs()], $over);
        $r = self::obj($a);
        $r->set('sig', Pca::b64u(sodium_crypto_sign_detached(ReadSide::READ_RECEIPT_DOMAIN . Json::canonicalizeStrict($r), self::key("\x22")[0])));
        return $r;
    }

    private static function chain(array $receipts, ?string $digest = null, int $now = 2000): array
    {
        return ReadSide::readChainLabels($receipts, self::rs(), $digest ?? self::digest(), $now);
    }

    private static function bad(array $over): void
    {
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], self::chain([self::rc(0, null, $over)]), json_encode($over));
    }

    private static function dropped(string $class = 'pii', array $f = []): array
    {
        return ['fields' => ['email' => array_merge(['class' => $class, 'action' => 'dropped', 'kind' => null, 'vd' => self::vd()], $f)], 'labels' => []];
    }

    public function testChainHappyAndLinks(): void
    {
        $r0 = self::rc(0, null);
        $r1 = self::rc(1, ReadSide::readReceiptRef($r0), ['fields' => ['name' => ['class' => 'public', 'action' => 'shown', 'kind' => null, 'vd' => self::vd()]], 'labels' => ['public']]);
        self::assertSame(['labels' => ['pii', 'public']], self::chain([$r0, $r1]));
        self::assertSame(['labels' => ['pii']], self::chain([$r0], null, 1500));
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], self::chain([$r0], null, 1499));
        $wrong = self::rc(1, self::vd(), ['fields' => ['name' => ['class' => 'public', 'action' => 'shown', 'kind' => null, 'vd' => self::vd()]], 'labels' => ['public']]);
        self::assertSame(['code' => 'bad_receipt', 'at' => 1], self::chain([$r0, $wrong]));
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], ReadSide::readChainLabels('x', self::rs(), self::digest(), 2000));
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], self::chain(['x']));
    }

    public function testReceiptShape(): void
    {
        self::assertSame(['labels' => ['pii']], self::chain([self::rc(0, null)]));
        self::bad(['extra' => 1]);
        self::bad(['v' => 2]);
        self::bad(['v' => '1']);
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], self::chain([self::rc(0, null, ['grant' => 'x'])], 'x'));
        self::assertSame(['labels' => ['pii']], self::chain([self::rc(0, null, ['verb' => str_repeat('v', 128)])]));
        self::bad(['verb' => str_repeat('v', 129)]);
        self::bad(['verb' => '']);
        self::assertSame(['labels' => ['pii']], self::chain([self::rc(0, null, ['resource' => str_repeat('r', 512)])]));
        self::bad(['resource' => str_repeat('r', 513)]);
        self::bad(['resource' => '']);
        self::bad(['purpose' => 'bad purpose']);
        self::bad(['seq' => '0']);
        self::bad(['issued_at' => '5']);
        // labels: 32 classes is the cap
        $f32 = [];
        foreach (self::seqNames('c', 33) as $c) {
            $f32['f' . $c] = ['class' => $c, 'action' => 'masked', 'kind' => 'last4', 'vd' => self::vd()];
        }
        $f33 = $f32;
        array_pop($f32);
        self::assertSame(['labels' => self::seqNames('c', 32)], self::chain([self::rc(0, null, ['fields' => $f32, 'labels' => self::seqNames('c', 32)])]));
        self::bad(['fields' => $f33, 'labels' => self::seqNames('c', 33)]);
        self::bad(['fields' => ['email' => ['class' => 'pii', 'action' => 'masked', 'kind' => 'last4', 'vd' => self::vd()],
            'name' => ['class' => 'public', 'action' => 'shown', 'kind' => null, 'vd' => self::vd()]], 'labels' => ['public', 'pii']]);
        // fields: 64 is the cap
        $d64 = [];
        foreach (self::seqNames('f', 65) as $k) {
            $d64[$k] = ['class' => 'pii', 'action' => 'dropped', 'kind' => null, 'vd' => self::vd()];
        }
        $d65 = $d64;
        array_pop($d64);
        self::assertSame(['labels' => []], self::chain([self::rc(0, null, ['fields' => $d64, 'labels' => []])]));
        self::bad(['fields' => $d65, 'labels' => []]);
        self::bad(['fields' => [], 'labels' => []]);
    }

    public function testReceiptSigMustBeAString(): void
    {
        $r = self::rc(0, null);
        $r->set('sig', new Num('5'));
        self::assertSame(['code' => 'bad_receipt', 'at' => 0], self::chain([$r]));
    }

    public function testReceiptFieldShape(): void
    {
        self::assertSame(['labels' => []], self::chain([self::rc(0, null, self::dropped())]));
        self::assertSame(['labels' => []], self::chain([self::rc(0, null, self::dropped('unclassified'))]));
        self::bad(['fields' => ['bad key' => ['class' => 'pii', 'action' => 'dropped', 'kind' => null, 'vd' => self::vd()]], 'labels' => []]);
        self::bad(['fields' => ['email' => 'x'], 'labels' => []]);
        self::bad(self::dropped('pii', ['extra' => 1]));
        self::bad(self::dropped('pii', ['class' => 5]));
        self::bad(self::dropped('Bad Class'));
        self::bad(['fields' => ['email' => ['class' => 'pii', 'action' => 'bogus', 'kind' => null, 'vd' => self::vd()]], 'labels' => ['pii']]);
        self::bad(self::dropped('pii', ['kind' => 5]));
        self::bad(self::dropped('pii', ['vd' => 'x']));
    }

    /** validReadReceipt alone: a malformed prev is refused even when seq and prev agree on "not the first". */
    public function testValidReadReceiptPrevShape(): void
    {
        $v = new \ReflectionMethod(ReadSide::class, 'validReadReceipt');
        $r0 = self::rc(0, null);
        self::assertTrue($v->invoke(null, $r0));
        self::assertTrue($v->invoke(null, self::rc(1, ReadSide::readReceiptRef($r0))));
        self::assertFalse($v->invoke(null, self::rc(1, 'not-a-digest')));
        self::assertFalse($v->invoke(null, self::rc(1, null)));
        self::assertFalse($v->invoke(null, self::rc(0, ReadSide::readReceiptRef($r0))));
    }
}
