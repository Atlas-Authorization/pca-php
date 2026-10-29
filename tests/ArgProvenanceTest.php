<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ArgProvenance.php';

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\Sign;
use Atlas\Pca\UnsupportedSigner;
use PHPUnit\Framework\TestCase;

/**
 * Provenance by default (0.5), the pure layer: every boundary of the decision pinned with literal expectations (the mutation
 * kills of the reference), the recorder round trip and one hybrid post-quantum receipt chain. The shared vectors are replayed
 * by VectorsTest::testArgProvenanceVectors.
 */
final class ArgProvenanceTest extends TestCase
{
    private static function rec(?callable $now = null): ProvenanceRecorder
    {
        return new ProvenanceRecorder('m', 'k', new KeyPair(str_repeat("\x05", 32)), Pca::b64u(str_repeat("\x06", 32)), $now ?? static fn (): int => 10);
    }

    private static function pin(): Obj
    {
        return self::rec()->pin;
    }

    private static function op(?Obj $params = null): Obj
    {
        return Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => $params ?? Obj::of(['a' => 'x'])]);
    }

    private static function copy(Obj $v): Obj
    {
        return Json::parseStrict(Json::canonicalizeStrict($v));
    }

    /** @return array<string,mixed> */
    private static function decide(mixed $bundle, ?Obj $op = null, ?array $pins = null, array $extra = []): array
    {
        $in = Obj::of(['operation' => $op ?? self::op(), 'mediators' => $pins ?? [self::pin()]]);
        if ($bundle !== null) {
            $in->set('bundle', $bundle);
        }
        foreach ($extra as $k => $v) {
            $in->set($k, $k === 'action' || $k === 'observed' ? Sign::n($v) : $v);
        }
        return ArgProvenance::decide($in);
    }

    private static function principalOnly(): Obj
    {
        $r = self::rec();
        $r->principal('x');
        return $r->forAction(self::op());
    }

    public function testWireConstants(): void
    {
        $this->assertSame(["atlas-pca/prov-receipt/v1\0", 'atlas-pca/prov-receipt-ref/v1', 'atlas-pca/prov-action/v1', 'PCA-Provenance', 'pca_provenance'],
            [ArgProvenance::RECEIPT_DOMAIN, ArgProvenance::RECEIPT_REF_DOMAIN, ArgProvenance::ACTION_DOMAIN, ArgProvenance::HEADER, ArgProvenance::BODY_MEMBER]);
        $this->assertSame([256, 65536], [ArgProvenance::MAX_RECEIPTS, ArgProvenance::MAX_CONTENT_BYTES]);
        $this->assertSame(['principal', 'tool', 'retrieval', 'web', 'action'], ArgProvenance::ORIGINS);
        $this->assertSame(['trusted', 'first_party', 'tool', 'web', 'agent'], ArgProvenance::LEVELS);
        $this->assertSame(['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data'], ArgProvenance::READ_SAFE_TRAITS);
    }

    public function testTokenBoundaryOnBothSidesOfEveryWordRangeEdge(): void
    {
        $edges = [['/', true], ['0', false], ['9', false], [':', true], ['@', true], ['A', false], ['Z', false], ['[', true],
            ['`', true], ['a', false], ['z', false], ['{', true], ['_', false], ['^', true], ["\x7f", true], ["\u{80}", false]];
        foreach ($edges as [$c, $boundary]) {
            $this->assertSame($boundary, ArgProvenance::occursAsToken("{$c}x", 'x'), 'before ' . bin2hex($c));
            $this->assertSame($boundary, ArgProvenance::occursAsToken("x{$c}", 'x'), 'after ' . bin2hex($c));
        }
    }

    public function testTokenNonAsciiAndNonWordNeedleEdges(): void
    {
        $this->assertFalse(ArgProvenance::occursAsToken('éx', 'x'));
        $this->assertFalse(ArgProvenance::occursAsToken('xé', 'x'));
        $this->assertTrue(ArgProvenance::occursAsToken('é x', 'x'));
        $this->assertTrue(ArgProvenance::occursAsToken('pay München now', 'München'));
        $this->assertFalse(ArgProvenance::occursAsToken('pay Münchener now', 'München'));
        $this->assertTrue(ArgProvenance::occursAsToken('a.b', '.b'));
        $this->assertFalse(ArgProvenance::occursAsToken('a.bc', '.b'));
        $this->assertFalse(ArgProvenance::occursAsToken('ab.', 'b.'));
        $this->assertFalse(ArgProvenance::occursAsToken('cb.', 'b.'));
        $this->assertTrue(ArgProvenance::occursAsToken(' b.', 'b.'));
        $this->assertTrue(ArgProvenance::occursAsToken('xx x', 'x'), 'a later occurrence counts');
        $this->assertFalse(ArgProvenance::occursAsToken('x', ''));
        $this->assertFalse(ArgProvenance::occursAsToken(1, '1'));
        $this->assertFalse(ArgProvenance::occursAsToken('1', 1));
    }

    public function testLeafLimits(): void
    {
        $nest = static function (int $n) use (&$nest): mixed {
            return $n === 0 ? 'x' : [$nest($n - 1)];
        };
        $this->assertSame(['x'], ArgProvenance::leaves($nest(32)));
        $this->assertNull(ArgProvenance::leaves($nest(33)));
        $o = new Obj();
        for ($i = 0; $i < 2048; $i++) {
            $o->set("k$i", 'v');
        }
        $this->assertCount(4096, ArgProvenance::leaves($o));
        $o->set('extra', 'v');
        $this->assertNull(ArgProvenance::leaves($o));
        $this->assertSame(['true', 'null', '120', 'k', 's'], ArgProvenance::leaves([true, null, new Num('120'), Obj::of(['k' => 's'])]));
    }

    public function testReceiptWireBoundsAreBytes(): void
    {
        $r = self::rec()->principal('p');
        $with = static function (string $k, mixed $v) use ($r): Obj {
            $x = $r->without();
            $x->set($k, $v);
            return $x;
        };
        $this->assertNull(ArgProvenance::receiptWireError($with('mediator', str_repeat('m', 256))));
        $this->assertStringContainsString('mediator', (string)ArgProvenance::receiptWireError($with('mediator', str_repeat('m', 257))));
        $this->assertStringContainsString('mediator', (string)ArgProvenance::receiptWireError($with('mediator', str_repeat('é', 129))));
        $this->assertNull(ArgProvenance::receiptWireError($with('kid', str_repeat('k', 64))));
        $this->assertStringContainsString('kid', (string)ArgProvenance::receiptWireError($with('kid', str_repeat('k', 65))));
        $this->assertStringContainsString('source', (string)ArgProvenance::receiptWireError($with('source', str_repeat('s', 257))));
        $this->assertNull(ArgProvenance::receiptWireError($with('seq', new Num('0'))));
        $this->assertNull(ArgProvenance::receiptWireError($with('issued_at', new Num('0'))));
        $this->assertStringContainsString('issued_at', (string)ArgProvenance::receiptWireError($with('issued_at', new Num('-1'))));
        $this->assertStringContainsString('v: 1', (string)ArgProvenance::receiptWireError($with('v', new Num('2'))));
        $this->assertStringContainsString('v: 1', (string)ArgProvenance::receiptWireError($with('kind', 'x')));
        $this->assertStringContainsString('session', (string)ArgProvenance::receiptWireError($with('session', 'x')));
        $this->assertStringContainsString('content_digest', (string)ArgProvenance::receiptWireError($with('content_digest', 'x')));
        $this->assertNotNull(ArgProvenance::receiptWireError($with('extra', 1)));
    }

    public function testSourceClipHalvesByUtf16UnitsLikeTheReference(): void
    {
        $e = "\u{e9}";
        $g = "\u{1F600}";
        $this->assertSame(str_repeat('a', 150), ProvenanceRecorder::clip(str_repeat('a', 300)));
        $this->assertSame(str_repeat('a', 256), ProvenanceRecorder::clip(str_repeat('a', 256)));
        $this->assertSame('-', ProvenanceRecorder::clip(''));
        $this->assertSame(str_repeat($e, 91), ProvenanceRecorder::clip(str_repeat($e, 100) . str_repeat($g, 41) . 'b'));
        $this->assertSame(str_repeat($g, 32), ProvenanceRecorder::clip(str_repeat($g, 64) . $e));
        try {
            ProvenanceRecorder::clip(str_repeat($g, 50) . str_repeat($e, 30) . 'x');
            $this->fail('a cut inside a surrogate pair was recorded');
        } catch (JsonError) {
        }
        $this->expectException(JsonError::class);
        self::rec()->tool(str_repeat($g, 50) . str_repeat($e, 30) . 'x', 'out');
    }

    public function testActionInfoPinsAndEnvelope(): void
    {
        $this->assertNull(ArgProvenance::actionInfoError(Sign::n(['effects' => array_fill(0, 64, 'e')])));
        $this->assertNotNull(ArgProvenance::actionInfoError(Sign::n(['effects' => array_fill(0, 65, 'e')])));
        $this->assertNull(ArgProvenance::actionInfoError(Sign::n(['traits' => [str_repeat('t', 128)]])));
        $this->assertNotNull(ArgProvenance::actionInfoError(Sign::n(['traits' => [str_repeat('t', 129)]])));
        $this->assertNotNull(ArgProvenance::actionInfoError(Sign::n(['params' => [str_repeat('p', 129) => 'tool']])));
        $this->assertNotNull(ArgProvenance::actionInfoError(Obj::of(['params' => []])));
        $this->assertNotNull(ArgProvenance::actionInfoError(null));
        $pin = self::pin();
        $with = static function (string $k, mixed $v) use ($pin): Obj {
            $x = $pin->without();
            $x->set($k, $v);
            return $x;
        };
        $this->assertFalse(ArgProvenance::isMediatorPin($with('pq_pk', '')));
        $this->assertTrue(ArgProvenance::isMediatorPin($with('pq_pk', 'x')));
        $this->assertFalse(ArgProvenance::isMediatorPin($with('kid', '')));
        $this->assertNull(ArgProvenance::envelopeError(Obj::of(['mediators' => array_fill(0, 16, $pin)])));
        $this->assertNotNull(ArgProvenance::envelopeError(Obj::of(['mediators' => array_fill(0, 17, $pin)])));
        $this->assertNull(ArgProvenance::envelopeError(Obj::of(['mode' => 'enforce'])));
        $this->assertNull(ArgProvenance::envelopeError(Obj::of(['mode' => 'insecure_off'])));
        $this->assertNotNull(ArgProvenance::envelopeError(Obj::of(['mode' => 'off'])));
        $this->assertNotNull(ArgProvenance::envelopeError(Obj::of(['mediators' => [new Obj()]])));
        $this->assertNotNull(ArgProvenance::envelopeError(Obj::of(['other' => true])));
        $this->assertNotNull(ArgProvenance::envelopeError(null));
    }

    public function testReadOnlyAction(): void
    {
        $this->assertTrue(ArgProvenance::isReadOnlyAction(Sign::n(['effects' => ['read']])));
        $this->assertTrue(ArgProvenance::isReadOnlyAction(Sign::n(['effects' => ['read'], 'traits' => ['pca.pii_access']])));
        $this->assertFalse(ArgProvenance::isReadOnlyAction(Sign::n(['effects' => ['read', 'send']])));
        $this->assertFalse(ArgProvenance::isReadOnlyAction(Sign::n(['effects' => ['read'], 'traits' => ['pca.money_movement']])));
        $this->assertFalse(ArgProvenance::isReadOnlyAction(Obj::of(['effects' => []])));
        $this->assertFalse(ArgProvenance::isReadOnlyAction(null), 'unknown facts are sensitive');
    }

    public function testRecorderRoundTripAndLimits(): void
    {
        $r = self::rec();
        for ($i = 0; $i < ArgProvenance::MAX_RECEIPTS - 1; $i++) {
            $r->principal('x');
        }
        $b = $r->forAction(self::op());
        $this->assertCount(256, $b->get('receipts'));
        $this->assertSame('pass', self::decide($b)['outcome']);
        $this->expectException(\LengthException::class);
        $r->forAction(self::op());
    }

    public function testPrincipalContentByteLimit(): void
    {
        $r = self::rec();
        $r->principal(str_repeat('é', ArgProvenance::MAX_CONTENT_BYTES / 2));
        $r->principal(str_repeat('y', ArgProvenance::MAX_CONTENT_BYTES + 1));
        $b = $r->forAction(self::op());
        $this->assertSame(['0'], array_map('strval', $b->get('contents')->keys()));
        $this->assertSame('pass', self::decide($b)['outcome']);
        $big = self::copy($b);
        $big->set('contents', Obj::of(['1' => str_repeat('y', ArgProvenance::MAX_CONTENT_BYTES + 1)]));
        $this->assertSame('malformed_bundle', self::decide($big)['code']);
    }

    public function testTrustedContextShortcutNeedsNoVerbatimText(): void
    {
        // only principal segments before the action: the context is trusted, every leaf is trusted without a text match
        $r = self::rec();
        $r->principal('nothing that names the value');
        $b = $r->forAction(self::op());
        $d = self::decide($b);
        $this->assertSame(['pass', 'trusted', []], [$d['outcome'], $d['control'], $d['tainted']]);
        $this->assertSame('trusted', $d['labels']->get('a'));
        $this->assertSame('pass', self::decide($b->without('contents'))['outcome']);
        // an observed tool raises the context: the shortcut no longer applies and an unmatched leaf takes the tool label
        $tool = ['observed' => [['origin' => 'tool', 'source' => 't']]];
        $d = self::decide($b, null, null, $tool);
        $this->assertSame(['escalate', 'untrusted_control_and_args', 'tool', ['a'], 'tool'], [$d['outcome'], $d['code'], $d['control'], $d['tainted'], $d['labels']->get('a')]);
        $typed = self::rec();
        $typed->principal('send x');
        $d = self::decide($typed->forAction(self::op()), null, null, $tool);
        $this->assertSame(['untrusted_control', [], 'trusted'], [$d['code'], $d['tainted'], $d['labels']->get('a')]);
    }

    public function testFirstReceiptPrevMustBeNull(): void
    {
        $b = self::copy(self::principalOnly());
        $b->get('receipts')[0]->set('prev', $b->get('receipts')[0]->get('content_digest'));
        $d = self::decide($b);
        $this->assertSame(['deny', 'broken_chain', 'receipt 0 does not link to its predecessor'], [$d['outcome'], $d['code'], $d['reason']]);
        $b = self::copy(self::principalOnly());
        $b->get('receipts')[1]->set('prev', null);
        $this->assertSame(['broken_chain', 'receipt 1 does not link to its predecessor'], [self::decide($b)['code'], self::decide($b)['reason']]);
    }

    public function testSeqGapIsABrokenChain(): void
    {
        $b = self::copy(self::principalOnly());
        $b->get('receipts')[1]->set('seq', new Num('2'));
        $d = self::decide($b);
        $this->assertSame(['broken_chain', 'receipt 1 has seq 2'], [$d['code'], $d['reason']]);
    }

    public function testIssuedAtMayRiseOrStayButNeverFall(): void
    {
        $b = self::principalOnly();
        $this->assertSame($b->get('receipts')[0]->get('issued_at')->int(), $b->get('receipts')[1]->get('issued_at')->int());
        $this->assertSame('pass', self::decide($b)['outcome']);
        $t = 10;
        $rising = self::rec(static function () use (&$t): int {
            return $t++;
        });
        $rising->principal('x');
        $rb = $rising->forAction(self::op());
        $this->assertSame([10, 11], [$rb->get('receipts')[0]->get('issued_at')->int(), $rb->get('receipts')[1]->get('issued_at')->int()]);
        $this->assertSame('pass', self::decide($rb)['outcome']);
        $back = self::copy($b);
        $back->get('receipts')[1]->set('issued_at', new Num('9'));
        $d = self::decide($back);
        $this->assertSame(['broken_chain', 'receipt 1 is older than its predecessor'], [$d['code'], $d['reason']]);
        // the recorder itself never goes back: a clock that falls is clamped to the previous issued_at
        $t = 50;
        $falling = self::rec(static function () use (&$t): int {
            return $t--;
        });
        $falling->principal('x');
        $fb = $falling->forAction(self::op());
        $this->assertSame([50, 50], [$fb->get('receipts')[0]->get('issued_at')->int(), $fb->get('receipts')[1]->get('issued_at')->int()]);
    }

    public function testTheLastReceiptBindsVerbResourceAndParams(): void
    {
        $b = self::principalOnly();
        foreach ([['w', 'r', Obj::of(['a' => 'x'])], ['v', 's', Obj::of(['a' => 'x'])], ['v', 'r', Obj::of(['a' => 'y'])], ['v', 'r', Obj::of(['a' => 'x', 'b' => 'x'])]] as [$verb, $res, $params]) {
            $d = self::decide($b, Obj::of(['verb' => $verb, 'resource' => $res, 'params' => $params]));
            $this->assertSame(['deny', 'unbound_action'], [$d['outcome'], $d['code']], "$verb $res");
        }
        $notAction = self::copy($b);
        $notAction->set('receipts', array_slice($notAction->get('receipts'), 0, 1));
        $this->assertSame('unbound_action', self::decide($notAction)['code']);
    }

    public function testPinLookupMatchesMediatorAndKid(): void
    {
        $b = self::principalOnly();
        $pin = self::pin();
        $with = static function (string $k, string $v) use ($pin): Obj {
            $x = $pin->without();
            $x->set($k, $v);
            return $x;
        };
        $this->assertTrue(self::decide($b)['verified']);
        foreach ([$with('mediator', 'other'), $with('kid', 'other')] as $other) {
            $d = self::decide($b, null, [$other]);
            $this->assertSame([false, 'escalate', 'untrusted_control_and_args', ['unlabelled']], [$d['verified'], $d['outcome'], $d['code'], $d['path']]);
        }
        $zero = $with('pk', Pca::b64u(str_repeat("\0", 32)));
        $this->assertSame('bad_signature', self::decide($b, null, [$zero, $pin])['code'], 'the first matching pin is used');
        $this->assertTrue(self::decide($b, null, [$with('mediator', 'other'), $pin])['verified']);
    }

    public function testFloorFallbackFirstPartyWhenSensitiveAgentWhenReadOnly(): void
    {
        $r = self::rec();
        $r->tool('t', 'x');
        $b = $r->forAction(self::op());
        $d = static fn (array $action): array => self::decide($b, null, null, ['principal_control' => true, 'action' => $action]);
        $this->assertSame([], $d(['effects' => ['read']])['tainted']);
        $this->assertSame(['a'], $d(['effects' => ['read'], 'params' => ['a' => 'first_party']])['tainted']);
        $this->assertSame(['a'], $d(['effects' => ['send']])['tainted']);
        $this->assertSame([], $d(['effects' => ['send'], 'params' => ['a' => 'tool']])['tainted']);
        $this->assertSame(['a'], $d(['effects' => ['send'], 'params' => ['b' => 'agent']])['tainted']);
    }

    public function testReadOnlyNeverEscalatesOnControlAlone(): void
    {
        $d = self::decide(null, self::op(new Obj()), null, ['action' => ['effects' => ['read']]]);
        $this->assertSame(['pass', false, 'agent'], [$d['outcome'], $d['sensitive'], $d['control']]);
        $d = self::decide(null, self::op(new Obj()));
        $this->assertSame(['escalate', 'untrusted_control', true], [$d['outcome'], $d['code'], $d['sensitive']]);
    }

    public function testEscalateReasonWording(): void
    {
        $r = self::rec();
        $r->tool('t', 'x');
        $two = Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => 'x', 'b' => 'y'])]);
        $this->assertSame('a, b derive from untrusted content [tool:t]: the principal must confirm (prompt-injection path)',
            self::decide($r->forAction($two), $two, null, ['principal_control' => true])['reason']);
        $r2 = self::rec();
        $r2->tool('t', 'x');
        $this->assertSame('a derives from untrusted content [tool:t]: the principal must confirm (prompt-injection path)',
            self::decide($r2->forAction(self::op()), null, null, ['principal_control' => true])['reason']);
        $r3 = self::rec();
        $r3->tool('t', 'x');
        $this->assertSame('the choice of v derives from untrusted content; a derives from untrusted content [tool:t]: the principal must confirm (prompt-injection path)',
            self::decide($r3->forAction(self::op()))['reason']);
    }

    public function testPathIsSortedAndDeduplicated(): void
    {
        $r = self::rec();
        $r->web('z', 'x');
        $r->tool('b', 'x');
        $r->tool('b', 'y');
        $d = self::decide($r->forAction(self::op()), null, null, ['observed' => [['origin' => 'retrieval', 'source' => 'a'], ['origin' => 'tool', 'source' => 'b']]]);
        $this->assertSame(['retrieval:a', 'tool:b', 'web:z'], $d['path']);
    }

    public function testVerbatimMatchNeedsTheStoredPrincipalContent(): void
    {
        $r = self::rec();
        $r->principal('send x');
        $r->tool('t', 'y');
        $b = $r->forAction(self::op());
        $this->assertSame('pass', self::decide($b, null, null, ['principal_control' => true])['outcome']);
        $this->assertSame(['a'], self::decide($b->without('contents'), null, null, ['principal_control' => true])['tainted']);
        $bad = self::copy($b);
        $bad->get('contents')->set('0', 'send z');
        $this->assertSame('content_mismatch', self::decide($bad)['code']);
    }

    public function testPrincipalPlanTrustsEveryParameterAndTheControl(): void
    {
        $r = self::rec();
        $r->web('evil', 'x');
        $d = self::decide($r->forAction(self::op()), null, null, ['principal_plan' => true]);
        $this->assertSame(['pass', 'trusted', 'trusted'], [$d['outcome'], $d['control'], $d['labels']->get('a')]);
    }

    public function testPrincipalDirectIsTrusted(): void
    {
        $op = ['verb' => 'payments.send', 'resource' => 'bank', 'params' => ['iban' => 'DE89370400440532013000', 'amount' => 120]];
        $b = ArgProvenance::principalDirect(self::rec(), $op);
        $d = self::decide($b, Sign::n($op));
        $this->assertSame(['pass', true, 'trusted', []], [$d['outcome'], $d['verified'], $d['control'], $d['tainted']]);
    }

    /** One hybrid post-quantum receipt chain: the pin carries pq_pk and both halves must verify. */
    public function testHybridPostQuantumReceipts(): void
    {
        $required = getenv('PCA_REQUIRE_PQ') === '1';
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->assertFalse($required, 'ML-DSA-65: OpenSSL >= 3.5 over FFI is required in CI');
            try {
                new PqKeyPair('ML-DSA-65');
                $this->fail('a PQ key was generated without a backend');
            } catch (UnsupportedSigner) {
            }
            return;
        }
        $pq = new PqKeyPair('ML-DSA-65');
        $r = new ProvenanceRecorder('m', 'k', new KeyPair(str_repeat("\x05", 32)), null, null, 'hybrid-ed25519-ml-dsa-65', $pq);
        $this->assertSame($pq->public, $r->pin->get('pq_pk'));
        $r->principal('x');
        $b = $r->forAction(self::op());
        $this->assertSame('hybrid-ed25519-ml-dsa-65', $b->get('receipts')[0]->get('alg'));
        $this->assertSame('pass', self::decide($b, null, [$r->pin])['outcome']);
        $noPq = $r->pin->without('pq_pk');
        $this->assertSame('bad_signature', self::decide($b, null, [$noPq])['code'], 'a hybrid receipt needs the pinned PQ key');
        $other = $r->pin->without();
        $other->set('pq_pk', (new PqKeyPair('ML-DSA-65'))->public);
        $this->assertSame('bad_signature', self::decide($b, null, [$other])['code']);
    }
}
