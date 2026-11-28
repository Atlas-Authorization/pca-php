<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/IntentV2.php';
require_once __DIR__ . '/../src/SignersMore.php';

/** Group 32 mutation kills for src/IntentV2.php: the signature checks of verifyIntentRequired and its fail-closed reason. */
final class IntentSurvivorKill32IntentV2Test extends TestCase
{
    private const SIG_SHAPE = 'sig must be {alg, kid, value, pq_value?}';

    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function site(string $fill = "\x05"): KeyPair
    {
        return new KeyPair(str_repeat($fill, 32));
    }

    private static function body(array $coords = ['a' => [0, 1]]): Obj
    {
        $b = Pca::b64u(str_repeat("\x01", 32));
        return Sign::n(['v' => 1, 'kind' => 'pca-intent-required', 'session' => $b, 'map_digest' => $b, 'schema' => $b, 'pcactn_digest' => $b,
            'action_digest' => $b, 'cell' => ['verb' => 'refund', 'coords' => $coords], 'reason' => 'uncertain', 'question_id' => 'q1',
            'friction' => 'tap', 'delivered_to' => 'wallet', 'expires_at' => 100]);
    }

    private static function signed(): Obj
    {
        return SignersMore::signIntentRequired(self::body(), 'k1', self::site());
    }

    /** The signed body with its sig rebuilt by `$f`. */
    private static function withSig(callable $f): Obj
    {
        $s = self::signed();
        $sig = $s->get('sig')->without();
        $f($sig);
        $out = $s->without('sig');
        $out->set('sig', $sig);
        return $out;
    }

    private static function verify(Obj $b, ?array $keys = null): array
    {
        return IntentV2::verifyIntentRequired($b, $keys ?? [SignersMore::actionSchemaKeyOf('k1', self::site())], 50);
    }

    public function testASignedQuestionVerifies(): void
    {
        self::assertSame(['ok' => true], self::verify(self::signed()));
    }

    /** An unknown sig.alg is named by the suite check, before the shape check. */
    public function testAnUnknownAlgIsNamed(): void
    {
        self::assertSame(['ok' => false, 'reason' => "sig.alg: unsupported_suite: 'bogus'"], self::verify(self::withSig(static fn(Obj $s) => $s->set('alg', 'bogus'))));
    }

    /** A pq_value that is not a string is refused. */
    public function testANonStringPqValueIsRefused(): void
    {
        self::assertSame(['ok' => false, 'reason' => 'sig.pq_value must be a string'], self::verify(self::withSig(static fn(Obj $s) => $s->set('pq_value', 5))));
    }

    /** A sig member outside {alg, kid, value, pq_value} is refused although the signature itself is good. */
    public function testAnExtraSigMemberIsRefused(): void
    {
        self::assertSame(['ok' => false, 'reason' => self::SIG_SHAPE], self::verify(self::withSig(static fn(Obj $s) => $s->set('x', 1))));
    }

    /** An absent sig.alg is the default suite (ed25519): the signature verifies. */
    public function testAnAbsentAlgIsTheDefaultSuite(): void
    {
        $b = self::signed();
        $out = $b->without('sig');
        $out->set('sig', $b->get('sig')->without('alg'));
        self::assertSame(['ok' => true], self::verify($out));
    }

    /** A kid that is not a string is a shape error (whatever the value is). */
    public function testANonStringKidIsRefused(): void
    {
        self::assertSame(['ok' => false, 'reason' => self::SIG_SHAPE], self::verify(self::withSig(static fn(Obj $s) => $s->set('kid', 5))));
    }

    /** With two site keys of one kid, the FIRST is the one verified against. */
    public function testTheFirstKeyOfAKidIsUsed(): void
    {
        $good = SignersMore::actionSchemaKeyOf('k1', self::site());
        $other = SignersMore::actionSchemaKeyOf('k1', self::site("\x06"));
        self::assertSame(['ok' => true], self::verify(self::signed(), [$good, $other]));
        self::assertSame(['ok' => false, 'reason' => 'site signature invalid'], self::verify(self::signed(), [$other, $good]));
    }

    /** A throw inside the check (a lone surrogate the canonical form refuses) fails closed with the reason prefix. */
    public function testAThrowFailsClosedWithItsReason(): void
    {
        $b = self::body(['a' => ["\xED\xA0\x80"]]);
        $b->set('sig', Sign::n(['alg' => 'ed25519', 'kid' => 'k1', 'value' => 'AAAA']));
        self::assertSame(['ok' => false, 'reason' => 'malformed intent_required: canonicalize: lone surrogate in string'], self::verify($b));
    }
}
