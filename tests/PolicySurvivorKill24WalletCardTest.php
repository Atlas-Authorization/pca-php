<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Catalog;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletCard;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/WalletCard.php: helpers, the typed target, card text, partly answers, typed values, clarification limits, card members. */
final class PolicySurvivorKill24WalletCardTest extends TestCase
{
    private static function call(string $m, mixed ...$a): mixed
    {
        $r = new \ReflectionMethod(WalletCard::class, $m);
        $r->setAccessible(true);
        return $r->invoke(null, ...$a);
    }

    private static function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        self::fail("no $class: $msg");
    }

    /** The string and number guards throw their own TypeError. */
    public function testGuards(): void
    {
        self::throws(static fn() => WalletCard::cleanText(5, 10), \TypeError::class, 'a string is required');
        self::throws(static fn() => WalletCard::formatNumber('x'), \TypeError::class, 'a number is required');
    }

    /** An infinite exponent clamps to 6 (or 0 when negative); a NaN exponent renders NaN after the sign. */
    public function testMoneyExponents(): void
    {
        $u = static fn(string $e): Obj => Obj::of(['kind' => 'money', 'currency' => 'XYZ', 'exponent' => $e]);
        $this->assertSame('XYZ 1.234567', WalletCard::formatNumber(1234567, $u('Infinity')));
        $this->assertSame('XYZ 1,234,567', WalletCard::formatNumber(1234567, $u('-Infinity')));
        $this->assertSame('-XYZ NaN', WalletCard::formatNumber(-5, $u('x')));
    }

    /** A monitor state path is labelled from its name. */
    public function testMonitorLabel(): void
    {
        $this->assertSame('state of a b c', self::call('dimLabel', 'env.mon.a_b.c.state'));
    }

    /** Category values and the action's own value are capped at 64 units. */
    public function testCategoryTextCap(): void
    {
        $s64 = str_repeat('a', 64);
        $s65 = str_repeat('b', 65);
        $cut = str_repeat('b', 63) . "\u{2026}";
        $d = Obj::of(['values' => [Obj::of(['kind' => 'exact', 'value' => $s64]), Obj::of(['kind' => 'exact', 'value' => $s65]),
            Obj::of(['kind' => 'prefix', 'value' => $s64]), Obj::of(['kind' => 'prefix', 'value' => $s65])]]);
        $this->assertSame(['"' . $s64 . '"', '"' . $cut . '"', 'anything starting with "' . $s64 . '"', 'anything starting with "' . $cut . '"'],
            [self::call('catValueText', $d, 0), self::call('catValueText', $d, 1), self::call('catValueText', $d, 2), self::call('catValueText', $d, 3)]);
        $this->assertSame('"' . $s64 . '" (this action: "' . $s64 . '")', self::call('catFact', $d, [0], $s64));
        $this->assertSame('"' . $cut . '" (this action: "' . $cut . '")', self::call('catFact', $d, [1], $s65));
    }

    /** A missing (null or undefined) values member throws, as the reference does. */
    public function testVgetNeedsValues(): void
    {
        foreach ([null, Jsx::$U] as $v) {
            self::throws(static fn() => self::call('vget', $v, 'p'), \TypeError::class, 'Cannot read properties of undefined');
        }
    }

    /** A tier name, or a one-element list of one, selects the answers; anything else has none. */
    public function testAnswersOf(): void
    {
        $this->assertSame('Yes', self::call('answersOf', ['tap'])[2]->get('label'));
        $this->assertSame('Press and hold to allow', self::call('answersOf', 'hold')[2]->get('label'));
        foreach ([['tap', 'hold'], [5], ['k' => 'tap'], 5, [], null, 'nope'] as $f) {
            $this->assertNull(self::call('answersOf', $f), json_encode($f));
        }
    }

    /** The first character is lowercased with Unicode rules, the rest untouched. */
    public function testLowerFirst(): void
    {
        $this->assertSame("\u{E9}AB", self::call('lowerFirst', "\u{C9}AB"));
    }

    private static function numDim(mixed $path): Obj
    {
        return Obj::of(['path' => $path, 'kind' => 'num']);
    }

    /** The typed target prefers the first money dimension, else the first number; non-string paths are used as strings. */
    public function testTypedTarget(): void
    {
        $vs = Obj::of(['dims' => [self::numDim('p.a'), self::numDim('p.b')]]);
        $act = Obj::of(['values' => Obj::of(['p.a' => 1, 'p.b' => 2])]);
        $m = Obj::of(['kind' => 'money', 'currency' => 'USD', 'exponent' => 2]);
        $this->assertSame('p.b', self::call('typedTarget', $vs, $act, Obj::of(['p.b' => $m]))->get('path'));
        $this->assertSame('p.a', self::call('typedTarget', $vs, $act, Obj::of(['p.a' => $m, 'p.b' => $m]))->get('path'));
    }

    /** A dimension path that is not a string throws TypeError (as the reference's d.path.startsWith does) instead of being read as text. */
    public function testTypedTargetRefusesANonStringPath(): void
    {
        $values = new Obj();
        $values->set('5', 3);
        $this->expectException(\TypeError::class);
        self::call('typedTarget', Obj::of(['dims' => [self::numDim(5)]]), Obj::of(['values' => $values]), new Obj());
    }

    private static function card(array $over = []): array
    {
        return $over + ['header' => 'H', 'sentence' => 'S', 'facts' => [['label' => 5, 'text' => 't']], 'banners' => [], 'answers' => [['label' => 'No']]];
    }

    /** cardText: a number label prints as text, an object or array label throws; the reason label line; an assoc array card works. */
    public function testCardText(): void
    {
        $this->assertSame("H\nR\nS\n- 5: t\n[No]", WalletCard::cardText(self::card(['reason_label' => 'R'])));
        $this->assertSame("H\nR\nS\n- 5: t\n[No]", WalletCard::cardText(Obj::of(self::card(['reason_label' => 'R']))));
        foreach ([[], new Obj()] as $bad) {
            self::throws(static fn() => WalletCard::cardText(self::card(['facts' => [['label' => $bad, 'text' => 't']]])), \TypeError::class, 'a string is required');
        }
        foreach (['x', ['k' => 1]] as $bad) {
            self::throws(static fn() => WalletCard::cardText(self::card(['facts' => $bad])), \TypeError::class, 'not iterable');
        }
    }

    private static function slot(mixed $lo, mixed $hi): array
    {
        return ['partial' => [['path' => 'n', 'kind' => 'num', 'lo' => $lo, 'hi' => $hi]]];
    }

    /** Partly answers on a number: the bounds, a non-number, the first slot of a path, except lists. */
    public function testPartialNumber(): void
    {
        $c = self::slot(0, 10);
        $this->assertNull(WalletCard::partialError($c, ['path' => 'n', 'from' => 10]));
        $this->assertSame('upTo must be an integer in [0, 9]', WalletCard::partialError($c, ['path' => 'n', 'upTo' => 10]));
        $this->assertSame('upTo must be an integer in [0, 9]', WalletCard::partialError($c, ['path' => 'n', 'upTo' => 'x']));
        $this->assertSame('upTo must be an integer in [0, 4]', WalletCard::partialError(self::slot(0, 5.5), ['path' => 'n', 'upTo' => 5]));
        $this->assertSame('from must be an integer in [0, 10]', WalletCard::partialError(self::slot(-1.5, 10), ['path' => 'n', 'from' => -1]));
        $two = ['partial' => [['path' => 'n', 'kind' => 'num', 'lo' => 0, 'hi' => 10], ['path' => 'n', 'kind' => 'num', 'lo' => 0, 'hi' => 3]]];
        $this->assertNull(WalletCard::partialError($two, ['path' => 'n', 'upTo' => 5]));
        $ex = 'except values must be integers in [0, 10]';
        $this->assertNull(WalletCard::partialError($c, ['path' => 'n', 'except' => [3]]));
        $this->assertSame($ex, WalletCard::partialError($c, ['path' => 'n', 'except' => [999]]));
        $this->assertSame($ex, WalletCard::partialError($c, ['path' => 'n', 'except' => 'x']));
        $this->assertSame($ex, WalletCard::partialError($c, ['path' => 'n', 'except' => []]));
        self::throws(static fn() => WalletCard::partialError($c, ['path' => 'n', 'except' => 5]), \TypeError::class, 'object of this type has no len()');
        self::throws(static fn() => WalletCard::partialError($c, 5), \TypeError::class, 'p is not an object');
    }

    /** The typed value: a non-object card throws, the path is a string, a large safe integer prints as digits. */
    public function testExpectedTyped(): void
    {
        self::throws(static fn() => WalletCard::expectedTyped(5, null), \TypeError::class, 'card is not an object');
        self::throws(static fn() => WalletCard::cardDigestMatches(5), \TypeError::class, 'card is not an object');
        $values = new Obj();
        $values->set('5', 1000000000000000);
        $this->assertSame('1000000000000000', WalletCard::expectedTyped(Obj::of(['typed' => Obj::of(['path' => 5, 'mode' => 'number'])]), Obj::of(['values' => $values])));
    }

    /** A typed number drops the whole whitespace set, the last member (U+FEFF) included. */
    public function testNormalizeTypedStripsTheBom(): void
    {
        $this->assertSame('12', WalletCard::normalizeTyped("\u{FEFF}1\u{3000}2", 'number'));
    }

    /** Clarification limits: a 128-unit verb and 64 values are allowed; one more of either is not. */
    public function testClarifyLimits(): void
    {
        $req = static function (string $verb, int $n): array {
            $v = new Obj();
            for ($i = 0; $i < $n; $i++) {
                $v->set("action.params.a$i", $i);
            }
            return WalletCard::parseClarifyRequest(Obj::of(['reason' => 'other', 'candidates' => [Obj::of(['verb' => $verb, 'values' => $v])]]));
        };
        $this->assertTrue($req(str_repeat('v', 128), 64)['ok']);
        $this->assertSame(['ok' => false, 'error' => 'candidates[0].verb must be a non-empty string'], $req(str_repeat('v', 129), 1));
        $this->assertSame(['ok' => false, 'error' => 'candidates[0] has too many values'], $req('v', 65));
    }

    /** The reference corpus base card input, with members replaced or removed. */
    private static function render(array $set = [], array $drop = []): array
    {
        $case = null;
        foreach (Base::cases('ref-wallet.json.gz', 'renderCard', 0) as $c) {
            if ($c->get('name') === 'renderCard/base') {
                $case = $c;
            }
        }
        self::assertNotNull($case);
        $x = $case->get('args')[0];
        $in = Obj::of(['omega' => RefWalletDifferentialTest::omegas()[$x->get('omegaId')]]);
        foreach ($x->keys() as $k) {
            if ($k !== 'omegaId' && !in_array($k, $drop, true)) {
                $in->set($k, $set[$k] ?? $x->get($k));
            }
        }
        foreach ($set as $k => $v) {
            $in->set($k, $v);
        }
        return WalletCard::renderCard($in);
    }

    /** A given catalog is used (a number description reads as text); without kind or friction the card has no such member; the site origin is capped at 256 units, a nameless site uses it (64). */
    public function testCardMembers(): void
    {
        $base = self::render();
        $this->assertTrue($base['ok']);
        $this->assertTrue($base['card']->has('kind'));
        $this->assertTrue($base['card']->has('friction'));
        $this->assertFalse(self::render([], ['kind'])['card']->has('kind'));
        $this->assertFalse(self::render([], ['friction'])['card']->has('friction'));
        $o256 = str_repeat('o', 256);
        $this->assertSame($o256, self::render(['site' => Obj::of(['origin' => $o256, 'name' => 'N'])])['card']->get('site')->get('origin'));
        $this->assertSame(str_repeat('o', 255) . "\u{2026}", self::render(['site' => Obj::of(['origin' => $o256 . 'o', 'name' => 'N'])])['card']->get('site')->get('origin'));
        $own = self::render(['catalog' => new Catalog([])])['card']->get('sentence');
        $this->assertStringStartsWith('Allow the action "stripe.refund" on Example Shop, ', $own);
        $num = self::render(['catalog' => new Catalog([['verb' => 'stripe.refund', 'description' => 5]])])['card']->get('sentence');
        $this->assertStringStartsWith('Allow 5, ', $num);
        $o64 = str_repeat('o', 64);
        $this->assertSame($o64, self::render(['site' => Obj::of(['origin' => $o64, 'name' => ''])])['card']->get('site')->get('name'));
        $this->assertSame(str_repeat('o', 63) . "\u{2026}", self::render(['site' => Obj::of(['origin' => $o64 . 'o', 'name' => ''])])['card']->get('site')->get('name'));
    }
}
