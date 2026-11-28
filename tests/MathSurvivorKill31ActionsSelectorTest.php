<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsSelector.php';

use Atlas\Pca\ActionsApprovalProfiles;
use Atlas\Pca\ActionsIdPattern;
use Atlas\Pca\ActionsSelector;
use Atlas\Pca\Approval;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of selector.ts / idpattern.ts / approval-profiles.ts. */
final class MathSurvivorKill31ActionsSelectorTest extends TestCase
{
    private const DD = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    private static function sel(string $j): Obj
    {
        return Json::parseLax($j);
    }

    private static function payment(): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-approval-render', 'verb' => 'bank.pay', 'def_digest' => self::DD, 'unreviewed' => false, 'fields' => [
            Obj::of(['id' => 'amount', 'class' => 'money.amount', 'value' => new Num('12345'), 'unit' => Obj::of(['kind' => 'money', 'ccy' => 'EUR', 'exp' => new Num('2')])]),
            Obj::of(['id' => 'payee', 'class' => 'party.payee', 'value' => 'Acme']),
        ]]);
    }

    /** any_of is true only when some listed trait is carried: a missing trait never makes it match, a present one always does. */
    public function testAnyOfMatchesOnlyOnACarriedTrait(): void
    {
        self::assertFalse(ActionsSelector::selectorMatches(self::sel('{"k":"any_of","ids":["z"]}'), ['a']));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"any_of","ids":["a"]}'), ['a']));
    }

    /** and needs both sides: one false side makes the conjunction false. */
    public function testAndNeedsBothSides(): void
    {
        $s = self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"trait","id":"z"}}');
        self::assertFalse(ActionsSelector::selectorMatches($s, ['a']));
        self::assertFalse(ActionsSelector::selectorMatches(self::sel('{"k":"and","a":{"k":"trait","id":"z"},"b":{"k":"trait","id":"a"}}'), ['a']));
    }

    /** A negation is found on either side of an and; a plain trait or a negation-free and has none. */
    public function testSelectorHasNotWalksAnd(): void
    {
        self::assertFalse(ActionsSelector::selectorHasNot(self::sel('{"k":"trait","id":"a"}')));
        self::assertFalse(ActionsSelector::selectorHasNot(self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"trait","id":"b"}}')));
        self::assertTrue(ActionsSelector::selectorHasNot(self::sel('{"k":"and","a":{"k":"not","s":{"k":"trait","id":"a"}},"b":{"k":"trait","id":"b"}}')));
        self::assertTrue(ActionsSelector::selectorHasNot(self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"not","s":{"k":"trait","id":"b"}}}')));
        self::assertSame('an allow selector must not use negation: the absence of a trait is never a safety claim',
            ActionsSelector::allowSelectorError(self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"not","s":{"k":"trait","id":"b"}}}'), true));
    }

    /** An unpinned allow selector without any_of is fine; any_of on either side of an and is refused with its reason. */
    public function testUnpinnedAllowAnyOfRule(): void
    {
        self::assertNull(ActionsSelector::allowSelectorError(self::sel('{"k":"trait","id":"a"}'), false));
        self::assertNull(ActionsSelector::allowSelectorError(self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"trait","id":"b"}}'), false));
        $msg = 'any_of in an allow selector requires the grant to be pinned to a pack digest';
        self::assertSame($msg, ActionsSelector::allowSelectorError(self::sel('{"k":"and","a":{"k":"any_of","ids":["a"]},"b":{"k":"trait","id":"b"}}'), false));
        self::assertSame($msg, ActionsSelector::allowSelectorError(self::sel('{"k":"any_of","ids":["a"]}'), false));
    }

    /** The id class character sets are exactly ID_CLASS_CHARS of the reference. */
    public function testIdClassChars(): void
    {
        $d = '0123456789';
        $l = 'abcdefghijklmnopqrstuvwxyz';
        $u = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        self::assertSame(['digits' => $d, 'hex' => $d . 'abcdef', 'alnum' => $d . $l . $u, 'slug' => $d . $l . '-_', 'uuid' => $d . 'abcdef-', 'any_safe' => $d . $l . $u . '._-:/'],
            ActionsIdPattern::idClassChars());
    }

    /** A pattern that is neither '*' nor an object never matches (and never throws). */
    public function testNonObjectPatternNeverMatches(): void
    {
        self::assertFalse(ActionsIdPattern::idMatches('foo', 'x'));
        self::assertFalse(ActionsIdPattern::idMatches(['exact' => 'x'], 'x'));
    }

    /** len bounds compare untruncated, as the reference: a fractional minimum is not rounded down, a negative maximum refuses even ''. */
    public function testLenBoundsAreNotTruncated(): void
    {
        $p = self::sel('{"prefix":"","class":"digits","len":[1.5,3]}');
        self::assertFalse(ActionsIdPattern::idMatches($p, '1'));
        self::assertTrue(ActionsIdPattern::idMatches($p, '12'));
        self::assertFalse(ActionsIdPattern::idMatches(self::sel('{"prefix":"","class":"digits","len":[0,-0.5]}'), ''));
        self::assertTrue(ActionsIdPattern::idMatches(self::sel('{"prefix":"","class":"digits","len":[0,0]}'), ''), 'control');
    }

    /** A prefix pattern with no class never matches. */
    public function testClasslessPatternNeverMatches(): void
    {
        self::assertFalse(ActionsIdPattern::idMatches(self::sel('{"prefix":"a","len":[0,5]}'), 'ab'));
    }

    /** An absent prefix reads as '' on either side of containment. */
    public function testAbsentPrefixIsEmpty(): void
    {
        self::assertTrue(ActionsIdPattern::idPatternContains(self::sel('{"class":"alnum","len":[0,10]}'), self::sel('{"prefix":"ab","class":"alnum","len":[0,3]}')));
        self::assertTrue(ActionsIdPattern::idPatternContains(self::sel('{"prefix":"","class":"alnum","len":[0,10]}'), self::sel('{"class":"digits","len":[0,3]}')));
    }

    /** An outer pattern with no class contains nothing. */
    public function testClasslessOuterContainsNothing(): void
    {
        self::assertFalse(ActionsIdPattern::idPatternContains(self::sel('{"prefix":"","len":[0,10]}'), self::sel('{"prefix":"a","class":"alnum","len":[0,3]}')));
    }

    /** An inner pattern with no id class is refused with a TypeError, as the reference. */
    public function testClasslessInnerThrows(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('resource.id.class is not an id class');
        ActionsIdPattern::idPatternContains(self::sel('{"prefix":"","class":"alnum","len":[0,10]}'), self::sel('{"prefix":"a","len":[0,3]}'));
    }

    /** The SPC expectation carries topOrigin, the decimal total and the payee under the chosen key. */
    public function testSpcExpectation(): void
    {
        $r = self::payment();
        self::assertSame(['topOrigin' => 'https://shop.example', 'total' => ['currency' => 'EUR', 'value' => '123.45'], 'payeeName' => 'Acme'],
            ActionsApprovalProfiles::spcExpectation($r, 'https://shop.example'));
        self::assertSame(['topOrigin' => 'https://shop.example', 'total' => ['currency' => 'EUR', 'value' => '123.45'], 'payeeOrigin' => 'Acme'],
            ActionsApprovalProfiles::spcExpectation($r, 'https://shop.example', 'origin'));
    }

    /** The CIBA entry is one pca_approval detail with the render and its digest, plus the digest's binding words. */
    public function testCibaApprovalDetails(): void
    {
        $r = self::payment();
        $d = Approval::renderDigest($r);
        $out = ActionsApprovalProfiles::cibaApprovalDetails($r);
        self::assertSame(['authorization_details', 'match_code'], array_keys($out));
        self::assertCount(1, $out['authorization_details']);
        $e = $out['authorization_details'][0];
        self::assertSame(['type', 'render', 'render_digest'], $e->keys());
        self::assertSame('pca_approval', $e->get('type'));
        self::assertSame($r, $e->get('render'));
        self::assertSame($d, $e->get('render_digest'));
        self::assertSame(Approval::bindingWords($d), $out['match_code']);
    }
}
