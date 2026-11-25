<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsSelector.php';

use Atlas\Pca\ActionsApprovalProfiles;
use Atlas\Pca\ActionsIdPattern;
use Atlas\Pca\ActionsSelector;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** selector.ts, idpattern.ts and the approval profiles of pca-actions. */
final class ActionsSelectorTest extends TestCase
{
    private static function sel(string $j): Obj
    {
        return Json::parseLax($j);
    }

    public function testSelectorMatching(): void
    {
        $cl = ['a', 'b'];
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"trait","id":"a"}'), $cl));
        self::assertFalse(ActionsSelector::selectorMatches(self::sel('{"k":"trait","id":"z"}'), $cl));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"all_of","ids":["a","b"]}'), $cl));
        self::assertFalse(ActionsSelector::selectorMatches(self::sel('{"k":"all_of","ids":["a","z"]}'), $cl));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"any_of","ids":["z","b"]}'), $cl));
        self::assertFalse(ActionsSelector::selectorMatches(self::sel('{"k":"any_of","ids":[]}'), $cl));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"all_of","ids":[]}'), $cl));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"not","s":{"k":"trait","id":"z"}}'), $cl));
        self::assertTrue(ActionsSelector::selectorMatches(self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"trait","id":"b"}}'), $cl));
        self::assertNull(ActionsSelector::selectorMatches(self::sel('{"k":"weird"}'), $cl));
    }

    public function testUnconfirmedActionsAreMaximallyDangerous(): void
    {
        $s = self::sel('{"k":"trait","id":"a"}');
        self::assertTrue(ActionsSelector::selectorMatchesFor($s, 'prohibit', [], false));
        self::assertFalse(ActionsSelector::selectorMatchesFor($s, 'allow', ['a'], false));
        self::assertTrue(ActionsSelector::selectorMatchesFor($s, 'allow', ['a'], true));
    }

    public function testAllowSelectorTypingAndPolicyDecision(): void
    {
        $not = self::sel('{"k":"not","s":{"k":"trait","id":"a"}}');
        $any = self::sel('{"k":"and","a":{"k":"trait","id":"a"},"b":{"k":"any_of","ids":["b"]}}');
        self::assertTrue(ActionsSelector::selectorHasNot($not));
        self::assertNotNull(ActionsSelector::allowSelectorError($not, true));
        self::assertNotNull(ActionsSelector::allowSelectorError($any, false));
        self::assertNull(ActionsSelector::allowSelectorError($any, true));
        $p = self::sel('{"prohibit":[{"k":"trait","id":"bad"}],"allow":[{"k":"trait","id":"ok"}],"pinned":["v1"],"on_new_action":"escalate"}');
        self::assertSame('deny', ActionsSelector::policyDecision($p, 'v1', ['bad', 'ok'], true));
        self::assertSame('allow', ActionsSelector::policyDecision($p, 'v1', ['ok'], true));
        self::assertSame('deny', ActionsSelector::policyDecision($p, 'v1', ['x'], true));
        self::assertSame('escalate', ActionsSelector::policyDecision($p, 'v2', ['ok'], true));
        self::assertSame('deny', ActionsSelector::policyDecision($p, 'v1', ['ok'], false));
    }

    public function testIdPatterns(): void
    {
        $pre = self::sel('{"prefix":"cus_","class":"alnum","len":[4,8]}');
        self::assertTrue(ActionsIdPattern::idMatches('*', 'a/b-1'));
        self::assertFalse(ActionsIdPattern::idMatches('*', ''));
        self::assertFalse(ActionsIdPattern::idMatches('*', 5));
        self::assertTrue(ActionsIdPattern::idMatches(self::sel('{"exact":"x1"}'), 'x1'));
        self::assertTrue(ActionsIdPattern::idMatches($pre, 'cus_abcd1'));
        self::assertFalse(ActionsIdPattern::idMatches($pre, 'cus_ab'));
        self::assertFalse(ActionsIdPattern::idMatches($pre, 'cus_ab-cd'));
        self::assertFalse(ActionsIdPattern::idMatches($pre, 'xyz_abcd'));
        $uuid = self::sel('{"prefix":"","class":"uuid","len":[36,36]}');
        self::assertTrue(ActionsIdPattern::idMatches($uuid, '123e4567-e89b-12d3-a456-426614174000'));
        self::assertFalse(ActionsIdPattern::idMatches($uuid, '123e4567-e89b-12d3-a456-42661417400g'));
        self::assertTrue(ActionsIdPattern::inClass('abc', 'hex'));
        self::assertFalse(ActionsIdPattern::inClass('abg', 'hex'));
    }

    public function testIdPatternContainment(): void
    {
        $outer = self::sel('{"prefix":"cus_","class":"alnum","len":[4,16]}');
        $inner = self::sel('{"prefix":"cus_ab","class":"hex","len":[2,8]}');
        self::assertTrue(ActionsIdPattern::idPatternContains('*', $outer));
        self::assertFalse(ActionsIdPattern::idPatternContains($outer, '*'));
        self::assertTrue(ActionsIdPattern::idPatternContains($outer, $inner));
        self::assertFalse(ActionsIdPattern::idPatternContains($inner, $outer));
        self::assertTrue(ActionsIdPattern::idPatternContains($outer, self::sel('{"exact":"cus_abcd"}')));
        self::assertFalse(ActionsIdPattern::idPatternContains(self::sel('{"exact":"cus_abcd"}'), $inner));
        self::assertTrue(ActionsIdPattern::idPatternContains(self::sel('{"exact":"a"}'), self::sel('{"exact":"a"}')));
        self::assertFalse(ActionsIdPattern::idPatternContains($outer, self::sel('{"prefix":"cus_","class":"alnum","len":[2,16]}')), 'a shorter minimum is not contained');
    }

    public function testApprovalProfiles(): void
    {
        self::assertSame('atlas-pca/approval-batch/v1', ActionsApprovalProfiles::APPROVAL_BATCH_DOMAIN);
    }
}
