<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/NlApproval.php';

use Atlas\Pca\Catalog;
use Atlas\Pca\KeyPair;
use Atlas\Pca\NlApproval;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in NlApproval: digests, model-output refusals, the analyzer verdict, approval times and the NL-to-agent door. */
final class MixSurvivorKill28NlApprovalTest extends TestCase
{
    private const T = 1800000000000;
    private const RAW = '{"permissions":{"stripe":["refund"]},"limits":{"refund":"$50/day"}}';

    protected function tearDown(): void
    {
        NlApproval::$clockHook = null;
    }

    private static function secret(): string
    {
        return hash('sha256', 'atlas-pca-conformance/nl-approval-28', true);
    }

    private static function pub(): string
    {
        return (new KeyPair(self::secret()))->public;
    }

    private static function draft(): Obj
    {
        return NlApproval::draftPolicyFromNL('do the thing', static fn(string $p): string => self::RAW);
    }

    private static function reviewers(array $extra = []): Obj
    {
        return Obj::of(['reviewers' => [self::pub()]] + $extra);
    }

    private static function throwsMsg(string $class, string $msg, callable $f): void
    {
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    /** The draft digest sorts connectors, so the order the model listed them in does not matter. */
    public function testDigestIgnoresConnectorOrder(): void
    {
        $a = NlApproval::draftDigest(Obj::of(['b' => ['x'], 'a' => ['y']]), new Obj(), 'cd');
        self::assertSame($a, NlApproval::draftDigest(Obj::of(['a' => ['y'], 'b' => ['x']]), new Obj(), 'cd'));
        self::assertNotSame($a, NlApproval::draftDigest(Obj::of(['a' => ['x'], 'b' => ['y']]), new Obj(), 'cd'));
    }

    /** policyFromNL reads a non-string completion as its string form rather than failing. */
    public function testPolicyFromNonStringCompletion(): void
    {
        $p = NlApproval::policyFromNL('x', static fn(string $s): int => 5);
        self::assertSame(5, $p['raw']);
        self::assertSame([], $p['permissions']->keys());
    }

    /** A completion that is not a string is refused with the documented message. */
    public function testDraftRefusesNonStringCompletion(): void
    {
        self::throwsMsg(\RuntimeException::class, 'draftPolicyFromNL: model output exceeds 16384 bytes or is not a string',
            static fn() => NlApproval::draftPolicyFromNL('x', static fn(string $s): int => 5));
    }

    /** A draft whose compiled policy lints an error (a limit no granted action matches) is not analyzer-ok. */
    public function testLintErrorFailsTheAnalyzer(): void
    {
        $cat = new Catalog([...Catalog::BUILTIN_ACTIONS, ['connector' => 'other', 'action' => 'y', 'verb' => 'stripe.x', 'reversibility' => 'reversible',
            'blastRadius' => 0.1, 'description' => 'odd row']]);
        $d = NlApproval::draftPolicyFromNL('x', static fn(string $s): string => '{"permissions":{"stripe":["x"]},"limits":{"x":"5/day"}}', $cat);
        self::assertSame(['stripe'], $d->get('permissions')->keys());
        self::assertContains('error', array_map(static fn(Obj $l): string => $l->get('level'), $d->get('lints')));
        self::assertFalse($d->get('analyzerOk'));
        self::assertTrue(self::draft()->get('analyzerOk'));
    }

    /** Without opts the approval starts at `$nowDefault` (0) and lasts the default hour; a huge default is a binary64 like the reference's. */
    public function testApprovalDefaultTimes(): void
    {
        $a = NlApproval::approveDraft(self::draft(), self::secret());
        self::assertSame(['0', '3600000'], [$a->get('approved_at')->lexeme, $a->get('expires_at')->lexeme]);
        $l = NlApproval::approveDraftLegacyV1(self::draft(), self::secret());
        self::assertSame(['0', '3600000'], [$l->get('approved_at')->lexeme, $l->get('expires_at')->lexeme]);
        $big = NlApproval::approveDraft(self::draft(), self::secret(), null, 9007199254740993)->get('approved_at')->lexeme;
        self::assertStringStartsWith('9007199254740992', $big);
    }

    /** A draft without, or with a null, unknownVerbs is the reference's TypeError. */
    public function testMissingUnknownVerbs(): void
    {
        self::throwsMsg(\TypeError::class, "Cannot read properties of undefined (reading 'length')",
            static fn() => NlApproval::approveDraft(Obj::of(['analyzerOk' => true]), self::secret()));
        self::throwsMsg(\TypeError::class, "Cannot read properties of null (reading 'length')",
            static fn() => NlApproval::approveDraft(Obj::of(['analyzerOk' => true, 'unknownVerbs' => null]), self::secret()));
    }

    /** A non-numeric or NaN `now` is refused as an invalid time. */
    public function testInvalidNowRefused(): void
    {
        foreach (['x', NAN] as $now) {
            self::throwsMsg(\RuntimeException::class, 'approveDraft: invalid time or ttl',
                static fn() => NlApproval::approveDraft(self::draft(), self::secret(), Obj::of(['now' => $now])));
        }
    }

    /** loadApproved without `now` checks the window at `$nowDefault`: 0 admits an approval at 0, not one at 1; 5 admits the one at 1. */
    public function testLoadDefaultNow(): void
    {
        $a0 = NlApproval::approveDraft(self::draft(), self::secret());
        self::assertTrue(NlApproval::loadApproved(self::draft(), $a0, self::reviewers())['ok']);
        $a1 = NlApproval::approveDraft(self::draft(), self::secret(), Obj::of(['now' => 1]));
        self::assertSame(['ok' => false, 'reason' => 'not_yet_valid'], NlApproval::loadApproved(self::draft(), $a1, self::reviewers()));
        self::assertTrue(NlApproval::loadApproved(self::draft(), $a1, self::reviewers(), 5)['ok']);
    }

    /** An expiry of exactly 2^53 - 1 is still a safe integer. */
    public function testExpiryAtMaxSafeInteger(): void
    {
        $now = 9007199254740991 - 3600000;
        $a = NlApproval::approveDraft(self::draft(), self::secret(), Obj::of(['now' => $now]));
        self::assertTrue(NlApproval::loadApproved(self::draft(), $a, self::reviewers(['now' => $now]))['ok']);
    }

    /** A draft that lost its unknownVerbs member still loads (only a non-empty list is refused). */
    public function testLoadWithoutUnknownVerbs(): void
    {
        $a0 = NlApproval::approveDraft(self::draft(), self::secret());
        self::assertTrue(NlApproval::loadApproved(self::draft()->without('unknownVerbs'), $a0, self::reviewers())['ok']);
        $str = self::draft();
        $str->set('unknownVerbs', 'x');
        self::assertTrue(NlApproval::loadApproved($str, $a0, self::reviewers())['ok']);
    }

    /** Without `now` the agent is minted at the clock, in whole milliseconds; a failed load throws with its code. */
    public function testAgentFromApprovedUsesTheClock(): void
    {
        NlApproval::$clockHook = static fn(): float => 1800000000.0005;
        $a = NlApproval::approveDraft(self::draft(), self::secret(), Obj::of(['now' => self::T]));
        $r = NlApproval::agentFromApproved(self::draft(), $a, self::reviewers(), new KeyPair(str_repeat("\1", 32)), 'do the thing');
        self::assertSame(self::T, $r['agent']->budget['tau']);
        self::throwsMsg(\RuntimeException::class, 'agentFromApprovedNL: no_reviewers_pinned',
            static fn() => NlApproval::agentFromApproved(self::draft(), $a, Obj::of(['reviewers' => []]), new KeyPair(str_repeat("\1", 32)), 'do the thing'));
    }

    /** The agent is compiled against the catalog in opts, not the built-in one. */
    public function testAgentUsesTheGivenCatalog(): void
    {
        $cat = new Catalog([...Catalog::BUILTIN_ACTIONS, Catalog::defineAction(['connector' => 'acme', 'action' => 'zap', 'reversibility' => 'reversible',
            'blastRadius' => 0.1, 'description' => 'Zap.'])]);
        $d = NlApproval::draftPolicyFromNL('zap it', static fn(string $s): string => '{"permissions":{"acme":["zap"]},"limits":{}}', $cat);
        self::assertTrue($d->get('analyzerOk'));
        $a = NlApproval::approveDraft($d, self::secret(), Obj::of(['now' => self::T]));
        $r = NlApproval::agentFromApproved($d, $a, self::reviewers(['catalog' => $cat, 'now' => self::T]), new KeyPair(str_repeat("\1", 32)), 'zap it');
        self::assertSame(['reversible', 'Zap.'], [$r['agent']->policy['actions'][0]['reversibility'], $r['agent']->policy['actions'][0]['description']]);
    }
}
