<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsDerive;
use Atlas\Pca\ActionsReview;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of the review flow: attestation verdict reasons, confirmDef refusals and their exact messages, ts handling. */
final class MathSurvivorKill31ActionsReviewTest extends TestCase
{
    private const FILE = 'ref-actions-review.json.gz';
    private const MALFORMED = 'the attestation final_traits, dismissed, ts or reviewer_kid is malformed';

    protected function tearDown(): void
    {
        Actions::$validateDefHook = null;
    }

    private static function case(string $fn, string $name): Obj
    {
        foreach (Base::cases(self::FILE, $fn, 0) as $c) {
            if ($c->get('name') === $name) {
                return $c;
            }
        }
        self::fail("no corpus case $name");
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/ref-actions-review-py/rev', true);
    }

    /** @return array<string,mixed> */
    private static function opts(Obj $oo): array
    {
        $rd = $oo->get('regDefs');
        $o = ['registry' => $rd === null ? Actions::coreRegistry() : Actions::extendRegistry(Actions::coreRegistry(), $rd),
            'reviewer' => ['kid' => $oo->get('kid'), 'secret' => Base::bytes($oo->get('seed'))], 'finalTraits' => $oo->get('finalTraits'), 'ts' => $oo->get('ts')];
        if ($oo->get('pins') !== null) {
            $o['pins'] = $oo->get('pins');
        }
        if ($oo->get('dismissed')) {
            $o['dismissed'] = $oo->get('dismissed');
        }
        return $o;
    }

    /** @return array{0:Obj,1:array<string,mixed>} the def and options of a confirmDef corpus case */
    private static function confirmCase(string $name): array
    {
        $a = self::case('confirmDef', "confirmDef/$name")->get('args');
        return [$a[0], self::opts($a[1])];
    }

    /** @return array{0:Obj,1:Obj} a confirmed def with a valid attestation and the pins it verifies against */
    private static function ok0(): array
    {
        $a = self::case('verifyAttestation', 'verifyAttestation/ok0')->get('args');
        return [$a[0], $a[1]];
    }

    private static function att(Obj $d): Obj
    {
        return $d->get('review')->get('attestation');
    }

    private static function verdict(mixed $d, Obj $pins): Obj
    {
        return ActionsReview::verifyAttestationVerdict($d, Actions::coreRegistry(), $pins);
    }

    private static function assertFail(string $reason, string $detail, Obj $v): void
    {
        self::assertSame([false, $reason, $detail], [$v->get('ok'), $v->get('reason'), $v->get('detail')]);
    }

    private static function confirmThrows(Obj $d, array $o): ActionKitError
    {
        try {
            ActionsReview::confirmDef($d, $o);
        } catch (ActionKitError $e) {
            return $e;
        }
        self::fail('confirmDef did not refuse');
    }

    /** Every refusing confirmDef case of the reference corpus refuses with the reference's exact code AND message. */
    public function testConfirmRefusalsCarryTheExactMessage(): void
    {
        $n = 0;
        foreach (Base::cases(self::FILE, 'confirmDef', 0) as $c) {
            $want = $c->get('out');
            if (!($want instanceof Obj) || !$want->has('$throws')) {
                continue;
            }
            $a = $c->get('args');
            $e = self::confirmThrows($a[0], self::opts($a[1]));
            self::assertSame([$want->get('code'), $want->get('$throws')], [$e->codeName, $e->getMessage()], (string)$c->get('name'));
            $n++;
        }
        self::assertSame(16, $n);
    }

    /** A ts that is not a non-negative safe integer is refused with its reason: a string, -0, an absent ts. */
    public function testConfirmTsRefusals(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        foreach (['1000', new Num('-0'), null] as $ts) {
            $o['ts'] = $ts;
            $e = self::confirmThrows($d, $o);
            self::assertSame(['bad_confirm', 'ts must be a non-negative integer'], [$e->codeName, $e->getMessage()]);
        }
    }

    /** ts is carried as the reference's integer: up to MAX_SAFE, digits only (never an exponent form), a Num 1e3 is 1000. */
    public function testConfirmTsIsTheInteger(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        $o['ts'] = 9007199254740991;
        self::assertSame('9007199254740991', self::att(ActionsReview::confirmDef($d, $o))->get('ts')->lexeme);
        $o['ts'] = 1000000000000000;
        self::assertSame('1000000000000000', self::att(ActionsReview::confirmDef($d, $o))->get('ts')->lexeme);
        $o['ts'] = new Num('1e3');
        $out = ActionsReview::confirmDef($d, $o);
        $want = self::case('confirmDef', 'confirmDef/ok stripe.charge')->get('out');
        self::assertSame('1000', self::att($out)->get('ts')->lexeme);
        self::assertSame(self::att($want)->get('sig'), self::att($out)->get('sig'));
    }

    /** A reviewer secret of the wrong length is refused with the reviewer-key message (before any key is built). */
    public function testConfirmShortSecret(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        $o['reviewer']['secret'] = 'short';
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('the reviewer key must be a 32-byte Ed25519 secret');
        ActionsReview::confirmDef($d, $o);
    }

    /** signReview refuses a key of another length with its message. */
    public function testSignReviewShortSecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('the reviewer key must be a 32-byte Ed25519 secret');
        ActionsReview::signReview(new Obj(), 'short');
    }

    /** Dismissals given as plain arrays work like Objs; a 256-character reason is still within bounds. */
    public function testDismissalsAsArraysAndMaxReason(): void
    {
        [$d, $o] = self::confirmCase('dismissed ok');
        $want = self::case('confirmDef', 'confirmDef/dismissed ok')->get('out');
        $o['dismissed'] = [['trait' => 'pca.bulk', 'reason' => 'one at a time']];
        self::assertSame(self::att($want)->get('sig'), self::att(ActionsReview::confirmDef($d, $o))->get('sig'));
        [$d, $o] = self::confirmCase('dismissed ok');
        $o['dismissed'] = [['trait' => 'pca.bulk', 'reason' => str_repeat('x', 256)]];
        self::assertSame(str_repeat('x', 256), self::att(ActionsReview::confirmDef($d, $o))->get('dismissed')[0]->get('reason'));
    }

    /** The attested dismissals are sorted by trait, whatever order the reviewer gave them in. */
    public function testDismissalsAreSorted(): void
    {
        [$d, $o] = self::confirmCase('dismissed ok');
        $d->get('review')->get('suggested_by')->get('added')->set('traits', ['pca.bulk', 'pca.zzz']);
        $o['dismissed'] = [['trait' => 'pca.zzz', 'reason' => 'r'], ['trait' => 'pca.bulk', 'reason' => 'r']];
        $dm = self::att(ActionsReview::confirmDef($d, $o))->get('dismissed');
        self::assertSame(['pca.bulk', 'pca.zzz'], array_map(fn($x) => $x->get('trait'), $dm));
    }

    /** A declared trait counts as shown: leaving it out of the final set without a dismissal is refused. */
    public function testDeclaredTraitsAreShown(): void
    {
        [$d, $o] = self::confirmCase('undismissed');
        $d->set('traits', ['pca.bulk']);
        $d->get('review')->get('suggested_by')->get('added')->set('traits', []);
        $e = self::confirmThrows($d, $o);
        self::assertSame(['undismissed_suggestion', "trait 'pca.bulk' was suggested and is not in the final set: record it as dismissed with a reason"],
            [$e->codeName, $e->getMessage()]);
    }

    /** A suggested_by without `added` has no added traits (it is not an error). */
    public function testSuggestedByWithoutAdded(): void
    {
        [$d, $o] = self::confirmCase('undismissed');
        $d->get('review')->set('suggested_by', new Obj());
        self::assertSame('confirmed', ActionsReview::confirmDef($d, $o)->get('review')->get('state'));
    }

    /** A shown trait implied by the def's own facts is covered: it needs neither a final entry nor a dismissal. */
    public function testImpliedTraitsAreCovered(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        $implied = ActionsDerive::impliedTraits(Actions::normalize($d));
        self::assertNotEmpty($implied);
        $d->set('traits', [$implied[0]]);
        $o['finalTraits'] = [];
        self::assertSame('confirmed', ActionsReview::confirmDef($d, $o)->get('review')->get('state'));
    }

    /** A shown trait implied (through the registry) by a final trait is covered too. */
    public function testFinalClosureIsCovered(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        $reg = $o['registry'];
        $implied = Actions::closure($reg, ActionsDerive::impliedTraits(Actions::normalize($d)));
        $pair = null;
        foreach (array_keys($reg) as $f) {
            foreach ($f === 'pca.unreviewed' ? [] : Actions::closure($reg, [$f]) as $u) {
                if ($pair === null && $u !== $f && !in_array($u, $implied, true)) {
                    $pair = [$f, $u];
                }
            }
        }
        self::assertNotNull($pair, 'some registry trait implies a trait the def\'s facts do not');
        $d->set('traits', [$pair[1]]);
        $o['finalTraits'] = [$pair[0]];
        self::assertSame([$pair[0]], ActionsReview::confirmDef($d, $o)->get('traits'));
    }

    /** Every shown trait is checked: a covered one first does not end the check for an uncovered one after it. */
    public function testEveryShownTraitIsChecked(): void
    {
        [$d, $o] = self::confirmCase('undismissed');
        self::assertArrayNotHasKey('pca.zzz', $o['registry']);
        $d->get('review')->get('suggested_by')->get('added')->set('traits', ['pca.irreversible', 'pca.zzz']);
        $o['finalTraits'] = ['pca.irreversible'];
        $e = self::confirmThrows($d, $o);
        self::assertSame(['undismissed_suggestion', "trait 'pca.zzz' was suggested and is not in the final set: record it as dismissed with a reason"],
            [$e->codeName, $e->getMessage()]);
    }

    /** A numeric-looking dismissed trait id is still matched against the shown traits as a string. */
    public function testNumericDismissedTraitIsMatchedAsString(): void
    {
        [$d, $o] = self::confirmCase('undismissed');
        $d->get('review')->get('suggested_by')->get('added')->set('traits', ['5']);
        $o['dismissed'] = [['trait' => '5', 'reason' => 'r']];
        $e = self::confirmThrows($d, $o);
        self::assertSame('bad_confirm', $e->codeName);
        self::assertStringStartsWith('the confirmed def is invalid: ', $e->getMessage());
    }

    /** A confirmed def that fails validation is refused, never returned. */
    public function testInvalidConfirmedDefIsRefused(): void
    {
        [$d, $o] = self::confirmCase('ok stripe.charge');
        Actions::$validateDefHook = static function (mixed $x): void {
            if ($x instanceof Obj && $x->get('review') instanceof Obj && $x->get('review')->get('state') === 'confirmed') {
                throw new \RuntimeException('boom');
            }
        };
        $e = self::confirmThrows($d, $o);
        self::assertSame(['bad_confirm', 'the confirmed def is invalid: malformed def: boom'], [$e->codeName, $e->getMessage()]);
    }

    /** A def that is not an object, or whose review is not an object, is not_confirmed (not malformed). */
    public function testVerdictNotConfirmedShapes(): void
    {
        [, $pins] = self::ok0();
        self::assertFail('not_confirmed', 'review.state is not confirmed', self::verdict('x', $pins));
        self::assertFail('not_confirmed', 'review.state is not confirmed', self::verdict(Obj::of(['review' => 'x']), $pins));
    }

    /** final_traits with a non-string, a non-list dismissed, a null / string / -0 ts are malformed with the shape detail. */
    public function testVerdictMalformedShapes(): void
    {
        foreach ([['final_traits', [5]], ['dismissed', 'x'], ['ts', null], ['ts', '1000'], ['ts', new Num('-0')]] as [$k, $v]) {
            [$d, $pins] = self::ok0();
            self::att($d)->set($k, $v);
            self::assertFail('malformed', self::MALFORMED, self::verdict($d, $pins));
        }
    }

    /** ts = MAX_SAFE is a well-formed ts (it is then judged by the key validity). */
    public function testVerdictMaxSafeTs(): void
    {
        [$d, $pins] = self::ok0();
        self::att($d)->set('ts', new Num('9007199254740991'));
        self::assertFail('outside_validity', 'the attestation time is outside the key validity', self::verdict($d, $pins));
    }

    /** The key validity bounds are inclusive: ts equal to not_before or not_after verifies, one past either does not. */
    public function testVerdictValidityBoundsInclusive(): void
    {
        foreach (['100' => true, '99' => false, '2000000000' => true, '2000000001' => false] as $ts => $ok) {
            [$d, $pins] = self::ok0();
            $a = self::att($d);
            $a->set('ts', new Num((string)$ts));
            $a->set('sig', Pca::b64u((new KeyPair(self::seed()))->sign(Actions::reviewMessage($a->without('sig')))));
            $v = self::verdict($d, $pins);
            if ($ok) {
                self::assertSame([true, 'rev1'], [$v->get('ok'), $v->get('kid')], "ts $ts");
            } else {
                self::assertFail('outside_validity', 'the attestation time is outside the key validity', $v);
            }
        }
    }

    /** A def confirmed with a valid dismissal verifies: a dismissed trait that is not final and has a reason is no conflict. */
    public function testVerdictAcceptsAValidDismissal(): void
    {
        [$d, $o] = self::confirmCase('dismissed ok');
        [, $pins] = self::ok0();
        $v = self::verdict(ActionsReview::confirmDef($d, $o), $pins);
        self::assertSame([true, 'rev1'], [$v->get('ok'), $v->get('kid')]);
    }

    /** The review view lists a member the new def added, and the declared traits it carries. */
    public function testPrepareReviewChangesAndDeclaredTraits(): void
    {
        [$d] = self::confirmCase('ok stripe.charge');
        self::assertSame(['aliases'], ActionsReview::prepareReview($d, Actions::coreRegistry(), $d->without('aliases'))->get('changes'));
        [$c] = self::ok0();
        self::assertSame(['pca.irreversible', 'pca.money_moving'], ActionsReview::prepareReview($c, Actions::coreRegistry())->get('declared_traits'));
    }
}
