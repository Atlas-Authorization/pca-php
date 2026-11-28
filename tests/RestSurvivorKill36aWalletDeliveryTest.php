<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/WalletDelivery.php';

use Atlas\Pca\Obj;
use Atlas\Pca\WalletDelivery;
use Atlas\Pca\WalletHandlers;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/WalletDelivery.php: refusal texts, the no-fetch webhook, the action shape gate and refusal statuses. */
final class RestSurvivorKill36aWalletDeliveryTest extends TestCase
{
    /** A question that does not verify is refused with the verifier's reason behind the fixed prefix. */
    public function testSiteQuestionNoticeCarriesTheRefusalReason(): void
    {
        try {
            WalletDelivery::siteQuestionNotice(new Obj(), ['now' => 'x']);
            self::fail('an unverified question produced a notice');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('siteQuestionNotice: the verifier clock is not a safe integer (fail closed)', $e->getMessage());
        }
    }

    private static function thrownMessage(\Closure $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'no throw';
    }

    /** The inbox link needs a string inbox_url and a string question_id; anything else is a TypeError naming the member. */
    public function testQuestionTextLinkMembersMustBeStrings(): void
    {
        $ok = WalletDelivery::questionText(Obj::of(['type' => 'pca.intent.clarification', 'question_id' => 'q1', 'inbox_url' => 'https://w.example/inbox']), null);
        self::assertSame("Your agent needs a decision about your request\n\nOpen your wallet to answer: https://w.example/inbox?question=q1", $ok->get('text'));
        self::assertSame('inbox_url must be a string', self::thrownMessage(static fn() => WalletDelivery::questionText(
            Obj::of(['type' => 'pca.intent.clarification', 'question_id' => 'q1', 'inbox_url' => 5]), null)));
        self::assertSame('question_id must be a string', self::thrownMessage(static fn() => WalletDelivery::questionText(
            Obj::of(['type' => 'pca.intent.clarification', 'question_id' => 7, 'inbox_url' => 'https://w.example/inbox']), null)));
    }

    /** A webhook with a URL but no fetch reports the fixed "no fetch available" reason instead of touching the network. */
    public function testWebhookWithoutFetchReportsNoFetch(): void
    {
        $ch = WalletDelivery::webhookChannel(['url' => 'https://w.example/hook']);
        self::assertTrue($ch->enabled);
        $d = $ch->notify(Obj::of(['question_id' => 'q1']));
        self::assertFalse($d->get('delivered'));
        self::assertSame('no fetch available: pass a FetchLike transport', $d->get('reason'));
    }

    /** The question endpoint refuses an action whose verb, resource or class is not a string before the channel sees it; unknown refusal codes map to 400. */
    public function testQuestionHandlerActionGateAndRefusalStatus(): void
    {
        $chan = new class {
            public int $calls = 0;
            public string $code = 'frozen';

            /** @return array{ok:bool,code:string} */
            public function receive(mixed $ir, mixed $ctx): array
            {
                $this->calls++;
                return ['ok' => false, 'code' => $this->code];
            }
        };
        $h = WalletHandlers::questionHandler(static fn(mixed $sid) => $chan);
        $req = static fn(array $over): Obj => Obj::of(['intent_required' => Obj::of(['x' => 1]), 'action' => Obj::of(array_merge(
            ['verb' => 'pay', 'resource' => 'acct:a', 'reversibility_class' => 'reversible', 'params' => Obj::of(['amount' => 1])], $over))]);
        $r = $h('s1', $req([]));
        self::assertSame([429, 'frozen', 1], [$r['status'], $r['body']->get('error'), $chan->calls]);
        foreach (['verb', 'resource', 'reversibility_class'] as $k) {
            $r = $h('s1', $req([$k => 5]));
            self::assertSame([400, 'bad_request', 1], [$r['status'], $r['body']->get('error'), $chan->calls], "non-string $k");
        }
        $chan->code = 'mystery';
        $r = $h('s1', $req([]));
        self::assertSame([400, 'mystery'], [$r['status'], $r['body']->get('error')]);
    }
}
