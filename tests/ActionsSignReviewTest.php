<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsReview.php';

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsReview;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** signReview (confirmation.ts): the producer half of a signed human confirmation. */
final class ActionsSignReviewTest extends TestCase
{
    public function testSignsTheNormalizedBody(): void
    {
        $seed = str_repeat("\5", 32);
        $dg = Pca::b64u(str_repeat("\1", 32));
        $b = Json::parseLax('{"def_digest":"' . $dg . '","traits_digest":"' . $dg . '","facts_digest":"' . $dg . '","final_traits":["pca.money_moving","pca.irreversible","pca.irreversible"],'
            . '"dismissed":[{"trait":"pca.z","reason":"r"},{"trait":"pca.a","reason":"s"}],"reviewer_kid":"k1","ts":5}');
        $r = ActionsReview::signReview($b, $seed);
        self::assertSame(['pca.irreversible', 'pca.money_moving'], $r->get('final_traits'));
        self::assertSame(['pca.a', 'pca.z'], array_map(fn($d) => $d->get('trait'), $r->get('dismissed')));
        $pub = (new KeyPair($seed))->public;
        self::assertTrue(Pca::verifyEd25519B64u($pub, Actions::reviewMessage($r), $r->get('sig')));
        self::assertSame(3, count($b->get('final_traits')), 'the input is not mutated');
        $this->expectException(\InvalidArgumentException::class);
        ActionsReview::signReview($b, 'short');
    }
}
