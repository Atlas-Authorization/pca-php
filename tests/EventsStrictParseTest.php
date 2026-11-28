<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Events;
use PHPUnit\Framework\TestCase;

/** An event is parsed with the strict canonical JSON profile: what json_decode would accept (last duplicate wins, 1e3, 1.0) is refused. */
final class EventsStrictParseTest extends TestCase
{
    private const ID = '_WFEOpHOF2DoDNCiZ82gsd88d9JSKrFI8i5s6c-eZMg';

    private static function event(string $at = '1700000000000', string $grant = '"g1"', string $extra = ''): string
    {
        return '{"id":"' . self::ID . '","type":"step_up.approved","at":' . $at . ',"grant_ref":' . $grant
            . ',"action":{"verb":"stripe.refund","resource":"pi_1"},"tier":2' . $extra . '}';
    }

    public function testACanonicalEventParses(): void
    {
        self::assertSame(self::ID, Events::parseEvent(self::event())['id']);
    }

    public function testRefusesWhatALaxParserAccepts(): void
    {
        $bad = [
            'duplicate member' => self::event('1700000000000', '"g1"', ',"id":"' . self::ID . '"'),
            'exponent' => self::event('17e11'),
            'trailing zero' => self::event('1700000000000.0'),
            'negative zero' => self::event('-0'),
            'lone surrogate' => self::event('1700000000000', '"\\ud800"'),
            'trailing characters' => self::event() . ' x',
            'unsafe integer' => self::event('9007199254740992'),
        ];
        foreach ($bad as $why => $text) {
            try {
                Events::parseEvent($text);
                self::fail("accepted: $why");
            } catch (\Throwable $e) {
                self::assertNotInstanceOf(\PHPUnit\Framework\AssertionFailedError::class, $e, $why);
            }
        }
    }
}
