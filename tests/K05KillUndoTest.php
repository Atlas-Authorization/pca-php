<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Undo.php';

use Atlas\Pca\IntentWb;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Undo;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Undo: idOk visibility, req() exception types, receipt shape checks, the UTF-16 note clip, big clocks. */
final class K05KillUndoTest extends TestCase
{
    public function testIdOkIsPublic(): void
    {
        self::assertTrue(Undo::idOk('a'));
        self::assertFalse(Undo::idOk(''));
    }

    public function testCompensationDigestOfNullReadsLikeJs(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Cannot read properties of null (reading 'verb')");
        Undo::compensationDigest(null);
    }

    public function testCompensationDigestOfNonObjectIsUndefined(): void
    {
        $this->expectException(JsonError::class);
        Undo::compensationDigest('x');
    }

    public function testDecodeNonObject(): void
    {
        self::assertNull(Undo::decodeToken(Pca::b64u('[1]')));
    }

    public function testReceiptShape(): void
    {
        $k = new KeyPair(str_repeat("\x03", 32));
        $r = Undo::signReceipt(Obj::of(['record' => 'rec1', 'event' => 'opened', 'state' => 'open', 'at' => new Num('1'),
            'compensation_digest' => 'cd', 'prev' => '', 'note' => '']), $k);
        self::assertTrue(Undo::verifyReceipt($r, $k->public));
        $resigned = static function (string $m, mixed $v) use ($r, $k): Obj {
            $b = $r->without('sig');
            $b->set($m, $v);
            $b->set('sig', Pca::b64u($k->sign(Undo::RECEIPT_DOMAIN . IntentWb::canon($b))));
            return $b;
        };
        self::assertFalse(Undo::verifyReceipt($resigned('extra', 'y'), $k->public), 'unknown member, validly signed');
        self::assertFalse(Undo::verifyReceipt($resigned('v', new Num('2')), $k->public), 'v 2, validly signed');
        self::assertFalse(Undo::verifyReceipt($resigned('kind', 'other'), $k->public), 'wrong kind, validly signed');
    }

    /** The receipt note of an abort: the reason clipped to 128 UTF-16 units, a surrogate pair never split. */
    private static function abortNote(string $reason): string
    {
        $rec = Obj::of(['state' => 'open', 'window_end' => new Num('100'), 'ver' => new Num('0')]);
        $t = Undo::transition($rec, Obj::of(['kind' => 'abort', 'reason' => $reason]), new Num('50'));
        self::assertSame('applied', $t['outcome']);
        return $t['receipt']['note'];
    }

    public function testNoteClipsUtf16Units(): void
    {
        $x = static fn (int $n): string => str_repeat('x', $n);
        $emoji = "\u{1F600}"; // 4 UTF-8 bytes, 2 UTF-16 units
        $euro = "\u{20AC}";   // 3 bytes (lead E2), 1 unit
        $tha = "\u{0920}";    // 3 bytes (lead E0), 1 unit
        self::assertSame($euro . $emoji, self::abortNote($euro . $emoji));
        self::assertSame($x(125) . $emoji . 'a', self::abortNote($x(125) . $emoji . 'ab'));
        self::assertSame($x(127) . $euro, self::abortNote($x(127) . $euro));
        self::assertSame($x(127) . $tha, self::abortNote($x(127) . $tha));
        self::assertSame($x(127), self::abortNote($x(127) . $emoji));
        self::assertSame($x(126) . $emoji, self::abortNote($x(126) . $emoji));
        // a stray continuation byte reads as a 2-byte lead (one unit) and takes the next byte with it
        self::assertSame($x(127) . "\x80a", self::abortNote($x(127) . "\x80a"));
    }

    public function testBigClockKeepsIntegerLexeme(): void
    {
        $rec = Obj::of(['state' => 'open', 'window_end' => new Num('100'), 'ver' => new Num('0')]);
        $t = Undo::transition($rec, Obj::of(['kind' => 'effect']), new Num('9007199254740991'));
        self::assertSame('applied', $t['outcome']);
        self::assertSame('9007199254740991', $t['record']->get('effect')->get('at')->lexeme);
        self::assertSame('1', $t['record']->get('ver')->lexeme);
    }

    public function testHasReadsObjAndArray(): void
    {
        $has = new \ReflectionMethod(Undo::class, 'has');
        self::assertTrue($has->invoke(null, Obj::of(['k' => 1]), 'k'));
        self::assertTrue($has->invoke(null, ['k' => null], 'k'));
        self::assertFalse($has->invoke(null, [], 'k'));
        self::assertFalse($has->invoke(null, 'x', 'k'));
    }

    /** A non-Obj that answers every Obj method is still malformed, even when it wraps a well-formed token. */
    public function testTokenCheckRefusesANonObjImpostor(): void
    {
        $k = new KeyPair(str_repeat("\x04", 32));
        $rec = Obj::of(['id' => 'rec1', 'aud' => 'a', 'principal' => 'p', 'compensation_digest' => 'cd', 'window_end' => new Num('100')]);
        $tok = Undo::signToken($rec, $k);
        self::assertSame('signer', Undo::tokenCheck($tok, 'someone-else', $rec, new Num('50')));
        $fake = new class($tok) {
            public function __construct(private Obj $o)
            {
            }

            public function __call(string $n, array $a): mixed
            {
                return $this->o->$n(...$a);
            }
        };
        self::assertSame('malformed', Undo::tokenCheck($fake, 'someone-else', $rec, new Num('50')));
    }
}
