<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Webbotauth;
use PHPUnit\Framework\TestCase;

/** Third-party signed JSON gets a duplicate-member check (json_decode and JSON.parse keep the last duplicate), not the canonical-number profile. */
final class DuplicateMemberTest extends TestCase
{
    private const KEY = '{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"}';

    public function testADuplicateMemberIsRefusedAtAnyDepth(): void
    {
        foreach (['{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '[{"a":1,"a":1}]', '{"a":1,"a":2}'] as $text) {
            try {
                Js::parseNoDuplicates($text);
                self::fail("accepted $text");
            } catch (\PHPUnit\Framework\AssertionFailedError $e) {
                throw $e;
            } catch (\Throwable) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testNumbersKeepTheirJsonParseValues(): void
    {
        $v = Js::parseNoDuplicates('{"a":1e3,"b":1.0}');
        self::assertSame(1000.0, Js::opt($v, 'a')->float());
        self::assertSame(1.0, Js::opt($v, 'b')->float());
    }

    public function testKeyDirectoryRefusesADuplicateKeysMember(): void
    {
        self::assertCount(1, Webbotauth::parseKeyDirectory('{"keys":[' . self::KEY . ']}')->get('keys') ?? []);
        $this->expectException(\Throwable::class);
        Webbotauth::parseKeyDirectory('{"keys":[' . self::KEY . '],"keys":[' . self::KEY . ']}');
    }
}
