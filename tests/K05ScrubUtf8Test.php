<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use PHPUnit\Framework\TestCase;

/** Invalid UTF-8 in a JWS header or payload decodes to U+FFFD (a lenient TextDecoder), never to a '?' a claim could be compared with. */
final class K05ScrubUtf8Test extends TestCase
{
    private static function scrub(string $s): string
    {
        return (new \ReflectionMethod(Common::class, 'scrubUtf8'))->invoke(null, $s);
    }

    public function testInvalidBytesBecomeTheReplacementCharacter(): void
    {
        $this->assertSame("a\u{FFFD}b", self::scrub("a\xFFb"));
        $this->assertSame("\u{FFFD}(", self::scrub("\xC3("));
        $this->assertSame('plain ?', self::scrub('plain ?'));
        $this->assertSame("\u{00E9}\u{FFFD}", self::scrub("\xC3\xA9\xFF"));
        $this->assertSame('?', mb_convert_encoding("\xFF", 'UTF-8', 'UTF-8'), 'the global substitute character is restored');
    }
}
