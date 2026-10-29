<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Refusals;
use PHPUnit\Framework\TestCase;

final class RefusalsTest extends TestCase
{
    private const REF = 'https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md';

    public function testLeadingCheckNameMapsToGuidance(): void
    {
        $h = Refusals::explainRefusal('audience: signed for another server');
        $this->assertSame('audience', $h['check']);
        $this->assertSame('The proof was signed for a different server.', $h['meaning']);
        $this->assertSame('Make the agent sign with the same audience string the server is configured with.', $h['fix']);
        $this->assertSame(self::REF . '#audience', $h['docs']);
    }

    public function testEmbeddedCheckNameAndPageOverrides(): void
    {
        $this->assertSame('replay', Refusals::explainRefusal('denied by replay: counter reused')['check']);
        $this->assertSame('https://github.com/Atlas-Authorization/pca/blob/main/docs/concepts/threshold-and-step-up.md',
            Refusals::explainRefusal('threshold: needs co-sign')['docs']);
        $this->assertSame('authorize_config', Refusals::explainRefusal('authorize_config: missing audience')['check']);
    }

    public function testUnknownAndNonStringNeverThrow(): void
    {
        foreach (['', 'something odd', null, 42, ['x']] as $r) {
            $h = Refusals::explainRefusal($r);
            $this->assertSame('unknown', $h['check']);
            $this->assertSame(self::REF, $h['docs']);
        }
    }
}
