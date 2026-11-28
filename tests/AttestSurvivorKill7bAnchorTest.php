<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestAllowlistAnchor.php';

use Atlas\Pca\AttestAllowlistAnchor;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\TransparencyLedger;
use PHPUnit\Framework\TestCase;

/** The allowlist anchor's feed cap: a feed of exactly MAX_FEED (100000) entries is still checked against the signed root. */
final class AttestSurvivorKill7bAnchorTest extends TestCase
{
    private const NOW = 1800000000000;

    /**
     * A guardian-signed head of size 100000 with a feed of 100000 entries passes the size check and is refused only because the entries
     * do not reproduce the signed root. Every entry is the same object, so the feed costs one allocation; the root check still commits
     * each one (about a second).
     */
    public function testAFeedOfExactlyTheCapReachesTheRootCheck(): void
    {
        $secret = hash('sha256', 'atlas-pca-conformance/kill7-anchor-guardian', true);
        $head = TransparencyLedger::signTreeHead(new KeyPair($secret), Obj::of(['instance_id' => 'inst-1', 'principal' => 'principal-1',
            'size' => 100000, 'root' => 'not-the-root', 'prev_root' => '', 'timestamp' => self::NOW]));
        $entry = Obj::of(['issuer' => 'iss', 'version' => 1, 'digest' => str_repeat('A', 43)]);
        $evidence = Obj::of(['head' => $head, 'entries' => array_fill(0, 100000, $entry), 'proof' => Obj::of([])]);
        $opts = Obj::of(['trust' => Obj::of(['logKey' => (new KeyPair($secret))->public, 'instanceId' => 'inst-1', 'principal' => 'principal-1']),
            'nowMs' => self::NOW]);
        self::assertSame(['ok' => false, 'code' => 'feed-mismatch', 'reason' => 'entries do not reproduce the signed root'],
            AttestAllowlistAnchor::verify($entry, $evidence, $opts));
    }
}
