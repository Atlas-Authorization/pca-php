<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CoreSmall;
use Atlas\Pca\IntentExtensions;
use Atlas\Pca\IntentRevocation;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\TransparencyLedger;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PolicyLink;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/CoreSmall.php';
require_once __DIR__ . '/../src/IntentExtensions.php';
require_once __DIR__ . '/../src/IntentRevocation.php';
require_once __DIR__ . '/../src/LedgerLog.php';

/**
 * The small core helpers against the TS reference (ref-core-kotlin-gaps: the salted ledger commit, the v2 goal parser, the profile
 * revocation scope and exposure window, the budget-allocation caveat), plus direct checks of the helpers that corpus does not carry.
 */
final class RefCoreGapsDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-kotlin-gaps.json.gz';
    private const TOTAL = 112;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'entryCommit' => static fn(array $a) => TransparencyLedger::entryCommit($a[0], $a[1]),
            'verifyOpening' => static fn(array $a) => TransparencyLedger::verifyOpening($a[0], $a[1]),
            'ledgerRootOf' => static fn(array $a) => TransparencyLedger::rootOf($a[0]),
            'parseIntentGoalV2' => static fn(array $a) => CoreSmall::parseIntentGoalV2($a[0]),
            'profileRevocationScope' => static fn(array $a) => IntentRevocation::profileRevocationScope($a[0]),
            'revocationExposureEnd' => static fn(array $a) => $a[2] === null
                ? IntentRevocation::revocationExposureEnd(Js::num($a[0]), Js::num($a[1]))
                : IntentRevocation::revocationExposureEnd(Js::num($a[0]), Js::num($a[1]), Js::num($a[2])),
            'budgetAllocCaveat' => static fn(array $a) => CoreSmall::budgetAllocCaveat(Js::num($a[0])),
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }

    public function testRevocationIdsAndScopes(): void
    {
        $this->assertSame('pca-intent:', IntentRevocation::PREFIX);
        $this->assertSame('pca-intent:session:s', IntentRevocation::sessionRevocationId('s'));
        $this->assertSame('pca-intent:map:m', IntentRevocation::mapRevocationId('m'));
        $this->assertSame('pca-intent:delta:g', IntentRevocation::deltaRevocationId('g'));
        $this->assertSame('pca-intent:profile:p@3', IntentRevocation::profileRevocationId('p', 3));
        $this->assertSame('pca-intent:profile:p@1.5', IntentRevocation::profileRevocationId('p', 1.5));
        $this->assertSame('pca-intent-session:s', IntentRevocation::sessionRevocationScope('s'));
        $this->assertSame(['payment' => 60, 'default' => 300], IntentRevocation::DEFAULT_MAX_AGE_S);
        $this->assertSame(60_000, IntentRevocation::DEFAULT_SKEW_MS);
    }

    public function testGoalV2RoundTrip(): void
    {
        $s = Pca::b64u(str_repeat("\x01", 32));
        $m = Pca::b64u(str_repeat("\x02", 32));
        $this->assertSame("pca-intent:v2:$s:$m", CoreSmall::intentGoalV2($s, $m));
        $this->assertSame("pca-intent:v2c:$s:$m", CoreSmall::intentGoalV2($s, $m, 'commit'));
        $this->assertSame(['session' => $s, 'mapDigest' => $m], CoreSmall::parseIntentGoalV2(CoreSmall::intentGoalV2($s, $m)));
        $this->assertNull(CoreSmall::parseIntentGoalV2(CoreSmall::intentGoalV2($s, $m, 'commit')));
    }

    public function testAllocationsMonotone(): void
    {
        $cv = static fn(int|float $l): Obj => CoreSmall::budgetAllocCaveat($l);
        $other = Obj::of(['type' => 'expires', 'at' => 'x']);
        $this->assertSame(['ok' => true], CoreSmall::allocationsMonotone([]));
        $this->assertSame(['ok' => true], CoreSmall::allocationsMonotone([$cv(10), $other, $cv(10), $cv(2.5), $cv(0)]));
        $this->assertSame(['ok' => false, 'reason' => 'malformed caveats'], CoreSmall::allocationsMonotone('x'));
        $this->assertSame(
            ['ok' => false, 'reason' => "budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)"],
            CoreSmall::allocationsMonotone([$cv(5), $other, $cv(6)]),
        );
        foreach ([Obj::of(['type' => 'budget_alloc']), Obj::of(['type' => 'budget_alloc', 'limit' => '5']), $cv(-1)] as $bad) {
            $this->assertSame(['ok' => false, 'reason' => 'budget_alloc caveat 1: limit must be a finite number >= 0'], CoreSmall::allocationsMonotone([$cv(5), $bad]));
        }
    }

    public function testMessagesAndConstants(): void
    {
        $this->assertSame(['enforced' => false], CoreSmall::notEnforced());
        $this->assertSame(1, PolicyLink::TEMPLATE_VERSION);
        $this->assertSame("atlas-pca/revoke/v1\0" . '{"grant_ref":"g","revoked_cap_id":"c"}', CoreSmall::revokeMessage('g', 'c'));

        $a = new KeyPair(str_repeat("\x07", 32));
        $b = new KeyPair(str_repeat("\x08", 32));
        $set = [['role' => 'agent', 'publicKey' => $a->public], ['role' => 'guardian', 'publicKey' => $b->public]];
        $ssh = Pca::signerSetHashRaw(\Atlas\Pca\Sign::n($set));
        $this->assertNotNull($ssh);
        $want = "atlas-pca/share/guardian\0" . hash('sha256', 'msg', true) . $ssh . "\x02";
        $this->assertSame($want, CoreSmall::shareMessage('guardian', 'msg', $set, 2));
        $this->assertSame($want, CoreSmall::shareMessage('guardian', 'msg', $set, 2, 'ed25519'));
        $this->assertSame($want . "\0atlas-pca/share-suite/v1\0ml-dsa-65", CoreSmall::shareMessage('guardian', 'msg', $set, 2, 'ml-dsa-65'));
        $this->assertSame($want, CoreSmall::shareMessage('guardian', 'msg', $set, 2, 'no-such-suite'));
        foreach ([0, 4, 1.5] as $t) {
            try {
                CoreSmall::shareMessage('guardian', 'msg', $set, $t);
                $this->fail("t = $t accepted");
            } catch (\RangeException) {
                $this->addToAssertionCount(1);
            }
        }

        $wire = IntentExtensions::wire();
        $this->assertSame(['intent', 'intentSession', 'freshAt'], array_keys($wire));
        $full = IntentExtensions::full();
        $this->assertSame(['wire', 'intentBinding', 'intentV2', 'freshAt'], array_keys($full));
        foreach ([...array_values($wire), $full['intentBinding'], $full['intentV2'], $full['freshAt']] as $f) {
            $this->assertIsCallable($f);
        }
    }
}
