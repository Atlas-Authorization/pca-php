<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/CatalogRisk.php';
require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/PolicyLink.php';
require_once __DIR__ . '/../src/Approval.php';
require_once __DIR__ . '/../src/Assurance.php';

use Atlas\Pca\CatalogRisk;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Small public pieces of the reference core: hash suites, base64url helpers, constants, threshold assembly, goal commit, catalog risk. */
final class CoreSmallSurfaceTest extends TestCase
{
    public function testHashSuites(): void
    {
        self::assertSame('sha256', Pca::DEFAULT_HASH_SUITE);
        self::assertSame(['sha256' => 32, 'sha384' => 48], Pca::HASH_LEN);
        self::assertTrue(Pca::isHashSuite('sha384'));
        self::assertFalse(Pca::isHashSuite('sha512'));
        self::assertFalse(Pca::isHashSuite(null));
        self::assertSame(hash('sha256', 'a', true), Pca::hashWithSuite('a'));
        self::assertSame(48, strlen(Pca::hashWithSuite('a', 'sha384')));
        $this->expectException(\InvalidArgumentException::class);
        Pca::hashWithSuite('a', 'md5');
    }

    public function testBase64urlHelpers(): void
    {
        foreach ([0, 1, 2, 3, 4, 31, 32, 33, 64] as $n) {
            self::assertSame(strlen(Pca::b64u(str_repeat("\xff", $n))), Pca::b64uLen($n));
        }
        $s = Pca::b64u(str_repeat("\1", 32));
        self::assertTrue(Pca::isCanonicalB64u($s));
        self::assertTrue(Pca::isCanonicalB64u($s, 32));
        self::assertFalse(Pca::isCanonicalB64u($s, 31));
        self::assertFalse(Pca::isCanonicalB64u($s . '='));
        self::assertSame(str_repeat("\1", 32), Pca::decodeB64uStrict($s, 32));
        self::assertNull(Pca::decodeB64uStrict(1));
    }

    public function testConstantsAndThreshold(): void
    {
        self::assertSame(3600000 + 2 * 60000, Pca::REPLAY_MIN_RETENTION_MS);
        self::assertSame(1200000, Pca::PCACTN_DEFAULT_TTL_MS);
        self::assertSame(2, Pca::PCACTN_VERSION);
        self::assertContains('sig', Pca::PCACTN_REQUIRED_FIELDS);
        self::assertContains('fresh_at', Pca::PCACTN_OPTIONAL_FIELDS);
        self::assertTrue(Pca::artifactTooLarge(str_repeat('x', Pca::MAX_ARTIFACT_BYTES + 1)));
        self::assertFalse(Pca::artifactTooLarge(str_repeat('x', Pca::MAX_ARTIFACT_BYTES)));
        $t = Pca::assembleThreshold(['a', 'b']);
        self::assertSame(['a', 'b'], $t->get('shares'));
        self::assertSame([], Pca::assembleThreshold('x')->get('shares'));
    }

    public function testGoalCommitOpens(): void
    {
        $c = Sign::goalCommit('pay rent', 'salt');
        self::assertTrue(Sign::verifyGoalCommit($c, 'pay rent', 'salt'));
        self::assertFalse(Sign::verifyGoalCommit($c, 'pay rent', 'salt2'));
        self::assertFalse(Sign::verifyGoalCommit($c, 'pay rents', 'salt'));
    }

    public function testCatalogRisk(): void
    {
        self::assertSame([], CatalogRisk::catalogRisk('nope.x', null, new Obj()));
        $p = KeyPair::generate();
        $k = KeyPair::generate();
        $env = ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => ['kappa' => 1000] + Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($p, $k->public, $env, 'g')['grant'];
        $r = CatalogRisk::catalogRisk('stripe.charge', ['amount' => 250], $grant, 0.5);
        self::assertSame(0.0, $r['reversibility']);
        self::assertSame(0.25, $r['blastRadius']);
        self::assertSame(0.5, $r['taint']);
        self::assertSame(1.0, CatalogRisk::catalogRisk('stripe.charge', [], $grant)['blastRadius']);
        self::assertSame(1.0, CatalogRisk::catalogRisk('stripe.charge', ['amount' => -1], $grant)['blastRadius']);
        self::assertArrayNotHasKey('taint', CatalogRisk::catalogRisk('stripe.charge', ['amount' => 1], $grant));
        self::assertSame(0.4, CatalogRisk::CATALOG_REVERSIBILITY_SCORE['rate_limited']);
        self::assertSame(0.4, CatalogRisk::catalogRisk('stripe.create_customer', null, $grant)['reversibility']);
    }

    public function testCheapClaims(): void
    {
        $p = Obj::of(['aud' => 'rs', 'iat' => new Num('1000'), 'exp' => new Num('2000')]);
        self::assertNull(Pca::pcactnCheapClaims($p, 'rs', 1500));
        self::assertSame('audience', Pca::pcactnCheapClaims($p, 'other', 1500)['check']);
        self::assertSame('audience', Pca::pcactnCheapClaims('x', 'rs', 1500)['check']);
        self::assertSame('the PCActn has expired', Pca::pcactnCheapClaims($p, 'rs', 2001)['reason']);
        self::assertSame('iat is in the future (clock skew)', Pca::pcactnCheapClaims($p, 'rs', 1000 - 60001)['reason']);
        self::assertNull(Pca::pcactnCheapClaims($p, 'rs', 1000 - 60000));
        self::assertSame('exp must be greater than iat', Pca::pcactnCheapClaims(Obj::of(['aud' => 'rs', 'iat' => new Num('5'), 'exp' => new Num('5')]), 'rs', 5)['reason']);
        self::assertSame('lifetime exceeds 3600000 ms', Pca::pcactnCheapClaims(Obj::of(['aud' => 'rs', 'iat' => new Num('0'), 'exp' => new Num('3600001')]), 'rs', 5)['reason']);
        self::assertSame('iat and exp must be safe-integer epoch ms', Pca::pcactnCheapClaims(Obj::of(['aud' => 'rs', 'iat' => 'x', 'exp' => new Num('5')]), 'rs', 5)['reason']);
        self::assertSame('the verifier clock is not a safe integer epoch-ms', Pca::pcactnCheapClaims($p, 'rs', PHP_INT_MAX)['reason']);
    }

    public function testBudgetAllocAndConstants(): void
    {
        self::assertTrue(Pca::isBudgetAllocCaveat(Obj::of(['type' => 'budget_alloc', 'limit' => new Num('5')])));
        self::assertTrue(Pca::isBudgetAllocCaveat(Obj::of(['type' => 'budget_alloc', 'limit' => new Num('0')])));
        self::assertFalse(Pca::isBudgetAllocCaveat(Obj::of(['type' => 'budget_alloc', 'limit' => new Num('-1')])));
        self::assertFalse(Pca::isBudgetAllocCaveat(Obj::of(['type' => 'budget_alloc'])));
        self::assertFalse(Pca::isBudgetAllocCaveat(Obj::of(['type' => 'rate', 'limit' => new Num('5')])));
        self::assertFalse(Pca::isBudgetAllocCaveat('x'));
        self::assertSame([1, 2, 3], Pca::VALID_THRESHOLDS);
        self::assertSame('2.1', Pca::AGENT_LEAF_SHARE_BINDING_VERSION);
        self::assertSame(64, \Atlas\Pca\Approval::MAX_RENDER_FIELDS);
        self::assertSame('pca-policy-template', \Atlas\Pca\PolicyLink::TEMPLATE_KIND);
        self::assertSame('pca-template-tighten', \Atlas\Pca\PolicyLink::TIGHTEN_KIND);
        self::assertSame(Pca::hashCanonical(Obj::of(['a' => 'b'])), \Atlas\Pca\PolicyLink::linkDigest(Obj::of(['a' => 'b'])));
    }

    public function testAssuranceRefresh(): void
    {
        $report = ['replay' => ['outcome' => 'fail'], 'chain' => ['outcome' => 'pass'], 'zk' => ['outcome' => 'unsupported', 'reason' => 'x']];
        $r = \Atlas\Pca\Assurance::refresh($report, ['replay' => 'pass', 'chain' => 'fail', 'zk' => 'pass', 'audience' => 'pass', 'validity' => 'not-enforced']);
        self::assertSame(['outcome' => 'pass'], $r['replay']);
        self::assertSame(['outcome' => 'fail'], $r['chain']);
        self::assertSame(['outcome' => 'unsupported', 'reason' => 'x'], $r['zk'], 'unsupported stays');
        self::assertSame(['outcome' => 'pass'], $r['audience']);
        self::assertSame(['outcome' => 'not-enforced'], $r['validity']);
        self::assertSame(['outcome' => 'fail'], $report['replay'], 'the input is not mutated');
    }
}
