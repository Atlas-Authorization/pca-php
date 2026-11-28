<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/CatalogRisk.php';
require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Catalog;
use Atlas\Pca\CatalogRisk;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** CatalogRisk::catalogRisk: the caller's catalog, Obj params, a grant without an envelope, a zero amount and the confidence. */
final class RestSurvivorKill36bCatalogRiskTest extends TestCase
{
    private static function grant(): Obj
    {
        $env = ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => ['kappa' => 1000] + Sign::defaultRiskPolicy()];
        return Sign::mintGrant(new KeyPair(str_repeat("\x05", 32)), (new KeyPair(str_repeat("\x06", 32)))->public, $env, 'g', 'c2FsdA')['grant'];
    }

    /** A caller-supplied catalog is used, an unknown reversibility class prices as 0 (not reversible) and a numeric blastRadius is read as a float. */
    public function testCallerCatalogIsUsed(): void
    {
        $cat = new Catalog([['connector' => 'acme', 'action' => 'x', 'verb' => 'acme.x', 'reversibility' => 'odd', 'blastRadius' => '0.5']]);
        $r = CatalogRisk::catalogRisk('acme.x', null, new Obj(), null, $cat);
        self::assertSame(['reversibility' => 0.0, 'blastRadius' => 0.5, 'confidence' => 1.0], $r);
        self::assertSame([], CatalogRisk::catalogRisk('acme.x', null, new Obj()));
    }

    /** The amount is read from Obj params; a missing amount in Obj params is the worst case. */
    public function testObjParamsAmount(): void
    {
        $g = self::grant();
        self::assertSame(0.25, CatalogRisk::catalogRisk('stripe.charge', Obj::of(['amount' => 250]), $g)['blastRadius']);
        self::assertSame(1.0, CatalogRisk::catalogRisk('stripe.charge', Obj::of(['other' => 250]), $g)['blastRadius']);
    }

    /** A zero amount is no blast; the confidence is 1. */
    public function testZeroAmountAndConfidence(): void
    {
        $r = CatalogRisk::catalogRisk('stripe.charge', ['amount' => 0], self::grant());
        self::assertSame(0.0, $r['blastRadius']);
        self::assertSame(1.0, $r['confidence']);
    }

    /** A grant with no readable envelope (no kappa) prices a money-moving verb at the worst case instead of failing. */
    public function testGrantWithoutEnvelope(): void
    {
        self::assertSame(1.0, CatalogRisk::catalogRisk('stripe.charge', ['amount' => 1], new Obj())['blastRadius']);
        self::assertSame(1.0, CatalogRisk::catalogRisk('stripe.charge', ['amount' => 1], 'not a grant')['blastRadius']);
    }
}
