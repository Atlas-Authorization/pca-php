<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsCompat;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the legacy catalog converter. */
final class RestSurvivorKill35ActionsCompatTest extends TestCase
{
    private static function spec(array $o = []): array
    {
        return $o + ['connector' => 'shop', 'action' => 'charge', 'verb' => 'shop.charge', 'description' => 'Charges a card.',
            'reversibility' => 'irreversible', 'blastRadius' => 0.5];
    }

    private static function c(mixed $v): string
    {
        return Json::canonicalizeLenient(Sign::n($v));
    }

    /** The canonical class names map to themselves. */
    public function testCanonicalClassesAreKept(): void
    {
        $this->assertSame('reversible', ActionsCompat::normalizeReversibility('reversible'));
        $this->assertSame('rate_limited', ActionsCompat::normalizeReversibility('rate_limited'));
    }

    /** A JSON number (Num) blast radius is read as its value, not as the worst case. */
    public function testNumBlastRadius(): void
    {
        $this->assertSame(['radius' => 'one', 'ppm' => 50000], ActionsCompat::blastOfFloat(new Num('0.05')));
        $this->assertSame(['radius' => 'tenant', 'ppm' => 900000], ActionsCompat::blastExactOfFloat(new Num('0.9')));
    }

    /** A non-string action name or description is used as its string form. */
    public function testNonStringActionAndDescription(): void
    {
        $d = ActionsCompat::fromCatalogSpec(self::spec(['action' => 5, 'description' => 7]));
        $this->assertSame(['update'], $d->get('effects'));
        $this->assertSame('7', $d->get('description'));
        $this->assertSame('7', $d->get('title'));
    }

    /** A send-like action name is a send effect. */
    public function testSendEffect(): void
    {
        $this->assertSame(['send'], ActionsCompat::fromCatalogSpec(self::spec(['action' => 'send_email']))->get('effects'));
    }

    /** An amount field becomes a bounded money.amount parameter (defaults USD, exponent 2, max 1e11) plus a 128-char idempotency key. */
    public function testAmountParameterDefaults(): void
    {
        $d = ActionsCompat::fromCatalogSpec(self::spec(['amountField' => 'amount']));
        $this->assertSame(['pay'], $d->get('effects'));
        $this->assertSame(['amount', 'idempotency_key'], $d->get('params')->keys());
        $this->assertSame(self::c(['type' => 'integer', 'role' => 'money.amount', 'min' => 0, 'max' => 100000000000,
            'unit' => ['kind' => 'money', 'ccy' => 'USD', 'exp' => 2]]), Json::canonicalizeLenient($d->get('params')->get('amount')));
        $this->assertSame(self::c(['type' => 'string', 'max_len' => 128]), Json::canonicalizeLenient($d->get('params')->get('idempotency_key')));
    }

    /** The options override the amount's maximum, currency and exponent. */
    public function testAmountParameterOptions(): void
    {
        $d = ActionsCompat::fromCatalogSpec(self::spec(['amountField' => 'amount']), ['maxAmount' => 5, 'ccy' => 'EUR', 'exp' => 3]);
        $this->assertSame(self::c(['type' => 'integer', 'role' => 'money.amount', 'min' => 0, 'max' => 5,
            'unit' => ['kind' => 'money', 'ccy' => 'EUR', 'exp' => 3]]), Json::canonicalizeLenient($d->get('params')->get('amount')));
    }

    /** A description over 120 UTF-16 units is cut to its first 117 plus '...'; exactly 120 is kept. */
    public function testTitleTruncation(): void
    {
        $long = str_repeat('abcdefghij', 13);
        $this->assertSame(substr($long, 0, 117) . '...', ActionsCompat::fromCatalogSpec(self::spec(['description' => $long]))->get('title'));
        $exact = str_repeat('abcdefghij', 12);
        $this->assertSame($exact, ActionsCompat::fromCatalogSpec(self::spec(['description' => $exact]))->get('title'));
    }

    /** A named resource is one safe id of 1..128 characters; no resource is the whole set. */
    public function testResourceShape(): void
    {
        $one = ActionsCompat::fromCatalogSpec(self::spec(['resource' => 'card']))->get('resource');
        $this->assertSame(self::c(['type' => 'shop', 'id' => ['prefix' => '', 'class' => 'any_safe', 'len' => [1, 128]], 'scope' => 'one']),
            Json::canonicalizeLenient($one));
        $set = ActionsCompat::fromCatalogSpec(self::spec())->get('resource');
        $this->assertSame(self::c(['type' => 'shop', 'id' => '*', 'scope' => 'set']), Json::canonicalizeLenient($set));
    }
}
