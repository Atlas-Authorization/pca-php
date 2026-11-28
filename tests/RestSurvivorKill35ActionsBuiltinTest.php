<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the built-in defs, their domain bindings and release context. */
final class RestSurvivorKill35ActionsBuiltinTest extends TestCase
{
    /** Runs $f with an extra domain 'zz' made of $bindings in the loaded built-in data, then restores the data. */
    private static function withDomain(array $bindings, \Closure $f): mixed
    {
        ActionsBuiltin::domainDefs();
        $p = new \ReflectionProperty(ActionsBuiltin::class, 'data');
        $orig = $p->getValue();
        $m = $orig;
        $dv = clone $orig['domainVerbs'];
        $dv->set('zz', $bindings);
        $m['domainVerbs'] = $dv;
        $p->setValue(null, $m);
        try {
            return $f();
        } finally {
            $p->setValue(null, $orig);
        }
    }

    private static function binding(string $id, string $verb, array $params = []): Obj
    {
        return Obj::of(['id' => $id, 'verb' => $verb, 'resourceType' => 'charge', 'params' => Obj::of($params)]);
    }

    private static function refusal(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    /** domainDefs is public; the release context and verifier are null before the first release signing. */
    public function testDomainDefsAndUnreleasedContext(): void
    {
        $this->assertNotSame([], ActionsBuiltin::domainDefs());
        $this->assertNull(ActionsBuiltin::builtinReviewerPins());
        $this->assertNull(ActionsBuiltin::builtinReleaseCtx());
        $this->assertNull(ActionsBuiltin::builtinReviewOpts());
    }

    /** signBuiltins checks each def's declared traits against the caller's registry. */
    public function testSignBuiltinsUsesTheRegistryAndDeclaredTraits(): void
    {
        $d = clone ActionsBuiltin::builtinDefs()[0];
        $d->set('traits', ['pca.bulk']);
        try {
            ActionsBuiltin::signBuiltins('k1', str_repeat("\x07", 32), 1000, [], [$d]);
            $this->fail('signed against an empty registry');
        } catch (\Throwable $e) {
            $this->assertStringContainsString("unknown trait 'pca.bulk'", $e->getMessage());
        }
        $d->set('traits', ['zz.not_a_trait']);
        try {
            ActionsBuiltin::signBuiltins('k1', str_repeat("\x07", 32), 1000, null, [$d]);
            $this->fail('signed an unknown declared trait');
        } catch (\Throwable $e) {
            $this->assertStringContainsString("unknown trait 'zz.not_a_trait'", $e->getMessage());
        }
    }

    /** domainVerbs derives with the caller's registry: an empty one knows none of the payment traits. */
    public function testDomainVerbsUsesTheRegistry(): void
    {
        try {
            ActionsBuiltin::domainVerbs('payments', []);
            $this->fail('derived against an empty registry');
        } catch (\Throwable $e) {
            $this->assertStringStartsWith("unknown trait '", $e->getMessage());
        }
    }

    /** A binding to an unknown def, to a non-alias id or to an unknown parameter is refused with its reason. */
    public function testBadBindingsAreRefused(): void
    {
        $this->assertSame("domain binding names unknown def 'nope.verb'",
            self::withDomain([self::binding('x', 'nope.verb')], static fn() => self::refusal(static fn() => ActionsBuiltin::domainVerbs('zz'))));
        $this->assertSame("domain binding 'not_alias' is not an alias of 'stripe.read_charge'",
            self::withDomain([self::binding('not_alias', 'stripe.read_charge')], static fn() => self::refusal(static fn() => ActionsBuiltin::domainVerbs('zz'))));
        $this->assertSame("domain binding 'read_charge' surfaces unknown parameter 'nope'",
            self::withDomain([self::binding('read_charge', 'stripe.read_charge', ['c' => 'nope'])], static fn() => self::refusal(static fn() => ActionsBuiltin::domainVerbs('zz'))));
    }

    /** domainRoles skips an unknown parameter and collects every NL name of one role, in order. */
    public function testDomainRoles(): void
    {
        $r = self::withDomain([self::binding('read_charge', 'stripe.read_charge', ['c' => 'nope'])], static fn() => ActionsBuiltin::domainRoles('zz'));
        $this->assertSame(['read_charge'], $r->keys());
        $this->assertSame([], $r->get('read_charge')->keys());
        $r = self::withDomain([self::binding('refund', 'stripe.refund', ['a' => 'amount', 'b' => 'amount', 'c' => 'charge'])], static fn() => ActionsBuiltin::domainRoles('zz'));
        $this->assertSame(['a', 'b'], $r->get('refund')->get('money.amount'));
        $this->assertSame(['c'], $r->get('refund')->get('id.stripe.charge'));
    }
}
