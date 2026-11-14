<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Actions.php';

use Atlas\Pca\Actions;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for Actions (second half): the JS-semantics helpers (jsHasOwn, truthy, jsNumber, jsSubset, jsLeq), normalize,
 * topTraits, the confirmation checks (verb + def level, dismissed reasons), rule 22's schemaVerbFloorError and registryOfSchema.
 */
final class K05KillActions3Test extends TestCase
{
    private const DEF = '{"v":1,"kind":"pca-action-def","verb":"acme.report.get","title":"Get a report","effects":["read"],'
        . '"resource":{"type":"acme.report","id":"*","scope":"tenant"},"params":{"q":{"type":"string","max_len":64},'
        . '"n":{"type":"integer","min":1,"max":50}},"reversibility":"reversible","idempotency":{"mode":"natural"}}';

    /** coreRegistry() caches in a static: coverage credits its build only to the first caller, so rebuild it here. */
    public function testCoreRegistryBuildsEveryTrait(): void
    {
        (new \ReflectionProperty(Actions::class, 'core'))->setValue(null, null);
        $reg = Actions::coreRegistry();
        $this->assertCount(22, $reg);
        foreach ($reg as $id => $t) {
            $this->assertStringStartsWith('pca.', $id);
            $this->assertSame($id, $t['id']);
        }
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Actions::class, $m))->invoke(null, ...$a);
    }

    private static function obj(string $json): Obj
    {
        $o = Json::parseLax($json);
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    /** @return array{0:class-string,1:string} */
    private static function thrown(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [$e::class, $e->getMessage()];
        }
        self::fail('expected a throw');
    }

    public function testJsHasOwn(): void
    {
        $h = fn(mixed $o, string $k): bool => self::priv('jsHasOwn', $o, $k);
        self::assertFalse($h(true, 'length'));           // a primitive has no own `length`
        self::assertFalse($h(null, '0'));
        self::assertTrue($h([], 'length'));
        self::assertTrue($h('', 'length'));
        self::assertTrue($h([1], '0'));
        self::assertFalse($h([1], '1'));                 // the index must be below the length
        self::assertFalse($h([1, 2], '01'));             // not a canonical index
        self::assertFalse($h([], 'x'));
        self::assertTrue($h("a\u{1F600}", '2'));         // UTF-16 length 3
        self::assertFalse($h("a\u{1F600}", '3'));
        self::assertTrue($h(Obj::of(['k' => 1]), 'k'));
        self::assertFalse($h(Obj::of(['k' => 1]), 'length'));
    }

    public function testTruthy(): void
    {
        $t = fn(mixed $x): bool => self::priv('truthy', $x);
        self::assertFalse($t(null));
        self::assertFalse($t(false));
        self::assertTrue($t(true));
        self::assertFalse($t(''));
        self::assertTrue($t('0'));
        self::assertFalse($t(0));
        self::assertFalse($t(new Num('0')));
        self::assertTrue($t(new Num('-1')));
        self::assertTrue($t(1));
        self::assertFalse($t(NAN));
        self::assertTrue($t([]));
        self::assertTrue($t(new Obj()));
    }

    public function testJsNumber(): void
    {
        $n = fn(mixed $x): float => self::priv('jsNumber', Obj::of(['a' => $x]), 'a');
        $notices = [];
        set_error_handler(static function (int $no, string $msg) use (&$notices): bool {
            $notices[] = $msg;
            return true;
        });
        try {
            self::assertSame(0.0, $n(null));
            self::assertSame(0.0, $n(''));
            self::assertSame(0.0, $n(" \t"));
            self::assertSame(5.0, $n(' 5 '));
            self::assertSame(5.0, $n('5'));
            self::assertSame(1000.0, $n('1e3'));
            self::assertSame(31.0, $n('0x1f'));
            self::assertNan($n('abc'));
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $notices);
    }

    /** Pinned to JS Number() (ECMA-262 StringToNumber): a floor read as a number where JS reads NaN would pass a forged floor. */
    public function testJsNumberMatchesJsOnEveryStringForm(): void
    {
        $n = fn(string $x): float => self::priv('jsNumber', Obj::of(['a' => $x]), 'a');
        foreach (['+-Infinity', '-+Infinity', '+0x1', '-0x1', '0x+1', '0x-1', '0x1_0', '0x 1', '0x', '0b2', '0o8', '1_000', "\u{661}", "\u{FF11}",
            'infinity', 'INFINITY', 'nan', 'NaN', '1e', '.', '+', '1f', '1d', 'L', '1L', '1 2', "1\0", "\u{85}1", "\u{180E}1", '0x1p3', "\u{A9}5", "5\u{2020}", "\u{A8}5", "5\u{200B}", "5\x85"] as $x) {
            self::assertNan($n($x), $x);
        }
        foreach ([['', 0.0], ["\t\n\r\x0B\x0C ", 0.0], [' 12 ', 12.0], ["\u{FEFF}12\u{A0}", 12.0], ["\u{1680}1\u{2000}", 1.0], ["\u{200A}1\u{2028}", 1.0], ["\u{2029}1\u{202F}", 1.0],
            ["\u{205F}1\u{3000}", 1.0], ['Infinity', INF], ['+Infinity', INF], ['-Infinity', -INF], ['0x10', 16.0], ['0X1f', 31.0], ['0o7', 7.0], ['0O17', 15.0],
            ['0b1', 1.0], ['0B101', 5.0], ['1.', 1.0], ['.5', 0.5], ['1e3', 1000.0], ['+1.5', 1.5], ['0x' . str_repeat('f', 300), INF]] as [$x, $want]) {
            self::assertSame($want, $n($x), $x);
        }
        self::assertSame('-0', (string)$n('-0')); // negative zero, as Number("-0")
    }

    public function testJsSubsetReads(): void
    {
        $iae = \InvalidArgumentException::class;
        self::assertSame([$iae, "Cannot read properties of undefined (reading 'includes')"],
            self::thrown(fn() => self::priv('jsSubset', ['a'], new Obj(), 'caveats')));
        self::assertSame([$iae, 'b.includes is not a function'],
            self::thrown(fn() => self::priv('jsSubset', ['a'], Obj::of(['caveats' => new Num('5')]), 'caveats')));
        self::assertTrue(self::priv('jsSubset', ['a'], Obj::of(['caveats' => 'xay']), 'caveats'));
    }

    private static function floors(mixed $rev): Obj
    {
        return Obj::of(['risk' => new Num('0'), 'rev' => $rev, 'blast_ppm' => new Num('0'), 'esc' => new Num('0')]);
    }

    public function testJsLeq(): void
    {
        self::assertSame([\InvalidArgumentException::class, "Cannot read properties of null (reading 'risk')"],
            self::thrown(fn() => self::priv('jsLeq', Actions::profile(), null)));
        self::assertTrue(self::priv('jsLeq', Actions::profile(), self::floors('reversible')));
        self::assertTrue(self::priv('jsLeq', Actions::profile(), self::floors(['reversible'])));   // String(['reversible'])
        self::assertFalse(self::priv('jsLeq', Actions::profile(), self::floors('bogus')));
    }

    public function testNormalizeSortsParamsAndFloorsThePpm(): void
    {
        $d = self::obj(self::DEF);
        $n = Actions::normalize($d);
        self::assertSame(['n', 'q'], $n->get('params')->keys());
        self::assertSame('700000', $n->get('blast')->get('ppm')->lexeme);   // tenant scope, no blast: the radius default
        $d->set('blast', self::obj('{"radius":"one","ppm":60000}'));
        self::assertSame('60000', Actions::normalize($d)->get('blast')->get('ppm')->lexeme);
        $d->set('blast', self::obj('{"radius":"one","ppm":10}'));
        self::assertSame('50000', Actions::normalize($d)->get('blast')->get('ppm')->lexeme);
    }

    public function testATagReadsAsItsPropertyKey(): void
    {
        self::assertSame(['pca.regulated_data'], Actions::impliedFromFacts([], [Obj::of(['tags' => [['pci']]])], null, 'reversible'));
    }

    public function testTopTraitsAreStrings(): void
    {
        self::assertSame(['10', '9', 'b.x'], Actions::topTraits(['b.x' => [], '10' => [], '9' => []]));
    }

    public function testRegistryOfSchemaIsPublicAndEmptyTraitDefsIsTheCore(): void
    {
        $core = Actions::coreRegistry();
        self::assertSame($core, Actions::extendRegistry($core, []));
        self::assertSame($core, Actions::registryOfSchema(Obj::of(['trait_defs' => []])));
        self::assertSame($core, Actions::registryOfSchema(new Obj()));
    }

    // ---- confirmations ------------------------------------------------------------------------------------------------------

    private static function kp(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function pins(): Obj
    {
        return Obj::of(['keys' => [Obj::of(['kid' => 'rev1', 'pk' => self::kp()[1], 'roles' => ['reviewer']])]]);
    }

    /** The test def carrying `$traits`, with a validly signed review whose final_traits are `$ft`. */
    private static function confirmedDef(array $traits, array $ft): Obj
    {
        $d = self::obj(self::DEF);
        $d->set('traits', $traits);
        $a = Obj::of(['def_digest' => Actions::defDigest($d), 'traits_digest' => Actions::traitsDigest(Actions::coreRegistry()), 'facts_digest' => 'f',
            'final_traits' => $ft, 'dismissed' => [], 'reviewer_kid' => 'rev1', 'ts' => new Num('1000')]);
        $a->set('sig', Pca::b64u(sodium_crypto_sign_detached(Actions::reviewMessage($a), self::kp()[0])));
        $d->set('review', Obj::of(['state' => 'confirmed', 'attestation' => $a]));
        return $d;
    }

    public function testIsConfirmedNeedsAListOfStringDeclaredTraits(): void
    {
        $core = Actions::coreRegistry();
        self::assertTrue(Actions::isConfirmed(self::confirmedDef(['x'], ['x']), $core, self::pins()), 'control');
        // the same set, but not a list
        self::assertFalse(Actions::isConfirmed(self::confirmedDef(['k' => 'x'], ['x']), $core, self::pins()));
        // the same set after a string-keyed dedupe, but one member is not a string
        $s = new class () {
            public function __toString(): string
            {
                return 'x';
            }
        };
        self::assertFalse(Actions::isConfirmed(self::confirmedDef(['x', $s], ['x']), $core, self::pins()));
    }

    public function testVerbConfirmationErrors(): void
    {
        $reg = Actions::coreRegistry();
        self::assertSame('no confirmation', Actions::verbConfirmationError(Obj::of(['def' => 'dd']), $reg, self::pins()));
        $v = Obj::of(['def' => 'dd', 'traits' => [], 'bad' => INF,
            'confirmation' => Obj::of(['sig' => 's', 'def_digest' => 'dd', 'facts_digest' => 'f'])]);
        self::assertSame('malformed confirmation: canonicalize: non-finite number', Actions::verbConfirmationError($v, $reg, self::pins()));
    }

    public function testADismissedTraitMustBeAString(): void
    {
        $reg = Actions::coreRegistry();
        $a = Obj::of(['traits_digest' => Actions::traitsDigest($reg), 'final_traits' => [], 'ts' => new Num('1'), 'reviewer_kid' => 'r',
            'dismissed' => [Obj::of(['trait' => new Num('5'), 'reason' => 'why'])]]);
        self::assertSame('a dismissed trait is also final, or has no reason', self::priv('attestationError', $a, $reg, Obj::of(['keys' => []])));
    }

    // ---- rule 22 ------------------------------------------------------------------------------------------------------------

    /** schemaVerbFloorError over an empty registry: only the declared reversibility and the carried floors.rev matter. */
    private static function floorErr(mixed $reversibility, mixed $rev, ?Obj $rb = null, ?Obj $params = null): ?string
    {
        $v = Obj::of(['effects' => [], 'traits' => [], 'params' => $params ?? new Obj(), 'reversibility' => $reversibility, 'floors' => self::floors($rev)]);
        if ($rb !== null) {
            $v->set('reversibility_by', $rb);
        }
        return Actions::schemaVerbFloorError($v, [], null);
    }

    public function testFloorsRevAgainstTheDeclaredReversibility(): void
    {
        $below = 'schema_floor_forged: floors.rev is below the declared reversibility';
        self::assertNull(self::floorErr('reversible', 'reversible'));
        self::assertSame($below, self::floorErr('rate_limited', 'reversible'));
        // a one-element array passes leq (String(x)) but ranks nowhere in indexOf
        self::assertSame($below, self::floorErr('reversible', ['reversible']));
        // an unknown declared class ranks nowhere either: nothing is below it
        self::assertNull(self::floorErr('bogus', ['reversible']));
    }

    public function testSchemaVerbFloorErrorReadsLikeJs(): void
    {
        self::assertSame("schema_floor_forged: Cannot read properties of null (reading 'effects')", Actions::schemaVerbFloorError(null, [], null));
        self::assertSame("schema_floor_forged: Cannot read properties of undefined (reading 'slice')",
            self::floorErr('reversible', 'reversible', Obj::of(['x' => new Num('1')])));
        // param 'q' is named '' (shorter than the prefix); an array param slices its tail: String([]) = '' names it
        $params = Obj::of(['q' => Obj::of(['type' => 'boolean'])]);
        $rb = Obj::of(['param' => ['x'], 'map' => Obj::of(['true' => 'reversible', 'false' => 'reversible'])]);
        self::assertNull(self::floorErr('reversible', 'reversible', $rb, $params));
        $rb->set('param', 'x');   // a string shorter than the prefix slices to '' too
        self::assertNull(self::floorErr('reversible', 'reversible', $rb, $params));
        $rb->set('param', 'action.params.zz');   // names no param: the default (absent = irreversible) joins
        self::assertSame('schema_traits_forged: missing implied trait pca.irreversible', self::floorErr('reversible', 'reversible', $rb, $params));
    }
}
