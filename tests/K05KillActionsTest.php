<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Actions.php';

use Atlas\Pca\Actions;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Actions: profFromObj refusals, public surface, T(d), verb confirmation trait binding, jsNumber reads, bad_registry. */
final class K05KillActionsTest extends TestCase
{
    private const DD = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

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

    private static function obj(string $json): Obj
    {
        $o = Json::parseLax($json);
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    public function testProfFromObjRefusals(): void
    {
        $iae = \InvalidArgumentException::class;
        self::assertSame([$iae, 'profile must be an object'], self::thrown(fn() => Actions::profFromObj('x')));
        self::assertSame([$iae, 'profile.risk'], self::thrown(fn() => Actions::profFromObj(self::obj('{"rev":"reversible","caveats":[],"context":[],"prules":[]}'))));
        self::assertSame([$iae, 'profile.rev'], self::thrown(fn() => Actions::profFromObj(self::obj('{"risk":0,"blast_ppm":0,"esc":0,"caveats":[],"context":[],"prules":[]}'))));
        self::assertSame([$iae, 'profile.caveats'], self::thrown(fn() => Actions::profFromObj(self::obj('{"risk":0,"blast_ppm":0,"esc":0,"rev":"reversible","caveats":"x","context":[],"prules":[]}'))));
        self::assertSame([$iae, 'profile.caveats'], self::thrown(fn() => Actions::profFromObj(self::obj('{"risk":0,"blast_ppm":0,"esc":0,"rev":"reversible","caveats":[1],"context":[],"prules":[]}'))));
        $p = Actions::profFromObj(self::obj('{"risk":1,"blast_ppm":0,"esc":0,"rev":"reversible","caveats":["a"],"context":[],"prules":[]}'));
        self::assertSame(['a'], $p['caveats']);
    }

    public function testWorstReversibilityOfNullThrowsLikeJs(): void
    {
        self::assertSame([\InvalidArgumentException::class, "Cannot read properties of null (reading 'by')"],
            self::thrown(fn() => Actions::worstReversibility(null, new Obj())));
    }

    public function testPackLeafAndTraitsOfArePublic(): void
    {
        self::assertInstanceOf(Obj::class, Actions::packLeaf(self::DD));
        $d = self::obj('{"v":1,"kind":"pca-action-def","verb":"bank.transfer.send","title":"Send","effects":["pay"],'
            . '"resource":{"type":"bank.account","id":"*","scope":"one"},"params":{"amount":{"type":"integer"}},'
            . '"reversibility":"irreversible","idempotency":{"mode":"natural"},"review":{"state":"authored"}}');
        $reg = Actions::coreRegistry();
        // unconfirmed means maximally dangerous: the whole registry, not the hint view
        self::assertSame(Actions::topTraits($reg), Actions::traitsOf($d, $reg, null));
        self::assertNotSame(Actions::hintTraits($d), Actions::traitsOf($d, $reg, null));
    }

    private static function confirmedVerb(mixed $traits, array $finalTraits): Obj
    {
        $v = Obj::of(['def' => 'dd', 'traits' => $traits]);
        $v->set('confirmation', Obj::of(['sig' => 's', 'def_digest' => 'dd', 'facts_digest' => Actions::factsDigest($v), 'final_traits' => $finalTraits]));
        return $v;
    }

    public function testVerbConfirmationBindsTheCarriedTraits(): void
    {
        $pins = Obj::of(['keys' => [Obj::of(['kid' => 'r1', 'pk' => self::DD, 'roles' => ['reviewer']])]]);
        $reg = Actions::coreRegistry();
        self::assertSame('malformed confirmation', Actions::verbConfirmationError(self::confirmedVerb('x', ['a']), $reg, $pins));
        self::assertSame('the verb does not carry every trait the reviewer signed', Actions::verbConfirmationError(self::confirmedVerb([], ['a']), $reg, $pins));
        self::assertSame('the confirmation was made against a different trait registry', Actions::verbConfirmationError(self::confirmedVerb(['a'], ['a']), $reg, $pins));
    }

    /** schemaVerbFloorError over a one-trait registry (floor risk 1) with floors.risk = `$risk`. */
    private static function floorWithRisk(mixed $risk): ?string
    {
        $reg = ['t.a' => ['id' => 't.a', 'implies' => [], 'floor' => Actions::profile(['risk' => 1]), 'card_phrase' => 'p']];
        $v = Obj::of(['effects' => [], 'traits' => ['t.a'], 'params' => new Obj(), 'reversibility' => 'reversible',
            'floors' => Obj::of(['risk' => $risk, 'rev' => 'reversible', 'blast_ppm' => new Num('0'), 'esc' => new Num('0')])]);
        return Actions::schemaVerbFloorError($v, $reg, null);
    }

    public function testFloorsReadAsJavaScriptNumbers(): void
    {
        $below = 'schema_floor_forged: floors are below the floor of the carried traits';
        self::assertNull(self::floorWithRisk(new Num('1')));
        self::assertSame($below, self::floorWithRisk(new Num('0')));
        self::assertNull(self::floorWithRisk(true));
        self::assertSame($below, self::floorWithRisk(false));
        self::assertNull(self::floorWithRisk('Infinity'));
        self::assertSame($below, self::floorWithRisk('-Infinity'));
        self::assertSame($below, self::floorWithRisk('0x0'));
        // a hex string is read without any deprecated conversion (recorded, not thrown: a throw could be swallowed by a
        // fail-closed catch and still give null; hexdec('0x10') would raise "Invalid characters passed ... ignored")
        $notices = [];
        set_error_handler(static function (int $no, string $msg) use (&$notices): bool {
            $notices[] = $msg;
            return true;
        });
        try {
            self::assertNull(self::floorWithRisk('0x10'));
            self::assertSame($below, self::floorWithRisk('0x0'));
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $notices);
    }

    public function testAThrowingVerbIsABadRegistry(): void
    {
        $e = Actions::schemaFloorError(Obj::of(['verbs' => ['x']]));
        self::assertIsString($e);
        self::assertStringStartsWith('bad_registry: ', $e);
        self::assertStringContainsString('get()', $e);
    }

    public function testValidateDefFailsClosedWhenSomethingThrows(): void
    {
        Actions::$validateDefHook = static function (mixed $x): void {
            throw new \RuntimeException('boom');
        };
        try {
            self::assertSame('malformed def: boom', Actions::validateDef(null));
        } finally {
            Actions::$validateDefHook = null;
        }
        self::assertSame('not strict JSON: only JSON values are allowed', Actions::validateDef(1));
    }
}
