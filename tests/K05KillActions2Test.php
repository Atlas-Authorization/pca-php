<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Actions.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for Actions (lines up to worstReversibility/units): safe-integer reads, NFC of invalid UTF-8, length
 * boundaries of verb / alias / resource.type / resource.id.len, the trait registry (reserved namespace default, cycles, depth),
 * extendRegistry on a keyed custom list, traitsDigest order independence, worstReversibility coverage and units().
 */
final class K05KillActions2Test extends TestCase
{
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

    private static function o(string $json): mixed
    {
        return Json::parseLax($json);
    }

    private static function tr(string $id, array $implies): Obj
    {
        return Obj::of(['id' => $id, 'implies' => $implies, 'floor' => Actions::profObj(Actions::profile()), 'card_phrase' => 'p']);
    }

    /** A 128-byte dotted name: 32 + 33 + 33 + 30 (+$extra more bytes in the last segment). */
    private static function name128(int $extra = 0): string
    {
        return str_repeat('a', 32) . '.' . str_repeat('b', 32) . '.' . str_repeat('c', 32) . '.' . str_repeat('d', 29 + $extra);
    }

    private static function def(array $d): mixed
    {
        return self::o(json_encode(['v' => 1, 'kind' => 'pca-action-def'] + $d, JSON_THROW_ON_ERROR));
    }

    public function testSafeIntegerReads(): void
    {
        $bad = 'numbers must be safe integers (no floats, no -0)';
        self::assertNull(Actions::jsonProfileError(new Num('0')));
        self::assertNull(Actions::jsonProfileError(new Num('-3')));
        self::assertSame($bad, Actions::jsonProfileError(new Num('-0')));
        self::assertSame($bad, Actions::jsonProfileError(new Num('1.5')));
        self::assertSame($bad, Actions::jsonProfileError(new Num('-2.5')));
        // PHP int and float tiers: an int reads as its value, a fractional float denies
        $call = Obj::of(['context' => []]);
        self::assertSame('allow', Actions::floorDecision(Obj::of(['max_esc' => 3, 'preauth_esc' => 3, 'caveats' => []]), $call, Actions::profile()));
        self::assertSame('deny', Actions::floorDecision(Obj::of(['max_esc' => 2.5, 'preauth_esc' => 0, 'caveats' => []]), $call, Actions::profile()));
    }

    public function testInvalidUtf8IsNotNfc(): void
    {
        // nfc() relies on intl refusing invalid UTF-8 (it converts to UTF-16 without substitution)
        self::assertFalse(\Normalizer::isNormalized("\xff", \Normalizer::FORM_C));
        self::assertSame('string is not NFC', Actions::jsonProfileError("a\xffb"));
        self::assertNull(Actions::jsonProfileError("caf\u{e9}"));
    }

    public function testIdLenBounds(): void
    {
        $err = 'resource.id.len must be [min, max] in 1..128';
        // a fractional max is not an integer even though it is in range
        self::assertSame($err, Actions::idPatternError(self::o('{"prefix":"","class":"digits","len":[1,5.5]}')));
        // min above 128 is out of range before min > max
        self::assertSame($err, Actions::idPatternError(self::o('{"prefix":"","class":"digits","len":[129,5]}')));
        self::assertSame('resource.id.len: min > max', Actions::idPatternError(self::o('{"prefix":"","class":"digits","len":[6,5]}')));
        self::assertNull(Actions::idPatternError(self::o('{"prefix":"","class":"digits","len":[1,128]}')));
    }

    public function testVerbAliasAndResourceTypeAre128BytesAtMost(): void
    {
        $title = 'title must be a non-empty string up to 120 bytes';
        self::assertSame(128, strlen(self::name128()));
        self::assertSame($title, Actions::validateDef(self::def(['verb' => self::name128()])));
        self::assertSame('verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)', Actions::validateDef(self::def(['verb' => self::name128(1)])));
        self::assertSame($title, Actions::validateDef(self::def(['verb' => 'a.b', 'aliases' => [self::name128()]])));
        self::assertSame('aliases must be distinct verb-shaped names other than the verb',
            Actions::validateDef(self::def(['verb' => 'a.b', 'aliases' => [self::name128(1)]])));
        $res = fn(string $t) => self::def(['verb' => 'a.b', 'title' => 'T', 'effects' => ['read'], 'resource' => ['type' => $t, 'id' => 5, 'scope' => 'one']]);
        self::assertSame("resource.id must be '*', {exact} or {prefix, class, len}", Actions::validateDef($res(self::name128())));
        self::assertSame('resource.type is malformed', Actions::validateDef($res(self::name128(1))));
    }

    public function testPcaNamespaceIsReservedByDefault(): void
    {
        $msg = "trait 'pca.x': the pca. namespace is reserved for core traits";
        self::assertSame($msg, Actions::registryError([self::tr('pca.x', [])]));
        self::assertNull(Actions::registryError([self::tr('pca.x', [])], true));
        self::assertSame([ActionKitError::class, $msg], self::thrown(fn() => Actions::buildRegistry([self::tr('pca.x', [])])));
        self::assertSame(['pca.x'], array_keys(Actions::buildRegistry([self::tr('pca.x', [])], true)));
    }

    public function testImpliesCycleAndDepth(): void
    {
        self::assertSame("trait 'x.a': implies cycle", Actions::registryError([self::tr('x.a', ['x.b']), self::tr('x.b', ['x.a'])]));
        $chain = fn(int $n) => array_map(fn($i) => self::tr("x.t$i", $i < $n ? ['x.t' . ($i + 1)] : []), range(1, $n));
        self::assertNull(Actions::registryError($chain(8)));
        self::assertSame("trait 'x.t1': implies depth 9 exceeds 8", Actions::registryError($chain(9)));
    }

    public function testExtendRegistryRefusals(): void
    {
        $core = Actions::coreRegistry();
        // a non-object custom trait is a bad_registry refusal, never a PHP Error from reading a member of it
        self::assertSame([ActionKitError::class, "custom trait 'undefined' may not redefine a core trait"],
            self::thrown(fn() => Actions::extendRegistry($core, ['x'])));
        self::assertSame([ActionKitError::class, "custom trait 'pca.y' may not redefine a core trait"],
            self::thrown(fn() => Actions::extendRegistry($core, [self::tr('pca.y', [])])));
    }

    public function testExtendRegistryIgnoresTheKeysOfTheCustomList(): void
    {
        // a custom list keyed by a core id must not overwrite that core trait (the core list is merged as a list)
        $reg = Actions::extendRegistry(Actions::coreRegistry(), ['pca.external_communication' => self::tr('acme.thing', [])]);
        self::assertCount(23, $reg);
        self::assertArrayHasKey('pca.external_communication', $reg);
        self::assertArrayHasKey('acme.thing', $reg);
    }

    public function testTraitsDigestIgnoresImpliesOrder(): void
    {
        $reg = fn(array $im) => Actions::buildRegistry([self::tr('x.a', $im), self::tr('x.b', []), self::tr('x.c', [])], false);
        self::assertSame(Actions::traitsDigest($reg(['x.b', 'x.c'])), Actions::traitsDigest($reg(['x.c', 'x.b'])));
    }

    public function testWorstReversibility(): void
    {
        $none = new Obj();
        // an array map: every value counts
        self::assertSame('irreversible', Actions::worstReversibility(self::o('{"by":"x","map":["reversible","irreversible"],"default":"reversible"}'), $none));
        // a one-element array value reads as its class name
        self::assertSame('irreversible', Actions::worstReversibility(self::o('{"by":"x","map":{"a":["irreversible"]},"default":"reversible"}'), $none));
        $bool = self::o('{"x":{"type":"boolean"}}');
        // a boolean domain is covered only by both spellings; uncovered adds the default (absent = irreversible)
        self::assertSame('reversible', Actions::worstReversibility(self::o('{"by":"x","map":{"true":"reversible","false":"reversible"}}'), $bool));
        self::assertSame('irreversible', Actions::worstReversibility(self::o('{"by":"x","map":{"false":"reversible"}}'), $bool));
        self::assertSame('irreversible', Actions::worstReversibility(self::o('{"by":"x","map":{"true":"reversible"}}'), $bool));
        // a non-string enum value is looked up by its JavaScript text
        self::assertSame('reversible', Actions::worstReversibility(self::o('{"by":"x","map":{"1":"reversible"}}'), self::o('{"x":{"type":"string","values":[1]}}')));
    }

    public function testUnitsAreUtf16CodeUnits(): void
    {
        $units = new \ReflectionMethod(Actions::class, 'units');
        self::assertSame([], $units->invoke(null, ''));
        self::assertSame(['a', 'b'], $units->invoke(null, 'ab'));
        self::assertSame(['a', "\u{e9}", "\u{4e2d}"], $units->invoke(null, "a\u{e9}\u{4e2d}"));
    }
}
