<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsUndoEngine.php';

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsReview;
use Atlas\Pca\ActionsUndoEngine;
use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/ActionsUndoEngine.php: value-keyed reversibility, mayBeReversible, compensation shape order, and the confirmation gate of the plan. */
final class RestSurvivorKill36cActionsUndoEngineTest extends TestCase
{
    private const RES = '{"type":"acme.note","id":{"prefix":"","class":"any_safe","len":[1,128]},"scope":"one"}';

    private static function parse(string $json): Obj
    {
        return (new Parser($json, PHP_INT_MAX))->run();
    }

    private static function def(string $verb, string $effect, string $params, string $rev, string $extra = ''): Obj
    {
        return self::parse('{"v":1,"kind":"pca-action-def","verb":"' . $verb . '","title":"T","effects":["' . $effect . '"],"resource":' . self::RES
            . ',"params":' . $params . ',"reversibility":' . $rev . ',"blast":{"radius":"one","ppm":100000}' . $extra . ',"review":{"state":"authored"},"since":"0.6.0"}');
    }

    /** The create def: only an optional `text` param, reversible, compensated by acme.note.remove. */
    private static function create(): Obj
    {
        return self::def('acme.note.create', 'create', '{"text":{"type":"string","max_len":1000,"required":false}}', '"reversible"', ',"compensates":"acme.note.remove"');
    }

    private static function remove(): Obj
    {
        return self::def('acme.note.remove', 'delete', '{"note":{"type":"string","max_len":128,"role":"id.acme.note"}}', '"irreversible"');
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/ref-actions-undo/reviewer', true);
    }

    private static function pins(): Obj
    {
        return Obj::of(['keys' => [Obj::of(['kid' => 'rv1', 'pk' => (new KeyPair(self::seed()))->public, 'roles' => ['reviewer']])]]);
    }

    /** $d with a review signed by the pinned rv1 key over registry $reg. */
    private static function confirm(Obj $d, array $reg): Obj
    {
        $body = Obj::of(['def_digest' => Actions::defDigest($d), 'traits_digest' => Actions::traitsDigest($reg), 'facts_digest' => str_repeat('F', 43),
            'final_traits' => [], 'dismissed' => [], 'reviewer_kid' => 'rv1', 'ts' => new Num('1800000000')]);
        $out = $d->without('review');
        $out->set('review', Obj::of(['state' => 'confirmed', 'attestation' => ActionsReview::signReview($body, self::seed())]));
        return $out;
    }

    private static function valueDef(): Obj
    {
        return self::def('acme.note.tag', 'create', '{"n":{"type":"string","max_len":30}}',
            '{"by":"n","map":{"true":"reversible","false":"irreversible","0":"reversible","-3":"reversible","9007199254740991":"reversible"},"default":"irreversible"}');
    }

    private static function op(mixed $params): Obj
    {
        return Obj::of(['verb' => 'acme.note.create', 'params' => $params]);
    }

    /** No params at all take the default, not a crash. */
    public function testValueReversibilityWithoutParams(): void
    {
        $this->assertSame('irreversible', ActionsUndoEngine::reversibilityFor(self::valueDef(), null));
    }

    /** Booleans, integers (0, negatives, 2^53-1) key the map by their JS string; -0 is not 0 and takes the default. */
    public function testValueReversibilityKeys(): void
    {
        $d = self::valueDef();
        $at = static fn(mixed $v): string => ActionsUndoEngine::reversibilityFor($d, Obj::of(['n' => $v]));
        $this->assertSame('reversible', $at(true));
        $this->assertSame('irreversible', $at(false));
        $this->assertSame('reversible', $at(0));
        $this->assertSame('reversible', $at(new Num('-3')));
        $this->assertSame('reversible', $at(new Num('9007199254740991')));
        $this->assertSame('irreversible', $at(-0.0));
        $this->assertSame('irreversible', $at(7), 'control: unmapped value takes the default');
    }

    /** mayBeReversible: a map with only irreversible values and an irreversible default is never reversible; a reversible default is. */
    public function testMayBeReversibleMapAndDefault(): void
    {
        $d = self::create();
        $d->set('reversibility', Obj::of(['by' => 'n', 'map' => Obj::of(['a' => 'irreversible']), 'default' => 'irreversible']));
        $this->assertFalse(ActionsUndoEngine::mayBeReversible($d));
        $d->set('reversibility', Obj::of(['by' => 'n', 'map' => new Obj(), 'default' => 'reversible']));
        $this->assertTrue(ActionsUndoEngine::mayBeReversible($d));
        $d->set('reversibility', Obj::of(['by' => 'n', 'map' => Obj::of(['a' => 'reversible']), 'default' => 'irreversible']));
        $this->assertTrue(ActionsUndoEngine::mayBeReversible($d), 'control');
    }

    /** An optional unsupplied param is skipped; a later required one still refuses the shape. */
    public function testOptionalParamDoesNotEndTheScan(): void
    {
        $comp = self::def('acme.note.fix', 'delete', '{"a":{"type":"string","max_len":5,"required":false},"b":{"type":"string","max_len":5}}', '"irreversible"');
        $this->assertSame(['ok' => false, 'reason' => "the compensating action acme.note.fix needs 'b', which neither the original call nor its result supplies"],
            ActionsUndoEngine::compensationShape(self::create(), $comp));
    }

    /** Params are scanned in UTF-16 order: U+10000 (a surrogate pair) comes before U+E000, so it is the one reported. */
    public function testParamsScannedInUtf16Order(): void
    {
        $hi = "\u{10000}";
        $pua = "\u{E000}";
        $comp = self::def('acme.note.fix', 'delete', '{"' . $pua . '":{"type":"string","max_len":5},"' . $hi . '":{"type":"string","max_len":5}}', '"irreversible"');
        $this->assertSame(['ok' => false, 'reason' => "the compensating action acme.note.fix needs '$hi', which neither the original call nor its result supplies"],
            ActionsUndoEngine::compensationShape(self::create(), $comp));
    }

    /** Non-object op params are treated as no params: the plan equals the one for {}. */
    public function testNonObjectParamsActAsEmpty(): void
    {
        $reg = Actions::coreRegistry();
        $plan = ActionsUndoEngine::undoEngine([self::confirm(self::create(), $reg), self::confirm(self::remove(), $reg)], self::pins());
        $empty = $plan(self::op(new Obj()));
        $this->assertInstanceOf(Obj::class, $empty);
        $this->assertSame('acme.note.remove', $empty->get('compensation')->get('verb'));
        $str = $plan(self::op('str'));
        $this->assertInstanceOf(Obj::class, $str);
        $this->assertSame(AnalyzerJs::jsJson($empty), AnalyzerJs::jsJson($str));
    }

    /** An unconfirmed original is never undoable, even under a registry whose floors would all allow undo; confirmed, the same def is. */
    public function testUnconfirmedOriginalHasNoPlan(): void
    {
        $reg = Actions::coreRegistry();
        foreach (array_keys($reg) as $id) {
            $reg[$id]['floor']['rev'] = 'reversible';
        }
        $rc = self::confirm(self::remove(), $reg);
        $ok = ActionsUndoEngine::undoEngine([self::confirm(self::create(), $reg), $rc], self::pins(), $reg);
        $this->assertInstanceOf(Obj::class, $ok(self::op(new Obj())), 'control: confirmed under this registry');
        $plan = ActionsUndoEngine::undoEngine([self::create(), $rc], self::pins(), $reg);
        $this->assertNull($plan(self::op(new Obj())));
    }
}
