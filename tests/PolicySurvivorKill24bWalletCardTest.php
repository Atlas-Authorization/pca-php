<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Catalog;
use Atlas\Pca\HarmModel;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletCard;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24b) for src/WalletCard.php: the uncatalogued verb cap, the dimension loop of renderCard and planClarification's choice of cell. */
final class PolicySurvivorKill24bWalletCardTest extends TestCase
{
    private static function cat(mixed $path, array $exact): Obj
    {
        $values = array_map(static fn(string $v): Obj => Obj::of(['kind' => 'exact', 'value' => $v]), $exact);
        $values[] = Obj::of(['kind' => 'other', 'value' => "\u{22A5}"]);
        return Obj::of(['kind' => 'cat', 'path' => $path, 'values' => $values]);
    }

    private static function verb(string $verb, array $dims): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => 'reversible', 'weight' => 1, 'dims' => $dims]);
    }

    private static function omega(array $verbs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    /** @return array{ok:bool,card?:Obj,reason?:string} */
    private static function render(Obj $omega, string $verb, Obj $coords): array
    {
        return WalletCard::renderCard(Obj::of(['omega' => $omega, 'verb' => $verb, 'coords' => $coords, 'catalog' => new Catalog([]),
            'site' => Obj::of(['origin' => 'https://s.example', 'name' => 'S'])]));
    }

    /** An uncatalogued verb is named in the sentence up to 64 units; a 65-unit one is cut to 63 and an ellipsis. */
    public function testUncataloguedVerbCap(): void
    {
        $v64 = 'zz.' . str_repeat('v', 61);
        $v65 = 'zz.' . str_repeat('v', 62);
        $res = self::cat('action.resource', ['r:a']);
        $om = self::omega([self::verb($v64, [$res]), self::verb($v65, [$res])]);
        $coords = Obj::of(['action.resource' => ['r:a']]);
        $this->assertSame("Allow the action \"$v64\" on S, that can be undone, with:", self::render($om, $v64, $coords)['card']->get('sentence'));
        $this->assertSame('Allow the action "' . substr($v65, 0, 63) . "\u{2026}\" on S, that can be undone, with:",
            self::render($om, $v65, $coords)['card']->get('sentence'));
    }

    /**
     * Provenance dimensions give banners, never facts: a numeric one is skipped and the loop goes on, a categorical one names the
     * dimension by its path after env.prov. (here an env.world path, labelled as a signed fact), and the dimensions after both still give facts.
     */
    public function testProvenanceDimensionsComeFirst(): void
    {
        $num = Obj::of(['kind' => 'num', 'path' => 'env.prov.score', 'lo' => 0, 'hi' => 10, 'cuts' => [], 'dist' => 'uniform']);
        $om = self::omega([self::verb('zz.op', [$num, self::cat('env.prov.env.world.src', ['agent', 'trusted']), self::cat('action.resource', ['r:a', 'r:b'])])]);
        $r = self::render($om, 'zz.op', Obj::of(['env.prov.score' => [0, 0], 'env.prov.env.world.src' => ['agent'], 'action.resource' => ['r:a', 'r:b']]));
        $this->assertTrue($r['ok']);
        $card = $r['card'];
        $this->assertSame(['This src (from a signed fact) was chosen by your agent, not taken from your request or from the site.'], $card->get('banners'));
        $facts = $card->get('facts');
        $this->assertCount(1, $facts);
        $this->assertSame(['action.resource', 'resource'], [$facts[0]->get('key'), $facts[0]->get('label')]);
        $partial = $card->get('partial');
        $this->assertCount(1, $partial);
        $this->assertSame(['action.resource', 'cat', ['r:a', 'r:b']], [$partial[0]->get('path'), $partial[0]->get('kind'), $partial[0]->get('options')]);
    }

    /** A dimension path that is not a string throws TypeError (as the reference's d.path.startsWith does) instead of being read as text. */
    public function testNonStringPathThrows(): void
    {
        $coords = new Obj();
        $coords->set('1.5', ['a']);
        $this->expectException(\TypeError::class);
        self::render(self::omega([self::verb('zz.op', [self::cat(1.5, ['a'])])]), 'zz.op', $coords);
    }

    private static function act(string $verb, string $r): Obj
    {
        return Obj::of(['verb' => $verb, 'values' => Obj::of(['action.resource' => $r])]);
    }

    /**
     * planClarification over one categorical dimension (cells a=0, c=1, other=2) with etaPos 2 and etaNeg 0.5, where the information gain
     * of every p below 2/3 is exactly -p. `$p` maps a resource to the view's acceptance.
     * @param list<Obj> $cands
     * @param array<string,float> $p
     */
    private static function plan(array $cands, array $p, ?HarmModel $harm = null): array
    {
        $dim = self::cat('action.resource', ['a', 'c']);
        $om = self::omega([self::verb('q.run', [$dim]), self::verb('q.alt', [$dim])]);
        $byIdx = array_values($p);
        $inp = ['omega' => $om, 'candidates' => $cands, 'etaPos' => 2, 'etaNeg' => 0.5, 'view' => [
            'p' => static fn(mixed $verb, array $idx): float => $byIdx[$idx[0]],
            'vetoed' => static fn(mixed $verb, array $idx): bool => false,
            'outsideCeiling' => static fn(mixed $verb, array $idx): bool => false,
        ]];
        if ($harm !== null) {
            $inp['harm'] = $harm;
        }
        return WalletCard::planClarification($inp);
    }

    /** A harm model that makes the cell of resource `$heavy` five times as harmful as the others. */
    private static function heavy(string $heavy): HarmModel
    {
        return new HarmModel(static fn(mixed $vs): float => 1.0, static fn(mixed $d, mixed $x): float => $x === $heavy ? 5.0 : 1.0);
    }

    /** The information gain of the fixture is exactly -p (the boundary tests below rely on it). */
    public function testFixtureGainIsMinusP(): void
    {
        foreach ([1e-12, 2e-12, 0.25] as $p) {
            $this->assertSame(-$p, WalletCard::informationGain($p, 2, 0.5));
        }
    }

    /**
     * A gain exactly 1e-12 above the best is still inside the tie band: the given harm model's heavier cell wins it (with the default
     * model, or without the band's boundary, the first cell would stay).
     */
    public function testTieBandBoundaryUsesTheGivenHarm(): void
    {
        $r = self::plan([self::act('q.run', 'a'), self::act('q.run', 'c')], ['a' => 2e-12, 'c' => 1e-12], self::heavy('c'));
        $this->assertSame(1, $r['ask']['index']);
        $this->assertSame([1], $r['ask']['idx']);
    }

    /** A gain exactly 1e-12 above the best is not a strict improvement: the lighter cell does not replace the heavier one. */
    public function testExactlyTheMarginIsNoImprovement(): void
    {
        $r = self::plan([self::act('q.run', 'a'), self::act('q.run', 'c')], ['a' => 2e-12, 'c' => 1e-12], self::heavy('a'));
        $this->assertSame(0, $r['ask']['index']);
    }

    /** Equal gain and weight: the lower flat index wins, whichever candidate comes first. */
    public function testEqualWeightPrefersTheLowerFlatIndex(): void
    {
        $p = ['a' => 0.25, 'c' => 0.25];
        $this->assertSame(1, self::plan([self::act('q.run', 'c'), self::act('q.run', 'a')], $p)['ask']['index']);
        $this->assertSame(0, self::plan([self::act('q.run', 'a'), self::act('q.run', 'c')], $p)['ask']['index']);
    }

    /** Equal gain, weight and flat index (the same cell of two verbs): the first candidate stays. */
    public function testFullTieKeepsTheFirst(): void
    {
        $r = self::plan([self::act('q.run', 'a'), self::act('q.alt', 'a')], ['a' => 0.25, 'c' => 0.25]);
        $this->assertSame([0, 'q.run'], [$r['ask']['index'], $r['ask']['verb']]);
    }

    /** A repeated cell is judged again but scored once, and the candidates after it are still judged. */
    public function testRepeatedCellDoesNotStopThePlan(): void
    {
        $r = self::plan([self::act('q.run', 'a'), self::act('q.run', 'a'), self::act('q.run', 'c')], ['a' => 0.25, 'c' => 0.25]);
        $this->assertSame([['index' => 0, 'verdict' => 'uncertain'], ['index' => 1, 'verdict' => 'uncertain'], ['index' => 2, 'verdict' => 'uncertain']], $r['verdicts']);
        $this->assertSame(0, $r['ask']['index']);
    }
}
