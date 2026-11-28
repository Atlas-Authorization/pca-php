<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsEvolve;
use Atlas\Pca\ActionsPack;
use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsPack.php';

/** ActionsPack: shard sizing and family names, the empty-pack refusal, the caller's registry and shard URIs, and verifyUpgrade's refusals. */
final class RestSurvivorKill36bActionsPackTest extends TestCase
{
    private const GH = '{"v":1,"kind":"pca-action-def","verb":"github.read","title":"Read repository contents","description":"Reads files from a repository.","effects":["read"],"resource":{"type":"github.repo","id":{"prefix":"","class":"any_safe","len":[1,128]},"scope":"one"},"params":{"repo":{"type":"string","max_len":128,"role":"id.github.repo"},"path":{"type":"string","max_len":1024,"role":"path.fs","tags":["path"],"required":false}},"reversibility":"reversible","blast":{"radius":"one","ppm":50000},"review":{"state":"authored"},"since":"0.5.0"}';
    private const GD = '{"v":1,"kind":"pca-action-def","verb":"gmail.delete","title":"Permanently delete a message","description":"Permanently deletes a message.","effects":["delete"],"resource":{"type":"gmail.message","id":{"prefix":"","class":"any_safe","len":[1,128]},"scope":"one"},"params":{"message":{"type":"string","max_len":128,"role":"id.gmail.message"}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":800000},"examples":[{"params":{"message":"msg_1"},"expect":"escalate"}],"review":{"state":"authored"},"since":"0.5.0"}';
    private const SOURCE = '{"kind":"openapi","uri":"https://example.com/spec","spec_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","licence":"MIT","licence_notes":""}';

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/actions-pack-36b', true);
    }

    private static function keys(): array
    {
        return [Obj::of(['kid' => 'reg1', 'alg' => 'ed25519', 'pk' => (new KeyPair(self::seed()))->public])];
    }

    private static function def(string $json): Obj
    {
        return Json::parseStrict($json);
    }

    /** @param list<Obj> $defs */
    private static function build(string $ns, string $version, array $defs, ?array $reg = null, ?Obj $prev = null, mixed $shard = null): array
    {
        return ActionsPack::buildPack($ns, $version, 'stable', $defs, Json::parseStrict(self::SOURCE), 'reg1', self::seed(), $reg, $prev, $shard);
    }

    /** @param array<string,mixed> $set */
    private static function resign(Obj $pack, array $set): Obj
    {
        $u = $pack->without('sig');
        foreach ($set as $k => $v) {
            $u->set($k, $v);
        }
        $p = $u->without();
        $p->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => 'reg1',
            'value' => Pca::b64u((new KeyPair(self::seed()))->sign(ActionsRegistry::PACK_SIG_DOMAIN . Json::canonicalizeNative($u)))]));
        return $p;
    }

    private static function codeOf(\Closure $f): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        }
        return 'no throw';
    }

    /** A shard size that is not a number (a string, a boolean) is refused as bad_shard_size. */
    public function testNonNumericShardSizeRefused(): void
    {
        foreach (['x', true] as $max) {
            self::assertSame('bad_shard_size: the shard size must be a positive integer', self::codeOf(static fn() => ActionsPack::shardDefs([], $max)));
        }
    }

    /** Family names are strings even when numeric, and each family gets its own defs (family '0' is not family 'a'). */
    public function testNumericFamilyNames(): void
    {
        $d0 = Obj::of(['resource' => Obj::of(['type' => '0.x'])]);
        $da = Obj::of(['resource' => Obj::of(['type' => 'a.y'])]);
        self::assertSame([['name' => '0', 'defs' => [$d0]], ['name' => 'a', 'defs' => [$da]]], ActionsPack::shardDefs([$da, $d0]));
    }

    /** An empty def list is refused as empty_pack before the previous pack is even looked at. */
    public function testEmptyPackRefusedFirst(): void
    {
        $other = self::build('other', '1.0.0', [self::def(self::GH)]);
        self::assertSame('empty_pack: a pack has at least one def',
            self::codeOf(static fn() => self::build('acme', '2.0.0', [], null, Obj::of(['pack' => $other['pack']]))));
    }

    /** The caller's trait registry is the one the pack commits to (traits_digest). */
    public function testCallerRegistryIsUsed(): void
    {
        $reg = Actions::extendRegistry(Actions::coreRegistry(), [Obj::of(['id' => 'acme.x', 'implies' => [], 'floor' => Actions::profObj(Actions::profile([])), 'card_phrase' => 'acme.x'])]);
        $pack = self::build('acme', '1.0.0', [self::def(self::GH)], $reg)['pack'];
        self::assertSame(Actions::traitsDigest($reg), $pack->get('traits_digest'));
        self::assertNotSame(Actions::traitsDigest(Actions::coreRegistry()), $pack->get('traits_digest'));
    }

    /** Exactly MAX_PACK_DEFS defs still build an unsharded pack: only a pack above the limit is sharded without being asked. */
    public function testExactlyMaxDefsStayUnsharded(): void
    {
        $defs = [];
        for ($i = 0; $i < ActionsPack::MAX_PACK_DEFS; $i++) {
            $defs[] = self::def(str_replace('"github.read"', '"github.r' . $i . '"', self::GH));
        }
        $r = self::build('acme', '1.0.0', $defs);
        self::assertIsArray($r['pack']->get('defs'));
        self::assertCount(ActionsPack::MAX_PACK_DEFS, $r['pack']->get('defs'));
        self::assertSame([], $r['shards']->keys());
    }

    /** A shard `uri` callback names the shard locations. */
    public function testShardUriCallback(): void
    {
        $r = self::build('acme', '1.0.0', [self::def(self::GH)], null, null, Obj::of(['uri' => static fn(string $n): string => "https://cdn.example/$n.json"]));
        $refs = $r['pack']->get('defs')->get('shards');
        self::assertCount(1, $refs);
        self::assertSame('github', $refs[0]->get('name'));
        self::assertSame('https://cdn.example/github.json', $refs[0]->get('uri'));
    }

    /** A successor signed with the SAME version is refused, with exactly that reason. */
    public function testSameVersionRefused(): void
    {
        $p1 = self::build('acme', '1.0.0', [self::def(self::GH)]);
        $n = self::build('acme', '1.1.0', [self::def(self::GH)], null, Obj::of(['pack' => $p1['pack']]));
        self::assertSame(['ok' => true], ActionsPack::verifyUpgrade($p1['pack'], $n['pack'], self::keys()));
        $same = self::resign($n['pack'], ['version' => '1.0.0']);
        self::assertSame(['ok' => false, 'reason' => 'the version does not increase'], ActionsPack::verifyUpgrade($p1['pack'], $same, self::keys()));
    }

    /** A signed evolution that is not the computed change is refused (ok false with the evolution reason). */
    public function testWrongEvolutionRefused(): void
    {
        $gh = self::def(self::GH);
        $p1 = self::build('acme', '1.0.0', [$gh]);
        $n = self::build('acme', '1.1.0', [$gh], null, Obj::of(['pack' => $p1['pack']]));
        $evo = ActionsEvolve::signEvolution(ActionsEvolve::evolutionRecords('acme', [], [$gh], Actions::coreRegistry()), 'reg1', self::seed());
        $bad = self::resign($n['pack'], ['evolution' => $evo]);
        self::assertSame(['ok' => false, 'reason' => 'evolution has 1 records, the change needs 0'], ActionsPack::verifyUpgrade($p1['pack'], $bad, self::keys()));
    }

    /** verifyUpgrade recomputes the change with the caller's registry: one without the def's traits cannot vouch for a changed def. */
    public function testCallerRegistryInUpgrade(): void
    {
        $gd = self::def(self::GD);
        $gd2 = $gd->without();
        $gd2->set('title', 'Delete a message forever');
        $p1 = self::build('acme', '1.0.0', [$gd]);
        $n = self::build('acme', '1.1.0', [$gd2], null, Obj::of(['pack' => $p1['pack']]));
        self::assertSame(['ok' => true], ActionsPack::verifyUpgrade($p1['pack'], $n['pack'], self::keys()));
        $r = ActionsPack::verifyUpgrade($p1['pack'], $n['pack'], self::keys(), null, null, []);
        self::assertFalse($r['ok']);
        self::assertStringStartsWith('evolution error: ', $r['reason']);
    }
}
