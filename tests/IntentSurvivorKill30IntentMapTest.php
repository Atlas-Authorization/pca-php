<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMap;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentMap.php: commitMap refusals and the Z0 disclosure entries (every audit path verifies against map_commit). */
final class IntentSurvivorKill30IntentMapTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function headerA(): Obj
    {
        return Obj::of(['verb' => 'a.x', 'dims' => [Obj::of(['kind' => 'cat', 'path' => 'action.params.s', 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'u']), Obj::of(['kind' => 'other', 'value' => IntentV2::MAP_OTHER])]])]]);
    }

    private static function headerB(): Obj
    {
        return Obj::of(['verb' => 'b.y', 'dims' => []]);
    }

    private static function cell(array $c, int $p, bool $in): Obj
    {
        return Obj::of(['cell' => $c, 'p_ppm' => $p, 'in_grant' => $in]);
    }

    private static function metrics(): Obj
    {
        return Obj::of(array_fill_keys(IntentV2::MAP_METRIC_FIELDS, 0));
    }

    private static function commit(?array $headers = null, ?Obj $cells = null, ?Obj $metrics = null, string $secret = ''): array
    {
        $headers ??= [self::headerB(), self::headerA()];
        $cells ??= Obj::of(['a.x' => [self::cell([0], 0, false), self::cell([1], 1000000, true)], 'b.y' => [self::cell([], 0, false)]]);
        return IntentMap::commitMap($headers, $cells, $metrics ?? self::metrics(), Pca::b64u(str_repeat("\1", 32)), $secret === '' ? str_repeat("\7", 32) : $secret);
    }

    private static function refused(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    private function checkEntry(array $r, Obj $e, int $index, string $kind): void
    {
        $this->assertSame(['index', 'salt', 'leaf', 'path'], $e->keys());
        $this->assertSame($index, $e->get('index'));
        $leaf = $r['leaves'][$index];
        $this->assertSame($kind, $leaf->get('kind'));
        $this->assertSame($leaf->get('salt'), $e->get('salt'));
        $this->assertSame($leaf->get('leaf'), $e->get('leaf'));
        $h = IntentV2::mapLeafHash($kind, (string)Pca::unb64u($e->get('salt'), 32), $e->get('leaf'));
        $path = array_map(static fn($p) => (string)Pca::unb64u($p, 32), $e->get('path'));
        $root = IntentV2::mapRootFromPath($index, $r['size'], $h, $path);
        $this->assertNotNull($root);
        $this->assertSame($r['map_commit'], IntentV2::mapCommitOf($r['size'], $root));
    }

    private function checkDisclosure(array $r, Obj $d, int $header, int $cell): void
    {
        $this->assertSame(['size', 'header', 'cell', 'metrics'], $d->keys());
        $this->assertSame($r['size'], $d->get('size'));
        $this->checkEntry($r, $d->get('header'), $header, 'header');
        $this->checkEntry($r, $d->get('cell'), $cell, 'cell');
        $this->checkEntry($r, $d->get('metrics'), $r['size'] - 2, 'metrics');
    }

    /** A 7-leaf map: every disclosed entry is the leaf at its index and its audit path recomputes map_commit. */
    public function testDisclosuresVerify(): void
    {
        $r = self::commit();
        $this->assertSame(7, $r['size']);
        $this->assertSame(['header', 'header', 'cell', 'cell', 'cell', 'metrics', 'learner'], array_map(static fn(Obj $l) => $l->get('kind'), $r['leaves']));
        $this->checkDisclosure($r, ($r['disclose'])('a.x', null, Obj::of(['s' => 'u'])), 0, 2);
        $this->checkDisclosure($r, ($r['disclose'])('a.x', null, Obj::of(['s' => 'zz'])), 0, 3);
        $this->checkDisclosure($r, ($r['disclose'])('b.y', null, new Obj()), 1, 4);
    }

    /** The smallest map (4 leaves) is accepted and discloses; 2 leaves are refused. */
    public function testLeafCountBounds(): void
    {
        $r = self::commit([self::headerB()], Obj::of(['b.y' => [self::cell([], 0, false)]]));
        $this->assertSame(4, $r['size']);
        $this->checkDisclosure($r, ($r['disclose'])('b.y', null, new Obj()), 0, 1);
        $this->assertSame('commitMap: the map has too few or too many leaves', self::refused(static fn() => self::commit([], new Obj())));
        $this->assertSame(16777216, IntentV2::MAX_MAP_LEAVES); // the upper bound is only reachable with 2^24 leaves
    }

    /** commitMap refusals keep their exact reasons. */
    public function testCommitRefusals(): void
    {
        $this->assertSame('commitMap: the secret is 32 bytes', self::refused(static fn() => self::commit(null, null, null, str_repeat("\7", 31))));
        $this->assertSame('commitMap: verb b.y needs 1 cell leaves', self::refused(static fn() => self::commit(null, Obj::of(['a.x' => [self::cell([0], 0, false), self::cell([1], 0, false)]]))));
        $this->assertSame('commitMap: ' . IntentV2::mapMetricsError(new Obj()), self::refused(static fn() => self::commit(null, null, new Obj())));
    }

    /** disclose refuses an unknown verb and an action outside the committed dimension, with the reason prefixed. */
    public function testDiscloseRefusals(): void
    {
        $r = self::commit();
        $this->assertSame('commitMap.disclose: verb zz is not in the map', self::refused(static fn() => ($r['disclose'])('zz', null, new Obj())));
        $this->assertSame("commitMap.disclose: the action's action.params.s lies outside the committed map's dimension", self::refused(static fn() => ($r['disclose'])('a.x', null, new Obj())));
    }
}
