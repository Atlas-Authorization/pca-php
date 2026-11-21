<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsYaml;
use Atlas\Pca\Obj;
use Atlas\Pca\YamlSeq;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * defsToYaml (the default stringifier of the reference's YAML package) byte-for-byte: test-data/ref-core-yaml-java.json.gz (plain data) and
 * ref-core-yaml-anchors-java.json.gz (containers reachable twice become anchors and aliases; shared lists are YamlSeq, shared objects Obj).
 */
final class RefActionsYamlEmitTest extends TestCase
{
    public static function provide(): array
    {
        $out = [];
        foreach (['ref-core-yaml-java.json.gz', 'ref-core-yaml-anchors-java.json.gz'] as $f) {
            foreach (Base::datasets($f) as $name => $d) {
                $out[$f . ' ' . $name] = $d;
            }
        }
        return $out;
    }

    /** Replace {"$ref": id} by the one container built for id (in place for objects and shared lists). */
    private static function fill(mixed $node, array $built): mixed
    {
        if ($node instanceof Obj) {
            if ($node->keys() === ['$ref']) {
                return $built[$node->get('$ref')];
            }
            foreach ($node->keys() as $k) {
                $node->set($k, self::fill($node->get($k), $built));
            }
            return $node;
        }
        if ($node instanceof YamlSeq) {
            $node->items = array_map(fn($x) => self::fill($x, $built), $node->items);
            return $node;
        }
        return is_array($node) ? array_map(fn($x) => self::fill($x, $built), $node) : $node;
    }

    private static function anchors(string $ns, array $defs, Obj $rules, Obj $shared): string
    {
        $built = [];
        foreach ($shared->keys() as $k) {
            $built[$k] = is_array($shared->get($k)) ? new YamlSeq() : new Obj();
        }
        foreach ($shared->keys() as $k) {
            $v = $shared->get($k);
            if (is_array($v)) {
                $built[$k]->items = $v;
            } else {
                foreach ($v->keys() as $m) {
                    $built[$k]->set($m, $v->get($m));
                }
            }
        }
        foreach ($built as $b) {
            self::fill($b, $built);
        }
        $defs = self::fill($defs, $built);
        $rules = self::fill($rules, $built);
        return ActionsYaml::defsToYaml($ns, $defs, $rules);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'defsToYaml' => fn(array $a) => isset($a[3])
                ? self::anchors($a[0], $a[1], $a[2], $a[3])
                : ActionsYaml::defsToYaml($a[0], $a[1], $a[2] ?? null),
        ]);
    }
}
