<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;

/**
 * Runner for primitives.depth[] (packages/pca/scripts/gen-conformance-depth.mjs): JSON nesting depth on every untrusted
 * entry point at limit-1 / limit / limit+1 and at ~100000. Shared by conformance.php and DepthCorpusTest.
 *
 * `expand` cases carry a marker that is replaced, ITERATIVELY, by `levels` nested arrays around `leaf`. The Zend engine
 * frees nested arrays recursively in C (no userland frame), so a 100000-deep PHP array would crash the runner when it is
 * released; after the verdict the marker is restored and the deep value is dismantled one level at a time
 * ({@see dismantle()}). The verifier itself only ever recurses through the strict profile, which stops at depth 33.
 */
final class DepthCases
{
    /** @return array{0:bool,1:string} [verdict, detail] for one primitives.depth entry. Exceptions propagate to the caller. */
    public static function run(Obj $case): array
    {
        $in = $case->get('input');
        $api = $case->get('api');
        $exp = $case->has('expand') ? $case->get('expand') : null;
        $slot = null;
        $deep = null;
        try {
            if ($exp instanceof Obj && ($api === 'chain' || $api === 'threshold_share')) {
                $slot = self::findMarker($in, $exp->get('marker'));
                if ($slot === null) {
                    throw new \LogicException('marker not found in ' . $case->get('name'));
                }
                $deep = self::nest($exp->get('levels')->int(), $exp->get('leaf'));
                self::put($slot, $deep);
            }
            switch ($api) {
                case 'chain':
                    [$why, $ok] = Pca::verifyChain($in->get('chain'), $in->get('expected_root_issuer'), true);
                    return [$ok, $why];
                case 'threshold_share':
                    return [Pca::verifyThresholdShare($in), ''];
                case 'pcactn_json':
                    $v = Pca::verifyJson(self::text($in, $exp), $in->get('grant'), $in->get('now')->int(), $in->get('aud'));
                    return [$v['allow'] === true, $v['reason']];
                case 'json_parse':
                    try {
                        Json::parseStrict(self::text($in, $exp));
                        return [true, ''];
                    } catch (JsonError $e) {
                        return [false, $e->getMessage()];
                    }
                default:
                    throw new \LogicException('unknown api ' . var_export($api, true));
            }
        } finally {
            if ($slot !== null) {
                self::put($slot, $exp->get('marker'));
            }
            self::dismantle($deep);
        }
    }

    private static function text(Obj $in, mixed $exp): string
    {
        $t = $in->get('text');
        if (!($exp instanceof Obj)) {
            return $t;
        }
        $n = $exp->get('levels')->int();
        $leaf = $exp->get('leaf');
        $leafText = $leaf instanceof Num ? $leaf->lexeme : json_encode($leaf, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $pos = strpos($t, $exp->get('marker'));
        if ($pos === false) {
            throw new \LogicException('marker not found in text');
        }
        return substr($t, 0, $pos) . str_repeat('[', $n) . $leafText . str_repeat(']', $n) . substr($t, $pos + strlen($exp->get('marker')));
    }

    /** `levels` arrays around `leaf`, built iteratively. */
    private static function nest(int $levels, mixed $leaf): mixed
    {
        $v = $leaf;
        for ($i = 0; $i < $levels; $i++) {
            $v = [$v];
        }
        return $v;
    }

    /** Release a nested array one level at a time (each step frees a parent whose only child is still referenced). */
    public static function dismantle(mixed &$v): void
    {
        while (is_array($v) && count($v) === 1 && array_key_exists(0, $v)) {
            $v = $v[0];
        }
        $v = null;
    }

    /** @return array{0:Obj|array,1:string|int,2:?array}|null a slot (container, key) holding the marker string */
    private static function findMarker(mixed $v, string $marker): ?array
    {
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                $x = $v->get($k);
                if ($x === $marker) {
                    return [$v, $k];
                }
                $r = self::findMarker($x, $marker);
                if ($r !== null) {
                    return $r;
                }
            }
        } elseif (is_array($v)) {
            foreach ($v as $i => $x) {
                if ($x === $marker) {
                    throw new \LogicException('marker directly inside a JSON array is not supported by this runner');
                }
                $r = self::findMarker($x, $marker);
                if ($r !== null) {
                    return $r;
                }
            }
        }
        return null;
    }

    private static function put(array $slot, mixed $value): void
    {
        [$obj, $k] = $slot;
        $obj->set($k, $value);
    }
}
