<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;

/**
 * Helpers of the intent replay tests: doubles out of transcendental functions (log / exp / pow) are compared to 12 significant digits
 * (libm and V8 may differ in the last bits), on both sides; the mapper rewrites the expectation in place.
 */
final class RefIntentRound
{
    public static function r12(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::r12($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::r12(...), $v);
        }
        if (Js::isNum($v)) {
            $f = (float)Js::num($v);
            return is_finite($f) && $f != 0.0 ? (float)sprintf('%.12g', $f) : $f;
        }
        return $v;
    }

    /** The native result rounded; the case's expectation is rounded the same way. */
    public static function close(mixed $have, Obj $case): mixed
    {
        $w = $case->get('out');
        if (!($w instanceof Obj && $w->has('$throws'))) {
            $case->set('out', self::r12($w));
        }
        return self::r12($have);
    }
}
