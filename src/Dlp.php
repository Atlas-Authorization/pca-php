<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';

/**
 * Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them
 * autonomously) and evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels
 * something upstream attached; this checks them against ceilings and never tracks data through a program.
 *
 * A policy is `{classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}`; a context is
 * `{verb, resource, taint, trustedRefs?}`; a result is `{outcome: allow | step_up | deny, class?, reason?}`. Values are the parsed-JSON
 * model (Obj, list arrays, string, Num / int / float, bool, null).
 */
final class Dlp
{
    /** A number that is not NaN (the reference's `typeof x === 'number' && !Number.isNaN(x)`). */
    private static function isNum(mixed $x): bool
    {
        return Js::isNum($x) && !is_nan((float)Js::num($x));
    }

    /** Exact, `*` for any, or a trailing-`*` prefix; a non-string pattern (or resource under a prefix pattern) is the reference's TypeError. */
    private static function matches(mixed $pattern, mixed $resource): bool
    {
        if ($pattern === '*') {
            return true;
        }
        if (!is_string($pattern)) {
            throw new \TypeError('pattern.endsWith is not a function');
        }
        if (str_ends_with($pattern, '*')) {
            if (!is_string($resource)) {
                throw new \TypeError('resource.startsWith is not a function');
            }
            return str_starts_with($resource, substr($pattern, 0, -1));
        }
        return $pattern === $resource;
    }

    /** Exact beats any prefix; a longer prefix beats a shorter one; `*` is the least specific. */
    private static function specificity(string $pattern): int
    {
        if ($pattern === '*') {
            return 0;
        }
        if (str_ends_with($pattern, '*')) {
            return Js::len($pattern) - 1;
        }
        return Js::len($pattern) + 1000;
    }

    /**
     * Lower is stricter. A malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent
     * ceiling (unconstrained) is the most lenient and sorts last.
     */
    private static function strictness(mixed $c): float
    {
        $m = Jsx::get($c, 'maxTaintForAuto');
        if (Jsx::isUndef($m)) {
            return INF;
        }
        return self::isNum($m) ? (float)Js::num($m) : -INF;
    }

    /** SameValueZero (Array.prototype.includes) of two JSON values; objects and arrays never share identity here. */
    private static function sameValueZero(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            if (!(Js::isNum($a) && Js::isNum($b))) {
                return false;
            }
            $x = (float)Js::num($a);
            $y = (float)Js::num($b);
            return $x == $y || (is_nan($x) && is_nan($y));
        }
        if (is_string($a)) {
            return is_string($b) && $a === $b;
        }
        if ($a === null || is_bool($a)) {
            return $a === $b;
        }
        return false;
    }

    /** `!c.verbs || c.verbs.includes(verb)`: a list or a string (substring) is searched; any other truthy value is the reference's TypeError. */
    private static function verbMatches(mixed $c, mixed $verb): bool
    {
        $vs = Jsx::get($c, 'verbs');
        if (!Jsx::truthy($vs)) {
            return true;
        }
        if (is_array($vs) && array_is_list($vs)) {
            foreach ($vs as $v) {
                if (self::sameValueZero($v, $verb)) {
                    return true;
                }
            }
            return false;
        }
        if (is_string($vs)) {
            return str_contains($vs, Jsx::str($verb));
        }
        throw new \TypeError('c.verbs.includes is not a function');
    }

    /**
     * The most specific matching class (the longest non-wildcard prefix wins, an exact match beats a prefix); of equally specific
     * classes the STRICTEST wins (lowest ceiling), never whichever was listed first. Null when none applies.
     *
     * @param list<mixed> $classes
     */
    private static function classFor(array $classes, mixed $ctx): mixed
    {
        $best = null;
        $bestSpec = 0;
        $bestStrict = 0.0;
        foreach ($classes as $c) {
            $res = Jsx::rd($c, 'resource');
            if (!self::matches($res, Jsx::rd($ctx, 'resource'))) {
                continue;
            }
            if (!self::verbMatches($c, Jsx::rd($ctx, 'verb'))) {
                continue;
            }
            $spec = self::specificity((string)$res);
            $strict = self::strictness($c);
            if ($best === null || $spec > $bestSpec || ($spec === $bestSpec && $strict < $bestStrict)) {
                $best = $c;
                $bestSpec = $spec;
                $bestStrict = $strict;
            }
        }
        return $best;
    }

    /** A ceiling that is present but not a number (or NaN) would make every `>` false and allow everything. */
    private static function malformed(mixed $policy, mixed $cls): bool
    {
        if ($cls !== null) {
            $m = Jsx::get($cls, 'maxTaintForAuto');
            $h = Jsx::get($cls, 'hardDenyAbove');
            return (!Jsx::isUndef($m) && !self::isNum($m)) || (!Jsx::isUndef($h) && !self::isNum($h));
        }
        $d = Jsx::get($policy, 'defaultMaxTaintForAuto');
        return !Jsx::isUndef($d) && !self::isNum($d);
    }

    private static function result(string $outcome, mixed $cls, ?string $reason): Obj
    {
        $r = Obj::of(['outcome' => $outcome]);
        if ($cls instanceof Obj && $cls->has('name')) {
            $r->set('class', $cls->get('name'));
        }
        if ($reason !== null) {
            $r->set('reason', $reason);
        }
        return $r;
    }

    /**
     * Evaluate an action's data flow against the DLP policy. Fails CLOSED: a malformed policy or ceiling is a deny, and a taint that is
     * not a finite number is treated as maximally tainted so it can never beat a ceiling.
     */
    public static function evaluateDlp(mixed $policy, mixed $ctx): Obj
    {
        Jsx::init();
        $classes = $policy instanceof Obj ? $policy->get('classes') : null;
        if (!is_array($classes) || !array_is_list($classes)) {
            return self::result('deny', null, 'malformed DLP policy');
        }
        $cls = self::classFor($classes, $ctx);
        if (self::malformed($policy, $cls)) {
            return self::result('deny', $cls, 'malformed DLP policy: ceilings must be numbers');
        }
        $max = $cls !== null ? Jsx::get($cls, 'maxTaintForAuto') : Jsx::get($policy, 'defaultMaxTaintForAuto');
        $t = Jsx::rd($ctx, 'taint');
        $bad = !(Js::isNum($t) && is_finite((float)Js::num($t)));
        $taint = $bad ? INF : (float)Js::num($t);
        if (Jsx::isUndef($max)) {
            return self::result('allow', $cls, null); // no ceiling at all: nothing to compare against
        }
        $name = $cls !== null ? Jsx::get($cls, 'name') : null;
        $label = $name === null || Jsx::isUndef($name) ? '<default>' : Js::str($name);
        $hard = $cls !== null ? Jsx::get($cls, 'hardDenyAbove') : Jsx::$U;
        if (!Jsx::isUndef($hard) && ($bad || $taint > (float)Js::num($hard))) {
            return self::result('deny', $cls, sprintf("taint %s exceeds hard ceiling %s for '%s'", Js::str($taint), Js::str($hard), $label));
        }
        if ($bad || $taint > (float)Js::num($max)) {
            return self::result('step_up', $cls, sprintf("taint %s > %s for '%s' — needs human review", Js::str($taint), Js::str($max), $label));
        }
        return self::result('allow', $cls, null);
    }

    /**
     * Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. `$opts` is `{piiResource?, secretsResource?}`;
     * null is the reference's TypeError.
     */
    public static function defaultDlpPolicy(mixed $opts = new Obj()): Obj
    {
        $classes = [];
        $pii = Js::get($opts, 'piiResource');
        if (Js::truthy($pii)) {
            $classes[] = Obj::of(['name' => 'pii', 'resource' => $pii, 'maxTaintForAuto' => 0, 'hardDenyAbove' => 2]);
        }
        $sec = Js::get($opts, 'secretsResource');
        if (Js::truthy($sec)) {
            $classes[] = Obj::of(['name' => 'secrets', 'resource' => $sec, 'maxTaintForAuto' => 0, 'hardDenyAbove' => 0]);
        }
        return Obj::of(['classes' => $classes]);
    }
}
