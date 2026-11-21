<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/AnalyzerCore.php';

/**
 * Policy plumbing for the intent layer (policy.ts): an outcome as the analyzer's concrete action, and the real evaluator as an
 * admission oracle. An outcome is an Obj `{verb, values: Obj}`, a verb space an Obj `{verb, reversibility, dims, ...}`.
 */
final class IntentPolicy
{
    public const ANY_RESOURCE = 'resource:any';

    /** {predicates, caveats}: a non-array member counts as empty. */
    public static function normalizePolicy(mixed $p): Obj
    {
        if (Js::truthy($p) && !($p instanceof Obj) && !is_array($p)) { // 'caveats' in p throws on a truthy primitive
            throw new \TypeError("Cannot use 'in' operator to search for 'caveats' in " . Js::str($p));
        }
        $preds = Js::opt($p, 'predicates');
        $cavs = Js::opt($p, 'caveats');
        return Obj::of([
            'predicates' => is_array($preds) && array_is_list($preds) ? $preds : [],
            'caveats' => is_array($cavs) && array_is_list($cavs) ? $cavs : [],
        ]);
    }

    /** @param list<string> $segs */
    private static function setPath(Obj $root, array $segs, mixed $value): void
    {
        $cur = $root;
        $last = count($segs) - 1;
        for ($i = 0; $i < $last; $i++) {
            $next = $cur->has($segs[$i]) ? $cur->get($segs[$i]) : null;
            if (!($next instanceof Obj)) {
                $next = new Obj();
                $cur->set($segs[$i], $next);
            }
            $cur = $next;
        }
        $cur->set($segs[$last], $value);
    }

    /** The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the verb space). */
    public static function outcomeToAction(mixed $vs, mixed $o): Obj
    {
        $params = new Obj();
        $env = new Obj();
        $subject = new Obj();
        $resource = self::ANY_RESOURCE;
        $values = Js::opt($o, 'values');
        foreach (Jsx::keys($values) as $path) {
            $value = Js::opt($values, $path);
            $segs = explode('.', $path);
            $n = count($segs);
            if ($path === 'action.resource') {
                $resource = Js::str($value);
            } elseif ($segs[0] === 'action' && $n > 2 && $segs[1] === 'params') {
                self::setPath($params, array_slice($segs, 2), $value);
            } elseif ($segs[0] === 'env' && $n > 1) {
                self::setPath($env, array_slice($segs, 1), $value);
            } elseif ($segs[0] === 'subject' && $n > 1) {
                self::setPath($subject, array_slice($segs, 1), $value);
            }
        }
        $a = Obj::of(['verb' => Js::opt($o, 'verb'), 'resource' => $resource, 'params' => $params]);
        if (Js::has($vs, 'reversibility')) {
            $a->set('reversibilityClass', Js::opt($vs, 'reversibility'));
        }
        if (count($env->keys()) > 0) {
            $a->set('env', $env);
        }
        if (count($subject->keys()) > 0) {
            $a->set('subject', $subject);
        }
        return $a;
    }

    /** A compiled admission oracle for one policy (compile once, query many times). */
    public static function admitter(mixed $policy): IntentAdmitter
    {
        return new IntentAdmitter(AnalyzerCore::toModel($policy));
    }

    /** The verb space of the outcome's verb in the omega, or null. */
    public static function vsOf(mixed $omega, mixed $o): mixed
    {
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === Js::opt($o, 'verb')) {
                return $v;
            }
        }
        return null;
    }
}

/** The compiled policy of {@see IntentPolicy::admitter}. */
final class IntentAdmitter
{
    public function __construct(private readonly Obj $model)
    {
    }

    public function admits(mixed $vs, mixed $o): bool
    {
        return AnalyzerCore::admitsAction($this->model, IntentPolicy::outcomeToAction($vs, $o));
    }
}
