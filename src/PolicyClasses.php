<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Decision.php';

/**
 * Policy classes (packages/pca/src/policy-classes.ts): a decision is the meet of every class consulted; denied_by / escalated_by
 * name who said no. Fail-strict and total. Replays packages/pca/conformance/policy-classes-vectors.json.
 */
final class PolicyClasses
{
    public const CLASSES = ['constitution', 'regulatory', 'org', 'blueprint', 'user'];
    private const KEYS = ['class', 'revision', 'digest', 'decision'];

    /** Null = a well-formed list: closed members, known classes, each at most once. */
    public static function listError(mixed $list): ?string
    {
        if (!K3Sig::isList($list)) {
            return 'policy classes must be an array';
        }
        if (count($list) > count(self::CLASSES)) {
            return 'more than ' . count(self::CLASSES) . ' policy classes';
        }
        $seen = [];
        foreach ($list as $i => $v) {
            if (!($v instanceof Obj)) {
                return "policy_classes[$i] must be an object";
            }
            foreach ($v->keys() as $k) {
                if (!in_array($k, self::KEYS, true)) {
                    return "policy_classes[$i] has unknown member '$k'";
                }
            }
            $c = $v->get('class');
            if (!is_string($c) || !in_array($c, self::CLASSES, true)) {
                return "policy_classes[$i].class is not a known class";
            }
            if (isset($seen[$c])) {
                return "policy class '$c' appears twice";
            }
            $seen[$c] = true;
            if (!K3Sig::anySafeInt($v->get('revision')) || K3Sig::num($v->get('revision')) < 0) {
                return "policy_classes[$i].revision must be a non-negative safe integer";
            }
            $d = $v->get('digest');
            if (!is_string($d) || $d === '' || K3Sig::utf16Len($d) > 128) {
                return "policy_classes[$i].digest invalid";
            }
            if (!in_array($v->get('decision'), ['allow', 'escalate', 'deny'], true)) {
                return "policy_classes[$i].decision must be allow, escalate or deny";
            }
        }
        return null;
    }

    /** @return array{decision: string, classes: list<Obj>, denied_by: list<string>, escalated_by: list<string>, reason?: string} */
    public static function decide(mixed $list): array
    {
        $none = static fn (string $reason): array => ['decision' => 'deny', 'classes' => [], 'denied_by' => [], 'escalated_by' => [], 'reason' => $reason];
        try {
            if (K3Sig::isList($list) && $list === []) {
                return $none('no_policy_class');
            }
            if (($e = self::listError($list)) !== null) {
                return $none("malformed policy classes: $e");
            }
            usort($list, static fn (Obj $a, Obj $b): int => array_search($a->get('class'), self::CLASSES, true) <=> array_search($b->get('class'), self::CLASSES, true));
            $classes = [];
            foreach ($list as $v) {
                $o = new Obj();
                foreach (self::KEYS as $k) {
                    $o->set($k, $v->get($k));
                }
                $classes[] = $o;
            }
            $by = static fn (string $d): array => array_values(array_map(static fn (Obj $c): string => $c->get('class'), array_filter($classes, static fn (Obj $c): bool => $c->get('decision') === $d)));
            return ['decision' => Decision::meetAll(array_map(static fn (Obj $c): string => $c->get('decision'), $classes)),
                'classes' => $classes, 'denied_by' => $by('deny'), 'escalated_by' => $by('escalate')];
        } catch (\Throwable) {
            return $none('evaluation error (fail closed)');
        }
    }
}
