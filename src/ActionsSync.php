<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDiff.php';

/**
 * Keep a platform's action definitions in step with the sources they were imported from (native port of sync.ts of the reference actions package).
 * Pure: the caller fetches the source and stores the lock. A def the lock does not attribute to this source is never touched; a changed operation
 * is never carried over as confirmed.
 */
final class ActionsSync
{
    private static function asImported(Obj $d): Obj
    {
        if ($d->get('review')->get('state') !== 'confirmed') {
            return $d;
        }
        $o = $d->without();
        $o->set('review', Obj::of(['state' => 'unreviewed']));
        return $o;
    }

    /**
     * Merge a fresh import of one source into the current defs: {defs, entries, deprecated, lock, needsReview}.
     *
     * @param list<Obj> $current @param list<Obj> $imported
     * @return array<string,mixed>
     */
    public static function syncSource(array $current, array $imported, string $specDigest, mixed $now, ?Obj $lock = null, ?array $registry = null, ?\Closure $verifier = null): array
    {
        $reg = $registry ?? Actions::coreRegistry();
        $cur = [];
        foreach ($current as $d) {
            $cur[$d->get('verb')] = $d;
        }
        $imp = [];
        foreach ($imported as $d) {
            $imp[$d->get('verb')] = self::asImported($d);
        }
        $lockedOps = $lock !== null && $lock->get('ops') instanceof Obj ? $lock->get('ops') : new Obj();
        $ops = new Obj();
        $entries = [];
        $defs = [];
        $verbs = array_map('strval', array_keys($imp));
        usort($verbs, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($verbs as $verb) {
            $d = $imp[$verb];
            $dg = Actions::defDigest($d);
            $ops->set($verb, $dg);
            $old = $cur[$verb] ?? null;
            $locked = $lock !== null ? $lockedOps->get($verb) : null;
            if ($old === null) {
                $entries[] = ['verb' => $verb, 'change' => 'added'];
                $defs[] = $d;
            } elseif ($locked === $dg || ($locked === null && Actions::defDigest($old) === $dg)) {
                $entries[] = ['verb' => $verb, 'change' => 'unchanged'];
                $defs[] = $old;
            } else {
                try {
                    $diff = ActionsDiff::diffDefs($old, $d, $reg, $verifier);
                } catch (\Throwable $e) {
                    $diff = ['class' => 'incomparable', 'reasons' => [$e->getMessage()]];
                }
                $entries[] = ['verb' => $verb, 'change' => 'changed', 'diff' => $diff];
                $defs[] = $d;
            }
        }
        $deprecated = array_values(array_filter($lockedOps->keys(), static fn(string $v): bool => !isset($imp[$v])));
        usort($deprecated, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($deprecated as $v) {
            $entries[] = ['verb' => $v, 'change' => 'removed'];
        }
        return ['defs' => $defs, 'entries' => $entries, 'deprecated' => $deprecated, 'lock' => Obj::of(['spec_digest' => $specDigest, 'ops' => $ops, 'synced_at' => $now]),
            'needsReview' => count(array_filter($entries, static fn(array $e): bool => in_array($e['change'], ['added', 'changed'], true))) > 0];
    }

    /** One line per changed entry, then a summary. @param array<string,mixed> $r a syncSource result */
    public static function syncText(array $r): string
    {
        $lines = [];
        foreach ($r['entries'] as $e) {
            if ($e['change'] === 'unchanged') {
                continue;
            }
            $extra = '';
            if (isset($e['diff'])) {
                $extra = '  (' . $e['diff']['class'] . ($e['diff']['reasons'] ? ': ' . implode(', ', $e['diff']['reasons']) : '') . ')';
            }
            $lines[] = str_pad($e['change'], 9) . ' ' . $e['verb'] . $extra;
        }
        $n = static fn(string $c): int => count(array_filter($r['entries'], static fn(array $e): bool => $e['change'] === $c));
        $lines[] = $n('added') . ' added, ' . $n('changed') . ' changed, ' . $n('removed') . ' removed (deprecated), ' . $n('unchanged') . ' unchanged'
            . ($r['needsReview'] ? '; added and changed actions are unreviewed (strict) until a reviewer confirms them' : '');
        return implode("\n", $lines);
    }
}
