<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDiff.php';
require_once __DIR__ . '/ActionsRegistry.php';
require_once __DIR__ . '/Agent.php';

/**
 * Signed per-definition changes between two versions of a pack (native port of evolve.ts of the reference actions package): the unsigned
 * records, Ed25519 registry signing and the whole-change consistency check. Record shape and signature verification are in ActionsRegistry.
 */
final class ActionsEvolve
{
    /** @param list<Obj> $defs @return array<string,Obj> */
    private static function byVerb(array $defs): array
    {
        $m = [];
        foreach ($defs as $d) {
            if (isset($m[$d->get('verb')])) {
                throw new ActionKitError('duplicate_def', "verb '" . $d->get('verb') . "' appears twice");
            }
            $m[$d->get('verb')] = $d;
        }
        return $m;
    }

    /** @param list<string> $xs @return list<string> UTF-16 code unit order */
    private static function u16sorted(array $xs): array
    {
        usort($xs, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        return $xs;
    }

    /**
     * The unsigned records that take $prev to $next (sorted by verb). A verb rename is `removed` + `added`.
     *
     * @param list<Obj> $prev @param list<Obj> $next @return list<Obj>
     */
    public static function evolutionRecords(string $ns, array $prev, array $next, ?array $reg = null, ?\Closure $verifier = null): array
    {
        $reg ??= Actions::coreRegistry();
        $a = self::byVerb($prev);
        $b = self::byVerb($next);
        $out = [];
        foreach (self::u16sorted(array_map('strval', array_unique(array_merge(array_keys($a), array_keys($b))))) as $verb) {
            $o = $a[$verb] ?? null;
            $n = $b[$verb] ?? null;
            $rec = static fn(?string $from, ?string $to, string $class, array $reasons): Obj => Obj::of(
                ['v' => new Num('1'), 'kind' => ActionsRegistry::EVOLUTION_RECORD_KIND, 'ns' => $ns, 'verb' => $verb, 'from' => $from, 'to' => $to, 'class' => $class, 'reasons' => $reasons]);
            if ($o === null) {
                $out[] = $rec(null, Actions::defDigest($n), 'added', []);
            } elseif ($n === null) {
                $out[] = $rec(Actions::defDigest($o), null, 'removed', []);
            } else {
                $f = Actions::defDigest($o);
                $t = Actions::defDigest($n);
                if ($f === $t) {
                    continue;
                }
                $d = ActionsDiff::diffDefs($o, $n, $reg, $verifier);
                $out[] = $rec($f, $t, $d['class'], $d['reasons']);
            }
        }
        return $out;
    }

    /**
     * Sign the records as the registry (Ed25519 over the evolution domain and the strict canonical record).
     *
     * @param list<Obj> $records @return list<Obj>
     */
    public static function signEvolution(array $records, string $kid, string $secret): array
    {
        $kp = new KeyPair($secret);
        $out = [];
        foreach ($records as $r) {
            $bad = ActionsRegistry::evolutionRecordError($r, false);
            if ($bad !== null) {
                throw new \InvalidArgumentException("signEvolutionRecord: $bad");
            }
            $sig = $kp->sign(ActionsRegistry::EVOLUTION_DOMAIN . Json::canonicalizeNative($r));
            $s = $r->without();
            $s->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => $kid, 'value' => Pca::b64u($sig)]));
            $out[] = $s;
        }
        return $out;
    }

    private static function key(Obj $r): string
    {
        return implode('|', [IntentWb::jsStr($r->get('verb')), IntentWb::jsStr($r->has('from') ? $r->get('from') : JsUndefined::U), IntentWb::jsStr($r->has('to') ? $r->get('to') : JsUndefined::U),
            IntentWb::jsStr($r->get('class')), ActionsRegistry::evolutionDiffDigest($r)]);
    }

    /**
     * Does $records EXACTLY describe the change from $prev to $next? Every record verifies under the pinned registry keys and names $ns; none is
     * missing or extra; each class is the one the diff computes. Null = consistent, else the reason.
     *
     * @param list<Obj> $prev @param list<Obj> $next @param list<mixed> $records
     */
    public static function evolutionError(string $ns, array $prev, array $next, array $records, mixed $keys, ?array $reg = null, ?\Closure $verifier = null): ?string
    {
        try {
            foreach ($records as $r) {
                $v = ActionsRegistry::verifyEvolutionRecord($r, $keys);
                if (!$v['ok']) {
                    return 'evolution record: ' . $v['reason'];
                }
                if ($r->get('ns') !== $ns) {
                    return "evolution record names namespace '" . IntentWb::jsStr($r->get('ns')) . "', not '$ns'";
                }
            }
            $want = self::u16sorted(array_map(self::key(...), self::evolutionRecords($ns, $prev, $next, $reg, $verifier)));
            $have = self::u16sorted(array_map(static fn(Obj $r): string => self::key($r->without('sig')), $records));
            if (count($want) !== count($have)) {
                return 'evolution has ' . count($have) . ' records, the change needs ' . count($want);
            }
            foreach ($want as $i => $w) {
                if ($w !== $have[$i]) {
                    return 'evolution records do not match the computed change (a missing, extra or mis-classified record)';
                }
            }
            return null;
        } catch (\Throwable $e) {
            return 'evolution error: ' . $e->getMessage();
        }
    }
}
