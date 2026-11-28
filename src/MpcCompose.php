<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Composition semantics (the "meet" of stakeholder authorities) and the cleartext reference: allow = AND, t = MAX, rQuant = MAX.
 * Composition can only tighten, never loosen. A composed decision is ['allow' => int, 't' => int, 'rQuant' => int].
 */
final class MpcCompose
{
    /** Rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer rQuant in [0,Q]). @param list<array{allow:int,t:int,rQuant:int}> $vectors */
    public static function assertDecisionVectors(array $vectors, int $Q): void
    {
        foreach ($vectors as $i => $v) {
            if (!is_array($v)) {
                throw new \InvalidArgumentException("party $i: decision vector must be an object");
            }
            if ($v['allow'] !== 0 && $v['allow'] !== 1) {
                throw new \InvalidArgumentException("party $i: allow must be 0 or 1");
            }
            if ($v['t'] < 1 || $v['t'] > 3) {
                throw new \InvalidArgumentException("party $i: t must be 1, 2 or 3");
            }
            if ($v['rQuant'] < 0 || $v['rQuant'] > $Q) {
                throw new \InvalidArgumentException("party $i: rQuant must be an integer in [0, $Q]");
            }
        }
    }

    /** @param list<array{allow:int,t:int,rQuant:int}> $vectors @return array{allow:int,t:int,rQuant:int} */
    public static function composeClear(array $vectors, int $Q = MpcParty::DEFAULT_Q): array
    {
        if ($vectors === []) {
            throw new \InvalidArgumentException('composeClear: no parties (fail closed)');
        }
        self::assertDecisionVectors($vectors, $Q);
        $allow = 1;
        $t = 1;
        $r = 0;
        foreach ($vectors as $v) {
            if ($v['allow'] === 0) {
                $allow = 0;
            }
            $t = max($t, $v['t']);
            $r = max($r, $v['rQuant']);
        }
        return ['allow' => $allow, 't' => $t, 'rQuant' => $r];
    }
}
