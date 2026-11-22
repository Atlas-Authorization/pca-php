<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * L4 information-flow taint and the `enforce.taint` gate (packages/pca/src/taint.ts and the proved kernels behind it).
 * The agent's own label is never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input
 * registry it populated, or its own committed resource graph); a ref the server cannot vouch for is `agent` (the worst case).
 * Pure and deterministic; malformed or absent provenance and any internal error fail CLOSED to taint 1.
 * A registry is any object with `lookup(string): ?Obj`; a resource graph any object with `node(string): mixed`.
 */
final class Taint
{
    public const LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'];
    private const MAX_RANK = 4;

    public static function isLevel(mixed $kind): bool
    {
        return is_string($kind) && in_array($kind, self::LEVELS, true);
    }

    /** The rank of a label; an unknown or non-string kind is the WORST rank (fail closed). */
    public static function labelRank(mixed $label): int
    {
        $kind = $label instanceof Obj ? $label->get('kind') : null;
        return self::isLevel($kind) ? (int)array_search($kind, self::LEVELS, true) : self::MAX_RANK;
    }

    public static function taintValue(mixed $label): float
    {
        return self::labelRank($label) / (float)self::MAX_RANK;
    }

    /** Least upper bound: the higher rank; equal ranks keep the id only when both agree, else the generic representative. */
    public static function joinLabel(Obj $a, Obj $b): Obj
    {
        $ra = self::labelRank($a);
        $rb = self::labelRank($b);
        if ($ra > $rb) {
            return $a;
        }
        if ($rb > $ra) {
            return $b;
        }
        if ($a->get('id') === $b->get('id')) {
            return $a;
        }
        return Obj::of(['kind' => $a->get('kind')]);
    }

    /** The empty lineage joins to the worst case: "no verifiable trusted input" is not "trusted". */
    public static function joinLabels(array $labels): Obj
    {
        if ($labels === []) {
            return Obj::of(['kind' => 'agent']);
        }
        $acc = $labels[0];
        for ($i = 1; $i < count($labels); $i++) {
            $acc = self::joinLabel($acc, $labels[$i]);
        }
        return $acc;
    }

    public static function classifyRef(mixed $ref, object $registry, ?object $graph): Obj
    {
        if (!is_string($ref) || $ref === '') {
            return Obj::of(['kind' => 'agent']);
        }
        $vouched = $registry->lookup($ref);
        if ($vouched instanceof Obj && self::isLevel($vouched->get('kind'))) {
            return $vouched;
        }
        try {
            if ($graph !== null && $graph->node($ref)) {
                return Obj::of(['kind' => 'first_party']);
            }
        } catch (\Throwable) {
            // worst case
        }
        return strlen($ref) <= 128 ? Obj::of(['kind' => 'agent', 'id' => $ref]) : Obj::of(['kind' => 'agent']);
    }

    private static function invalid(string $reason): array
    {
        return ['taint' => 1.0, 'label' => Obj::of(['kind' => 'agent']), 'refs' => [], 'valid' => false, 'reason' => $reason];
    }

    /** `['taint', 'label', 'refs', 'valid', 'reason'?]` for a PCActn's provenance. Never throws. */
    public static function computeTaint(mixed $provenance, mixed $registry, ?object $graph = null): array
    {
        try {
            $regOk = is_object($registry) && method_exists($registry, 'lookup');
            $provOk = $provenance instanceof Obj;
            $refs = [];
            if ($regOk && $provOk && $provenance->has('trusted_refs')) {
                $raw = $provenance->get('trusted_refs');
                if (!is_array($raw) || !array_is_list($raw)) {
                    return self::invalid('taint: trusted_refs must be an array');
                }
                foreach ($raw as $r) {
                    if (!is_string($r) || $r === '') {
                        return self::invalid('taint: trusted_refs must be non-empty strings');
                    }
                }
                $refs = $raw;
            }
            if (!$regOk) {
                return self::invalid('taint: no trusted-input registry');
            }
            if (!$provOk) {
                return self::invalid('taint: provenance is absent or malformed');
            }
            $classified = [];
            foreach ($refs as $r) {
                $classified[] = ['ref' => $r, 'label' => self::classifyRef($r, $registry, $graph)];
            }
            $label = self::joinLabels(array_map(static fn(array $c): Obj => $c['label'], $classified));
            return ['taint' => self::labelRank($label) / (float)self::MAX_RANK, 'label' => $label, 'refs' => $classified, 'valid' => true];
        } catch (\Throwable $e) {
            return self::invalid('taint: evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    /**
     * The enforce.taint gate: `['ok' => true]` or `['ok' => false, 'reason' => ...]`. `$maxTaint` is the largest taint the policy
     * accepts; a negative or non-numeric bound is a misconfiguration and never passes.
     */
    public static function taintGate(mixed $provenance, mixed $registry, ?object $graph, mixed $maxTaint): array
    {
        try {
            $t = self::computeTaint($provenance, $registry, $graph);
            if (!$t['valid']) {
                return ['ok' => false, 'reason' => $t['reason'] ?? 'provenance lineage is not server-verifiable (fail closed)'];
            }
            $max = $maxTaint instanceof Num ? $maxTaint->float() : $maxTaint;
            if (!(is_int($max) || is_float($max)) || !is_finite((float)$max) || $max < 0) {
                return ['ok' => false, 'reason' => 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)'];
            }
            $allowed = -1;
            for ($r = 0; $r <= self::MAX_RANK; $r++) {
                if ($r / self::MAX_RANK <= $max) {
                    $allowed = $r;
                }
            }
            if (self::labelRank($t['label']) <= $allowed) {
                return ['ok' => true];
            }
            return ['ok' => false, 'reason' => 'information-flow taint ' . IntentV2::jsNumStr((float)$t['taint']) . ' exceeds policy max ' . IntentV2::jsNumStr((float)$max)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'taint gate error (fail closed): ' . $e->getMessage()];
        }
    }
}

/** The server's trusted-input registry: digest -> label. Only the server populates it; nothing an agent sends reaches it. */
final class InMemoryTaintRegistry
{
    /** @var array<string, Obj> */
    private array $m = [];

    public function record(string $digest, Obj $label): self
    {
        if ($digest !== '' && Taint::isLevel($label->get('kind'))) {
            $this->m[$digest] = $label;
        }
        return $this;
    }

    public function recordTrusted(string $digest): self { return $this->record($digest, Obj::of(['kind' => 'trusted'])); }
    public function recordFirstParty(string $digest): self { return $this->record($digest, Obj::of(['kind' => 'first_party'])); }
    public function recordTool(string $digest, string $id): self { return $this->record($digest, Obj::of(['kind' => 'tool', 'id' => $id])); }
    public function recordWeb(string $digest): self { return $this->record($digest, Obj::of(['kind' => 'web'])); }
    public function lookup(string $digest): ?Obj { return $this->m[$digest] ?? null; }
    public function size(): int { return count($this->m); }
}
