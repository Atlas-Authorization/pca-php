<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentV2.php';

/** The wallet-side builder of the committed Intent Map (rule 19 leaf order, per-leaf salts derived from a 32-byte secret). */
final class IntentMap
{
    private static function sha(string $s): string
    {
        return hash('sha256', $s, true);
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    /** @param list<string> $hs */
    private static function auditPath(array $hs, int $idx, array &$out): void
    {
        if (count($hs) === 1) {
            return;
        }
        $k = self::split(count($hs));
        if ($idx < $k) {
            self::auditPath(array_slice($hs, 0, $k), $idx, $out);
            $out[] = IntentV2::mapTreeRoot(array_slice($hs, $k));
        } else {
            self::auditPath(array_slice($hs, $k), $idx - $k, $out);
            $out[] = IntentV2::mapTreeRoot(array_slice($hs, 0, $k));
        }
    }

    private static function dimCells(Obj $d): int
    {
        return $d->get('kind') === 'num' ? count(IntentV2::mapNumCells($d)) : count($d->get('values'));
    }

    /**
     * Build the committed form. `$headers` is a list of Obj {verb, dims}; `$cells` an Obj verb => list of Obj {cell, p_ppm, in_grant}.
     * Returns ['map_commit', 'size', 'leaves' => [{kind, leaf, salt}], 'disclose' => fn(verb, resource, params)]. Throws on malformed input.
     */
    public static function commitMap(array $headers, Obj $cells, mixed $metrics, string $learnerDigest, string $secret): array
    {
        if (strlen($secret) !== 32) {
            throw new \InvalidArgumentException('commitMap: the secret is 32 bytes');
        }
        usort($headers, static fn($a, $b) => strcmp($a->get('verb'), $b->get('verb')));
        for ($i = 1; $i < count($headers); $i++) {
            if ($headers[$i]->get('verb') === $headers[$i - 1]->get('verb')) {
                throw new \InvalidArgumentException('commitMap: duplicate verb');
            }
        }
        $nxt = count($headers);
        $full = [];
        foreach ($headers as $h) {
            $n = 1;
            foreach ($h->get('dims') as $d) {
                $n *= self::dimCells($d);
            }
            $full[] = Obj::of(['verb' => $h->get('verb'), 'first' => $nxt, 'cells' => $n, 'dims' => $h->get('dims')]);
            $nxt += $n;
        }
        $leaves = [];
        foreach ($full as $h) {
            $leaves[] = ['header', $h];
        }
        foreach ($full as $h) {
            $cs = $cells->has($h->get('verb')) ? $cells->get($h->get('verb')) : null;
            if (!is_array($cs) || count($cs) !== $h->get('cells')) {
                throw new \InvalidArgumentException("commitMap: verb {$h->get('verb')} needs {$h->get('cells')} cell leaves");
            }
            foreach ($cs as $c) {
                $leaves[] = ['cell', Obj::of(['verb' => $h->get('verb'), 'cell' => $c->get('cell'), 'p_ppm' => $c->get('p_ppm'), 'in_grant' => $c->get('in_grant')])];
            }
        }
        $leaves[] = ['metrics', $metrics];
        $leaves[] = ['learner', Obj::of(['learner_digest' => $learnerDigest])];
        foreach ($leaves as [$kind, $leaf]) {
            $e = match ($kind) {
                'header' => IntentV2::mapHeaderError($leaf),
                'cell' => IntentV2::mapCellError($leaf),
                'metrics' => IntentV2::mapMetricsError($leaf),
                default => IntentV2::mapLearnerError($leaf),
            };
            if ($e !== null) {
                throw new \InvalidArgumentException('commitMap: ' . $e);
            }
        }
        $size = count($leaves);
        if ($size < 4 || $size > IntentV2::MAX_MAP_LEAVES) {
            throw new \InvalidArgumentException('commitMap: the map has too few or too many leaves');
        }
        $salts = [];
        $hashes = [];
        foreach ($leaves as $i => [$kind, $leaf]) {
            $salts[$i] = self::sha(IntentV2::MAP_TAG_SALT . $secret . pack('J', $i));
            $hashes[$i] = IntentV2::mapLeafHash($kind, $salts[$i], $leaf);
        }
        $root = IntentV2::mapTreeRoot($hashes);
        $entry = static function (int $i) use ($salts, $leaves, $hashes): Obj {
            $path = [];
            self::auditPath($hashes, $i, $path);
            return Obj::of(['index' => $i, 'salt' => Pca::b64u($salts[$i]), 'leaf' => $leaves[$i][1], 'path' => array_map([Pca::class, 'b64u'], $path)]);
        };
        $disclose = static function (string $verb, mixed $resource, mixed $params) use ($full, $size, $entry): Obj {
            $hi = -1;
            foreach ($full as $i => $h) {
                if ($h->get('verb') === $verb) {
                    $hi = $i;
                    break;
                }
            }
            if ($hi < 0) {
                throw new \InvalidArgumentException("commitMap.disclose: verb $verb is not in the map");
            }
            $w = IntentV2::mapCellOf($full[$hi], $resource, $params);
            if (isset($w['error'])) {
                throw new \InvalidArgumentException('commitMap.disclose: ' . $w['error']);
            }
            return Obj::of(['size' => $size, 'header' => $entry($hi), 'cell' => $entry($full[$hi]->get('first') + $w['flat']), 'metrics' => $entry($size - 2)]);
        };
        $out = [];
        foreach ($leaves as $i => [$kind, $leaf]) {
            $out[] = Obj::of(['kind' => $kind, 'leaf' => $leaf, 'salt' => Pca::b64u($salts[$i])]);
        }
        return ['map_commit' => IntentV2::mapCommitOf($size, $root), 'size' => $size, 'leaves' => $out, 'disclose' => $disclose];
    }
}
