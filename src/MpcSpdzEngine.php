<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** The SPDZ online engine: partial openings and the batched MAC-check (records are described on MpcSpdz). */
final class MpcSpdzEngine
{
    /** @var list<array> */
    private array $opened = [];
    private int $counter = 0;

    /** @param list<array> $deviations */
    public function __construct(private readonly array $ctx, private readonly array $deviations = [])
    {
        $bits = MpcSpdz::macSoundnessBits(1 + count($ctx['extraKeys']));
        if ($bits < MpcSpdz::MIN_MAC_SOUNDNESS_BITS) {
            throw new \InvalidArgumentException('SpdzEngine: MAC context gives only ' . (int) floor($bits + 0.5) . ' bits of statistical soundness (< ' . MpcSpdz::MIN_MAC_SOUNDNESS_BITS
                . '); use setupMac(n, rng) with the default ' . MpcSpdz::MAC_KEYS . ' keys');
        }
    }

    public function openCount(): int
    {
        return $this->counter;
    }

    public function open(array $x, string $label = ''): \GMP
    {
        $idx = $this->counter++;
        if (count($x['extraMac']) !== count($this->ctx['extraKeys'])) {
            throw new \InvalidArgumentException('open: value and MAC context disagree on the key count');
        }
        $valueShares = $x['value'];
        $macShares = array_merge([$x['mac']], $x['extraMac']);
        foreach ($this->deviations as $d) {
            if ($d['openIndex'] !== $idx) {
                continue;
            }
            if ($d['party'] < 0 || $d['party'] >= $this->ctx['n']) {
                throw new \InvalidArgumentException('Deviation.party out of range');
            }
            if ($d['valueDelta'] !== null) {
                $valueShares[$d['party']] = MpcField::fadd($valueShares[$d['party']], $d['valueDelta']);
            }
            if ($d['macDelta'] !== null) {
                $key = $d['macKey'] ?? 0;
                if ($key < 0 || $key >= count($macShares)) {
                    throw new \InvalidArgumentException('Deviation.macKey out of range');
                }
                $macShares[$key][$d['party']] = MpcField::fadd($macShares[$key][$d['party']], $d['macDelta']);
            }
        }
        $value = gmp_init(0);
        foreach ($valueShares as $s) {
            $value = MpcField::fadd($value, $s);
        }
        $this->opened[] = ['value' => $value, 'macShares' => $macShares, 'label' => $label];
        return $value;
    }

    /** Batched MAC-check over every partial open so far; throws MpcMacCheckAbort on any inconsistency. */
    public function macCheck(MpcFieldRng $rng): void
    {
        if ($this->opened === []) {
            return;
        }
        $keys = MpcSpdz::macKeys($this->ctx);
        $challenges = [];
        foreach ($keys as $l => $_) {
            for ($j = 0; $j < count($this->opened); $j++) {
                $challenges[$l][$j] = $rng->next();
            }
        }
        $alphas = array_map(static fn(array $k): array => $k['alphaShares'], $keys);
        $sigma = MpcSpdz::macResiduals(MpcField::prime(), $alphas, $this->opened, $challenges);

        foreach ($sigma as $row) {
            $nonces = [];
            foreach ($row as $_) {
                $nonces[] = $rng->next();
            }
            $commitments = [];
            foreach ($row as $i => $s) {
                $commitments[$i] = MpcSpdz::commit($s, $nonces[$i]);
            }
            foreach ($commitments as $i => $c) {
                if (MpcSpdz::commit($row[$i], $nonces[$i]) !== $c) {
                    throw new MpcMacCheckAbort("MAC-check: commitment from party $i did not open consistently");
                }
            }
        }
        foreach ($sigma as $l => $row) {
            $residual = gmp_init(0);
            foreach ($row as $s) {
                $residual = MpcField::fadd($residual, $s);
            }
            if (gmp_sign($residual) !== 0) {
                throw new MpcMacCheckAbort("MAC-check FAILED (key $l): residual " . gmp_strval($residual) . " != 0 \u{2014} an actively-malicious party was detected; aborting with no output");
            }
        }
    }
}
