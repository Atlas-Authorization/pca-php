<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and the
 * per-peer OT messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript disagrees.
 * This class holds the pure parts (strict parsing, audit, blame, the commit-first binding); the timed exchange is the networked driver's.
 *
 * SlotDisclosure: ['bits' => list<int>, 'y' => GMP, 'z' => GMP, 'recv' => array<int,list<GMP>>, 'rho' => array<int,list<GMP>>]
 * (recv / rho keyed by peer index, insertion ordered). AuditResult: ['selfBad' => list<int>, 'pairBad' => list<array{0:int,1:int}>].
 */
final class MpcNetForensics
{
    public const DEFAULT_FORENSIC_DEADLINE_MS = 30000;

    public static function slotsFor(int $partners): int
    {
        return 1 + $partners;
    }

    /** The wire (JSON) form of a disclosure, a list of ordered maps. @param list<array> $d */
    public static function wireDisclosure(array $d): array
    {
        $out = [];
        foreach ($d as $s) {
            $out[] = ['bits' => implode('', $s['bits']), 'y' => MpcNetWire::hx($s['y']), 'z' => MpcNetWire::hx($s['z']),
                'recv' => self::side($s['recv']), 'rho' => self::side($s['rho'])];
        }
        return $out;
    }

    private static function side(array $x): array
    {
        $out = [];
        foreach ($x as $peer => $vals) {
            $out[] = [$peer, array_map(MpcNetWire::hx(...), $vals)];
        }
        return $out;
    }

    private static function field(mixed $s): \GMP
    {
        return MpcNetWire::unhx($s) ?? throw new \InvalidArgumentException('bad field element');
    }

    /**
     * Strict parse of a peer's disclosure (a parsed JSON value); throws on any deviation from the expected shape.
     * @param list<int> $peers @return list<array>
     */
    public static function parseDisclosure(mixed $raw, int $slots, int $rows, array $peers): array
    {
        if (!is_array($raw) || !array_is_list($raw) || count($raw) !== $slots) {
            throw new \InvalidArgumentException('bad forensic disclosure');
        }
        $out = [];
        foreach ($raw as $r) {
            if (!$r instanceof Obj || !is_string($r->get('bits')) || preg_match('/\A[01]{' . $rows . '}\z/', $r->get('bits')) !== 1) {
                throw new \InvalidArgumentException('bad choice bits');
            }
            $bits = array_map(static fn(string $c): int => $c === '1' ? 1 : 0, str_split($r->get('bits')));
            $out[] = ['bits' => $bits, 'y' => self::field($r->get('y')), 'z' => self::field($r->get('z')),
                'recv' => self::sideParse($r->get('recv'), $rows, $peers), 'rho' => self::sideParse($r->get('rho'), $rows, $peers)];
        }
        return $out;
    }

    /** @param list<int> $peers @return array<int,list<\GMP>> */
    private static function sideParse(mixed $x, int $rows, array $peers): array
    {
        if (!is_array($x) || !array_is_list($x) || count($x) !== count($peers)) {
            throw new \InvalidArgumentException('bad peer table');
        }
        $m = [];
        foreach ($x as $e) {
            if (!is_array($e) || !array_is_list($e) || count($e) !== 2 || !$e[0] instanceof Num) {
                throw new \InvalidArgumentException('bad peer entry');
            }
            $pd = $e[0]->float();
            $p = $pd === floor($pd) && abs($pd) < 1e9 ? (int) $pd : null;
            if ($p === null || !in_array($p, $peers, true) || array_key_exists($p, $m)) {
                throw new \InvalidArgumentException('bad peer entry');
            }
            $vals = $e[1];
            if (!is_array($vals) || !array_is_list($vals) || count($vals) !== $rows) {
                throw new \InvalidArgumentException('bad row table');
            }
            $arr = [];
            for ($i = 0; $i < $rows; $i++) {
                $arr[$i] = self::field($vals[$i]);
            }
            $m[$p] = $arr;
        }
        return $m;
    }

    /**
     * Cross-checks every party's disclosure of one failed triple against the public gadget.
     * @param array<int,list<array>> $all party => slots @param list<\GMP> $gadget
     * @return array{selfBad:list<int>,pairBad:list<array{0:int,1:int}>}
     */
    public static function auditDisclosures(array $all, array $gadget): array
    {
        $selfBad = [];
        $pairBad = [];
        $parties = array_keys($all);
        sort($parties);
        $at = static fn(array $m, int $p): array => $m[$p] ?? throw new \InvalidArgumentException('disclosure lacks peer ' . $p);
        foreach ($parties as $i) {
            foreach ($all[$i] as $s => $sd) {
                $value = gmp_init(0);
                foreach ($gadget as $k => $g) {
                    if ($k < count($sd['bits']) && $sd['bits'][$k] === 1) {
                        $value = gmp_add($value, $g);
                    }
                }
                $implied = MpcField::fmul(MpcField::mod($value), $sd['y']);
                foreach ($parties as $p) {
                    if ($p === $i) {
                        continue;
                    }
                    foreach ($at($sd['recv'], $p) as $v) {
                        $implied = MpcField::fadd($implied, MpcField::mod($v));
                    }
                    foreach ($at($sd['rho'], $p) as $v) {
                        $implied = MpcField::fsub($implied, $v);
                    }
                }
                if (gmp_cmp($implied, $sd['z']) !== 0) {
                    $selfBad[$i] = true;
                }
                foreach ($parties as $p) {
                    if ($p === $i) {
                        continue;
                    }
                    $sp = $all[$p][$s] ?? throw new \InvalidArgumentException('disclosure lacks a slot');
                    $rho = $at($sp['rho'], $i);
                    $got = $at($sd['recv'], $p);
                    $y = MpcField::mod($sp['y']);
                    $bad = false;
                    foreach ($gadget as $k => $g) {
                        if ($bad) {
                            break;
                        }
                        $add = $k < count($sd['bits']) && $sd['bits'][$k] === 1 ? MpcField::fmul($g, $y) : gmp_init(0);
                        $want = MpcField::fadd($rho[$k], $add);
                        if (gmp_cmp(MpcField::mod($got[$k]), $want) !== 0) {
                            $bad = true;
                        }
                    }
                    if ($bad) {
                        $pairBad[] = [$i, $p];
                    }
                }
            }
        }
        $sb = array_keys($selfBad);
        sort($sb);
        return ['selfBad' => $sb, 'pairBad' => $pairBad];
    }

    /** The party the verifier $me blames, or null when the evidence cannot name one. @param array{selfBad:list<int>,pairBad:list<array>} $r */
    public static function blameFrom(int $me, array $r): ?int
    {
        $own = array_values(array_filter($r['selfBad'], static fn(int $p): bool => $p !== $me));
        if ($own !== []) {
            return min($own);
        }
        foreach ($r['pairBad'] as $pr) {
            if ($pr[0] === $me) {
                return $pr[1];
            }
            if ($pr[1] === $me) {
                return $pr[0];
            }
        }
        return null;
    }

    /** Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form. */
    public static function disclosureCommit(string $sessionId, int $party, int $tripleIndex, int $deadlineMs, string $nonce, mixed $wire): string
    {
        return hash('sha256', "atlas-pca-mpc/forensic-commit/v1\0" . MpcNetWire::stringify([$sessionId, $party, $tripleIndex, $deadlineMs, $nonce, $wire]));
    }

    /**
     * Commit-first disclosure exchange. Returns every OTHER party's verified disclosure (by party). Nobody opens before every
     * commitment is in hand (the `forensic-c` exchange completes first), so no party's disclosure can depend on another's; an opening
     * that does not match its commitment is blamed, a late or absent party times out at the shared deadline.
     *
     * @param list<array> $mine @return array<int,list<array>>
     */
    public static function exchangeDisclosures(string $sessionId, int $id, int $n, int $tripleIndex, array $mine, int $slots, int $rows, int $deadlineMs, MpcNetExchanger $io): array
    {
        $wire = self::wireDisclosure($mine);
        $nonce = bin2hex(random_bytes(32));
        $myCommit = self::disclosureCommit($sessionId, $id, $tripleIndex, $deadlineMs, $nonce, $wire);
        $commits = $io->exchange('forensic-c', static fn(int $p): array => ['c' => $myCommit, 'd' => $deadlineMs], static function (int $p, mixed $raw) use ($io, $deadlineMs): string {
            $c = $raw instanceof Obj ? $raw->get('c') : null;
            if (!is_string($c) || preg_match('/\A[0-9a-f]{64}\z/', $c) !== 1) {
                $io->bad($p, 'bad forensic commitment');
            }
            $d = $raw->get('d');
            if (!$d instanceof Num || $d->float() !== (float) $deadlineMs) {
                $io->bad($p, 'forensic deadline differs from the agreed ' . $deadlineMs);
            }
            return $c;
        }, $deadlineMs);
        return $io->exchange('forensic-o', static fn(int $p): array => ['w' => $wire, 'nonce' => $nonce], static function (int $p, mixed $raw) use ($io, $sessionId, $id, $n, $tripleIndex, $deadlineMs, $commits, $slots, $rows): array {
            $nn = $raw instanceof Obj ? $raw->get('nonce') : null;
            if (!is_string($nn) || preg_match('/\A[0-9a-f]{64}\z/', $nn) !== 1) {
                $io->bad($p, 'bad forensic opening');
            }
            if (!hash_equals($commits[$p], self::disclosureCommit($sessionId, $p, $tripleIndex, $deadlineMs, $nn, $raw->get('w')))) {
                throw new MpcNetAbort('commitment', $p, $id, "party $p opened a forensic disclosure that does not match its commitment");
            }
            return self::parseDisclosure($raw->get('w'), $slots, $rows, array_values(array_filter(range(0, $n - 1), static fn(int $q): bool => $q !== $p)));
        }, $deadlineMs);
    }
}
