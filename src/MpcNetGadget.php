<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** What the networked rounds need from the party driver: one un-echoed all-to-all round, and a malformed-data abort. */
interface MpcNetExchanger
{
    /**
     * Send mine($peer) to every peer, collect theirs and validate each with parse($peer, $raw); a throw inside parse aborts the run
     * naming that peer. $timeoutMs null means the mesh default.
     *
     * @param callable(int):mixed $mine @param callable(int,mixed):mixed $parse @return array<int,mixed> parsed values by peer
     */
    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array;

    /** Throws a malformed-data abort naming peer $p. */
    public function bad(int $p, string $what): never;
}

/**
 * Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so that ONE corrupt party cannot make the
 * honest parties derive different gadgets and then blame each other. Every commitment and opening is SIGNED with the sender's pinned
 * TLS identity key; each party then echoes the signed values it got from each third party (`gd-e`). An echoed signature that does not
 * verify is a forgery by the echoer; an echoed statement that verifies but differs from the one received directly means the signer
 * signed two values for one round (blamed, with both statements as transferable evidence). With n = 2 there is no third party, so
 * the echo round is skipped.
 */
final class MpcNetGadget
{
    private const HEX64 = '/\A[0-9a-f]{64}\z/';
    private const HEXSIG = '/\A[0-9a-f]{16,200}\z/';

    private static function isSigned(mixed $x, string $valueRe): bool
    {
        if (!$x instanceof Obj) {
            return false;
        }
        $v = $x->get('v');
        $s = $x->get('s');
        return is_string($v) && preg_match($valueRe, $v) === 1 && is_string($s) && preg_match(self::HEXSIG, $s) === 1;
    }

    /**
     * Run the signed commit / reveal / echo and return every party's raw seed in party order (mine included).
     * @return list<string>
     */
    public static function agreeGadgetSeeds(MpcNetMesh $net, int $n, MpcNetExchanger $io, ?string $mySeed = null): array
    {
        $mySeed ??= random_bytes(32);
        $id = $net->selfId;
        $sid = $net->sessionId();
        $sign = static fn(string $round, string $value): array => ['v' => $value, 's' => bin2hex($net->sign(MpcNetCodec::gadgetStatement($sid, $round, $id, $value)))];
        $check = static function (int $signer, string $round, Obj $m) use ($net, $sid): bool {
            $s = $m->get('s');
            return strlen($s) % 2 === 0 && $net->verify($signer, MpcNetCodec::gadgetStatement($sid, $round, $signer, $m->get('v')), (string) hex2bin($s));
        };

        $myCommit = MpcNetCodec::gadgetCommit($sid, $id, $mySeed);
        $commits = $io->exchange('gd-c', static fn(int $p): array => $sign('gd-c', $myCommit), static function (int $p, mixed $raw) use ($io, $check) {
            if (!self::isSigned($raw, self::HEX64)) {
                $io->bad($p, 'bad gadget commitment');
            }
            if (!$check($p, 'gd-c', $raw)) {
                $io->bad($p, 'gadget commitment signature does not verify');
            }
            return $raw;
        });
        $mySeedHex = bin2hex($mySeed);
        $opens = $io->exchange('gd-o', static fn(int $p): array => $sign('gd-o', $mySeedHex), static function (int $p, mixed $raw) use ($io, $check, $sid, $id, $commits) {
            if (!self::isSigned($raw, self::HEX64)) {
                $io->bad($p, 'bad gadget seed');
            }
            if (!$check($p, 'gd-o', $raw)) {
                $io->bad($p, 'gadget seed signature does not verify');
            }
            if (MpcNetCodec::gadgetCommit($sid, $p, (string) hex2bin($raw->get('v'))) !== $commits[$p]->get('v')) {
                throw new MpcNetAbort('commitment', $p, $id, "party $p opened a gadget seed that does not match its commitment");
            }
            return $raw;
        });

        if ($n >= 3) {
            $others = array_values(array_filter(range(0, $n - 1), static fn(int $i): bool => $i !== $id));
            $io->exchange('gd-e', static function (int $peer) use ($others, $commits, $opens): array {
                $o = [];
                foreach ($others as $j) {
                    if ($j !== $peer) {
                        $o[] = ['j' => $j, 'c' => $commits[$j], 'o' => $opens[$j]];
                    }
                }
                return $o;
            }, static function (int $p, mixed $raw) use ($others, $io, $check, $commits, $opens, $id) {
                $expect = array_values(array_filter($others, static fn(int $j): bool => $j !== $p));
                if (!is_array($raw) || !array_is_list($raw) || count($raw) !== count($expect)) {
                    $io->bad($p, 'bad gadget echo');
                }
                foreach ($expect as $k => $j) {
                    $e = $raw[$k];
                    $ej = $e instanceof Obj ? $e->get('j') : null;
                    if (!$e instanceof Obj || !$ej instanceof Num || $ej->float() !== (float) $j || !self::isSigned($e->get('c'), self::HEX64) || !self::isSigned($e->get('o'), self::HEX64)) {
                        $io->bad($p, 'bad gadget echo entry');
                    }
                    $ec = $e->get('c');
                    $eo = $e->get('o');
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    if (!$check($j, 'gd-c', $ec) || !$check($j, 'gd-o', $eo)) {
                        $io->bad($p, "gadget echo carries a statement that party $j did not sign");
                    }
                    $mineC = $commits[$j];
                    $mineO = $opens[$j];
                    if ($ec->get('v') !== $mineC->get('v') || $eo->get('v') !== $mineO->get('v')) {
                        // both statements verify under j's key and differ: j signed two values for one round
                        $com = $ec->get('v') !== $mineC->get('v');
                        throw new MpcNetAbort('equivocation', $j, $id,
                            "party $j signed different gadget " . ($com ? 'commitments' : 'seeds') . " for different parties (shown by party $p's echo)", null, null, null,
                            ['signer' => $j, 'round' => $com ? 'gd-c' : 'gd-o', 'statements' => $com ? [$mineC, $ec] : [$mineO, $eo]]);
                    }
                }
                return true;
            });
        }
        $out = [];
        for ($p = 0; $p < $n; $p++) {
            $out[] = $p === $id ? $mySeed : (string) hex2bin($opens[$p]->get('v'));
        }
        return $out;
    }
}
