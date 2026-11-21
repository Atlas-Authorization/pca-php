<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Pairwise base oblivious transfer OVER THE NETWORK between two nodes: `ec` is the malicious-secure Chou-Orlandi-style base OT on
 * Ed25519 (Schnorr proof of knowledge, subgroup validation of every received point, transcript KDF); `lwe` is the post-quantum endemic
 * OT over Module-LWE (MpcEndemicOt, which needs the liblweot library). A FUNCTIONAL-CORRECTNESS demonstration: afterwards the receiver
 * reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can check the pads over
 * a real network. A result is ['kind','role','count','ms','matched','padDigest'].
 */
final class MpcNetOt
{
    /** Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round. */
    public static function netBinding(MpcNetMesh $mesh, int $senderIndex, int $receiverIndex, string $round): array
    {
        return ['sessionId' => hash('sha256', 'atlas-pca-mpc/net-session/v2' . Js::utf8($mesh->sessionId()), true), 'senderIndex' => $senderIndex, 'receiverIndex' => $receiverIndex, 'round' => $round];
    }

    private static function parsing(MpcNetMesh $mesh, int $peer, string $rd, callable $f): mixed
    {
        try {
            return $f();
        } catch (\Throwable $e) {
            $ne = new MpcNetAbort('malformed', $peer, $mesh->selfId, "round '$rd': " . $e->getMessage());
            $mesh->fail($ne);
            throw $ne;
        }
    }

    private static function bit(mixed $o): int
    {
        return $o instanceof Num && $o->lexeme === '0' ? 0 : ($o instanceof Num && $o->lexeme === '1' ? 1 : -1);
    }

    /** @param list<string> $pads */
    private static function digest(array $pads): string
    {
        return hash('sha256', implode('', $pads));
    }

    /** @return array<int,array{0:string,1:string}> */
    private static function parseCtPairs(mixed $raw, int $count): array
    {
        if (!is_array($raw) || !array_is_list($raw) || count($raw) !== $count) {
            throw new \InvalidArgumentException('bad ciphertext array');
        }
        return array_map(static function (mixed $pp): array {
            if (!is_array($pp) || !array_is_list($pp) || count($pp) !== 2) {
                throw new \InvalidArgumentException('bad ct pair');
            }
            return [MpcNetCodec::unb64($pp[0]), MpcNetCodec::unb64($pp[1])];
        }, $raw);
    }

    /** The sending side (the one whose pads the receiver proves it holds). @return array<string,mixed> */
    public static function runOtSender(MpcNetMesh $mesh, int $peer, string $kind, int $count): array
    {
        $t0 = microtime(true);
        $rng = MpcOtRandom::secure();
        if ($kind === 'ec') {
            $binding = self::netBinding($mesh, $mesh->selfId, $peer, 'ot-ec');
            $setup = MpcOt::malBaseOtSenderSetup($rng, $binding);
            $mesh->send($peer, 'ot-S', ['S' => MpcNetCodec::ptJ($setup['S']), 'U' => MpcNetCodec::ptJ($setup['proof']['U']), 'z' => MpcNetWire::hx($setup['proof']['z'])]);
            $rRaw = $mesh->recv($peer, 'ot-R');
            $R = self::parsing($mesh, $peer, 'ot-R', static function () use ($rRaw, $count): array {
                if (!is_array($rRaw) || !array_is_list($rRaw) || count($rRaw) !== $count) {
                    throw new \InvalidArgumentException('bad R array');
                }
                return array_map(MpcNetCodec::jPt(...), $rRaw);
            });
            try {
                $senderPads = MpcOt::malBaseOtSenderDerive($setup['y'], $setup['T'], $R, $setup['S'], $binding);
            } catch (\Throwable $e) {
                $ne = new MpcNetAbort('malformed', $peer, $mesh->selfId, $e->getMessage());
                $mesh->fail($ne);
                throw $ne;
            }
        } elseif ($kind === 'lwe') {
            $m = $mesh->recv($peer, 'ot-recv');
            $msg = self::parsing($mesh, $peer, 'ot-recv', static function () use ($m, $count): array {
                $pts = $m instanceof Obj ? $m->get('points') : null;
                $rhos = $m instanceof Obj ? $m->get('rhos') : null;
                if (!is_array($pts) || !is_array($rhos) || count($pts) !== $count || count($rhos) !== $count) {
                    throw new \InvalidArgumentException('bad receiver message');
                }
                return ['rn' => MpcNetCodec::unb64($m->get('rn'), 32), 'rhos' => array_map(static fn(mixed $r): string => MpcNetCodec::unb64($r, 32), $rhos),
                    'points' => array_map(static function (mixed $pp): array {
                        if (!is_array($pp) || count($pp) !== 2) {
                            throw new \InvalidArgumentException('bad point pair');
                        }
                        return [MpcNetCodec::unb64($pp[0]), MpcNetCodec::unb64($pp[1])];
                    }, $pts)];
            });
            try {
                $sm = MpcEndemicOt::sendRandom($msg, $rng);
            } catch (\Throwable $e) {
                $ne = new MpcNetAbort('malformed', $peer, $mesh->selfId, 'lwe sender: ' . $e->getMessage());
                $mesh->fail($ne);
                throw $ne;
            }
            $senderPads = $sm['senderPads'];
            $mesh->send($peer, 'ot-ct', array_map(static fn(array $c): array => [MpcNetCodec::b64($c[0]), MpcNetCodec::b64($c[1])], $sm['ciphertexts']));
        } else {
            throw new \InvalidArgumentException('unknown OT kind');
        }
        // demo-only verification: the receiver reveals choices + pad hashes
        $v = $mesh->recv($peer, 'ot-verify');
        $ok = self::parsing($mesh, $peer, 'ot-verify', static function () use ($v, $count, $senderPads): bool {
            $cs = $v instanceof Obj ? $v->get('choices') : null;
            $hs = $v instanceof Obj ? $v->get('padHashes') : null;
            if (!is_array($cs) || !is_array($hs) || count($cs) !== $count || count($hs) !== $count) {
                throw new \InvalidArgumentException('bad verify message');
            }
            foreach ($cs as $i => $c) {
                $b = self::bit($c);
                if ($b < 0 || hash('sha256', $senderPads[$i][$b]) !== $hs[$i]) {
                    return false;
                }
            }
            return true;
        });
        $mesh->send($peer, 'ot-done', ['matched' => $ok]);
        $mesh->finish();
        $flat = [];
        foreach ($senderPads as $p) {
            $flat[] = $p[0];
            $flat[] = $p[1];
        }
        return ['kind' => $kind, 'role' => 'sender', 'count' => $count, 'ms' => (microtime(true) - $t0) * 1000, 'matched' => $ok, 'padDigest' => self::digest($flat)];
    }

    /** The receiving side. @return array<string,mixed> */
    public static function runOtReceiver(MpcNetMesh $mesh, int $peer, string $kind, int $count): array
    {
        $t0 = microtime(true);
        $rng = MpcOtRandom::secure();
        $choices = [];
        for ($i = 0; $i < $count; $i++) {
            $choices[] = ord($rng->bytes(1)) & 1;
        }
        if ($kind === 'ec') {
            $sRaw = $mesh->recv($peer, 'ot-S');
            $parsed = self::parsing($mesh, $peer, 'ot-S', static function () use ($sRaw): array {
                if (!$sRaw instanceof Obj) {
                    throw new \InvalidArgumentException('bad S message');
                }
                return ['proof' => ['U' => MpcNetCodec::jPt($sRaw->get('U')), 'z' => MpcNetCodec::hexBig($sRaw->get('z'))], 'S' => MpcNetCodec::jPt($sRaw->get('S'))];
            });
            try {
                $res = MpcOt::malBaseOtReceiverRespond($parsed['S'], $parsed['proof'], $choices, $rng, self::netBinding($mesh, $peer, $mesh->selfId, 'ot-ec'));
            } catch (\Throwable $e) {
                $ne = new MpcNetAbort($e instanceof MpcBaseOtAbort ? 'commitment' : 'malformed', $peer, $mesh->selfId, $e->getMessage());
                $mesh->fail($ne);
                throw $ne;
            }
            $recvPads = $res['recvPads'];
            $mesh->send($peer, 'ot-R', array_map(MpcNetCodec::ptJ(...), $res['R']));
        } elseif ($kind === 'lwe') {
            $r = MpcEndemicOt::receive($choices, $rng);
            $message = $r['message'];
            $mesh->send($peer, 'ot-recv', ['rn' => MpcNetCodec::b64($message['rn']),
                'points' => array_map(static fn(array $pp): array => [MpcNetCodec::b64($pp[0]), MpcNetCodec::b64($pp[1])], $message['points']),
                'rhos' => array_map(MpcNetCodec::b64(...), $message['rhos'])]);
            $ctRaw = $mesh->recv($peer, 'ot-ct');
            $cts = self::parsing($mesh, $peer, 'ot-ct', static fn(): array => self::parseCtPairs($ctRaw, $count));
            $recvPads = self::parsing($mesh, $peer, 'ot-ct', static fn(): array => MpcEndemicOt::recoverRandom($r['state'], ['ciphertexts' => $cts, 'senderPads' => []]));
        } else {
            throw new \InvalidArgumentException('unknown OT kind');
        }
        $mesh->send($peer, 'ot-verify', ['choices' => $choices, 'padHashes' => array_map(static fn(string $p): string => hash('sha256', $p), $recvPads)]);
        $d = $mesh->recv($peer, 'ot-done');
        $matched = $d instanceof Obj && $d->get('matched') === true;
        $mesh->finish();
        return ['kind' => $kind, 'role' => 'receiver', 'count' => $count, 'ms' => (microtime(true) - $t0) * 1000, 'matched' => $matched, 'padDigest' => self::digest($recvPads)];
    }
}
