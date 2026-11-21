<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers: strict
 * base64, minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the gadget seed
 * exchange. Every decoder throws \InvalidArgumentException on input that is not the canonical form.
 */
final class MpcNetCodec
{
    public static function b64(string $u): string
    {
        return base64_encode($u);
    }

    /** Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); $len < 0 means any length. */
    public static function unb64(mixed $s, int $len = -1): string
    {
        if (!is_string($s) || preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $s) !== 1) {
            throw new \InvalidArgumentException('bad base64');
        }
        $b = base64_decode($s, true);
        if ($b === false) {
            throw new \InvalidArgumentException('bad base64');
        }
        if (base64_encode($b) !== $s) {
            throw new \InvalidArgumentException('non-canonical base64');
        }
        if ($len >= 0 && strlen($b) !== $len) {
            throw new \InvalidArgumentException('bad length');
        }
        return $b;
    }

    /** @param array $p an Ed25519 point @return array{x:string,y:string} */
    public static function ptJ(array $p): array
    {
        [$x, $y] = MpcEc::toAffine($p);
        return ['x' => MpcNetWire::hx($x), 'y' => MpcNetWire::hx($y)];
    }

    /** Canonical lowercase hex without leading zeros of an element below the curve field prime. */
    public static function hexBig(mixed $s): \GMP
    {
        if (!is_string($s) || preg_match('/\A(?:0|[1-9a-f][0-9a-f]{0,63})\z/', $s) !== 1) {
            throw new \InvalidArgumentException('bad field element');
        }
        $v = gmp_init($s, 16);
        if (gmp_cmp($v, MpcEc::q()) >= 0) {
            throw new \InvalidArgumentException('non-canonical field element');
        }
        return $v;
    }

    /** A point from {x, y} canonical hex (an Obj), validated to be a non-identity prime-order-subgroup point. */
    public static function jPt(mixed $v): array
    {
        if (!$v instanceof Obj) {
            throw new \InvalidArgumentException('bad point');
        }
        $x = self::hexBig($v->get('x'));
        $y = self::hexBig($v->get('y'));
        $p = ['X' => $x, 'Y' => $y, 'Z' => gmp_init(1), 'T' => gmp_mod(gmp_mul($x, $y), MpcEc::q())];
        MpcEc::assertInSubgroup($p, 'received point');
        return $p;
    }

    public static function sharingsPerTriple(int $partners): int
    {
        return 3 + 2 * $partners;
    }

    /** Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex. */
    public static function gadgetCommit(string $sessionId, int $party, string $seed): string
    {
        return hash('sha256', 'atlas-pca-mpc/gadget-commit' . Js::utf8($sessionId) . $party . $seed);
    }

    /** The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o"). */
    public static function gadgetStatement(string $sessionId, string $round, int $signer, string $value): string
    {
        return MpcNetWire::stringify(['atlas-pca-mpc/gadget-sig/v1', $sessionId, $round, $signer, $value]);
    }
}
