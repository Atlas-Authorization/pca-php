<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Ed25519Core.php';

/** A signer's secret nonce pair for one session; frozen (zeroed) by Frost::sign. */
final class FrostNonces
{
    public function __construct(public string $hiding, public string $binding)
    {
    }
}

/**
 * FROST threshold signatures for Ed25519 (RFC 9591, FROST(Ed25519, SHA-512)): trusted-dealer key split, round 1 (commit), round 2
 * (sign), aggregation into one ordinary 64-byte Ed25519 signature under the group key, and the per-share check. All group and scalar
 * arithmetic is libsodium's (libsodium through Ed25519Core): nothing here is a
 * hand-rolled primitive. Every point a caller can influence goes through decodeSafePoint (canonical, on the curve, not small order,
 * prime-order subgroup). Identifiers are positive safe integers. Nonces are one-shot: zeroed after use, and a byte-clone is refused by
 * its public commitment (per process; callers must not persist nonces).
 *
 * Shapes: a participant share is ['identifier' => int, 'share' => bytes, 'publicKey' => bytes]; a commitment ['identifier', 'hiding',
 * 'binding']; a signature share ['identifier', 'sigShare']; a verification share ['identifier', 'publicKey']. Scalars and points are
 * 32-byte strings (little-endian scalars, canonical).
 * shortcut: secrets are ordinary PHP strings (no constant-time or zeroisation beyond the nonce wipe); use an enclave when that matters.
 */
final class Frost
{
    private const CTX = 'FROST-ED25519-SHA512-v1';
    private const MAX_ID = 9007199254740991;
    public const SPENT_COMMITMENT_CAP = 262144;
    private const L = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

    /** @var array<string,true> insertion-ordered set of spent commitment keys */
    private static array $spent = [];

    private static function identity(): string
    {
        return "\x01" . str_repeat("\0", 31);
    }

    private static function zero(): string
    {
        return str_repeat("\0", 32);
    }

    // ---- scalars (32-byte little endian, always canonical) -------------------------------------------------------------------------

    private static function isZero(string $b): bool
    {
        return hash_equals(str_repeat("\0", strlen($b)), $b);
    }

    public static function sAdd(string $a, string $b): string
    {
        return Ed25519Core::scalarAdd($a, $b);
    }

    private static function sSub(string $a, string $b): string
    {
        return Ed25519Core::scalarSub($a, $b);
    }

    public static function sMul(string $a, string $b): string
    {
        return Ed25519Core::scalarMul($a, $b);
    }

    private static function sInv(string $a): string
    {
        if (self::isZero($a)) {
            throw new \InvalidArgumentException('frost: modular inverse of zero');
        }
        return Ed25519Core::scalarInvert($a);
    }

    /** 0..64 little-endian bytes reduced mod L (65 or more is refused). */
    public static function bytesToScalar(mixed $b): string
    {
        if (!is_string($b)) {
            throw new \TypeError('frost: expected bytes');
        }
        if (strlen($b) > 64) {
            throw new \InvalidArgumentException('frost: scalar input longer than 64 bytes');
        }
        if ($b === '') {
            return self::zero();
        }
        return Ed25519Core::scalarReduce(str_pad($b, 64, "\0"));
    }

    public static function scalarOfId(int $id): string
    {
        return pack('P', $id) . str_repeat("\0", 24);
    }

    /** True iff `$b` is exactly 32 bytes encoding a scalar < L. */
    public static function isCanonicalScalar(mixed $b): bool
    {
        if (!is_string($b) || strlen($b) !== 32) {
            return false;
        }
        for ($i = 31; $i >= 0; $i--) {
            $x = ord($b[$i]);
            if ($x !== self::L[$i]) {
                return $x < self::L[$i];
            }
        }
        return false;
    }

    // ---- points (32-byte encodings; the identity is "\x01\0..\0") ----------------------------------------------------------------------

    public static function mulBase(string $s): string
    {
        if (self::isZero($s)) {
            return self::identity();
        }
        try {
            return Ed25519Core::mulBaseNoclamp($s);
        } catch (\SodiumException) {
            return self::identity();
        }
    }

    public static function mulPoint(string $p, string $s): string
    {
        if (self::isZero($s) || $p === self::identity()) {
            return self::identity();
        }
        try {
            return Ed25519Core::mulNoclamp($s, $p);
        } catch (\SodiumException) {
            throw new \RuntimeException('frost: point multiplication refused');
        }
    }

    public static function add(string $a, string $b): string
    {
        if ($a === self::identity()) {
            return $b;
        }
        if ($b === self::identity()) {
            return $a;
        }
        try {
            return Ed25519Core::add($a, $b);
        } catch (\SodiumException) {
            throw new \RuntimeException('frost: point addition refused');
        }
    }

    /** Strict point decode: 32 bytes, canonical, on the curve, not small order (so not the identity), in the prime-order subgroup. */
    public static function decodeSafePoint(mixed $b): string
    {
        if (!is_string($b) || strlen($b) !== 32) {
            throw new \InvalidArgumentException('frost: point must be 32 bytes');
        }
        if (!Ed25519Core::isValidPoint($b)) {
            throw new \InvalidArgumentException('frost: point rejected (non-canonical, off-curve, small-order or not in the prime-order subgroup)');
        }
        return $b;
    }

    // ---- ciphersuite hashes (RFC 9591 section 6.1) ---------------------------------------------------------------------------------------

    private static function hashToScalar(string $m): string
    {
        return self::bytesToScalar(hash('sha512', $m, true));
    }

    public static function h1(string $m): string
    {
        return self::hashToScalar(self::CTX . 'rho' . $m);
    }

    public static function h2(string $m): string
    {
        return self::hashToScalar($m);
    }

    public static function h3(string $m): string
    {
        return self::hashToScalar(self::CTX . 'nonce' . $m);
    }

    public static function h4(string $m): string
    {
        return hash('sha512', self::CTX . 'msg' . $m, true);
    }

    public static function h5(string $m): string
    {
        return hash('sha512', self::CTX . 'com' . $m, true);
    }

    private static function assertValidId(mixed $id): int
    {
        if (!is_int($id) || $id <= 0 || $id > self::MAX_ID) {
            throw new \InvalidArgumentException('frost: participant identifier must be a positive safe integer');
        }
        return $id;
    }

    /** A threshold JS number: a safe integer >= 1, else a refusal (null = absent). */
    private static function thresholdValue(mixed $t): ?int
    {
        if ($t === null) {
            return null;
        }
        if ($t instanceof Num) {
            $t = $t->isInt() ? $t->int() : $t->float();
        }
        if (is_float($t) && is_finite($t) && $t == floor($t) && abs($t) <= self::MAX_ID) {
            $t = (int)$t;
        }
        if (!is_int($t) || $t < 1 || $t > self::MAX_ID) {
            throw new \InvalidArgumentException('frost: invalid threshold');
        }
        return $t;
    }

    /** @param list<array{identifier:int,hiding:string,binding:string}> $list */
    private static function validateCommitments(array $list, mixed $threshold = null): void
    {
        if ($list === []) {
            throw new \InvalidArgumentException('frost: empty commitment list');
        }
        $t = self::thresholdValue($threshold);
        if ($t !== null && count($list) < $t) {
            throw new \InvalidArgumentException("frost: need at least t=$t commitments (got " . count($list) . ')');
        }
        $seen = [];
        foreach ($list as $c) {
            $id = self::assertValidId($c['identifier']);
            if (isset($seen[$id])) {
                throw new \InvalidArgumentException("frost: duplicate commitment identifier $id");
            }
            $seen[$id] = true;
            self::decodeSafePoint($c['hiding']);
            self::decodeSafePoint($c['binding']);
        }
    }

    // ---- key generation ----------------------------------------------------------------------------------------------------------------------

    public static function randomScalar(): string
    {
        return self::bytesToScalar(random_bytes(32));
    }

    /**
     * Trusted-dealer t-of-n split: f(x) = a0 + a1 x + ..., share_i = f(i), group key = a0*B. `$secret` / `$coefficients` fix the polynomial.
     * @param ?list<string> $coefficients @param ?list<int> $identifiers
     * @return array{groupPublicKey:string,participantShares:list<array{identifier:int,share:string,publicKey:string}>,groupCommitment:list<string>}
     */
    public static function trustedDealerKeygen(int $t, int $n, ?string $secret = null, ?array $coefficients = null, ?array $identifiers = null): array
    {
        if ($t < 1 || $n < $t || $n > 100000) {
            throw new \InvalidArgumentException("frostTrustedDealerKeygen: need 1 <= t <= n (got t=$t, n=$n)");
        }
        $ids = $identifiers ?? range(1, $n);
        if (count($ids) !== $n) {
            throw new \InvalidArgumentException('frostTrustedDealerKeygen: identifiers.length must equal n');
        }
        if (count(array_unique($ids)) !== count($ids)) {
            throw new \InvalidArgumentException('frostTrustedDealerKeygen: identifiers must be distinct');
        }
        foreach ($ids as $id) {
            if (!is_int($id) || $id <= 0 || $id > self::MAX_ID) {
                throw new \InvalidArgumentException('frostTrustedDealerKeygen: identifiers must be positive integers');
            }
        }
        $coeffs = [$secret !== null ? self::bytesToScalar($secret) : self::randomScalar()];
        for ($i = 1; $i < $t; $i++) {
            $coeffs[] = $coefficients !== null && $i - 1 < count($coefficients) ? self::bytesToScalar($coefficients[$i - 1]) : self::randomScalar();
        }
        $shares = [];
        foreach ($ids as $id) {
            $x = self::scalarOfId($id);
            $acc = self::zero();
            foreach (array_reverse($coeffs) as $a) {
                $acc = self::sAdd(self::sMul($acc, $x), $a);
            }
            $shares[] = ['identifier' => $id, 'share' => $acc, 'publicKey' => self::mulBase($acc)];
        }
        $gc = array_map(self::mulBase(...), $coeffs);
        return ['groupPublicKey' => $gc[0], 'participantShares' => $shares, 'groupCommitment' => $gc];
    }

    /** The verification share of a secret signing share: share*B (a raw scalar, not a clamped Ed25519 secret). */
    public static function verifyingShare(mixed $share): string
    {
        return self::mulBase(self::bytesToScalar($share));
    }

    // ---- round 1 ----------------------------------------------------------------------------------------------------------------------------------

    private static function nonceGenerate(mixed $randomness, string $secretShare): string
    {
        if (!is_string($randomness) || strlen($randomness) !== 32) {
            throw new \InvalidArgumentException('frostCommit: nonce randomness must be 32 bytes');
        }
        return self::h3($randomness . self::bytesToScalar($secretShare));
    }

    /**
     * @param array{identifier:int,share:string} $p
     * @return array{hidingNonce:string,bindingNonce:string,commitment:array{identifier:int,hiding:string,binding:string}}
     */
    public static function commit(array $p, mixed $hidingRandomness = null, mixed $bindingRandomness = null): array
    {
        $hr = $hidingRandomness ?? self::randomScalar();
        $br = $bindingRandomness ?? self::randomScalar();
        $h = self::nonceGenerate($hr, $p['share']);
        $b = self::nonceGenerate($br, $p['share']);
        return ['hidingNonce' => $h, 'bindingNonce' => $b, 'commitment' => ['identifier' => $p['identifier'], 'hiding' => self::mulBase($h), 'binding' => self::mulBase($b)]];
    }

    // ---- binding factors, group commitment, challenge ---------------------------------------------------------------------------------------------------

    private static function sorted(array $l): array
    {
        usort($l, static fn(array $a, array $b): int => $a['identifier'] <=> $b['identifier']);
        return $l;
    }

    /** @return array<int,string> */
    private static function bindingFactors(string $group, array $list, string $msg): array
    {
        $enc = '';
        foreach ($list as $c) {
            $enc .= self::scalarOfId($c['identifier']) . $c['hiding'] . $c['binding'];
        }
        $prefix = $group . self::h4($msg) . self::h5($enc);
        $out = [];
        foreach ($list as $c) {
            $out[$c['identifier']] = self::h1($prefix . self::scalarOfId($c['identifier']));
        }
        return $out;
    }

    private static function groupCommitment(array $list, array $bf): string
    {
        $r = self::identity();
        foreach ($list as $c) {
            if (!isset($bf[$c['identifier']])) {
                throw new \RuntimeException('frost: missing binding factor');
            }
            $r = self::add(self::add($r, self::decodeSafePoint($c['hiding'])), self::mulPoint(self::decodeSafePoint($c['binding']), $bf[$c['identifier']]));
        }
        return $r;
    }

    /** @param list<int> $participants */
    private static function interpolatingValue(array $participants, int $i): string
    {
        if (!in_array($i, $participants, true)) {
            throw new \InvalidArgumentException('frost: identifier not in participant list');
        }
        $num = self::scalarOfId(1);
        $den = self::scalarOfId(1);
        $xi = self::scalarOfId($i);
        foreach ($participants as $j) {
            if ($j !== $i) {
                $xj = self::scalarOfId($j);
                $num = self::sMul($num, $xj);
                $den = self::sMul($den, self::sSub($xj, $xi));
            }
        }
        $lam = self::sMul($num, self::sInv($den));
        if (self::isZero($lam)) {
            throw new \InvalidArgumentException('frost: zero Lagrange coefficient');
        }
        return $lam;
    }

    // ---- round 2 ---------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * One-shot signing share z_i = hiding + binding*bf + lambda*share*c. The nonces are zeroed afterwards and their commitments recorded.
     * `$opts`: threshold, verificationShare (bytes), verificationShares (list of ['identifier','publicKey']).
     * @param list<array{identifier:int,hiding:string,binding:string}> $signingCommitments
     * @return array{identifier:int,sigShare:string}
     */
    public static function sign(mixed $identifier, mixed $share, mixed $groupPublicKey, ?FrostNonces $nonces, mixed $message, array $signingCommitments, array $opts = []): array
    {
        $identifier = self::assertValidId($identifier);
        self::validateCommitments($signingCommitments, $opts['threshold'] ?? null);
        self::decodeSafePoint($groupPublicKey);
        if (!is_string($share) || !is_string($message)) {
            throw new \TypeError('frost: expected bytes');
        }
        if ($nonces === null) {
            throw new \InvalidArgumentException('frostSign: malformed nonces');
        }
        if (self::isZero($nonces->hiding) || self::isZero($nonces->binding)) {
            throw new \InvalidArgumentException('frostSign: zero/zeroized nonce (one-shot; reuse would leak the signing share)');
        }
        if ($nonces->hiding === $nonces->binding) {
            throw new \InvalidArgumentException('frostSign: hiding and binding nonce must differ');
        }
        $list = self::sorted($signingCommitments);
        $mine = null;
        foreach ($list as $c) {
            if ($c['identifier'] === $identifier) {
                $mine = $c;
                break;
            }
        }
        if ($mine === null) {
            throw new \InvalidArgumentException('frostSign: this identifier has no commitment in the set');
        }
        $hiding = self::bytesToScalar($nonces->hiding);
        $binding = self::bytesToScalar($nonces->binding);
        $sk = self::bytesToScalar($share);
        if (self::mulBase($hiding) !== self::decodeSafePoint($mine['hiding']) || self::mulBase($binding) !== self::decodeSafePoint($mine['binding'])) {
            throw new \InvalidArgumentException('frostSign: own commitment does not match nonces');
        }
        $hKey = 'h' . bin2hex($mine['hiding']);
        $bKey = 'b' . bin2hex($mine['binding']);
        if (isset(self::$spent[$hKey]) || isset(self::$spent[$bKey])) {
            throw new \InvalidArgumentException('frostSign: nonces already used (one-shot; reuse would leak the signing share)');
        }
        if (isset($opts['verificationShare']) && self::mulBase($sk) !== self::decodeSafePoint($opts['verificationShare'])) {
            throw new \InvalidArgumentException('frostSign: share does not match verification share');
        }
        $participants = array_map(static fn(array $c): int => $c['identifier'], $list);
        if (isset($opts['verificationShares'])) {
            $acc = self::identity();
            foreach ($participants as $id) {
                $vs = null;
                foreach ($opts['verificationShares'] as $v) {
                    if ($v['identifier'] === $id) {
                        $vs = $v;
                        break;
                    }
                }
                if ($vs === null) {
                    throw new \InvalidArgumentException("frostSign: missing verification share for $id");
                }
                $acc = self::add($acc, self::mulPoint(self::decodeSafePoint($vs['publicKey']), self::interpolatingValue($participants, $id)));
            }
            if ($acc !== self::decodeSafePoint($groupPublicKey)) {
                throw new \InvalidArgumentException('frostSign: group public key does not match the verification shares');
            }
        }
        $bfs = self::bindingFactors($groupPublicKey, $list, $message);
        if (!isset($bfs[$identifier])) {
            throw new \RuntimeException('frost: missing binding factor');
        }
        $r = self::groupCommitment($list, $bfs);
        $lambda = self::interpolatingValue($participants, $identifier);
        $c = self::h2($r . $groupPublicKey . $message);
        $z = self::sAdd(self::sAdd($hiding, self::sMul($binding, $bfs[$identifier])), self::sMul(self::sMul($lambda, $sk), $c));
        foreach ([$hKey, $bKey] as $k) {
            self::$spent[$k] = true;
            if (count(self::$spent) > self::SPENT_COMMITMENT_CAP) {
                unset(self::$spent[array_key_first(self::$spent)]);
            }
        }
        $nonces->hiding = str_repeat("\0", strlen($nonces->hiding));
        $nonces->binding = str_repeat("\0", strlen($nonces->binding));
        return ['identifier' => $identifier, 'sigShare' => $z];
    }

    // ---- aggregation / share check ----------------------------------------------------------------------------------------------------------------------------

    /** Check one signature share: z_i*B == (hiding_i + bf_i*binding_i) + (c*lambda_i)*PK_i. Never throws; any malformed input is false. */
    public static function verifySigShare(mixed $identifier, mixed $publicKey, mixed $commitment, mixed $sigShare, mixed $signingCommitments, mixed $groupPublicKey, mixed $message): bool
    {
        try {
            if (!is_array($signingCommitments) || !is_string($groupPublicKey) || !is_string($message) || !is_int($identifier)) {
                return false;
            }
            self::validateCommitments($signingCommitments);
            $list = self::sorted($signingCommitments);
            $bfs = self::bindingFactors($groupPublicKey, $list, $message);
            if (!isset($bfs[$identifier])) {
                return false;
            }
            $r = self::groupCommitment($list, $bfs);
            $commShare = self::add(self::decodeSafePoint($commitment['hiding']), self::mulPoint(self::decodeSafePoint($commitment['binding']), $bfs[$identifier]));
            $c = self::h2($r . $groupPublicKey . $message);
            $lambda = self::interpolatingValue(array_map(static fn(array $x): int => $x['identifier'], $list), $identifier);
            if (!self::isCanonicalScalar($sigShare['sigShare'])) {
                return false;
            }
            $lhs = self::mulBase(self::bytesToScalar($sigShare['sigShare']));
            $rhs = self::add($commShare, self::mulPoint(self::decodeSafePoint($publicKey), self::sMul($c, $lambda)));
            return $lhs === $rhs;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Aggregate verified signature shares into a standard Ed25519 signature R || z. `$verificationShares` is required: every share is
     * verified first, and the result is verified under the group key before it is returned.
     * @return string 64 bytes
     */
    public static function aggregate(mixed $message, array $signingCommitments, array $sigShares, mixed $groupPublicKey, mixed $threshold = null, ?array $verificationShares = null): string
    {
        if (!is_string($message)) {
            throw new \TypeError('frost: expected bytes');
        }
        self::validateCommitments($signingCommitments, $threshold);
        self::decodeSafePoint($groupPublicKey);
        $list = self::sorted($signingCommitments);
        if (count($sigShares) !== count($list)) {
            throw new \InvalidArgumentException('frostAggregate: need exactly one signature share per commitment');
        }
        $ids = [];
        foreach ($sigShares as $s) {
            $found = false;
            foreach ($list as $c) {
                $found = $found || $c['identifier'] === $s['identifier'];
            }
            if (!$found) {
                throw new \InvalidArgumentException('frostAggregate: share from non-signer');
            }
            if (isset($ids[$s['identifier']])) {
                throw new \InvalidArgumentException('frostAggregate: duplicate signature share');
            }
            $ids[$s['identifier']] = true;
        }
        if ($verificationShares === null) {
            throw new \InvalidArgumentException('frostAggregate: verificationShares are required (every signature share is verified before aggregation)');
        }
        foreach ($sigShares as $s) {
            $vs = null;
            $cm = null;
            foreach ($verificationShares as $v) {
                $vs ??= $v['identifier'] === $s['identifier'] ? $v : null;
            }
            foreach ($list as $c) {
                $cm ??= $c['identifier'] === $s['identifier'] ? $c : null;
            }
            if ($vs === null || $cm === null || !self::verifySigShare($s['identifier'], $vs['publicKey'], $cm, $s, $list, $groupPublicKey, $message)) {
                throw new \InvalidArgumentException("frostAggregate: invalid signature share from participant {$s['identifier']}");
            }
        }
        $r = self::groupCommitment($list, self::bindingFactors($groupPublicKey, $list, $message));
        $z = self::zero();
        foreach ($sigShares as $s) {
            $z = self::sAdd($z, self::bytesToScalar($s['sigShare']));
        }
        $sig = $r . $z;
        if (!sodium_crypto_sign_verify_detached($sig, $message, $groupPublicKey)) {
            throw new \InvalidArgumentException('frostAggregate: aggregate signature does not verify (a share is invalid)');
        }
        return $sig;
    }

    /**
     * One-shot in-process coordinator over a quorum: commit, sign (every safety check on), aggregate (re-verified).
     * @param list<array{identifier:int,share:string,publicKey:string}> $quorum
     */
    public static function cosign(mixed $groupPublicKey, array $quorum, mixed $message, mixed $threshold = null): string
    {
        if ($quorum === []) {
            throw new \InvalidArgumentException('frostCosign: empty signing quorum');
        }
        $t = self::thresholdValue($threshold);
        if ($t !== null && count($quorum) < $t) {
            throw new \InvalidArgumentException('frostCosign: quorum of ' . count($quorum) . " is below the threshold t=$t");
        }
        $ids = [];
        foreach ($quorum as $p) {
            $id = self::assertValidId($p['identifier']);
            if (isset($ids[$id])) {
                throw new \InvalidArgumentException("frostCosign: duplicate participant $id in quorum");
            }
            $ids[$id] = true;
        }
        $vss = array_map(static fn(array $p): array => ['identifier' => $p['identifier'], 'publicKey' => $p['publicKey']], $quorum);
        $commits = array_map(static fn(array $p): array => self::commit($p), $quorum);
        $cs = array_map(static fn(array $c): array => $c['commitment'], $commits);
        $shares = [];
        foreach ($quorum as $i => $p) {
            $shares[] = self::sign($p['identifier'], $p['share'], $groupPublicKey, new FrostNonces($commits[$i]['hidingNonce'], $commits[$i]['bindingNonce']), $message, $cs,
                ['threshold' => $threshold, 'verificationShare' => $p['publicKey'], 'verificationShares' => $vss]);
        }
        return self::aggregate($message, $cs, $shares, $groupPublicKey, $threshold, $vss);
    }
}
