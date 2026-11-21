<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
 * draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings). Signatures and generators live in G1 (48 bytes compressed),
 * public keys in G2 (96 bytes), scalars are 32 bytes big-endian. All curve work is blst's (through ext-ffi, see Bls12); the scalar
 * field is GMP arithmetic. Byte inputs are raw strings, scalars are \GMP integers, results of the verifiers are
 * ['ok' => bool, 'reason' => string] (reason only on failure). A missing libblst throws RuntimeException (fail closed).
 */
final class Bbs
{
    public const MAX_MESSAGES = 1024; // a verifier derives the message count from attacker-supplied lengths
    public const CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
    public const API_ID = self::CIPHERSUITE_ID . 'H2G_HM2S_';
    public const SCALAR_LEN = 32;
    public const POINT_LEN = 48;
    public const EXPAND_LEN = 48;
    public const H2S_DST = self::API_ID . 'H2S_';
    public const MAP_DST = self::API_ID . 'MAP_MSG_TO_SCALAR_AS_HASH_';
    public const SEED_DST = self::API_ID . 'SIG_GENERATOR_SEED_';
    public const GEN_DST = self::API_ID . 'SIG_GENERATOR_DST_';
    public const GEN_SEED = self::API_ID . 'MESSAGE_GENERATOR_SEED';
    public const KEYGEN_DST = self::API_ID . 'KEYGEN_DST_';
    /** P1: the fixed G1 generator of the ciphersuite (draft 7.2.2) */
    public const P1_HEX = 'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9';

    public const MALFORMED_SIGNATURE = 'malformed-signature';
    public const MALFORMED_PUBLIC_KEY = 'malformed-public-key';
    public const MALFORMED_PROOF = 'malformed-proof';
    public const DISCLOSED_LENGTH_MISMATCH = 'disclosed-length-mismatch';
    public const INVALID_DISCLOSED_INDEXES = 'invalid-disclosed-indexes';
    public const PAIRING_MISMATCH = 'pairing-mismatch';
    public const CHALLENGE_MISMATCH = 'challenge-mismatch';

    private static ?\FFI\CData $p1 = null;
    private static ?\FFI\CData $bp2 = null;

    private static function p1Gen(): \FFI\CData
    {
        return self::$p1 ??= Bls12::decode(1, hex2bin(self::P1_HEX));
    }

    private static function bp2(): \FFI\CData
    {
        return self::$bp2 ??= Bls12::generator(2);
    }

    /** @return array{ok:bool,reason?:string} */
    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    private static function bytesArg(mixed $v, string $what): string
    {
        if (!is_string($v)) {
            throw new \InvalidArgumentException("bbs: $what must be bytes");
        }
        return $v;
    }

    private static function i2osp(\GMP|int $n, int $len): string
    {
        return Bls12::i2osp($n, $len);
    }

    private static function expand(string $msg, string $dst, int $len): string
    {
        return Bls12::expandMessageXmd($msg, $dst, $len);
    }

    /** hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2) */
    public static function hashToScalar(mixed $msg, string $dst): \GMP
    {
        return Bls12::mod(Bls12::os2ip(self::expand(self::bytesArg($msg, 'message'), $dst, self::EXPAND_LEN)));
    }

    /** MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2) */
    public static function mapMessageToScalarAsHash(mixed $message): \GMP
    {
        return self::hashToScalar($message, self::MAP_DST);
    }

    /** @return list<\GMP> */
    private static function messagesToScalars(array $messages): array
    {
        return array_map(self::mapMessageToScalarAsHash(...), array_values($messages));
    }

    /** @return list<\FFI\CData> the G1 generators (Q_1, H_1, ..., H_{count-1}) */
    private static function gens(mixed $count): array
    {
        if (!is_int($count) || $count < 0) {
            throw new \InvalidArgumentException('bbs: generator count must be a non-negative integer');
        }
        if ($count > self::MAX_MESSAGES + 1) {
            throw new \InvalidArgumentException('bbs: at most ' . self::MAX_MESSAGES . ' messages are supported');
        }
        $v = self::expand(self::GEN_SEED, self::SEED_DST, self::EXPAND_LEN);
        $out = [];
        for ($i = 1; $i <= $count; $i++) {
            $v = self::expand($v . self::i2osp($i, 8), self::SEED_DST, self::EXPAND_LEN);
            $out[] = Bls12::hashToG1($v, self::GEN_DST);
        }
        return $out;
    }

    /** create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1) @return list<string> */
    public static function createGenerators(mixed $count): array
    {
        return array_map(static fn(\FFI\CData $g) => Bls12::compress(1, $g), self::gens($count));
    }

    // ---- key generation ----

    /** KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0. */
    public static function keyGen(mixed $keyMaterial, mixed $keyInfo = ''): \GMP
    {
        $km = self::bytesArg($keyMaterial, 'key material');
        $ki = self::bytesArg($keyInfo, 'key info');
        if (strlen($km) < 32) {
            throw new \InvalidArgumentException('bbs: key material must be at least 32 octets');
        }
        if (strlen($ki) > 65535) {
            throw new \InvalidArgumentException('bbs: key info must be at most 65535 octets');
        }
        $sk = self::hashToScalar($km . self::i2osp(strlen($ki), 2) . $ki, self::KEYGEN_DST);
        if (gmp_sign($sk) === 0) {
            throw new \RuntimeException('bbs: derived SK is zero (retry with different key material)');
        }
        return $sk;
    }

    /** SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2) */
    public static function skToPk(\GMP $sk): string
    {
        return Bls12::compress(2, Bls12::pMul(2, self::bp2(), $sk));
    }

    /**
     * A fresh key pair from the system CSPRNG; refuses an all-zero entropy source.
     *
     * @return array{sk:\GMP,pk:string}
     */
    public static function generateKeyPair(): array
    {
        $ikm = random_bytes(32);
        if ($ikm === str_repeat("\0", 32)) {
            throw new \RuntimeException('bbs: entropy source returned all zeros (RNG failure); refusing to generate a key');
        }
        $sk = self::keyGen($ikm);
        return ['sk' => $sk, 'pk' => self::skToPk($sk)];
    }

    public static function skToBytes(\GMP $sk): string
    {
        return self::i2osp($sk, self::SCALAR_LEN);
    }

    public static function skFromBytes(mixed $bytes): \GMP
    {
        if (!is_string($bytes) || strlen($bytes) !== self::SCALAR_LEN) {
            throw new \InvalidArgumentException('bbs: SK must be 32 octets');
        }
        $sk = Bls12::os2ip($bytes);
        if (gmp_sign($sk) === 0 || gmp_cmp($sk, Bls12::r()) >= 0) {
            throw new \InvalidArgumentException('bbs: SK out of range');
        }
        return $sk;
    }

    // ---- serialization (draft 4.2.4): ['p', point] compressed, ['s', n] scalars 32 octets, ['i', n] integers 8 octets ----

    private static function serialize(array $els): string
    {
        $out = '';
        foreach ($els as [$kind, $v]) {
            $out .= match ($kind) {
                'p' => Bls12::compress(1, $v),
                's' => self::i2osp($v, self::SCALAR_LEN),
                'i' => self::i2osp($v, 8),
                default => throw new \InvalidArgumentException('bbs: cannot serialize'),
            };
        }
        return $out;
    }

    // ---- signature octets ----

    private static function signatureToOctets(\FFI\CData $a, \GMP $e): string
    {
        return Bls12::compress(1, $a) . self::i2osp($e, self::SCALAR_LEN);
    }

    /** @return array{0:\FFI\CData,1:\GMP} the signature point A and scalar e */
    private static function octetsToSignature(mixed $sig): array
    {
        if (!is_string($sig) || strlen($sig) !== self::POINT_LEN + self::SCALAR_LEN) {
            throw new \InvalidArgumentException('bbs: signature must be 80 octets');
        }
        $a = Bls12::decode(1, substr($sig, 0, self::POINT_LEN));
        if (Bls12::isInf(1, $a)) {
            throw new \InvalidArgumentException('bbs: signature point A is the identity');
        }
        $e = Bls12::os2ip(substr($sig, self::POINT_LEN, self::SCALAR_LEN));
        if (gmp_sign($e) <= 0 || gmp_cmp($e, Bls12::r()) >= 0) {
            throw new \InvalidArgumentException('bbs: signature scalar e out of range');
        }
        return [$a, $e];
    }

    // ---- domain (draft 4.2.3) ----

    /** @param list<\FFI\CData> $h */
    private static function calculateDomain(string $pk, \FFI\CData $q1, array $h, string $header): \GMP
    {
        $domOcts = self::serialize([['i', count($h)], ['p', $q1], ...array_map(static fn($x) => ['p', $x], $h)]) . self::API_ID;
        return self::hashToScalar($pk . $domOcts . self::i2osp(strlen($header), 8) . $header, self::H2S_DST);
    }

    /**
     * B = P1 + Q_1*domain + sum H_i*msg_i
     *
     * @param list<\FFI\CData> $h
     * @param list<\GMP> $scalars
     */
    private static function computeB(\FFI\CData $q1, array $h, \GMP $domain, array $scalars): \FFI\CData
    {
        $b = Bls12::pAdd(1, self::p1Gen(), Bls12::pMul(1, $q1, $domain));
        foreach ($scalars as $i => $m) {
            $b = Bls12::pAdd(1, $b, Bls12::pMul(1, $h[$i], $m));
        }
        return $b;
    }

    // ---- Sign / Verify ----

    /** Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector. */
    public static function sign(\GMP $sk, mixed $pk, mixed $header, array $messages): string
    {
        if (gmp_sign($sk) <= 0 || gmp_cmp($sk, Bls12::r()) >= 0) {
            throw new \InvalidArgumentException('bbs: SK out of range');
        }
        $pk = self::bytesArg($pk, 'public key');
        $header = self::bytesArg($header, 'header');
        $ms = self::messagesToScalars($messages);
        $g = self::gens(count($ms) + 1);
        $q1 = $g[0];
        $h = array_slice($g, 1);
        $domain = self::calculateDomain($pk, $q1, $h, $header);
        $e = self::hashToScalar(self::serialize([['s', $sk], ...array_map(static fn($m) => ['s', $m], $ms), ['s', $domain]]), self::H2S_DST);
        $b = self::computeB($q1, $h, $domain, $ms);
        return self::signatureToOctets(Bls12::pMul(1, $b, Bls12::inv(gmp_add($sk, $e))), $e);
    }

    /** a decoded public key: strict G2, not the identity; null when malformed */
    private static function decodePk(mixed $pk): ?\FFI\CData
    {
        try {
            $w = Bls12::decode(2, $pk);
        } catch (\InvalidArgumentException) {
            return null;
        }
        return Bls12::isInf(2, $w) ? null : $w;
    }

    /**
     * Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input.
     *
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyDetailed(mixed $pk, mixed $signature, mixed $header, array $messages): array
    {
        try {
            [$a, $e] = self::octetsToSignature($signature);
        } catch (\InvalidArgumentException) {
            return self::fail(self::MALFORMED_SIGNATURE);
        }
        $w = self::decodePk($pk);
        if ($w === null) {
            return self::fail(self::MALFORMED_PUBLIC_KEY);
        }
        if (count($messages) > self::MAX_MESSAGES) {
            return self::fail(self::DISCLOSED_LENGTH_MISMATCH);
        }
        $header = self::bytesArg($header, 'header');
        $ms = self::messagesToScalars($messages);
        $g = self::gens(count($ms) + 1);
        $q1 = $g[0];
        $h = array_slice($g, 1);
        $domain = self::calculateDomain($pk, $q1, $h, $header);
        $b = self::computeB($q1, $h, $domain, $ms);
        // e(A, W + BP2*e) == e(B, BP2)
        return Bls12::pairingEq($a, Bls12::pAdd(2, $w, Bls12::pMul(2, self::bp2(), $e)), $b, self::bp2()) ? ['ok' => true] : self::fail(self::PAIRING_MISMATCH);
    }

    public static function verify(mixed $pk, mixed $signature, mixed $header, array $messages): bool
    {
        return self::verifyDetailed($pk, $signature, $header, $messages)['ok'];
    }

    // ---- challenge (draft 3.7.4) ----

    /**
     * @param list<int> $idx
     * @param list<\GMP> $msgs
     */
    private static function calculateChallenge(\FFI\CData $abar, \FFI\CData $bbar, \FFI\CData $d, \FFI\CData $t1, \FFI\CData $t2, array $idx, array $msgs, \GMP $domain, string $ph): \GMP
    {
        $els = [['i', count($idx)]];
        foreach ($idx as $k => $ix) {
            $els[] = ['i', $ix];
            $els[] = ['s', $msgs[$k]];
        }
        array_push($els, ['p', $abar], ['p', $bbar], ['p', $d], ['p', $t1], ['p', $t2], ['s', $domain]);
        return self::hashToScalar(self::serialize($els) . self::i2osp(strlen($ph), 8) . $ph, self::H2S_DST);
    }

    // ---- proof octets ----

    /** @param list<\GMP> $mHat */
    private static function proofToOctets(\FFI\CData $abar, \FFI\CData $bbar, \FFI\CData $d, \GMP $eHat, \GMP $r1Hat, \GMP $r3Hat, array $mHat, \GMP $c): string
    {
        $out = Bls12::compress(1, $abar) . Bls12::compress(1, $bbar) . Bls12::compress(1, $d)
            . self::i2osp($eHat, self::SCALAR_LEN) . self::i2osp($r1Hat, self::SCALAR_LEN) . self::i2osp($r3Hat, self::SCALAR_LEN);
        foreach ($mHat as $m) {
            $out .= self::i2osp($m, self::SCALAR_LEN);
        }
        return $out . self::i2osp($c, self::SCALAR_LEN);
    }

    private static function readScalar(string $proof, int $offset): \GMP
    {
        $v = Bls12::os2ip(substr($proof, $offset, self::SCALAR_LEN));
        if (gmp_cmp($v, Bls12::r()) >= 0) {
            throw new \InvalidArgumentException('bbs: proof scalar out of range');
        }
        return $v;
    }

    /** @return array{abar:\FFI\CData,bbar:\FFI\CData,d:\FFI\CData,eHat:\GMP,r1Hat:\GMP,r3Hat:\GMP,mHat:list<\GMP>,c:\GMP} */
    private static function octetsToProof(mixed $proof): array
    {
        if (!is_string($proof)) {
            throw new \InvalidArgumentException('bbs: malformed proof');
        }
        $fixed = 3 * self::POINT_LEN + 4 * self::SCALAR_LEN;
        if (strlen($proof) < $fixed || (strlen($proof) - $fixed) % self::SCALAR_LEN !== 0) {
            throw new \InvalidArgumentException('bbs: malformed proof length');
        }
        $abar = Bls12::decode(1, substr($proof, 0, self::POINT_LEN));
        $bbar = Bls12::decode(1, substr($proof, self::POINT_LEN, self::POINT_LEN));
        $d = Bls12::decode(1, substr($proof, 2 * self::POINT_LEN, self::POINT_LEN));
        $o = 3 * self::POINT_LEN;
        $eHat = self::readScalar($proof, $o);
        $r1Hat = self::readScalar($proof, $o + self::SCALAR_LEN);
        $r3Hat = self::readScalar($proof, $o + 2 * self::SCALAR_LEN);
        $o += 3 * self::SCALAR_LEN;
        $u = intdiv(strlen($proof) - $fixed, self::SCALAR_LEN);
        $mHat = [];
        for ($i = 0; $i < $u; $i++) {
            $mHat[] = self::readScalar($proof, $o + $i * self::SCALAR_LEN);
        }
        $c = self::readScalar($proof, $o + $u * self::SCALAR_LEN);
        if (Bls12::isInf(1, $abar) || Bls12::isInf(1, $bbar) || Bls12::isInf(1, $d)) {
            throw new \InvalidArgumentException('bbs: proof contains the identity point');
        }
        return ['abar' => $abar, 'bbar' => $bbar, 'd' => $d, 'eHat' => $eHat, 'r1Hat' => $r1Hat, 'r3Hat' => $r3Hat, 'mHat' => $mHat, 'c' => $c];
    }

    // ---- index-set helpers ----

    private static function validateIndexes(array $indexes, int $l): void
    {
        $seen = [];
        foreach ($indexes as $i) {
            if (!is_int($i) || $i < 0 || $i >= $l) {
                throw new \InvalidArgumentException('bbs: disclosed index ' . (is_int($i) ? $i : gettype($i)) . " out of range [0, $l)");
            }
            if (isset($seen[$i])) {
                throw new \InvalidArgumentException("bbs: duplicate disclosed index $i");
            }
            $seen[$i] = true;
        }
    }

    /** @return list<int> */
    private static function undisclosedAscending(array $disclosed, int $l): array
    {
        $set = array_flip($disclosed);
        $out = [];
        for ($i = 0; $i < $l; $i++) {
            if (!isset($set[$i])) {
                $out[] = $i;
            }
        }
        return $out;
    }

    // ---- ProofGen ----

    /**
     * ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
     * discloses the messages at the given indexes. $fixedRandomScalars (5 + undisclosed count \GMP scalars) pins the randomness for
     * test vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability.
     *
     * @param list<int> $disclosedIndexes
     * @param list<\GMP>|null $fixedRandomScalars
     */
    public static function proofGen(mixed $pk, mixed $signature, mixed $header, mixed $ph, array $messages, array $disclosedIndexes, ?array $fixedRandomScalars = null): string
    {
        $pk = self::bytesArg($pk, 'public key');
        $header = self::bytesArg($header, 'header');
        $ph = self::bytesArg($ph, 'presentation header');
        [$a, $e] = self::octetsToSignature($signature);
        $ms = self::messagesToScalars($messages);
        $l = count($ms);
        self::validateIndexes($disclosedIndexes, $l);
        $disclosed = array_values(array_unique($disclosedIndexes));
        sort($disclosed);
        $undisclosed = self::undisclosedAscending($disclosed, $l);
        $u = count($undisclosed);

        $g = self::gens($l + 1);
        $q1 = $g[0];
        $h = array_slice($g, 1);
        $domain = self::calculateDomain($pk, $q1, $h, $header);
        $b = self::computeB($q1, $h, $domain, $ms);

        if ($fixedRandomScalars !== null) {
            $rs = array_values($fixedRandomScalars);
        } else {
            $rs = [];
            for ($i = 0; $i < 5 + $u; $i++) {
                $rs[] = Bls12::mod(Bls12::os2ip(random_bytes(self::EXPAND_LEN)));
            }
        }
        if (count($rs) !== 5 + $u) {
            throw new \InvalidArgumentException('bbs: expected ' . (5 + $u) . ' random scalars, got ' . count($rs));
        }
        if (gmp_sign($rs[0]) === 0 || gmp_sign($rs[1]) === 0) {
            throw new \InvalidArgumentException('bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)');
        }
        [$r1, $r2, $eTilde, $r1Tilde, $r3Tilde] = array_slice($rs, 0, 5);
        $mTilde = array_slice($rs, 5);

        $d = Bls12::pMul(1, $b, $r2);
        $abar = Bls12::pMul(1, $a, Bls12::mul($r1, $r2));
        $bbar = Bls12::pSub(1, Bls12::pMul(1, $d, $r1), Bls12::pMul(1, $abar, $e));
        $t1 = Bls12::pAdd(1, Bls12::pMul(1, $abar, $eTilde), Bls12::pMul(1, $d, $r1Tilde));
        $t2 = Bls12::pMul(1, $d, $r3Tilde);
        foreach ($undisclosed as $k => $ix) {
            $t2 = Bls12::pAdd(1, $t2, Bls12::pMul(1, $h[$ix], $mTilde[$k]));
        }

        $c = self::calculateChallenge($abar, $bbar, $d, $t1, $t2, $disclosed, array_map(static fn(int $i) => $ms[$i], $disclosed), $domain, $ph);

        $r3 = Bls12::inv($r2);
        $eHat = Bls12::add($eTilde, Bls12::mul($e, $c));
        $r1Hat = Bls12::sub($r1Tilde, Bls12::mul($r1, $c));
        $r3Hat = Bls12::sub($r3Tilde, Bls12::mul($r3, $c));
        $mHat = [];
        foreach ($undisclosed as $k => $ix) {
            $mHat[] = Bls12::add($mTilde[$k], Bls12::mul($ms[$ix], $c));
        }
        return self::proofToOctets($abar, $bbar, $d, $eHat, $r1Hat, $r3Hat, $mHat, $c);
    }

    // ---- ProofVerify ----

    /**
     * ProofVerify with a rejection reason. $disclosedMessages[k] corresponds to $disclosedIndexes[k].
     *
     * @param list<int> $disclosedIndexes
     * @return array{ok:bool,reason?:string}
     */
    public static function proofVerifyDetailed(mixed $pk, mixed $proof, mixed $header, mixed $ph, array $disclosedMessages, array $disclosedIndexes): array
    {
        try {
            $p = self::octetsToProof($proof);
        } catch (\InvalidArgumentException) {
            return self::fail(self::MALFORMED_PROOF);
        }
        $w = self::decodePk($pk);
        if ($w === null) {
            return self::fail(self::MALFORMED_PUBLIC_KEY);
        }
        if (count($disclosedMessages) !== count($disclosedIndexes)) {
            return self::fail(self::DISCLOSED_LENGTH_MISMATCH);
        }
        $header = self::bytesArg($header, 'header');
        $ph = self::bytesArg($ph, 'presentation header');
        $u = count($p['mHat']);
        $l = count($disclosedIndexes) + $u;
        if ($l > self::MAX_MESSAGES) {
            return self::fail(self::MALFORMED_PROOF);
        }
        try {
            self::validateIndexes($disclosedIndexes, $l);
            $scalars = self::messagesToScalars($disclosedMessages);
        } catch (\InvalidArgumentException) {
            return self::fail(self::INVALID_DISCLOSED_INDEXES);
        }
        $order = [];
        foreach (array_values($disclosedIndexes) as $k => $ix) {
            $order[] = [$ix, $k];
        }
        usort($order, static fn(array $x, array $y) => [$x[0], $x[1]] <=> [$y[0], $y[1]]);
        $undisclosed = self::undisclosedAscending($disclosedIndexes, $l);

        $g = self::gens($l + 1);
        $q1 = $g[0];
        $h = array_slice($g, 1);
        $domain = self::calculateDomain($pk, $q1, $h, $header);

        $t1 = Bls12::pAdd(1, Bls12::pAdd(1, Bls12::pMul(1, $p['bbar'], $p['c']), Bls12::pMul(1, $p['abar'], $p['eHat'])), Bls12::pMul(1, $p['d'], $p['r1Hat']));
        $bv = Bls12::pAdd(1, self::p1Gen(), Bls12::pMul(1, $q1, $domain));
        $sortedIdx = [];
        $sortedMsgs = [];
        foreach ($order as [$ix, $k]) {
            $sortedIdx[] = $ix;
            $sortedMsgs[] = $scalars[$k];
            $bv = Bls12::pAdd(1, $bv, Bls12::pMul(1, $h[$ix], $scalars[$k]));
        }
        $t2 = Bls12::pAdd(1, Bls12::pMul(1, $bv, $p['c']), Bls12::pMul(1, $p['d'], $p['r3Hat']));
        foreach ($undisclosed as $k => $ix) {
            $t2 = Bls12::pAdd(1, $t2, Bls12::pMul(1, $h[$ix], $p['mHat'][$k]));
        }

        $cv = self::calculateChallenge($p['abar'], $p['bbar'], $p['d'], $t1, $t2, $sortedIdx, $sortedMsgs, $domain, $ph);
        if (gmp_cmp($cv, $p['c']) !== 0) {
            return self::fail(self::CHALLENGE_MISMATCH);
        }
        return Bls12::pairingEq($p['abar'], $w, $p['bbar'], self::bp2()) ? ['ok' => true] : self::fail(self::PAIRING_MISMATCH);
    }

    /** @param list<int> $disclosedIndexes */
    public static function proofVerify(mixed $pk, mixed $proof, mixed $header, mixed $ph, array $disclosedMessages, array $disclosedIndexes): bool
    {
        return self::proofVerifyDetailed($pk, $proof, $header, $ph, $disclosedMessages, $disclosedIndexes)['ok'];
    }
}
