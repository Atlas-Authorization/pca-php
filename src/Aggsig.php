<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';

/**
 * BLS12-381 signature aggregation (IETF proof-of-possession ciphersuite), a rogue-key-safe key registry, the aggregated BLS capability
 * chain and aggregated witness cosignatures (the reference's pca-aggsig). Backend: blst (supranational/blst, constant time, audited)
 * through ext-ffi, bound lazily; no library means every call throws (fail closed). Build blst as a shared library and name it with
 * PCA_BLST_LIB (or put libblst.so / libblst.dylib on the loader path). Public keys sit in G1 (48 bytes), signatures in G2 (96 bytes);
 * keys, signatures and messages are raw byte strings. Never hand-rolled curve arithmetic: every point operation is a blst call.
 */
final class Aggsig
{
    public const SIG_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';
    public const POP_DST = 'BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';
    public const PUBLIC_KEY_LENGTH = 48;
    public const SIGNATURE_LENGTH = 96;
    public const SECRET_KEY_LENGTH = 32;
    public const BLS_SUITE = 'bls12-381-pop';
    public const MAX_CHAIN_DEPTH = 16;
    public const R_HEX = '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';
    public const CAP_BLS_DOMAIN = "atlas-pca/cap-bls/v1\0";
    public const STH_WITNESS_BLS_DOMAIN = "atlas-pca/sth-witness-bls/v1\0";
    private const P1 = 144; // sizeof(blst_p1); the affine form is 96, blst_p2 is 288 (affine 192), a scalar 32
    private const P1A = 96;
    private const P2 = 288;
    private const P2A = 192;

    private static ?\FFI $ffi = null;
    /** @var array<string,bool> */
    private static array $kv = [];

    private static function lib(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (!extension_loaded('FFI')) {
            throw new \RuntimeException('BLS aggregation needs the FFI extension and a built libblst');
        }
        $cdef = <<<'CDEF'
            void blst_scalar_from_bendian(void *out, const char *a);
            bool blst_sk_check(const void *a);
            void blst_sk_to_pk_in_g1(void *out_pk, const void *sk);
            void blst_p1_compress(void *out, const void *in);
            int blst_p1_uncompress(void *out, const char *in);
            bool blst_p1_affine_in_g1(const void *p);
            bool blst_p1_affine_is_inf(const void *p);
            void blst_p1_add_or_double_affine(void *out, const void *a, const void *b);
            void blst_p2_compress(void *out, const void *in);
            int blst_p2_uncompress(void *out, const char *in);
            bool blst_p2_affine_in_g2(const void *p);
            void blst_p2_add_or_double_affine(void *out, const void *a, const void *b);
            void blst_hash_to_g2(void *out, const char *msg, size_t len, const char *dst, size_t dstlen, const char *aug, size_t auglen);
            void blst_sign_pk_in_g1(void *out_sig, const void *hash, const void *sk);
            int blst_core_verify_pk_in_g1(const void *pk, const void *sig, bool hoe, const char *msg, size_t msglen, const char *dst, size_t dstlen, const char *aug, size_t auglen);
            size_t blst_pairing_sizeof(void);
            void blst_pairing_init(void *ctx, bool hoe, const char *dst, size_t dstlen);
            int blst_pairing_aggregate_pk_in_g1(void *ctx, const void *pk, const void *sig, const char *msg, size_t msglen, const char *aug, size_t auglen);
            void blst_pairing_commit(void *ctx);
            bool blst_pairing_finalverify(const void *ctx, const void *gtsig);
            CDEF;
        $paths = [];
        $env = getenv('PCA_BLST_LIB');
        if (is_string($env) && $env !== '') {
            $paths[] = $env;
        }
        $packaged = NativeDir::lib('blst');
        if ($packaged !== null) {
            $paths[] = $packaged; // after the override, before the system names
        }
        array_push($paths, 'libblst.so', 'libblst.dylib', 'blst.dll');
        if (self::$pathsHook !== null) {
            $paths = (self::$pathsHook)($paths);
        }
        foreach ($paths as $p) {
            try {
                return self::$ffi = \FFI::cdef($cdef, $p);
            } catch (\Throwable) {
                continue;
            }
        }
        throw new \RuntimeException('BLS aggregation needs a built libblst (supranational/blst shared library; set PCA_BLST_LIB)');
    }

    private static function buf(int $n): \FFI\CData
    {
        return self::lib()->new("uint8_t[$n]");
    }

    /** A C-owned copy of a byte string (blst keeps the DST pointer, so it must outlive the PHP call). */
    private static function cstr(string $s): \FFI\CData
    {
        $c = self::lib()->new('char[' . max(1, strlen($s)) . ']');
        if ($s !== '') {
            \FFI::memcpy($c, $s, strlen($s));
        }
        return $c;
    }

    private static function read(\FFI\CData $b, int $n): string
    {
        return \FFI::string($b, $n);
    }

    private static function bytes(mixed $v, string $what): string
    {
        if (!is_string($v)) {
            throw new \TypeError("$what: expected bytes");
        }
        return $v;
    }

    private static function compressed(mixed $b, int $len): bool
    {
        return is_string($b) && strlen($b) === $len && (ord($b[0]) & 0x80) !== 0;
    }

    private static function g2Affine(string $sig): ?\FFI\CData
    {
        $a = self::buf(self::P2A);
        return self::lib()->blst_p2_uncompress($a, $sig) === 0 ? $a : null;
    }

    private static function g1Affine(string $pk): ?\FFI\CData
    {
        $a = self::buf(self::P1A);
        return self::lib()->blst_p1_uncompress($a, $pk) === 0 ? $a : null;
    }

    private static function reencodeG2(\FFI\CData $aff): string
    {
        $acc = self::buf(self::P2);
        self::lib()->blst_p2_add_or_double_affine($acc, $acc, $aff);
        $out = self::buf(self::SIGNATURE_LENGTH);
        self::lib()->blst_p2_compress($out, $acc);
        return self::read($out, self::SIGNATURE_LENGTH);
    }

    private static function reencodeG1(\FFI\CData $aff): string
    {
        $acc = self::buf(self::P1);
        self::lib()->blst_p1_add_or_double_affine($acc, $acc, $aff);
        $out = self::buf(self::PUBLIC_KEY_LENGTH);
        self::lib()->blst_p1_compress($out, $acc);
        return self::read($out, self::PUBLIC_KEY_LENGTH);
    }

    /** A 96-byte compressed G2 point whose canonical re-encoding is the input (subgroup membership is checked at verify). */
    public static function canonicalSignature(mixed $sig): bool
    {
        if (!self::compressed($sig, self::SIGNATURE_LENGTH)) {
            return false;
        }
        $a = self::g2Affine($sig);
        return $a !== null && self::lib()->blst_p2_affine_in_g2($a) && self::reencodeG2($a) === $sig;
    }

    /** The secret key as a blst scalar; refuses anything but 32 bytes with 1 <= n < r. */
    private static function skScalar(mixed $secretKey): \FFI\CData
    {
        $sk = self::bytes($secretKey, 'secret key');
        if (strlen($sk) !== self::SECRET_KEY_LENGTH) {
            throw new \InvalidArgumentException('invalid private key, expected ' . self::SECRET_KEY_LENGTH . ' bytes, got ' . strlen($sk));
        }
        $s = self::buf(self::SECRET_KEY_LENGTH); // the scalar buffer is exactly one key long
        self::lib()->blst_scalar_from_bendian($s, $sk);
        if (!self::lib()->blst_sk_check($s)) {
            throw new \InvalidArgumentException('expected valid private key: 1 <= n < ' . gmp_strval(gmp_init(self::R_HEX, 16)));
        }
        return $s;
    }

    public static function publicKeyOf(mixed $secretKey): string
    {
        $p1 = self::buf(self::P1);
        self::lib()->blst_sk_to_pk_in_g1($p1, self::skScalar($secretKey));
        $out = self::buf(self::PUBLIC_KEY_LENGTH);
        self::lib()->blst_p1_compress($out, $p1);
        return self::read($out, self::PUBLIC_KEY_LENGTH);
    }

    /** @return array{secret_key:string,public_key:string} */
    public static function keyGen(): array
    {
        $r = gmp_init(self::R_HEX, 16);
        $sk = gmp_add(gmp_mod(gmp_init(bin2hex(self::randomBytes(48)), 16), gmp_sub($r, 1)), 1);
        if (gmp_cmp($sk, 1) === 0) {
            throw new \RuntimeException('keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue');
        }
        $secret = hex2bin(str_pad(gmp_strval($sk, 16), 64, '0', STR_PAD_LEFT));
        return ['secret_key' => $secret, 'public_key' => self::publicKeyOf($secret)];
    }

    /** KeyValidate: canonical compressed encoding, on curve, not the identity, in the prime-order subgroup. */
    public static function keyValidate(mixed $publicKey): bool
    {
        if (!self::compressed($publicKey, self::PUBLIC_KEY_LENGTH)) {
            return false;
        }
        if (isset(self::$kv[$publicKey])) {
            return self::$kv[$publicKey];
        }
        $a = self::g1Affine($publicKey);
        $ok = $a !== null && !self::lib()->blst_p1_affine_is_inf($a) && self::reencodeG1($a) === $publicKey && self::lib()->blst_p1_affine_in_g1($a);
        if (count(self::$kv) < 4096) {
            self::$kv[$publicKey] = $ok;
        }
        return $ok;
    }

    private static function signWith(mixed $secretKey, string $msg, string $dst): string
    {
        $sk = self::skScalar($secretKey);
        $h = self::buf(self::P2);
        $d = self::cstr($dst);
        self::lib()->blst_hash_to_g2($h, $msg, strlen($msg), $d, strlen($dst), null, 0);
        $s = self::buf(self::P2);
        self::lib()->blst_sign_pk_in_g1($s, $h, $sk);
        $out = self::buf(self::SIGNATURE_LENGTH);
        self::lib()->blst_p2_compress($out, $s);
        return self::read($out, self::SIGNATURE_LENGTH);
    }

    public static function sign(mixed $secretKey, mixed $msg): string
    {
        return self::signWith($secretKey, self::bytes($msg, 'message'), self::SIG_DST);
    }

    public static function popProve(mixed $secretKey): string
    {
        return self::signWith($secretKey, self::publicKeyOf($secretKey), self::POP_DST);
    }

    /** The public key was validated by the caller; the signature is subgroup-checked here. */
    private static function coreVerify(string $pk, string $msg, string $sig, bool $pop): bool
    {
        $pa = self::g1Affine($pk);
        $sa = self::g2Affine($sig);
        if ($pa === null || $sa === null || !self::lib()->blst_p2_affine_in_g2($sa)) {
            return false;
        }
        $dst = $pop ? self::POP_DST : self::SIG_DST;
        $m = $pop ? $pk : $msg;
        $d = self::cstr($dst);
        return self::lib()->blst_core_verify_pk_in_g1($pa, $sa, true, $m, strlen($m), $d, strlen($dst), null, 0) === 0;
    }

    public static function verify(mixed $publicKey, mixed $msg, mixed $sig): bool
    {
        try {
            return self::canonicalSignature($sig) && self::keyValidate($publicKey) && self::coreVerify($publicKey, self::bytes($msg, 'message'), $sig, false);
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function popVerify(mixed $publicKey, mixed $pop): bool
    {
        try {
            return self::canonicalSignature($pop) && self::keyValidate($publicKey) && self::coreVerify($publicKey, '', $pop, true);
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    /** @param list<string> $sigs */
    public static function aggregate(mixed $sigs): string
    {
        if (!is_array($sigs) || $sigs === []) {
            throw new \InvalidArgumentException('aggregate: need at least one signature');
        }
        foreach ($sigs as $sg) {
            if (!self::canonicalSignature($sg)) {
                throw new \InvalidArgumentException('aggregate: every signature must be a 96-byte compressed G2 point');
            }
        }
        $acc = self::buf(self::P2);
        foreach ($sigs as $sg) {
            self::lib()->blst_p2_add_or_double_affine($acc, $acc, self::g2Affine($sg));
        }
        $out = self::buf(self::SIGNATURE_LENGTH);
        self::lib()->blst_p2_compress($out, $acc);
        return self::read($out, self::SIGNATURE_LENGTH);
    }

    /** @param list<string> $publicKeys */
    public static function aggregatePublicKeys(mixed $publicKeys): string
    {
        if (!is_array($publicKeys) || $publicKeys === []) {
            throw new \InvalidArgumentException('aggregatePublicKeys: need at least one key');
        }
        $acc = self::buf(self::P1);
        foreach ($publicKeys as $pk) {
            $a = self::g1Affine(self::bytes($pk, 'public key')) ?? throw new \InvalidArgumentException('aggregatePublicKeys: not a G1 point');
            self::lib()->blst_p1_add_or_double_affine($acc, $acc, $a);
        }
        $out = self::buf(self::PUBLIC_KEY_LENGTH);
        self::lib()->blst_p1_compress($out, $acc);
        return self::read($out, self::PUBLIC_KEY_LENGTH);
    }

    /** @param list<string> $publicKeys @param list<string> $msgs */
    public static function rawAggregateVerify(array $publicKeys, array $msgs, mixed $aggSig): bool
    {
        try {
            if (!self::canonicalSignature($aggSig) || $publicKeys === [] || count($publicKeys) !== count($msgs)) {
                return false;
            }
            $seen = [];
            foreach ($msgs as $m) {
                $h = self::bytes($m, 'message');
                if (isset($seen[$h])) {
                    return false;
                }
                $seen[$h] = true;
            }
            foreach ($publicKeys as $pk) {
                if (!self::keyValidate($pk)) {
                    return false;
                }
            }
            $sig = self::g2Affine($aggSig);
            if ($sig === null || !self::lib()->blst_p2_affine_in_g2($sig)) {
                return false;
            }
            $ctx = self::buf((int)self::lib()->blst_pairing_sizeof());
            $dst = self::cstr(self::SIG_DST);
            self::lib()->blst_pairing_init($ctx, true, $dst, strlen(self::SIG_DST));
            foreach (array_values($publicKeys) as $i => $pk) {
                $m = array_values($msgs)[$i];
                if (self::lib()->blst_pairing_aggregate_pk_in_g1($ctx, self::g1Affine($pk), $i === 0 ? $sig : null, $m, strlen($m), null, 0) !== 0) {
                    return false;
                }
            }
            self::lib()->blst_pairing_commit($ctx);
            return (bool)self::lib()->blst_pairing_finalverify($ctx, null);
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    /** @param list<string> $publicKeys */
    public static function rawFastAggregateVerify(array $publicKeys, mixed $msg, mixed $aggSig): bool
    {
        try {
            if (!self::canonicalSignature($aggSig) || $publicKeys === []) {
                return false;
            }
            foreach ($publicKeys as $pk) {
                if (!self::keyValidate($pk)) {
                    return false;
                }
            }
            $agg = self::aggregatePublicKeys(array_values($publicKeys));
            return self::keyValidate($agg) && self::coreVerify($agg, self::bytes($msg, 'message'), $aggSig, false);
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- registry: only keys admitted through a proof of possession may enter an aggregate (rogue-key defence) ----

    /** True only for a {@see RegisteredKey} (a key admitted through {@see registerKey}). */
    public static function isRegisteredKey(mixed $x): bool
    {
        return $x instanceof RegisteredKey;
    }

    /** @return array{ok:bool,reason?:string,key?:RegisteredKey} */
    public static function registerKey(mixed $publicKey, mixed $pop): array
    {
        if (!is_string($publicKey) || !is_string($pop)) {
            return ['ok' => false, 'reason' => 'public key and proof of possession must be Uint8Arrays'];
        }
        if (!self::keyValidate($publicKey)) {
            return ['ok' => false, 'reason' => 'public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)'];
        }
        if (strlen($pop) !== self::SIGNATURE_LENGTH) {
            return ['ok' => false, 'reason' => 'proof of possession is not a 96-byte compressed G2 signature'];
        }
        if (!self::popVerify($publicKey, $pop)) {
            return ['ok' => false, 'reason' => 'proof of possession does not verify for this key'];
        }
        return ['ok' => true, 'key' => RegisteredKey::admit($publicKey)];
    }

    /** @param list<mixed> $keys */
    private static function checkRegistered(mixed $keys): ?string
    {
        if (!is_array($keys) || !array_is_list($keys)) {
            return 'keys must be an array of RegisteredKey';
        }
        if ($keys === []) {
            return 'no keys';
        }
        foreach ($keys as $i => $k) {
            if (!($k instanceof RegisteredKey)) {
                return "key $i is not a registered key: it was not admitted through registerKey (proof of possession)";
            }
        }
        return null;
    }

    /** @param list<RegisteredKey> $keys @param list<string> $msgs */
    public static function aggregateVerify(mixed $keys, array $msgs, mixed $aggSig): bool
    {
        return self::checkRegistered($keys) === null && self::rawAggregateVerify(array_map(static fn(RegisteredKey $k) => $k->bytes, $keys), $msgs, $aggSig);
    }

    /** @param list<RegisteredKey> $keys */
    public static function fastAggregateVerify(mixed $keys, mixed $msg, mixed $aggSig): bool
    {
        if (self::checkRegistered($keys) !== null) {
            return false;
        }
        $bytes = array_map(static fn(RegisteredKey $k) => $k->bytes, $keys);
        return count(array_unique($bytes)) === count($bytes) && self::rawFastAggregateVerify($bytes, $msg, $aggSig);
    }

    // ---- BLS capability chain (one aggregate signature over every hop) ----

    private static function f(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function bodyOf(mixed $c): Obj
    {
        return Obj::of(['issuer' => self::f($c, 'issuer'), 'holder' => self::f($c, 'holder'), 'caveats' => self::f($c, 'caveats'), 'parent' => self::f($c, 'parent')]);
    }

    private static function unb64u(mixed $s): string
    {
        return is_string($s) ? (Pca::unb64u($s) ?? throw new \InvalidArgumentException('bad base64url')) : throw new \InvalidArgumentException('bad base64url');
    }

    private static function sigMessage(string $bodyDigest): string
    {
        return self::CAP_BLS_DOMAIN . self::unb64u($bodyDigest);
    }

    /** base64url(sha256(strict canonical of the capability without its signature)). */
    public static function capHash(mixed $c): string
    {
        $o = new Obj();
        foreach ($c->keys() as $k) {
            if ($k !== 'sig') {
                $o->set($k, $c->get($k));
            }
        }
        return Pca::hashCanonical($o);
    }

    private static function seal(Obj $body, mixed $signerSecret): Obj
    {
        $digest = Pca::hashCanonical(self::bodyOf($body));
        $cap = Obj::of(['id' => $digest, 'issuer' => $body->get('issuer'), 'holder' => $body->get('holder'), 'caveats' => $body->get('caveats'),
            'body_digest' => $digest, 'sig' => Pca::b64u(self::sign($signerSecret, self::sigMessage($digest))), 'suite' => self::BLS_SUITE]);
        if ($body->has('parent')) {
            $cap->set('parent', $body->get('parent'));
        }
        return $cap;
    }

    public static function blsPublicKey(mixed $secretKey): string
    {
        return Pca::b64u(self::publicKeyOf($secretKey));
    }

    public static function mintBlsRoot(mixed $principalSecret, mixed $principalPublic, mixed $holder, mixed $caveats): Obj
    {
        return self::seal(Obj::of(['issuer' => $principalPublic, 'holder' => $holder, 'caveats' => $caveats]), $principalSecret);
    }

    public static function blsDelegate(Obj $parent, mixed $toHolder, mixed $added, mixed $signerSecret): Obj
    {
        return self::seal(Obj::of(['issuer' => $parent->get('holder'), 'holder' => $toHolder, 'caveats' => [...$parent->get('caveats'), ...$added],
            'parent' => self::capHash($parent)]), $signerSecret);
    }

    public static function blsAttenuate(Obj $parent, mixed $added, mixed $signerSecret): Obj
    {
        return self::blsDelegate($parent, $parent->get('holder'), $added, $signerSecret);
    }

    private static function wellTyped(mixed $c): bool
    {
        if (!($c instanceof Obj)) {
            return false;
        }
        foreach (['id', 'issuer', 'holder', 'body_digest', 'sig'] as $k) {
            if (!is_string($c->get($k))) {
                return false;
            }
        }
        if ($c->get('suite') !== self::BLS_SUITE || ($c->has('parent') && !is_string($c->get('parent')))) {
            return false;
        }
        $cav = $c->get('caveats');
        if (!is_array($cav) || !array_is_list($cav)) {
            return false;
        }
        foreach ($cav as $cv) {
            if (!($cv instanceof Obj) || !is_string($cv->get('type'))) {
                return false;
            }
        }
        return true;
    }

    /** @param list<Obj> $chain */
    public static function aggregateChainSignatures(mixed $chain): string
    {
        if (!is_array($chain) || $chain === []) {
            throw new \InvalidArgumentException('aggregateChainSignatures: empty chain');
        }
        return self::aggregate(array_map(static fn($c) => self::unb64u($c->get('sig')), $chain));
    }

    /** @return array{ok:bool,reason?:string} */
    public static function verifyAggregatedChain(mixed $chain, mixed $aggSig, KeyRegistry $registry, ?string $expectedRootPrincipal = null): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            return $no('empty chain');
        }
        if (count($chain) > self::MAX_CHAIN_DEPTH) {
            return $no('chain too long (max ' . self::MAX_CHAIN_DEPTH . ' hops)');
        }
        foreach ($chain as $i => $c) {
            if (!self::wellTyped($c)) {
                return $no("hop $i: malformed capability");
            }
        }
        $root = $chain[0];
        if ($root->has('parent')) {
            return $no('hop 0: root must not have a parent');
        }
        if ($expectedRootPrincipal !== null && $root->get('issuer') !== $expectedRootPrincipal) {
            return $no('hop 0: root issuer is not the expected principal');
        }
        $pks = [];
        $msgs = [];
        foreach ($chain as $i => $c) {
            try {
                $digest = Pca::hashCanonical(self::bodyOf($c));
            } catch (\Throwable) {
                return $no("hop $i: malformed body");
            }
            if ($digest !== $c->get('body_digest') || $c->get('id') !== $c->get('body_digest')) {
                return $no("hop $i: body digest mismatch");
            }
            try {
                $pk = $registry->get(self::unb64u($c->get('issuer')));
            } catch (\Throwable) {
                return $no("hop $i: malformed issuer key");
            }
            if ($pk === null) {
                return $no("hop $i: issuer key has no verified proof of possession (not in the registry)");
            }
            if ($i > 0) {
                $parent = $chain[$i - 1];
                if ($c->get('parent') !== self::capHash($parent)) {
                    return $no("hop $i: broken parent link");
                }
                if ($c->get('issuer') !== $parent->get('holder')) {
                    return $no("hop $i: issuer is not the parent's bound holder");
                }
                if (count($c->get('caveats')) < count($parent->get('caveats'))) {
                    return $no("hop $i: drops parent caveat(s)");
                }
                foreach ($parent->get('caveats') as $j => $pc) {
                    if (Pca::hashCanonical($c->get('caveats')[$j]) !== Pca::hashCanonical($pc)) {
                        return $no("hop $i: caveat $j altered or reordered");
                    }
                }
            }
            $pks[] = $pk;
            $msgs[] = self::sigMessage($c->get('body_digest'));
        }
        try {
            foreach ($chain as $i => $c) {
                if (Pca::b64u(self::unb64u($c->get('sig'))) !== $c->get('sig')) {
                    return $no("hop $i: non-canonical sig encoding");
                }
            }
            if (self::aggregate(array_map(static fn($c) => self::unb64u($c->get('sig')), $chain)) !== self::bytes($aggSig, 'aggregate signature')) {
                return $no('hop sig fields do not sum to the aggregate signature');
            }
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return $no('malformed hop sig');
        }
        return self::aggregateVerify($pks, $msgs, $aggSig) ? ['ok' => true] : $no('aggregate signature does not verify over all hops');
    }

    // ---- witnesses: BLS cosignatures over a signed tree head, aggregable into one signature ----

    private static function witnessMessage(mixed $h): string
    {
        foreach (['size', 'root', 'prev_root'] as $k) {
            if (!Js::has($h, $k)) {
                throw new \TypeError("canonicalize: undefined value for $k");
            }
        }
        $epoch = self::f($h, 'guardian_epoch');
        return self::STH_WITNESS_BLS_DOMAIN . Json::canonicalizeNative(Obj::of(['size' => self::f($h, 'size'), 'root' => self::f($h, 'root'),
            'prev_root' => self::f($h, 'prev_root'), 'guardian_epoch' => $epoch ?? new Num('0')]));
    }

    public static function cosignTreeHead(mixed $statement, mixed $witnessSecret): Obj
    {
        return Obj::of(['key' => Pca::b64u(self::publicKeyOf($witnessSecret)), 'sig' => Pca::b64u(self::sign($witnessSecret, self::witnessMessage($statement))), 'suite' => self::BLS_SUITE]);
    }

    public static function verifyWitnessCosignature(mixed $statement, mixed $cosig): bool
    {
        try {
            if (!($cosig instanceof Obj) || $cosig->get('suite') !== self::BLS_SUITE) {
                return false;
            }
            return self::verify(self::unb64u($cosig->get('key')), self::witnessMessage($statement), self::unb64u($cosig->get('sig')));
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function aggregateWitnessCosignatures(mixed $cosigs): string
    {
        if (!is_array($cosigs) || $cosigs === []) {
            throw new \InvalidArgumentException('aggregateWitnessCosignatures: empty set');
        }
        return self::aggregate(array_map(static fn($c) => self::unb64u($c->get('sig')), $cosigs));
    }

    /** @param list<RegisteredKey> $witnessKeys */
    public static function verifyAggregatedWitnessCosignatures(mixed $statement, mixed $witnessKeys, mixed $aggSig): bool
    {
        try {
            if (!is_array($witnessKeys) || $witnessKeys === []) {
                return false;
            }
            foreach ($witnessKeys as $k) {
                if (!($k instanceof RegisteredKey)) {
                    return false;
                }
            }
            $bytes = array_map(static fn(RegisteredKey $k) => $k->bytes, $witnessKeys);
            if (count(array_unique($bytes)) !== count($bytes)) {
                return false;
            }
            return self::fastAggregateVerify($witnessKeys, self::witnessMessage($statement), $aggSig);
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable) {
            return false;
        }
    }

    /** @internal Test seam: when set, random bytes are read from it (called with the byte count) instead of random_bytes. */
    public static ?\Closure $randomHook = null;
    /** @internal Test seam: when set, it gets the candidate libblst paths, in load order, and returns the list to try instead. */
    public static ?\Closure $pathsHook = null;
    private static function randomBytes(int $n): string { return self::$randomHook !== null ? (self::$randomHook)($n) : random_bytes($n); }
}

/** A public key that passed KeyValidate and proof of possession. Only {@see Aggsig::registerKey} mints one. */
final class RegisteredKey
{
    private function __construct(public readonly string $bytes)
    {
    }

    /** @internal */
    public static function admit(string $key): self
    {
        return new self($key);
    }
}

/** Keys admitted through a proof of possession. */
final class KeyRegistry
{
    /** @var array<string,RegisteredKey> */
    private array $keys = [];

    /** @return array{ok:bool,reason?:string} */
    public function register(mixed $publicKey, mixed $pop): array
    {
        $r = Aggsig::registerKey($publicKey, $pop);
        if ($r['ok']) {
            $this->keys[$publicKey] = $r['key'];
        }
        return $r;
    }

    public function get(mixed $publicKey): ?RegisteredKey
    {
        return is_string($publicKey) && strlen($publicKey) === Aggsig::PUBLIC_KEY_LENGTH ? ($this->keys[$publicKey] ?? null) : null;
    }

    public function has(mixed $publicKey): bool
    {
        return $this->get($publicKey) !== null;
    }

    public function size(): int
    {
        return count($this->keys);
    }
}
