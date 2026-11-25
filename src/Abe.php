<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Proof-carrying encryption: FAME ciphertext-policy ABE (Fame) in the asymmetric BLS12-381 pairing, with the payload sealed under
 * AES-256-GCM and the whole header authenticated. Keys, ciphertexts and policies are JSON values (Obj, list arrays, strings, Num),
 * parsed fail-closed: a malformed ciphertext or key is a refusal (null), never an exception. Curve and pairing work is blst through
 * ext-ffi plus the GT shim (see Bls12); needs ext-gmp and ext-openssl.
 *
 * Honest limits (as the reference): no key revocation, the policy is public in the ciphertext, the master-key holder decrypts
 * everything, and it is not post-quantum or constant time.
 */
final class Abe
{
    public const ALG = 'fame-cpabe-bls12381-type3/aes-256-gcm';
    private const CEK_INFO = 'atlas-pca-abe/cek/v3';
    private const SALT_LEN = 16;

    private static function two(): Num
    {
        return new Num('2');
    }

    private static function isV2(mixed $v): bool
    {
        return $v instanceof Num && $v->float() === 2.0;
    }

    private static function scalarBe(\GMP $k): string
    {
        return Bls12::i2osp(Bls12::mod($k), 32);
    }

    // ---- wire ----

    private static function g1(mixed $x): ?\FFI\CData
    {
        return self::point(1, 48, $x);
    }

    private static function g2(mixed $x): ?\FFI\CData
    {
        return self::point(2, 96, $x);
    }

    /** a strict, canonical, in-subgroup, non-identity point from base64url */
    private static function point(int $g, int $len, mixed $x): ?\FFI\CData
    {
        $b = Pca::unb64u($x);
        if ($b === null || strlen($b) !== $len) {
            return null;
        }
        try {
            $p = Bls12::decode($g, $b);
        } catch (\InvalidArgumentException) {
            return null;
        }
        return Bls12::isInf($g, $p) ? null : $p;
    }

    /** @return ?list<\FFI\CData> */
    private static function tri(mixed $x, callable $one): ?array
    {
        if (!is_array($x) || !array_is_list($x) || count($x) !== 3) {
            return null;
        }
        $out = [];
        foreach ($x as $e) {
            $p = $one($e);
            if ($p === null) {
                return null;
            }
            $out[] = $p;
        }
        return $out;
    }

    /** @param list<\FFI\CData> $x @return list<string> */
    private static function tri1Json(array $x): array
    {
        return array_map(static fn(\FFI\CData $p): string => Pca::b64u(Bls12::compress(1, $p)), $x);
    }

    /** @param list<\FFI\CData> $x @return list<string> */
    private static function tri2Json(array $x): array
    {
        return array_map(static fn(\FFI\CData $p): string => Pca::b64u(Bls12::compress(2, $p)), $x);
    }

    // ---- setup / keygen ----

    /**
     * A fresh master key pair [mpk, msk] as JSON values. $fixed = [a1, a2, b1, b2, d1, d2, d3] (GMP) makes it deterministic, for
     * conformance tests only: never pass it in production.
     *
     * @param ?list<\GMP> $fixed
     * @return array{0:Obj,1:Obj}
     */
    public static function setup(?array $fixed = null): array
    {
        $s = $fixed ?? array_map(static fn(int $i): \GMP => Fame::randomScalar(), range(0, 6));
        [$pk, $sk] = Fame::setup([$s[0], $s[1]], [$s[2], $s[3]], [$s[4], $s[5], $s[6]]);
        $mpk = Obj::of(['v' => self::two(), 'curve' => 'bls12-381',
            'h' => array_map(static fn(\FFI\CData $p): string => Pca::b64u(Bls12::compress(2, $p)), $pk['h']),
            't' => array_map(Pca::b64u(...), $pk['t'])]);
        $msk = Obj::of(['v' => self::two(), 'curve' => 'bls12-381',
            'a' => array_map(static fn(\GMP $k): string => Pca::b64u(self::scalarBe($k)), $sk['a']),
            'b' => array_map(static fn(\GMP $k): string => Pca::b64u(self::scalarBe($k)), $sk['b']),
            'g' => self::tri1Json($sk['g'])]);
        return [$mpk, $msk];
    }

    /** exactly one encoding per scalar: 32 bytes, non-zero, and < r */
    private static function canonicalScalar(mixed $x): ?\GMP
    {
        $b = Pca::unb64u($x);
        if ($b === null || strlen($b) !== 32) {
            return null;
        }
        $n = Bls12::os2ip($b);
        return gmp_sign($n) !== 0 && gmp_cmp($n, Bls12::r()) < 0 ? $n : null;
    }

    private static function parseMsk(mixed $x): array
    {
        $bad = new \InvalidArgumentException('invalid master secret key');
        if (!($x instanceof Obj) || !self::isV2($x->get('v'))) {
            throw $bad;
        }
        $msk = [];
        foreach (['a', 'b'] as $k) {
            $l = $x->get($k);
            if (!is_array($l) || !array_is_list($l) || count($l) !== 2) {
                throw $bad;
            }
            $msk[$k] = [];
            foreach ($l as $e) {
                $n = self::canonicalScalar($e);
                if ($n === null) {
                    throw $bad;
                }
                $msk[$k][] = $n;
            }
        }
        $g = self::tri($x->get('g'), self::g1(...));
        if ($g === null) {
            throw $bad;
        }
        $msk['g'] = $g;
        return $msk;
    }

    private static function parseMpk(mixed $x): array
    {
        $bad = new \InvalidArgumentException('invalid master public key');
        if (!($x instanceof Obj) || !self::isV2($x->get('v'))) {
            throw $bad;
        }
        $h = $x->get('h');
        $t = $x->get('t');
        if (!is_array($h) || !array_is_list($h) || count($h) !== 2 || !is_array($t) || !array_is_list($t) || count($t) !== 2) {
            throw $bad;
        }
        $mpk = ['h' => [self::g2($h[0]), self::g2($h[1])], 't' => []];
        if ($mpk['h'][0] === null || $mpk['h'][1] === null) {
            throw $bad;
        }
        foreach ($t as $e) {
            $b = Pca::unb64u($e);
            if ($b === null || !Bls12::gtIsElement($b)) {
                throw $bad;
            }
            $mpk['t'][] = $b;
        }
        return $mpk;
    }

    /**
     * Issue a decryption key for the attribute tokens (deduplicated in order; empty or ill-formed ones dropped): [key, issued names].
     * $fixed = ['r' => [r1, r2], 'sigmas' => list, 'sigmaPrime' => s] (GMP) is for conformance tests only.
     *
     * @param list<string> $attrs
     * @return array{0:Obj,1:list<string>}
     */
    public static function issue(mixed $msk, array $attrs, ?array $fixed = null): array
    {
        $m = self::parseMsk($msk);
        $seen = [];
        $names = [];
        foreach ($attrs as $a) {
            if (!isset($seen[$a])) {
                $seen[$a] = true;
                if ($a !== '' && !AbePolicy::illFormed($a)) {
                    $names[] = $a;
                }
            }
        }
        $r = $fixed['r'] ?? [Fame::randomScalar(), Fame::randomScalar()];
        $sigmas = $fixed['sigmas'] ?? array_map(static fn(string $n): \GMP => Fame::randomScalar(), $names);
        $key = Fame::keygen($m, $names, $r, $sigmas, $fixed['sigmaPrime'] ?? Fame::randomScalar());
        $am = new Obj();
        foreach ($names as $n) {
            $am->set($n, Obj::of(['k' => self::tri1Json($key['attrs'][$n])]));
        }
        return [Obj::of(['v' => self::two(), 'curve' => 'bls12-381', 'k0' => self::tri2Json($key['k0']), 'kp' => self::tri1Json($key['kp']), 'attrs' => $am]), $names];
    }

    /** A decryption key for an explicit set of attribute tokens. @param list<string> $attrs */
    public static function keygenForAttributes(mixed $msk, array $attrs): Obj
    {
        return self::issue($msk, $attrs)[0];
    }

    /** an untrusted key: a malformed attribute component counts as not held; null if K0, K' or the container is malformed */
    private static function parseKey(mixed $x): ?array
    {
        if (!($x instanceof Obj) || !self::isV2($x->get('v')) || !($x->get('attrs') instanceof Obj)) {
            return null;
        }
        $k0 = self::tri($x->get('k0'), self::g2(...));
        $kp = self::tri($x->get('kp'), self::g1(...));
        if ($k0 === null || $kp === null) {
            return null;
        }
        $attrs = [];
        $am = $x->get('attrs');
        foreach ($am->keys() as $name) {
            $c = $am->get($name);
            $k = $c instanceof Obj ? self::tri($c->get('k'), self::g1(...)) : null;
            if ($k !== null) {
                $attrs[$name] = $k;
            }
        }
        return ['k0' => $k0, 'kp' => $kp, 'attrs' => $attrs];
    }

    // ---- encrypt ----

    private static function cek(string $ikm, string $salt): string
    {
        return hash_hkdf('sha256', $ikm, 32, self::CEK_INFO, $salt);
    }

    /** the authenticated header: canonical JSON of {v, alg, salt, ct0, tree, rows}; throws JsonError outside the canonical profile */
    private static function aad(string $salt, array $ct0, array $tree, array $rows): string
    {
        return Json::canonicalizeNative(Obj::of(['v' => self::two(), 'alg' => self::ALG, 'salt' => $salt, 'ct0' => $ct0, 'tree' => AbePolicy::toJson($tree), 'rows' => $rows]));
    }

    /**
     * Encrypt $plaintext so that it decrypts only for a holder whose attributes satisfy $policy. Throws InvalidArgumentException
     * on an invalid policy (including one naming an attribute twice) or master public key.
     *
     * @param ?list<\GMP> $fixed two encryption scalars: conformance tests only
     */
    public static function encryptForPolicy(mixed $mpk, mixed $policy, string $plaintext, ?array $fixed = null): Obj
    {
        $norm = AbePolicy::normalize($policy);
        if ($norm['tree'] === null) {
            throw new \InvalidArgumentException('invalid policy: ' . $norm['reason']);
        }
        $tree = $norm['tree'];
        $dup = AbePolicy::firstRepeatedAttribute($tree);
        if ($dup !== null) {
            throw new \InvalidArgumentException('invalid policy: attribute ' . Json::canonicalizeLenient($dup) . ' is named by more than one leaf (single-use attributes only)');
        }
        $pk = self::parseMpk($mpk);
        $salt = random_bytes(self::SALT_LEN);
        [$ct, $k] = Fame::encrypt($pk, $tree, $fixed ?? [Fame::randomScalar(), Fame::randomScalar()]);
        $saltB = Pca::b64u($salt);
        $ct0 = self::tri2Json($ct['ct0']);
        $rows = array_map(self::tri1Json(...), $ct['rows']);
        try {
            $aad = self::aad($saltB, $ct0, $tree, $rows);
        } catch (JsonError) {
            throw new \InvalidArgumentException('policy cannot be authenticated (header outside the canonical JSON profile)');
        }
        $iv = random_bytes(12);
        $tag = '';
        $body = openssl_encrypt($plaintext, 'aes-256-gcm', self::cek($k, $salt), OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if ($body === false) {
            throw new \RuntimeException('AES-256-GCM encryption failed');
        }
        return Obj::of(['v' => self::two(), 'alg' => self::ALG, 'salt' => $saltB, 'ct0' => $ct0, 'tree' => AbePolicy::toJson($tree), 'rows' => $rows,
            'iv' => Pca::b64u($iv), 'ct' => Pca::b64u($body), 'tag' => Pca::b64u($tag)]);
    }

    /** Encrypt a JSON value (the payload layer of decryptWithCapability). */
    public static function encryptToolPayload(mixed $mpk, mixed $policy, mixed $payload): Obj
    {
        return self::encryptForPolicy($mpk, $policy, Json::canonicalizeLenient($payload));
    }

    // ---- parse / decrypt ----

    /** @return ?list<string> three strictly base64url strings */
    private static function strTri(mixed $x): ?array
    {
        if (!is_array($x) || !array_is_list($x) || count($x) !== 3) {
            return null;
        }
        foreach ($x as $e) {
            if (!is_string($e) || Pca::unb64u($e) === null) {
                return null;
            }
        }
        return $x;
    }

    /** @return ?array{salt:string,iv:string,ct:string,tag:string,ct0:list<string>,tree:array,rows:list<list<string>>} */
    private static function parseCt(mixed $x): ?array
    {
        if (!($x instanceof Obj) || !self::isV2($x->get('v')) || $x->get('alg') !== self::ALG) {
            return null;
        }
        $c = [];
        foreach (['salt', 'iv', 'ct', 'tag'] as $f) {
            $s = $x->get($f);
            if (!is_string($s) || Pca::unb64u($s) === null) {
                return null;
            }
            $c[$f] = $s;
        }
        $ct0 = self::strTri($x->get('ct0'));
        $tree = AbePolicy::parseTree($x->get('tree'));
        $rows = $x->get('rows');
        if ($ct0 === null || $tree === null || !is_array($rows) || !array_is_list($rows)) {
            return null;
        }
        if (count($rows) !== AbePolicy::leafCount($tree) || AbePolicy::firstRepeatedAttribute($tree) !== null) {
            return null;
        }
        $c['ct0'] = $ct0;
        $c['tree'] = $tree;
        $c['rows'] = [];
        foreach ($rows as $r) {
            $t = self::strTri($r);
            if ($t === null) {
                return null;
            }
            $c['rows'][] = $t;
        }
        return $c;
    }

    /** Validate an untrusted value as a ciphertext; null (fail closed) on any deviation. */
    public static function parseCiphertext(mixed $x): ?Obj
    {
        $c = self::parseCt($x);
        return $c === null ? null : Obj::of(['v' => self::two(), 'alg' => self::ALG, 'salt' => $c['salt'], 'ct0' => $c['ct0'], 'tree' => AbePolicy::toJson($c['tree']),
            'rows' => $c['rows'], 'iv' => $c['iv'], 'ct' => $c['ct'], 'tag' => $c['tag']]);
    }

    /** The plaintext iff the key's attributes satisfy the ciphertext's policy AND the AEAD authenticates; otherwise null. Never throws on hostile input. */
    public static function decrypt(mixed $key, mixed $ciphertext): ?string
    {
        $ct = self::parseCt($ciphertext);
        $pk = $ct === null ? null : self::parseKey($key);
        if ($ct === null || $pk === null) {
            return null;
        }
        $ct0 = self::tri($ct['ct0'], self::g2(...));
        if ($ct0 === null) {
            return null;
        }
        $rows = [];
        foreach ($ct['rows'] as $r) {
            $t = self::tri($r, self::g1(...));
            if ($t === null) {
                return null;
            }
            $rows[] = $t;
        }
        $k = Fame::decrypt($pk, $ct['tree'], ['ct0' => $ct0, 'rows' => $rows]);
        if ($k === null) {
            return null;
        }
        try {
            $aad = self::aad($ct['salt'], $ct['ct0'], $ct['tree'], $ct['rows']);
        } catch (JsonError) {
            return null; // a header outside the canonical profile cannot be authentic
        }
        $iv = (string) Pca::unb64u($ct['iv']);
        $tag = (string) Pca::unb64u($ct['tag']);
        if (strlen($iv) !== 12 || strlen($tag) !== 16) {
            return null;
        }
        $pt = openssl_decrypt((string) Pca::unb64u($ct['ct']), 'aes-256-gcm', self::cek($k, (string) Pca::unb64u($ct['salt'])), OPENSSL_RAW_DATA, $iv, $tag, $aad);
        return $pt === false ? null : $pt;
    }

    /** decrypt() with the plaintext read as UTF-8 text (invalid sequences replaced by U+FFFD, a leading BOM dropped) */
    public static function decryptText(mixed $key, mixed $ciphertext): ?string
    {
        $pt = self::decrypt($key, $ciphertext);
        if ($pt === null) {
            return null;
        }
        $prev = mb_substitute_character();
        mb_substitute_character(0xFFFD);
        try {
            $s = mb_scrub($pt, 'UTF-8');
        } finally {
            mb_substitute_character($prev);
        }
        return str_starts_with($s, "\xEF\xBB\xBF") ? substr($s, 3) : $s;
    }

    /** {ok:true, payload} or {ok:false, reason} */
    public static function decryptWithCapability(mixed $key, mixed $ciphertext): Obj
    {
        $pt = self::decrypt($key, $ciphertext);
        if ($pt === null) {
            return Obj::of(['ok' => false, 'reason' => 'capability does not satisfy the policy, or ciphertext is invalid']);
        }
        try {
            if (preg_match('//u', $pt) !== 1) {
                throw new JsonError('invalid UTF-8');
            }
            return Obj::of(['ok' => true, 'payload' => Js::parse($pt)]);
        } catch (JsonError) {
            return Obj::of(['ok' => false, 'reason' => 'decrypted payload is not valid JSON']);
        }
    }

    // ---- capability attributes ----

    /** @return list<string> */
    private static function verbs(mixed $v): array
    {
        if (is_string($v)) {
            return [$v];
        }
        return is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
    }

    /** === on identifiers: objects are never identical */
    private static function sameId(mixed $a, mixed $b): bool
    {
        return $a === null ? $b === null : is_string($a) && $a === $b;
    }

    /**
     * The canonical attribute tokens a capability possesses, in insertion order (deterministic and total). scope:, act:, verb: and
     * resource: tokens come only from the ROOT capability: a delegated hop's own caveats are restrictions, never grants.
     *
     * @return list<string>
     */
    private static function capAttrs(mixed $cap, ?Obj $opts): array
    {
        if (!($cap instanceof Obj)) {
            return [];
        }
        $scopeSource = null;
        $envSource = null;
        if ($opts !== null && $opts->has('chain')) {
            $chain = $opts->get('chain');
            $chain = is_array($chain) && array_is_list($chain) ? $chain : [];
            $root = $chain[0] ?? null;
            $last = $chain === [] ? null : $chain[count($chain) - 1];
            if (!($root instanceof Obj) || !($last instanceof Obj) || !self::sameId($last->get('id'), $cap->get('id'))) {
                return [];
            }
            $principal = $opts->get('principal');
            $have = is_string($principal);
            if (!$have) {
                $principal = $root->get('issuer');
                $have = is_string($principal);
            }
            $pins = null;
            if ($opts->get('pqPins') instanceof Obj) {
                $pins = new Obj();
                foreach ($opts->get('pqPins')->keys() as $k) {
                    if (is_string($opts->get('pqPins')->get($k))) {
                        $pins->set($k, $opts->get('pqPins')->get($k));
                    }
                }
            }
            [, $ok] = Pca::verifyChain($chain, $have ? $principal : null, $have, null, $pins);
            if (!$ok) {
                return [];
            }
            $scopeSource = $root->get('caveats');
            $envSource = $root;
        } elseif (!$cap->has('parent')) {
            $scopeSource = $cap->get('caveats');
            $envSource = $cap;
        }
        $out = [];
        $seen = [];
        $add = static function (string $s) use (&$out, &$seen): void {
            if (!isset($seen[$s])) {
                $seen[$s] = true;
                $out[] = $s;
            }
        };
        $holder = $cap->get('holder');
        if (is_string($holder) && $holder !== '') {
            $add('holder:' . $holder);
        }
        if (is_array($scopeSource) && array_is_list($scopeSource)) {
            foreach ($scopeSource as $cv) {
                if (!($cv instanceof Obj)) {
                    continue;
                }
                if ($cv->get('type') === 'scope' && is_string($cv->get('value'))) {
                    $add('scope:' . $cv->get('value'));
                }
                if ($cv->get('type') === 'scopes' && is_array($cv->get('values')) && array_is_list($cv->get('values'))) {
                    foreach ($cv->get('values') as $s) {
                        if (is_string($s)) {
                            $add('scope:' . $s);
                        }
                    }
                }
            }
        }
        $env = $envSource === null ? null : Authorize::readEnvelope($envSource);
        $plist = $env?->get('predicates');
        if (is_array($plist) && array_is_list($plist)) {
            $preds = [];
            foreach ($plist as $p) {
                if ($p instanceof Obj) {
                    $preds[] = $p;
                } elseif (is_array($p) && array_is_list($p)) {
                    $preds[] = new Obj(); // an array counts as a predicate that names no verb or resource
                }
            }
            foreach ($preds as $p) {
                if (is_string($p->get('resource'))) {
                    foreach (self::verbs($p->get('verb')) as $v) {
                        try {
                            $add('act:' . Json::canonicalizeNative([$v, $p->get('resource')]));
                        } catch (JsonError) {
                            // a pair outside the canonical profile names no attribute
                        }
                    }
                }
            }
            if (count($preds) === 1) {
                foreach (self::verbs($preds[0]->get('verb')) as $v) {
                    $add('verb:' . $v);
                }
                if (is_string($preds[0]->get('resource'))) {
                    $add('resource:' . $preds[0]->get('resource'));
                }
            }
        }
        return $out;
    }

    /**
     * The sorted canonical attribute set a capability possesses. $opts: {chain (root first, ending in the capability; required for
     * scope/act/verb/resource tokens on a delegated hop, and a chain that fails verification yields none), principal (pins the root
     * issuer; default the chain's own root issuer), pqPins}.
     *
     * @return list<string>
     */
    public static function capabilityAttributes(mixed $capability, ?Obj $opts = null): array
    {
        return AbePolicy::jsSort(self::capAttrs($capability, $opts));
    }

    /**
     * A key bound to a capability's attributes plus any extra tokens; the holder is recorded. Returns [key, issued names].
     *
     * @param list<string> $extra
     * @return array{0:Obj,1:list<string>}
     */
    public static function issueForCapability(mixed $msk, mixed $capability, array $extra = [], ?Obj $opts = null): array
    {
        $attrs = self::capAttrs($capability, $opts);
        foreach ($extra as $a) {
            if ($a !== '') {
                $attrs[] = $a;
            }
        }
        [$key, $names] = self::issue($msk, $attrs);
        if ($capability instanceof Obj && is_string($capability->get('holder'))) {
            $key->set('holder', $capability->get('holder'));
        }
        return [$key, $names];
    }

    /** @param list<string> $extra */
    public static function keygenForCapability(mixed $msk, mixed $capability, array $extra = [], ?Obj $opts = null): Obj
    {
        return self::issueForCapability($msk, $capability, $extra, $opts)[0];
    }
}
