<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';

/**
 * The signed group descriptor that pins a FROST threshold to its group key. A FROST aggregate is a plain Ed25519 signature, so its
 * threshold is a label until an authority the verifier pins attests how the group was formed. Ed25519 and SHA-256 are libsodium's.
 *
 * Wire values arrive as parsed JSON (Obj / list / string / Num / bool / null) or as plain PHP values; keys may be a base64url string or
 * raw bytes in a {@see Bytes}. A failed verification is a refusal (never an exception); an impossible issue request throws.
 */
final class GroupDescriptor
{
    public const GROUP_DESCRIPTOR_VERSION = 1;
    public const GROUP_SUITE = 'frost-ed25519';
    public const MAX_GROUP_SIZE = 1024;
    private const DESCRIPTOR_DOMAIN = "atlas-pca-pq-threshold/group-descriptor/v1\0";
    private const SIGNER_SET_DOMAIN = "atlas-pca-pq-threshold/signer-set/v1\0";

    // ---- JavaScript-flavoured value helpers -------------------------------------------------------------------------

    /** The JavaScript number value of a Num / int / float, or null for anything else (a string is not a number). */
    public static function numOf(mixed $o): ?float
    {
        if ($o instanceof Num) {
            return $o->float();
        }
        return is_int($o) || is_float($o) ? (float) $o : null;
    }

    /** Number.isInteger. */
    public static function isInteger(mixed $o): bool
    {
        $d = self::numOf($o);
        return $d !== null && is_finite($d) && floor($d) === $d;
    }

    /** A member of a JSON object; an array, a non-object or a missing member is null. */
    public static function member(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null;
    }

    /** Was the member present at all (JavaScript: `k in o`)? */
    public static function has(mixed $o, string $k): bool
    {
        if ($o instanceof Obj) {
            return $o->has($k);
        }
        return is_array($o) && !array_is_list($o) && array_key_exists($k, $o);
    }

    /** typeof x === 'object' && x !== null (an array counts). */
    public static function isObject(mixed $o): bool
    {
        return $o instanceof Obj || is_array($o);
    }

    /** A key as canonical-form base64url text: a Bytes is encoded, a string passes through, anything else is null. */
    public static function asB64u(mixed $k): ?string
    {
        return $k instanceof Bytes ? Pca::b64u($k->raw) : (is_string($k) ? $k : null);
    }

    /** String(x) for the reasons: integers print without a fraction. */
    public static function show(mixed $o): string
    {
        $d = self::numOf($o);
        if ($d !== null) {
            return self::isInteger($o) && abs($d) < 1e21 ? sprintf('%.0f', $d) : (string) json_encode($d);
        }
        return match (true) {
            $o === null => 'null',
            is_bool($o) => $o ? 'true' : 'false',
            is_string($o) => $o,
            default => '[object Object]',
        };
    }

    /** A JS-integer value as a canonical-form number (2.0 and 2 are the same value). */
    private static function num(mixed $o): mixed
    {
        return self::isInteger($o) ? new Num(sprintf('%.0f', self::numOf($o))) : $o;
    }

    private static function withDomain(string $domain, string $body): string
    {
        return $domain . $body;
    }

    // ---- signer set -------------------------------------------------------------------------------------------------

    /**
     * sha256(DOMAIN || canonical(sorted [{id, pk}])): order-insensitive, ids distinct. Each participant is {identifier (positive safe
     * integer), publicKey (canonical b64u 32 bytes, or a Bytes)}. Throws on a malformed set.
     * @param mixed $participants
     */
    public static function signerSetCommitment(mixed $participants): string
    {
        if (!is_array($participants) || !array_is_list($participants) || $participants === [] || count($participants) > self::MAX_GROUP_SIZE) {
            throw new \InvalidArgumentException('signerSetCommitment: need 1..' . self::MAX_GROUP_SIZE . ' participants');
        }
        $rows = [];
        foreach ($participants as $p) {
            if (!self::isObject($p)) {
                throw new \InvalidArgumentException('signerSetCommitment: participant is not an object');
            }
            $idObj = self::member($p, 'identifier');
            $pk = self::asB64u(self::member($p, 'publicKey'));
            $id = self::numOf($idObj);
            if ($id === null || !self::isInteger($idObj) || $id <= 0 || $id > 9007199254740991.0) {
                throw new \InvalidArgumentException('signerSetCommitment: participant identifiers must be positive safe integers');
            }
            if ($pk === null || Pca::unb64u($pk, 32) === null) {
                throw new \InvalidArgumentException('signerSetCommitment: verification share is not a canonical b64u(32) value');
            }
            $rows[] = [(int) $id, $pk];
        }
        usort($rows, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        $out = [];
        foreach ($rows as $i => $r) {
            if ($i > 0 && $r[0] === $rows[$i - 1][0]) {
                throw new \InvalidArgumentException('signerSetCommitment: duplicate participant identifier');
            }
            $out[] = Obj::of(['id' => new Num((string) $r[0]), 'pk' => $r[1]]);
        }
        return Pca::b64u(hash('sha256', self::withDomain(self::SIGNER_SET_DOMAIN, Json::canonicalizeNative($out)), true));
    }

    private static function descriptorBytes(mixed $v, mixed $suite, mixed $groupPk, mixed $t, mixed $n, mixed $signerSet): string
    {
        $body = Obj::of(['v' => self::num($v), 'suite' => $suite, 'group_pk' => $groupPk, 't' => self::num($t), 'n' => self::num($n), 'signer_set' => $signerSet]);
        return self::withDomain(self::DESCRIPTOR_DOMAIN, Json::canonicalizeNative($body));
    }

    /**
     * Issue a descriptor at dealing time: {descriptor: {v, suite, groupPublicKey, t, n, signerSetCommitment}, authority, sig}. The
     * authority secret is a 32-byte Ed25519 seed (raw string or Bytes). Throws on an impossible group (t < 1, t > n, a non-canonical
     * group key, a bad authority key).
     * @return array{descriptor:Obj,authority:string,sig:string}
     */
    public static function issueGroupDescriptor(mixed $authoritySecretKey, mixed $groupPublicKey, mixed $t, mixed $participants): array
    {
        if (!is_array($participants) || !array_is_list($participants)) {
            throw new \InvalidArgumentException('issueGroupDescriptor: participants must be an array');
        }
        $n = count($participants);
        $td = self::numOf($t);
        if ($td === null || !self::isInteger($t) || $td < 1 || $td > $n) {
            throw new \InvalidArgumentException('issueGroupDescriptor: need 1 <= t <= n (t=' . self::show($t) . ", n=$n)");
        }
        $gpk = self::asB64u($groupPublicKey);
        if ($gpk === null || Pca::unb64u($gpk, 32) === null) {
            throw new \InvalidArgumentException('issueGroupDescriptor: group public key is not canonical b64u(32)');
        }
        $seed = Bytes::of($authoritySecretKey);
        if ($seed === null || strlen($seed) !== 32) {
            throw new \InvalidArgumentException('issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key');
        }
        $commitment = self::signerSetCommitment($participants);
        $tl = (int) $td;
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $sk = sodium_crypto_sign_secretkey($kp);
        $d = Obj::of(['v' => new Num((string) self::GROUP_DESCRIPTOR_VERSION), 'suite' => self::GROUP_SUITE, 'groupPublicKey' => $gpk,
            't' => new Num((string) $tl), 'n' => new Num((string) $n), 'signerSetCommitment' => $commitment]);
        $sig = sodium_crypto_sign_detached(self::descriptorBytes(self::GROUP_DESCRIPTOR_VERSION, self::GROUP_SUITE, $gpk, $tl, $n, $commitment), $sk);
        sodium_memzero($sk);
        return ['descriptor' => $d, 'authority' => Pca::b64u(sodium_crypto_sign_publickey($kp)), 'sig' => Pca::b64u($sig)];
    }

    /** @return array{ok:false,reason:string} */
    private static function fail(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /**
     * Check a signed descriptor against the verifier's pins; never throws. `$trustedAuthorities` are pinned b64u keys (string or
     * Bytes), `$groupKey` the pinned group key, `$t` the threshold the verifier requires (the descriptor's t must EQUAL it) and
     * `$signerSetCommitment` an optional pin (null = absent; any non-string pin never matches).
     * @return array{ok:true,descriptor:mixed}|array{ok:false,reason:string}
     */
    public static function verifyGroupDescriptor(mixed $s, mixed $trustedAuthorities, mixed $groupKey, mixed $t, mixed $signerSetCommitment = null): array
    {
        try {
            if (!self::isObject($s)) {
                return self::fail('no signed group descriptor: the threshold is unattested');
            }
            $d = self::member($s, 'descriptor');
            $authority = self::member($s, 'authority');
            $sig = self::member($s, 'sig');
            if (!self::isObject($d) || !is_string($authority) || !is_string($sig)) {
                return self::fail('malformed group descriptor');
            }
            $dv = self::numOf(self::member($d, 'v'));
            if ($dv === null || $dv !== (float) self::GROUP_DESCRIPTOR_VERSION || self::member($d, 'suite') !== self::GROUP_SUITE) {
                return self::fail('unsupported group descriptor version or suite');
            }
            $gpk = self::member($d, 'groupPublicKey');
            $ssc = self::member($d, 'signerSetCommitment');
            if (!is_string($gpk) || !is_string($ssc)) {
                return self::fail('malformed group descriptor');
            }
            $dt = self::member($d, 't');
            $dn = self::member($d, 'n');
            if (!self::isInteger($dt) || !self::isInteger($dn) || self::numOf($dt) < 1 || self::numOf($dn) < self::numOf($dt) || self::numOf($dn) > self::MAX_GROUP_SIZE) {
                return self::fail('malformed group descriptor: need 1 <= t <= n');
            }
            if (!is_array($trustedAuthorities) || !array_is_list($trustedAuthorities)) {
                return self::fail('group descriptor could not be verified (malformed)');
            }
            $trusted = [];
            foreach ($trustedAuthorities as $a) {
                $x = self::asB64u($a);
                if ($x !== null) {
                    $trusted[$x] = true;
                }
            }
            if (!isset($trusted[$authority])) {
                return self::fail('group descriptor authority is not trusted');
            }
            if (Pca::unb64u($authority, 32) === null || Pca::unb64u($sig, 64) === null) {
                return self::fail('malformed authority key or signature');
            }
            if (!Pca::verifyEd25519B64u($authority, self::descriptorBytes(self::GROUP_DESCRIPTOR_VERSION, self::GROUP_SUITE, $gpk, $dt, $dn, $ssc), $sig)) {
                return self::fail('group descriptor signature does not verify');
            }
            if ($gpk !== self::asB64u($groupKey)) {
                return self::fail('group descriptor is for a different group key');
            }
            if (!self::isInteger($t) || self::numOf($t) < 1) {
                return self::fail('required t must be a positive integer');
            }
            if (self::numOf($dt) !== self::numOf($t)) {
                return self::fail('group was set up as ' . self::show($dt) . '-of-' . self::show($dn) . ' but ' . self::show($t) . ' is required: the threshold is not bound to this key');
            }
            if ($signerSetCommitment !== null && $ssc !== $signerSetCommitment) {
                return self::fail('group descriptor is for a different signer set');
            }
            return ['ok' => true, 'descriptor' => $d];
        } catch (\Throwable) {
            return self::fail('group descriptor could not be verified (malformed)');
        }
    }
}
