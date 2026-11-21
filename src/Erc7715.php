<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Attest/Common.php';

use Atlas\Pca\Attest\Common;

/**
 * ERC-7715 (wallet_requestExecutionPermissions) for PCA grants: map a grant's money envelope to a permission request, filter the
 * wallet's supported permissions, the revoke params, and verify what the wallet actually granted (a wallet may narrow, never
 * widen). Pure mapping, no chain access. Mirrors @atlasauth/pca-erc7715 including the reference's JS value coercions
 * (String(x) / BigInt(x)). The request / response are the ERC's own camelCase JSON; options use the reference's names.
 */
final class Erc7715
{
    private const HEX_ADDR = '/\A0x[0-9a-fA-F]{40}\z/';
    private const HEX_QTY = '/\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z/';
    private const DEC = '/\A(0|[1-9][0-9]*)\z/';

    /** RegExp#test coerces its argument with String(x). */
    private static function test(string $re, mixed $x): bool
    {
        return preg_match($re, IntentWb::jsStr($x)) === 1;
    }

    /** x.toLowerCase(): only a string has it. */
    private static function lower(mixed $x): string
    {
        if (!is_string($x)) {
            throw new \TypeError('toLowerCase is not a function');
        }
        return function_exists('mb_strtolower') ? mb_strtolower($x, 'UTF-8') : strtolower($x);
    }

    /** o[k] with JS property-read semantics: null throws, a non-object has no members. */
    private static function get(mixed $o, string $k): mixed
    {
        if ($o === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        return Js::opt($o, $k);
    }

    private static function has(mixed $o, string $k): bool
    {
        return ($o instanceof Obj && $o->has($k)) || (is_array($o) && !array_is_list($o) && array_key_exists($k, $o));
    }

    private static function bigInt(mixed $v): \GMP
    {
        return Common::bigInt(is_array($v) ? IntentWb::jsStr($v) : $v);
    }

    private static function hex(\GMP $n): string
    {
        return '0x' . gmp_strval($n, 16);
    }

    /**
     * Options: chainId (int, decimal string or GMP), sessionAccount, tokenAddress (absent: native token), baseUnitsPerMinor
     * (decimal string: the exact token base units per ONE minor unit; there is no price oracle), from, isAdjustmentAllowed.
     * Throws on a bad envelope or option.
     */
    public static function grantToPermissionRequest(mixed $g, mixed $o): array
    {
        $cap = self::get($g, 'capMinor');
        $exp = self::get($g, 'expiresAtSec');
        if (!K3Sig::anySafeInt($cap) || Js::num($cap) <= 0 || !K3Sig::anySafeInt($exp) || Js::num($exp) <= 0) {
            throw new \RangeException('grantToPermissionRequest: bad envelope');
        }
        if (!self::test(self::HEX_ADDR, self::get($o, 'sessionAccount')) || (self::has($o, 'from') && !self::test(self::HEX_ADDR, Js::opt($o, 'from')))
            || (self::has($o, 'tokenAddress') && !self::test(self::HEX_ADDR, Js::opt($o, 'tokenAddress')))) {
            throw new \RangeException('grantToPermissionRequest: bad address');
        }
        $bupm = Js::opt($o, 'baseUnitsPerMinor');
        if (!self::test(self::DEC, $bupm) || $bupm === '0') {
            throw new \RangeException('grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string');
        }
        $c = Js::opt($o, 'chainId');
        $chain = $c instanceof \GMP ? $c : (is_int($c) || (is_string($c) && preg_match('/\A-?[0-9]+\z/', $c) === 1) ? gmp_init($c, 10) : null);
        if ($chain === null) {
            throw new \TypeError('grantToPermissionRequest: chainId must be an integer');
        }
        if (gmp_sign($chain) <= 0) {
            throw new \RangeException('grantToPermissionRequest: bad chain');
        }
        $allowance = self::hex(gmp_mul(self::bigInt($cap), self::bigInt($bupm)));
        $adj = Js::opt($o, 'isAdjustmentAllowed') ?? true;
        $req = ['chainId' => self::hex($chain)];
        if (self::has($o, 'from')) {
            $req['from'] = Js::opt($o, 'from');
        }
        $req['to'] = Js::opt($o, 'sessionAccount');
        $req['permission'] = self::has($o, 'tokenAddress')
            ? ['type' => 'erc20-token-allowance', 'isAdjustmentAllowed' => $adj, 'data' => ['tokenAddress' => Js::opt($o, 'tokenAddress'), 'allowance' => $allowance]]
            : ['type' => 'native-token-allowance', 'isAdjustmentAllowed' => $adj, 'data' => ['allowance' => $allowance]];
        $req['rules'] = [['type' => 'expiry', 'data' => ['timestamp' => $exp]]];
        return $req;
    }

    /** wallet_getSupportedExecutionPermissions result filtered to what the request could use. Total (false on anything odd). */
    public static function supportsRequest(mixed $supported, mixed $req): bool
    {
        try {
            $type = self::get(self::get($req, 'permission'), 'type');
            if ($supported === null) {
                throw new \TypeError('supported is null');
            }
            $s = Js::isObj($supported) ? Js::opt($supported, IntentWb::jsStr($type)) : null;
            if ($s === null) {
                return false;
            }
            $ids = self::get($s, 'chainIds');
            if (!is_array($ids) || !array_is_list($ids) || !in_array(self::lower(self::get($req, 'chainId')), array_map(self::lower(...), $ids), true)) {
                return false;
            }
            $rt = self::get($s, 'ruleTypes') ?? self::get($s, 'rulesTypes'); // the draft spells both
            $rules = self::get($req, 'rules') ?? [];
            if (!is_array($rules) || !array_is_list($rules)) {
                throw new \TypeError('rules.every is not a function');
            }
            foreach ($rules as $r) {
                $t = self::get($r, 'type');
                if (!is_array($rt) || !array_is_list($rt) || $t === null || !in_array($t, $rt, true)) {
                    return false;
                }
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function revokeParams(mixed $context): array
    {
        return ['permissionContext' => $context];
    }

    /** The JS relational operand value of a grant's expiresAtSec (missing: NaN; null: 0; a string: Number(s)). */
    private static function relNum(mixed $g, string $k): float
    {
        if ($g === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        if (!self::has($g, $k)) {
            return NAN;
        }
        $v = Js::opt($g, $k);
        return match (true) {
            $v === null => 0.0,
            is_bool($v) => $v ? 1.0 : 0.0,
            is_string($v) => IntentWb::jsNumber($v),
            Js::isNum($v) => (float)Js::num($v),
            default => IntentWb::jsNumber(IntentWb::jsStr($v)),
        };
    }

    /**
     * null when what the wallet granted is within the request and the grant, else the reason. Options: allowedManagers (delegation
     * managers trusted for this chain, case-insensitive), contextOwner (callable(string $context): ?string, the grant digest a
     * context handle is already bound to). Fail-strict: an unknown permission or rule type, any widening, a missing expiry, an
     * unexpected chain / account / manager is refused. Never throws (a hostile shape is 'response_malformed').
     */
    public static function verifyGrantedPermission(mixed $g, mixed $sent, mixed $got, mixed $o): ?string
    {
        try {
            $perm = Js::opt($got, 'permission');
            if (!($perm instanceof Obj) && !is_array($perm)) {
                return 'response_malformed';
            }
            $ctx = Js::opt($got, 'context');
            if (!is_string($ctx) || preg_match('/\A0x[0-9a-fA-F]+\z/', $ctx) !== 1) {
                return 'context_malformed';
            }
            $co = Js::opt($o, 'contextOwner');
            $owner = is_callable($co) ? $co($ctx) : null;
            if ($owner !== null && $owner !== self::get($g, 'grantDigest')) {
                return 'context_bound_to_other_grant';
            }
            $mgr = Js::opt($got, 'delegationManager');
            if (!is_string($mgr) || preg_match(self::HEX_ADDR, $mgr) !== 1) {
                return 'delegation_manager_not_allowed';
            }
            $allowed = self::get($o, 'allowedManagers');
            if (!is_array($allowed) || !array_is_list($allowed)) {
                throw new \TypeError('allowedManagers.map is not a function');
            }
            if (!in_array(self::lower($mgr), array_map(self::lower(...), $allowed), true)) {
                return 'delegation_manager_not_allowed';
            }
            if (self::lower(IntentWb::jsStr(Js::opt($got, 'chainId'))) !== self::lower(self::get($sent, 'chainId'))) {
                return 'chain_mismatch';
            }
            if (self::lower(IntentWb::jsStr(Js::opt($got, 'to'))) !== self::lower(self::get($sent, 'to'))) {
                return 'recipient_mismatch';
            }
            if (self::has($sent, 'from') && self::lower(IntentWb::jsStr(Js::opt($got, 'from'))) !== self::lower(Js::opt($sent, 'from'))) {
                return 'from_mismatch';
            }
            $pt = Js::opt($perm, 'type');
            $sperm = self::get($sent, 'permission');
            if ($pt !== self::get($sperm, 'type') || !in_array($pt, ['native-token-allowance', 'erc20-token-allowance'], true)) {
                return 'permission_type_mismatch';
            }
            $d = Js::opt($perm, 'data');
            $sd = self::get($sperm, 'data');
            $tok = static fn(mixed $x): string => self::lower(IntentWb::jsStr(self::get($x, 'tokenAddress') ?? ''));
            if ($tok($d) !== $tok($sd)) {
                return 'token_mismatch';
            }
            $amt = self::get($d, 'allowance');
            if (!is_string($amt) || preg_match(self::HEX_QTY, $amt) !== 1) {
                return 'amount_malformed';
            }
            if (gmp_cmp(self::bigInt($amt), self::bigInt(self::get($sd, 'allowance'))) > 0) {
                return 'amount_widened';
            }
            if (Js::opt($perm, 'isAdjustmentAllowed') === true && Js::opt($sperm, 'isAdjustmentAllowed') !== true) {
                return 'adjustment_widened';
            }
            $rules = Js::opt($got, 'rules');
            if (!is_array($rules) || !array_is_list($rules)) {
                return 'expiry_missing';
            }
            $expiry = null;
            foreach ($rules as $rule) {
                if (($rule === null ? null : Js::opt($rule, 'type')) !== 'expiry') {
                    return 'unknown_rule_type';
                }
                if ($expiry !== null) {
                    return 'duplicate_expiry';
                }
                $expiry = self::get(self::get($rule, 'data'), 'timestamp');
                if (!K3Sig::anySafeInt($expiry) || K3Sig::isNegZero($expiry)) {
                    return 'expiry_malformed';
                }
            }
            if ($expiry === null) {
                return 'expiry_missing';
            }
            return Js::num($expiry) > self::relNum($g, 'expiresAtSec') ? 'expiry_extended' : null;
        } catch (\Throwable) {
            return 'response_malformed';
        }
    }

    /** hashCanonical(grant) of the JS value (numbers normalized as JSON.parse reads them). */
    public static function grantDigestOf(mixed $grant): string
    {
        return Pca::hashCanonical(IntentWb::norm($grant));
    }
}
