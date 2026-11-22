<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The type is
 * a pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Total: never throws. Results:
 * validate -> null (accepted) or a code; parse -> [list, null] or [null, code]; check -> [index, null] or [null, code].
 */
final class PcaGrant
{
    public const TYPE = 'pca_grant';
    public const DOMAIN = 'atlas-pca/pca-grant-chain/v1';
    private const MEMBERS = ['type', 'chain_digest', 'chain_len', 'chain_ref', 'bundle_revision', 'locations'];
    private const REFUSED = ['actions', 'datatypes', 'identifier', 'privileges'];

    /** https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'. */
    public static function isHttpsUrl(mixed $u): bool
    {
        if (!is_string($u) || strlen($u) > 2048 || !str_starts_with($u, 'https://')) {
            return false;
        }
        for ($i = 0, $n = strlen($u); $i < $n; $i++) {
            $c = ord($u[$i]);
            if ($c < 0x21 || $c > 0x7e || $c === 0x23 || $c === 0x5c) {
                return false;
            }
        }
        $rest = substr($u, 8);
        $cut = strcspn($rest, '/?');
        $authority = substr($rest, 0, $cut);
        return $authority !== '' && !str_contains($authority, '@');
    }

    /** @param list<string> $ids */
    public static function chainDigest(array $ids): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::DOMAIN, 'ids' => array_values($ids)]));
    }

    public static function validate(mixed $x): ?string
    {
        if (!($x instanceof Obj)) {
            return 'bad_entry';
        }
        if ($x->get('type') !== self::TYPE) {
            return 'bad_type';
        }
        foreach ($x->keys() as $k) {
            if (in_array($k, self::REFUSED, true)) {
                return 'refused_member';
            }
            if (!in_array($k, self::MEMBERS, true)) {
                return 'unknown_member';
            }
        }
        $d = $x->get('chain_digest');
        if (!is_string($d) || Pca::unb64u($d, 32) === null) {
            return 'bad_chain_digest';
        }
        $n = $x->get('chain_len');
        if (!K3Sig::anySafeInt($n) || K3Sig::num($n) < 1.0 || K3Sig::num($n) > 16.0) {
            return 'bad_chain_len';
        }
        if ($x->has('chain_ref') && !self::isHttpsUrl($x->get('chain_ref'))) {
            return 'bad_chain_ref';
        }
        if ($x->has('bundle_revision') && !K3Sig::isSafeInt($x->get('bundle_revision'))) {
            return 'bad_bundle_revision';
        }
        if ($x->has('locations')) {
            $l = $x->get('locations');
            if (!K3Sig::isList($l) || count($l) === 0 || count($l) > 8) {
                return 'bad_locations';
            }
            foreach ($l as $u) {
                if (!self::isHttpsUrl($u)) {
                    return 'bad_locations';
                }
            }
        }
        return null;
    }

    /** @return array{0: ?list<Obj>, 1: ?string} */
    public static function parse(mixed $arr): array
    {
        if (!K3Sig::isList($arr)) {
            return [null, 'not_an_array'];
        }
        if (count($arr) > 16) {
            return [null, 'too_many_details'];
        }
        $out = [];
        foreach ($arr as $e) {
            if (!($e instanceof Obj) || !is_string($e->get('type'))) {
                return [null, 'bad_entry'];
            }
            if ($e->get('type') !== self::TYPE) {
                continue;
            }
            $code = self::validate($e);
            if ($code !== null) {
                return [null, $code];
            }
            $out[] = $e;
        }
        return [$out, null];
    }

    /**
     * Allow only with a verified per-action proof (exactly true) and a detail naming a prefix of the presented chain (and this resource).
     * @param list<Obj> $details @param list<string> $chainIds
     * @return array{0: ?int, 1: ?string}
     */
    public static function check(array $details, string $resource, array $chainIds, mixed $proofVerified): array
    {
        if (count($details) === 0) {
            return [null, 'no_detail'];
        }
        if ($proofVerified !== true) {
            return [null, 'proof_required'];
        }
        $reason = 'chain_mismatch';
        foreach ($details as $i => $d) {
            $n = (int)K3Sig::num($d->get('chain_len'));
            if (count($chainIds) < $n || self::chainDigest(array_slice($chainIds, 0, $n)) !== $d->get('chain_digest')) {
                continue;
            }
            if ($d->has('locations') && !in_array($resource, $d->get('locations'), true)) {
                $reason = 'wrong_location';
                continue;
            }
            return [$i, null];
        }
        return [null, $reason];
    }
}
