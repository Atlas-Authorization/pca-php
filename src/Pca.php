<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';

/**
 * Reference verifier for the CORE PCActn checks: capability chain, Merkle plan inclusion,
 * Ed25519 leaf signature, counter. Port of the Go reference verifier (byte-matches @atlasauth/pca).
 * Inputs come from Json::parse (json_decode with objects as stdClass).
 */
final class Pca
{
    public const SIG_DOMAIN = "atlas-pca/actn/v1\0";
    public const CAP_DOMAIN = "atlas-pca/cap/v1\0";
    public const DEFAULT_REV = 'reversible';

    // ---- helpers ------------------------------------------------------------------------

    public static function b64u(string $raw): string
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /** Strict decode; null when invalid. */
    public static function unb64u(mixed $s): ?string
    {
        if (!is_string($s)) {
            return null;
        }
        try {
            return sodium_base642bin($s, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\Throwable) {
            return null;
        }
    }

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    public static function hashCanonical(mixed $v): string
    {
        return self::b64u(self::sha(Json::canonicalize($v)));
    }

    /** Property of a decoded JSON object, or null (also null for non-objects). */
    private static function get(mixed $o, string $k): mixed
    {
        if ($o instanceof \stdClass) {
            return property_exists($o, $k) ? $o->$k : null;
        }
        return null;
    }

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof \stdClass && property_exists($o, $k);
    }

    private static function obj(mixed $o): ?\stdClass
    {
        return $o instanceof \stdClass ? $o : null;
    }

    // ---- Merkle -------------------------------------------------------------------------

    private static function leafHash(mixed $leaf): string
    {
        return self::sha("\x00" . Json::canonicalize($leaf));
    }

    private static function nodeHash(string $l, string $r): string
    {
        return self::sha("\x01" . $l . $r);
    }

    private static function split(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return $k;
    }

    private static function build(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = self::split(count($hs));
        return self::nodeHash(self::build(array_slice($hs, 0, $k)), self::build(array_slice($hs, $k)));
    }

    public static function merkleRoot(array $leaves): string
    {
        if (count($leaves) === 0) {
            throw new \InvalidArgumentException('empty leaf set');
        }
        return self::b64u(self::build(array_map([self::class, 'leafHash'], array_values($leaves))));
    }

    /** Never throws; malformed proofs return false. */
    public static function verifyInclusion(string $root, mixed $proof, mixed $leaf): bool
    {
        try {
            $path = self::get($proof, 'path');
            if (!is_array($path)) {
                return false;
            }
            $h = self::leafHash($leaf);
            foreach ($path as $step) {
                if (!($step instanceof \stdClass)) {
                    return false;
                }
                $side = self::get($step, 'side');
                if ($side !== 'L' && $side !== 'R') {
                    return false;
                }
                $sib = self::unb64u(self::get($step, 'hash') ?? '');
                if ($sib === null) {
                    return false;
                }
                $h = $side === 'L' ? self::nodeHash($sib, $h) : self::nodeHash($h, $sib);
            }
            return self::b64u($h) === $root;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function paramsDigest(mixed $params = null): string
    {
        return self::hashCanonical($params ?? new \stdClass());
    }

    private static function conditionsDigest(mixed $pre, mixed $post): string
    {
        return self::hashCanonical((object)['pre' => $pre, 'post' => $post]);
    }

    private static function planLeaf(mixed $nodeId, mixed $action, string $cond): \stdClass
    {
        if ($nodeId === null) {
            throw new \InvalidArgumentException('missing node_id');
        }
        $pd = self::get($action, 'params_digest') ?? self::paramsDigest();
        $rc = self::get($action, 'reversibility_class') ?? self::DEFAULT_REV;
        return (object)[
            'node_id' => $nodeId, 'verb' => self::get($action, 'verb'), 'resource' => self::get($action, 'resource'),
            'params_digest' => $pd, 'reversibility_class' => $rc, 'conditions' => $cond,
        ];
    }

    // ---- keys ---------------------------------------------------------------------------

    private static function verifyB64u(mixed $pub, string $msg, mixed $sig): bool
    {
        $pk = self::unb64u($pub);
        $sg = self::unb64u($sig);
        if ($pk === null || strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        if ($sg === null || strlen($sg) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sg, $msg, $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- capability chain ---------------------------------------------------------------

    public static function capHash(mixed $c): string
    {
        return self::hashCanonical($c);
    }

    private static function bodyOf(\stdClass $c): \stdClass
    {
        return (object)[
            'issuer' => self::get($c, 'issuer'), 'holder' => self::get($c, 'holder'),
            'caveats' => self::get($c, 'caveats'), 'parent' => self::get($c, 'parent'),
        ];
    }

    private static function checkSig(\stdClass $c, mixed $signer, string $label): string
    {
        $digest = self::hashCanonical(self::bodyOf($c));
        $bd = self::get($c, 'body_digest');
        $id = self::get($c, 'id');
        if (!is_string($bd) || $digest !== $bd || $id !== $bd) {
            return $label . ': body digest mismatch';
        }
        $d = self::unb64u($bd);
        if ($d === null || !self::verifyB64u($signer, self::CAP_DOMAIN . $d, self::get($c, 'sig'))) {
            return $label . ': bad signature (not signed by expected key)';
        }
        return '';
    }

    /** @return array{0:string,1:bool} [reason, ok] */
    public static function verifyChain(array $chain, mixed $expectedRootIssuer, bool $haveIssuer): array
    {
        if (count($chain) === 0) {
            return ['empty chain', false];
        }
        $root = self::obj($chain[0]);
        if ($root === null) {
            return ['hop 0: malformed', false];
        }
        if (self::has($root, 'parent')) {
            return ['hop 0: root must not have a parent', false];
        }
        if ($haveIssuer && self::get($root, 'issuer') !== $expectedRootIssuer) {
            return ['hop 0: root issuer is not the expected principal', false];
        }
        if (($e = self::checkSig($root, self::get($root, 'issuer'), 'hop 0')) !== '') {
            return [$e, false];
        }
        for ($i = 1; $i < count($chain); $i++) {
            $parent = self::obj($chain[$i - 1]);
            $c = self::obj($chain[$i]);
            $label = "hop $i";
            if ($parent === null || $c === null) {
                return [$label . ': malformed', false];
            }
            if (self::get($c, 'parent') !== self::capHash($parent)) {
                return [$label . ': broken parent link', false];
            }
            if (self::get($c, 'issuer') !== self::get($parent, 'holder')) {
                return [$label . ': issuer is not the parent\'s bound holder', false];
            }
            if (($e = self::checkSig($c, self::get($parent, 'holder'), $label)) !== '') {
                return [$e, false];
            }
            $pc = self::get($parent, 'caveats');
            $cc = self::get($c, 'caveats');
            $pc = is_array($pc) ? $pc : [];
            $cc = is_array($cc) ? $cc : [];
            if (count($cc) < count($pc)) {
                return [$label . ': drops parent caveat(s)', false];
            }
            foreach ($pc as $j => $pcv) {
                if (self::hashCanonical($cc[$j]) !== self::hashCanonical($pcv)) {
                    return ["$label: caveat $j altered or reordered", false];
                }
            }
        }
        return ['', true];
    }

    // ---- PCActn -------------------------------------------------------------------------

    /** SIG_DOMAIN || sha256(canonical(pcactn without `sig` and `threshold`)). */
    public static function thresholdMessage(\stdClass $p): string
    {
        $body = new \stdClass();
        foreach (get_object_vars($p) as $k => $v) {
            if ($k !== 'sig' && $k !== 'threshold') {
                $body->$k = $v;
            }
        }
        return self::SIG_DOMAIN . self::sha(Json::canonicalize($body));
    }

    /**
     * @return array{allow:bool, checks:array<string,bool>, reason:string}
     */
    public static function verifyPcactnCore(mixed $pcactn, mixed $grant): array
    {
        $v = ['allow' => false, 'reason' => '',
            'checks' => ['chain' => false, 'plan_inclusion' => false, 'leaf_signature' => false, 'counter' => false]];
        $failed = false;
        $fail = function (string $name, string $why) use (&$v, &$failed): void {
            $failed = true;
            if (isset($v['checks'][$name])) {
                $v['checks'][$name] = false;
            }
            if ($v['reason'] === '') {
                $v['reason'] = $name . ': ' . $why;
            }
        };

        try {
            if (self::get($pcactn, 'ver') !== 1) {
                $fail('version', 'unsupported ver');
            }

            $chain = self::get($pcactn, 'cap_chain');
            $chain = is_array($chain) ? $chain : [];
            if (count($chain) === 0) {
                $fail('chain', 'empty chain');
            } else {
                $rootCap = $chain[0];
                if (self::capHash($rootCap) !== self::capHash($grant)) {
                    $fail('chain', 'chain root is not the grant');
                } else {
                    $gi = self::get($grant, 'issuer');
                    [$why, $ok] = self::verifyChain($chain, $gi, is_string($gi));
                    if ($ok) {
                        $v['checks']['chain'] = true;
                    } else {
                        $fail('chain', $why);
                    }
                }
            }

            $plan = self::get($pcactn, 'plan');
            $action = self::get($pcactn, 'action');
            $cond = self::get($plan, 'conditions_digest');
            if (!is_string($cond)) {
                $cond = self::conditionsDigest(null, null);
            }
            $root = self::get($plan, 'root');
            $proof = self::get($plan, 'inclusion_proof');
            $included = false;
            try {
                $leaf = self::planLeaf(self::get($plan, 'node_id'), $action, $cond);
                $included = is_string($root) && self::verifyInclusion($root, $proof, $leaf);
            } catch (\InvalidArgumentException) {
            }
            if ($included) {
                $v['checks']['plan_inclusion'] = true;
            } else {
                $fail('plan_inclusion', 'action is not a node of the committed plan');
            }

            if (count($chain) > 0) {
                $holder = self::get(end($chain), 'holder');
                $sig = self::get($pcactn, 'sig');
                $msg = self::thresholdMessage($pcactn);
                if (is_string($sig) && self::verifyB64u($holder, $msg, $sig)) {
                    $v['checks']['leaf_signature'] = true;
                } else {
                    $fail('leaf_signature', 'signature does not verify under the leaf holder key');
                }
            } else {
                $fail('leaf_signature', 'signature does not verify under the leaf holder key');
            }

            $counter = self::get($pcactn, 'counter');
            if (is_int($counter) && $counter >= 0) {
                $v['checks']['counter'] = true;
            } else {
                $fail('counter', 'missing or not a non-negative integer');
            }

            $v['allow'] = !$failed;
        } catch (\Throwable $e) {
            $v['allow'] = false;
            $v['reason'] = 'malformed PCActn: ' . $e->getMessage();
        }
        return $v;
    }
}
