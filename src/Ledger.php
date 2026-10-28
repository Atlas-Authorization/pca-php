<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * Transparency-ledger verification (every signature suite this runtime implements; a PQ key only under a verifier pin): RFC 6962 inclusion, RFC 9162 consistency, signed tree heads, witness
 * cosignatures, checkpoint chains, legacy witnessed heads and equivocation. Every function is total: any malformed input
 * returns false / a failing verdict, never throws. Verdicts match the shared extension-layer vectors (ledger-vectors.json).
 * Inputs are the library's JSON values (Obj, lists, strings, Num). `$pins` is { ed25519 identity => ML-DSA-65 public key }: a
 * pure-PQ or hybrid artifact verifies only under the pin of the identity it names. `null` = absent (cosigners then fall back to
 * the policy's `pqPins`), an empty set is explicit and replaces them.
 */
final class Ledger
{
    public const STH_DOMAIN = "atlas-pca/sth/v1\0";
    public const STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\0";
    public const HEAD_DOMAIN = "atlas-pca/ledger-head/v1\0";
    /** The longest path a tree of fewer than 2^53 leaves can need. */
    private const MAX_CONSISTENCY_PATH = 2 * 53 + 2;
    private const MAX_SAFE = 9007199254740991;

    public static function emptyTreeRoot(): string
    {
        return Pca::b64u(hash('sha256', '', true));
    }

    /** A JSON number (Num or native) as a float, else null. */
    private static function num(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    /** JS Number.isSafeInteger: a number, integral, within +-(2^53-1). */
    private static function safeInt(mixed $x): bool
    {
        $v = self::num($x);
        return $v !== null && floor($v) === $v && abs($v) <= self::MAX_SAFE;
    }

    private static function int(mixed $x): int
    {
        return (int)self::num($x);
    }

    /** @return string the member list as a body Obj; throws when a member is absent (a refusal) */
    private static function pick(Obj $o, array $keys): Obj
    {
        $b = new Obj();
        foreach ($keys as $k) {
            if (!$o->has($k)) {
                throw new \InvalidArgumentException("missing $k");
            }
            $b->set($k, $o->get($k));
        }
        return $b;
    }

    /** The PQ key pinned for `$identity` in `$pins` (an Obj or an array), else null. */
    public static function pinFor(mixed $pins, mixed $identity): ?string
    {
        if (!is_string($identity)) {
            return null;
        }
        $p = $pins instanceof Obj ? ($pins->has($identity) ? $pins->get($identity) : null) : (is_array($pins) ? ($pins[$identity] ?? null) : null);
        return is_string($p) ? $p : null;
    }

    /**
     * A signature of `$m` (alg / pq_pk / sig / pq_sig) over `$domain . canonical(bindSuite($body))` under `$identity`, suite-agile:
     * an absent `alg` is ed25519, an explicit null / unknown / unimplemented one is refused, a PQ half only under `$pins[$identity]`.
     */
    public static function signed(string $domain, Obj $body, mixed $identity, Obj $m, mixed $pins): bool
    {
        if (!is_string($identity) || !is_string($m->get('sig'))) {
            return false;
        }
        $alg = $m->has('alg') ? $m->get('alg') : 'ed25519';
        if (!Pca::suiteImplemented($alg)) {
            return false;
        }
        if ($alg !== 'ed25519') {
            if (!$m->has('pq_pk')) {
                return false;
            }
            $bound = new Obj();
            foreach ($body->keys() as $k) {
                $bound->set($k, $body->get($k));
            }
            $bound->set('alg', $alg);
            $bound->set('pq_pk', $m->get('pq_pk'));
            $body = $bound;
        }
        return Pca::verifyPinnedSuite($alg, $identity, $m->get('pq_pk'), $domain . Json::canonicalizeStrict($body), $m->get('sig'),
            $m->get('pq_sig'), self::pinFor($pins, $identity)) === true;
    }

    private static function nodeHash(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    /** RFC 6962 inclusion of a ledger commit string under `$root`. */
    public static function verifyInclusion(mixed $root, mixed $proof, mixed $commit): bool
    {
        return is_string($root) && Pca::verifyInclusion($root, $proof, $commit);
    }

    /** RFC 9162 section 2.1.4.2 consistency of the tree with `$oldRoot` and the tree with `$newRoot`. */
    public static function verifyConsistency(mixed $oldRoot, mixed $newRoot, mixed $proof): bool
    {
        try {
            if (!is_string($oldRoot) || !is_string($newRoot) || !($proof instanceof Obj)) {
                return false;
            }
            $firstV = $proof->get('oldSize');
            $secondV = $proof->get('newSize');
            if (!self::safeInt($firstV) || !self::safeInt($secondV)) {
                return false;
            }
            $first = self::int($firstV);
            $second = self::int($secondV);
            if ($first < 0 || $first > $second) {
                return false;
            }
            $pathIn = $proof->get('path');
            if (!is_array($pathIn) || !array_is_list($pathIn) || count($pathIn) > self::MAX_CONSISTENCY_PATH) {
                return false;
            }
            $empty = self::emptyTreeRoot();
            if ($first === 0) {
                if ($pathIn !== [] || $oldRoot !== $empty) {
                    return false;
                }
                return $second === 0 ? $newRoot === $empty : true;
            }
            if ($first === $second) {
                return $pathIn === [] && $oldRoot === $newRoot;
            }
            $path = [];
            foreach ($pathIn as $p) {
                $d = Pca::unb64u($p);
                if ($d === null) {
                    return false;
                }
                $path[] = $d;
            }
            if (($first & ($first - 1)) === 0) {
                $o = Pca::unb64u($oldRoot);
                if ($o === null) {
                    return false;
                }
                array_unshift($path, $o);
            }
            if ($path === []) {
                return false;
            }
            $fn = $first - 1;
            $sn = $second - 1;
            while (($fn & 1) === 1) {
                $fn >>= 1;
                $sn >>= 1;
            }
            $fr = $sr = $path[0];
            for ($i = 1; $i < count($path); $i++) {
                $c = $path[$i];
                if ($sn === 0) {
                    return false;
                }
                if (($fn & 1) === 1 || $fn === $sn) {
                    $fr = self::nodeHash($c, $fr);
                    $sr = self::nodeHash($c, $sr);
                    while (($fn & 1) === 0 && $fn !== 0) {
                        $fn >>= 1;
                        $sn >>= 1;
                    }
                } else {
                    $sr = self::nodeHash($sr, $c);
                }
                $fn >>= 1;
                $sn >>= 1;
            }
            return $sn === 0 && Pca::b64u($fr) === $oldRoot && Pca::b64u($sr) === $newRoot;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function witnessBody(Obj $sth): Obj
    {
        $ge = $sth->get('guardian_epoch');
        $body = self::pick($sth, ['instance_id', 'principal', 'size', 'root', 'prev_root']);
        $body->set('guardian_epoch', $ge ?? new Num('0'));
        return $body;
    }

    /** One witness cosignature over the head statement, bound to this exact head. */
    public static function verifyWitnessCosignature(mixed $sth, mixed $cosig, mixed $witnessPublic, mixed $pins = null): bool
    {
        try {
            if (!($sth instanceof Obj) || !($cosig instanceof Obj) || $cosig->get('key') !== $witnessPublic
                || !is_string($cosig->get('sig')) || !is_string($witnessPublic)) {
                return false;
            }
            return self::signed(self::STH_WITNESS_DOMAIN, self::witnessBody($sth), $witnessPublic, $cosig, $pins);
        } catch (\Throwable) {
            return false;
        }
    }

    /** k-of-n: at least `threshold` DISTINCT trusted witnesses carry a valid cosignature. */
    public static function verifyWitnessCosignatures(mixed $sth, mixed $policy, mixed $pins = null): bool
    {
        try {
            if (!($policy instanceof Obj) || !($sth instanceof Obj)) {
                return false;
            }
            $pins ??= $policy->get('pqPins');
            $t = $policy->get('threshold');
            if (!self::safeInt($t) || self::num($t) < 0) {
                return false;
            }
            $threshold = self::int($t);
            if ($threshold === 0) {
                return true;
            }
            $keys = $policy->get('witnessKeys');
            $trusted = is_array($keys) ? array_flip(array_filter($keys, 'is_string')) : [];
            $witnesses = $sth->get('witnesses');
            if ($trusted === [] || !is_array($witnesses) || !array_is_list($witnesses)) {
                return false;
            }
            $counted = [];
            foreach ($witnesses as $w) {
                if (!($w instanceof Obj) || !is_string($w->get('key')) || !is_string($w->get('sig'))) {
                    continue;
                }
                $k = $w->get('key');
                if (!isset($trusted[$k]) || isset($counted[$k]) || !self::verifyWitnessCosignature($sth, $w, $k, $pins)) {
                    continue;
                }
                $counted[$k] = true;
                if (count($counted) >= $threshold) {
                    return true;
                }
            }
            return count($counted) >= $threshold;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Guardian signature over a signed tree head, plus the witness threshold when `$witnessPolicy` is given. */
    public static function verifyTreeHead(mixed $sth, mixed $guardianPublic, mixed $witnessPolicy = null, mixed $pins = null): bool
    {
        try {
            if (!($sth instanceof Obj) || $sth->get('guardian') !== $guardianPublic) {
                return false;
            }
            if (!self::safeInt($sth->get('size')) || self::num($sth->get('size')) < 0) {
                return false;
            }
            $body = self::pick($sth, ['instance_id', 'principal', 'size', 'root', 'prev_root', 'timestamp']);
            if (!self::signed(self::STH_DOMAIN, $body, $guardianPublic, $sth, $pins)) {
                return false;
            }
            return $witnessPolicy === null || self::verifyWitnessCosignatures($sth, $witnessPolicy, $pins);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Both heads genuine, same log, the proof connects them, and (adjacent heads) newer.prev_root == older.root. */
    public static function verifyHeadConsistency(mixed $older, mixed $newer, mixed $proof, mixed $guardianPublic, mixed $witnessPolicy = null, mixed $pins = null): bool
    {
        try {
            if (!self::verifyTreeHead($older, $guardianPublic, $witnessPolicy, $pins) || !self::verifyTreeHead($newer, $guardianPublic, $witnessPolicy, $pins)) {
                return false;
            }
            if (!($proof instanceof Obj) || $older->get('instance_id') !== $newer->get('instance_id')
                || $older->get('principal') !== $newer->get('principal')) {
                return false;
            }
            $os = $proof->get('oldSize');
            $ns = $proof->get('newSize');
            if (!(self::safeInt($os) && self::num($os) === self::num($older->get('size'))
                && self::safeInt($ns) && self::num($ns) === self::num($newer->get('size')))) {
                return false;
            }
            if (self::num($newer->get('size')) === self::num($older->get('size')) + 1 && $newer->get('prev_root') !== $older->get('root')) {
                return false;
            }
            return self::verifyConsistency($older->get('root'), $newer->get('root'), $proof);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify pinned checkpoints end to end.
     * @return array{ok: true}|array{ok: false, at: int} `at` = the index of the first bad checkpoint
     */
    public static function verifyCheckpointChain(mixed $chain, mixed $guardianPublic, mixed $witnessPolicy = null, mixed $pins = null): array
    {
        try {
            if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
                return ['ok' => false, 'at' => 0];
            }
            foreach ($chain as $i => $cp) {
                if (!($cp instanceof Obj) || !self::verifyTreeHead($cp->get('sth'), $guardianPublic, $witnessPolicy, $pins)) {
                    return ['ok' => false, 'at' => $i];
                }
                if ($i === 0) {
                    continue;
                }
                $proof = $cp->get('proof');
                if (!self::truthy($proof) || !self::verifyHeadConsistency($chain[$i - 1]->get('sth'), $cp->get('sth'), $proof, $guardianPublic, $witnessPolicy, $pins)) {
                    return ['ok' => false, 'at' => $i];
                }
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'at' => 0];
        }
    }

    /** Python-style truthiness of a JSON value (None, false, 0, "", [] and {} are false). */
    private static function truthy(mixed $x): bool
    {
        return !($x === null || $x === false || $x === '' || $x === [] || ($x instanceof Num && $x->float() == 0.0)
            || ($x instanceof Obj && $x->keys() === []));
    }

    /** A legacy witness-signed ledger head. */
    public static function verifyWitnessedHead(mixed $wh, mixed $witnessPublic, mixed $pins = null): bool
    {
        try {
            if (!($wh instanceof Obj) || $wh->get('witness') !== $witnessPublic) {
                return false;
            }
            return self::signed(self::HEAD_DOMAIN, self::pick($wh, ['principal', 'size', 'root']), $witnessPublic, $wh, $pins);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Two valid heads of one witness for the same principal and size with different roots. */
    public static function detectEquivocation(mixed $a, mixed $b, mixed $witnessPublic, mixed $pins = null): bool
    {
        try {
            return self::verifyWitnessedHead($a, $witnessPublic, $pins) && self::verifyWitnessedHead($b, $witnessPublic, $pins)
                && $a->get('principal') === $b->get('principal') && self::num($a->get('size')) === self::num($b->get('size'))
                && $a->get('root') !== $b->get('root');
        } catch (\Throwable) {
            return false;
        }
    }
}
