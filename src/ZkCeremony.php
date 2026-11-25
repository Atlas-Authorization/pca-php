<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';

/**
 * Trusted-setup bookkeeping for the Groth16 circuits (pure: no file or process access). A verifying key is only as trustworthy as the
 * ceremony that made it; {@see ceremonyOf} answers `multi-party` ONLY when the caller supplies a transcript, pins its SHA-256
 * (published out of band by the ceremony coordinator), the transcript is well-formed (at least two distinct contributions chained
 * from the initial key, a public random beacon applied last) and names exactly this verifying key. Everything else is
 * `single-party`. The cryptographic check of the contributions themselves is the ceremony tooling's job; nothing here claims more
 * than the pinned transcript says. Values are parsed JSON (Obj, lists, strings, numbers); every check fails closed on an odd shape.
 */
final class ZkCeremony
{
    private const H64 = '/\A[0-9a-f]{64}\z/';

    /** The reference's `undefined`: an absent member (distinct from a JSON null). */
    private static ?\stdClass $absent = null;

    private static function g(mixed $o, string $k): mixed
    {
        return Js::has($o, $k) ? Js::opt($o, $k) : (self::$absent ??= new \stdClass());
    }

    /** Strict equality of two member values (numbers by value, absent equals absent, an object or a list equals nothing). */
    private static function same(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && Js::num($a) === Js::num($b);
        }
        return ($a === null || is_bool($a) || is_string($a) || $a === self::$absent) && $a === $b;
    }

    /** The SHA-256 test over the text form of a value (the reference tests `String(value)`). */
    private static function h64(mixed $v): bool
    {
        return $v !== self::$absent && preg_match(self::H64, Js::str($v)) === 1;
    }

    private static function safeInt(mixed $v): ?float
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= 9007199254740991.0 ? $f : null;
    }

    /** Id of a verifying key: `vk_` + SHA-256 (hex) of its canonical JSON. A re-setup always yields a new id. */
    public static function vkId(mixed $vkey): string
    {
        return 'vk_' . hash('sha256', Json::canonicalizeNative($vkey));
    }

    /**
     * What a verifying key was built from: `{circuit, sourceSha256, r1csSha256, vkId}` of `$args` {circuit, sourceSha256, r1csSha256, vkey}.
     * Throws for an empty circuit id, a hash that is not 64 lower-case hex digits, or a missing key.
     */
    public static function circuitProvenance(mixed $args): Obj
    {
        $circuit = self::g($args, 'circuit');
        if (!self::h64(self::g($args, 'sourceSha256')) || !self::h64(self::g($args, 'r1csSha256')) || $circuit === '') {
            throw new \InvalidArgumentException('circuitProvenance: bad circuit id or hash');
        }
        if (!Js::has($args, 'vkey') || $circuit === self::$absent) {
            throw new \InvalidArgumentException('circuitProvenance: the circuit id and the verifying key are required');
        }
        return Obj::of(['circuit' => $circuit, 'sourceSha256' => Js::opt($args, 'sourceSha256'), 'r1csSha256' => Js::opt($args, 'r1csSha256'), 'vkId' => self::vkId(Js::opt($args, 'vkey'))]);
    }

    /**
     * First reason `$prov` does not describe `$expect['vkey']` built from the expected sources and constraint system, or null.
     * `$expect` is {circuit, sourceSha256, r1csSha256?, vkey}.
     */
    public static function checkCircuitProvenance(mixed $prov, mixed $expect): ?string
    {
        if (!($prov instanceof Obj) && !is_array($prov)) {
            return 'not a provenance record';
        }
        if (!self::same(self::g($prov, 'circuit'), self::g($expect, 'circuit'))) {
            return 'record is for another circuit';
        }
        if (!self::same(self::g($prov, 'sourceSha256'), self::g($expect, 'sourceSha256'))) {
            return 'circuit sources differ from the pinned version';
        }
        $r = Js::opt($prov, 'r1csSha256');
        if (!is_string($r) || preg_match(self::H64, $r) !== 1 || (Js::has($expect, 'r1csSha256') && $r !== Js::opt($expect, 'r1csSha256'))) {
            return 'constraint system differs';
        }
        if (Js::opt($prov, 'vkId') !== self::vkId(Js::opt($expect, 'vkey'))) {
            return 'verifying key is not the recorded one';
        }
        return null;
    }

    /** SHA-256 (hex) of a transcript's canonical JSON: the value a coordinator publishes and a verifier pins. */
    public static function transcriptSha256(mixed $t): string
    {
        return hash('sha256', Json::canonicalizeNative($t));
    }

    /**
     * The first problem with a ceremony transcript, or null when it is well-formed. `$opts` is null or
     * {minContributions?, r1csSha256?, circuit?}; the contribution minimum is never below 2.
     */
    public static function checkTranscript(mixed $t, mixed $opts = null): ?string
    {
        if (!($t instanceof Obj) || Js::num($t->get('version')) !== 1.0) {
            return 'not a version-1 transcript';
        }
        $circuit = $t->get('circuit');
        if (!is_string($circuit) || $circuit === '') {
            return 'no circuit id';
        }
        if (Js::has($opts, 'circuit') && $circuit !== Js::opt($opts, 'circuit')) {
            return 'transcript is for another circuit';
        }
        if ($t->get('curve') !== 'bn128' && $t->get('curve') !== 'bls12-381') {
            return 'unknown curve';
        }
        foreach (['r1csSha256', 'ptauSha256', 'initZkeySha256'] as $k) {
            if (!self::h64(self::g($t, $k))) {
                return "$k is not a SHA-256";
            }
        }
        if (Js::has($opts, 'r1csSha256') && !self::same(self::g($t, 'r1csSha256'), Js::opt($opts, 'r1csSha256'))) {
            return 'transcript is for a different constraint system';
        }
        $min = 2.0;
        foreach ([Js::num(Js::opt($opts, 'minContributions')), self::safeInt($t->get('minContributions'))] as $m) {
            if ($m !== null) {
                $min = is_nan($m) || is_nan($min) ? NAN : max($min, $m);
            }
        }
        $cs = $t->get('contributions');
        if (!is_array($cs) || !array_is_list($cs) || count($cs) < $min) {
            return 'fewer than ' . Js::str($min) . ' contributions';
        }
        $names = [];
        $keys = [];
        $prev = self::g($t, 'initZkeySha256');
        foreach ($cs as $i => $c) {
            $index = Js::num(Js::opt($c, 'index'));
            $name = Js::opt($c, 'name');
            if (!Js::truthy($c) || $index !== (float) $i || ($i === 0 && fdiv(1.0, $index) < 0) || !is_string($name) || $name === '') {
                return "contribution $i is malformed";
            }
            $key = self::g($c, 'zkeySha256');
            if (!self::h64($key) || !self::same(self::g($c, 'prevZkeySha256'), $prev)) {
                return "contribution $i does not chain from the previous key";
            }
            if (isset($names[$name]) || (is_string($key) && isset($keys[$key]))) {
                return "contribution $i repeats a name or key";
            }
            $names[$name] = true;
            if (is_string($key)) {
                $keys[$key] = true;
            }
            $prev = $key;
        }
        $b = $t->get('beacon');
        $exp = self::safeInt(Js::opt($b, 'iterationsExp'));
        if (!Js::truthy($b) || !self::h64(self::g($b, 'hashHex')) || $exp === null || $exp < 10 || $exp > 63) {
            return 'no valid random beacon';
        }
        if (!self::same(self::g($b, 'prevZkeySha256'), $prev) || !self::h64(self::g($b, 'zkeySha256'))) {
            return 'beacon is not applied after the last contribution';
        }
        if (!self::same(self::g($t, 'finalZkeySha256'), self::g($b, 'zkeySha256'))) {
            return 'final key is not the beacon output';
        }
        $vk = $t->get('vkId');
        if (!is_string($vk) || preg_match('/\Avk_[0-9a-f]{64}\z/', $vk) !== 1) {
            return 'no verifying-key id';
        }
        return null;
    }

    /**
     * `multi-party` only when `$evidence` {transcript, sha256, r1csSha256?, circuit?} pins the transcript's hash, the transcript is
     * well-formed and names `$vkey`. Anything else, including an error, is `single-party`.
     */
    public static function ceremonyOf(mixed $vkey, mixed $evidence = null): string
    {
        try {
            if (!Js::truthy($vkey) || !Js::truthy($evidence)) {
                return 'single-party';
            }
            $t = Js::opt($evidence, 'transcript');
            $opts = [];
            foreach (['r1csSha256', 'circuit'] as $k) {
                if (Js::has($evidence, $k)) {
                    $opts[$k] = Js::opt($evidence, $k);
                }
            }
            if (self::checkTranscript($t, $opts === [] ? null : $opts) !== null) {
                return 'single-party';
            }
            if (self::transcriptSha256($t) !== Js::opt($evidence, 'sha256') || $t->get('vkId') !== self::vkId($vkey)) {
                return 'single-party';
            }
            return 'multi-party';
        } catch (\Throwable) {
            return 'single-party';
        }
    }
}
