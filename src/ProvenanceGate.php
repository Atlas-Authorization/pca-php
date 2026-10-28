<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Build provenance as a K1 discharge (track K9): a port of provenance-gate.ts (security contract C-520..C-526). The policy half
 * of a Sigstore / SLSA provenance check: RFC 9162 inclusion, `gate` (facts against the verifier's pinned signer-builder pairs)
 * and `caveat` (`needs_discharge` with issuer_class "artifact").
 *
 * Values are the SDK's JSON model: Obj, list arrays, string, Num (or a native int / float), bool, null. `gate` returns
 * `['ok' => true, 'level' => int, 'claims' => array]` or `['ok' => false, 'code' => string]`. Everything is total.
 */
final class ProvenanceGate
{
    public const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';
    public const INTOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
    private const HEX = ['sha256' => '/\A[0-9a-f]{64}\z/D', 'sha512' => '/\A[0-9a-f]{128}\z/D'];

    /** RFC 9162 section 2.1.1: SHA-256(0x00 || data). */
    public static function rfc9162LeafHash(string $data): string
    {
        return hash('sha256', "\x00" . $data, true);
    }

    private static function b32(mixed $v): bool
    {
        return is_string($v) && strlen($v) === 32;
    }

    /** A safe-integer JSON number as a PHP int (callers check IntentWb::isSafeInt first). */
    private static function n(mixed $v): int
    {
        if ($v instanceof Num) {
            return $v->isInt() ? (int)$v->lexeme : (int)$v->float();
        }
        return (int)$v;
    }

    /** RFC 9162 section 2.1.3.2. `$proof` runs from the leaf level up. False on any malformed input. */
    public static function verifyRfc9162Inclusion(mixed $leafHash, mixed $index, mixed $size, mixed $proof, mixed $root): bool
    {
        try {
            if (!(IntentWb::isSafeInt($index) && IntentWb::isSafeInt($size))) {
                return false;
            }
            $fn = self::n($index);
            $size = self::n($size);
            if (!($fn >= 0 && $size >= 1 && $fn < $size) || !self::b32($leafHash) || !self::b32($root)) {
                return false;
            }
            if (!is_array($proof) || !array_is_list($proof) || count($proof) > 64) {
                return false;
            }
            foreach ($proof as $p) {
                if (!self::b32($p)) {
                    return false;
                }
            }
            $sn = $size - 1;
            $r = $leafHash;
            foreach ($proof as $p) {
                if ($sn === 0) {
                    return false;
                }
                if (($fn & 1) === 1 || $fn === $sn) {
                    $r = hash('sha256', "\x01" . $p . $r, true);
                    if (($fn & 1) === 0) {
                        while (($fn & 1) === 0 && $fn !== 0) {
                            $fn >>= 1;
                            $sn >>= 1;
                        }
                    }
                } else {
                    $r = hash('sha256', "\x01" . $r . $p, true);
                }
                $fn >>= 1;
                $sn >>= 1;
            }
            return $sn === 0 && hash_equals($r, $root);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Non-empty string of at most `$max` UTF-8 bytes. */
    private static function str(mixed $v, int $max = 2048): bool
    {
        return is_string($v) && $v !== '' && strlen($v) <= $max;
    }

    private static function level(mixed $v): bool
    {
        return IntentWb::isSafeInt($v) && in_array(self::n($v), [1, 2, 3], true);
    }

    /** JS String.length (UTF-16 code units) of a UTF-8 string: non-continuation bytes, plus one per 4-byte sequence. */
    private static function utf16Len(string $s): int
    {
        return preg_match_all('/[^\x80-\xBF]/', $s) + preg_match_all('/[\xF0-\xF7]/', $s);
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function closed(Obj $o, array $required, array $optional = [], string $where = 'object'): ?string
    {
        foreach (IntentWb::jsKeys($o) as $k) {
            if (!in_array($k, $required, true) && !in_array($k, $optional, true)) {
                return "unknown member '$where.$k'";
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return "missing member '$where.$k'";
            }
        }
        return null;
    }

    private static function subjectError(mixed $s): bool
    {
        if (!($s instanceof Obj) || self::closed($s, ['alg', 'digest']) !== null) {
            return true;
        }
        $alg = $s->get('alg');
        $d = $s->get('digest');
        return !(is_string($alg) && isset(self::HEX[$alg]) && is_string($d) && preg_match(self::HEX[$alg], $d) === 1);
    }

    /** Null when well-formed (closed members, bounded strings). */
    public static function factsError(mixed $f): ?string
    {
        if (!($f instanceof Obj)) {
            return 'facts must be an object';
        }
        $e = self::closed($f, ['v', 'predicate_type', 'build_type', 'builder_id', 'subjects', 'identity', 'oidc_issuer', 'integrated_time', 'rekor_log_index'],
            ['source_repo', 'source_ref', 'source_digest', 'provenance_source'], 'facts');
        if ($e !== null) {
            return $e;
        }
        if (!(IntentWb::isSafeInt($f->get('v')) && self::n($f->get('v')) === 1)) {
            return 'facts.v must be 1';
        }
        foreach (['predicate_type', 'build_type', 'builder_id', 'identity', 'oidc_issuer'] as $k) {
            if (!self::str($f->get($k))) {
                return "facts.$k must be a non-empty string";
            }
        }
        foreach (['source_repo', 'source_ref', 'source_digest'] as $k) {
            if ($f->has($k) && !self::str($f->get($k))) {
                return "facts.$k must be a non-empty string";
            }
        }
        $s = $f->get('subjects');
        if (!self::isList($s) || count($s) < 1 || count($s) > 64 || array_filter($s, static fn($x) => self::subjectError($x)) !== []) {
            return 'facts.subjects must be 1..64 {alg, digest}';
        }
        foreach (['integrated_time', 'rekor_log_index'] as $k) {
            if (!(IntentWb::isSafeInt($f->get($k)) && self::n($f->get($k)) >= 0)) {
                return "facts.$k must be a non-negative integer";
            }
        }
        if ($f->has('provenance_source')) {
            $p = $f->get('provenance_source');
            if (!($p instanceof Obj) || self::closed($p, ['uri'], ['git_commit']) !== null || !self::str($p->get('uri'))
                || ($p->has('git_commit') && !self::str($p->get('git_commit')))) {
                return 'facts.provenance_source is malformed';
            }
        }
        return null;
    }

    /** Null when well-formed. */
    public static function policyError(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'policy must be an object';
        }
        $e = self::closed($p, ['roots', 'min_level'], ['source_repo', 'source_ref', 'source_ref_prefix', 'build_types', 'max_age_s', 'require_runtime'], 'policy');
        if ($e !== null) {
            return $e;
        }
        $roots = $p->get('roots');
        if (!self::isList($roots) || count($roots) < 1 || count($roots) > 32) {
            return 'policy.roots must hold 1..32 pairs';
        }
        foreach ($roots as $r) {
            if (!($r instanceof Obj) || self::closed($r, ['oidc_issuer', 'builder_id', 'level'], ['identity', 'identity_prefix']) !== null) {
                return 'policy root is malformed';
            }
            if (!self::str($r->get('oidc_issuer')) || !self::str($r->get('builder_id'))) {
                return 'policy root needs oidc_issuer and builder_id';
            }
            if ($r->has('identity') === $r->has('identity_prefix')) {
                return 'policy root needs exactly one of identity and identity_prefix';
            }
            if ($r->has('identity') && !self::str($r->get('identity'))) {
                return 'policy root identity is malformed';
            }
            // a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing
            if ($r->has('identity_prefix') && !(self::str($r->get('identity_prefix')) && self::utf16Len($r->get('identity_prefix')) >= 10)) {
                return 'policy root identity_prefix must be at least 10 characters';
            }
            if (!self::level($r->get('level'))) {
                return 'policy root level must be 1, 2 or 3';
            }
        }
        if (!self::level($p->get('min_level'))) {
            return 'policy.min_level must be 1, 2 or 3';
        }
        if ($p->has('source_repo') && !self::str($p->get('source_repo'))) {
            return 'policy.source_repo is malformed';
        }
        if ($p->has('source_ref') && $p->has('source_ref_prefix')) {
            return 'policy takes source_ref or source_ref_prefix, not both';
        }
        if ($p->has('source_ref') && !self::str($p->get('source_ref'))) {
            return 'policy.source_ref is malformed';
        }
        if ($p->has('source_ref_prefix') && !self::str($p->get('source_ref_prefix'))) {
            return 'policy.source_ref_prefix is malformed';
        }
        if ($p->has('build_types')) {
            $b = $p->get('build_types');
            if (!(self::isList($b) && count($b) >= 1 && count($b) <= 16 && array_filter($b, static fn($x) => !self::str($x)) === [])) {
                return 'policy.build_types must hold 1..16 strings';
            }
        }
        if ($p->has('max_age_s') && !(IntentWb::isSafeInt($p->get('max_age_s')) && self::n($p->get('max_age_s')) >= 1)) {
            return 'policy.max_age_s must be a positive integer';
        }
        if ($p->has('require_runtime') && !is_bool($p->get('require_runtime'))) {
            return 'policy.require_runtime must be a boolean';
        }
        return null;
    }

    /**
     * The provenance gates in the reference order (provenanceGate): policy, facts, clock, runtime shape, predicate type, time,
     * pinned pair and level, provenance source, source pins, build type, subject, claim lengths. Total.
     *
     * @return array{ok: bool, code?: string, level?: int, claims?: array<string, string|int|bool>}
     */
    public static function gate(mixed $input): array
    {
        $no = static fn(string $code): array => ['ok' => false, 'code' => $code];
        try {
            if (!($input instanceof Obj)) {
                return $no('malformed_facts');
            }
            $f = $input->get('facts');
            $p = $input->get('policy');
            $now = $input->get('now');
            if (self::policyError($p) !== null) {
                return $no('malformed_policy');
            }
            if (self::factsError($f) !== null) {
                return $no('malformed_facts');
            }
            if (!(IntentWb::isSafeInt($now) && self::n($now) >= 0)) {
                return $no('malformed_facts');
            }
            $now = self::n($now);
            $hasRt = $input->has('runtime');
            $rt = $input->get('runtime');
            if ($hasRt && self::subjectError($rt)) {
                return $no('malformed_runtime');
            }
            if ($f->get('predicate_type') !== self::SLSA_PROVENANCE_V1) {
                return $no('predicate_type');
            }
            $it = self::n($f->get('integrated_time'));
            if ($it > $now) {
                return $no('future');
            }
            if ($p->has('max_age_s') && $now - $it > self::n($p->get('max_age_s'))) {
                return $no('stale');
            }
            $level = 0;
            $id = $f->get('identity');
            foreach ($p->get('roots') as $r) {
                if ($r->get('oidc_issuer') !== $f->get('oidc_issuer') || $r->get('builder_id') !== $f->get('builder_id')) {
                    continue;
                }
                if ($r->has('identity') ? $r->get('identity') !== $id : !str_starts_with($id, $r->get('identity_prefix'))) {
                    continue;
                }
                $level = max($level, self::n($r->get('level')));
            }
            if ($level === 0) {
                return $no('no_root');
            }
            if ($level < self::n($p->get('min_level'))) {
                return $no('level');
            }
            if ($f->has('provenance_source')) {
                $ps = $f->get('provenance_source');
                if ($ps->has('git_commit') && $f->has('source_digest') && $ps->get('git_commit') !== $f->get('source_digest')) {
                    return $no('source_mismatch');
                }
                if ($f->has('source_repo')) {
                    $g = 'git+' . $f->get('source_repo');
                    if (!($ps->get('uri') === $g || str_starts_with($ps->get('uri'), $g . '@'))) {
                        return $no('source_mismatch');
                    }
                }
            }
            if ($p->has('source_repo') && $f->get('source_repo') !== $p->get('source_repo')) {
                return $no('source_repo');
            }
            if ($p->has('source_ref') && $f->get('source_ref') !== $p->get('source_ref')) {
                return $no('source_ref');
            }
            if ($p->has('source_ref_prefix') && !($f->has('source_ref') && str_starts_with($f->get('source_ref'), $p->get('source_ref_prefix')))) {
                return $no('source_ref');
            }
            if ($p->has('build_types') && !in_array($f->get('build_type'), $p->get('build_types'), true)) {
                return $no('build_type');
            }
            $subjects = $f->get('subjects');
            $bound = false;
            if ($hasRt) {
                $subject = null;
                foreach ($subjects as $s) {
                    if ($s->get('alg') === $rt->get('alg') && $s->get('digest') === $rt->get('digest')) {
                        $subject = $s;
                        break;
                    }
                }
                if ($subject === null) {
                    return $no('runtime_mismatch');
                }
                $bound = true;
            } else {
                if ($p->get('require_runtime') === true) {
                    return $no('runtime_required');
                }
                if (count($subjects) !== 1) {
                    return $no('subject_ambiguous');
                }
                $subject = $subjects[0];
            }
            $claims = [
                'subject_alg' => $subject->get('alg'),
                'subject_digest' => $subject->get('digest'),
                'slsa_level' => $level,
                'builder_id' => $f->get('builder_id'),
                'build_type' => $f->get('build_type'),
                'oidc_issuer' => $f->get('oidc_issuer'),
                'identity' => $id,
            ];
            foreach (['source_repo', 'source_ref', 'source_digest'] as $k) {
                if ($f->has($k)) {
                    $claims[$k] = $f->get($k);
                }
            }
            $claims['rekor_log_index'] = self::n($f->get('rekor_log_index'));
            $claims['runtime_bound'] = $bound;
            foreach ($claims as $v) {
                if (is_string($v) && strlen($v) > 256) {
                    return $no('claim_too_long');
                }
            }
            return ['ok' => true, 'level' => $level, 'claims' => $claims];
        } catch (\Throwable) {
            return $no('malformed_facts');
        }
    }

    /**
     * A `needs_discharge` caveat that asks the pinned `artifact` verifier for provenance claims. Options as in the reference
     * (ProvenanceCaveatOptions): issuer, min_level, and optional id, source_repo, builder_ids, oidc_issuer, require_runtime
     * (default true), bind (default "action"), ttl_ms (default 300000).
     */
    public static function caveat(array $o): Obj
    {
        $req = [Obj::of(['claim' => 'slsa_level', 'op' => 'gte', 'value' => $o['min_level']])];
        if (isset($o['source_repo'])) {
            $req[] = Obj::of(['claim' => 'source_repo', 'op' => 'eq', 'value' => $o['source_repo']]);
        }
        if (isset($o['builder_ids'])) {
            $req[] = Obj::of(['claim' => 'builder_id', 'op' => 'in', 'value' => array_values($o['builder_ids'])]);
        }
        if (isset($o['oidc_issuer'])) {
            $req[] = Obj::of(['claim' => 'oidc_issuer', 'op' => 'eq', 'value' => $o['oidc_issuer']]);
        }
        if (($o['require_runtime'] ?? true) !== false) {
            $req[] = Obj::of(['claim' => 'runtime_bound', 'op' => 'eq', 'value' => true]);
        }
        return Obj::of(['type' => 'needs_discharge', 'id' => $o['id'] ?? 'provenance', 'issuer' => $o['issuer'], 'issuer_class' => 'artifact',
            'bind' => $o['bind'] ?? 'action', 'ttl_ms' => $o['ttl_ms'] ?? 300_000, 'require' => $req]);
    }
}
