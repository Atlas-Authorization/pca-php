<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Facade.php';
require_once __DIR__ . '/IntentCompilers.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/PolicySim.php';

/**
 * The approval half of natural-language policy authoring: the model's completion is parsed strictly and grounded in the catalog, the draft is
 * content-addressed and bound to the instruction, the model and the prompt, a reviewer signs it, and only a verified, unexpired approval compiles into
 * an agent. The model is an injected `complete(prompt): string`: no model dependency is added. A draft and an approval are the language-neutral JSON of
 * the wire (an Obj). A catalog is a {@see Catalog} (null: the built-in one).
 */
final class NlApproval
{
    public const DOMAIN = "atlas-pca/nl-approval/v1\0";
    public const DOMAIN_V2 = "atlas-pca/nl-approval/v2\0";
    public const MAX_OUTPUT_BYTES = 16384;
    public const MAX_APPROVAL_TTL_MS = 24 * 3600000;
    private const DEFAULT_TTL_MS = 3600000;

    private static function hash(mixed $v): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient($v), true));
    }

    private static function cat(?Catalog $c): Catalog
    {
        return $c ?? Catalog::defaultCatalog();
    }

    /** The specs of a catalog as `nlPrompt` takes them (null for the built-in catalog). @return ?list<array<string,mixed>> */
    private static function specs(?Catalog $c): ?array
    {
        return $c === null ? null : $c->all();
    }

    /** The digest of the catalog vocabulary a draft was grounded against: rows `[verb, reversibility, amountField|null]` sorted by verb (NOT {@see Catalog::catalogDigest}). */
    public static function catalogDigest(?Catalog $catalog = null): string
    {
        $rows = [];
        foreach (self::cat($catalog)->all() as $s) {
            $rows[] = [$s['verb'], $s['reversibility'], $s['amountField'] ?? null];
        }
        usort($rows, static fn(array $a, array $b): int => Actions::u16Order((string)$a[0], (string)$b[0]));
        return self::hash(Obj::of(['v' => 1, 'rows' => $rows]));
    }

    /** `{instruction_digest, model, prompt_digest}`: what a draft is bound to, recomputed from public inputs (the prompt is deterministic). */
    public static function draftBinding(string $instruction, ?Catalog $catalog = null, ?string $model = null): Obj
    {
        return Obj::of(['instruction_digest' => self::hash(Obj::of(['d' => 'atlas-pca/nl-instruction/v1', 'text' => $instruction])), 'model' => $model,
            'prompt_digest' => self::hash(Obj::of(['d' => 'atlas-pca/nl-prompt/v1', 'text' => IntentCompilers::nlPrompt($instruction, self::specs($catalog))]))]);
    }

    /** Connectors and their actions sorted (UTF-16 code unit order), as hashed. */
    private static function sortedPermissions(mixed $permissions): Obj
    {
        $o = new Obj();
        $keys = Jsx::keys($permissions);
        usort($keys, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($keys as $c) {
            $acts = array_values(Jsx::iter(Jsx::get($permissions, $c)));
            usort($acts, static fn($a, $b): int => Actions::u16Order(Jsx::str($a), Jsx::str($b)));
            $o->set($c, $acts);
        }
        return $o;
    }

    /** The digest an approval v2 signs: the v1 content plus `{instruction_digest, model, prompt_digest}`. */
    public static function draftDigestV2(mixed $permissions, mixed $limits, mixed $catalogDigest, mixed $binding): string
    {
        return self::hash(Obj::of(['v' => 2, 'permissions' => self::sortedPermissions($permissions), 'limits' => $limits, 'catalog_digest' => $catalogDigest,
            'instruction_digest' => Jsx::rd($binding, 'instruction_digest'), 'model' => Jsx::get($binding, 'model'), 'prompt_digest' => Jsx::get($binding, 'prompt_digest')]));
    }

    /** The digest a v1 (pre-0.5) reviewer signed: no binding. */
    public static function draftDigest(mixed $permissions, mixed $limits, mixed $catalogDigest): string
    {
        return self::hash(Obj::of(['v' => 1, 'permissions' => self::sortedPermissions($permissions), 'limits' => $limits, 'catalog_digest' => $catalogDigest]));
    }

    /** @return list<array<string,mixed>> the lints of a grounded policy (none for no permission) */
    private static function lintsOf(mixed $permissions, mixed $limits, Catalog $catalog): array
    {
        return count(Jsx::keys($permissions)) > 0 ? PolicySim::lintPolicy(Facade::compilePolicy($permissions, $limits, $catalog), $catalog) : [];
    }

    /**
     * Ask the model for a policy, ground it against the catalog and lint the compiled result.
     * @param callable(string):mixed $complete @return array{permissions:Obj,limits:Obj,unknownVerbs:list<string>,droppedLimits:list<string>,raw:mixed,lints:mixed}
     */
    public static function policyFromNL(string $instruction, callable $complete, ?Catalog $catalog = null): array
    {
        $c = self::cat($catalog);
        $raw = $complete(IntentCompilers::nlPrompt($instruction, self::specs($catalog)));
        $p = IntentCompilers::parseNlPolicy((string)$raw, self::specs($catalog));
        return $p + ['raw' => $raw, 'lints' => Sign::n(self::lintsOf($p['permissions'], $p['limits'], $c))];
    }

    /** Ask the model for a DRAFT (never enforced). Throws when the model output is not a string or exceeds {@see MAX_OUTPUT_BYTES} UTF-8 bytes. */
    public static function draftPolicyFromNL(string $instruction, callable $complete, ?Catalog $catalog = null, ?string $model = null): Obj
    {
        $c = self::cat($catalog);
        $raw = $complete(IntentCompilers::nlPrompt($instruction, self::specs($catalog)));
        if (!is_string($raw) || strlen(Js::utf8($raw)) > self::MAX_OUTPUT_BYTES) {
            throw new \RuntimeException('draftPolicyFromNL: model output exceeds ' . self::MAX_OUTPUT_BYTES . ' bytes or is not a string');
        }
        $p = IntentCompilers::parseNlPolicy($raw, self::specs($catalog));
        $lints = self::lintsOf($p['permissions'], $p['limits'], $c);
        $cd = self::catalogDigest($catalog);
        $binding = self::draftBinding($instruction, $catalog, $model);
        $hasError = false;
        foreach ($lints as $l) {
            $hasError = $hasError || ($l['level'] ?? null) === 'error';
        }
        return Obj::of(['status' => 'draft', 'instruction' => $instruction, 'permissions' => $p['permissions'], 'limits' => $p['limits'], 'catalog_digest' => $cd,
            'binding' => $binding, 'digest' => self::draftDigestV2($p['permissions'], $p['limits'], $cd, $binding), 'unknownVerbs' => $p['unknownVerbs'],
            'droppedLimits' => $p['droppedLimits'], 'lints' => Sign::n($lints), 'analyzerOk' => count($p['permissions']->keys()) > 0 && !$hasError]);
    }

    private static function message(mixed $a): string
    {
        $v = Jsx::get($a, 'v');
        $body = Obj::of(['v' => $v, 'digest' => Jsx::get($a, 'digest'), 'catalog_digest' => Jsx::get($a, 'catalog_digest'), 'reviewer' => Jsx::get($a, 'reviewer'),
            'approved_at' => Jsx::get($a, 'approved_at'), 'expires_at' => Jsx::get($a, 'expires_at')]);
        return ($v instanceof Num && $v->float() === 2.0 || $v === 2 ? self::DOMAIN_V2 : self::DOMAIN) . Json::canonicalizeLenient($body);
    }

    private static function approval(int $v, mixed $digest, mixed $cd, string $reviewer, mixed $at, mixed $exp, KeyPair $kp): Obj
    {
        $body = Obj::of(['v' => $v, 'digest' => $digest, 'catalog_digest' => $cd, 'reviewer' => $reviewer, 'approved_at' => $at, 'expires_at' => $exp]);
        $body->set('sig', Pca::b64u($kp->sign(self::message($body))));
        return $body;
    }

    /**
     * The human step: sign the exact draft (v2). Refuses a draft the analyzer rejects or one that proposed unknown verbs. `$opts`: `{now?, ttlMs?}`
     * (default one hour, capped at {@see MAX_APPROVAL_TTL_MS}). @param string $reviewerSecret the 32-byte Ed25519 seed
     */
    public static function approveDraft(mixed $draft, string $reviewerSecret, mixed $opts = null, int $nowDefault = 0): Obj
    {
        if (!Js::truthy(Jsx::get($draft, 'analyzerOk'))) { // a truthiness test, as the reference's `!draft.analyzerOk`
            throw new \RuntimeException('approveDraft: the draft did not pass the static analyzer');
        }
        $uv = Jsx::get($draft, 'unknownVerbs');
        if ($uv instanceof Undef || $uv === null) {
            throw new \TypeError("Cannot read properties of " . ($uv === null ? 'null' : 'undefined') . " (reading 'length')");
        }
        if (is_array($uv) && count($uv) > 0) {
            throw new \RuntimeException('approveDraft: the draft proposed verbs that are not in the catalog');
        }
        $n = Jsx::get($opts, 'now');
        $t = Jsx::get($opts, 'ttlMs');
        $now = $n instanceof Undef || $n === null ? (float)$nowDefault : Js::num($n);
        $ttl = $t instanceof Undef || $t === null ? (float)self::DEFAULT_TTL_MS : Js::num($t);
        if ($now === null || !is_finite($now) || $ttl === null || !is_finite($ttl) || $ttl <= 0 || $ttl > self::MAX_APPROVAL_TTL_MS) {
            throw new \RuntimeException('approveDraft: invalid time or ttl');
        }
        $kp = new KeyPair($reviewerSecret);
        return self::approval(2, Jsx::get($draft, 'digest'), Jsx::get($draft, 'catalog_digest'), $kp->public, Sign::n($now), Sign::n($now + $ttl), $kp);
    }

    /** @deprecated Pre-0.5 approval (v1): signs the draft WITHOUT the instruction, model or prompt. Only for the legacy-load compatibility window. */
    public static function approveDraftLegacyV1(mixed $draft, string $reviewerSecret, mixed $opts = null, int $nowDefault = 0): Obj
    {
        $v2 = self::approveDraft($draft, $reviewerSecret, $opts, $nowDefault);
        $kp = new KeyPair($reviewerSecret);
        return self::approval(1, self::draftDigest(Jsx::get($draft, 'permissions'), Jsx::get($draft, 'limits'), Jsx::get($draft, 'catalog_digest')),
            Jsx::get($draft, 'catalog_digest'), $kp->public, $v2->get('approved_at'), $v2->get('expires_at'), $kp);
    }

    private static function isInt(mixed $n): bool
    {
        $f = Js::num($n);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function isObject(mixed $x): bool
    {
        return $x instanceof Obj || is_array($x);
    }

    /**
     * The only door from a draft to policy: recomputes the digest, the grounding and the lints from the draft's contents and checks the approval. Never throws.
     * `$opts`: `{reviewers: list<string>, catalog?: Catalog, now?}`. @return array<string,mixed> `{ok: true, permissions, limits, reviewer, instruction,
     * legacy_unbound_instruction}` or `{ok: false, reason}` (the rejection codes)
     */
    public static function loadApproved(mixed $draft, mixed $approval, mixed $opts, int $nowDefault = 0): array
    {
        $fail = static fn(string $r): array => ['ok' => false, 'reason' => $r];
        try {
            $cobj = Jsx::get($opts, 'catalog');
            $catalog = $cobj instanceof Catalog ? $cobj : null;
            $c = self::cat($catalog);
            $nv = Jsx::get($opts, 'now');
            $now = $nv instanceof Undef || $nv === null ? (float)$nowDefault : (float)Js::num($nv);
            $reviewers = Jsx::get($opts, 'reviewers');
            if (!is_array($reviewers) || !array_is_list($reviewers) || $reviewers === []) {
                return $fail('no_reviewers_pinned');
            }
            $perms = Jsx::get($draft, 'permissions');
            $limits = Jsx::get($draft, 'limits');
            if (!Jsx::truthy($draft) || Jsx::get($draft, 'status') !== 'draft' || !self::isObject($perms) || !self::isObject($limits)) {
                return $fail('not_a_draft');
            }
            $cd = self::catalogDigest($catalog);
            if (Jsx::get($draft, 'catalog_digest') !== $cd) {
                return $fail('catalog_mismatch');
            }
            $instruction = Jsx::get($draft, 'instruction');
            if (!is_string($instruction)) {
                return $fail('not_a_draft');
            }
            $db = Jsx::get($draft, 'binding');
            $legacyDraft = $db instanceof Undef;
            if (!$legacyDraft && !self::isObject($db)) {
                return $fail('not_a_draft');
            }
            if ($legacyDraft) {
                if (self::draftDigest($perms, $limits, $cd) !== Jsx::get($draft, 'digest')) {
                    return $fail('tampered_draft');
                }
            } else {
                $model = Jsx::get($db, 'model');
                $binding = self::draftBinding($instruction, $catalog, is_string($model) ? $model : null);
                if (Jsx::get($db, 'instruction_digest') !== $binding->get('instruction_digest') || Jsx::get($db, 'prompt_digest') !== $binding->get('prompt_digest')
                    || $model !== $binding->get('model')) {
                    return $fail('tampered_draft');
                }
                if (self::draftDigestV2($perms, $limits, $cd, $binding) !== Jsx::get($draft, 'digest')) {
                    return $fail('tampered_draft');
                }
            }
            foreach (Jsx::keys($perms) as $conn) {
                $acts = Jsx::get($perms, $conn);
                if (!is_array($acts) || !array_is_list($acts)) {
                    return $fail('unknown_verbs');
                }
                foreach ($acts as $a) {
                    if (!is_string($a) || $c->get("$conn.$a") === null) {
                        return $fail('unknown_verbs');
                    }
                }
            }
            $uv = Jsx::get($draft, 'unknownVerbs');
            if (is_array($uv) && array_is_list($uv) && count($uv) > 0) {
                return $fail('unknown_verbs');
            }
            if (count(Jsx::keys($perms)) === 0) {
                return $fail('empty_permissions');
            }
            foreach (self::lintsOf($perms, $limits, $c) as $l) {
                if (($l['level'] ?? null) === 'error') {
                    return $fail('analyzer_error');
                }
            }
            $v = Jsx::get($approval, 'v');
            $vf = Js::num($v);
            if (!Jsx::truthy($approval) || ($vf !== 1.0 && $vf !== 2.0) || !is_string(Jsx::get($approval, 'sig')) || !is_string(Jsx::get($approval, 'reviewer'))
                || !is_string(Jsx::get($approval, 'digest')) || !is_string(Jsx::get($approval, 'catalog_digest')) || !self::isInt(Jsx::get($approval, 'approved_at'))
                || !self::isInt(Jsx::get($approval, 'expires_at'))) {
                return $fail('malformed_approval');
            }
            $legacy = $vf === 1.0;
            if ($legacyDraft && !$legacy) {
                return $fail('digest_mismatch');
            }
            if (Jsx::get($approval, 'digest') !== ($legacy ? self::draftDigest($perms, $limits, $cd) : Jsx::get($draft, 'digest')) || Jsx::get($approval, 'catalog_digest') !== $cd) {
                return $fail('digest_mismatch');
            }
            $reviewer = Jsx::get($approval, 'reviewer');
            if (!in_array($reviewer, $reviewers, true)) {
                return $fail('reviewer_not_pinned');
            }
            $at = (float)Js::num(Jsx::get($approval, 'approved_at'));
            $exp = (float)Js::num(Jsx::get($approval, 'expires_at'));
            if ($exp - $at <= 0 || $exp - $at > self::MAX_APPROVAL_TTL_MS) {
                return $fail('ttl_too_long');
            }
            if (!(is_finite($now) && $at <= $now)) {
                return $fail('not_yet_valid');
            }
            if (!(is_finite($now) && $now < $exp)) {
                return $fail('expired');
            }
            if (!Pca::verifyEd25519B64u($reviewer, self::message($approval), Jsx::get($approval, 'sig'))) {
                return $fail('bad_signature');
            }
            return ['ok' => true, 'permissions' => $perms, 'limits' => $limits, 'reviewer' => $reviewer, 'instruction' => $instruction, 'legacy_unbound_instruction' => $legacy];
        } catch (\Throwable) {
            return $fail('malformed_approval');
        }
    }

    /**
     * The ONLY NL-to-agent path: mints an agent from a draft a pinned reviewer signed; throws `agentFromApprovedNL: <code>` otherwise. A v2 approval requires
     * `$goal` to equal the approved instruction. `$opts`: as {@see loadApproved} plus `aud?`. @return array{agent: AgentHandle, reviewer: string, legacy_unbound_instruction: bool}
     */
    public static function agentFromApproved(mixed $draft, mixed $approval, mixed $opts, KeyPair $principal, string $goal, ?KeyPair $holder = null, ?string $aud = null): array
    {
        $nv = Jsx::get($opts, 'now');
        $now = $nv instanceof Undef || $nv === null ? (int)(microtime(true) * 1000) : (int)Js::num($nv);
        $loaded = self::loadApproved($draft, $approval, $opts, $now);
        if ($loaded['ok'] !== true) {
            throw new \RuntimeException('agentFromApprovedNL: ' . $loaded['reason']);
        }
        if ($loaded['legacy_unbound_instruction'] !== true && $goal !== $loaded['instruction']) {
            throw new \RuntimeException('agentFromApprovedNL: goal_mismatch');
        }
        $cobj = Jsx::get($opts, 'catalog');
        $agent = Facade::createAgent($principal, $goal, $loaded['permissions'], $loaded['limits'], $holder, null, null, null, $cobj instanceof Catalog ? $cobj : null, $aud, $now);
        return ['agent' => $agent, 'reviewer' => $loaded['reviewer'], 'legacy_unbound_instruction' => $loaded['legacy_unbound_instruction']];
    }
}
