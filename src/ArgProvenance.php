<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Agent.php';

/**
 * PROVENANCE BY DEFAULT: an agent cannot be steered by injected content into choosing who, where or how much (check
 * `provenance_flow`; not the Intent v2 rule 17 check `provenance`, nor the build-provenance gate {@see ProvenanceGate}).
 *
 * A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees the bytes enter the model's context and holds a key the
 * model cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
 * (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`), and finally the action the
 * model chose (`action`, bound to the exact operation). The verifier re-derives every label from that chain: nothing the agent
 * writes can lower a label, and no chain (or one from an unpinned mediator) leaves every value at `agent`, the top. A sensitive
 * action (anything but a pure read) whose choice or any argument is not trusted is `escalate`: only a principal-signed answer
 * admits it. A forged chain (bad signature under a pinned key, a gap, content that does not hash to its receipt, a final
 * receipt for another operation) is `deny`.
 *
 * Values are the SDK's JSON model (Obj, list arrays, Num, string, bool, null). Strict canonical JSON is taken of the JS value
 * ({@see IntentWb::canon}), as the reference does. Every function here is pure and total; malformed input fails closed.
 *
 * TOKENS: {@see occursAsToken} scans the UTF-8 bytes. That is the reference's UTF-16 scan: a UTF-8 byte >= 0x80 belongs to a
 * non-ASCII character, i.e. to a UTF-16 code unit >= 0x80 (a word character either way), and since UTF-8 is self-synchronising
 * a valid UTF-8 needle only matches at character boundaries, so the occurrences and their neighbours are the same.
 */
final class ArgProvenance
{
    public const RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\0";
    public const RECEIPT_REF_DOMAIN = 'atlas-pca/prov-receipt-ref/v1';
    public const ACTION_DOMAIN = 'atlas-pca/prov-action/v1';
    /** Request header carrying a bundle (base64url of its JSON); the JSON body member is {@see BODY_MEMBER}. */
    public const HEADER = 'PCA-Provenance';
    public const BODY_MEMBER = 'pca_provenance';
    public const MAX_RECEIPTS = 256;
    /** Largest principal message a bundle may carry (UTF-8 bytes). */
    public const MAX_CONTENT_BYTES = 65536;
    /** Leaves examined per parameter; a larger value is not examined and keeps the context label. */
    public const MAX_LEAVES = 4096;
    private const MAX_DEPTH = 32;
    public const MAX_ENVELOPE_MEDIATORS = 16;

    public const ORIGINS = ['principal', 'tool', 'retrieval', 'web', 'action'];
    /** The label lattice: trusted < first_party < tool < web < agent. */
    public const LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'];
    private const RANK = ['trusted' => 0, 'first_party' => 1, 'tool' => 2, 'web' => 3, 'agent' => 4];
    /** The level a segment of each origin carries (`action` contributes nothing: it is the model's own output). */
    private const ORIGIN_LEVEL = ['principal' => 'trusted', 'tool' => 'tool', 'retrieval' => 'tool', 'web' => 'web'];
    /** Per-parameter floors a signed action definition may declare (`provenance_min`). */
    public const FLOORS = ['first_party', 'tool', 'agent'];
    /** Traits a read-only action may carry and still be non-sensitive. Any other trait makes the action sensitive. */
    public const READ_SAFE_TRAITS = ['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data'];
    private const RECEIPT_FIELDS = ['v', 'kind', 'mediator', 'kid', 'session', 'seq', 'prev', 'origin', 'source', 'content_digest', 'issued_at', 'sig'];

    // ---- wire -------------------------------------------------------------------------------------------------------

    /** The digest an `action` receipt binds: the exact operation (verb, resource, params). Throws JsonError when not canonical. */
    public static function actionDigest(mixed $verb, mixed $resource, mixed $params): string
    {
        return IntentWb::valueDigest(Obj::of(['d' => self::ACTION_DOMAIN, 'verb' => $verb, 'resource' => $resource, 'params' => $params]));
    }

    /** Content address of a receipt (signature included). Throws JsonError when not canonical. */
    public static function receiptRef(mixed $r): string
    {
        return IntentWb::artifactRef(self::RECEIPT_REF_DOMAIN, 'r', $r);
    }

    private static function member(Obj $o, string $k): mixed
    {
        return $o->has($k) ? $o->get($k) : JsUndefined::U;
    }

    private static function isOne(mixed $v): bool
    {
        return !is_bool($v) && IntentWb::scalarEq($v, 1);
    }

    private static function nonNegInt(mixed $v): bool
    {
        return IntentWb::isSafeInt($v) && self::int($v) >= 0;
    }

    /** A safe-integer JSON number as a PHP int (callers check isSafeInt first). */
    private static function int(mixed $v): int
    {
        return $v instanceof Num ? (int)$v->float() : (int)$v;
    }

    /** Is `$k` a well-formed mediator pin `{mediator (<= 256 bytes), kid (<= 64 bytes), pk (b64u 32 bytes), pq_pk?}`? */
    public static function isMediatorPin(mixed $k): bool
    {
        return $k instanceof Obj && IntentWb::closedMembers($k, ['mediator', 'kid', 'pk'], ['pq_pk']) === null
            && IntentWb::isBoundedString($k->get('mediator'), 256) && IntentWb::isBoundedString($k->get('kid'), 64)
            && IntentWb::isDigest($k->get('pk')) && IntentWb::pinPqOk(self::member($k, 'pq_pk'));
    }

    /** Wire validation of one receipt. Null = well-formed. */
    public static function receiptWireError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'a receipt must be an object';
        }
        $m = IntentWb::closedMembers($r, self::RECEIPT_FIELDS, IntentWb::SUITE_MEMBERS, 'receipt');
        if ($m !== null) {
            return $m;
        }
        if (!self::isOne($r->get('v')) || $r->get('kind') !== 'pca-prov') {
            return 'a receipt must be {v: 1, kind: "pca-prov"}';
        }
        if (!IntentWb::isBoundedString($r->get('mediator'), 256)) {
            return "'mediator' must be a non-empty string (<= 256 bytes)";
        }
        if (!IntentWb::isBoundedString($r->get('kid'), 64)) {
            return "'kid' must be a non-empty string (<= 64 bytes)";
        }
        if (!IntentWb::isDigest($r->get('session'))) {
            return "'session' must be canonical base64url (32 bytes)";
        }
        if (!self::nonNegInt($r->get('seq'))) {
            return "'seq' must be a non-negative safe integer";
        }
        if ($r->get('prev') !== null && !IntentWb::isDigest($r->get('prev'))) {
            return "'prev' must be null or canonical base64url (32 bytes)";
        }
        if (!in_array($r->get('origin'), self::ORIGINS, true)) {
            return "'origin' must be one of " . implode(', ', self::ORIGINS);
        }
        if (!IntentWb::isBoundedString($r->get('source'), 256)) {
            return "'source' must be a non-empty string (<= 256 bytes)";
        }
        if (!IntentWb::isDigest($r->get('content_digest'))) {
            return "'content_digest' must be canonical base64url (32 bytes)";
        }
        if (!self::nonNegInt($r->get('issued_at'))) {
            return "'issued_at' must be a non-negative safe integer";
        }
        if (!is_string($r->get('sig'))) {
            return "'sig' must be a string";
        }
        return IntentWb::artifactSuiteError($r);
    }

    private static function isStringList(mixed $v, int $max, int $each): bool
    {
        if (!is_array($v) || !array_is_list($v) || count($v) > $max) {
            return false;
        }
        foreach ($v as $x) {
            if (!IntentWb::isBoundedString($x, $each)) {
                return false;
            }
        }
        return true;
    }

    /** Validate action facts `{effects?, traits?, params?: {name: floor}}`. Null = well-formed. */
    public static function actionInfoError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'action info must be an object';
        }
        $m = IntentWb::closedMembers($a, [], ['effects', 'traits', 'params'], 'action info');
        if ($m !== null) {
            return $m;
        }
        foreach (['effects', 'traits'] as $k) {
            if ($a->has($k) && !self::isStringList($a->get($k), 64, 128)) {
                return "action info '$k' must be a list of strings";
            }
        }
        if ($a->has('params')) {
            $p = $a->get('params');
            if (!($p instanceof Obj)) {
                return "action info 'params' must be an object";
            }
            foreach (IntentWb::jsKeys($p) as $k) {
                if (!IntentWb::isBoundedString($k, 128) || !in_array($p->get($k), self::FLOORS, true)) {
                    return "action info param '$k' must map to first_party | tool | agent";
                }
            }
        }
        return null;
    }

    /** Is an action with these facts non-sensitive (it only reads)? Unknown facts (null) are sensitive. */
    public static function isReadOnlyAction(mixed $a): bool
    {
        if (!($a instanceof Obj)) {
            return false;
        }
        $effects = $a->get('effects');
        if (!is_array($effects) || !array_is_list($effects) || $effects === []) {
            return false;
        }
        foreach ($effects as $e) {
            if ($e !== 'read') {
                return false;
            }
        }
        $traits = $a->has('traits') ? $a->get('traits') : [];
        if (!is_array($traits) || !array_is_list($traits)) {
            return false;
        }
        foreach ($traits as $t) {
            if (!in_array($t, self::READ_SAFE_TRAITS, true)) {
                return false;
            }
        }
        return true;
    }

    // ---- tokens and leaves --------------------------------------------------------------------------------------------

    /** Word characters for token boundaries: ASCII letters, digits, `_`, and every non-ASCII byte (see the class doc). */
    private static function isWord(int $c): bool
    {
        return ($c >= 48 && $c <= 57) || ($c >= 65 && $c <= 90) || ($c >= 97 && $c <= 122) || $c === 95 || $c >= 0x80;
    }

    /**
     * Does `$needle` occur in `$text` as a whole token? An occurrence counts when the character before it is not a word
     * character (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, no
     * normalization. An empty needle never occurs.
     */
    public static function occursAsToken(mixed $text, mixed $needle): bool
    {
        if (!is_string($text) || !is_string($needle) || $needle === '') {
            return false;
        }
        $n = strlen($needle);
        $len = strlen($text);
        $headWord = self::isWord(ord($needle[0]));
        $tailWord = self::isWord(ord($needle[$n - 1]));
        for ($i = strpos($text, $needle); $i !== false; $i = strpos($text, $needle, $i + 1)) {
            $okB = !$headWord || $i === 0 || !self::isWord(ord($text[$i - 1]));
            $end = $i + $n;
            $okA = !$tailWord || $end === $len || !self::isWord(ord($text[$end]));
            if ($okB && $okA) {
                return true;
            }
        }
        return false;
    }

    /**
     * The text of every leaf of a value: strings as is, object keys then their values (JSON member order), any other scalar in
     * strict canonical form (`true`, `null`, `120`, `1.5`). Null when deeper than 32, more than 4096 leaves, or not canonical.
     *
     * @return list<string>|null
     */
    public static function leaves(mixed $v): ?array
    {
        $out = [];
        $walk = static function (mixed $x, int $depth) use (&$walk, &$out): bool {
            if ($depth > self::MAX_DEPTH || count($out) > self::MAX_LEAVES) {
                return false;
            }
            if (is_string($x)) {
                $out[] = $x;
            } elseif (is_array($x)) {
                foreach ($x as $y) {
                    if (!$walk($y, $depth + 1)) {
                        return false;
                    }
                }
            } elseif ($x instanceof Obj) {
                foreach (IntentWb::jsKeys($x) as $k) {
                    $out[] = (string)$k;
                    if (!$walk($x->get($k), $depth + 1)) {
                        return false;
                    }
                }
            } else {
                try {
                    $out[] = IntentWb::canon($x);
                } catch (\Throwable) {
                    return false;
                }
            }
            return count($out) <= self::MAX_LEAVES;
        };
        return $walk($v, 0) ? $out : null;
    }

    // ---- the decision -------------------------------------------------------------------------------------------------

    private static function join(string $a, string $b): string
    {
        return self::RANK[$a] >= self::RANK[$b] ? $a : $b;
    }

    /** @param iterable<string> $xs @return list<string> sorted (UTF-8 byte order), de-duplicated */
    private static function sortU(iterable $xs): array
    {
        $u = [];
        foreach ($xs as $x) {
            $u['k' . $x] = $x;
        }
        $out = array_values($u);
        usort($out, [IntentWb::class, 'compareUtf8']);
        return $out;
    }

    private static function operationOk(mixed $op): bool
    {
        return $op instanceof Obj && IntentWb::isBoundedString($op->get('verb'), 256) && is_string($op->get('resource'))
            && $op->get('params') instanceof Obj;
    }

    private static function observationsOk(mixed $obs): bool
    {
        if (!is_array($obs) || !array_is_list($obs)) {
            return false;
        }
        foreach ($obs as $o) {
            if (!($o instanceof Obj) || !in_array($o->get('origin'), ['tool', 'retrieval', 'web'], true)
                || !IntentWb::isBoundedString($o->get('source'), 256)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Verify a bundle against the pins and the operation.
     * @return array{verified: bool, context: string, path: list<string>, texts: list<string>}|array{code: string, reason: string}
     */
    private static function verifyChain(mixed $bundle, Obj $op, array $pins): array
    {
        $unverified = ['verified' => false, 'context' => 'agent', 'path' => ['unlabelled'], 'texts' => []];
        if ($bundle === null) {
            return $unverified;
        }
        $bad = static fn(string $code, string $reason): array => ['code' => $code, 'reason' => $reason];
        if (!($bundle instanceof Obj)) {
            return $bad('malformed_bundle', 'the bundle must be an object');
        }
        $m = IntentWb::closedMembers($bundle, ['v', 'kind', 'receipts'], ['contents'], 'bundle');
        if ($m !== null) {
            return $bad('malformed_bundle', $m);
        }
        if (!self::isOne($bundle->get('v')) || $bundle->get('kind') !== 'pca-provenance') {
            return $bad('malformed_bundle', 'the bundle must be {v: 1, kind: "pca-provenance"}');
        }
        $rs = $bundle->get('receipts');
        if (!is_array($rs) || !array_is_list($rs) || $rs === [] || count($rs) > self::MAX_RECEIPTS) {
            return $bad('malformed_bundle', 'the bundle must hold 1..' . self::MAX_RECEIPTS . ' receipts');
        }
        foreach ($rs as $i => $r) {
            $e = self::receiptWireError($r);
            if ($e !== null) {
                return $bad('malformed_bundle', "receipt $i: $e");
            }
        }
        $contents = $bundle->has('contents') ? $bundle->get('contents') : new Obj();
        if (!($contents instanceof Obj)) {
            return $bad('malformed_bundle', "'contents' must be an object");
        }
        /** @var list<Obj> $rs */
        $first = $rs[0];
        foreach ($rs as $i => $r) {
            if (self::int($r->get('seq')) !== $i) {
                return $bad('broken_chain', "receipt $i has seq " . IntentWb::jsStr($r->get('seq')));
            }
            if ($r->get('session') !== $first->get('session') || $r->get('mediator') !== $first->get('mediator') || $r->get('kid') !== $first->get('kid')) {
                return $bad('broken_chain', "receipt $i belongs to another session or mediator");
            }
            if ($i === 0 ? $r->get('prev') !== null : $r->get('prev') !== self::receiptRef($rs[$i - 1])) {
                return $bad('broken_chain', "receipt $i does not link to its predecessor");
            }
            if ($i > 0 && self::int($r->get('issued_at')) < self::int($rs[$i - 1]->get('issued_at'))) {
                return $bad('broken_chain', "receipt $i is older than its predecessor");
            }
        }
        $last = $rs[count($rs) - 1];
        if ($last->get('origin') !== 'action' || $last->get('source') !== $op->get('verb')
            || $last->get('content_digest') !== self::actionDigest($op->get('verb'), $op->get('resource'), $op->get('params'))) {
            return $bad('unbound_action', 'the last receipt is not the action receipt of this operation');
        }
        $texts = [];
        foreach (IntentWb::jsKeys($contents) as $k) {
            $k = (string)$k;
            $text = $contents->get($k);
            $r = preg_match('/\A(?:0|[1-9][0-9]{0,8})\z/', $k) === 1 ? ($rs[(int)$k] ?? null) : null;
            if ($r === null || $r->get('origin') !== 'principal') {
                return $bad('malformed_bundle', "contents '$k' does not name a principal receipt");
            }
            if (!is_string($text) || strlen($text) > self::MAX_CONTENT_BYTES) {
                return $bad('malformed_bundle', "contents '$k' must be a string of at most " . self::MAX_CONTENT_BYTES . ' bytes');
            }
            try {
                $d = IntentWb::valueDigest($text);
            } catch (\Throwable) {
                return $bad('content_mismatch', "contents '$k' is not canonical text");
            }
            if ($d !== $r->get('content_digest')) {
                return $bad('content_mismatch', "contents '$k' does not hash to its receipt");
            }
            $texts[] = $text;
        }
        $pin = null;
        foreach ($pins as $p) {
            if ($p->get('mediator') === $first->get('mediator') && $p->get('kid') === $first->get('kid')) {
                $pin = $p;
                break;
            }
        }
        // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
        if ($pin === null) {
            return $unverified;
        }
        foreach ($rs as $i => $r) {
            if (!IntentWb::verifyArtifactSig(self::RECEIPT_DOMAIN, $r, $pin)) {
                return $bad('bad_signature', "receipt $i does not verify under the pinned mediator key");
            }
        }
        $before = array_values(array_filter(array_slice($rs, 0, -1), static fn(Obj $r): bool => $r->get('origin') !== 'action'));
        $context = $before === [] ? 'agent' : 'trusted';
        $path = [];
        foreach ($before as $r) {
            $context = self::join($context, self::ORIGIN_LEVEL[$r->get('origin')]);
            if ($r->get('origin') !== 'principal') {
                $path[] = $r->get('origin') . ':' . $r->get('source');
            }
        }
        if ($before === []) {
            $path[] = 'unlabelled';
        }
        return ['verified' => true, 'context' => $context, 'path' => self::sortU($path), 'texts' => $texts];
    }

    /**
     * The provenance decision for one operation. `$input` is an Obj with `operation` {verb, resource, params}, `mediators` (the
     * pins), optional `bundle` (absent or null = none), `action` (absent = unknown action: sensitive), `principal_plan`,
     * `principal_control` (true to set) and `observed` ([{origin, source}], raise only). Steps, first failure wins:
     *   0. inputs well-formed, else `deny` (malformed_config / malformed_operation / malformed_action);
     *   1. the bundle: wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at), the last
     *      receipt is the `action` receipt of this operation, every principal content hashes to its receipt, every signature
     *      verifies under the pinned (mediator, kid). A failure is `deny`. An unpinned mediator's chain is ignored (no trust);
     *   2. observations join into the context; 3. control = `trusted` under a principal plan or principal control, else context;
     *   4. each parameter: `trusted` under a principal plan; else the join over its leaves (a leaf is trusted when the context is,
     *      or when it occurs as a token in a verified principal content); no leaves = trusted; too large = context;
     *   5. floors: the facts' `params` floor, else `first_party` for a sensitive action and `agent` otherwise;
     *   6. a sensitive action whose control is not trusted, or any parameter above its floor, is `escalate`; else `pass`.
     *
     * @return array{outcome: string, code?: string, reason?: string, sensitive: bool, verified: bool, control: string, labels: Obj,
     *               tainted: list<string>, path: list<string>}
     */
    public static function decide(mixed $input): array
    {
        $base = ['sensitive' => true, 'verified' => false, 'control' => 'agent', 'labels' => new Obj(), 'tainted' => [], 'path' => []];
        $deny = static function (string $code, string $reason) use (&$base): array {
            return ['outcome' => 'deny', 'code' => $code, 'reason' => $reason] + $base;
        };
        try {
            if (!($input instanceof Obj)) {
                return $deny('malformed_config', 'input must be an object');
            }
            $pins = $input->get('mediators');
            $pinsOk = is_array($pins) && array_is_list($pins);
            foreach ($pinsOk ? $pins : [] as $p) {
                $pinsOk = $pinsOk && self::isMediatorPin($p);
            }
            if (!$pinsOk) {
                return $deny('malformed_config', 'mediator pins must be a list of {mediator, kid, pk, pq_pk?}');
            }
            $op = $input->get('operation');
            if (!self::operationOk($op)) {
                return $deny('malformed_operation', 'the operation needs a verb, a resource and a params object');
            }
            $action = $input->has('action') ? $input->get('action') : null;
            if ($input->has('action') && ($e = self::actionInfoError($action)) !== null) {
                return $deny('malformed_action', $e);
            }
            $obs = $input->has('observed') ? $input->get('observed') : [];
            if (!self::observationsOk($obs)) {
                return $deny('malformed_config', 'observations must be a list of {origin, source}');
            }
            $sensitive = !self::isReadOnlyAction($action);
            $base['sensitive'] = $sensitive;
            $ch = self::verifyChain($input->get('bundle'), $op, $pins);
            if (isset($ch['code'])) {
                return $deny($ch['code'], $ch['reason']);
            }
            $base['verified'] = $ch['verified'];
            $context = $ch['context'];
            $path = $ch['path'];
            foreach ($obs as $o) {
                $context = self::join($context, self::ORIGIN_LEVEL[$o->get('origin')]);
                $path[] = $o->get('origin') . ':' . $o->get('source');
            }
            $base['path'] = self::sortU($path);
            $plan = $input->get('principal_plan') === true;
            $control = $plan || $input->get('principal_control') === true ? 'trusted' : $context;
            $base['control'] = $control;
            $params = $op->get('params');
            $labels = new Obj();
            foreach (self::sortU(array_map('strval', $params->keys())) as $p) {
                if ($plan) {
                    $labels->set($p, 'trusted');
                    continue;
                }
                $leaves = self::leaves($params->get($p));
                if ($leaves === null) {
                    $labels->set($p, $context);
                    continue;
                }
                $l = 'trusted';
                foreach ($leaves as $leaf) {
                    // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                    $typed = $context === 'trusted';
                    foreach ($typed ? [] : $ch['texts'] as $t) {
                        if (self::occursAsToken($t, $leaf)) {
                            $typed = true;
                            break;
                        }
                    }
                    $l = self::join($l, $typed ? 'trusted' : $context);
                }
                $labels->set($p, $l);
            }
            $base['labels'] = $labels;
            $floors = $action instanceof Obj && $action->get('params') instanceof Obj ? $action->get('params') : new Obj();
            $tainted = [];
            foreach ($labels->keys() as $p) {
                $f = $floors->has($p) ? $floors->get($p) : ($sensitive ? 'first_party' : 'agent');
                if (self::RANK[$labels->get($p)] > self::RANK[$f]) {
                    $tainted[] = $p;
                }
            }
            $base['tainted'] = self::sortU($tainted);
            // no segment origin maps to first_party, so a control label is trusted or untrusted
            $badControl = $sensitive && $control !== 'trusted';
            if (!$badControl && $base['tainted'] === []) {
                return ['outcome' => 'pass'] + $base;
            }
            $where = $base['path'] !== [] ? ' [' . implode(', ', $base['path']) . ']' : '';
            $code = $badControl && $base['tainted'] !== [] ? 'untrusted_control_and_args' : ($badControl ? 'untrusted_control' : 'untrusted_args');
            $parts = [];
            if ($badControl) {
                $parts[] = 'the choice of ' . $op->get('verb') . ' derives from untrusted content';
            }
            if ($base['tainted'] !== []) {
                $parts[] = implode(', ', $base['tainted']) . (count($base['tainted']) === 1 ? ' derives' : ' derive') . ' from untrusted content';
            }
            return ['outcome' => 'escalate', 'code' => $code,
                'reason' => implode('; ', $parts) . $where . ': the principal must confirm (prompt-injection path)'] + $base;
        } catch (\Throwable $e) {
            return $deny('malformed_config', 'evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- the grant envelope member --------------------------------------------------------------------------------------

    /**
     * The grant envelope member `provenance` (signed by the principal with the rest of the grant): `mediators` the principal
     * designates (added to the verifier's pins) and `mode`. `mode: 'insecure_off'` is the DOCUMENTED DANGEROUS opt-out: the gate is
     * not evaluated for this grant, so injected content can steer its sensitive actions. Null when well-formed.
     */
    public static function envelopeError(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'provenance must be an object';
        }
        $m = IntentWb::closedMembers($p, [], ['mode', 'mediators'], 'provenance');
        if ($m !== null) {
            return $m;
        }
        if ($p->has('mode') && $p->get('mode') !== 'enforce' && $p->get('mode') !== 'insecure_off') {
            return "provenance.mode must be 'enforce' or 'insecure_off'";
        }
        if ($p->has('mediators')) {
            $ms = $p->get('mediators');
            $ok = is_array($ms) && array_is_list($ms) && count($ms) <= self::MAX_ENVELOPE_MEDIATORS;
            foreach ($ok ? $ms : [] as $k) {
                $ok = $ok && self::isMediatorPin($k);
            }
            if (!$ok) {
                return 'provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}';
            }
        }
        return null;
    }

    /** The bundle's session id when its first receipt names one (for an `observed` source). */
    public static function bundleSession(mixed $b): ?string
    {
        $rs = $b instanceof Obj ? $b->get('receipts') : null;
        $s = is_array($rs) && ($rs[0] ?? null) instanceof Obj ? $rs[0]->get('session') : null;
        return is_string($s) ? $s : null;
    }

    /**
     * The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
     * input, no model in between): one principal segment holding the operation, then the action. Under a pinned recorder key the
     * operation's choice and values are trusted.
     */
    public static function principalDirect(ProvenanceRecorder $recorder, mixed $operation): Obj
    {
        [$verb, $resource, $params] = ProvenanceRecorder::operationParts($operation);
        $recorder->principal(IntentWb::canon(Obj::of(['verb' => $verb, 'resource' => $resource, 'params' => $params])));
        return $recorder->forAction($operation);
    }
}

/**
 * The mediator side of provenance by default: one recorder per agent session. It must run where the bytes enter the model's
 * context (the harness that builds the prompt, a gateway, an MCP client), with a key the model cannot reach. Record the
 * principal's messages with {@see principal}, every untrusted segment with {@see tool} / {@see retrieval} / {@see web}, and present
 * {@see forAction}'s bundle with the call (`PCA-Provenance` header, base64url of its JSON, or the body member `pca_provenance`).
 * The verifier pins {@see $pin} (or the principal's grant envelope names it under `provenance.mediators`).
 */
final class ProvenanceRecorder
{
    public readonly string $session;
    /** The pin a verifier (or the principal's grant envelope) must carry for this recorder. */
    public readonly Obj $pin;
    private readonly KeyPair $key;
    private readonly \Closure $now;
    /** @var list<Obj> */
    private array $chain = [];
    private Obj $contents;

    /**
     * @param string        $mediator the mediator name (1..256 UTF-8 bytes)
     * @param string        $kid      the key id (1..64 UTF-8 bytes)
     * @param KeyPair|null  $key      the mediator's Ed25519 key (generated when null: then pin {@see $pin})
     * @param string|null   $session  b64u 32-byte session id (random when null)
     * @param callable|null $now      `(): int` epoch milliseconds (default: the wall clock)
     * @param string|null   $alg      a post-quantum / hybrid artifact suite (with `$pq`); null = Ed25519
     */
    public function __construct(
        private readonly string $mediator,
        private readonly string $kid,
        ?KeyPair $key = null,
        ?string $session = null,
        ?callable $now = null,
        private readonly ?string $alg = null,
        private readonly ?PqKeyPair $pq = null,
    ) {
        if (!IntentWb::isBoundedString($mediator, 256) || !IntentWb::isBoundedString($kid, 64)) {
            throw new \InvalidArgumentException('ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required');
        }
        $session ??= Pca::b64u(random_bytes(32));
        if (!IntentWb::isDigest($session)) {
            throw new \InvalidArgumentException('ProvenanceRecorder: session must be canonical base64url of 32 bytes');
        }
        $this->key = $key ?? KeyPair::generate();
        $this->session = $session;
        $this->now = $now === null ? static fn(): int => (int)(microtime(true) * 1000) : \Closure::fromCallable($now);
        $this->contents = new Obj();
        $pin = Obj::of(['mediator' => $mediator, 'kid' => $kid, 'pk' => $this->key->public]);
        if ($alg !== null && $alg !== 'ed25519') {
            if ($pq === null) {
                throw new \InvalidArgumentException("ProvenanceRecorder: $alg needs a post-quantum key pair");
            }
            $pin->set('pq_pk', $pq->public);
        }
        $this->pin = $pin;
    }

    /** @return array{0: mixed, 1: mixed, 2: Obj} verb, resource and params (the SDK's JSON model) of an operation array / Obj */
    public static function operationParts(mixed $operation): array
    {
        $get = static fn(string $k): mixed => $operation instanceof Obj ? $operation->get($k) : (is_array($operation) ? ($operation[$k] ?? null) : null);
        $params = Sign::n($get('params') ?? new Obj());
        if (!($params instanceof Obj)) {
            throw new \InvalidArgumentException('provenance: the operation params must be a JSON object');
        }
        return [$get('verb'), $get('resource'), $params];
    }

    /**
     * The reference's source clip, exactly: while over 256 UTF-8 bytes keep the first max(1, floor(n / 2)) UTF-16 units. A cut can
     * leave a lone high surrogate (3 bytes, as U+FFFD); if one survives, the strict canonical form refuses it, so this throws.
     *
     * @internal public for the boundary tests
     */
    public static function clip(string $s): string
    {
        $u = mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
        $lone = static fn (string $u): bool => strlen($u) >= 2 && (ord($u[strlen($u) - 2]) & 0xFC) === 0xD8;
        $len = static fn (string $u): int => $lone($u)
            ? strlen(mb_convert_encoding(substr($u, 0, -2), 'UTF-8', 'UTF-16BE')) + 3
            : strlen(mb_convert_encoding($u, 'UTF-8', 'UTF-16BE'));
        while ($len($u) > 256) {
            $u = substr($u, 0, 2 * max(1, intdiv(intdiv(strlen($u), 2), 2)));
        }
        if ($lone($u)) {
            throw new JsonError('provenance: clipping the source split a surrogate pair (lone surrogate, not canonical)');
        }
        return $u === '' ? '-' : mb_convert_encoding($u, 'UTF-8', 'UTF-16BE');
    }

    private function append(string $origin, string $source, string $digest): Obj
    {
        $prev = $this->chain === [] ? null : $this->chain[count($this->chain) - 1];
        $issued = max($prev === null ? 0 : $prev->get('issued_at')->int(), (int)($this->now)());
        $body = Obj::of(['v' => 1, 'kind' => 'pca-prov', 'mediator' => $this->mediator, 'kid' => $this->kid, 'session' => $this->session,
            'seq' => count($this->chain), 'prev' => $prev === null ? null : ArgProvenance::receiptRef($prev), 'origin' => $origin,
            'source' => self::clip($source), 'content_digest' => $digest, 'issued_at' => $issued]);
        $r = Sign::signArtifact(ArgProvenance::RECEIPT_DOMAIN, $body, $this->key, $this->alg, $this->pq);
        $this->chain[] = $r;
        return $r;
    }

    private function segment(string $origin, string $source, mixed $content): Obj
    {
        try {
            $text = is_string($content) ? $content : Json::canonicalizeLenient(Sign::n($content));
        } catch (\Throwable) {
            $text = get_debug_type($content);
        }
        $r = $this->append($origin, $source, IntentWb::valueDigest($text));
        if ($origin === 'principal' && strlen($text) <= ArgProvenance::MAX_CONTENT_BYTES) {
            $this->contents->set((string)$r->get('seq')->int(), $text);
        }
        return $r;
    }

    /** The principal's own message (TRUSTED). */
    public function principal(string $text): Obj
    {
        return $this->segment('principal', 'user', $text);
    }

    /** A tool result (UNTRUSTED). Non-string output is recorded as its JSON text. */
    public function tool(string $name, mixed $output): Obj
    {
        return $this->segment('tool', $name, $output);
    }

    /** A retrieved document (UNTRUSTED). */
    public function retrieval(string $source, mixed $content): Obj
    {
        return $this->segment('retrieval', $source, $content);
    }

    /** A fetched web page or HTTP response (UNTRUSTED). */
    public function web(string $url, mixed $content): Obj
    {
        return $this->segment('web', $url, $content);
    }

    /** Record the chosen action (`['verb', 'resource', 'params']` or an Obj) and return the bundle to present with it. */
    public function forAction(mixed $operation): Obj
    {
        if (count($this->chain) >= ArgProvenance::MAX_RECEIPTS) {
            throw new \LengthException('provenance: the session holds ' . ArgProvenance::MAX_RECEIPTS . " receipts; start a new session with the principal's message");
        }
        [$verb, $resource, $params] = self::operationParts($operation);
        if (!is_string($verb) || !is_string($resource)) {
            throw new \InvalidArgumentException('provenance: the operation needs a verb and a resource');
        }
        $this->append('action', $verb, ArgProvenance::actionDigest($verb, $resource, $params));
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-provenance', 'receipts' => $this->chain]);
        if ($this->contents->keys() !== []) {
            $b->set('contents', $this->contents->without());
        }
        return $b;
    }

    /** @return list<Obj> every receipt so far */
    public function receipts(): array
    {
        return $this->chain;
    }
}
