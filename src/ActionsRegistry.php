<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs
 * (with shards), pack inclusion proofs, the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures,
 * digests and pins; they do NOT recompute the semantic diff. Pure and total: malformed input is a refusal.
 */
final class ActionsRegistry
{
    public const EVOLUTION_RECORD_KIND = 'pca-evolution-record';
    public const REAPPROVAL_KIND = 'pca-reapproval';
    public const EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\0";
    public const EVOLUTION_DIFF_DOMAIN = 'atlas-pca/action-evolution-diff/v1';
    public const REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\0";
    public const PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\0";
    public const PACK_REF_DOMAIN = 'atlas-pca/action-pack-ref/v1';
    public const PACK_SHARD_DOMAIN = 'atlas-pca/action-pack-shard/v1';
    public const RULES_DIGEST_DOMAIN = 'atlas-pca/action-rules/v1';
    public const MAX_EVOLUTION_STEPS = 32;
    private const CLASSES = ['equal', 'narrow', 'widen', 'incomparable', 'added', 'removed'];
    private const STABILITIES = ['draft', 'beta', 'stable'];
    private const CAVEATS = ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'];
    private const CONTEXT = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'];
    private const PRULES = ['array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency',
        'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged'];
    private const B64U_43 = '/\A[A-Za-z0-9_-]{43}\z/';
    private const NS_RE = '/\A[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}\z/';
    private const VERB_RE = '/\A[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}\z/';
    private const SEMVER_RE = '/\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\z/';
    private const SHARD_NAME_RE = '/\A[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}\z/';

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    private static function u16(string $s): int
    {
        return intdiv(strlen(mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2);
    }

    private static function u16cmp(string $a, string $b): int
    {
        return strcmp(mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), mb_convert_encoding($b, 'UTF-16BE', 'UTF-8'));
    }

    private static function closed(Obj $o, array $allowed): ?string
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return "unknown member '$k'";
            }
        }
        return null;
    }

    private static function sha(mixed $x): bool
    {
        return is_string($x) && preg_match(self::B64U_43, $x) === 1;
    }

    private static function isNum(mixed $x): bool
    {
        return $x instanceof Num && $x->isInt();
    }

    private static function is1(mixed $x): bool
    {
        return self::isNum($x) && $x->lexeme === '1';
    }

    private static function tier(mixed $x): bool
    {
        return self::isNum($x) && $x->int() >= 0 && $x->int() <= 3;
    }

    private static function str(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : null;
    }

    private static function inS(mixed $x, array $options): bool
    {
        return is_string($x) && in_array($x, $options, true);
    }

    // ---- evolution records ------------------------------------------------------------------------------------------------

    public static function evolutionRecordError(mixed $x, bool $signed = true): ?string
    {
        if (!($x instanceof Obj)) {
            return 'evolution record must be an object';
        }
        $u = self::closed($x, ['v', 'kind', 'ns', 'verb', 'from', 'to', 'class', 'reasons'] + ($signed ? [8 => 'sig'] : []));
        if ($u !== null) {
            return "evolution record: $u";
        }
        if (!self::is1($x->get('v')) || $x->get('kind') !== self::EVOLUTION_RECORD_KIND) {
            return 'evolution record: bad v/kind';
        }
        if (!is_string($x->get('ns')) || preg_match(self::NS_RE, $x->get('ns')) !== 1) {
            return 'evolution record: bad ns';
        }
        if (!is_string($x->get('verb')) || preg_match(self::VERB_RE, $x->get('verb')) !== 1) {
            return 'evolution record: bad verb';
        }
        if (!$x->has('from') || ($x->get('from') !== null && !self::sha($x->get('from')))) {
            return 'evolution record: bad from';
        }
        if (!$x->has('to') || ($x->get('to') !== null && !self::sha($x->get('to')))) {
            return 'evolution record: bad to';
        }
        $c = $x->get('class');
        if (!self::inS($c, self::CLASSES)) {
            return 'evolution record: bad class';
        }
        if (($c === 'added') !== ($x->get('from') === null) || ($c === 'removed') !== ($x->get('to') === null)) {
            return 'evolution record: endpoints do not match the class';
        }
        $r = $x->get('reasons');
        if (!self::isList($r) || count($r) > 64) {
            return 'evolution record: bad reasons';
        }
        foreach ($r as $e) {
            if (!is_string($e) || self::u16($e) > 512) {
                return 'evolution record: bad reasons';
            }
        }
        if ($signed) {
            $s = $x->get('sig');
            if (!($s instanceof Obj) || self::closed($s, ['alg', 'kid', 'value', 'pq_value']) !== null) {
                return 'evolution record: bad sig';
            }
            $kid = $s->get('kid');
            if (!is_string($kid) || self::u16($kid) === 0 || self::u16($kid) > 128 || !is_string($s->get('value')) || !is_string($s->get('alg'))) {
                return 'evolution record: bad sig';
            }
            if ($s->has('pq_value') && !is_string($s->get('pq_value'))) {
                return 'evolution record: bad sig';
            }
        }
        try {
            IntentV2::canonicalize($x->without('sig'));
        } catch (\Throwable $e) {
            return 'evolution record: ' . $e->getMessage();
        }
        return null;
    }

    /** Digest of ONE record's diff; throws when a member is absent (the reference throws on undefined). */
    public static function evolutionDiffDigest(mixed $r): string
    {
        $o = [];
        foreach (['ns', 'verb', 'from', 'to', 'class', 'reasons'] as $k) {
            if (!($r instanceof Obj) || !$r->has($k)) {
                throw new \InvalidArgumentException("missing $k");
            }
            $o[$k] = $r->get($k);
        }
        return IntentV2::hashCanonical(Obj::of(['d' => self::EVOLUTION_DIFF_DOMAIN] + $o));
    }

    public static function verifyEvolutionRecord(mixed $rec, mixed $keys): array
    {
        $bad = self::evolutionRecordError($rec);
        if ($bad !== null) {
            return ['ok' => false, 'reason' => $bad];
        }
        return IntentV2::verifyRegistrySig(self::EVOLUTION_DOMAIN, $rec->without('sig'), $rec->get('sig'), $keys);
    }

    public static function reapprovalValid(mixed $r, mixed $grantId, mixed $issuer, mixed $verb, mixed $diff): bool
    {
        try {
            if (!($r instanceof Obj) || self::closed($r, ['v', 'kind', 'grant', 'verb', 'diff', 'sig']) !== null) {
                return false;
            }
            if (!self::is1($r->get('v')) || $r->get('kind') !== self::REAPPROVAL_KIND || !$r->has('grant') || $r->get('grant') !== $grantId
                || !$r->has('verb') || $r->get('verb') !== $verb || !$r->has('diff') || $r->get('diff') !== $diff) {
                return false;
            }
            $s = $r->get('sig');
            if (!($s instanceof Obj) || self::closed($s, ['alg', 'value']) !== null || $s->get('alg') !== 'ed25519' || !is_string($s->get('value'))) {
                return false;
            }
            return IntentV2::verifyEd25519($issuer, self::REAPPROVAL_DOMAIN . IntentV2::canonicalize($r->without('sig')), $s->get('value'));
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- the pin -----------------------------------------------------------------------------------------------------------

    public static function actionPinError(mixed $x): ?string
    {
        if (!($x instanceof Obj)) {
            return 'actions must be an object';
        }
        $u = self::closed($x, ['pack', 'defs', 'on_new_action', 'max_esc', 'preauth_esc', 'caveats']);
        if ($u !== null) {
            return "actions: $u";
        }
        $p = $x->get('pack');
        if (!($p instanceof Obj) || self::closed($p, ['ns', 'root']) !== null) {
            return 'actions.pack must be {ns, root}';
        }
        if (!is_string($p->get('ns')) || preg_match(self::NS_RE, $p->get('ns')) !== 1) {
            return 'actions.pack.ns is not a namespace';
        }
        if (!self::sha($p->get('root'))) {
            return 'actions.pack.root must be a base64url digest';
        }
        if (!self::inS($x->get('on_new_action'), ['deny', 'escalate'])) {
            return "actions.on_new_action must be 'deny' or 'escalate'";
        }
        if ($x->has('max_esc') && !self::tier($x->get('max_esc'))) {
            return 'actions.max_esc must be an integer tier 0..3';
        }
        if ($x->has('preauth_esc') && !self::tier($x->get('preauth_esc'))) {
            return 'actions.preauth_esc must be an integer tier 0..3';
        }
        if (self::tier($x->get('max_esc')) && self::tier($x->get('preauth_esc')) && $x->get('preauth_esc')->int() > $x->get('max_esc')->int()) {
            return 'actions.preauth_esc exceeds actions.max_esc';
        }
        if ($x->has('caveats')) {
            $c = $x->get('caveats');
            if (!self::isList($c) || count(array_unique(array_map('strval', array_filter($c, 'is_string')))) !== count($c)) {
                return 'actions.caveats must be distinct caveat kinds';
            }
            foreach ($c as $k) {
                if (!self::inS($k, self::CAVEATS)) {
                    return 'actions.caveats must be distinct caveat kinds';
                }
            }
        }
        if ($x->has('defs')) {
            $d = $x->get('defs');
            if (!($d instanceof Obj)) {
                return 'actions.defs must be an object';
            }
            foreach ($d->keys() as $verb) {
                if (preg_match(self::VERB_RE, $verb) !== 1) {
                    return "actions.defs: '$verb' is not a verb";
                }
                if (!self::sha($d->get($verb))) {
                    return "actions.defs.$verb must be a base64url digest";
                }
            }
        }
        return null;
    }

    private static function deny(string $code, string $reason, bool $escalate = false, ?string $needs = null): array
    {
        $o = ['ok' => false, 'code' => $code, 'escalate' => $escalate, 'reason' => $reason];
        if ($needs !== null) {
            $o['needs_reapproval'] = $needs;
        }
        return $o;
    }

    /** @param array $i keys: pin, doc, verb, records, keys, reapprovals, grant (PHP array of Obj/lists) */
    public static function decidePin(array $i): array
    {
        try {
            $pe = self::actionPinError($i['pin']);
            if ($pe !== null) {
                return self::deny('bad_pin', $pe);
            }
            $pin = $i['pin'];
            $doc = $i['doc'];
            $verb = $i['verb'];
            $verbs = $doc instanceof Obj ? $doc->get('verbs') : null;
            $v = null;
            if (self::isList($verbs)) {
                foreach ($verbs as $x) {
                    if ($x instanceof Obj && $x->has('verb') && $x->get('verb') === $verb) {
                        $v = $x;
                        break;
                    }
                }
            }
            if ($v === null) {
                return self::deny('unknown_verb', "the accepted schema does not declare '$verb'");
            }
            $pk = $doc->get('pack');
            $ns = $pin->get('pack')->get('ns');
            if (!($pk instanceof Obj) || !$pk->has('ns') || $pk->get('ns') !== $ns) {
                return self::deny('pack_mismatch', "the schema does not come from the pinned pack '$ns'");
            }
            if (!$pin->has('defs')) {
                return $pk->has('root') && $pk->get('root') === $pin->get('pack')->get('root') ? ['ok' => true, 'via' => 'pack']
                    : self::deny('pack_mismatch', 'the pack root differs from the pinned root (the grant pins the pack as a whole)');
            }
            if (!$pin->get('defs')->has($verb)) {
                $on = $pin->get('on_new_action');
                return self::deny('new_action', "the grant does not name '$verb' (on_new_action: $on)", $on === 'escalate');
            }
            $pinned = $pin->get('defs')->get($verb);
            $presented = $v->get('def');
            if (!is_string($presented)) {
                return self::deny('def_changed', 'the schema verb carries no definition digest');
            }
            if ($presented === $pinned) {
                return ['ok' => true, 'via' => 'exact'];
            }
            $edges = [];
            $keys = $i['keys'] ?? [];
            $grant = $i['grant'];
            foreach ($i['records'] ?? [] as $r) {
                if (!self::verifyEvolutionRecord($r, $keys)['ok']) {
                    continue;
                }
                if ($r->get('ns') !== $ns || $r->get('verb') !== $verb || $r->get('from') === null || $r->get('to') === null) {
                    continue;
                }
                $diff = self::evolutionDiffDigest($r);
                $approved = in_array($r->get('class'), ['equal', 'narrow'], true);
                if (!$approved) {
                    foreach ($i['reapprovals'] ?? [] as $a) {
                        if (self::reapprovalValid($a, $grant->get('id'), $grant->get('issuer'), $verb, $diff)) {
                            $approved = true;
                            break;
                        }
                    }
                }
                $edges[$r->get('from')][] = ['to' => $r->get('to'), 'blocked' => $approved ? null : $diff];
            }
            $search = function (bool $usableOnly) use ($edges, $pinned, $presented): array {
                $parent = [];
                $seen = [$pinned => true];
                $frontier = [$pinned];
                for ($step = 0; $step < self::MAX_EVOLUTION_STEPS && $frontier && !isset($parent[$presented]); $step++) {
                    $next = [];
                    foreach ($frontier as $f) {
                        foreach ($edges[$f] ?? [] as $e) {
                            if (isset($seen[$e['to']]) || ($usableOnly && $e['blocked'] !== null)) {
                                continue;
                            }
                            $seen[$e['to']] = true;
                            $parent[$e['to']] = ['from' => $f, 'blocked' => $e['blocked']];
                            $next[] = $e['to'];
                        }
                    }
                    $frontier = $next;
                }
                return $parent;
            };
            if (isset($search(true)[$presented])) {
                return ['ok' => true, 'via' => 'chain'];
            }
            $all = $search(false);
            if (isset($all[$presented])) {
                $first = null;
                for ($cur = $presented; $cur !== $pinned;) {
                    $p = $all[$cur];
                    if ($p['blocked'] !== null) {
                        $first = $p['blocked'];
                    }
                    $cur = $p['from'];
                }
                return self::deny('def_changed', 'the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve', false, $first);
            }
            return self::deny('def_changed', 'the definition differs from the pinned digest and no signed evolution record chains to it');
        } catch (\Throwable $e) {
            return self::deny('bad_pin', 'pin evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- signed packs -----------------------------------------------------------------------------------------------------

    public static function compareVersions(string $a, string $b): int
    {
        if (preg_match(self::SEMVER_RE, $a, $pa) !== 1 || preg_match(self::SEMVER_RE, $b, $pb) !== 1) {
            throw new ActionKitError('bad_version', "'$a' or '$b' is not MAJOR.MINOR.PATCH");
        }
        for ($k = 1; $k <= 3; $k++) {
            if ((int)$pa[$k] !== (int)$pb[$k]) {
                return (int)$pa[$k] - (int)$pb[$k];
            }
        }
        return 0;
    }

    public static function rulesDigest(): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::RULES_DIGEST_DOMAIN, 'prules' => self::PRULES, 'caveats' => self::CAVEATS, 'context' => self::CONTEXT]));
    }

    public static function packDigest(Obj $p): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::PACK_REF_DOMAIN, 'p' => $p]));
    }

    public static function shardDigest(Obj $s): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::PACK_SHARD_DOMAIN, 's' => $s]));
    }

    private static function defsError(array $defs): ?string
    {
        foreach ($defs as $i => $d) {
            $e = Actions::validateDef($d);
            if ($e !== null) {
                return "def $i: $e";
            }
            if ($i > 0 && self::u16cmp($defs[$i - 1]->get('verb'), $d->get('verb')) >= 0) {
                return "defs must be sorted by verb and unique (at '" . $d->get('verb') . "')";
            }
        }
        return null;
    }

    public static function packShapeError(mixed $x, bool $signed = true): ?string
    {
        try {
            if (!($x instanceof Obj)) {
                return 'pack must be an object';
            }
            $e = self::closed($x, ['v', 'kind', 'ns', 'version', 'stability', 'traits_digest', 'roles_digest', 'rules_digest', 'root', 'defs', 'source', 'prev', 'evolution'] + ($signed ? [13 => 'sig'] : []));
            if ($e !== null) {
                return "pack: $e";
            }
            if (!self::is1($x->get('v')) || $x->get('kind') !== 'pca-action-pack') {
                return 'pack: bad v/kind';
            }
            if (!is_string($x->get('ns')) || preg_match(self::NS_RE, $x->get('ns')) !== 1) {
                return 'pack: bad ns';
            }
            if (!is_string($x->get('version')) || preg_match(self::SEMVER_RE, $x->get('version')) !== 1) {
                return 'pack: version must be MAJOR.MINOR.PATCH';
            }
            if (!self::inS($x->get('stability'), self::STABILITIES)) {
                return 'pack: bad stability';
            }
            foreach (['traits_digest', 'roles_digest', 'rules_digest', 'root'] as $k) {
                if (!self::sha($x->get($k))) {
                    return "pack: $k must be a base64url digest";
                }
            }
            if (!$x->has('prev') || ($x->get('prev') !== null && !self::sha($x->get('prev')))) {
                return 'pack: bad prev';
            }
            $s = $x->get('source');
            if (!($s instanceof Obj) || self::closed($s, ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) !== null
                || count($s->keys()) !== 5) {
                return 'pack: source must be {kind, uri, spec_digest, licence, licence_notes}';
            }
            foreach (['kind', 'uri', 'spec_digest', 'licence', 'licence_notes'] as $k) {
                $v = $s->get($k);
                if (!is_string($v) || ($k !== 'licence_notes' && $v === '') || self::u16($v) > 2048) {
                    return "pack: source.$k is not a string of 1..2048 characters";
                }
            }
            $d = $x->get('defs');
            if (self::isList($d)) {
                if (count($d) === 0 || count($d) > 4096) {
                    return 'pack: inline defs must number 1..4096 (larger packs are sharded)';
                }
                $de = self::defsError($d);
                if ($de !== null) {
                    return "pack: $de";
                }
            } else {
                if (!($d instanceof Obj) || self::closed($d, ['shards']) !== null || !self::isList($d->get('shards')) || count($d->get('shards')) === 0 || count($d->get('shards')) > 4096) {
                    return 'pack: defs must be a list of defs or {shards}';
                }
                $names = [];
                foreach ($d->get('shards') as $r) {
                    if (!($r instanceof Obj) || self::closed($r, ['name', 'digest', 'uri']) !== null) {
                        return 'pack: bad shard ref';
                    }
                    $n = $r->get('name');
                    if (!is_string($n) || preg_match(self::SHARD_NAME_RE, $n) !== 1 || isset($names[$n])) {
                        return 'pack: shard names must be distinct simple names';
                    }
                    $names[$n] = true;
                    $u = $r->get('uri');
                    if (!self::sha($r->get('digest')) || !is_string($u) || $u === '' || self::u16($u) > 2048) {
                        return 'pack: bad shard digest or uri';
                    }
                }
            }
            $ev = $x->get('evolution');
            if (!self::isList($ev) || count($ev) > 65536) {
                return 'pack: evolution must be a list of records';
            }
            foreach ($ev as $r) {
                $re = self::evolutionRecordError($r);
                if ($re !== null) {
                    return "pack: $re";
                }
            }
            if ($signed) {
                $g = $x->get('sig');
                if (!($g instanceof Obj) || self::closed($g, ['alg', 'kid', 'value', 'pq_value']) !== null || !is_string($g->get('kid')) || !is_string($g->get('value')) || !is_string($g->get('alg'))) {
                    return 'pack: bad sig';
                }
            }
            IntentV2::hashCanonical($x->without('sig'));
            return null;
        } catch (\Throwable $err) {
            return 'pack: ' . $err->getMessage();
        }
    }

    /** @return list<Obj> */
    public static function packDefs(Obj $pack, mixed $shards = null): array
    {
        $d = $pack->get('defs');
        if (self::isList($d)) {
            return $d;
        }
        $all = [];
        foreach ($d->get('shards') as $r) {
            $n = $r->get('name');
            $s = $shards instanceof Obj && $shards->has($n) ? $shards->get($n) : null;
            if ($s === null) {
                throw new ActionKitError('missing_shard', "shard '$n' was not supplied");
            }
            if (self::shardDigest($s) !== $r->get('digest')) {
                throw new ActionKitError('shard_digest_mismatch', "shard '$n' does not match its digest");
            }
            if (!($s instanceof Obj) || !self::is1($s->get('v')) || $s->get('kind') !== 'pca-action-pack-shard' || $s->get('ns') !== $pack->get('ns')
                || $s->get('version') !== $pack->get('version') || $s->get('name') !== $n || !self::isList($s->get('defs'))) {
                throw new ActionKitError('bad_shard', "shard '$n' is not a shard of this pack");
            }
            array_push($all, ...$s->get('defs'));
        }
        usort($all, fn($a, $b) => self::u16cmp($a->get('verb'), $b->get('verb')));
        return $all;
    }

    /** @return array{ok:bool, reason?:string, defs?:list<Obj>, digest?:string} */
    public static function verifyPack(mixed $pack, mixed $keys, mixed $shards = null): array
    {
        try {
            $se = self::packShapeError($pack);
            if ($se !== null) {
                return ['ok' => false, 'reason' => $se];
            }
            $v = IntentV2::verifyRegistrySig(self::PACK_SIG_DOMAIN, $pack->without('sig'), $pack->get('sig'), $keys);
            if (!$v['ok']) {
                return ['ok' => false, 'reason' => 'pack signature: ' . $v['reason']];
            }
            if ($pack->get('traits_digest') !== Actions::traitsDigest(Actions::coreRegistry())) {
                return ['ok' => false, 'reason' => 'traits_digest does not match the trait registry'];
            }
            if ($pack->get('roles_digest') !== Actions::tablesDigest()) {
                return ['ok' => false, 'reason' => 'roles_digest does not match the vocabulary tables'];
            }
            if ($pack->get('rules_digest') !== self::rulesDigest()) {
                return ['ok' => false, 'reason' => 'rules_digest does not match the rule tables'];
            }
            try {
                $defs = self::packDefs($pack, $shards);
            } catch (ActionKitError $e) {
                return ['ok' => false, 'reason' => $e->getMessage()];
            }
            $de = self::defsError($defs);
            if ($de !== null) {
                return ['ok' => false, 'reason' => $de];
            }
            if (count($defs) === 0 || count($defs) > 1000000) {
                return ['ok' => false, 'reason' => 'the pack lists no defs or too many'];
            }
            $digests = array_map([Actions::class, 'defDigest'], $defs);
            if (Actions::packRoot($digests) !== $pack->get('root')) {
                return ['ok' => false, 'reason' => 'the Merkle root does not match the defs'];
            }
            $have = array_flip($digests);
            foreach ($pack->get('evolution') as $r) {
                $rv = self::verifyEvolutionRecord($r, $keys);
                if (!$rv['ok']) {
                    return ['ok' => false, 'reason' => 'evolution record: ' . $rv['reason']];
                }
                if ($r->get('ns') !== $pack->get('ns')) {
                    return ['ok' => false, 'reason' => 'evolution record of another namespace'];
                }
                if ($r->get('to') !== null && !isset($have[$r->get('to')])) {
                    return ['ok' => false, 'reason' => "evolution record for '" . $r->get('verb') . "' names a definition that is not in the pack"];
                }
            }
            return ['ok' => true, 'defs' => $defs, 'digest' => self::packDigest($pack)];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'pack verification error: ' . $e->getMessage()];
        }
    }

    // ---- rule 22 over a whole document ------------------------------------------------------------------------------------

    private const CODES = ['schema_floor_forged', 'schema_traits_forged', 'unknown_trait', 'traits_digest_mismatch', 'bad_registry'];

    /** @return array{ok:bool, code?:string} */
    public static function rule22Integrity(mixed $doc, ?Obj $pins = null): array
    {
        try {
            $e = $doc instanceof Obj ? Actions::schemaFloorError($doc, $pins) : 'bad_registry: not an object';
        } catch (\Throwable $t) {
            $e = 'schema_floor_forged: ' . $t->getMessage();
        }
        if ($e === null) {
            return ['ok' => true];
        }
        foreach (self::CODES as $c) {
            if (str_contains($e, $c)) {
                return ['ok' => false, 'code' => $c];
            }
        }
        return ['ok' => false, 'code' => 'unknown'];
    }

    public static function rule22Decide(mixed $doc, string $verb, Obj $grant, array $context): string
    {
        try {
            $v = null;
            foreach ($doc->get('verbs') ?? [] as $x) {
                if ($x->get('verb') === $verb) {
                    $v = $x;
                    break;
                }
            }
            if ($v === null || Actions::profileError($v->get('floors')) !== null) {
                return 'deny';
            }
            $kinds = array_values(array_filter($grant->get('caveats'), fn($k) => is_string($k) && in_array($k, self::CAVEATS, true)));
            $ctx = array_values(array_filter($context, fn($k) => is_string($k) && (in_array($k, self::CONTEXT, true) || preg_match('/\Asession_taint_max:[a-z_]{1,16}\z/', $k) === 1)));
            return Actions::floorDecision(Obj::of(['caveats' => $kinds, 'max_esc' => $grant->get('max_esc'), 'preauth_esc' => $grant->get('preauth_esc')]),
                Obj::of(['context' => $ctx]), Actions::profFromObj($v->get('floors')));
        } catch (\Throwable) {
            return 'deny';
        }
    }
}

/** The verifier's view of a registry: refuses rollback, fork and chain gap (the semantic diff of an upgrade is not recomputed natively). */
final class PackTracker
{
    /** @var array<string,array{version:string,digest:string}> */
    private array $seen = [];

    public function __construct(private readonly mixed $keys)
    {
    }

    /** @return array{ok:bool, status?:string, code?:string, reason?:string} */
    public function accept(mixed $pack, mixed $shards = null): array
    {
        $v = ActionsRegistry::verifyPack($pack, $this->keys, $shards);
        if (!$v['ok']) {
            return ['ok' => false, 'code' => 'bad_pack', 'reason' => $v['reason']];
        }
        $ns = $pack->get('ns');
        $cur = $this->seen[$ns] ?? null;
        $rec = ['version' => $pack->get('version'), 'digest' => $v['digest']];
        if ($cur === null) {
            $this->seen[$ns] = $rec;
            return ['ok' => true, 'status' => 'first'];
        }
        if ($cur['digest'] === $v['digest']) {
            return ['ok' => true, 'status' => 'same'];
        }
        $c = ActionsRegistry::compareVersions($pack->get('version'), $cur['version']);
        if ($c < 0) {
            return ['ok' => false, 'code' => 'rollback', 'reason' => 'older than the accepted version'];
        }
        if ($c === 0) {
            return ['ok' => false, 'code' => 'fork', 'reason' => 'two different packs claim one version'];
        }
        if ($pack->get('prev') !== $cur['digest']) {
            return ['ok' => false, 'code' => 'chain_gap', 'reason' => 'prev does not name the accepted pack'];
        }
        $this->seen[$ns] = $rec;
        return ['ok' => true, 'status' => 'upgrade'];
    }
}
