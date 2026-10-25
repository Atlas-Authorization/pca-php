<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Part of {@see IntentV2} (a trait so the 3800-line class is split into mutation-testable files): rule 13 (the PCActn member, the grant caveat, the session root).
 * Members are used through IntentV2 only; constants and shared helpers stay in IntentV2.
 */
trait IntentV2Session
{
    // ==== rule 13: the PCActn member, the grant caveat, the session root ================================================

    private static function digestList(mixed $v, string $name, int $max): ?string
    {
        if (!self::isList($v) || count($v) > $max) {
            return "'intent_session.$name' must be an array of at most $max digests";
        }
        foreach ($v as $x) {
            if (!self::b32($x)) {
                return "'intent_session.$name' entries must be canonical base64url (32 bytes)";
            }
        }
        if (!self::distinct($v)) {
            return "'intent_session.$name' entries must be distinct";
        }
        return null;
    }

    /** Wire validation of the signed `intent_session` member (validateIntentSessionWire). Null = well-formed. */
    public static function validateIntentSessionWire(mixed $v): ?string
    {
        if (!($v instanceof Obj)) {
            return "'intent_session' must be an object";
        }
        foreach (self::jsKeys($v) as $k) {
            if (!in_array($k, self::INTENT_SESSION_FIELDS, true)) {
                return "unknown field 'intent_session.$k'";
            }
        }
        foreach (['session', 'root', 'seq', 'schema'] as $k) {
            if (!$v->has($k)) {
                return "missing field 'intent_session.$k'";
            }
        }
        foreach (['session', 'root', 'schema'] as $k) {
            if (!self::b32($v->get($k))) {
                return "'intent_session.$k' is not canonical base64url (32 bytes)";
            }
        }
        $seq = $v->get('seq');
        if (!self::isNonNeg($seq) || self::f($seq) > self::MAX_SESSION_SEQ) {
            return "'intent_session.seq' must be a safe integer in [0, 2147483647]";
        }
        if ($v->has('acc')) {
            $acc = $v->get('acc');
            if (!self::isList($acc) || count($acc) > self::MAX_IS_ACC) {
                return "'intent_session.acc' must be an array of at most " . self::MAX_IS_ACC . ' entries';
            }
            $ids = [];
            foreach ($acc as $i => $a) {
                if (!($a instanceof Obj)) {
                    return "'intent_session.acc[$i]' must be an object";
                }
                foreach (self::jsKeys($a) as $k) {
                    if (!in_array($k, ['id', 'post', 'receipt'], true)) {
                        return "unknown field 'intent_session.acc[$i].$k'";
                    }
                }
                $id = self::m($a, 'id');
                if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1) {
                    return "'intent_session.acc[$i].id' must match [A-Za-z0-9_]{1,64}";
                }
                if (isset($ids['k' . $id])) {
                    return "'intent_session.acc' ids must be distinct";
                }
                $ids['k' . $id] = true;
                if (!self::isNonNeg(self::m($a, 'post'))) {
                    return "'intent_session.acc[$i].post' must be a non-negative safe integer";
                }
                if ($a->has('receipt') && !self::b32($a->get('receipt'))) {
                    return "'intent_session.acc[$i].receipt' is not canonical base64url (32 bytes)";
                }
            }
        }
        if ($v->has('facts') && ($e = self::digestList($v->get('facts'), 'facts', self::MAX_IS_FACTS)) !== null) {
            return $e;
        }
        if ($v->has('offer_set') && !self::b32($v->get('offer_set'))) {
            return "'intent_session.offer_set' is not canonical base64url (32 bytes)";
        }
        if ($v->has('prov')) {
            $prov = $v->get('prov');
            if (!($prov instanceof Obj) || count($prov->keys()) > self::MAX_IS_PROV_PATHS) {
                return "'intent_session.prov' must be an object of at most " . self::MAX_IS_PROV_PATHS . ' entries';
            }
            foreach (self::jsKeys($prov) as $path) {
                if (preg_match(self::PARAM_PATH_RE, $path) !== 1) {
                    return "'intent_session.prov' key '$path' is not action.params.<name>";
                }
                $refs = $prov->get($path);
                $ok = self::isList($refs) && count($refs) > 0 && count($refs) <= self::MAX_IS_PROV_REFS;
                foreach ($ok ? $refs : [] as $r) {
                    if (!self::isStr($r, self::MAX_IS_STRING_BYTES)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return "'intent_session.prov.$path' must be 1.." . self::MAX_IS_PROV_REFS . ' non-empty strings of at most '
                        . self::MAX_IS_STRING_BYTES . ' UTF-8 bytes';
                }
            }
        }
        if ($v->has('classes') && ($e = self::digestList($v->get('classes'), 'classes', self::MAX_IS_CLASSES)) !== null) {
            return $e;
        }
        if ($v->has('labels') && ($e = self::digestList($v->get('labels'), 'labels', self::MAX_IS_LABELS)) !== null) {
            return $e;
        }
        if ($v->has('map_form') && $v->get('map_form') !== self::MAP_FORM_COMMIT) {
            return "'intent_session.map_form' must be \"commit\" when present";
        }
        return null;
    }

    /** Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0. */
    public static function intentSessionCaveatError(mixed $c): ?string
    {
        if (!($c instanceof Obj) || self::m($c, 'type') !== self::INTENT_SESSION_CAVEAT) {
            return 'not an intent_session caveat';
        }
        foreach (self::jsKeys($c) as $k) {
            if (!in_array($k, ['type', 'session', 'seq', 'root', 'prev'], true)) {
                return "intent_session caveat: unknown member '$k'";
            }
        }
        if (!self::b32(self::m($c, 'session')) || !self::b32(self::m($c, 'root'))) {
            return 'intent_session caveat: session and root must be canonical base64url (32 bytes)';
        }
        $seq = self::m($c, 'seq');
        if (!self::isNonNeg($seq) || self::f($seq) > self::MAX_SESSION_SEQ) {
            return 'intent_session caveat: seq must be a safe integer in [0, 2147483647]';
        }
        if (self::eq($seq, 0) === $c->has('prev')) {
            return 'intent_session caveat: prev is present exactly when seq > 0';
        }
        if ($c->has('prev') && !self::b32($c->get('prev'))) {
            return 'intent_session caveat: prev must be canonical base64url (32 bytes)';
        }
        return null;
    }

    /** The FIRST caveat of `$grant` whose type is `intent_session` (as is), else absent. */
    public static function grantSessionCaveat(mixed $grant): mixed
    {
        $cv = self::m($grant, 'caveats');
        foreach (self::isList($cv) ? $cv : [] as $c) {
            if ($c instanceof Obj && self::m($c, 'type') === self::INTENT_SESSION_CAVEAT) {
                return $c;
            }
        }
        return self::undef();
    }

    private static function predicateShapeOk(mixed $p): bool
    {
        $verb = self::m($p, 'verb');
        if (!($p instanceof Obj)) {
            return false;
        }
        if (is_string($verb)) {
            return true;
        }
        return self::isList($verb) && count($verb) > 0 && count(array_filter($verb, 'is_string')) === count($verb);
    }

    /** Accumulator declaration (rule 15). Null = well-formed. */
    public static function accumulatorDeclError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'accumulator must be an object';
        }
        foreach (self::jsKeys($a) as $k) {
            if (!in_array($k, ['id', 'agg', 'val', 'unit', 'sel', 'win', 'key', 'domain_max', 'cap', 'holder'], true)) {
                return "accumulator: unknown member '$k'";
            }
        }
        $id = self::m($a, 'id');
        if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1 || in_array($id, self::RESERVED_NAMES, true)) {
            return 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
        }
        $at = "accumulator '$id'";
        $agg = self::m($a, 'agg');
        if (!is_string($agg) || !in_array($agg, self::ACC_AGGS, true)) {
            return "$at: unknown agg";
        }
        $val = self::m($a, 'val');
        if (!self::isU($val) && (!is_string($val) || preg_match(self::PARAM_PATH_RE, $val) !== 1)) {
            return "$at: val must be action.params.<name>";
        }
        $unit = self::m($a, 'unit');
        if (!self::isU($unit) && (!is_string($unit) || self::u16len($unit) > 64 || preg_match(self::UNIT_ID_RE, $unit) !== 1)) {
            return "$at: unit must be a unit id";
        }
        $sel = self::m($a, 'sel');
        if (!($sel instanceof Obj)) {
            return "$at: sel must be an object";
        }
        foreach (self::jsKeys($sel) as $k) {
            if (!in_array($k, ['verbs', 'accumulates_into', 'event'], true)) {
                return "$at: sel has unknown member '$k'";
            }
        }
        $verbs = self::m($sel, 'verbs');
        if (!self::isU($verbs)) {
            $ok = self::isList($verbs) && count($verbs) > 0 && count($verbs) <= 64;
            foreach ($ok ? $verbs : [] as $v) {
                if (!is_string($v) || $v === '') {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: sel.verbs must be 1..64 verb names";
            }
        }
        $sai = self::m($sel, 'accumulates_into');
        if (!self::isU($sai) && (!is_string($sai) || preg_match(self::UNIT_ID_RE, $sai) !== 1)) {
            return "$at: sel.accumulates_into must be a unit id";
        }
        $event = self::m($sel, 'event');
        if (!self::isU($event) && !(is_string($event) && in_array($event, ['intent_required', 'question', 'clarification'], true))) {
            return "$at: unknown sel.event";
        }
        $actionSel = !self::isU($verbs) || !self::isU($sai);
        if ($actionSel === !self::isU($event)) {
            return "$at: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind";
        }
        $w = self::m($a, 'win');
        if (!($w instanceof Obj)) {
            return "$at: win must be an object";
        }
        $wk = self::m($w, 'kind');
        if ($wk === 'task') {
            if (count($w->keys()) !== 1) {
                return "$at: win {kind: task} has no other member";
            }
        } elseif ($wk === 'sliding') {
            $ms = self::m($w, 'ms');
            if (self::sortedJoin($w) !== 'kind,ms' || !(self::isInt($ms) && self::f($ms) > 0)) {
                return "$at: win sliding needs a positive ms";
            }
        } elseif ($wk === 'period') {
            $ms = self::m($w, 'ms');
            if (self::sortedJoin($w) !== 'kind,ms,t0' || !(self::isInt($ms) && self::f($ms) > 0) || !self::isNonNeg(self::m($w, 't0'))) {
                return "$at: win period needs a positive ms and t0 >= 0";
            }
        } else {
            return "$at: unknown win kind";
        }
        $key = self::m($a, 'key');
        if ($key !== null && (!is_string($key) || preg_match(self::PARAM_PATH_RE, $key) !== 1)) {
            return "$at: key must be null or action.params.<name>";
        }
        if ($a->has('domain_max') && !self::isNonNeg($a->get('domain_max'))) {
            return "$at: domain_max must be a non-negative safe integer";
        }
        if ($a->has('cap') && !self::isNonNeg($a->get('cap'))) {
            return "$at: cap must be a non-negative safe integer";
        }
        $h = self::m($a, 'holder');
        if (!($h instanceof Obj)) {
            return "$at: holder must be an object";
        }
        $hk = self::m($h, 'kind');
        if ($hk === 'site_local' || $hk === 'wallet') {
            if (count($h->keys()) !== 1) {
                return "$at: holder $hk has no other member";
            }
        } elseif ($hk === 'sequenced') {
            foreach (self::jsKeys($h) as $k) {
                if (!in_array($k, ['kind', 'uri', 'root', 'root_alg', 'root_pq_pk', 'keys_uri'], true)) {
                    return "$at: holder sequenced has unknown member '$k'";
                }
            }
            $uri = self::m($h, 'uri');
            if (!is_string($uri) || $uri === '') {
                return "$at: holder sequenced needs a uri";
            }
            if (Pca::unb64u(self::m($h, 'root'), 32) === null) {
                return "$at: holder.root is not canonical base64url (32 bytes)";
            }
            if (($se = self::suiteError(self::m($h, 'root_alg'))) !== null) {
                return "$at: holder.root_alg: $se";
            }
            if ($h->has('root_pq_pk') && Pca::unb64u($h->get('root_pq_pk')) === null) {
                return "$at: holder.root_pq_pk is not canonical base64url";
            }
            if ($h->has('keys_uri') && (!is_string($h->get('keys_uri')) || $h->get('keys_uri') === '')) {
                return "$at: holder.keys_uri must be a non-empty string";
            }
        } else {
            return "$at: unknown holder kind";
        }
        $wallet = $hk === 'wallet';
        if ($wallet !== !self::isU($event)) {
            return "$at: wallet events are wallet-held and only wallet events are";
        }
        if (!$wallet) {
            if ($agg !== 'count' && self::isU($val) && self::isU($sai)) {
                return "$at: $agg needs val (or sel.accumulates_into for a sum)";
            }
            if ($agg !== 'sum' && $agg !== 'count' && self::isU($val)) {
                return "$at: $agg needs val";
            }
            if ($agg === 'count' && !self::isU($val)) {
                return "$at: count takes no val";
            }
        }
        return null;
    }

    /** Monitor declaration (rule 15). Null = well-formed. */
    public static function monitorDeclError(mixed $m): ?string
    {
        if (!($m instanceof Obj)) {
            return 'monitor must be an object';
        }
        foreach (self::jsKeys($m) as $k) {
            if (!in_array($k, ['id', 'kind', 'p', 'q', 'status', 'within'], true)) {
                return "monitor: unknown member '$k'";
            }
        }
        $id = self::m($m, 'id');
        if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1 || in_array($id, self::RESERVED_NAMES, true)) {
            return 'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
        }
        $at = "monitor '$id'";
        $kind = self::m($m, 'kind');
        if (!is_string($kind) || !in_array($kind, self::MONITOR_KINDS, true)) {
            return "$at: unknown kind";
        }
        if (!self::predicateShapeOk(self::m($m, 'p'))) {
            return "$at: p must be a predicate";
        }
        $needsQ = $kind === 'requires_prior' || $kind === 'precedes' || $kind === 'responds_within';
        if ($needsQ !== $m->has('q')) {
            return "$at: q is required exactly for requires_prior / precedes / responds_within";
        }
        if ($m->has('q') && !self::predicateShapeOk($m->get('q'))) {
            return "$at: q must be a predicate";
        }
        if ($m->has('status') && $m->get('status') !== 'admitted' && $m->get('status') !== 'committed') {
            return "$at: status must be admitted or committed";
        }
        if (($kind === 'responds_within') !== $m->has('within')) {
            return "$at: within is required exactly for responds_within";
        }
        $within = self::m($m, 'within');
        if (!self::isU($within) && !(self::isInt($within) && self::f($within) >= 1 && self::f($within) <= self::MAX_MONITOR_WITHIN)) {
            return "$at: within must be an integer in 1.." . self::MAX_MONITOR_WITHIN;
        }
        return null;
    }

    /** The state set Q of a monitor. @return list<string> */
    public static function monitorStates(mixed $m): array
    {
        $kind = self::m($m, 'kind');
        // strict, like the reference: a non-string `kind` must not loosely match a case (true == 'requires_prior')
        switch (is_string($kind) ? $kind : '') {
            case 'requires_prior':
            case 'precedes':
                return ['unmet', 'met'];
            case 'never':
                return ['clean', 'seen'];
            case 'always':
                return ['ok', 'broken'];
            case 'responds_within':
                $w = self::m($m, 'within');
                $out = ['idle'];
                for ($i = 1, $n = self::isInt($w) ? self::iv($w) : 0; $i <= $n; $i++) {
                    $out[] = "pending:$i";
                }
                $out[] = 'missed';
                return $out;
            default:
                return [];
        }
    }

    /** sessionRootShapeError (signed). Null = well-formed. Never throws. */
    public static function sessionRootShapeError(mixed $s): ?string
    {
        try {
            if (!($s instanceof Obj)) {
                return 'session root is not an object';
            }
            foreach (self::jsKeys($s) as $k) {
                if (!in_array($k, self::ROOT_KEYS, true)) {
                    return "session root: unknown member '$k'";
                }
            }
            if (!self::eq(self::m($s, 'v'), 1) || self::m($s, 'kind') !== self::INTENT_SESSION_KIND) {
                return 'not a pca-intent-session v1';
            }
            if (!self::b32(self::m($s, 'session')) || !self::b32(self::m($s, 'intent_ref'))) {
                return 'session and intent_ref must be canonical base64url (32 bytes)';
            }
            $principals = self::m($s, 'principals');
            if (!self::isList($principals) || count($principals) === 0 || count($principals) > self::MAX_SESSION_PRINCIPALS) {
                return 'principals must be 1..' . self::MAX_SESSION_PRINCIPALS . ' keys';
            }
            $keys = [];
            foreach ($principals as $p) {
                $ok = $p instanceof Obj && self::b32(self::m($p, 'key'));
                foreach ($ok ? self::jsKeys($p) : [] as $k) {
                    if (!in_array($k, ['key', 'alg', 'pq_pk'], true)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return 'principals entries are {key, alg?, pq_pk?} with a 32-byte key';
                }
                if (($se = self::suiteKnownError(self::m($p, 'alg'))) !== null) {
                    return "principal alg: $se";
                }
                if ($p->has('pq_pk') && Pca::unb64u($p->get('pq_pk')) === null) {
                    return 'principal pq_pk is not canonical base64url';
                }
                if (isset($keys['k' . $p->get('key')])) {
                    return 'principal keys must be distinct';
                }
                $keys['k' . $p->get('key')] = true;
            }
            $schema = self::m($s, 'schema');
            if (!($schema instanceof Obj) || self::sortedJoin($schema) !== 'aud,digest' || !is_string(self::m($schema, 'aud'))
                || $schema->get('aud') === '' || !self::b32(self::m($schema, 'digest'))) {
                return 'schema must be {aud, digest}';
            }
            $L = self::m($s, 'layers');
            if (!($L instanceof Obj)) {
                return 'layers must be an object';
            }
            foreach (self::jsKeys($L) as $k) {
                if (!in_array($k, ['org', 'std', 'task'], true)) {
                    return "layers: unknown member '$k'";
                }
            }
            $task = self::m($L, 'task');
            if (!($task instanceof Obj) || implode(',', self::jsKeys($task)) !== 'map_digest' || !self::b32(self::m($task, 'map_digest'))) {
                return 'layers.task must be {map_digest}';
            }
            if ($L->has('org') && (!($L->get('org') instanceof Obj) || !self::b32(self::m($L->get('org'), 'digest')))) {
                return 'layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)';
            }
            if ($L->has('std')) {
                $d = $L->get('std');
                $prof = self::m($d, 'profile');
                $ver = self::m($d, 'version');
                if (!($d instanceof Obj) || self::sortedJoin($d) !== 'digest,profile,version' || !is_string($prof) || $prof === ''
                    || strlen($prof) > 128 || !(self::isInt($ver) && self::f($ver) >= 1) || !self::b32(self::m($d, 'digest'))) {
                    return 'layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)';
                }
            }
            $accs = self::m($s, 'accumulators');
            if (!self::isList($accs) || count($accs) > self::MAX_SESSION_ACCUMULATORS) {
                return 'accumulators must be an array of at most ' . self::MAX_SESSION_ACCUMULATORS;
            }
            $ids = [];
            foreach ($accs as $a) {
                if (($e = self::accumulatorDeclError($a)) !== null) {
                    return $e;
                }
                if (isset($ids['k' . $a->get('id')])) {
                    return 'accumulator and monitor ids must be distinct';
                }
                $ids['k' . $a->get('id')] = true;
            }
            $mons = self::m($s, 'monitors');
            if (!self::isList($mons) || count($mons) > self::MAX_SESSION_MONITORS) {
                return 'monitors must be an array of at most ' . self::MAX_SESSION_MONITORS;
            }
            $mids = [];
            foreach ($mons as $mo) {
                if (($e = self::monitorDeclError($mo)) !== null) {
                    return $e;
                }
                if (isset($mids['k' . $mo->get('id')])) {
                    return 'monitor ids must be distinct';
                }
                $mids['k' . $mo->get('id')] = true;
            }
            $qu = self::m($s, 'question_uri');
            if (!is_string($qu) || $qu === '' || strlen($qu) > 2048) {
                return 'question_uri must be a non-empty string';
            }
            if ($s->has('revocation')) {
                $r = $s->get('revocation');
                $ok = $r instanceof Obj;
                foreach ($ok ? self::jsKeys($r) : [] as $k) {
                    if (!in_array($k, ['epoch_uri', 'max_age_s', 'key', 'pq_pk'], true)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return 'revocation must be {epoch_uri, max_age_s, key, pq_pk?}';
                }
                $eu = self::m($r, 'epoch_uri');
                if (!is_string($eu) || $eu === '') {
                    return 'revocation.epoch_uri must be a non-empty string';
                }
                if (!self::isNonNeg(self::m($r, 'max_age_s'))) {
                    return 'revocation.max_age_s must be a non-negative safe integer';
                }
                if (!self::b32(self::m($r, 'key'))) {
                    return 'revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)';
                }
                if (isset($keys['k' . $r->get('key')])) {
                    return 'revocation.key must not be a session principal (a dedicated revocation authority)';
                }
                if ($r->has('pq_pk') && Pca::unb64u($r->get('pq_pk')) === null) {
                    return 'revocation.pq_pk must be canonical base64url';
                }
            }
            if ($s->has('flows') && !($s->get('flows') instanceof Obj)) {
                return 'flows must be an object';
            }
            if (!self::isNonNeg(self::m($s, 'expires_at'))) {
                return 'expires_at must be a non-negative safe integer (epoch ms)';
            }
            $signer = self::m($s, 'signer');
            if (!self::b32($signer)) {
                return 'signer must be canonical base64url (32 bytes)';
            }
            if (!isset($keys['k' . $signer])) {
                return 'signer is not one of the session principals';
            }
            if (($se = self::suiteKnownError(self::m($s, 'alg'))) !== null) {
                return "alg: $se";
            }
            if (self::suiteOf(self::m($s, 'alg')) === 'ed25519' && ($s->has('pq_pk') || $s->has('pq_sig'))) {
                return 'an ed25519 session root must not carry pq_pk / pq_sig';
            }
            if (!is_string(self::m($s, 'sig'))) {
                return 'sig must be a string';
            }
            self::canonicalize(self::sessionRootBody($s));
            return null;
        } catch (\Throwable $e) {
            return 'malformed session root: ' . $e->getMessage();
        }
    }

    private static function sessionRootBody(Obj $s): Obj
    {
        $o = new Obj();
        foreach (['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors', 'question_uri'] as $k) {
            $o->set($k, self::m($s, $k));
        }
        foreach (['revocation', 'flows'] as $k) {
            if ($s->has($k)) {
                $o->set($k, $s->get($k));
            }
        }
        $o->set('expires_at', self::m($s, 'expires_at'));
        return $o;
    }

    /**
     * verifySessionRoot: shape, signer listed, suite signature. R3-01 (fail closed): a non-ed25519 root verifies only under
     * the VERIFIER's pin for its signer (`$pins` = context session.pq_pins, an Obj; its own member for the signer must be a
     * string), never under the root's own principals[].pq_pk; the signer's own entry, when it declares a pq_pk, must agree.
     * An ed25519 root never consults the pins. @return array{ok:bool, reason?:string}
     */
    public static function verifySessionRoot(mixed $s, mixed $pins = null): array
    {
        try {
            $bad = self::sessionRootShapeError($s);
            if ($bad !== null) {
                return self::bad($bad);
            }
            /** @var Obj $s */
            $signer = $s->get('signer');
            $p = null;
            foreach ($s->get('principals') as $x) {
                if ($x->get('key') === $signer) {
                    $p = $x;
                    break;
                }
            }
            $body = self::sessionRootBody($s);
            $body->set('signer', $signer);
            $alg = self::m($s, 'alg');
            $pq = self::m($s, 'pq_pk');
            $pin = null;
            if (self::suiteOf($alg) !== 'ed25519') {
                $pin = $pins instanceof Obj && $pins->has($signer) ? $pins->get($signer) : null;
                if (!is_string($pin)) {
                    return self::bad("session root suite '" . self::suiteOf($alg) . "' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it");
                }
                if ($pq !== $pin) {
                    return self::bad("session root pq_pk does not match the verifier's pin for the signer");
                }
                if ($p !== null && $p->has('pq_pk') && $p->get('pq_pk') !== $pq) {
                    return self::bad("session root pq_pk does not match the signer's principals entry");
                }
            }
            if (($se = self::suiteError($alg)) !== null) {
                return self::bad("alg: $se");
            }
            $msg = self::INTENT_SESSION_SIG_DOMAIN . self::canonicalize(self::bindSuite($body, $alg, $pq));
            if (!self::verifyPinned($alg, $signer, $pq, $msg, self::m($s, 'sig'), self::m($s, 'pq_sig'),
                $pin !== null ? $signer : null, $pin)) {
                return self::bad('session root signature invalid');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('malformed session root: ' . $e->getMessage());
        }
    }

    /** digest(S): the content address of the whole signed session root. */
    public static function sessionRootDigest(mixed $s): string
    {
        return self::hashCanonical(Obj::of(['d' => self::INTENT_SESSION_REF_DOMAIN, 's' => $s]));
    }
}
