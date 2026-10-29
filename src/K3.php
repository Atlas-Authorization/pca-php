<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/FreshAt.php';

/**
 * K3 operational-plane artifacts, verification only: signed policy bundles, decision records and log heads (hash chain, Merkle
 * inclusion, batches), list-authorized receipts and cursors, and the grant-management signatures (amend / revoke / need approval).
 * Every signature is a strict Ed25519 signature over DOMAIN || strict canonical JSON of the body (the domain strings end in a NUL
 * byte). Inputs are the library's JSON values (Obj, lists, strings, Num). Every function is total: malformed input returns the
 * failure value of the shared vectors (k3-vectors.json), never throws.
 */
final class K3
{
    public const BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\0";
    public const BUNDLE_REF_DOMAIN = 'atlas-pca/policy-bundle-ref/v1';
    public const RECORD_DOMAIN = 'atlas-pca/decision-record/v1';
    public const LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\0";
    public const LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\0";
    public const LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\0";
    public const GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\0";
    public const GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\0";
    public const NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\0";
    private const MAX_LIST = 4096;

    private static function str(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    /** A JS template-literal rendering of a value (only for reason texts). */
    private static function js(mixed $v, bool $present = true): string
    {
        if (!$present) {
            return 'undefined';
        }
        if ($v instanceof Num) {
            return $v->isInt() ? (string)(int)$v->lexeme : $v->lexeme;
        }
        return match (true) {
            is_string($v) => $v,
            $v === null => 'null',
            is_bool($v) => $v ? 'true' : 'false',
            default => '[object Object]',
        };
    }

    private static function int(mixed $v): int
    {
        return (int)K3Sig::num($v);
    }

    private static function same(mixed $a, mixed $b): bool
    {
        $x = K3Sig::num($a);
        return $x !== null && $x === K3Sig::num($b);
    }

    // ---- signed policy bundles ----------------------------------------------------------------------------------------------

    public static function bundleDigest(mixed $b): ?string
    {
        try {
            return $b instanceof Obj ? Pca::hashCanonical(Obj::of(['d' => self::BUNDLE_REF_DOMAIN, 'b' => $b->without('sigs')])) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** Version compare of dotted numerics; -1 / 0 / 1 (a segment that is not a number compares as greater, like NaN in the reference). */
    public static function compareVersion(string $a, string $b): int
    {
        $seg = static fn(?string $s): float => $s === null || $s === '' ? 0.0 : (preg_match('/\A[0-9]+\z/D', $s) === 1 ? (float)$s : NAN);
        $pa = explode('.', $a);
        $pb = explode('.', $b);
        for ($i = 0, $n = max(count($pa), count($pb)); $i < $n; $i++) {
            $d = $seg($pa[$i] ?? null) - $seg($pb[$i] ?? null);
            if (is_nan($d)) {
                return 1;
            }
            if ($d !== 0.0) {
                return $d < 0 ? -1 : 1;
            }
        }
        return 0;
    }

    public static function bundleShapeError(mixed $b): ?string
    {
        if (!($b instanceof Obj) || !K3Sig::isNumber($b->get('v'), 1.0) || $b->get('kind') !== 'pca-policy-bundle') {
            return 'not a policy bundle';
        }
        if (!K3Sig::isSafeInt($b->get('revision')) || K3Sig::num($b->get('revision')) < 1 || !K3Sig::isSafeInt($b->get('issued_at'))) {
            return 'bad revision or time';
        }
        if (K3Sig::isNumber($b->get('revision'), 1.0) ? $b->has('prev') : !K3Sig::isStr($b->get('prev'), 128)) {
            return 'prev must be absent at revision 1 and present after';
        }
        foreach (['grants' => 'bad grants', 'template_digests' => 'bad template_digests'] as $k => $msg) {
            $l = $b->get($k);
            if (!K3Sig::isList($l) || count($l) > self::MAX_LIST) {
                return $msg;
            }
            foreach ($l as $g) {
                if (!K3Sig::isStr($g, 128)) {
                    return $msg;
                }
            }
        }
        foreach (['schema_digest', 'constitution_digest', 'flow_rules_digest'] as $k) {
            if ($b->has($k) && !K3Sig::isStr($b->get($k), 128)) {
                return "bad $k";
            }
        }
        $v = $b->get('min_verifier_version');
        if (!is_string($v) || preg_match('/\A\d{1,6}(\.\d{1,6}){0,3}\z/D', $v) !== 1) {
            return 'bad min_verifier_version';
        }
        return null;
    }

    /**
     * Verify a k-of-n signed bundle. `$o`: {signers, threshold, verifierVersion, last?: {revision, digest}}.
     *
     * @return array{ok:true, revision:int, digest:string, signers:list<string>}|array{ok:false, code:string, reason:string}
     */
    public static function verifyBundle(mixed $b, mixed $o): array
    {
        try {
            $e = self::bundleShapeError($b);
            if ($e !== null) {
                return ['ok' => false, 'code' => 'malformed', 'reason' => $e];
            }
            /** @var Obj $b */
            $sigs = $b->get('sigs');
            $th = self::str($o, 'threshold');
            if (!K3Sig::isList($sigs) || count($sigs) > 64 || !K3Sig::anySafeInt($th) || K3Sig::num($th) < 1) {
                return ['ok' => false, 'code' => 'malformed', 'reason' => 'bad sigs or threshold'];
            }
            $pinned = self::str($o, 'signers');
            $pinned = K3Sig::isList($pinned) ? $pinned : [];
            $body = $b->without('sigs');
            $good = [];
            foreach ($sigs as $s) {
                $who = self::str($s, 'signer');
                if ($s instanceof Obj && is_string($who) && in_array($who, $pinned, true) && !in_array($who, $good, true)
                    && K3Sig::verifyBody(self::BUNDLE_DOMAIN, $body, $who, $s->get('sig'))) {
                    $good[] = $who;
                }
            }
            if (count($good) < self::int($th)) {
                return ['ok' => false, 'code' => 'below_threshold', 'reason' => count($good) . ' valid pinned signature(s), need ' . self::int($th)];
            }
            $ver = self::str($o, 'verifierVersion');
            $min = (string)$b->get('min_verifier_version');
            // an unparseable verifier version is too old, never newer (fail closed)
            if (!is_string($ver) || preg_match('/\A[0-9]{1,6}(\.[0-9]{1,6}){0,3}\z/D', $ver) !== 1 || self::compareVersion($ver, $min) < 0) {
                return ['ok' => false, 'code' => 'verifier_too_old', 'reason' => "needs verifier >= $min"];
            }
            $digest = (string)self::bundleDigest($b);
            $last = self::str($o, 'last');
            if ($last instanceof Obj) {
                $rev = K3Sig::num($b->get('revision'));
                $lrev = K3Sig::num($last->get('revision'));
                if ($lrev !== null) {
                    if ($rev < $lrev) {
                        return ['ok' => false, 'code' => 'rollback', 'reason' => 'revision ' . self::int($b->get('revision')) . ' < accepted ' . self::int($last->get('revision'))];
                    }
                    if ($rev === $lrev && $digest !== $last->get('digest')) {
                        return ['ok' => false, 'code' => 'broken_chain', 'reason' => 'same revision, different content'];
                    }
                    if ($rev === $lrev + 1 && $b->get('prev') !== $last->get('digest')) {
                        return ['ok' => false, 'code' => 'broken_chain', 'reason' => 'prev does not chain to the accepted revision'];
                    }
                }
            }
            return ['ok' => true, 'revision' => self::int($b->get('revision')), 'digest' => $digest, 'signers' => $good];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'malformed', 'reason' => 'bad sigs or threshold'];
        }
    }

    // ---- decision records, log heads, batches ------------------------------------------------------------------------------

    public static function recordCommit(mixed $r): ?string
    {
        try {
            return Pca::hashCanonical(Obj::of(['d' => self::RECORD_DOMAIN, 'r' => $r]));
        } catch (\Throwable) {
            return null;
        }
    }

    public static function verifyLogHead(mixed $h, mixed $signer): bool
    {
        if (!($h instanceof Obj) || !K3Sig::isNumber($h->get('v'), 1.0) || $h->get('signer') !== $signer || !K3Sig::isSafeInt($h->get('size'))
            || !K3Sig::isSafeInt($h->get('issued_at')) || !is_string($h->get('root')) || !is_string($h->get('last_commit'))) {
            return false;
        }
        return K3Sig::verifyBody(self::LOG_HEAD_DOMAIN, $h->without('sig'), $signer, $h->get('sig'));
    }

    /** Offline: this record is in the log the signed head commits to, and the head is by the pinned signer. */
    public static function verifyRecordInclusion(mixed $rec, mixed $proof, mixed $head, mixed $signer): bool
    {
        try {
            $commit = self::recordCommit($rec);
            return $commit !== null && self::verifyLogHead($head, $signer) && Pca::verifyInclusion((string)self::str($head, 'root'), $proof, $commit);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Receiver side of the decision stream: contiguous sequence, intact hash chain from `$state` {next, lastCommit}, and (when the
     * batch reaches the head) the head's last commit and size match.
     *
     * @return array{ok:true, next:int, lastCommit:string}|array{ok:false, reason:string}
     */
    public static function verifyBatch(mixed $b, mixed $state, mixed $signer): array
    {
        try {
            if (!($b instanceof Obj) || !($state instanceof Obj)) {
                return ['ok' => false, 'reason' => 'malformed batch'];
            }
            if (!self::same($b->get('from'), $state->get('next'))) {
                return ['ok' => false, 'reason' => 'gap or replay: batch starts at ' . self::js($b->get('from'), $b->has('from')) . ', expected ' . self::js($state->get('next'), $state->has('next'))];
            }
            $head = $b->get('head');
            if (!self::verifyLogHead($head, $signer)) {
                return ['ok' => false, 'reason' => 'head not signed by the pinned log signer'];
            }
            $recs = $b->get('records');
            if (!K3Sig::isList($recs)) {
                return ['ok' => false, 'reason' => 'malformed batch'];
            }
            $last = $state->get('lastCommit');
            $n = self::int($state->get('next'));
            foreach ($recs as $r) {
                if ($r === null) {
                    return ['ok' => false, 'reason' => 'malformed batch'];
                }
                if (!($r instanceof Obj) || !self::same($r->get('seq'), $n) || $r->get('prev') !== $last) {
                    return ['ok' => false, 'reason' => 'chain broken at seq ' . ($r instanceof Obj ? self::js($r->get('seq'), $r->has('seq')) : 'undefined')];
                }
                $last = self::recordCommit($r);
                if ($last === null) {
                    return ['ok' => false, 'reason' => 'malformed batch'];
                }
                $n++;
            }
            $size = K3Sig::num($head->get('size'));
            if ($n > $size) {
                return ['ok' => false, 'reason' => 'batch is longer than the signed head'];
            }
            if ($n === (int)$size && $last !== $head->get('last_commit')) {
                return ['ok' => false, 'reason' => 'batch end does not match the signed head'];
            }
            return ['ok' => true, 'next' => $n, 'lastCommit' => (string)$last];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'malformed batch'];
        }
    }

    // ---- list-authorized ----------------------------------------------------------------------------------------------------

    public static function objectsDigest(mixed $objects): ?string
    {
        try {
            return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/list-objects/v1', 'o' => $objects]));
        } catch (\Throwable) {
            return null;
        }
    }

    /** The receipt is well formed and signed by `$signer`; with `$objects` given, they are exactly the ones it counts and digests. */
    public static function verifyListReceipt(mixed $r, mixed $signer, mixed $objects = null, bool $hasObjects = false): bool
    {
        if (!($r instanceof Obj) || !K3Sig::isNumber($r->get('v'), 1.0) || $r->get('signer') !== $signer || !K3Sig::isStr($r->get('subject'))
            || !K3Sig::isStr($r->get('resource_type')) || !K3Sig::isSafeInt($r->get('count')) || !K3Sig::isSafeInt($r->get('issued_at'))) {
            return false;
        }
        if (!K3Sig::verifyBody(self::LIST_RECEIPT_DOMAIN, $r->without('sig'), $signer, $r->get('sig'))) {
            return false;
        }
        return !$hasObjects || (K3Sig::isList($objects) && self::same(count($objects), $r->get('count')) && self::objectsDigest($objects) === $r->get('objects_digest'));
    }

    /** What a page cursor is bound to. `$a`: {subject, resourceType, filterId, policyDigest, limit, relation?: {relation}}. */
    public static function listBind(mixed $a): ?string
    {
        try {
            $rel = self::str($a, 'relation');
            return Pca::hashCanonical(Obj::of([
                's' => self::str($a, 'subject'), 't' => self::str($a, 'resourceType'), 'f' => self::str($a, 'filterId'),
                'p' => self::str($a, 'policyDigest'), 'r' => self::str($rel, 'relation'), 'l' => self::str($a, 'limit'),
            ]));
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Shape, signature by `$signer` and (when `$bind` is given) that the cursor was issued for exactly those inputs.
     *
     * @return array{ok:true, skip:int, inner?:string}|array{ok:false, reason:string}
     */
    public static function verifyListCursor(mixed $tok, mixed $signer, mixed $bind = null): array
    {
        $bad = ['ok' => false, 'reason' => 'malformed'];
        try {
            if (!is_string($tok)) {
                return $bad;
            }
            $parts = explode('.', $tok);
            $raw = $parts[0] !== '' ? Pca::unb64u($parts[0]) : null;
            $c = $raw !== null ? Json::parseLax($raw) : null;
            $s = $parts[1] ?? '';
            if (count($parts) > 2 || !($c instanceof Obj) || $s === '' || !K3Sig::isNumber($c->get('v'), 1.0) || !is_string($c->get('bind'))
                || !K3Sig::isSafeInt($c->get('skip')) || ($c->has('inner') && !is_string($c->get('inner')))) {
                return $bad;
            }
            if ($c->get('signer') !== $signer || !K3Sig::verifyBody(self::LIST_CURSOR_DOMAIN, $c, $signer, $s)) {
                return ['ok' => false, 'reason' => 'signature'];
            }
            if ($bind !== null && $c->get('bind') !== self::listBind($bind)) {
                return ['ok' => false, 'reason' => 'bind'];
            }
            $out = ['ok' => true, 'skip' => self::int($c->get('skip'))];
            if ($c->has('inner')) {
                $out['inner'] = $c->get('inner');
            }
            return $out;
        } catch (\Throwable) {
            return $bad;
        }
    }

    // ---- authority ----------------------------------------------------------------------------------------------------------

    private static function lim(mixed $a): ?Obj
    {
        $l = self::str($a, 'limits');
        return $l instanceof Obj ? $l : null;
    }

    /** The comparable authority shape is well formed (`checkAuthority` of the reference). */
    public static function authorityOk(mixed $a): bool
    {
        if (!($a instanceof Obj)) {
            return false;
        }
        foreach (['verbs' => [256, 128], 'resources' => [1024, 512]] as $k => [$max, $len]) {
            $l = $a->get($k);
            if (!K3Sig::isList($l) || count($l) > $max) {
                return false;
            }
            foreach ($l as $v) {
                if (!K3Sig::isStr($v, $len)) {
                    return false;
                }
            }
        }
        if ($a->has('limits')) {
            $l = $a->get('limits');
            if (!($l instanceof Obj)) {
                return false;
            }
            foreach ($l->keys() as $k) {
                $v = K3Sig::num($l->get($k));
                if ($v === null || $v < 0) {
                    return false;
                }
            }
        }
        return !$a->has('expires_at') || K3Sig::isSafeInt($a->get('expires_at'));
    }

    public static function authorityDigest(mixed $a): ?string
    {
        try {
            $copy = new Obj();
            foreach ($a->keys() as $k) {
                $v = $a->get($k);
                $copy->set($k, ($k === 'verbs' || $k === 'resources') && is_array($v) ? K3Sig::sortedUtf16($v) : $v);
            }
            return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/authority/v1', 'a' => $copy]));
        } catch (\Throwable) {
            return null;
        }
    }

    private static function resCovers(string $p, string $r): bool
    {
        return str_ends_with($p, '*') ? str_starts_with($r, substr($p, 0, -1)) : $p === $r;
    }

    /** everything `$a` allows, `$b` allows */
    private static function le(Obj $a, Obj $b): bool
    {
        foreach ($a->get('verbs') as $v) {
            if (!in_array($v, $b->get('verbs'), true)) {
                return false;
            }
        }
        foreach ($a->get('resources') as $s) {
            $covered = false;
            foreach ($b->get('resources') as $p) {
                if (self::resCovers($p, $s) && (!str_ends_with($s, '*') || str_ends_with($p, '*') || $p === $s)) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                return false;
            }
        }
        $al = self::lim($a);
        $bl = self::lim($b);
        foreach ($al?->keys() ?? [] as $k) {
            if ($bl !== null && $bl->has($k) && !(K3Sig::num($al->get($k)) <= K3Sig::num($bl->get($k)))) {
                return false;
            }
        }
        foreach ($bl?->keys() ?? [] as $k) {
            if ($al === null || !$al->has($k)) {
                return false;
            }
        }
        $ae = $a->has('expires_at') ? K3Sig::num($a->get('expires_at')) : INF;
        $be = $b->has('expires_at') ? K3Sig::num($b->get('expires_at')) : INF;
        return $ae <= $be;
    }

    /** 'narrower' | 'equal' | 'wider' | 'incomparable' */
    public static function compareAuthority(Obj $old, Obj $new): string
    {
        $nle = self::le($new, $old);
        $ole = self::le($old, $new);
        return $nle && $ole ? 'equal' : ($nle ? 'narrower' : ($ole ? 'wider' : 'incomparable'));
    }

    /** Union; a ceiling or expiry is only ever RAISED by the delta, one the delta omits is kept. */
    public static function mergeAuthority(Obj $a, Obj $d): Obj
    {
        $limits = new Obj();
        $al = self::lim($a);
        $dl = self::lim($d);
        foreach ($al?->keys() ?? [] as $k) {
            $v = $al->get($k);
            $dv = $dl !== null && $dl->has($k) ? $dl->get($k) : $v;
            $limits->set($k, K3Sig::num($v) >= K3Sig::num($dv) ? $v : $dv);
        }
        $out = new Obj();
        $out->set('verbs', array_values(array_unique(array_merge($a->get('verbs'), $d->get('verbs')))));
        $out->set('resources', array_values(array_unique(array_merge($a->get('resources'), $d->get('resources')))));
        if ($limits->keys() !== []) {
            $out->set('limits', $limits);
        }
        if ($a->has('expires_at')) {
            $ae = $a->get('expires_at');
            $de = $d->has('expires_at') ? $d->get('expires_at') : $ae;
            $out->set('expires_at', K3Sig::num($ae) >= K3Sig::num($de) ? $ae : $de);
        }
        return $out;
    }

    /**
     * Decide an amendment against the current grant facts. Order is normative: request shape, authority shape, grant active,
     * classification, signature (the PRINCIPAL when it widens), step-up. `$stepUpOk` is the already evaluated step-up verdict.
     *
     * @return array{ok:true, widens:bool, next:Obj}|array{ok:false, code:string}
     */
    public static function verifyAmendment(mixed $cur, mixed $req, bool $stepUpOk): array
    {
        try {
            if (!($cur instanceof Obj) || !($req instanceof Obj) || !in_array($req->get('action'), ['narrow', 'merge', 'replace'], true)) {
                return ['ok' => false, 'code' => 'bad_request'];
            }
            $action = $req->get('action');
            $auth = $req->get('authority');
            if (!self::authorityOk($auth)) {
                return ['ok' => false, 'code' => 'bad_request'];
            }
            if ($cur->get('status') !== 'active') {
                return ['ok' => false, 'code' => 'not_active'];
            }
            $next = $action === 'merge' ? self::mergeAuthority($cur->get('authority'), $auth) : $auth;
            $order = self::compareAuthority($cur->get('authority'), $next);
            $widens = $order === 'wider' || $order === 'incomparable';
            if (!$widens && $action === 'narrow' && $order === 'equal') {
                return ['ok' => false, 'code' => 'not_narrower'];
            }
            if ($widens && $action === 'narrow') {
                return ['ok' => false, 'code' => 'not_narrower'];
            }
            $by = $req->get('signed_by');
            if (!is_string($req->get('sig')) || ($by !== 'holder' && $by !== 'principal')) {
                return ['ok' => false, 'code' => 'signature_required'];
            }
            if ($widens && $by !== 'principal') {
                return ['ok' => false, 'code' => 'signature_required'];
            }
            $msg = Obj::of(['grant' => $cur->get('id'), 'rev' => $cur->get('rev'), 'action' => $action, 'authority' => self::authorityDigest($auth)]);
            if (!K3Sig::verifyBody(self::GRANT_AMEND_DOMAIN, $msg, $by === 'principal' ? $cur->get('principal') : $cur->get('agent'), $req->get('sig'))) {
                return ['ok' => false, 'code' => 'bad_signature'];
            }
            if ($widens && !$stepUpOk) {
                return ['ok' => false, 'code' => 'step_up_required'];
            }
            return ['ok' => true, 'widens' => $widens, 'next' => $next];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'bad_request'];
        }
    }

    /**
     * The principal's signature over (grant id, scope).
     *
     * @return array{ok:true, scope:string}|array{ok:false, code:string}
     */
    public static function verifyRevokeSignature(mixed $root, mixed $scope, mixed $sig): array
    {
        if (!in_array($scope, ['grant', 'agent', 'subtree'], true)) {
            return ['ok' => false, 'code' => 'bad_request'];
        }
        $msg = Obj::of(['grant' => self::str($root, 'id'), 'scope' => $scope]);
        return K3Sig::verifyBody(self::GRANT_REVOKE_DOMAIN, $msg, self::str($root, 'principal'), $sig)
            ? ['ok' => true, 'scope' => $scope] : ['ok' => false, 'code' => 'bad_signature'];
    }

    /**
     * A needs approval: pending, principal signature over (need, grant, rev, approved), same count, each approved need names the
     * same verb and resource with amounts only LOWERED (and only when `adjustable`), step-up. Yields the merged authority.
     *
     * @return array{ok:true, authority:Obj}|array{ok:false, code:string}
     */
    public static function verifyNeedApproval(mixed $nr, mixed $g, mixed $approved, mixed $sig, bool $stepUpOk): array
    {
        try {
            if (!($nr instanceof Obj) || !($g instanceof Obj)) {
                return ['ok' => false, 'code' => 'bad_request'];
            }
            if ($nr->get('status') !== 'pending') {
                return ['ok' => false, 'code' => 'conflict'];
            }
            $msg = Obj::of(['need' => $nr->get('id'), 'grant' => $nr->get('grant_id'), 'rev' => $g->get('rev'), 'approved' => $approved]);
            if (!K3Sig::verifyBody(self::NEED_APPROVE_DOMAIN, $msg, $g->get('principal'), $sig)) {
                return ['ok' => false, 'code' => 'bad_signature'];
            }
            $needs = $nr->get('needs');
            if (!K3Sig::isList($approved) || !K3Sig::isList($needs) || count($approved) !== count($needs)) {
                return ['ok' => false, 'code' => 'need_not_lowered_only'];
            }
            $verbs = [];
            $resources = [];
            $limits = new Obj();
            foreach ($approved as $i => $a) {
                $want = $needs[$i];
                if (!($a instanceof Obj) || !($want instanceof Obj) || !is_string($a->get('verb')) || $a->get('verb') !== $want->get('verb')
                    || !is_string($a->get('resource')) || $a->get('resource') !== $want->get('resource')) {
                    return ['ok' => false, 'code' => 'need_not_lowered_only'];
                }
                $al = self::lim($a);
                $wl = self::lim($want);
                foreach ($al?->keys() ?? [] as $k) {
                    $v = K3Sig::num($al->get($k));
                    $w = $wl !== null && $wl->has($k) ? K3Sig::num($wl->get($k)) : null;
                    if ($w === null || $v === null || $v > $w) {
                        return ['ok' => false, 'code' => 'need_not_lowered_only'];
                    }
                    if ($v < $w && $want->get('adjustable') !== true) {
                        return ['ok' => false, 'code' => 'need_not_adjustable'];
                    }
                }
                $verbs[] = $a->get('verb');
                $resources[] = $a->get('resource');
                // a limit the need names but the principal omitted is not granted at all (omission is the lowest amount)
                foreach ($al?->keys() ?? [] as $k) {
                    $cur = $limits->has($k) ? $limits->get($k) : new Num('0');
                    $limits->set($k, K3Sig::num($cur) >= K3Sig::num($al->get($k)) ? $cur : $al->get($k));
                }
            }
            if (!$stepUpOk) {
                return ['ok' => false, 'code' => 'step_up_required'];
            }
            $delta = Obj::of(['verbs' => $verbs, 'resources' => $resources]);
            if ($limits->keys() !== []) {
                $delta->set('limits', $limits);
            }
            return ['ok' => true, 'authority' => self::mergeAuthority($g->get('authority'), $delta)];
        } catch (\Throwable) {
            return ['ok' => false, 'code' => 'bad_request'];
        }
    }

    // ---- shared-vector replay -----------------------------------------------------------------------------------------------

    private static function n(int $i): Num
    {
        return new Num((string)$i);
    }

    /** A verdict array as the vector's JSON value (ints become Num, lists stay lists). */
    private static function toJson(array $r): Obj
    {
        $o = new Obj();
        foreach ($r as $k => $v) {
            $o->set((string)$k, is_int($v) ? self::n($v) : $v);
        }
        return $o;
    }

    /** Run one k3-vectors.json primitive row (`$kind`, its `input`) and return the value the row's `expect` holds. */
    public static function run(string $kind, Obj $in): Obj
    {
        $g = static fn(string $k): mixed => $in->get($k);
        switch ($kind) {
            case 'fresh_at_verify':
                return Obj::of(['valid' => FreshAt::verify($g('token'), $g('signer'))]);
            case 'fresh_at_digest':
                return Obj::of(['digest' => FreshAt::digest($g('token'))]);
            case 'fresh_at_check':
                $v = FreshAt::check($g('token'), $g('local'), $g('options'));
                if (isset($v['behind'])) {
                    $v['behind'] = array_values($v['behind']);
                }
                return self::toJson($v);
            case 'bundle_digest':
                return Obj::of(['digest' => self::bundleDigest($g('bundle'))]);
            case 'bundle_verify':
                return self::toJson(self::verifyBundle($g('bundle'), $g('options')));
            case 'log_commit':
                return Obj::of(['commit' => self::recordCommit($g('record'))]);
            case 'log_head_verify':
                return Obj::of(['valid' => self::verifyLogHead($g('head'), $g('signer'))]);
            case 'log_inclusion':
                return Obj::of(['valid' => self::verifyRecordInclusion($g('record'), $g('proof'), $g('head'), $g('signer'))]);
            case 'log_batch_verify':
                return self::toJson(self::verifyBatch($g('batch'), $g('state'), $g('signer')));
            case 'list_objects_digest':
                return Obj::of(['digest' => self::objectsDigest($g('objects'))]);
            case 'list_receipt_verify':
                return Obj::of(['valid' => self::verifyListReceipt($g('receipt'), $g('signer'), $g('objects'), $in->has('objects'))]);
            case 'list_bind':
                return Obj::of(['digest' => self::listBind($g('bind'))]);
            case 'list_cursor_verify':
                return self::toJson(self::verifyListCursor($g('cursor'), $g('signer'), $in->has('bind') ? $g('bind') : null));
            case 'authority_digest':
                return Obj::of(['digest' => self::authorityDigest($g('authority'))]);
            case 'authority_compare':
                return Obj::of(['order' => self::compareAuthority($g('old'), $g('new'))]);
            case 'amend_verify':
                $r = self::verifyAmendment($g('grant'), $g('request'), $g('step_up_ok') === true);
                return $r['ok'] ? Obj::of(['ok' => true, 'widens' => $r['widens'], 'next_digest' => self::authorityDigest($r['next'])]) : self::toJson($r);
            case 'revoke_verify':
                return self::toJson(self::verifyRevokeSignature($g('root'), $g('scope'), $g('sig')));
            case 'need_approve_verify':
                $r = self::verifyNeedApproval($g('need_request'), $g('grant'), $g('approved'), $g('sig'), $g('step_up_ok') === true);
                return $r['ok'] ? Obj::of(['ok' => true, 'authority_digest' => self::authorityDigest($r['authority'])]) : self::toJson($r);
            default:
                throw new \InvalidArgumentException("unknown k3 primitive: $kind");
        }
    }
}
