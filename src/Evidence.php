<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Predicates.php';

/**
 * The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
 * form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the
 * accumulator cap reader, and the validators of the verifier's trust inputs (the reference's pca-evidence). The JavaScript
 * semantics a hostile bundle reaches (property reads on any value, `Object.keys` order, relational comparison, the `||` chain of
 * the sort comparators) are reproduced through {@see Jsx}, so a malformed bundle gives the same shape error, the same order or
 * the same refusal (a thrown error) as the reference. Not ported: the full replay (`verifyEvidenceBundle`), the COSE signed
 * statement and the command-line tool.
 */
final class Evidence
{
    public const EVIDENCE_DOMAIN = 'atlas-pca/intent-evidence/v1';
    public const EVIDENCE_REPORT_DOMAIN = 'atlas-pca/intent-evidence-report/v1';
    public const EVIDENCE_CONTENT_TYPE = 'application/pca-intent-evidence+json';
    public const INTENT_ANCHOR_DOMAIN = 'atlas-pca/intent-anchor/v1';
    private const MAX_SAFE = 9007199254740991;
    private const TOP_KEYS = ['v', 'kind', 'subject', 'statement', 'session_root', 'schema', 'root_grant', 'maps', 'answers', 'canary_labels', 'canaries',
        'deltas', 'pcactns', 'verdicts', 'accumulator', 'facts', 'classifier', 'offer_sets', 'labels', 'effects', 'settlements',
        'revocation_epochs', 'anchors'];

    private static function isObj(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    private static function isNum(mixed $v): bool
    {
        return Js::isNum($v);
    }

    /** A safe integer that is not -0. */
    private static function isInt(mixed $v): bool
    {
        return K3Sig::anySafeInt($v) && !K3Sig::isNegZero($v);
    }

    private static function isOne(mixed $v): bool
    {
        return self::isNum($v) && Js::num($v) === 1.0;
    }

    private static function f(mixed $v): float
    {
        return (float)Js::num($v);
    }

    private static function g(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    private static function closed(mixed $o, array $keys, string $where): ?string
    {
        if (!self::isObj($o)) {
            return "$where must be an object";
        }
        foreach (Jsx::keys($o) as $k) {
            if (!in_array($k, $keys, true)) {
                return "$where: unknown member \"$k\"";
            }
        }
        return null;
    }

    /** Closed-member shape validation (unknown members are refused at every level the bundle owns). Null when well formed. */
    public static function bundleShapeError(mixed $b): ?string
    {
        $top = self::closed($b, self::TOP_KEYS, 'bundle');
        if ($top !== null) {
            return $top;
        }
        $x = $b;
        if (!self::isOne(self::g($x, 'v')) || self::g($x, 'kind') !== 'pca-intent-evidence') {
            return 'not a pca-intent-evidence v1 bundle';
        }
        $subj = self::closed(self::g($x, 'subject'), ['pcactn_digest', 'aud', 'session'], 'subject');
        if ($subj !== null) {
            return $subj;
        }
        $s = self::g($x, 'subject');
        foreach (['pcactn_digest', 'aud', 'session'] as $k) {
            if (!is_string(self::g($s, $k))) {
                return 'subject members must be strings';
            }
        }
        $st = self::closed(self::g($x, 'statement'), ['commit', 'opening'], 'statement');
        if ($st !== null) {
            return $st;
        }
        if (!is_string(self::g(self::g($x, 'statement'), 'commit'))) {
            return 'statement.commit must be a string';
        }
        $sr = self::g($x, 'session_root');
        if (!self::isObj($sr) || !self::isOne(self::g($sr, 'v')) || self::g($sr, 'kind') !== 'pca-intent-session') {
            return 'session_root is not a pca-intent-session v1';
        }
        if (!is_string(self::g($sr, 'session')) || !is_string(self::g($sr, 'intent_ref')) || !self::isInt(self::g($sr, 'expires_at'))) {
            return 'session_root is missing session / intent_ref / expires_at';
        }
        $pr = self::g($sr, 'principals');
        $prOk = is_array($pr) && count($pr) > 0;
        foreach ($prOk ? $pr : [] as $p) {
            $prOk = $prOk && self::isObj($p) && is_string(self::g($p, 'key'));
        }
        if (!$prOk) {
            return 'session_root.principals must be a non-empty key list';
        }
        $sc = self::closed(self::g($x, 'schema'), ['doc', 'anchor'], 'schema');
        if ($sc !== null) {
            return $sc;
        }
        $doc = self::g(self::g($x, 'schema'), 'doc');
        if (!self::isObj($doc) || self::g($doc, 'kind') !== 'pca-action-schema' || !self::isObj(self::g($doc, 'sig'))) {
            return 'schema.doc is not a signed pca-action-schema';
        }
        if (!self::isObj(self::g($x, 'root_grant'))) {
            return 'root_grant must be a capability';
        }
        foreach (['maps', 'answers', 'canary_labels', 'deltas', 'pcactns', 'verdicts', 'effects', 'revocation_epochs', 'anchors'] as $k) {
            if (!K3Sig::isList(self::g($x, $k))) {
                return "$k must be an array";
            }
        }
        foreach (['facts', 'classifier', 'offer_sets', 'labels', 'settlements'] as $k) {
            if ($x->has($k) && !K3Sig::isList($x->get($k))) {
                return "$k must be an array";
            }
        }
        foreach ($x->get('maps') as $i => $m) {
            $e = self::closed($m, ['seq', 'commit', 'map', 'disclosed'], "maps[$i]");
            if ($e !== null) {
                return $e;
            }
            if (!self::isInt(self::g($m, 'seq')) || self::f(self::g($m, 'seq')) < 0 || !is_string(self::g($m, 'commit'))) {
                return "maps[$i] needs an integer seq and a commit";
            }
        }
        foreach ($x->get('canary_labels') as $i => $c) {
            $e = self::closed($c, ['question_id', 'label'], "canary_labels[$i]");
            if ($e !== null) {
                return $e;
            }
            $lab = self::g($c, 'label');
            if (!is_string(self::g($c, 'question_id')) || !(self::isNum($lab) && (self::f($lab) === 0.0 || self::f($lab) === 1.0))) {
                return "canary_labels[$i] is malformed";
            }
        }
        $cs = self::closed(self::g($x, 'canaries'), ['asked', 'false_yes', 'false_no'], 'canaries');
        if ($cs !== null) {
            return $cs;
        }
        $cn = $x->get('canaries');
        foreach (['asked', 'false_yes', 'false_no'] as $k) {
            if (!(self::isInt(self::g($cn, $k)) && self::f(self::g($cn, $k)) >= 0)) {
                return 'canaries counts must be non-negative integers';
            }
        }
        $ac = self::closed(self::g($x, 'accumulator'), ['holder', 'events', 'receipts', 'sequencer_keys'], 'accumulator');
        if ($ac !== null) {
            return $ac;
        }
        $acc = $x->get('accumulator');
        if (!in_array(self::g($acc, 'holder'), ['site_local', 'sequenced'], true)) {
            return 'accumulator.holder must be site_local or sequenced';
        }
        if (!K3Sig::isList(self::g($acc, 'events'))) {
            return 'accumulator.events must be an array';
        }
        foreach ($acc->get('events') as $i => $ev) {
            $e = self::closed($ev, ['acc', 'post', 'pcactn_digest', 'delta', 'status'], "accumulator.events[$i]");
            if ($e !== null) {
                return $e;
            }
            if (!is_string(self::g($ev, 'acc')) || !self::isInt(self::g($ev, 'post')) || self::f(self::g($ev, 'post')) < 0 || !is_string(self::g($ev, 'pcactn_digest'))) {
                return "accumulator.events[$i] is malformed";
            }
            if ($ev->has('delta') && !(self::isInt($ev->get('delta')) && self::f($ev->get('delta')) >= 0)) {
                return "accumulator.events[$i].delta must be a non-negative integer";
            }
        }
        if ($acc->has('receipts') && !K3Sig::isList($acc->get('receipts'))) {
            return 'accumulator.receipts must be an array';
        }
        if ($acc->has('sequencer_keys') && !K3Sig::isList($acc->get('sequencer_keys'))) {
            return 'accumulator.sequencer_keys must be an array';
        }
        foreach ($x->get('revocation_epochs') as $i => $r) {
            $e = self::closed($r, ['epoch', 'revoked'], "revocation_epochs[$i]");
            if ($e !== null) {
                return $e;
            }
            if (!self::isObj(self::g($r, 'epoch')) || !K3Sig::isList(self::g($r, 'revoked'))) {
                return "revocation_epochs[$i] needs an epoch and its revoked list";
            }
        }
        foreach ($x->get('anchors') as $i => $a) {
            $e = self::closed($a, ['kind', 'digest', 'index', 'proof', 'signed_tree_head'], "anchors[$i]");
            if ($e !== null) {
                return $e;
            }
        }
        foreach ($x->get('effects') as $i => $ef) {
            if (!self::isObj($ef) || !is_string(self::g($ef, 'pcactn_digest'))) {
                return "effects[$i] needs a pcactn_digest";
            }
        }
        return null;
    }

    // ---- normal form --------------------------------------------------------------------------------------------------

    private static function key(mixed $v): string
    {
        return Pca::hashCanonical(Sign::n($v));
    }

    private static function seqOf(mixed $c): mixed
    {
        $cvs = Jsx::rd($c, 'caveats');
        if (!is_array($cvs) || !array_is_list($cvs)) {
            throw new \TypeError('find is not a function');
        }
        foreach ($cvs as $k) {
            if (Jsx::rd($k, 'type') === 'intent_session') {
                $seq = Jsx::get($k, 'seq');
                return self::isInt($seq) ? $seq : self::MAX_SAFE;
            }
        }
        return self::MAX_SAFE;
    }

    /** hashCanonical of the effect without its params opening (`const {params, ...k} = e`). */
    private static function effectKey(mixed $e): string
    {
        if ($e === null || Jsx::isUndef($e)) {
            throw new \TypeError('cannot destructure');
        }
        return self::key(Jsx::spread($e)->without('params'));
    }

    private static function sortIn(Obj $x, string $k, callable $cmp): void
    {
        $x->set($k, Jsx::sort(Jsx::rd($x, $k), $cmp));
    }

    /**
     * Deterministic normal form: the members that are sets (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
     * canary labels, ...) are sorted by a content key; `accumulator.events` is a sequence and is never reordered. Throws on a bundle
     * that cannot be put in order (a refusal, like the reference's thrown error).
     */
    public static function normalizeBundle(mixed $b): Obj
    {
        $x = Jsx::plain($b);
        if (!($x instanceof Obj)) {
            Jsx::rd($x, 'maps');
            throw new \TypeError('sort is not a function');
        }
        $r = static fn($o, string $k) => Jsx::rd($o, $k);
        $cm = static fn(string $k) => static fn($a, $c): float => Jsx::cmp($r($a, $k), $r($c, $k));
        $sb = static fn(string $k) => static fn($a, $c): float => Jsx::sub($r($a, $k), $r($c, $k));
        self::sortIn($x, 'maps', static fn($a, $c) => Jsx::or($sb('seq')($a, $c), static fn() => $cm('commit')($a, $c)));
        self::sortIn($x, 'answers', static fn($a, $c) => Jsx::or($sb('observed_at')($a, $c), static fn() => Jsx::or($cm('question_id')($a, $c), static fn() => $cm('sig')($a, $c))));
        self::sortIn($x, 'canary_labels', static fn($a, $c) => Jsx::or($cm('question_id')($a, $c), static fn() => $sb('label')($a, $c)));
        self::sortIn($x, 'deltas', static fn($a, $c) => Jsx::or(Jsx::sub(self::seqOf($a), self::seqOf($c)), static fn() => $cm('id')($a, $c)));
        self::sortIn($x, 'pcactns', static fn($a, $c) => Jsx::or($sb('iat')($a, $c), static fn() => Jsx::or($sb('counter')($a, $c), static fn() => (float)Jsx::cmp(self::key($a), self::key($c)))));
        self::sortIn($x, 'verdicts', static fn($a, $c) => Jsx::or($cm('pcactn_digest')($a, $c), static fn() => (float)Jsx::cmp(self::key($a), self::key($c))));
        // sorted without the params opening, so withholding an opening never reorders the commitments-only form
        self::sortIn($x, 'effects', static fn($a, $c) => Jsx::or($cm('pcactn_digest')($a, $c), static fn() => (float)Jsx::cmp(self::effectKey($a), self::effectKey($c))));
        // issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
        $ep = static fn($o, string $k) => $r($r($o, 'epoch'), $k);
        self::sortIn($x, 'revocation_epochs', static fn($a, $c) => Jsx::or(Jsx::sub($ep($a, 'issued_at'), $ep($c, 'issued_at')),
            static fn() => Jsx::or(Jsx::sub($ep($a, 'epoch'), $ep($c, 'epoch')), static fn() => (float)Jsx::cmp(self::key($a), self::key($c)))));
        self::sortIn($x, 'anchors', static fn($a, $c) => Jsx::or($cm('kind')($a, $c), static fn() => Jsx::or($sb('index')($a, $c), static fn() => $cm('digest')($a, $c))));
        foreach (['facts', 'classifier', 'offer_sets', 'labels', 'settlements'] as $k) {
            $v = Jsx::get($x, $k);
            if ($v !== null && !Jsx::isUndef($v)) {
                $x->set($k, Jsx::sort($v, static fn($a, $c): float => (float)Jsx::cmp(self::key($a), self::key($c))));
            }
        }
        $acc = $r($x, 'accumulator');
        $receipts = Jsx::get($acc, 'receipts');
        if (Jsx::truthy($receipts)) {
            $acc->set('receipts', Jsx::sort($receipts, static fn($a, $c): float => (float)Jsx::cmp(self::key($a), self::key($c))));
        }
        return $x;
    }

    /** Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence). */
    public static function buildEvidenceBundle(mixed $parts): Obj
    {
        $b = Obj::of(['v' => 1, 'kind' => 'pca-intent-evidence']);
        $p = Jsx::spread($parts);
        foreach ($p->keys() as $k) {
            $b->set($k, $p->get($k));
        }
        $n = self::normalizeBundle($b);
        $bad = self::bundleShapeError($n);
        if ($bad !== null) {
            throw new \InvalidArgumentException("buildEvidenceBundle: $bad");
        }
        return $n;
    }

    /** @return array{0:Obj,1:bool} the commitments-only form, and whether a committed member is undefined (it cannot be hashed) */
    private static function commitment(mixed $b): array
    {
        $n = self::normalizeBundle($b);
        $rest = $n->without('anchors');
        $undef = false;
        $statement = Jsx::get($n, 'statement');
        if ($statement === null || Jsx::isUndef($statement)) {
            throw new \TypeError("cannot read 'commit' of undefined");
        }
        $commit = Jsx::get($statement, 'commit');
        $st = new Obj();
        if (Jsx::isUndef($commit)) {
            $undef = true;
        } else {
            $st->set('commit', $commit);
        }
        $rest->set('statement', $st);
        $maps = [];
        foreach ($n->get('maps') as $m) {
            $seq = Jsx::rd($m, 'seq');
            $mc = Jsx::rd($m, 'commit');
            $disclosed = Jsx::get($m, 'disclosed');
            $entry = new Obj();
            foreach ([['seq', $seq], ['commit', $mc]] as [$k, $v]) {
                if (Jsx::isUndef($v)) {
                    $undef = true;
                } else {
                    $entry->set($k, $v);
                }
            }
            if (!Jsx::isUndef($disclosed)) {
                $entry->set('disclosed', $disclosed);
            }
            $maps[] = $entry;
        }
        $rest->set('maps', $maps);
        $effects = [];
        foreach ($n->get('effects') as $e) {
            if ($e === null || Jsx::isUndef($e)) {
                throw new \TypeError('cannot destructure');
            }
            $effects[] = Jsx::spread($e)->without('params');
        }
        $rest->set('effects', $effects);
        return [$rest, $undef];
    }

    /** The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params; every signed artifact and claim stays in. */
    public static function commitmentForm(mixed $b): Obj
    {
        return self::commitment($b)[0];
    }

    /** The bundle's content address: the hash over the commitments-only normal form. */
    public static function evidenceDigest(mixed $b): string
    {
        [$form, $undef] = self::commitment($b);
        if ($undef) {
            throw new \TypeError('canonicalize: undefined member');
        }
        return Pca::hashCanonical(Sign::n(Obj::of(['d' => self::EVIDENCE_DOMAIN, 'b' => $form])));
    }

    /** The public reference to a bundle: its digest and subject (the bundle itself stays with the site). */
    public static function evidenceRef(mixed $bundle): Obj
    {
        $digest = self::evidenceDigest($bundle);
        return Obj::of(['kind' => 'pca-intent-evidence-ref', 'digest' => $digest, 'subject' => Jsx::spread(Jsx::rd($bundle, 'subject'))]);
    }

    /**
     * A COSE Signed Statement (COSE_Sign1 bytes) over the bundle reference, ready to register with a SCITT service. `$opts`: alg
     * ('EdDSA' | 'ES256'), key, issuer, optional subject (default: the bundle's pcactn digest; null also takes the default).
     * Throws on a malformed bundle.
     */
    public static function evidenceSignedStatement(mixed $bundle, mixed $opts): string
    {
        $ref = self::evidenceRef($bundle);
        $subject = Js::opt($opts, 'subject') ?? Js::opt($ref->get('subject'), 'pcactn_digest');
        $o = ['alg' => Js::opt($opts, 'alg'), 'key' => Js::opt($opts, 'key'), 'issuer' => Js::opt($opts, 'issuer'), 'contentType' => self::EVIDENCE_CONTENT_TYPE];
        if ($subject !== null) { // `subject ?? ref.subject?.pcactn_digest` is undefined without either: no sub claim
            $o['subject'] = $subject;
        }
        return Scitt::signStatement($ref, $o);
    }

    /** The intent-log leaf for an anchored artifact (any kind). */
    public static function anchorCommit(mixed $kind, mixed $digest): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_ANCHOR_DOMAIN, 'kind' => $kind, 'digest' => $digest]));
    }

    public static function evidenceAnchorCommit(mixed $digest): string
    {
        return self::anchorCommit('evidence', $digest);
    }

    // ---- accumulator cap ----------------------------------------------------------------------------------------------

    /** @return list<mixed> */
    private static function leafCaps(mixed $conds, string $path): array
    {
        $out = [];
        foreach (Jsx::iter($conds === null || Jsx::isUndef($conds) ? [] : $conds) as $c) {
            if (Predicates::isLeafCondition($c)) {
                if ($c->get('field') !== $path || $c->has('ref') || !Js::isNum($c->get('value'))) {
                    continue;
                }
                if ($c->get('op') === 'lte') {
                    $out[] = $c->get('value');
                } elseif ($c->get('op') === 'lt') {
                    $out[] = self::f($c->get('value')) - 1;
                }
            } elseif (Predicates::isGroupCondition($c) && $c->has('all_of')) {
                array_push($out, ...self::leafCaps($c->get('all_of'), $path));
            }
        }
        return $out;
    }

    /**
     * The cap `env.acc.<id>.post <= v` that the grant's envelope states for `$verb`: per predicate the tightest bound in its `where`
     * (descending into `all_of`); across predicates (a union) the loosest. Null when a predicate admitting the verb states no
     * bound, or none admits it.
     */
    public static function capOf(mixed $grant, mixed $accId, mixed $verb): int|float|null
    {
        $env = Authorize::readEnvelope($grant);
        if ($env === null) {
            return null;
        }
        $path = 'env.acc.' . Js::str($accId) . '.post';
        $cap = null;
        foreach ($env->get('predicates') as $p) {
            $pv = Jsx::rd($p, 'verb');
            $verbs = is_array($pv) ? array_map(Jsx::str(...), $pv) : [Jsx::str($pv)];
            if (!in_array($verb, $verbs, true) && !in_array('*', $verbs, true)) {
                continue;
            }
            $caps = self::leafCaps(Jsx::get($p, 'where'), $path);
            if ($caps === []) {
                return null;
            }
            $m = min(array_map(self::f(...), $caps));
            $cap = $cap === null ? $m : max($cap, $m);
        }
        return $cap === null ? null : (floor($cap) === $cap && abs($cap) < 9.0e15 ? (int)$cap : $cap);
    }

    // ---- trust-input validators ---------------------------------------------------------------------------------------

    /** Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. Null = valid (call with no argument for an absent value). */
    public static function principalsTrustError(mixed ...$a): ?string
    {
        if ($a === []) {
            return null;
        }
        $p = $a[0];
        if (!K3Sig::isList($p) || count($p) === 0) {
            return 'trust.principals must be a non-empty array of {key, pq_pk?}';
        }
        foreach ($p as $i => $x) {
            if (!($x instanceof Obj)) {
                return "trust.principals[$i] must be an object {key, pq_pk?}";
            }
            foreach (Jsx::keys($x) as $k) {
                if ($k !== 'key' && $k !== 'pq_pk') {
                    return "trust.principals[$i]: unknown member '$k'";
                }
            }
            if (Pca::unb64u($x->get('key'), 32) === null) {
                return "trust.principals[$i].key must be canonical base64url (32 bytes)";
            }
            if ($x->has('pq_pk') && Pca::unb64u($x->get('pq_pk')) === null) {
                return "trust.principals[$i].pq_pk must be canonical base64url";
            }
        }
        return null;
    }

    /** Validate `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. Null = valid (no argument = absent). */
    public static function accTrustError(mixed ...$a): ?string
    {
        if ($a === []) {
            return null;
        }
        $acc = $a[0];
        if (!($acc instanceof Obj)) {
            return 'trust.acc must be an object';
        }
        foreach (Jsx::keys($acc) as $k) {
            $v = $acc->get($k);
            if ($k !== 'max_receipt_age_s' && $k !== 'max_keyset_age_s') {
                return "trust.acc: unknown member '$k'";
            }
            if (!(self::isInt($v) && self::f($v) >= 0)) {
                return "trust.acc.$k must be a non-negative safe integer";
            }
        }
        return null;
    }
}
