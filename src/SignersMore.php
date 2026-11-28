<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Mesh.php';
require_once __DIR__ . '/ReadSide.php';
require_once __DIR__ . '/PolicyLink.php';
require_once __DIR__ . '/RevocationStaleness.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * More producer-side signers: the artifacts an agent, a principal, a guardian, a site or a resource server signs beyond the grant
 * and the PCActn ({@see Sign}). Same wire as the TypeScript reference, byte for byte for Ed25519 and for the deterministic PQ suites.
 * Every signer runs the reference's checks before signing and throws on a malformed body (fail closed), with the reference's
 * message. The functions that take `$alg` / `$pq` sign under any suite this runtime can sign ({@see Sign::signWithSuite}); a
 * registered suite it cannot sign throws {@see UnsupportedSigner} (`unsupported_suite: <alg>`).
 */
final class SignersMore
{
    public const PQ_BINDING_DOMAIN = "atlas-pca/pq-binding/v2\0";
    public const CAUTION_DOMAIN = 'atlas-pca/caution/v1';
    public const HEARTBEAT_DOMAIN = 'atlas-pca/lease-hb/v2';
    public const PROGRESS_SIG_DOMAIN = 'atlas-pca/progress-step/v2';
    public const INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\0";
    public const MAX_CAUTION_REASON_LEN = 64;
    private const MAX_SAFE = 9007199254740991;
    private const IR_KEYS = ['v', 'kind', 'session', 'map_digest', 'schema', 'pcactn_digest', 'action_digest', 'cell', 'reason', 'question_id',
        'friction', 'delivered_to', 'expires_at', 'sig'];
    private const EPOCH_FIELDS = ['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'];

    private static function obj(mixed $v, string $what): Obj
    {
        $o = Sign::n($v);
        return $o instanceof Obj ? $o : throw new \InvalidArgumentException("$what: not an object");
    }

    /** A JSON safe integer (the reference's Number.isSafeInteger, never -0). */
    private static function safeInt(mixed $v): bool
    {
        $f = $v instanceof Num ? $v->float() : null;
        return $f !== null && $f === floor($f) && abs($f) <= self::MAX_SAFE && $v->lexeme !== '-0';
    }

    private static function b32(mixed $v): bool
    {
        return is_string($v) && Pca::unb64u($v, 32) !== null;
    }

    private static function u16len(string $s): int
    {
        return intdiv(strlen(mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2);
    }

    /** The reference's msgOf: canonical {d: domain, b: body}. */
    private static function msgOf(string $domain, Obj $body): string
    {
        return Json::canonicalizeLenient(Obj::of(['d' => $domain, 'b' => $body]));
    }

    /** The reference's msgOf for the artifacts whose body it canonicalizes STRICTLY (caution claims, lease heartbeats): -0, an unsafe integer or a number needing an exponent is refused. */
    private static function msgStrict(string $domain, Obj $body): string
    {
        return Json::canonicalizeNative(Obj::of(['d' => $domain, 'b' => $body]));
    }

    private static function alg(?string $alg): string
    {
        return $alg ?? 'ed25519';
    }

    // ---- threshold shares (threshold.ts signShare / signPreparedShare) ------------------------------------------------------

    /**
     * Sign already-computed share bytes (the share message a step-up hands a principal device). Ed25519 gives
     * {role, publicKey, sig}, byte-identical to the pre-agility share; another suite adds `alg` (and `pq_sig` for a hybrid). The
     * role's PQ public key is registered in the signer set, not carried in the share.
     */
    public static function signPreparedShare(string $role, KeyPair $key, string $prepared, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $parts = Sign::signWithSuite($alg, $key, $pq, $prepared);
        $share = Obj::of(['role' => $role, 'publicKey' => $key->public, 'sig' => $parts['sig']]);
        if (self::alg($alg) !== 'ed25519') {
            $share->set('alg', $alg);
            if (isset($parts['pq_sig'])) {
                $share->set('pq_sig', $parts['pq_sig']);
            }
        }
        return $share;
    }

    /**
     * A role's explicit threshold share (agent, guardian or principal) over the bound share message
     * "atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t [|| suite tag], where `$message` is the PCActn's threshold
     * message (raw bytes). The share can only be replayed into the same signer set and threshold.
     */
    public static function signThresholdShare(string $role, KeyPair $key, string $message, mixed $signerSet, int $t, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if ($t < 1 || $t > 3) {
            throw new \InvalidArgumentException('signShare: t must be 1, 2 or 3');
        }
        $ssh = Pca::signerSetHashRaw(Sign::n($signerSet)) ?? throw new \InvalidArgumentException('signShare: malformed signer set');
        $tag = self::alg($alg) === 'ed25519' ? '' : Pca::SHARE_SUITE_TAG . $alg;
        $msg = Pca::SHARE_DOMAIN_PREFIX . Js::utf8($role) . "\0" . hash('sha256', $message, true) . $ssh . chr($t) . $tag;
        return self::signPreparedShare($role, $key, $msg, $alg, $pq);
    }

    /** Reason text for a possibly hostile value: primitives as String(v), containers by kind only. */
    private static function showValue(mixed $v): string
    {
        return $v instanceof Obj ? '<object>' : (is_array($v) ? '<array>' : Js::str($v));
    }

    /**
     * The t-of-n check over a ThresholdSignature {shares} (threshold.ts verifyThreshold without the agent-leaf baseline), following
     * the proved decision (Threshold.dfy Verify): t must be 1, 2 or 3; the signer set is validated first (known role, canonical
     * 32-byte key, well-formed pq_pk, one key per role, one role per key); then every share in order counts its DISTINCT
     * registered key once its role, key, suite, pq_pk and signature all check, and the first failure is the reason.
     * `$message` is the raw threshold message. Returns {ok, count, roles, reason?}.
     */
    public static function verifyThreshold(mixed $sig, string $message, mixed $signerSet, mixed $t): array
    {
        $tf = Js::num($t);
        $tv = $tf !== null && in_array($tf, [1.0, 2.0, 3.0], true) ? (int)$tf : null;
        $bad = static fn(string $r): array => ['ok' => false, 'count' => 0, 'roles' => [], 'reason' => $r];
        if ($tv === null) {
            return $bad('invalid threshold t=' . self::showValue($t) . ' (must be 1, 2 or 3)');
        }
        $set = is_array($signerSet) && array_is_list($signerSet) ? $signerSet : [];
        $reg = []; // role => key, in registration order
        $pqOf = []; // role => ?pq_pk (first well-formed registration)
        $seen = [];
        foreach ($set as $i => $s) {
            $role = $s instanceof Obj && in_array($s->get('role'), ['agent', 'guardian', 'principal'], true) ? $s->get('role') : null;
            $key = $s instanceof Obj ? $s->get('publicKey') : null;
            if ($role === null || Pca::unb64u($key, 32) === null) {
                return $bad('malformed signer set');
            }
            $pqOk = true;
            if ($s->has('pq_pk')) {
                $raw = Pca::unb64u($s->get('pq_pk'));
                $pqOk = $raw !== null && in_array(strlen($raw), [1952, 2592, 32, 64, 897, 1793, 97484], true);
            }
            $pq = is_string($s->get('pq_pk')) ? $s->get('pq_pk') : null;
            $id = "$role\0$key";
            if ($pqOk && array_key_exists($id, $seen) && $seen[$id] !== $pq) {
                $pqOk = false; // a duplicate (role, key) with a conflicting pq_pk
            } elseif ($pqOk) {
                $seen[$id] = $pq;
            }
            if (!$pqOk) {
                return $bad('malformed signer set (pq_pk)');
            }
            if (isset($reg[$role]) && $reg[$role] !== $key) {
                return $bad('signer set registers more than one key for role ' . self::showValue($s->get('role')));
            }
            $other = array_search($key, $reg, true);
            if ($other !== false && $other !== $role) {
                return $bad('signer set registers one key under two roles');
            }
            if (!isset($reg[$role])) {
                $reg[$role] = $key;
                $pqOf[$role] = $pq;
            }
        }
        $shares = $sig instanceof Obj && is_array($sig->get('shares')) && array_is_list($sig->get('shares')) ? $sig->get('shares') : [];
        $keys = [];
        $roles = [];
        $reason = null;
        $tmsg = Pca::b64u($message);
        foreach ($shares as $sh) {
            $well = $sh instanceof Obj && is_string($sh->get('role')) && is_string($sh->get('publicKey'));
            if (!$well) {
                $reason ??= 'malformed share';
                continue;
            }
            $k = $sh->get('publicKey');
            if (in_array($k, $keys, true)) {
                continue;
            }
            $r = $sh->get('role');
            $who = self::showValue($r);
            if (!isset($reg[$r])) {
                $reason ??= "role $who is not in the signer set";
            } elseif ($reg[$r] !== $k) {
                $reason ??= "share for role $who uses a key not registered for that role";
            } elseif ($sh->has('alg') && !in_array($sh->get('alg'), Pca::REGISTERED_SUITES, true)) {
                $reason ??= "share for role $who declares an unknown signature alg";
            } elseif ($sh->has('pq_pk') && !(is_string($sh->get('pq_pk')) && $sh->get('pq_pk') === $pqOf[$r])) {
                $reason ??= "share for role $who names a pq_pk that is not the key its role registers";
            } elseif (!Pca::verifyThresholdShare(Obj::of(['role' => $r, 't' => new Num((string)$tv), 'signer_set' => $set, 'threshold_message' => $tmsg, 'share' => $sh]))) {
                $reason ??= "invalid signature for role $who";
            } else {
                $keys[] = $k;
                $roles[] = $r;
            }
        }
        $n = count($keys);
        if ($n >= $tv) {
            return ['ok' => true, 'count' => $n, 'roles' => $roles];
        }
        return ['ok' => false, 'count' => $n, 'roles' => $roles, 'reason' => $reason ?? "only $n distinct valid key(s), need " . self::showValue($t)];
    }

    // ---- PQ key binding (pq.ts signPqBinding) ---------------------------------------------------------------------------------

    /**
     * An identity's signed statement "this PQ key is mine, as of `$epoch`, for audience `$aud`": an Ed25519 signature over the
     * domain, the identity, the PQ key, the epoch and the audience. `$epoch` grows on every rotation (>= 1).
     */
    public static function signPqBinding(KeyPair $key, string $pqPublic, mixed $epoch, string $aud): Obj
    {
        $epoch = Sign::n($epoch);
        if (!self::safeInt($epoch) || $epoch->float() < 1) {
            throw new \InvalidArgumentException('signPqBinding: epoch must be a positive safe integer');
        }
        $epoch = (int)$epoch->float();
        if ($aud === '') {
            throw new \InvalidArgumentException('signPqBinding: aud (the instance/audience id) is required');
        }
        $msg = self::PQ_BINDING_DOMAIN . "{$key->public}\0$pqPublic\0$epoch\0$aud";
        return Sign::n(['ed' => $key->public, 'pq' => $pqPublic, 'epoch' => $epoch, 'aud' => $aud, 'sig' => Pca::b64u($key->sign($msg))]);
    }

    // ---- agent-native: caution, lease heartbeat, progress step ----------------------------------------------------------------

    private static function cautionBodyError(mixed $b): ?string
    {
        if (!($b instanceof Obj)) {
            return 'not an object';
        }
        foreach (['action_digest', 'holder'] as $k) {
            if (!is_string($b->get($k)) || $b->get($k) === '') {
                return "$k required";
            }
        }
        $c = $b->get('caution');
        if (!($c instanceof Num) || !is_finite($c->float()) || $c->float() < 0 || $c->float() > 1) {
            return 'caution must be a finite number in [0,1]';
        }
        if ($b->has('reason')) {
            $r = $b->get('reason');
            if (!is_string($r) || self::u16len($r) > self::MAX_CAUTION_REASON_LEN || preg_match('/\A[A-Za-z0-9_.:-]+\z/', $r) !== 1) {
                return 'invalid reason';
            }
        }
        return null;
    }

    /** The holder's signed caution claim about one action ({action_digest, caution in [0,1], reason?, holder}). */
    public static function signCaution(mixed $body, KeyPair $holder): Obj
    {
        $b = Sign::n($body);
        $err = self::cautionBodyError($b);
        if ($err !== null) {
            throw new \InvalidArgumentException("signCaution: $err");
        }
        $clean = Obj::of(['action_digest' => $b->get('action_digest'), 'caution' => $b->get('caution'), 'holder' => $b->get('holder')]);
        if ($b->has('reason')) {
            $clean->set('reason', $b->get('reason'));
        }
        $out = $clean->without();
        $out->set('sig', Pca::b64u($holder->sign(self::msgStrict(self::CAUTION_DOMAIN, $clean))));
        return $out;
    }

    /** The lease holder's signed liveness proof ({cap_id, seq, at, holder, lease_issued_at}). */
    public static function signHeartbeat(mixed $body, KeyPair $holder): Obj
    {
        $b = self::obj($body, 'signHeartbeat');
        $clean = new Obj();
        foreach (['cap_id', 'seq', 'at', 'holder', 'lease_issued_at'] as $k) {
            if (!$b->has($k)) {
                throw new \InvalidArgumentException("signHeartbeat: $k is required");
            }
            $clean->set($k, $b->get($k));
        }
        $out = $clean->without();
        $out->set('sig', Pca::b64u($holder->sign(self::msgStrict(self::HEARTBEAT_DOMAIN, $clean))));
        return $out;
    }

    /**
     * The holder's signed progress step {step, holder, sig}: Ed25519 over the domain-separated binding of the step to the holder,
     * goal, action, before / after state, sequence, chain link and step digest. A step missing one of those is refused.
     */
    public static function signProgressStep(mixed $step, KeyPair $holder): Obj
    {
        $s = self::obj($step, 'signProgressStep');
        $bound = Obj::of(['holder' => $holder->public]);
        foreach (['goal_commitment', 'action_digest', 'before_digest', 'after_digest', 'seq', 'prev', 'step_digest' => 'digest'] as $k => $from) {
            if (!$s->has($from)) {
                throw new \InvalidArgumentException("signProgressStep: step.$from is required");
            }
            $bound->set(is_int($k) ? $from : $k, $s->get($from));
        }
        return Obj::of(['step' => $s, 'holder' => $holder->public, 'sig' => Pca::b64u($holder->sign(self::msgOf(self::PROGRESS_SIG_DOMAIN, $bound)))]);
    }

    // ---- read receipt (readside.ts signReadReceipt, resource-server side) -----------------------------------------------------

    /** The resource server's signed receipt for a read under `$grant` (the read grant BODY); `$prev` is the previous receipt. */
    public static function signReadReceipt(KeyPair $rs, mixed $grant, string $verb, string $resource, string $purpose, mixed $fields, mixed $labels,
                                           int $issuedAt, ?Obj $prev = null): Obj
    {
        $seq = $prev === null ? null : Sign::n($prev->get('seq'));
        // every verifier refuses a receipt whose seq is not a non-negative safe integer: never sign the successor of one
        if ($prev !== null && (!self::safeInt($seq) || $seq->float() < 0)) {
            throw new \InvalidArgumentException('signReadReceipt: prev.seq must be a non-negative safe integer');
        }
        $base = Sign::n(['v' => 1, 'grant' => ReadSide::readGrantDigest(self::obj($grant, 'signReadReceipt')), 'verb' => $verb, 'resource' => $resource,
            'purpose' => $purpose, 'seq' => $prev === null ? 0 : $seq->int() + 1,
            'prev' => $prev === null ? null : ReadSide::readReceiptRef($prev), 'fields' => $fields, 'labels' => $labels, 'issued_at' => $issuedAt,
            'signer' => $rs->public]);
        $base->set('sig', Pca::b64u($rs->sign(ReadSide::READ_RECEIPT_DOMAIN . Json::canonicalizeNative($base))));
        return $base;
    }

    // ---- cross-domain mesh (mesh.ts signMeshAction / assembleMeshProof) -------------------------------------------------------

    /** The leaf holder's signature over {action, tip = capHash(last hop)}. @param Obj[] $chain */
    public static function signMeshAction(array $chain, mixed $action, KeyPair $leaf): string
    {
        if ($chain === []) {
            throw new \InvalidArgumentException('signMeshAction: empty chain');
        }
        $body = Obj::of(['action' => Sign::n($action), 'tip' => Pca::capHash($chain[count($chain) - 1])]);
        return Pca::b64u($leaf->sign(Mesh::ACTION_DOMAIN . Json::canonicalizeNative($body)));
    }

    /**
     * A compact mesh proof: hops issued against the same head share one table entry (their cosignatures merged by witness),
     * identical revocation bracketing leaves are carried once, and the leaf holder signs the action.
     * @param Obj[] $chain @param Obj[] $hops one {domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?} per hop
     */
    public static function assembleMeshProof(array $chain, array $hops, mixed $action, KeyPair $leaf, array $pinProofs = []): Obj
    {
        $heads = [];
        $headIdx = [];
        $leaves = [];
        $leafIdx = [];
        $compact = static function (Obj $n) use (&$leaves, &$leafIdx): Obj {
            $out = new Obj();
            if ($n->has('size')) { // an undefined member is dropped from the JSON
                $out->set('size', $n->get('size'));
            }
            foreach (['lo', 'hi'] as $k) {
                if ($n->get($k) instanceof Obj) {
                    $key = Json::canonicalizeLenient($n->get($k));
                    if (!isset($leafIdx[$key])) {
                        $leafIdx[$key] = count($leaves);
                        $leaves[] = $n->get($k);
                    }
                    $out->set($k, new Num((string)$leafIdx[$key]));
                }
            }
            return $out;
        };
        $outHops = [];
        foreach ($hops as $ev) {
            $ev = self::obj($ev, 'assembleMeshProof');
            $h = $ev->get('head');
            $key = $h->get('sig') . '|' . Json::canonicalizeLenient($h->get('head'));
            if (!isset($headIdx[$key])) {
                $headIdx[$key] = count($heads);
                $heads[] = Obj::of(['head' => $h->get('head'), 'sig' => $h->get('sig'), 'cosigs' => $h->get('cosigs')]);
            } else {
                $entry = $heads[$headIdx[$key]];
                $cosigs = $entry->get('cosigs');
                $have = array_map(static fn(Obj $c) => $c->get('witness'), $cosigs);
                foreach ($h->get('cosigs') as $c) {
                    if (!in_array($c->get('witness'), $have, true)) {
                        $cosigs[] = $c;
                        $have[] = $c->get('witness');
                    }
                }
                $entry->set('cosigs', $cosigs);
            }
            $rev = $ev->get('revocation');
            $o = new Obj();
            foreach (['domain'] as $k) {
                $ev->has($k) && $o->set($k, $ev->get($k));
            }
            $o->set('head', new Num((string)$headIdx[$key]));
            $ev->has('inclusion') && $o->set('inclusion', $ev->get('inclusion'));
            $o->set('revocation', Obj::of(['cap' => $compact($rev->get('cap')), 'issuer_key' => $compact($rev->get('issuer_key'))]));
            if ($ev->get('binding') instanceof Obj) {
                $o->set('binding', $ev->get('binding'));
            }
            $outHops[] = $o;
        }
        $proof = Obj::of(['chain' => $chain, 'heads' => $heads, 'rev_leaves' => $leaves, 'hops' => $outHops, 'action' => Sign::n($action),
            'action_sig' => self::signMeshAction($chain, $action, $leaf)]);
        if ($pinProofs !== []) {
            $proof->set('pin_proofs', Sign::n($pinProofs));
        }
        return $proof;
    }

    // ---- Intent v2 session root and session grant (intent-session.ts) ---------------------------------------------------------

    /** Sign the session root as one of its principals (the signer's Ed25519 key must be listed in `principals`). */
    public static function signSessionRoot(mixed $body, KeyPair $principal, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj($body, 'signSessionRoot')->without('signer', 'sig', 'alg', 'pq_pk', 'pq_sig');
        $candidate = $b->without();
        $candidate->set('signer', $principal->public);
        $candidate->set('sig', '');
        $bad = IntentV2::sessionRootShapeError($candidate);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signSessionRoot: $bad");
        }
        $base = $b->without();
        $base->set('signer', $principal->public);
        return Sign::signArtifact(IntentV2::INTENT_SESSION_SIG_DOMAIN, $base, $principal, $alg, $pq);
    }

    /**
     * G_0 (seq 0) or a delta grant D_k: a principal-signed root capability whose caveats are the envelope (goal
     * "pca-intent:v2:<session>:<map_digest>", or v2c over a committed map) and the `intent_session` caveat. Returns
     * ['grant', 'goal_salt'] (the salt goes in the PCActn's `intent.goal_salt`).
     * @return array{grant:Obj, goal_salt:string}
     */
    public static function mintSessionGrant(KeyPair $principal, string $holder, string $session, int $seq, string $root, string $mapDigest, array $predicates,
                                            ?string $prev = null, ?string $mapForm = null, ?array $caveats = null, mixed $agentBinding = null,
                                            ?array $riskPolicy = null, ?string $salt = null, ?string $holderPq = null, ?string $alg = null,
                                            ?PqKeyPair $pq = null): array
    {
        $sc = Sign::n(['type' => 'intent_session', 'session' => $session, 'seq' => $seq, 'root' => $root] + ($prev === null ? [] : ['prev' => $prev]));
        $bad = IntentV2::intentSessionCaveatError($sc);
        if ($bad !== null) {
            throw new \InvalidArgumentException("mintSessionGrant: $bad");
        }
        if (!self::b32($mapDigest)) {
            throw new \InvalidArgumentException('mintSessionGrant: mapDigest must be canonical base64url (32 bytes)');
        }
        $salt ??= Pca::b64u(random_bytes(16));
        $goal = ($mapForm === 'commit' ? Pca::INTENT_GOAL_V2C_PREFIX : Pca::INTENT_GOAL_V2_PREFIX) . "$session:$mapDigest";
        $envelope = ['type' => 'envelope', 'goal_commit' => Sign::goalCommit($goal, $salt), 'predicates' => $predicates, 'caveats' => $caveats ?? [],
            'agent_binding' => $agentBinding ?? new Obj(), 'risk_policy' => $riskPolicy ?? Sign::defaultRiskPolicy()];
        return ['grant' => Sign::mintRoot($principal, $holder, [$envelope, $sc], $holderPq, $alg, $pq), 'goal_salt' => $salt];
    }

    // ---- site-signed documents: action schema, intent_required; labels; oracle facts ------------------------------------------

    /** @param array{sig:string, pq_sig?:string} $parts */
    private static function siteSig(?string $alg, string $kid, array $parts): Obj
    {
        $sig = Obj::of(['alg' => self::alg($alg), 'kid' => $kid, 'value' => $parts['sig']]);
        if (isset($parts['pq_sig'])) {
            $sig->set('pq_value', $parts['pq_sig']);
        }
        return $sig;
    }

    /**
     * Sign an action schema as the site: `sig = {alg, kid, value, pq_value?}` over utf8(domain) || strictCanonical(doc). `$kid` names
     * the site's discovery key entry ({@see actionSchemaKeyOf}).
     */
    public static function signActionSchema(mixed $doc, string $kid, KeyPair $site, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $d = self::obj($doc, 'signActionSchema');
        $bad = IntentV2::actionSchemaShapeError($d, false);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signActionSchema: $bad");
        }
        if (!IntentV2::isStr($kid, 128)) {
            throw new \InvalidArgumentException('signActionSchema: sig.kid must be a non-empty string');
        }
        $body = $d->without('sig');
        $out = $body->without();
        $out->set('sig', self::siteSig($alg, $kid, Sign::signWithSuite($alg, $site, $pq, IntentV2::ACTION_SCHEMA_DOMAIN . Json::canonicalizeNative($body))));
        return $out;
    }

    /** The discovery key entry {kid, alg, pk, pq_pk?} a verifier pins for a site signer. */
    public static function actionSchemaKeyOf(string $kid, KeyPair $site, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if (!IntentV2::isStr($kid, 128)) {
            throw new \InvalidArgumentException('actionSchemaKeyOf: kid must be a non-empty string');
        }
        $a = self::alg($alg);
        if (!in_array($a, Pca::REGISTERED_SUITES, true)) {
            throw new \InvalidArgumentException("unknown signature alg '$a'");
        }
        $k = Obj::of(['kid' => $kid, 'alg' => $a, 'pk' => $site->public]);
        if ($a !== 'ed25519' && $pq !== null) {
            $k->set('pq_pk', $pq->public);
        }
        return $k;
    }

    public static function cellCoordsError(mixed $c): ?string
    {
        if (!($c instanceof Obj) || count($c->keys()) === 0 || count($c->keys()) > 64) {
            return 'coords must be an object of 1..64 dimensions';
        }
        foreach ($c->keys() as $k) {
            $v = $c->get($k);
            $n = self::u16len($k);
            if ($n === 0 || $n > 256) {
                return 'a coordinate path must be 1..256 characters';
            }
            $list = is_array($v) && array_is_list($v);
            if ($list && count($v) === 2 && self::safeInt($v[0]) && self::safeInt($v[1])) {
                if (!($v[0]->float() >= 0 && $v[0]->float() <= $v[1]->float())) {
                    return "coords '$k': need 0 <= lo <= hi";
                }
            } elseif ($list && count($v) >= 1 && count($v) <= 256 && count(array_filter($v, 'is_string')) === count($v)) {
                if (count(array_unique($v)) !== count($v)) {
                    return "coords '$k': values must be distinct";
                }
            } else {
                return "coords '$k': an index range [lo, hi] or a value set";
            }
        }
        return null;
    }

    /** The reference's shape check of an UNSIGNED `pca-intent-required` v1 body (the signer's pre-check). Null = well-formed. */
    public static function intentRequiredShapeError(mixed $b): ?string
    {
        if (!($b instanceof Obj)) {
            return 'not an object';
        }
        foreach ($b->keys() as $k) {
            if (!in_array($k, self::IR_KEYS, true)) {
                return "unknown member '$k'";
            }
        }
        $v = $b->get('v');
        if (!($v instanceof Num) || $v->float() !== 1.0 || $b->get('kind') !== 'pca-intent-required') {
            return 'not a pca-intent-required v1';
        }
        foreach (['session', 'map_digest', 'schema', 'pcactn_digest', 'action_digest'] as $k) {
            if (!self::b32($b->get($k))) {
                return "$k must be canonical base64url (32 bytes)";
            }
        }
        $cell = $b->get('cell');
        $keys = $cell instanceof Obj ? $cell->keys() : [];
        sort($keys);
        if ($keys !== ['coords', 'verb'] || !is_string($cell->get('verb')) || $cell->get('verb') === '') {
            return 'cell must be {verb, coords}';
        }
        $ce = self::cellCoordsError($cell->get('coords'));
        if ($ce !== null) {
            return $ce;
        }
        if ($b->get('reason') !== 'uncertain') {
            return "reason must be 'uncertain'";
        }
        if (!is_string($b->get('question_id')) || preg_match('/\A[A-Za-z0-9_-]{1,64}\z/', $b->get('question_id')) !== 1) {
            return 'question_id must match [A-Za-z0-9_-]{1,64}';
        }
        if (!in_array($b->get('friction'), ['tap', 'hold', 'typed', 'device'], true)) {
            return 'unknown friction tier';
        }
        if ($b->get('delivered_to') !== 'wallet' && $b->get('delivered_to') !== 'agent') {
            return "delivered_to must be 'wallet' or 'agent'";
        }
        if (!self::safeInt($b->get('expires_at')) || $b->get('expires_at')->float() < 0) {
            return 'expires_at must be a non-negative safe integer';
        }
        return $b->has('sig') ? 'an unsigned body must not carry sig' : null;
    }

    /**
     * The site's signed `pca-intent-required` v1 body: `sig = {alg, kid, value, pq_value?}` over utf8(domain) || strictCanonical(body),
     * pinned by the same discovery key entry as the action schema.
     */
    public static function signIntentRequired(mixed $body, string $kid, KeyPair $site, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = Sign::n($body);
        $bad = self::intentRequiredShapeError($b);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signIntentRequired: $bad");
        }
        $out = $b->without();
        $out->set('sig', self::siteSig($alg, $kid, Sign::signWithSuite($alg, $site, $pq, self::INTENT_REQUIRED_DOMAIN . Json::canonicalizeNative($b))));
        return $out;
    }

    private static function kinded(string $kind, mixed $body, string $what): Obj
    {
        $full = Sign::n(['v' => 1, 'kind' => $kind]);
        $b = self::obj($body, $what);
        foreach ($b->keys() as $k) {
            $full->set($k, $b->get($k));
        }
        return $full;
    }

    /** A site's signed label receipt (`pca-labels` v1). */
    public static function signLabels(mixed $body, KeyPair $key, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return Sign::signArtifact(IntentWb::LABELS_DOMAIN, self::kinded('pca-labels', $body, 'signLabels'), $key, $alg, $pq);
    }

    /** An oracle's signed fact (`pca-fact` v1). */
    public static function signFact(mixed $body, KeyPair $key, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return Sign::signArtifact(IntentWb::FACT_DOMAIN, self::kinded('pca-fact', $body, 'signFact'), $key, $alg, $pq);
    }

    /**
     * A site's signed offer set (`pca-offer-set` v1; the body carries its own v / kind). As in the reference, only the strict
     * canonical profile is checked before signing (the verifier checks the wire).
     */
    public static function signOfferSet(mixed $body, KeyPair $key, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return Sign::signArtifact(IntentWb::OFFER_SET_DOMAIN, self::obj($body, 'signOfferSet'), $key, $alg, $pq);
    }

    // ---- linked policy templates (policy-link.ts signTemplate / signTighten) --------------------------------------------------

    /** The principal's signed policy template {def, signer, sig}. */
    public static function signTemplate(mixed $def, KeyPair $key): Obj
    {
        $d = Sign::n($def);
        $e = PolicyLink::templateDefError($d);
        if ($e !== null) {
            throw new \InvalidArgumentException("signTemplate: $e");
        }
        $msg = PolicyLink::SIG_DOMAIN_TEMPLATE . hash('sha256', PolicyLink::templateDigest($d), true);
        return Obj::of(['def' => $d, 'signer' => $key->public, 'sig' => Pca::b64u($key->sign($msg))]);
    }

    /** The principal's signed tighten overlay {overlay, signer, sig} (it can only add where conditions and caveats). */
    public static function signTighten(mixed $overlay, KeyPair $key): Obj
    {
        $o = Sign::n($overlay);
        $e = PolicyLink::tightenOverlayError($o);
        if ($e !== null) {
            throw new \InvalidArgumentException("signTighten: $e");
        }
        $msg = PolicyLink::SIG_DOMAIN_TIGHTEN . hash('sha256', Pca::hashCanonical($o), true);
        return Obj::of(['overlay' => $o, 'signer' => $key->public, 'sig' => Pca::b64u($key->sign($msg))]);
    }

    // ---- revocation epoch (revocation.ts signRevocationEpoch, guardian side) --------------------------------------------------

    /**
     * The guardian's signed revocation epoch over {instance_id, grant_ref, epoch, set_size, root, issued_at, not_after}; a non-ed25519
     * suite binds `alg` and `pq_pk` into the signed bytes. The output names the guardian.
     */
    public static function signRevocationEpoch(KeyPair $guardian, mixed $body, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj($body, 'signRevocationEpoch');
        $fields = new Obj();
        foreach (self::EPOCH_FIELDS as $k) {
            if (!$b->has($k)) {
                throw new \InvalidArgumentException("signRevocationEpoch: missing $k");
            }
            $fields->set($k, $b->get($k));
        }
        $out = Sign::signArtifact(RevocationStaleness::EPOCH_DOMAIN, $fields, $guardian, $alg, $pq);
        $out->set('guardian', $guardian->public);
        return $out;
    }

    // ---- registry documents and re-approval (action-pin.ts), accumulator receipts and sequencer key sets (intent-acc.ts),
    // ---- classifier verdicts (intent-classifier.ts): the signing side of artifacts this package already verifies

    /** The scopes an accumulator can be kept at. */
    public const ACC_SCOPES = ['session', 'principal', 'org', 'fleet'];
    public const ACC_RECEIPT_CORE_DOMAIN = 'atlas-pca/acc-receipt-core/v1';

    /** Sign `$body` under `$domain` as a registry key: `{alg, kid, value, pq_value?}` over utf8(domain) || strictCanonical(body). */
    public static function signRegistryDoc(string $domain, mixed $body, string $kid, KeyPair $registry, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return self::siteSig($alg, $kid, Sign::signWithSuite($alg, $registry, $pq, $domain . Json::canonicalizeNative($body)));
    }

    /** Sign an unsigned evolution record as the registry (`$kid` names the pinned registry key entry); throws for a malformed record. */
    public static function signEvolutionRecord(mixed $rec, string $kid, KeyPair $registry, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $r = Sign::n($rec);
        $bad = ActionsRegistry::evolutionRecordError($r, false);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signEvolutionRecord: $bad");
        }
        $out = $r->without();
        $out->set('sig', self::signRegistryDoc(ActionsRegistry::EVOLUTION_DOMAIN, $r, $kid, $registry, $alg, $pq));
        return $out;
    }

    /** The registry key entry {kid, alg, pk, pq_pk?} a verifier pins for a registry signer. */
    public static function registryKeyOf(string $kid, KeyPair $registry, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return self::actionSchemaKeyOf($kid, $registry, $alg, $pq);
    }

    /**
     * The principal approves one evolution step (`$record`, signed or not) for the grant `$grantId`:
     * `{v: 1, kind: "pca-reapproval", grant, verb, diff, sig: {alg: "ed25519", value}}`.
     */
    public static function signReapproval(string $grantId, mixed $record, KeyPair $principal): Obj
    {
        $r = self::obj($record, 'signReapproval');
        $body = Sign::n(['v' => 1, 'kind' => ActionsRegistry::REAPPROVAL_KIND, 'grant' => $grantId, 'verb' => $r->get('verb'), 'diff' => ActionsRegistry::evolutionDiffDigest($r)]);
        $out = $body->without();
        $out->set('sig', Obj::of(['alg' => 'ed25519', 'value' => Pca::b64u($principal->sign(ActionsRegistry::REAPPROVAL_DOMAIN . Json::canonicalizeNative($body)))]));
        return $out;
    }

    /** `$body` members `$keys` in that order (an absent member is left out), then `$tail`. */
    private static function pick(Obj $body, array $keys, array $tail = []): Obj
    {
        $o = new Obj();
        foreach ($keys as $k) {
            if ($body->has($k)) {
                $o->set($k, $body->get($k));
            }
        }
        foreach ($tail as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    /**
     * Sign an accumulator receipt as the sequencer: the receipt body plus `signer` (the sequencer key) and the suite's signature
     * fields. Throws when the result is not a well-formed receipt (the shape rules of the verifier).
     */
    public static function signAccReceipt(mixed $body, KeyPair $sequencer, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj($body, 'signAccReceipt');
        $ledger = $b->get('ledger');
        if (!($ledger instanceof Obj)) {
            throw new \InvalidArgumentException('signAccReceipt: the receipt needs its ledger position');
        }
        $base = self::pick($b, ['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at', 'expires_at', 'kid'],
            ['ledger' => self::pick($ledger, ['index', 'head']), 'signer' => $sequencer->public]);
        $out = Sign::signArtifact(IntentV2::ACC_RECEIPT_DOMAIN, $base, $sequencer, $alg, $pq);
        $bad = IntentV2::accReceiptShapeError($out);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signAccReceipt: $bad");
        }
        return $out;
    }

    /**
     * The receipt's log leaf content: the receipt without its `ledger` position, its `kid` and its signature fields. Two receipts with
     * the same (session, acc, seq) and different cores in one witnessed log are provable equivocation.
     */
    public static function accReceiptCoreDigest(mixed $r): string
    {
        $o = self::obj($r, 'accReceiptCoreDigest');
        $core = new Obj();
        foreach (['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at', 'expires_at'] as $k) {
            $core->set($k, $o->get($k));
        }
        return Pca::hashCanonical(Obj::of(['d' => self::ACC_RECEIPT_CORE_DOMAIN, 'r' => $core]));
    }

    /** Sign a sequencer key set as the root key (`sequencer` is derived from it). Throws when the result is not a well-formed key set. */
    public static function signSequencerKeySet(mixed $body, KeyPair $root, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $b = self::obj($body, 'signSequencerKeySet');
        $base = new Obj();
        foreach (['v', 'kind', 'sequencer', 'version', 'issued_at', 'keys'] as $k) {
            if ($k === 'sequencer') {
                $base->set($k, $root->public);
            } elseif ($b->has($k)) {
                $base->set($k, $b->get($k));
            }
        }
        $out = Sign::signArtifact(IntentV2::SEQUENCER_KEYS_DOMAIN, $base, $root, $alg, $pq);
        $bad = IntentV2::sequencerKeySetShapeError($out);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signSequencerKeySet: $bad");
        }
        return $out;
    }

    /** Sign a classifier verdict (classifier side): `v`, `kind` and `judge` (the key) are set here, the rest comes from `$body`. */
    public static function signClassifierVerdict(mixed $body, KeyPair $judge, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $o = Sign::n(['v' => 1, 'kind' => 'pca-intent-classification']);
        $b = self::obj($body, 'signClassifierVerdict');
        foreach ($b->keys() as $k) {
            $o->set($k, $b->get($k));
        }
        $o->set('judge', $judge->public);
        return Sign::signArtifact(IntentWb::INTENT_CLASSIFIER_DOMAIN, $o, $judge, $alg, $pq);
    }
}
