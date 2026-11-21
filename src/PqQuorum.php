<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/K3Sig.php';

/**
 * Post-quantum t-of-n authorization by composition (the TypeScript reference pq-threshold.ts is authoritative): a quorum SET of n
 * registered PQ signers with a threshold t and a diversity commitment k (the minimum number of hash-based signers), a quorum PROOF of
 * at least t independent per-signer signatures over one domain-separated message, and ROTATION certificates chained from a genesis set.
 * No new cryptography: counting, binding and de-duplication on top of the suite seam ({@see Sign::signWithSuite}, {@see Pca::verifyWithSuite}).
 *
 * Values are the parsed-JSON model (Obj, list arrays, string, Num, bool, null). Verifiers never throw and answer with the reference's
 * reason strings; the signing and digest functions throw on missing key material and on a value the strict canonical form refuses.
 */
final class PqQuorum
{
    public const PQ_QUORUM_MAX_SIGNERS = 256;
    public const PQ_QUORUM_MAX_CHAIN = 1024;
    private const SET_DOMAIN = 'atlas-pca/pq-quorum-set/v1';
    private const MSG_DOMAIN = "atlas-pca/pq-quorum-msg/v1\0";
    private const ROTATION_KIND = 'pq-quorum-rotation';
    private const ED_PK_BYTES = 32;
    private const MAX_SAFE = 9007199254740991.0;
    private const BAD_SET = ['ok' => false, 'reason' => 'bad-set'];
    /** The public-key member of a signer input, by PQ family (LESS is not a quorum suite). */
    private const KEY_MEMBER = ['ML-DSA-65' => 'mlDsaPub', 'ML-DSA-87' => 'mlDsa87Pub', 'SLH-DSA-SHA2-128f' => 'slhDsaPub', 'SLH-DSA-SHA2-256s' => 'slhDsa256sPub',
        'FN-DSA-512' => 'fnDsa512Pub', 'FN-DSA-1024' => 'fnDsa1024Pub'];

    // ---- value helpers ---------------------------------------------------------------------------------------------

    /** The double of a JSON number that is a safe integer, else null. */
    private static function safeInt(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : null;
        return $v !== null && is_finite($v) && floor($v) === $v && abs($v) <= self::MAX_SAFE ? $v : null;
    }

    /** A non-negative safe integer, never -0. */
    private static function isEpoch(mixed $x): bool
    {
        $v = self::safeInt($x);
        return $v !== null && $v >= 0 && !K3Sig::isNegZero($x);
    }

    private static function sha384(string $bytes): string
    {
        return hash('sha384', $bytes, true);
    }

    private static function isHashBased(string $alg): bool
    {
        return str_starts_with((string)Pq::SIG_SUITES[$alg]['family'], 'SLH-DSA');
    }

    /** `$list[$i]` as the reference indexes an array: by a natural number or its decimal string. */
    private static function at(mixed $list, mixed $i): mixed
    {
        if (!is_array($list)) {
            return null;
        }
        if (is_string($i)) {
            return preg_match('/\A(0|[1-9][0-9]{0,15})\z/', $i) === 1 ? ($list[(int)$i] ?? null) : null;
        }
        $v = self::safeInt($i);
        return $v !== null && $v >= 0 ? ($list[(int)$v] ?? null) : null;
    }

    private static function member(mixed $o, string $k): mixed
    {
        if ($o === null) {
            throw new \InvalidArgumentException("cannot read $k of null");
        }
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : JsUndefined::U;
    }

    // ---- the quorum set --------------------------------------------------------------------------------------------

    /** @return array{alg: string, ed?: string, pq: string}|null */
    private static function normalizeEntry(mixed $alg, bool $hasEd, mixed $ed, mixed $pq): ?array
    {
        $suite = is_string($alg) ? Pq::resolveSigAlg($alg) : null;
        if ($suite === null || !isset(self::KEY_MEMBER[$suite['family']]) || Pca::unb64u($pq, $suite['pqPkBytes']) === null) {
            return null;
        }
        if ($suite['hasEd25519']) {
            return Pca::unb64u($ed, self::ED_PK_BYTES) === null ? null : ['alg' => $alg, 'ed' => $ed, 'pq' => $pq];
        }
        return $hasEd ? null : ['alg' => $alg, 'pq' => $pq];
    }

    private static function entryKey(array $e): string
    {
        return $e['alg'] . '|' . ($e['ed'] ?? '') . '|' . $e['pq'];
    }

    private static function entryObj(array $e): Obj
    {
        return Obj::of($e);
    }

    /** @param list<array{alg: string, ed?: string, pq: string}> $entries @return array{ok: bool, reason?: string, set?: Obj, sorted?: list<array>} */
    private static function finalize(array $entries, mixed $t, mixed $k): array
    {
        $n = count($entries);
        $tv = self::safeInt($t);
        $kv = self::safeInt($k);
        if ($n < 1 || $n > self::PQ_QUORUM_MAX_SIGNERS || $tv === null || $tv < 1 || $tv > $n || $kv === null || $kv < 0 || $kv > $tv) {
            return self::BAD_SET;
        }
        $sorted = $entries;
        usort($sorted, static fn(array $a, array $b): int => strcmp(self::entryKey($a), self::entryKey($b)));
        $seen = [];
        $hash = 0;
        foreach ($sorted as $e) {
            foreach (isset($e['ed']) ? [$e['ed'], $e['pq']] : [$e['pq']] as $c) {
                if (isset($seen["k$c"])) {
                    return self::BAD_SET;
                }
                $seen["k$c"] = true;
            }
            $hash += self::isHashBased($e['alg']) ? 1 : 0;
        }
        if ($hash < $kv) {
            return self::BAD_SET;
        }
        $body = Obj::of(['d' => self::SET_DOMAIN, 't' => $t, 'k' => $k,
            's' => array_map(static fn(array $e): Obj => Obj::of(['a' => $e['alg'], 'e' => $e['ed'] ?? null, 'p' => $e['pq']]), $sorted)]);
        $id = Pca::b64u(self::sha384(Json::canonicalizeNative($body))); // a negative-zero k is refused here, as the reference's strict form does
        return ['ok' => true, 'set' => Obj::of(['t' => $t, 'minHashBased' => $k, 'signers' => array_map(self::entryObj(...), $sorted), 'id' => $id]), 'sorted' => $sorted];
    }

    /**
     * Build a quorum set from `[{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?, fnDsa1024Pub?}}]`
     * (base64url public keys), a threshold `$t` and the diversity commitment `$minHashBased`. Every key component must be distinct
     * across the whole set. Never throws.
     *
     * @return array{ok: true, set: Obj}|array{ok: false, reason: string}
     */
    public static function buildQuorumSet(mixed $signers, mixed $t, mixed $minHashBased = 0): array
    {
        try {
            if (!is_array($signers) || !array_is_list($signers)) {
                return self::BAD_SET;
            }
            $entries = [];
            foreach ($signers as $s) {
                $keys = $s instanceof Obj ? $s->get('keys') : null;
                $suite = $s instanceof Obj && $s->has('alg') && is_string($s->get('alg')) ? Pq::resolveSigAlg($s->get('alg')) : null;
                if (!($keys instanceof Obj) || $suite === null) {
                    return self::BAD_SET;
                }
                $e = self::normalizeEntry($s->get('alg'), $keys->has('edPub'), $keys->get('edPub'), $keys->get(self::KEY_MEMBER[$suite['family']] ?? 'slhDsa256sPub'));
                if ($e === null) {
                    return self::BAD_SET;
                }
                $entries[] = $e;
            }
            $num = static fn(mixed $x): mixed => is_int($x) ? new Num((string)$x) : $x;
            $r = self::finalize($entries, $num($t), $num($minHashBased));
            return $r['ok'] ? ['ok' => true, 'set' => $r['set']] : self::BAD_SET;
        } catch (\Throwable) {
            return self::BAD_SET;
        }
    }

    /**
     * Load a quorum set from the wire: the id is re-derived and must match, the signer order must already be canonical, and an entry
     * is `{alg, ed?, pq}` with `ed` required on a hybrid and forbidden otherwise. Never throws.
     *
     * @return array{ok: true, set: Obj}|array{ok: false, reason: string}
     */
    public static function loadQuorumSet(mixed $x): array
    {
        try {
            $signers = $x instanceof Obj ? $x->get('signers') : null;
            if (!is_array($signers) || !array_is_list($signers) || !is_string($x->get('id'))) {
                return self::BAD_SET;
            }
            $entries = [];
            foreach ($signers as $s) {
                $e = $s instanceof Obj ? self::normalizeEntry($s->get('alg'), $s->has('ed'), $s->get('ed'), $s->get('pq')) : null;
                if ($e === null) {
                    return self::BAD_SET;
                }
                $entries[] = $e;
            }
            $r = self::finalize($entries, $x->get('t'), $x->get('minHashBased'));
            if (!$r['ok'] || array_map(self::entryKey(...), $r['sorted']) !== array_map(self::entryKey(...), $entries) || $r['set']->get('id') !== $x->get('id')) {
                return self::BAD_SET;
            }
            return ['ok' => true, 'set' => $r['set']];
        } catch (\Throwable) {
            return self::BAD_SET;
        }
    }

    // ---- message, shares, proof ------------------------------------------------------------------------------------

    /**
     * The bytes every signer signs: the domain prefix, then SHA-384 of the strict canonical form of `{set_id, epoch, action}`. The
     * arguments are not validated (any JSON value); a value the strict canonical form refuses throws.
     */
    public static function quorumMessage(mixed $setId, mixed $epoch, mixed $actionDigest): string
    {
        return self::MSG_DOMAIN . self::sha384(Json::canonicalizeNative(Obj::of(['set_id' => $setId, 'epoch' => $epoch, 'action' => $actionDigest])));
    }

    /** The action digest of an arbitrary message: base64url of its SHA-384. */
    public static function quorumActionDigest(string $message): string
    {
        return Pca::b64u(self::sha384($message));
    }

    /**
     * One signer's share `{i, sig, pq_sig?}` over the quorum message. `$ed` is the Ed25519 key of a hybrid slot; of `$pq` the key
     * pair whose family the slot's suite needs is used. Throws on an unknown index or missing key material.
     */
    public static function signQuorumShare(mixed $set, mixed $index, mixed $epoch, mixed $actionDigest, ?KeyPair $ed = null, PqKeyPair ...$pq): Obj
    {
        $e = self::at(self::member($set, 'signers'), $index);
        if (!($e instanceof Obj) || !is_string($e->get('alg')) || !isset(Pq::SIG_SUITES[$e->get('alg')])) {
            throw new \RangeException('signQuorumShare: no such signer index');
        }
        $family = Pq::SIG_SUITES[$e->get('alg')]['family'];
        $key = null;
        foreach ($pq as $p) {
            $key ??= $p->family === $family ? $p : null;
        }
        $id = self::member($set, 'id');
        $p = Sign::signWithSuite($e->get('alg'), $ed, $key, self::quorumMessage($id === JsUndefined::U ? throw new \InvalidArgumentException('signQuorumShare: the set has no id') : $id, $epoch, $actionDigest));
        $out = Obj::of(['i' => $index, 'sig' => $p['sig']]);
        if (isset($p['pq_sig'])) {
            $out->set('pq_sig', $p['pq_sig']);
        }
        return $out;
    }

    /** `{set_id, sigs}`: the shares are copied untouched (the verifier judges them). Throws when `$set` is null or `$shares` is not a list. */
    public static function assembleQuorumProof(mixed $set, mixed $shares): Obj
    {
        $id = self::member($set, 'id');
        if (is_string($shares)) {
            $shares = $shares === '' ? [] : mb_str_split($shares, 1, 'UTF-8'); // the reference spreads a string into its characters
        }
        if (!is_array($shares) || !array_is_list($shares)) {
            throw new \InvalidArgumentException('assembleQuorumProof: shares is not a list');
        }
        $out = new Obj();
        if ($id !== JsUndefined::U) {
            $out->set('set_id', $id);
        }
        $out->set('sigs', $shares);
        return $out;
    }

    /**
     * Verify a quorum proof. `$input` is `{set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}`. Never throws.
     *
     * @return array{ok: true, signers: list<int>, count: int, hashBased: int}|array{ok: false, reason: string, detail?: int}
     */
    public static function verifyQuorum(mixed $input): array
    {
        $no = static fn(string $reason, ?int $detail = null): array => ['ok' => false, 'reason' => $reason] + ($detail === null ? [] : ['detail' => $detail]);
        try {
            if (!($input instanceof Obj)) {
                return $no('malformed');
            }
            $loaded = self::loadQuorumSet($input->get('set'));
            if (!$loaded['ok']) {
                return $no('bad-set');
            }
            $set = $loaded['set'];
            $signers = $set->get('signers');
            $n = count($signers);
            if ($input->has('expectedSetId') && $input->get('expectedSetId') !== $set->get('id')) {
                return $no('set-mismatch');
            }
            if (!self::isEpoch($input->get('epoch')) || !is_string($input->get('actionDigest'))) {
                return $no('malformed');
            }
            $p = $input->get('proof');
            $sigs = $p instanceof Obj ? $p->get('sigs') : null;
            if (!is_array($sigs) || !array_is_list($sigs) || !is_string($p->get('set_id'))) {
                return $no('malformed');
            }
            if ($p->get('set_id') !== $set->get('id')) {
                return $no('set-mismatch');
            }
            if (count($sigs) > $n) {
                return $no('too-many-signatures'); // before any signature work
            }
            $msg = self::quorumMessage($set->get('id'), $input->get('epoch'), $input->get('actionDigest'));
            $seen = [];
            $hashBased = 0;
            foreach ($sigs as $raw) {
                if (!($raw instanceof Obj) || !is_string($raw->get('sig'))) {
                    return $no('malformed');
                }
                if (!self::isEpoch($raw->get('i')) || $raw->get('i')->float() >= $n) {
                    return $no('unknown-signer');
                }
                $i = (int)$raw->get('i')->float();
                if (isset($seen[$i])) {
                    return $no('duplicate-signer', $i);
                }
                $seen[$i] = true;
                $e = $signers[$i];
                $alg = $e->get('alg');
                $keys = ['pq' => Pca::resolvePqVerifyKey($e->get('ed') ?? '', null, ['trustedPk' => $e->get('pq')])];
                if ($e->has('ed')) {
                    $keys['edPub'] = $e->get('ed');
                }
                if (Pq::SIG_SUITES[$alg]['needsPqSig'] !== $raw->has('pq_sig') || !Pca::verifyWithSuite($alg, $keys, $msg, ['sig' => $raw->get('sig'), 'pq_sig' => $raw->get('pq_sig')])) {
                    return $no('bad-signature', $i);
                }
                $hashBased += self::isHashBased($alg) ? 1 : 0;
            }
            if (count($seen) < $set->get('t')->float()) {
                return $no('below-threshold');
            }
            $req = $input->get('requireHashBased') === null ? 0.0 : Jsx::toNum($input->get('requireHashBased'));
            $k = is_nan($req) ? NAN : max($set->get('minHashBased')->float(), $req);
            if (!is_finite($k) || floor($k) !== $k || abs($k) > self::MAX_SAFE || $k < 0) {
                return $no('malformed');
            }
            if ($hashBased < $k) {
                return $no('diversity-unmet');
            }
            $who = array_keys($seen);
            sort($who);
            return ['ok' => true, 'signers' => $who, 'count' => count($who), 'hashBased' => $hashBased];
        } catch (\Throwable) {
            return $no('malformed');
        }
    }

    /**
     * Did the quorum approve `$message` (raw bytes) at `$epoch`? `$opts` may carry `expectedSetId` and `requireHashBased` (an Obj or
     * an array). A message that is not a byte string is false. Never throws.
     */
    public static function verifyQuorumApproval(mixed $set, mixed $proof, mixed $message, mixed $epoch, mixed $opts = null): bool
    {
        try {
            if (!is_string($message)) {
                return false;
            }
            $in = Obj::of(['set' => $set, 'proof' => $proof, 'epoch' => $epoch, 'actionDigest' => self::quorumActionDigest($message)]);
            foreach (['expectedSetId', 'requireHashBased'] as $k) {
                if (Js::has($opts, $k)) {
                    $in->set($k, Js::opt($opts, $k));
                }
            }
            return self::verifyQuorum($in)['ok'];
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- rotation --------------------------------------------------------------------------------------------------

    /** The action digest the OLD quorum signs to hand over to `$toSetId` at `$toEpoch` (any JSON values; throws on an unhashable one). */
    public static function rotationActionDigest(mixed $toSetId, mixed $toEpoch): string
    {
        return Pca::b64u(self::sha384(Json::canonicalizeNative(Obj::of(['kind' => self::ROTATION_KIND, 'to_set_id' => $toSetId, 'to_epoch' => $toEpoch]))));
    }

    /** `x + 1` as the reference evaluates it: arithmetic on a number, concatenation on a string. */
    private static function plusOne(mixed $x): mixed
    {
        if (is_string($x) || is_array($x) || $x instanceof Obj) {
            return IntentWb::jsStr($x) . '1';
        }
        return Sign::n(Jsx::toNum($x) + 1.0);
    }

    /** `{from_set_id, from_epoch, to_set, to_epoch, proof}`: the hand-over from `$from` at `$fromEpoch` to `$to`, carrying the old quorum's shares. */
    public static function buildRotationCert(mixed $from, mixed $fromEpoch, mixed $to, mixed $shares): Obj
    {
        $out = new Obj();
        $id = self::member($from, 'id');
        if ($id !== JsUndefined::U) {
            $out->set('from_set_id', $id);
        }
        $out->set('from_epoch', $fromEpoch);
        $out->set('to_set', $to);
        $out->set('to_epoch', self::plusOne($fromEpoch));
        $out->set('proof', self::assembleQuorumProof($from, $shares));
        return $out;
    }

    /** One old-quorum signer's share over the rotation to `$to`. Throws like {@see signQuorumShare}, and when `$to` is null. */
    public static function signRotationShare(mixed $from, mixed $index, mixed $fromEpoch, mixed $to, ?KeyPair $ed = null, PqKeyPair ...$pq): Obj
    {
        $toId = self::member($to, 'id');
        if ($toId === JsUndefined::U) {
            throw new \InvalidArgumentException('signRotationShare: the new set has no id');
        }
        return self::signQuorumShare($from, $index, $fromEpoch, self::rotationActionDigest($toId, self::plusOne($fromEpoch)), $ed, ...$pq);
    }

    /**
     * Walk a rotation chain from a genesis set and epoch: every link must name the current set, advance the epoch by exactly one,
     * carry a loadable, different next set, and be approved by the CURRENT quorum. Never throws.
     *
     * @return array{ok: true, set: Obj, epoch: mixed, length: int}|array{ok: false, reason: string, at: int}
     */
    public static function verifyRotationChain(mixed $genesisSet, mixed $genesisEpoch, mixed $chain): array
    {
        $no = static fn(string $reason, int $at): array => ['ok' => false, 'reason' => $reason, 'at' => $at];
        try {
            $g = self::loadQuorumSet($genesisSet);
            if (!$g['ok'] || !self::isEpoch($genesisEpoch)) {
                return $no('bad-set', -1);
            }
            if (!is_array($chain) || !array_is_list($chain)) {
                return $no('malformed', -1);
            }
            if (count($chain) > self::PQ_QUORUM_MAX_CHAIN) {
                return $no('chain-too-long', -1);
            }
            $cur = $g['set'];
            $epoch = $genesisEpoch;
            foreach ($chain as $n => $c) {
                if (!($c instanceof Obj) || !is_string($c->get('from_set_id')) || !self::isEpoch($c->get('from_epoch')) || !self::isEpoch($c->get('to_epoch'))) {
                    return $no('malformed', $n);
                }
                if ($c->get('from_set_id') !== $cur->get('id')) {
                    return $no('chain-broken', $n);
                }
                if ($c->get('from_epoch')->float() !== $epoch->float() || $c->get('to_epoch')->float() !== $epoch->float() + 1.0) {
                    return $no('non-monotone-epoch', $n);
                }
                $next = self::loadQuorumSet($c->get('to_set'));
                if (!$next['ok'] || $next['set']->get('id') === $cur->get('id')) {
                    return $no('bad-rotation', $n);
                }
                $v = self::verifyQuorum(Obj::of(['set' => $cur, 'proof' => $c->get('proof'), 'epoch' => $epoch,
                    'actionDigest' => self::rotationActionDigest($next['set']->get('id'), $c->get('to_epoch')), 'expectedSetId' => $cur->get('id')]));
                if (!$v['ok']) {
                    return $no($v['reason'], $n);
                }
                $cur = $next['set'];
                $epoch = $c->get('to_epoch');
            }
            return ['ok' => true, 'set' => $cur, 'epoch' => $epoch, 'length' => count($chain)];
        } catch (\Throwable) {
            return $no('malformed', -1);
        }
    }

    /** JS `===` of two members that may be absent: absent equals absent, numbers by value, lists and objects never (distinct values). */
    private static function same(Obj $a, Obj $b, string $k): bool
    {
        if (!$a->has($k) || !$b->has($k)) {
            return !$a->has($k) && !$b->has($k);
        }
        [$x, $y] = [$a->get($k), $b->get($k)];
        if ($x instanceof Num && $y instanceof Num) {
            return $x->float() === $y->float();
        }
        return !is_array($x) && !is_object($x) && $x === $y;
    }

    /** Two rotation certificates that leave the SAME set at the SAME epoch for DIFFERENT next sets (equivocation by the old quorum). Structural only. */
    public static function isRotationFork(mixed $a, mixed $b): bool
    {
        if (!($a instanceof Obj) || !($b instanceof Obj) || !($a->get('to_set') instanceof Obj) || !($b->get('to_set') instanceof Obj)) {
            return false;
        }
        [$x, $y] = [$a->get('to_set')->get('id'), $b->get('to_set')->get('id')];
        return self::same($a, $b, 'from_set_id') && self::same($a, $b, 'from_epoch') && is_string($x) && is_string($y) && $x !== $y;
    }

    // ---- size ------------------------------------------------------------------------------------------------------

    private static function shareBytes(mixed $e): int
    {
        $alg = $e instanceof Obj ? $e->get('alg') : null;
        if (!is_string($alg) || !isset(Pq::SIG_SUITES[$alg])) {
            throw new \InvalidArgumentException('quorumProofSize: unknown suite');
        }
        return Pq::SIG_SUITES[$alg]['sigBytes'] + Pq::SIG_SUITES[$alg]['pqSigBytes'];
    }

    /**
     * Signature bytes of a quorum proof: of the t smallest and the t largest signers, and of the chosen `$indices` when given (an
     * unknown index counts 0). There is no compact form: `compact` is always false. Throws on a value that is not a set.
     *
     * @return array{minBytes: int, maxBytes: int, t: mixed, compact: false, chosenBytes?: int}
     */
    public static function quorumProofSize(mixed $set, mixed $indices = null): array
    {
        $signers = self::member($set, 'signers');
        $t = self::safeInt($set->get('t'));
        if (!is_array($signers) || !array_is_list($signers) || $t === null || $t < 0) {
            throw new \InvalidArgumentException('quorumProofSize: not a quorum set');
        }
        $sizes = array_map(self::shareBytes(...), $signers);
        sort($sizes);
        $take = (int)min($t, count($sizes));
        $r = ['minBytes' => array_sum(array_slice($sizes, 0, $take)), 'maxBytes' => array_sum(array_slice($sizes, count($sizes) - $take)), 't' => $set->get('t'), 'compact' => false];
        if ($indices !== null) {
            if (!is_array($indices) || !array_is_list($indices)) {
                throw new \InvalidArgumentException('quorumProofSize: indices is not a list');
            }
            $r['chosenBytes'] = array_sum(array_map(static fn(mixed $i): int => ($e = self::at($signers, $i)) === null ? 0 : self::shareBytes($e), $indices));
        }
        return $r;
    }
}
