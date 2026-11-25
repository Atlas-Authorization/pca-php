<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Evidence.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentHistory.php';
require_once __DIR__ . '/IntentJit.php';
require_once __DIR__ . '/IntentMapKit.php';
require_once __DIR__ . '/IntentStatement.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Ledger.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/Webauthn.php';

/**
 * `EvidenceVerify::verifyEvidenceBundle`: deterministic replay of a dispute evidence bundle (Intent Layer v2). Every finding is
 * RECOMPUTED from the signed artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the
 * verdicts) is taken on trust. The output is a findings report whose text comes from fixed templates, so two readers of the same
 * bundle with the same trust inputs get byte-identical reports (`report_digest`). Three statuses, never mixed: `pass` (re-verified
 * here), `fail` (re-verification refuted it), `unverified` (this verifier had no way to check it: no verifier for the format, an
 * unopened map, a missing trust key); `complete` is false whenever one is present.
 *
 * Never throws on a malformed bundle: it is a report with a failed `shape` finding, and a fault inside the replay is a failed
 * `shape` finding too (fail closed). A `trust.verifiers[name]` port is a callable `(artifact, bundle) -> {ok, reason}` (an Obj or an
 * array) that OVERRIDES the core default of that artifact.
 */
final class EvidenceVerify
{
    private const INTENT_ANCHOR_LOG = 'pca-intent:v1';
    private const DEFAULT_REVOCATION_MAX_AGE_S = 300;
    private const V2_CHECKS = ['schema', 'intent_session', 'accumulators'];
    private const TS_CHECK_NAMES = ['chain' => 'cap_chain', 'freshness_anchor' => 'freshness'];

    private const TEMPLATES = [
        'shape' => 'The bundle is well formed (pca-intent-evidence v1, closed members)',
        'principal.pinned' => 'Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)',
        'trust.principals' => 'The pinned principal keys (trust.principals) are well formed',
        'statement.commit' => 'The session root commits to the intent statement the bundle names',
        'statement.opening' => 'The opened statement is signed by a principal and hashes to the committed ref',
        'session_root.signature' => 'The session root is signed by one of its principal keys',
        'schema.signature' => 'The action schema is signed by a site key',
        'schema.digest' => 'The session root binds this action schema',
        'schema.anchor' => 'The action schema is anchored in a transparency log',
        'map.replay' => 'The task map replays to its committed digest',
        'root_grant' => 'The root intent grant G_0 is principal-signed and bound to the session',
        'delta.signature' => 'The delta grant is a root capability signed by a principal of the session',
        'delta.chain' => 'The delta grant chains to the session (session, seq, prev, root)',
        'delta.backed' => 'Every delta grant is backed by a principal "yes" answer',
        'answer.signature' => 'The answer is signed by a principal of the session, for this session',
        'answer.map' => 'The answer refers to a map version in the bundle',
        'answer.tier' => 'The answer meets the site minimum friction tier for the verb',
        'answer.typed' => 'The typed-tier value re-derives the signed typed digest',
        'answer.device' => 'The device-tier WebAuthn assertion verifies with user verification',
        'canaries.summary' => 'The canary summary equals the one recomputed from the signed canary answers',
        'pcactn.verify' => 'The PCActn verifies (signature, chain, audience, validity at its issue time)',
        'pcactn.root' => "The PCActn's root capability is G_0 or a bundled delta grant",
        'pcactn.session' => "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        'subject.present' => 'The subject PCActn is in the bundle',
        'jit.consent' => 'The irreversible subject action carries a principal JIT consent bound to its exact action digest',
        'accumulator.declared' => 'The accumulator is declared in the session root',
        'accumulator.arithmetic' => 'The accumulator posts are the running values of the counted events',
        'accumulator.cap' => "Every accumulator post is within the admitting grant's cap",
        'accumulator.receipts' => 'The sequencer reservation receipt verifies and is consistent',
        'acc.keysets.equivocation' => 'No two different sequencer key sets share one root and version',
        'acc.keysets' => "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        'trust.acc' => 'The verifier freshness configuration (trust.acc) is well formed',
        'effect.binding' => "The effect record is bound to the PCActn's signed params",
        'effect.charged' => 'The charged amount is within the confirmed value',
        'effect.frame' => 'No monitored state outside the write set changed',
        'effect.signature' => 'The effect record is signed by the site',
        'verdict.signature' => 'The site verdict record verifies',
        'fact.signature' => 'The oracle fact verifies under a pinned oracle key',
        'classifier.signature' => 'The classifier verdict verifies under a pinned judge key',
        'offer_set.signature' => 'The offer set is signed by a site key, for this session',
        'labels.signature' => 'The label receipt is signed by a pinned site key, for this session',
        'settlement.signature' => 'The settlement record verifies',
        'revocation.history' => 'The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)',
        'revocation.epoch' => 'A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time',
        'anchor.inclusion' => 'The anchored artifact is included under a guardian-signed head of the intent log',
    ];
    private const STATUS_TEXT = ['pass' => 'verified', 'fail' => 'REFUTED', 'unverified' => 'not verified here'];
    private const NOT_PROVEN = [
        'That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.',
        "That the site's signed schema describes what its endpoints really do (SCH).",
        "That the site's effect records and any oracle facts are true (EFF, ORC).",
        'Acceptance of this bundle by any card network, court or regulator.',
    ];

    // ---- helpers -------------------------------------------------------------------------------------------------------------

    private static function g(mixed $o, string $k): mixed
    {
        return Jsx::get($o, $k);
    }

    private static function t(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    private static function n(mixed $v): string
    {
        return Jsx::str($v);
    }

    /** A value that must be a list (a TypeError otherwise, which the replay turns into a failed shape finding). @return list<mixed> */
    private static function lst(mixed $v): array
    {
        if (!is_array($v) || !array_is_list($v)) {
            throw new \TypeError('not a list');
        }
        return $v;
    }

    private static function num(mixed $v): float
    {
        $x = Js::num($v);
        if ($x === null) {
            throw new \TypeError('not a number');
        }
        return $x;
    }

    /** An integral float as an int (so a canonical report carries 3, not 3.0). */
    private static function ni(float $x): int|float
    {
        return floor($x) === $x && abs($x) <= 9007199254740991.0 ? (int)$x : $x;
    }

    /** JS `===` over the parsed-JSON model: numbers by value, containers never equal, the undefined sentinel equal to itself. */
    private static function eq(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) === Js::num($b);
        }
        if (is_array($a) || $a instanceof Obj || is_array($b) || $b instanceof Obj) {
            return false;
        }
        return $a === $b;
    }

    private static function hasKey(array $m, mixed $k): bool
    {
        return is_string($k) && array_key_exists($k, $m);
    }

    /** @param list<mixed> $xs @return list<mixed> UTF-16 code unit order, stable */
    private static function sorted16(array $xs): array
    {
        usort($xs, static fn($a, $b): int => Jsx::cmp($a, $b));
        return $xs;
    }

    /** `Number(x?.[k]) || 0` */
    private static function numOr0(mixed $x, string $k): float
    {
        $v = Jsx::toNum(Jsx::get($x, $k));
        return is_nan($v) ? 0.0 : $v;
    }

    private static function signOf(float $a): int
    {
        return $a < 0 ? -1 : ($a > 0 ? 1 : 0);
    }

    private static function finiteNum(mixed $v): bool
    {
        return Js::isNum($v) && is_finite((float)Js::num($v));
    }

    private static function tsCheckName(string $name): string
    {
        return self::TS_CHECK_NAMES[$name] ?? $name;
    }

    private static function tsReason(mixed $reason): mixed
    {
        if (!is_string($reason)) {
            return $reason;
        }
        $pos = strpos($reason, ': ');
        if ($pos !== false) {
            $head = substr($reason, 0, $pos);
            if (isset(self::TS_CHECK_NAMES[$head])) {
                $reason = self::TS_CHECK_NAMES[$head] . ': ' . substr($reason, $pos + 2);
            }
        }
        if ($reason === 'leaf_signature: signature does not verify under the leaf holder key') {
            $reason .= ' / suite';
        }
        return $reason;
    }

    /** A verdict member of an Obj or of an array (a port may return either). */
    private static function vget(mixed $v, string $k): mixed
    {
        return $v instanceof Obj ? $v->get($k) : (is_array($v) ? ($v[$k] ?? null) : null);
    }

    /** The suite's own loop guards must end the test, never turn into a finding. */
    private static function guard(\Throwable $e): void
    {
        if ($e instanceof \RuntimeException && preg_match('/^test (deadline of|memory above) /', $e->getMessage()) === 1) {
            throw $e;
        }
    }

    // ---- findings ------------------------------------------------------------------------------------------------------------

    /** @param list<array{code:string,status:string,text:string,refs:list<string>}> $f */
    private static function add(array &$f, string $code, string $status, ?array $refs = null, mixed $detail = null): void
    {
        $d = Jsx::truthy($detail) ? ' (' . self::n($detail) . ')' : '';
        $f[] = ['code' => $code, 'status' => $status, 'text' => self::TEMPLATES[$code] . ': ' . self::STATUS_TEXT[$status] . $d . '.', 'refs' => $refs ?? []];
    }

    private static function verdict(array &$f, string $code, mixed $v, ?array $refs = null): void
    {
        if (Jsx::truthy(self::vget($v, 'ok'))) {
            self::add($f, $code, 'pass', $refs);
        } else {
            self::add($f, $code, 'fail', $refs, self::vget($v, 'reason'));
        }
    }

    /** Run `$port` if supplied, else the core default; with neither, the artifact stays unverified. */
    private static function check(array &$f, string $code, mixed $port, ?\Closure $core, mixed $artifact, mixed $bundle, array $refs, string $what): void
    {
        try {
            if ($port !== null && $port !== false) {
                if (!is_callable($port)) {
                    throw new \TypeError('the verifier is not callable');
                }
                $v = $port($artifact, $bundle);
            } elseif ($core !== null) {
                $v = $core();
            } else {
                $v = null;
            }
        } catch (\Throwable $e) { // a throwing verifier is a refutation
            self::guard($e);
            $v = ['ok' => false, 'reason' => 'verifier threw: ' . $e->getMessage()];
        }
        if ($v === null) {
            self::add($f, $code, 'unverified', $refs, "no verifier for $what");
        } else {
            self::verdict($f, $code, $v, $refs);
        }
    }

    private static function nul(?string $e): array
    {
        return $e === null ? ['ok' => true] : ['ok' => false, 'reason' => $e];
    }

    private static function emptySummary(): array
    {
        return ['admitted_under' => null, 'principal_keys' => [], 'answers' => ['total' => 0, 'yes' => 0, 'no' => 0, 'partial' => 0, 'canaries' => 0], 'refusals' => [],
            'consent' => null, 'charged' => null, 'canary_accuracy' => ['correct' => 0, 'asked' => 0], 'attribution' => ['pinned' => false, 'keys_to_check' => []],
            'proven' => [], 'not_proven' => self::NOT_PROVEN];
    }

    /** Arrays that are objects become Obj (an empty array stays a list); Obj and scalars pass through. */
    private static function toObj(mixed $v): mixed
    {
        if (is_int($v)) {
            return new Num((string)$v); // the strict canonical form takes JSON numbers only
        }
        if (!is_array($v)) {
            return $v;
        }
        if (array_is_list($v)) {
            return array_map(self::toObj(...), $v);
        }
        $o = new Obj();
        foreach ($v as $k => $x) {
            $o->set((string)$k, self::toObj($x));
        }
        return $o;
    }

    private static function finish(array $f, ?string $digest, array $summary): Obj
    {
        usort($f, static fn(array $x, array $y): int => Jsx::cmp($x['code'], $y['code'])
            ?: Jsx::cmp(implode(',', $x['refs']), implode(',', $y['refs']))
            ?: Jsx::cmp($x['status'], $y['status'])
            ?: Jsx::cmp($x['text'], $y['text']));
        $consistent = $f !== [] && count(array_filter($f, static fn(array $x): bool => $x['status'] === 'fail')) === 0;
        $pinned = array_values(array_filter($f, static fn(array $x): bool => $x['code'] === 'principal.pinned'));
        $attributed = count(array_filter($pinned, static fn(array $x): bool => $x['status'] === 'pass')) > 0
            && count(array_filter($pinned, static fn(array $x): bool => $x['status'] !== 'pass')) === 0;
        $ok = $consistent && $attributed;
        $complete = count(array_filter($f, static fn(array $x): bool => $x['status'] === 'unverified')) === 0;
        if ($consistent && !$attributed && $summary['attribution']['keys_to_check'] !== []) {
            array_unshift($summary['not_proven'], 'The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: '
                . implode(', ', $summary['attribution']['keys_to_check']) . '.');
        }
        $unverified = self::sorted16(array_values(array_unique(array_map(
            static fn(array $x): string => $x['code'],
            array_filter($f, static fn(array $x): bool => $x['status'] === 'unverified')
        ))));
        if ($unverified !== []) {
            $summary['not_proven'][] = 'Checked only through a supplied verifier, or not at all: ' . implode(', ', $unverified) . '.';
        }
        $findings = array_map(static fn(array $x): Obj => Obj::of(['code' => $x['code'], 'status' => $x['status'], 'text' => $x['text'], 'refs' => $x['refs']]), $f);
        $body = Obj::of(['ok' => $ok, 'consistent' => $consistent, 'attributed' => $attributed, 'complete' => $complete, 'digest' => $digest,
            'findings' => $findings, 'summary' => self::toObj($summary)]);
        $out = Obj::of([]);
        foreach ($body->keys() as $k) {
            $out->set($k, $body->get($k));
        }
        $out->set('report_digest', Pca::hashCanonical(Obj::of(['d' => Evidence::EVIDENCE_REPORT_DOMAIN, 'r' => $body])));
        return $out;
    }

    /**
     * Replay a bundle against the reader's trust inputs (`$trust`: siteKeys, principals, sessionRootDigest, minTier, jitTier, typedValues,
     * credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, verifiers; all optional; an Obj or an assoc array).
     * Returns the findings report Obj {ok, consistent, attributed, complete, digest, findings, summary, report_digest}.
     */
    public static function verifyEvidenceBundle(mixed $bundle, mixed $trust = null): Obj
    {
        if ($trust === null || $trust === []) {
            $trust = new Obj();
        } elseif (is_array($trust) && !array_is_list($trust)) {
            $trust = Obj::of($trust);
        }
        if (!($trust instanceof Obj)) {
            throw new \TypeError('trust must be an object');
        }
        $f = [];
        $summary = self::emptySummary();
        $te = $trust->has('acc') ? Evidence::accTrustError($trust->get('acc')) : Evidence::accTrustError();
        if ($te !== null) {
            self::add($f, 'trust.acc', 'fail', [], $te);
            return self::finish($f, null, $summary);
        }
        $pe = $trust->has('principals') ? Evidence::principalsTrustError($trust->get('principals')) : Evidence::principalsTrustError();
        if ($pe !== null) {
            self::add($f, 'trust.principals', 'fail', [], $pe);
            return self::finish($f, null, $summary);
        }
        $bad = Evidence::bundleShapeError($bundle);
        if ($bad !== null) {
            self::add($f, 'shape', 'fail', [], $bad);
            return self::finish($f, null, $summary);
        }
        try {
            $b = Evidence::normalizeBundle($bundle);
            $digest = Evidence::evidenceDigest($b);
        } catch (\Throwable $e) {
            self::guard($e);
            self::add($f, 'shape', 'fail', [], 'not canonicalizable: ' . $e->getMessage());
            return self::finish($f, null, $summary);
        }
        self::add($f, 'shape', 'pass');
        try {
            self::replay($b, $digest, $trust, $f, $summary);
        } catch (\Throwable $e) { // a fault inside the replay refutes the shape (fail closed)
            self::guard($e);
            self::add($f, 'shape', 'fail', [], 'replay aborted: ' . $e->getMessage());
        }
        return self::finish($f, $digest, $summary);
    }

    /** The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local accumulators and monitor states. */
    private static function accContextFor(Obj $sRoot, array $history, Obj $params, mixed $t, Obj $schema): Obj
    {
        $state = new Obj();
        foreach (self::lst($sRoot->get('accumulators')) as $a) {
            if ($a->get('holder')->get('kind') !== 'site_local') {
                continue;
            }
            if ($a->get('key') !== null && IntentHistory::accKeyOf($a, $params) === null) { // the verifier fails the claim (missing key)
                continue;
            }
            $state->set($a->get('id'), IntentHistory::accPreState($a, $history, $params, $t, $schema));
        }
        $monitors = new Obj();
        foreach (self::lst($sRoot->get('monitors') ?? []) as $m) {
            $monitors->set($m->get('id'), IntentHistory::monitorState($m, $history));
        }
        return Obj::of(['state' => $state, 'monitors' => $monitors]);
    }

    private static function replay(Obj $b, string $digest, Obj $trust, array &$f, array &$summary): void
    {
        $sRoot = $b->get('session_root');
        $session = $b->get('subject')->get('session');
        $aud = $b->get('subject')->get('aud');
        $doc = $b->get('schema')->get('doc');
        $stmt = $b->get('statement');
        // Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
        $principals = self::sorted16(array_map(static fn($p) => $p->get('key'), self::lst($sRoot->get('principals'))));
        $summary['principal_keys'] = $principals;
        $sRef = $trust->get('sessionRootDigest') !== null ? $trust->get('sessionRootDigest') : IntentV2::sessionRootDigest($sRoot);
        $ports = $trust->get('verifiers') instanceof Obj ? $trust->get('verifiers') : new Obj();
        // The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own S.principals).
        $pqPins = new Obj();
        $tp = $trust->get('principals');
        foreach ($tp === null ? [] : self::lst($tp) as $p) {
            if (is_string($p->get('pq_pk'))) {
                $pqPins->set($p->get('key'), $p->get('pq_pk'));
            }
        }
        $siteKeys = $trust->get('siteKeys');

        // -- session root ---------------------------------------------------------------------------------------------------------
        if (!self::eq($sRoot->get('session'), $session)) {
            self::add($f, 'session_root.signature', 'fail', ['session_root'], 'session root is for another session');
        } else {
            self::check($f, 'session_root.signature', $ports->get('sessionRoot'), static fn() => IntentV2::verifySessionRoot($sRoot, $pqPins), $sRoot, $b, ['session_root'], 'the session root');
        }

        // -- statement ------------------------------------------------------------------------------------------------------------
        self::add($f, 'statement.commit', self::eq($sRoot->get('intent_ref'), $stmt->get('commit')) ? 'pass' : 'fail', ['statement']);
        $opening = self::g($stmt, 'opening');
        if (Jsx::isUndef($opening)) {
            self::add($f, 'statement.opening', 'unverified', ['statement'], 'the statement was not opened (it stays a commitment)');
        } else {
            $v = IntentStatement::verifyIntent($opening);
            if (!$v['ok']) {
                self::add($f, 'statement.opening', 'fail', ['statement'], $v['reason'] ?? null);
            } elseif (IntentStatement::intentRef($opening) !== $stmt->get('commit')) {
                self::add($f, 'statement.opening', 'fail', ['statement'], 'the opening does not hash to the commitment');
            } elseif (!in_array(self::g($opening, 'principal'), $principals, true)) {
                self::add($f, 'statement.opening', 'fail', ['statement'], 'signed by a key that is not a principal of the session');
            } else {
                self::add($f, 'statement.opening', 'pass', ['statement']);
            }
        }

        // -- schema ---------------------------------------------------------------------------------------------------------------
        self::check($f, 'schema.signature', $ports->get('schema'), $siteKeys === null ? null : static fn() => IntentV2::verifyActionSchema($doc, $siteKeys), $doc, $b, ['schema'],
            'the action schema (no site keys supplied)');
        $schemaDigest = IntentV2::actionSchemaDigest($doc);
        $sch = $sRoot->get('schema');
        self::add($f, 'schema.digest', self::eq($sch->get('digest'), $schemaDigest) && self::eq($sch->get('aud'), $aud) ? 'pass' : 'fail', ['schema']);

        // -- maps -----------------------------------------------------------------------------------------------------------------
        $mapCommits = [];
        foreach ($b->get('maps') as $m) {
            if (is_string($m->get('commit'))) {
                $mapCommits[$m->get('commit')] = true;
            }
        }
        foreach ($b->get('maps') as $m) {
            $ref = ['map:' . self::n($m->get('seq'))];
            if (!self::t(self::g($m, 'map'))) {
                self::add($f, 'map.replay', 'unverified', $ref, 'committed map not revealed');
                continue;
            }
            $r = IntentMapKit::verifyIntentMap($m->get('map'));
            if (!$r['ok']) {
                self::add($f, 'map.replay', 'fail', $ref, implode('; ', array_slice($r['problems'], 0, 3)));
            } elseif (IntentMapKit::intentMapDigest($m->get('map')) !== $m->get('commit')) {
                self::add($f, 'map.replay', 'fail', $ref, 'the revealed map does not hash to its commit');
            } else {
                self::add($f, 'map.replay', 'pass', $ref);
            }
        }

        // -- grants: G_0 and the delta chain (core intent_session caveat) ---------------------------------------------------------
        $grants = []; // id => ['cap' => Obj, 'seq' => int]
        $g0 = $b->get('root_grant');
        $cv = IntentV2::grantSessionCaveat($g0);
        [$why, $ok] = Pca::verifyChain([$g0], $g0->get('issuer'), true, null, $pqPins);
        if (!$ok) {
            self::add($f, 'root_grant', 'fail', ['G_0'], $why);
        } elseif (!in_array($g0->get('issuer'), $principals, true)) {
            self::add($f, 'root_grant', 'fail', ['G_0'], 'not signed by a principal of the session');
        } elseif (!($cv instanceof Obj) || IntentV2::intentSessionCaveatError($cv) !== null) {
            self::add($f, 'root_grant', 'fail', ['G_0'], !($cv instanceof Obj) ? 'no intent_session caveat' : (IntentV2::intentSessionCaveatError($cv) ?? ''));
        } elseif (!self::eq($cv->get('session'), $session) || !self::eq($cv->get('seq'), 0) || !self::eq($cv->get('root'), $sRef)) {
            self::add($f, 'root_grant', 'fail', ['G_0'], 'intent_session caveat does not bind seq 0 of this session root');
        } else {
            self::add($f, 'root_grant', 'pass', ['G_0']);
            $grants[(string)$g0->get('id')] = ['cap' => $g0, 'seq' => 0];
        }
        $prevId = $g0->get('id');
        foreach ($b->get('deltas') as $i => $d) {
            $want = $i + 1;
            $ref = ["D_$want"];
            [$why, $ok] = Pca::verifyChain([$d], $d->get('issuer'), true, null, $pqPins);
            if (!$ok || !in_array($d->get('issuer'), $principals, true) || $d->has('parent')) {
                self::add($f, 'delta.signature', 'fail', $ref, !$ok ? $why : 'not a principal-signed root capability');
                continue;
            }
            self::add($f, 'delta.signature', 'pass', $ref);
            $cv = IntentV2::grantSessionCaveat($d);
            $nCv = 0;
            foreach (self::lst($d->get('caveats')) as $k) {
                if (self::g($k, 'type') === 'intent_session') {
                    $nCv++;
                }
            }
            $why2 = null;
            if (!($cv instanceof Obj) || $nCv !== 1) {
                $why2 = 'no single intent_session caveat';
            } elseif (IntentV2::intentSessionCaveatError($cv) !== null) {
                $why2 = IntentV2::intentSessionCaveatError($cv);
            } elseif (!self::eq($cv->get('session'), $session)) {
                $why2 = 'bound to another session';
            } elseif (!self::eq($cv->get('root'), $sRef)) {
                $why2 = 'bound to another session root';
            } elseif (!self::eq($cv->get('seq'), $want)) {
                $why2 = 'seq ' . self::n($cv->get('seq')) . " where $want was expected (gap, duplicate or reorder)";
            } elseif (!self::eq(self::g($cv, 'prev'), $prevId)) {
                $why2 = 'prev does not name the previous grant';
            }
            if ($why2 !== null) {
                self::add($f, 'delta.chain', 'fail', $ref, $why2);
            } else {
                self::add($f, 'delta.chain', 'pass', $ref);
                $grants[(string)$d->get('id')] = ['cap' => $d, 'seq' => $want];
            }
            $prevId = $d->get('id');
        }

        // -- answers --------------------------------------------------------------------------------------------------------------
        $verified = [];
        foreach ($b->get('answers') as $a) {
            $qid = self::g($a, 'question_id');
            $ref = ['answer:' . self::n($qid)];
            $v = Wallet::verifyIntentAnswer($a, $principals);
            if (!$v['ok']) {
                self::add($f, 'answer.signature', 'fail', $ref, $v['reason'] ?? null);
                continue;
            }
            if (!self::eq($a->get('session'), $session)) {
                self::add($f, 'answer.signature', 'fail', $ref, 'answer for another session');
                continue;
            }
            self::add($f, 'answer.signature', 'pass', $ref);
            $verified[] = $a;
            self::add($f, 'answer.map', self::hasKey($mapCommits, $a->get('map_digest')) ? 'pass' : 'fail', $ref);
            $ux = $a->get('ux');
            if (self::t(self::g($ux, 'canary')) || !self::eq($a->get('y'), 1)) {
                continue;
            }
            $minTier = $trust->get('minTier');
            $verb = $a->get('verb');
            $mn = $minTier instanceof Obj && is_string($verb) ? $minTier->get($verb) : null;
            if ($mn !== null) {
                self::add($f, 'answer.tier', Wallet::frictionRank($ux->get('tier')) >= Wallet::frictionRank($mn) ? 'pass' : 'fail', $ref,
                    self::n($ux->get('tier')) . ' vs minimum ' . self::n($mn));
            }
            if ($ux->get('tier') === 'typed') {
                $typedValues = $trust->get('typedValues');
                $tv = $typedValues instanceof Obj && is_string($qid) ? $typedValues->get($qid) : null;
                if ($tv === null) {
                    self::add($f, 'answer.typed', 'unverified', $ref, 'the typed value is not known to this verifier');
                } else {
                    self::add($f, 'answer.typed', Wallet::typedDigest($qid, $tv) === self::g($ux, 'typed_digest') ? 'pass' : 'fail', $ref);
                }
            }
            if ($ux->get('tier') !== 'device') {
                continue;
            }
            $wa = $ux->get('webauthn');
            $creds = $trust->get('credentials');
            $cid = self::t($wa) ? self::g($wa, 'credential_id') : null;
            $cred = self::t($wa) && $creds instanceof Obj && is_string($cid) ? $creds->get($cid) : null;
            if (!self::t($wa) || $cred === null) {
                self::add($f, 'answer.device', 'unverified', $ref, 'unknown authenticator');
            } else {
                $sc = $cred->get('signCount');
                $r = Webauthn::verifyAssertion(
                    ['authenticatorData' => Pca::unb64u($wa->get('authenticator_data')), 'clientDataJSON' => Pca::unb64u($wa->get('client_data_json')),
                        'signature' => Pca::unb64u($wa->get('signature')), 'publicKey' => $cred->get('publicKey')],
                    ['expectedChallenge' => Wallet::deviceChallenge($qid, $ux->get('rendered_digest'), $a->get('y'), $ux->get('action_digest')), 'rpId' => $cred->get('rpId'),
                        'origins' => $cred->get('origins'), 'requireUV' => true, 'storedSignCount' => $sc === null ? 0 : $sc]
                );
                self::add($f, 'answer.device', $r['ok'] ? 'pass' : 'fail', $ref, $r['ok'] ? null : ($r['reason'] ?? null));
            }
        }
        $real = array_values(array_filter($verified, fn($a): bool => !self::t(self::g($a->get('ux'), 'canary'))));
        $canaries = array_values(array_filter($verified, fn($a): bool => self::t(self::g($a->get('ux'), 'canary'))));
        $summary['answers'] = [
            'total' => count($real),
            'yes' => count(array_filter($real, fn($a): bool => self::eq($a->get('y'), 1) && !$a->has('partial'))),
            'no' => count(array_filter($real, fn($a): bool => self::eq($a->get('y'), 0))),
            'partial' => count(array_filter($real, fn($a): bool => $a->has('partial'))),
            'canaries' => count($canaries),
        ];
        $summary['refusals'] = self::sorted16(array_values(array_map(fn($a) => $a->get('question_id'), array_filter($real, fn($a): bool => self::eq($a->get('y'), 0)))));
        $yesCount = count(array_filter($real, fn($a): bool => self::eq($a->get('y'), 1)));
        $nDeltas = count($b->get('deltas'));
        self::add($f, 'delta.backed', $yesCount >= $nDeltas ? 'pass' : 'fail', [], "$nDeltas delta(s), $yesCount principal yes answer(s)");

        // -- canaries: recomputed, the claimed summary is never trusted --------------------------------------------------------------
        $labels = [];
        foreach ($b->get('canary_labels') as $c) {
            $labels[(string)$c->get('question_id')] = $c->get('label');
        }
        $falseYes = $falseNo = $missing = 0;
        $canaryLabels = $trust->get('canaryLabels') instanceof Obj ? $trust->get('canaryLabels') : new Obj();
        foreach ($canaries as $a) {
            $qid = $a->get('question_id');
            $label = is_string($qid) ? $canaryLabels->get($qid) : null;
            if ($label === null && is_string($qid)) {
                $label = $labels[$qid] ?? null;
            }
            if ($label === null) {
                $missing++;
            } elseif (self::eq($label, 0) && self::eq($a->get('y'), 1)) {
                $falseYes++;
            } elseif (self::eq($label, 1) && self::eq($a->get('y'), 0)) {
                $falseNo++;
            }
        }
        $nCan = count($canaries);
        $summary['canary_accuracy'] = ['correct' => $nCan - $missing - $falseYes - $falseNo, 'asked' => $nCan];
        $c = $b->get('canaries');
        if ($missing > 0) {
            self::add($f, 'canaries.summary', 'fail', [], "$missing canary answer(s) without a known label");
        } elseif (!self::eq($c->get('asked'), $nCan) || !self::eq($c->get('false_yes'), $falseYes) || !self::eq($c->get('false_no'), $falseNo)) {
            self::add($f, 'canaries.summary', 'fail', [], 'claimed ' . self::n($c->get('asked')) . '/' . self::n($c->get('false_yes')) . '/' . self::n($c->get('false_no'))
                . ", recomputed $nCan/$falseYes/$falseNo");
        } else {
            self::add($f, 'canaries.summary', 'pass', [], "$nCan asked, $falseYes false yes, $falseNo false no");
        }

        // -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like core keyset_versions ------------
        $accTrust = $trust->get('acc');
        $freshness = static function (array $ks) use ($accTrust): array {
            $mra = $accTrust instanceof Obj && $accTrust->get('max_receipt_age_s') !== null ? self::ni(self::num($accTrust->get('max_receipt_age_s')) * 1000) : null;
            $mka = $accTrust instanceof Obj && $accTrust->get('max_keyset_age_s') !== null ? self::ni(self::num($accTrust->get('max_keyset_age_s')) * 1000) : null;
            $tracked = $ks['tracked'];
            $min = $tracked === null ? $ks['minV'] : null;
            return [$mra, $mka, $min, $tracked];
        };

        $rootHolders = [];
        foreach (self::lst($sRoot->get('accumulators')) as $a) {
            if ($a->get('holder')->get('kind') === 'sequenced') {
                $rootHolders[(string)$a->get('holder')->get('root')] = $a->get('holder');
            }
        }
        $accepted = [];
        $verifiedSets = []; // signed under a pinned root and not a rollback (equivocating sets included): the tracked-version history
        $equivocated = [];
        $accBlock = $b->get('accumulator');
        $seqkeys = $accBlock->get('sequencer_keys');
        $sets = $seqkeys === null ? [] : self::lst($seqkeys);
        usort($sets, static function ($x, $y): int {
            foreach (['issued_at', 'version'] as $k) {
                $d = self::signOf(self::numOr0($x, $k) - self::numOr0($y, $k));
                if ($d !== 0) {
                    return $d;
                }
            }
            return Jsx::cmp(Pca::hashCanonical($x), Pca::hashCanonical($y));
        });
        $tracked = [];
        $byVersion = [];
        foreach ($sets as $i => $k) {
            $ref = "keyset#$i:" . ($k instanceof Obj ? self::n(self::g($k, 'version')) : '?');
            $holder = $k instanceof Obj && is_string($k->get('sequencer')) ? ($rootHolders[$k->get('sequencer')] ?? null) : null;
            if ($holder === null) {
                self::add($f, 'acc.keysets', 'fail', [$ref], 'not signed by a sequencer root the session root pins');
                continue;
            }
            $root = (string)$holder->get('root');
            if (!IntentV2::verifySequencerKeySet($k, $root, $holder->get('root_pq_pk'))) {
                self::add($f, 'acc.keysets', 'fail', [$ref], 'the key set does not verify under its pinned root');
                continue;
            }
            $prev = $tracked[$root] ?? null;
            $ver = self::num($k->get('version'));
            if ($prev !== null && $ver < $prev) {
                self::add($f, 'acc.keysets', 'fail', [$ref], 'version ' . self::n($k->get('version')) . ' rolls back the tracked version ' . self::n($prev));
                continue;
            }
            // Equivocation (core rule 15): two DIFFERENT sets under one root and version are both refused; an identical duplicate is not.
            $slot = $root . '#' . self::n($k->get('version'));
            $kd = IntentV2::sequencerKeySetDigest($k);
            $seen = $byVersion[$slot] ?? null;
            if ($seen !== null && $seen['digest'] !== $kd) {
                $equivocated[$slot] = true;
                $verifiedSets[] = $k;
                self::add($f, 'acc.keysets.equivocation', 'fail', [$seen['ref'], $ref], 'two different key sets under version ' . self::n($k->get('version')) . ' of one sequencer root');
                continue;
            }
            if ($seen === null) {
                $byVersion[$slot] = ['digest' => $kd, 'ref' => $ref];
            }
            $verifiedSets[] = $k;
            $tracked[$root] = max($prev ?? 0.0, $ver);
            $accepted[] = $k;
            self::add($f, 'acc.keysets', 'pass', [$ref]);
        }
        $accepted = array_values(array_filter($accepted, static fn($k): bool => !isset($equivocated[$k->get('sequencer') . '#' . self::n($k->get('version'))])));

        // In force = accepted sets of the root issued by admission (+ the core skew); the tracked state is the newest VERIFIED set issued by then.
        $keySetsAt = static function (string $root, mixed $t) use ($accepted, $verifiedSets, $equivocated): array {
            $tf = self::num($t);
            $own = array_values(array_filter($accepted, static fn($k): bool => $k->get('sequencer') === $root));
            $newest = null;
            foreach ($verifiedSets as $k) {
                if ($k->get('sequencer') === $root && self::num($k->get('issued_at')) <= $tf && ($newest === null || self::num($k->get('version')) > self::num($newest->get('version')))) {
                    $newest = $k;
                }
            }
            $poisoned = $newest !== null && isset($equivocated[$root . '#' . self::n($newest->get('version'))]);
            $floor = $newest === null ? 0.0 : self::num($newest->get('version'));
            return [
                'sets' => array_values(array_filter($own, static fn($k): bool => self::num($k->get('issued_at')) <= $tf + IntentV2::RECEIPT_SKEW_MS && self::num($k->get('version')) >= $floor)),
                'minV' => $newest === null ? null : $newest->get('version'),
                'tracked' => $newest !== null && !$poisoned ? Obj::of(['version' => $newest->get('version'), 'digest' => IntentV2::sequencerKeySetDigest($newest)]) : null,
            ];
        };

        // -- PCActns --------------------------------------------------------------------------------------------------------------
        $byDigest = [];
        $rootSeq = [];
        $effects = $b->get('effects');
        $effectOf = static function (mixed $d) use ($effects): mixed {
            foreach ($effects as $e) {
                if (self::eq(self::g($e, 'pcactn_digest'), $d)) {
                    return $e;
                }
            }
            return null;
        };
        $digestOf = static function (mixed $p): ?string {
            try {
                return Pca::hashCanonical($p);
            } catch (\Throwable) {
                return null;
            }
        };
        $grantList = array_values($grants);
        usort($grantList, static fn(array $x, array $y): int => $x['seq'] <=> $y['seq']);
        $grantsBySeq = array_map(static fn(array $g) => $g['cap'], $grantList);

        // Index of the epoch in force at t (the last one issued at or before t, in issue order), or -1.
        $epochs = $b->get('revocation_epochs');
        $epochIdxAt = static function (mixed $t) use ($epochs): int {
            $idx = -1;
            foreach ($epochs as $i => $r) {
                if (self::num($r->get('epoch')->get('issued_at')) <= self::num($t)) {
                    $idx = $i;
                }
            }
            return $idx;
        };

        // The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
        $history = [];
        foreach (self::lst($accBlock->get('events')) as $ev) {
            foreach ($history as $h) {
                if ($h->get('id') === $ev->get('pcactn_digest')) {
                    continue 2;
                }
            }
            $p = null;
            foreach ($b->get('pcactns') as $x) {
                if ($digestOf($x) === $ev->get('pcactn_digest')) {
                    $p = $x;
                    break;
                }
            }
            $eff = $effectOf($ev->get('pcactn_digest'));
            $params = $eff instanceof Obj ? $eff->get('params') : null;
            if ($p === null || !self::t($params)) {
                continue;
            }
            $status = $ev->get('status');
            $history[] = Obj::of(['id' => $ev->get('pcactn_digest'), 'verb' => $p->get('action')->get('verb'), 'resource' => $p->get('action')->get('resource'),
                'params' => $params, 't' => $p->get('iat'), 'status' => $status ?? 'committed']);
        }

        // The verifier state `decideIntentV2` reads, rebuilt from the bundle (null when the bundle lacks the plaintext params).
        $v2Context = static function (Obj $p, string $d, mixed $seq) use ($sRoot, $doc, $history, $effectOf, $accBlock, $epochs, $epochIdxAt, $rootHolders, $keySetsAt, $grantsBySeq, $pqPins, $siteKeys, $accTrust): ?Obj {
            $eff = $effectOf($d);
            $params = $eff instanceof Obj ? $eff->get('params') : null;
            if (!self::t($params) || $seq === null) {
                return null;
            }
            $idx = -1;
            foreach ($history as $hi => $h) {
                if ($h->get('id') === $d) {
                    $idx = $hi;
                    break;
                }
            }
            $before = $idx >= 0 ? array_slice($history, 0, $idx)
                : array_values(array_filter($history, static fn($h): bool => self::num($h->get('t')) <= self::num($p->get('iat'))));
            $acc = self::accContextFor($sRoot, $before, $params, $p->get('iat'), Obj::of(['verbs' => $doc->get('verbs')]));
            $ri = $epochIdxAt($p->get('iat'));
            $rev = $ri >= 0 ? $epochs[$ri] : null;
            $revLast = $ri > 0 ? $epochs[$ri - 1] : null;
            $kv = new Obj();
            $seqKeys = [];
            foreach (array_keys($rootHolders) as $root) {
                $at = $keySetsAt((string)$root, $p->get('iat'));
                if ($at['tracked'] !== null) {
                    $kv->set((string)$root, $at['tracked']);
                }
                array_push($seqKeys, ...$at['sets']);
            }
            $sessionCtx = Obj::of(['root' => $sRoot, 'grants' => array_slice($grantsBySeq, 0, (int)$seq), 'pq_pins' => $pqPins]);
            if ($rev !== null) {
                $sessionCtx->set('revocation', $rev);
            }
            if ($revLast !== null) {
                $sessionCtx->set('revocation_last', $revLast);
            }
            $acc->set('receipts', $accBlock->get('receipts') ?? []);
            $acc->set('sequencer_keys', $seqKeys);
            $acc->set('keyset_versions', $kv);
            $ctx = Obj::of(['params' => $params, 'schema' => Obj::of(['docs' => [$doc], 'keys' => $siteKeys ?? []]), 'session' => $sessionCtx, 'acc' => $acc]);
            if ($accTrust !== null) {
                $ctx->set('policy', Obj::of(['acc' => $accTrust]));
            }
            return $ctx;
        };

        foreach ($b->get('pcactns') as $p) {
            $d = $digestOf($p);
            if ($d === null) {
                self::add($f, 'pcactn.verify', 'fail', ['pcactn:?'], 'not canonicalizable');
                continue;
            }
            $byDigest[$d] = $p;
            $ref = ["pcactn:$d"];
            $chain = $p instanceof Obj ? $p->get('cap_chain') : null;
            $root = is_array($chain) && array_is_list($chain) && $chain !== [] ? $chain[0] : null;
            if (!self::t($root)) {
                self::add($f, 'pcactn.verify', 'fail', $ref, 'empty capability chain');
                continue;
            }
            $rid = $root instanceof Obj ? $root->get('id') : null;
            $g = is_string($rid) ? ($grants[$rid] ?? null) : null;
            $sameRoot = $g !== null && Pca::hashCanonical($g['cap']) === Pca::hashCanonical($root);
            $is = self::g($p, 'intent_session');
            $ctx = !Jsx::isUndef($is) && $sameRoot ? $v2Context($p, $d, $g['seq']) : null;
            // The root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals): a non-Ed25519
            // root verifies only under the reader's pins, else it is refused.
            $iat = self::g($p, 'iat');
            $r = Pca::verifyPcactnCore(Sign::n($p), Sign::n($root), Js::isNum($iat) ? (int)Js::num($iat) : 0, $aud, intentV2: $ctx, insecureSkipPlanRootCheck: true, pqPins: $pqPins, grantFromArtifact: true);
            $checks = $r['checks'];
            $reason = $r['reason'] ?? '';
            $failedNames = [];
            foreach ($checks as $nm => $st) {
                if ($st === false) {
                    $failedNames[] = self::tsCheckName((string)$nm);
                }
            }
            $failed = self::sorted16($failedNames);
            $v1f = array_values(array_filter($failed, static fn($k): bool => !in_array($k, self::V2_CHECKS, true)));
            $v2f = array_values(array_filter($failed, static fn($k): bool => in_array($k, self::V2_CHECKS, true)));
            self::add($f, 'pcactn.verify', $v1f === [] ? 'pass' : 'fail', $ref, $v1f === [] ? null : implode(', ', $v1f) . ': ' . self::n(self::tsReason($reason) ?? ''));
            if ($sameRoot) {
                self::add($f, 'pcactn.root', 'pass', $ref, $g['seq'] === 0 ? 'G_0' : 'D_' . $g['seq']);
                $rootSeq[$d] = $g['seq'];
            } else {
                self::add($f, 'pcactn.root', 'fail', $ref, 'rooted at a grant that is not G_0 or a verified delta of this session');
            }
            if (Jsx::isUndef($is)) {
                continue;
            }
            $why = null;
            if (!self::eq(self::g($is, 'session'), $session)) {
                $why = 'another session';
            } elseif (!self::eq(self::g($is, 'root'), $sRef)) {
                $why = 'another session root';
            } elseif (!self::eq(self::g($is, 'schema'), $schemaDigest)) {
                $why = 'another schema';
            } elseif ($g !== null && !self::eq(self::g($is, 'seq'), $g['seq'])) {
                $why = 'seq ' . self::n(self::g($is, 'seq')) . ' but rooted at seq ' . $g['seq'];
            } else {
                $claims = self::g($is, 'acc');
                if (Jsx::isUndef($claims) || $claims === null) {
                    $claims = [];
                }
                if (!is_array($claims) || !array_is_list($claims)) {
                    throw new \TypeError('is_.acc is not iterable');
                }
                foreach ($claims as $cl) {
                    $ev = null;
                    foreach (self::lst($accBlock->get('events')) as $e) {
                        if ($e->get('pcactn_digest') === $d && self::eq($e->get('acc'), self::g($cl, 'id'))) {
                            $ev = $e;
                            break;
                        }
                    }
                    if ($ev === null || !self::eq($ev->get('post'), self::g($cl, 'post'))) {
                        $why = 'the signed claim ' . self::n(self::g($cl, 'id')) . '.post = ' . self::n(self::g($cl, 'post')) . ' has no matching accumulator event';
                    }
                }
            }
            if ($why === null && $v2f !== []) {
                $why = 'core v2 checks failed: ' . implode(', ', $v2f);
            }
            if ($why !== null) {
                self::add($f, 'pcactn.session', 'fail', $ref, $why);
            } elseif ($ctx === null) {
                self::add($f, 'pcactn.session', 'unverified', $ref, 'the core v2 checks need the plaintext params of the effect record');
            } else {
                self::add($f, 'pcactn.session', 'pass', $ref);
            }
        }
        $subjectDigest = $b->get('subject')->get('pcactn_digest');
        $subject = $byDigest[$subjectDigest] ?? null;
        self::add($f, 'subject.present', $subject === null ? 'fail' : 'pass', ["pcactn:$subjectDigest"]);
        $sSeq = $rootSeq[$subjectDigest] ?? null;
        $summary['admitted_under'] = $sSeq === null ? null : ($sSeq === 0 ? 'G_0' : "D_$sSeq");

        // -- effects (no core format yet: signature through the port) ---------------------------------------------------------------
        foreach ($effects as $e) {
            $ref = ['effect:' . self::n($e->get('pcactn_digest'))];
            $p = $byDigest[$e->get('pcactn_digest')] ?? null;
            if ($p === null) {
                self::add($f, 'effect.binding', 'fail', $ref, 'no such PCActn in the bundle');
                continue;
            }
            if (!$e->has('params')) {
                self::add($f, 'effect.binding', 'unverified', $ref, 'no raw params to bind');
            } else {
                self::add($f, 'effect.binding', Pca::paramsDigest($e->get('params')) === $p->get('action')->get('params_digest') ? 'pass' : 'fail', $ref);
            }
            $charged = self::g($e, 'charged');
            if (self::t($charged)) {
                $cref = self::g($charged, 'ref');
                $name = is_string($cref) && str_starts_with($cref, 'action.params.') ? substr($cref, strlen('action.params.')) : null;
                $params = self::g($e, 'params');
                $bound = $name !== null && self::t($params) && $params instanceof Obj ? self::g($params, $name) : Jsx::$U;
                $amount = self::g($charged, 'amount');
                if (!self::finiteNum($bound) || !self::finiteNum($amount)) {
                    self::add($f, 'effect.charged', 'unverified', $ref, 'no numeric ' . self::n($cref) . ' to compare');
                } else {
                    self::add($f, 'effect.charged', self::num($amount) <= self::num($bound) ? 'pass' : 'fail', $ref, self::n($amount) . ' vs ' . self::n($bound));
                    if ($e->get('pcactn_digest') === $subjectDigest) {
                        $summary['charged'] = ['amount' => $amount, 'bound' => $bound];
                    }
                }
            }
            if ($e->has('frame_violations')) {
                $fv = self::lst($e->get('frame_violations'));
                self::add($f, 'effect.frame', $fv === [] ? 'pass' : 'fail', $ref, $fv === [] ? null : implode(', ', self::sorted16(array_map(self::n(...), $fv))));
            }
            self::check($f, 'effect.signature', $ports->get('effect'), null, $e, $b, $ref, 'effect records (no core format yet)');
        }

        // -- JIT consent for an irreversible subject action (core action digest) -----------------------------------------------------
        if ($subject !== null && $subject->get('action')->get('reversibility_class') === 'irreversible') {
            $ref = ["pcactn:$subjectDigest"];
            $ad = IntentJit::intentActionDigest($subject->get('action'));
            $need = $trust->get('jitTier') ?? 'typed';
            $cons = null;
            foreach ($real as $a) {
                $ux = $a->get('ux');
                if (self::eq($a->get('y'), 1) && $ux->get('consent_for_action') === true && self::g($ux, 'action_digest') === $ad
                    && Wallet::frictionRank($ux->get('tier')) >= Wallet::frictionRank($need)) {
                    $cons = $a;
                    break;
                }
            }
            if ($cons !== null) {
                self::add($f, 'jit.consent', 'pass', $ref, 'question ' . self::n($cons->get('question_id')) . ', ' . self::n($cons->get('ux')->get('tier')) . ' tier');
                $summary['consent'] = ['question_id' => $cons->get('question_id'), 'tier' => $cons->get('ux')->get('tier'), 'signer' => $cons->get('signer')];
            } else {
                self::add($f, 'jit.consent', 'fail', $ref, 'no principal yes at ' . self::n($need) . ' tier or above bound to this action digest');
            }
        }

        // -- accumulators (core declarations and value rule) -------------------------------------------------------------------------
        $decls = [];
        foreach (self::lst($sRoot->get('accumulators')) as $a) {
            $decls[(string)$a->get('id')] = $a;
        }
        $schemaVerbs = Obj::of(['verbs' => $doc->get('verbs')]);
        $valueOf = static function (Obj $decl, mixed $d) use ($byDigest, $effectOf, $schemaVerbs): ?int {
            $p = is_string($d) ? ($byDigest[$d] ?? null) : null;
            $eff = $effectOf($d);
            $params = $eff instanceof Obj ? $eff->get('params') : null;
            if ($p === null || !self::t($params)) {
                return null;
            }
            $v = IntentV2::accValueOf($decl, $p->get('action')->get('verb'), $params, $schemaVerbs);
            return $v['ok'] ? $v['val'] : null;
        };

        $running = [];
        foreach (self::lst($accBlock->get('events')) as $i => $ev) {
            $ref = ['acc:' . $ev->get('acc') . "#$i"];
            $decl = $decls[(string)$ev->get('acc')] ?? null;
            if ($decl === null) {
                self::add($f, 'accumulator.declared', 'fail', $ref);
                continue;
            }
            $p = $byDigest[$ev->get('pcactn_digest')] ?? null;
            $counted = $ev->get('status') !== 'released' && $ev->get('status') !== 'reverted';
            $prev = $running[(string)$ev->get('acc')] ?? 0.0;
            $post = self::num($ev->get('post'));
            $expected = null;
            if (!$counted) {
                $expected = $prev;
            } elseif ($decl->get('agg') === 'count') {
                $expected = $prev + 1;
            } elseif (in_array($decl->get('agg'), ['sum', 'max'], true)) {
                $val = $valueOf($decl, $ev->get('pcactn_digest'));
                if ($val !== null) {
                    $expected = $decl->get('agg') === 'sum' ? $prev + $val : max($prev, (float)$val);
                }
            }
            if ($p === null) {
                self::add($f, 'accumulator.arithmetic', 'fail', $ref, 'event names a PCActn that is not in the bundle');
            } elseif ($expected === null) {
                self::add($f, 'accumulator.arithmetic', $post >= $prev ? 'unverified' : 'fail', $ref, $post >= $prev ? 'contribution not recomputable' : 'post decreased');
            } else {
                self::add($f, 'accumulator.arithmetic', $post === (float)$expected ? 'pass' : 'fail', $ref, $post === (float)$expected ? null : 'post ' . self::n($ev->get('post')) . ', recomputed ' . self::n($expected));
            }
            $running[(string)$ev->get('acc')] = $counted ? $post : $prev;
            if (!$counted) {
                continue;
            }
            $seq = $p === null ? null : ($rootSeq[$ev->get('pcactn_digest')] ?? null);
            $delta = self::g($ev, 'delta');
            if (!Jsx::isUndef($delta) && $seq !== null && !self::eq($delta, $seq)) {
                self::add($f, 'accumulator.cap', 'fail', $ref, 'the event names a different admitting grant from the PCActn root');
                continue;
            }
            $wantSeq = $seq ?? $delta;
            $grant = null;
            foreach ($grants as $gr) {
                if (self::eq($gr['seq'], $wantSeq)) {
                    $grant = $gr;
                    break;
                }
            }
            $caps = [];
            $cc = $grant !== null && $p !== null ? Evidence::capOf($grant['cap'], $ev->get('acc'), $p->get('action')->get('verb')) : null;
            if ($cc !== null) {
                $caps[] = (float)$cc;
            }
            if (self::finiteNum($decl->get('domain_max'))) {
                $caps[] = self::num($decl->get('domain_max'));
            }
            if (self::finiteNum($decl->get('cap'))) {
                $caps[] = self::num($decl->get('cap'));
            }
            if ($caps === []) {
                self::add($f, 'accumulator.cap', 'unverified', $ref, 'no cap stated for this accumulator');
            } else {
                $cap = min($caps);
                self::add($f, 'accumulator.cap', $post <= $cap ? 'pass' : 'fail', $ref, 'post ' . self::n($ev->get('post')) . ', cap ' . self::n($cap));
            }
        }
        $receipts = $accBlock->get('receipts') ?? [];
        if ($accBlock->get('holder') === 'sequenced' && $receipts === []) {
            self::add($f, 'accumulator.receipts', 'fail', ['accumulator'], 'a sequenced accumulator without receipts');
        }
        foreach (self::lst($receipts) as $i => $r) {
            $core = static function () use ($r, $decls, $session, $aud, $byDigest, $keySetsAt, $freshness, $valueOf): ?array {
                // null = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
                $decl = $decls[(string)$r->get('acc')] ?? null;
                if ($decl === null || $decl->get('holder')->get('kind') !== 'sequenced') {
                    return ['ok' => false, 'reason' => 'the receipt names an accumulator that is not sequenced in the session root'];
                }
                $holder = $decl->get('holder');
                if (!self::eq($r->get('session'), $session) || !self::eq($r->get('aud'), $aud)) {
                    return ['ok' => false, 'reason' => 'receipt for another session or audience'];
                }
                $d = null;
                foreach ($byDigest as $dd => $pp) {
                    if (IntentV2::pcactnReservationDigest($pp) === $r->get('pcactn_digest')) {
                        $d = (string)$dd;
                        break;
                    }
                }
                if ($d === null) {
                    return ['ok' => false, 'reason' => 'the receipt reserves for a PCActn that is not in the bundle'];
                }
                // Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
                $admittedAt = $byDigest[$d]->get('iat');
                $ks = $keySetsAt((string)$holder->get('root'), $admittedAt);
                [$mra, $mka, $minV, $trk] = $freshness($ks);
                if (IntentV2::verifyReceiptAgainstHolder($r, $holder, $ks['sets'], $admittedAt, $mra, $mka, $minV, $trk) !== 'valid') {
                    return ['ok' => false, 'reason' => 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time'];
                }
                if (!(self::num($admittedAt) <= self::num($r->get('expires_at')))) {
                    return ['ok' => false, 'reason' => 'the receipt had expired when the action was admitted'];
                }
                $val = $valueOf($decl, $d);
                if ($val === null) {
                    return null;
                }
                if (!IntentV2::receiptArithmeticOk($decl, $r, $val)) {
                    return ['ok' => false, 'reason' => 'pre + delta does not give post for the reserved value'];
                }
                return ['ok' => true];
            };
            $rs = self::g($r, 'seq');
            self::check($f, 'accumulator.receipts', $ports->get('receipt'), $core, $r, $b, ['receipt:' . self::n(self::g($r, 'acc')) . '#' . self::n(Jsx::isUndef($rs) || $rs === null ? $i : $rs)],
                'the reserved contribution (the effect params were withheld)');
        }

        // -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts ------------------------------------------------------
        $oracleKeys = $trust->get('oracleKeys');
        foreach ($b->get('facts') ?? [] as $i => $x) {
            $pk = $x instanceof Obj && is_string($x->get('oracle')) && $oracleKeys instanceof Obj ? $oracleKeys->get($x->get('oracle')) : null;
            $factCore = static function () use ($x, $pk): array {
                $w = IntentWb::validateFactWire($x);
                if ($w !== null) {
                    return ['ok' => false, 'reason' => $w];
                }
                return IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $x, $pk) ? ['ok' => true] : ['ok' => false, 'reason' => 'bad oracle signature'];
            };
            self::check($f, 'fact.signature', $ports->get('fact'), $pk === null ? null : $factCore, $x, $b, ["fact:$i"], 'this fact (oracle key not pinned)');
        }
        $judges = $trust->get('judges') ?? [];
        foreach ($b->get('classifier') ?? [] as $i => $x) {
            $judge = $x instanceof Obj && is_string($x->get('judge')) ? $x->get('judge') : null;
            $clsCore = static function () use ($x, $session, $judge): array {
                $w = IntentWb::validateClassifierVerdictWire($x);
                if ($w !== null) {
                    return ['ok' => false, 'reason' => $w];
                }
                if (!self::eq($x->get('session'), $session)) {
                    return ['ok' => false, 'reason' => 'verdict for another session'];
                }
                return IntentWb::verifyArtifactSig(IntentWb::INTENT_CLASSIFIER_DOMAIN, $x, $judge) ? ['ok' => true] : ['ok' => false, 'reason' => 'bad judge signature'];
            };
            self::check($f, 'classifier.signature', $ports->get('classifier'), $judge === null || !is_array($judges) || !in_array($judge, $judges, true) ? null : $clsCore, $x, $b,
                ["classifier:$i"], 'this classifier verdict (judge not pinned)');
        }
        foreach ($b->get('offer_sets') ?? [] as $i => $x) {
            $key = null;
            foreach ($siteKeys === null ? [] : self::lst($siteKeys) as $k) {
                if ($x instanceof Obj && self::eq(self::g($k, 'kid'), self::g($x, 'kid')) && self::g($k, 'alg') === 'ed25519') {
                    $key = $k;
                    break;
                }
            }
            $offerCore = static function () use ($x, $session, $key): array {
                $w = IntentWb::validateOfferSetWire($x);
                if ($w !== null) {
                    return ['ok' => false, 'reason' => $w];
                }
                if (!self::eq($x->get('session'), $session)) {
                    return ['ok' => false, 'reason' => 'offer set for another session'];
                }
                return IntentWb::verifyArtifactSig(IntentWb::OFFER_SET_DOMAIN, $x, $key->get('pk')) ? ['ok' => true] : ['ok' => false, 'reason' => 'bad site signature'];
            };
            self::check($f, 'offer_set.signature', $ports->get('offerSet'), $key === null ? null : $offerCore, $x, $b, ["offer_set:$i"], 'this offer set (site key not pinned)');
        }
        if ($trust->get('labelKeys') !== null) {
            $labelKeys = $trust->get('labelKeys');
        } else {
            $labelKeys = [];
            foreach ($siteKeys === null ? [] : self::lst($siteKeys) as $k) {
                if ($k->get('alg') === 'ed25519') {
                    $labelKeys[] = Obj::of(['site' => $doc->get('site'), 'kid' => $k->get('kid'), 'pk' => $k->get('pk')]);
                }
            }
        }
        foreach ($b->get('labels') ?? [] as $i => $x) {
            $labelsCore = static function () use ($x, $labelKeys, $session): array {
                $e = IntentWb::verifyLabels($x, $labelKeys);
                if ($e === null && !self::eq(self::g($x, 'session'), $session)) {
                    return ['ok' => false, 'reason' => 'label receipt for another session'];
                }
                return self::nul($e);
            };
            self::check($f, 'labels.signature', $ports->get('labels'), $labelKeys === [] ? null : $labelsCore, $x, $b, ["labels:$i"], 'this label receipt (no site keys)');
        }

        // -- ported artifacts with no core format --------------------------------------------------------------------------------------
        foreach ($b->get('verdicts') as $v) {
            self::check($f, 'verdict.signature', $ports->get('verdict'), null, $v, $b, ['verdict:' . self::n(self::g($v, 'pcactn_digest'))], 'site verdicts (no core format yet)');
        }
        foreach ($b->get('settlements') ?? [] as $i => $x) {
            self::check($f, 'settlement.signature', $ports->get('settlement'), null, $x, $b, ["settlement:$i"], 'settlement records (no core format yet)');
        }

        // -- revocation (core check_session_revocation, rule 13 step 7) ------------------------------------------------------------------
        // The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation authority: every
        // epoch is checked as of its own issue time with its predecessor as the tracked `last`; the epoch in force at the action time decides.
        $rev = self::g($sRoot, 'revocation');
        if ($epochs === []) {
            self::add($f, 'revocation.epoch', 'unverified', [], 'no revocation epoch in the bundle');
        } elseif (!self::t($rev)) {
            self::add($f, 'revocation.epoch', 'fail', [], 'the session root names no revocation authority');
        } else {
            $authority = $rev->get('key');
            $maxAge = $rev->get('max_age_s');
            $maxAgeMs = self::ni(Jsx::toNum($maxAge ?? self::DEFAULT_REVOCATION_MAX_AGE_S) * 1000);
            $pin = Jsx::isUndef(self::g($rev, 'pq_pk')) ? null : $rev->get('pq_pk');
            $rcheck = static function (mixed $ev, array $ids, mixed $now, mixed $last) use ($session, $authority, $maxAgeMs, $pin): array {
                $c = ['session' => $session, 'authority' => $authority, 'ids' => $ids, 'now' => $now, 'maxAgeMs' => $maxAgeMs, 'pqPin' => $pin];
                if ($last !== null) {
                    $c['last'] = $last;
                }
                return IntentV2::checkSessionRevocation($ev, $c);
            };
            $historyOk = true;
            foreach ($epochs as $i => $ev) {
                $v = $rcheck($ev, [], $ev->get('epoch')->get('issued_at'), $i > 0 ? $epochs[$i - 1] : null);
                if (!$v['ok']) {
                    $historyOk = false;
                }
                self::verdict($f, 'revocation.history', $v, ["epoch#$i:" . self::n($ev->get('epoch')->get('epoch'))]);
            }
            if ($subject === null) {
                self::add($f, 'revocation.epoch', 'unverified', [], 'no subject action time');
            } else {
                $ids = [IntentV2::sessionRevocationId($session)];
                foreach ($b->get('maps') as $m) {
                    $ids[] = 'pca-intent:map:' . self::n($m->get('commit'));
                }
                foreach ($b->get('deltas') as $d) {
                    $ids[] = 'pca-intent:delta:' . self::n($d->get('id'));
                }
                $idx = $epochIdxAt($subject->get('iat'));
                $ev = $idx >= 0 ? $epochs[$idx] : null;
                if ($ev === null) {
                    self::add($f, 'revocation.epoch', 'fail', [], 'every epoch was issued after the action');
                } elseif (!$historyOk) {
                    self::add($f, 'revocation.epoch', 'fail', ['epoch:' . self::n($ev->get('epoch')->get('epoch'))], 'the bundled epochs are not one append-only chain');
                } else {
                    self::verdict($f, 'revocation.epoch', $rcheck($ev, $ids, $subject->get('iat'), $idx > 0 ? $epochs[$idx - 1] : null), ['epoch:' . self::n($ev->get('epoch')->get('epoch'))]);
                }
            }
        }

        // -- anchors --------------------------------------------------------------------------------------------------------------
        if (self::t(self::g($b->get('schema'), 'anchor'))) {
            self::add($f, 'schema.anchor', 'unverified', ['schema'], 'the anchor names a log position without an inclusion proof');
        }
        $anchorable = static function (mixed $kind, mixed $d) use ($digest, $stmt, $mapCommits, $schemaDigest, $verified): bool {
            return match ($kind) {
                'evidence' => $d === $digest,
                'statement' => $d === $stmt->get('commit'),
                'map' => is_string($d) && self::hasKey($mapCommits, $d),
                'schema' => $d === $schemaDigest,
                'observation' => count(array_filter($verified, static fn($a): bool => Wallet::answerRef($a) === $d)) > 0,
                default => false,
            };
        };
        $anchors = $b->get('anchors');
        if (count(array_filter($anchors, static fn($a): bool => $a->get('kind') === 'evidence')) === 0) {
            self::add($f, 'anchor.inclusion', 'unverified', ['anchor:evidence'], 'the bundle is not anchored');
        }
        foreach ($anchors as $a) {
            $ref = ['anchor:' . self::n($a->get('kind')) . ':' . self::n($a->get('index'))];
            if (!$anchorable($a->get('kind'), $a->get('digest'))) {
                self::add($f, 'anchor.inclusion', 'fail', $ref, 'the anchor names an artifact that is not this one');
                continue;
            }
            $gd = $trust->get('anchorGuardian');
            if (!self::t($gd)) {
                self::add($f, 'anchor.inclusion', 'unverified', $ref, 'no anchor-log guardian key supplied');
                continue;
            }
            $h = $a->get('signed_tree_head');
            $okk = $h->get('principal') === self::INTENT_ANCHOR_LOG && self::eq($h->get('instance_id'), $gd->get('instance')) && Ledger::verifyTreeHead($h, $gd->get('public'))
                && self::eq($a->get('proof')->get('index'), $a->get('index')) && self::eq($a->get('proof')->get('size'), $h->get('size'))
                && Ledger::verifyInclusion($h->get('root'), $a->get('proof'), Evidence::anchorCommit($a->get('kind'), $a->get('digest')));
            self::add($f, 'anchor.inclusion', $okk ? 'pass' : 'fail', $ref);
        }

        // -- attribution: the session-root keys that sign in this bundle must be pinned by the reader --------------------------------------
        // Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal consistency only.
        // The revocation authority and the sequencer roots are named inside S, so they are attributed transitively once S's signer is pinned.
        $signing = [self::g($sRoot, 'signer'), $g0->get('issuer')];
        foreach ($b->get('deltas') as $d) {
            $signing[] = $d->get('issuer');
        }
        foreach ($b->get('answers') as $a) {
            $signing[] = self::g($a, 'signer');
        }
        if (self::t($opening)) {
            $signing[] = self::g($opening, 'principal');
        }
        $keys = self::sorted16(array_values(array_unique(array_filter($signing, 'is_string'))));
        $summary['attribution']['keys_to_check'] = $keys;
        $pinsIn = $trust->get('principals');
        if ($pinsIn === null) {
            self::add($f, 'principal.pinned', 'unverified', $keys, 'no pinned principal keys: the bundle names its own principals; verify these keys out of band');
        } else {
            $pins = [];
            foreach (self::lst($pinsIn) as $p) {
                $pins[(string)$p->get('key')] = $p;
            }
            $unpinned = array_values(array_filter($keys, static fn($k): bool => !array_key_exists($k, $pins)));
            $pqMismatch = static function (string $k) use ($pins, $sRoot): bool {
                $pin = $pins[$k] ?? null;
                $sp = null;
                foreach (self::lst($sRoot->get('principals')) as $x) {
                    if ($x->get('key') === $k) {
                        $sp = $x;
                        break;
                    }
                }
                return $pin !== null && $pin->get('pq_pk') !== ($sp === null ? null : $sp->get('pq_pk'));
            };
            $mism = array_values(array_filter($keys, $pqMismatch));
            if ($unpinned !== []) {
                self::add($f, 'principal.pinned', 'fail', $unpinned, 'signing keys that are not pinned principals');
            } elseif ($mism !== []) {
                self::add($f, 'principal.pinned', 'fail', $mism, 'the session root binds a different PQ key than the pin');
            } else {
                self::add($f, 'principal.pinned', 'pass', $keys);
                $summary['attribution']['pinned'] = true;
            }
        }

        // -- plain-language facts (only what passed) ---------------------------------------------------------------------------------------
        $proven = [];
        $passed = static fn(string $code): bool => count(array_filter($f, static fn(array $x): bool => $x['code'] === $code && $x['status'] === 'pass')) > 0
            && count(array_filter($f, static fn(array $x): bool => $x['code'] === $code && $x['status'] === 'fail')) === 0;
        if ($summary['admitted_under'] !== null && $passed('pcactn.verify')) {
            $proven[] = 'The subject action was signed by the agent under ' . $summary['admitted_under'] . ', a grant signed by the session principal'
                . ($summary['attribution']['pinned'] ? ' (pinned)' : ' (NOT pinned)') . '.';
        }
        if ($summary['consent'] !== null) {
            $k = $summary['consent']['signer'];
            $who = $summary['attribution']['pinned'] ? "Pinned principal key $k" : "Session-root key $k (NOT pinned: not attributed to a known principal)";
            $proven[] = $who . ' signed a ' . $summary['consent']['tier'] . '-tier "yes" bound to this exact action (question ' . $summary['consent']['question_id'] . ').';
        }
        $ch = $summary['charged'];
        if ($ch !== null && self::num($ch['amount']) <= self::num($ch['bound'])) {
            $proven[] = 'The charged amount ' . self::n($ch['amount']) . ' is within the confirmed value ' . self::n($ch['bound']) . '.';
        }
        if ($summary['refusals'] !== []) {
            $proven[] = 'The principal refused ' . count($summary['refusals']) . ' question(s): ' . implode(', ', $summary['refusals']) . '.';
        }
        if ($summary['canary_accuracy']['asked'] > 0) {
            $proven[] = 'Canary accuracy ' . $summary['canary_accuracy']['correct'] . '/' . $summary['canary_accuracy']['asked'] . '.';
        }
        if ($passed('accumulator.cap')) {
            $proven[] = 'Every accumulator post is within the cap of the grant that admitted it.';
        }
        if ($passed('effect.frame')) {
            $proven[] = 'The site reports no change to monitored state outside the write set.';
        }
        $summary['proven'] = $proven;
    }
}
