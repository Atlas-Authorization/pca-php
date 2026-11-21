<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Explain.php';
require_once __DIR__ . '/IntentWb.php';

/** A JS `Set` with SameValueZero identity: primitives by value, objects (Obj / lists) each distinct. */
final class JsSet
{
    /** @var array<string,true> */
    private array $keys = [];
    private int $n = 0;

    public function add(mixed $v): void
    {
        if (is_bool($v)) {
            $k = 'b:' . ($v ? '1' : '0');
        } elseif (Js::isNum($v)) {
            $f = (float)Js::num($v);
            $k = 'n:' . (is_nan($f) ? 'nan' : IntentWb::jsNumStr($f));
        } elseif (is_string($v)) {
            $k = 's:' . $v;
        } elseif ($v === null || $v instanceof Undef) {
            $k = 'z:' . ($v === null ? 'null' : 'undef');
        } else {
            $k = 'o:' . (++$this->n);
        }
        $this->keys[$k] = true;
    }

    public function size(): int
    {
        return count($this->keys);
    }
}

/**
 * Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use: EU AI Act
 * Art. 12 / Art. 50, ISO/IEC 42001 clauses and SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR) (the
 * reference's pca-compliance). Pure and read-only, and total where the reference is. HONEST SCOPE: an evidence mapping, not a legal
 * certification. Inputs are the reference's JSON shapes (Obj / lists); property reads follow JavaScript semantics (a missing member
 * is `undefined`, reading through null throws), so reports match the reference text for text.
 */
final class Compliance
{
    public const COMPLIANCE_FRAMEWORKS = ['eu-ai-act', 'iso-42001', 'soc2'];
    private const FRAMEWORK_IDS = ['eu-ai-act', 'soc2', 'gdpr'];
    private const STATUS_GLYPH = ['satisfied' => '✓', 'partial' => '◐', 'not-evidenced' => '·'];

    private const MAPPINGS_JSON = <<<'JSON'
[
{
"framework":"eu-ai-act",
"controlId":"eu-ai-act:art-12",
"controlTitle":"Record-keeping — automatic, traceable logging of events",
"clause":"EU AI Act, Article 12",
"requirement":"High-risk AI systems must automatically record events (\"logs\") over their lifetime, enabling traceability of the system's functioning.",
"pcaEvidence":"Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.",
"evidenceFields":[
"evidence.pcactnDigest",
"evidence.leafSignature",
"evidence.cryptographicallyVerifiable",
"timestamps.issuedAt"
]
},
{
"framework":"eu-ai-act",
"controlId":"eu-ai-act:art-50",
"controlTitle":"Transparency — disclosure of automated decisions and the acting agent",
"clause":"EU AI Act, Article 50",
"requirement":"Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.",
"pcaEvidence":"Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.",
"evidenceFields":[
"agent.holder",
"agent.principal",
"action.summary",
"decision.outcome",
"decision.reason"
]
},
{
"framework":"iso-42001",
"controlId":"iso-42001:A.6.2.8",
"controlTitle":"Reasoning trace — AI system event logging",
"clause":"ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)",
"requirement":"The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.",
"pcaEvidence":"Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.",
"evidenceFields":[
"decision.reason",
"risk.r",
"risk.tier",
"risk.budget",
"decision.checks"
]
},
{
"framework":"iso-42001",
"controlId":"iso-42001:A.9.2",
"controlTitle":"Delegation & authorization chain",
"clause":"ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)",
"requirement":"Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.",
"pcaEvidence":"The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.",
"evidenceFields":[
"delegation.hops",
"delegation.depth",
"agent.principal",
"delegation.hops[].scope"
]
},
{
"framework":"iso-42001",
"controlId":"iso-42001:A.9.3",
"controlTitle":"Human oversight of AI systems",
"clause":"ISO/IEC 42001 Annex A.9.3 (human oversight)",
"requirement":"Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.",
"pcaEvidence":"Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text \"approved by\"); denials and step-up requirements show the oversight boundary being enforced.",
"evidenceFields":[
"humanOverride.humanApproved",
"humanOverride.approvers",
"decision.outcome",
"risk.tier"
]
},
{
"framework":"iso-42001",
"controlId":"iso-42001:A.6.2.2",
"controlTitle":"Intended use — action bound to a committed plan",
"clause":"ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)",
"requirement":"The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.",
"pcaEvidence":"Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.",
"evidenceFields":[
"evidence.planRoot",
"action.verb",
"action.resource",
"decision.checks"
]
},
{
"framework":"soc2",
"controlId":"soc2:CC6.1",
"controlTitle":"Logical access security — least privilege",
"clause":"SOC 2 CC6.1",
"requirement":"The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.",
"pcaEvidence":"Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.",
"evidenceFields":[
"decision.outcome",
"delegation.hops[].scope",
"decision.checks",
"evidence.cryptographicallyVerifiable"
]
},
{
"framework":"soc2",
"controlId":"soc2:CC6.2",
"controlTitle":"Registration & authorization of credentials / identities",
"clause":"SOC 2 CC6.2",
"requirement":"Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.",
"pcaEvidence":"Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.",
"evidenceFields":[
"agent.principal",
"agent.holder",
"delegation.hops",
"evidence.grantRef"
]
},
{
"framework":"soc2",
"controlId":"soc2:CC6.3",
"controlTitle":"Access modification & removal (attenuation / revocation)",
"clause":"SOC 2 CC6.3",
"requirement":"The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.",
"pcaEvidence":"Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.",
"evidenceFields":[
"delegation.hops[].scope",
"delegation.hops[].budgetAlloc",
"decision.outcome"
]
}
]

JSON;

    private static ?array $mappings = null;

    /** @return list<Obj> */
    public static function controlMappingTable(): array
    {
        return self::$mappings ??= (new Parser(self::MAPPINGS_JSON, PHP_INT_MAX))->run();
    }

    // ---- JavaScript semantics ---------------------------------------------------------------------------------------------

    private static function u(): Undef
    {
        return Jsx::$U;
    }

    private static function isU(mixed $v): bool
    {
        return $v instanceof Undef;
    }

    private static function own(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : Jsx::$U;
    }

    /** `o.k`: throws when `o` is null / undefined, like the reference. */
    private static function prop(mixed $o, string $k): mixed
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError(sprintf("Cannot read properties of %s (reading '%s')", $o === null ? 'null' : 'undefined', $k));
        }
        return self::own($o, $k);
    }

    private static function qprop(mixed $o, string $k): mixed
    {
        return $o === null || $o instanceof Undef ? Jsx::$U : self::own($o, $k);
    }

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v instanceof Undef;
    }

    private static function finite(mixed $v): bool
    {
        $f = Js::isNum($v) ? Js::num($v) : null;
        return $f !== null && is_finite($f);
    }

    private static function truthy(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    private static function num(mixed $v): float
    {
        return Jsx::toNum($v);
    }

    private static function gt(mixed $a, mixed $b): bool
    {
        return Jsx::gt($a, $b);
    }

    private static function jsn(mixed $v): string
    {
        return IntentWb::jsNumStr((float)Js::num($v));
    }

    private static function jsRound(float $v): int
    {
        $r = floor($v);
        return (int)($v - $r >= 0.5 ? $r + 1 : $r);
    }

    private static function isIntegerNum(mixed $v): bool
    {
        $f = Js::isNum($v) ? Js::num($v) : null;
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    private static function len16(string $s): int
    {
        return Js::len($s);
    }

    /** `v.length` (string: UTF-16 units; array: items); throws on null / undefined; undefined for any other value. */
    private static function length(mixed $v): mixed
    {
        if ($v === null || $v instanceof Undef) {
            throw new \TypeError(sprintf("Cannot read properties of %s (reading 'length')", $v === null ? 'null' : 'undefined'));
        }
        if (is_string($v)) {
            return self::len16($v);
        }
        return is_array($v) && array_is_list($v) ? count($v) : Jsx::$U;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function stringify(mixed $v): string
    {
        return Js::stringify($v);
    }

    private static function pretty(mixed $v, string $base = ''): string
    {
        if (self::isList($v)) {
            if ($v === []) {
                return '[]';
            }
            $ind = $base . '  ';
            return "[\n" . implode(",\n", array_map(static fn($x) => $ind . ($x instanceof Undef ? 'null' : self::pretty($x, $ind)), $v)) . "\n" . $base . ']';
        }
        if ($v instanceof Obj) {
            $keys = array_values(array_filter(Js::ownKeys($v->keys()), static fn($k) => !($v->get($k) instanceof Undef)));
            if ($keys === []) {
                return '{}';
            }
            $ind = $base . '  ';
            return "{\n" . implode(",\n", array_map(static fn($k) => $ind . Js::stringify($k) . ': ' . self::pretty($v->get($k), $ind), $keys)) . "\n" . $base . '}';
        }
        return self::stringify($v);
    }

    /** (year, month, day) of a day count since 1970-01-01 (proleptic Gregorian). @return array{0:int,1:int,2:int} */
    private static function civil(int $days): array
    {
        $z = $days + 719468;
        $era = intdiv($z - ($z < 0 ? 146096 : 0), 146097);
        $doe = $z - $era * 146097;
        $yoe = intdiv($doe - intdiv($doe, 1460) + intdiv($doe, 36524) - intdiv($doe, 146096), 365);
        $y = $yoe + $era * 400;
        $doy = $doe - (365 * $yoe + intdiv($yoe, 4) - intdiv($yoe, 100));
        $mp = intdiv(5 * $doy + 2, 153);
        $d = $doy - intdiv(153 * $mp + 2, 5) + 1;
        $m = $mp < 10 ? $mp + 3 : $mp - 9;
        return [$m <= 2 ? $y + 1 : $y, $m, $d];
    }

    /** `new Date(ms).toISOString()`; throws for an invalid / unrepresentable time (RangeError there). */
    private static function isoString(mixed $ms): string
    {
        $f = Js::isNum($ms) ? Js::num($ms) : null;
        if ($f === null || !is_finite($f) || abs($f) > 8.64e15) {
            throw new \RangeException('Invalid time value');
        }
        $t = (int)$f;
        $M = 86400000;
        $rem = (($t % $M) + $M) % $M;
        $days = intdiv($t - $rem, $M);
        [$y, $mo, $d] = self::civil($days);
        $ys = $y >= 0 && $y <= 9999 ? sprintf('%04d', $y) : ($y > 0 ? '+' : '-') . sprintf('%06d', abs($y));
        return sprintf('%s-%02d-%02dT%02d:%02d:%02d.%03dZ', $ys, $mo, $d, intdiv($rem, 3600000), intdiv($rem, 60000) % 60, intdiv($rem, 1000) % 60, $rem % 1000);
    }

    private static function iso(mixed $ms): string
    {
        if (!self::finite($ms)) {
            return '(unknown time)';
        }
        try {
            return self::isoString($ms);
        } catch (\RangeException) {
            return '(unrepresentable time)';
        }
    }

    private static function ts(mixed $ms): Obj
    {
        return Obj::of(['epochMs' => $ms, 'iso' => self::iso($ms)]);
    }

    private static function nowMs(): int
    {
        return (int)(microtime(true) * 1000);
    }

    /** Abbreviate a long key for display (UTF-16 units, like the reference). */
    private static function short(mixed $key, int $n = 12): string
    {
        if (!is_string($key) || $key === '') {
            return '(none)';
        }
        return self::len16($key) <= $n + 1 ? $key : Explain::slice16($key, 0, $n) . '…';
    }

    private static function numFmt(mixed $x): string
    {
        if (!self::finite($x)) {
            return Jsx::str($x);
        }
        if (self::isIntegerNum($x)) {
            return self::jsn($x);
        }
        return IntentWb::jsNumStr(self::jsRound((float)Js::num($x) * 1e4) / 1e4);
    }

    private static function tpl(mixed $v): string
    {
        return Jsx::str($v);
    }

    private static function put(Obj $o, string $k, mixed $v): void
    {
        if (!($v instanceof Undef)) {
            $o->set($k, $v);
        }
    }

    // ---- AuditEvent -------------------------------------------------------------------------------------------------------

    private static function isBudgetAlloc(mixed $cv): bool
    {
        if (!($cv instanceof Obj) || $cv->get('type') !== 'budget_alloc' || !self::finite($cv->get('limit'))) {
            return false;
        }
        return Js::num($cv->get('limit')) >= 0;
    }

    /** A bounded, human-readable rendering of one caveat. */
    public static function describeCaveat(mixed $cv): string
    {
        if (!($cv instanceof Obj) || !is_string($cv->get('type'))) {
            return '(malformed caveat)';
        }
        $t = $cv->get('type');
        if ($t === 'envelope') {
            $preds = $cv->get('predicates');
            $inner = $cv->get('caveats');
            return sprintf('policy envelope (%d predicate(s), %d caveat(s))', self::isList($preds) ? count($preds) : 0, self::isList($inner) ? count($inner) : 0);
        }
        if (self::isBudgetAlloc($cv)) {
            return 'budget allocation ≤ ' . self::numFmt($cv->get('limit'));
        }
        $parts = [];
        foreach (array_slice(Js::ownKeys($cv->keys()), 0, 8) as $k) {
            if ($k === 'type') {
                continue;
            }
            $v = $cv->get($k);
            $parts[] = $k . '=' . (($v instanceof Obj || self::isList($v)) ? self::stringify($v) : self::numFmt($v));
        }
        return $parts !== [] ? sprintf('%s(%s)', $t, implode(', ', $parts)) : $t;
    }

    /** The delegation hops: issuer -> holder and the caveats each hop ADDED (append-only diff against its parent). @return list<Obj> */
    public static function buildDelegationHops(mixed $chain): array
    {
        $safe = self::isList($chain) ? $chain : [];
        $hops = [];
        foreach ($safe as $i => $cap) {
            if (!self::truthy($cap)) {
                continue;
            }
            $isRoot = $i === 0;
            $parent = $i > 0 ? $safe[$i - 1] : null;
            $pcv = self::truthy($parent) ? self::own($parent, 'caveats') : Jsx::$U;
            $parentLen = self::isList($pcv) ? count($pcv) : 0;
            $ownCv = self::own($cap, 'caveats');
            $own = self::isList($ownCv) ? $ownCv : [];
            $added = $isRoot ? $own : (count($own) >= $parentLen ? array_slice($own, $parentLen) : []);
            $scope = array_map(fn($c) => self::describeCaveat($c), $added);
            $budgetCv = null;
            foreach ($added as $c) {
                if (self::isBudgetAlloc($c)) {
                    $budgetCv = $c;
                    break;
                }
            }
            $issuer = self::own($cap, 'issuer');
            $holder = self::own($cap, 'holder');
            $joined = implode('; ', $scope);
            if ($isRoot) {
                $narrative = sprintf('Principal %s granted authority to %s%s.', self::short($issuer), self::short($holder), $scope !== [] ? ' under: ' . $joined : '');
            } else {
                $narrative = sprintf('%s delegated to %s%s.', self::short($issuer), self::short($holder), $scope !== [] ? ', narrowing scope: ' . $joined : ' (rebind only, no new constraints)');
            }
            $hop = Obj::of(['index' => $i, 'isRoot' => $isRoot, 'scope' => $scope, 'caveats' => array_values($added), 'narrative' => $narrative]);
            self::put($hop, 'issuer', $issuer);
            self::put($hop, 'holder', $holder);
            if ($budgetCv !== null) {
                $hop->set('budgetAlloc', $budgetCv->get('limit'));
            }
            $hops[] = $hop;
        }
        return $hops;
    }

    /** The signed co-signature (human override) of a PCActn's threshold signature, if any. */
    public static function buildHumanOverride(mixed $threshold, mixed $requiredTier, mixed $thresholdCheck): ?Obj
    {
        $sh = self::truthy($threshold) ? self::own($threshold, 'shares') : Jsx::$U;
        $shares = self::isList($sh) ? $sh : [];
        if (count($shares) === 0) {
            return null;
        }
        // `threshold` is outside the signed body: never report a signed approval (or name approvers) from unverified shares.
        if ($thresholdCheck !== 'pass') {
            return Obj::of(['humanApproved' => false, 'approvers' => [], 'guardianCosigners' => [], 'roles' => [], 'requiredTier' => $requiredTier,
                'narrative' => sprintf('%d co-signature share(s) were presented but NOT verified (threshold check: %s); no human approval is recorded.', count($shares), self::nullish($thresholdCheck) ? 'absent' : self::tpl($thresholdCheck))]);
        }
        $approvers = [];
        $guardians = [];
        $roles = [];
        foreach ($shares as $s) {
            if (!self::truthy($s) || !is_string(self::own($s, 'role'))) {
                continue;
            }
            $role = $s->get('role');
            $roles[] = $role;
            $pk = $s->get('publicKey');
            if ($role === 'principal' && is_string($pk)) {
                $approvers[] = $pk;
            }
            if ($role === 'guardian' && is_string($pk)) {
                $guardians[] = $pk;
            }
        }
        $approved = count($approvers) > 0;
        if ($approved) {
            $narrative = sprintf('Step-up approved by a signed human co-signature from principal %s%s at tier t=%s.', self::short($approvers[0]), $guardians !== [] ? sprintf(' (plus %d guardian co-sign)', count($guardians)) : '', self::tpl($requiredTier));
        } else {
            $narrative = sprintf('Co-signed by %d guardian share(s) at tier t=%s (no human principal signature present).', count($guardians), self::tpl($requiredTier));
        }
        return Obj::of(['humanApproved' => $approved, 'approvers' => $approvers, 'guardianCosigners' => $guardians, 'roles' => $roles, 'requiredTier' => $requiredTier, 'narrative' => $narrative]);
    }

    private static function firstReasonOr(mixed $decision, string $fallback): mixed
    {
        $rs = self::own($decision, 'reasons');
        $rs = self::isList($rs) ? $rs : [];
        return count($rs) > 0 && is_string($rs[0]) ? $rs[0] : $fallback;
    }

    /** The auditor-facing outcome from the proof's verification and the Policy-VM decision. */
    public static function resolveOutcome(mixed $verify, mixed $decision): Obj
    {
        if (!self::truthy($verify) || self::own($verify, 'allow') !== true) {
            $r = self::qprop($verify, 'reason');
            return Obj::of(['outcome' => 'deny', 'reason' => self::nullish($r) ? 'proof failed verification' : $r]);
        }
        if (!self::truthy($decision)) {
            return Obj::of(['outcome' => 'allow', 'reason' => 'proof verified; no policy decision supplied']);
        }
        if (self::truthy(self::own($decision, 'admit'))) {
            return Obj::of(['outcome' => 'allow', 'reason' => self::firstReasonOr($decision, 'auto-admitted within policy and budget')]);
        }
        if (self::truthy(self::own($decision, 'releaseGuardianShare'))) {
            return Obj::of(['outcome' => 'step-up', 'reason' => self::firstReasonOr($decision, 'policy satisfied but a co-signature is required')]);
        }
        return Obj::of(['outcome' => 'deny', 'reason' => self::firstReasonOr($decision, 'policy did not release authority (default-deny)')]);
    }

    private static function safeDigest(mixed $p): string
    {
        if ($p instanceof Undef) {
            return '(undigestible)';
        }
        try {
            return Pca::hashCanonical($p);
        } catch (\Throwable) {
            return '(undigestible)';
        }
    }

    /** A normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision: `{pcactn, verify, decision?, now?, session?}`. */
    public static function toAuditEvent(mixed $inp): Obj
    {
        $p = self::prop($inp, 'pcactn');
        $verify = self::own($inp, 'verify');
        if (self::nullish($verify)) {
            $verify = Obj::of(['allow' => false, 'checks' => new Obj()]);
        }
        $decision = self::own($inp, 'decision');
        $now = self::own($inp, 'now');
        if (self::nullish($now)) {
            $now = self::nowMs();
        }
        $cc = self::qprop($p, 'cap_chain');
        $chain = self::isList($cc) ? $cc : null;
        $hops = self::buildDelegationHops($chain);
        $leaf = $chain !== null && count($chain) > 0 ? $chain[count($chain) - 1] : Jsx::$U;
        $root = $chain !== null && count($chain) > 0 ? $chain[0] : Jsx::$U;
        $res = self::resolveOutcome($verify, $decision);
        $outcome = $res->get('outcome');
        $reason = $res->get('reason');
        $tier = self::qprop(self::qprop($decision, 'requiredThreshold'), 't');
        $requiredTier = self::nullish($tier) ? 1 : $tier;
        $checksRaw = self::own($verify, 'checks');
        $human = self::buildHumanOverride(self::qprop($p, 'threshold'), $requiredTier, self::qprop($checksRaw, 'threshold'));
        $checks = self::nullish($checksRaw) ? new Obj() : $checksRaw;
        $cryptoOk = self::own($checks, 'wire') === 'pass' && self::own($checks, 'leaf_signature') === 'pass';

        $action = self::qprop($p, 'action');
        $verbV = self::qprop($action, 'verb');
        $resV = self::qprop($action, 'resource');
        $verb = is_string($verbV) ? $verbV : '(unknown verb)';
        $resource = is_string($resV) ? $resV : '(unknown resource)';
        $gr = self::qprop($p, 'grant_ref');
        $grantRef = is_string($gr) ? $gr : '(none)';
        $sig = self::qprop($p, 'sig');
        $alg = self::qprop($p, 'alg');
        $planRoot = self::qprop(self::qprop($p, 'plan'), 'root');
        $pd = self::qprop($action, 'params_digest');
        $counter = self::qprop($p, 'counter');
        $nonce = self::qprop($p, 'nonce');
        $evidence = Obj::of([
            'pcactnDigest' => self::safeDigest($p),
            'leafSignature' => is_string($sig) ? $sig : '(unsigned)',
            'signatureSuite' => is_string($alg) ? $alg : 'ed25519',
            'planRoot' => is_string($planRoot) ? $planRoot : '(none)',
            'paramsDigest' => is_string($pd) ? $pd : '(none)',
            'grantRef' => $grantRef,
            'counter' => Js::isNum($counter) ? $counter : -1,
            'cryptographicallyVerifiable' => $cryptoOk,
        ]);
        if (is_string($nonce)) {
            $evidence->set('nonce', $nonce);
        }
        $risk = new Obj();
        if (self::truthy($decision)) {
            $rt = self::own($decision, 'requiredThreshold');
            foreach ([['r', self::own($decision, 'r')], ['tier', self::qprop($rt, 't')], ['proof', self::qprop($rt, 'proof')], ['budget', self::own($decision, 'budget')]] as [$key, $val]) {
                self::put($risk, $key, $val);
            }
        }
        $word = $outcome === 'allow' ? 'ALLOWED' : ($outcome === 'deny' ? 'DENIED' : 'STEP-UP');
        $narrative = sprintf('Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s',
            self::short(self::qprop($leaf, 'holder')), $word, $verb, $resource, count($hops), self::short(self::qprop($root, 'issuer')),
            $cryptoOk ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable',
            $human !== null && $human->get('humanApproved') ? '; human-signed step-up' : '', self::tpl($reason));

        $holder = self::qprop($leaf, 'holder');
        $principal = self::qprop($root, 'issuer');
        $sess = self::own($inp, 'session');
        $rc = self::qprop($action, 'reversibility_class');
        $iat = self::qprop($p, 'iat');
        $exp = self::qprop($p, 'exp');
        $agent = Obj::of(['holder' => is_string($holder) ? $holder : '(none)', 'session' => self::nullish($sess) ? $grantRef : $sess]);
        if (is_string($principal)) {
            $agent->set('principal', $principal);
        }
        $event = Obj::of([
            'schema' => 'atlas-pca/audit-event/v1',
            'recordedAt' => self::ts($now),
            'agent' => $agent,
            'delegation' => Obj::of(['depth' => max(0, count($hops) - 1), 'hops' => $hops]),
            'action' => Obj::of(['verb' => $verb, 'resource' => $resource, 'paramsDigest' => $evidence->get('paramsDigest'),
                'reversibilityClass' => is_string($rc) ? $rc : '(unknown)', 'summary' => sprintf('%s on %s', $verb, $resource)]),
            'decision' => Obj::of(['outcome' => $outcome, 'reason' => $reason, 'proofVerified' => self::own($verify, 'allow') === true, 'checks' => $checks]),
            'risk' => $risk,
            'timestamps' => Obj::of(['issuedAt' => self::ts(Js::isNum($iat) ? $iat : NAN), 'expiresAt' => self::ts(Js::isNum($exp) ? $exp : NAN)]),
            'evidence' => $evidence,
            'narrative' => $narrative,
        ]);
        if ($human !== null) {
            $event->set('humanOverride', $human);
        }
        return $event;
    }

    // ---- control mappings -------------------------------------------------------------------------------------------------

    private static function assertFramework(mixed $framework): void
    {
        if (!(is_string($framework) && in_array($framework, self::COMPLIANCE_FRAMEWORKS, true))) {
            throw new \InvalidArgumentException(sprintf("pca-compliance: unknown framework '%s' (have: %s)", self::tpl($framework), implode(', ', self::COMPLIANCE_FRAMEWORKS)));
        }
    }

    /** The control mappings for a framework (the whole table when none is given). @return list<Obj> */
    public static function controlMappings(mixed ...$a): array
    {
        if (!array_key_exists(0, $a)) {
            return self::controlMappingTable();
        }
        self::assertFramework($a[0]);
        return array_values(array_filter(self::controlMappingTable(), static fn(Obj $m) => $m->get('framework') === $a[0]));
    }

    // ---- ComplianceReport -------------------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private static function computeStats(array $events): array
    {
        $agents = new JsSet();
        $principals = new JsSet();
        $sample = Jsx::$U;
        $verifiable = $denied = $stepUp = $allowed = $human = $withChain = $withPlan = 0;
        $maxDepth = 0;
        foreach ($events as $e) {
            if (!self::truthy($e)) {
                continue;
            }
            if (self::truthy(self::prop(self::prop($e, 'evidence'), 'cryptographicallyVerifiable'))) {
                $verifiable++;
            }
            $outcome = self::prop(self::prop($e, 'decision'), 'outcome');
            if ($outcome === 'deny') {
                $denied++;
            } elseif ($outcome === 'step-up') {
                $stepUp++;
            } else {
                $allowed++;
            }
            if (self::truthy(self::qprop(self::own($e, 'humanOverride'), 'humanApproved'))) {
                $human++;
            }
            $hopsLen = self::length(self::prop(self::prop($e, 'delegation'), 'hops'));
            if (!self::isU($hopsLen) && $hopsLen > 0) {
                $withChain++;
            }
            if (self::prop(self::prop($e, 'evidence'), 'planRoot') !== '(none)') {
                $withPlan++;
            }
            $depth = self::prop(self::prop($e, 'delegation'), 'depth');
            if (self::gt($depth, $maxDepth)) {
                $maxDepth = $depth;
            }
            $agents->add(self::prop(self::prop($e, 'agent'), 'holder'));
            $principal = self::prop(self::prop($e, 'agent'), 'principal');
            if (!self::isU($principal)) {
                $principals->add($principal);
            }
            $digest = self::prop(self::prop($e, 'evidence'), 'pcactnDigest');
            if (self::isU($sample) && $digest !== '(undigestible)') {
                $sample = $digest;
            }
        }
        return ['total' => count($events), 'verifiable' => $verifiable, 'denied' => $denied, 'stepUp' => $stepUp, 'allowed' => $allowed, 'humanOverrides' => $human,
            'withChain' => $withChain, 'withPlanRoot' => $withPlan, 'maxDepth' => $maxDepth, 'agents' => $agents->size(), 'principals' => $principals->size(), 'sampleDigest' => $sample];
    }

    /** @param array<string,mixed> $s @return array{status:string,evidence:string,findings:list<string>} */
    private static function evaluateControl(string $id, array $s): array
    {
        $findings = [];
        $total = $s['total'];
        $digestNote = self::isU($s['sampleDigest']) ? '' : sprintf(' (e.g. %s)', self::short($s['sampleDigest'], 16));
        if ($total === 0) {
            return ['status' => 'not-evidenced', 'evidence' => 'no actions in the reporting period', 'findings' => ['no events supplied — nothing to evidence']];
        }
        switch ($id) {
            case 'eu-ai-act:art-12':
                $status = $s['verifiable'] === $total ? 'satisfied' : 'partial';
                if ($s['verifiable'] < $total) {
                    $findings[] = sprintf('%d of %d entries are not cryptographically verifiable', $total - $s['verifiable'], $total);
                }
                return ['status' => $status, 'evidence' => sprintf('%d actions logged; %d/%d cite a cryptographically verifiable proof%s', $total, $s['verifiable'], $total, $digestNote), 'findings' => $findings];
            case 'eu-ai-act:art-50':
                return ['status' => 'satisfied', 'evidence' => sprintf('%d actions each disclose the acting agent, the principal (%d distinct) and the automated decision outcome', $total, $s['principals']), 'findings' => $findings];
            case 'iso-42001:A.6.2.8':
                return ['status' => 'satisfied', 'evidence' => sprintf('%d actions each carry a decision reason + risk/tier/budget reasoning trace', $total), 'findings' => $findings];
            case 'iso-42001:A.9.2':
                $wc = $s['withChain'];
                $status = $wc === $total ? 'satisfied' : ($wc > 0 ? 'partial' : 'not-evidenced');
                if ($wc < $total) {
                    $findings[] = sprintf('%d entries have no delegation chain', $total - $wc);
                }
                return ['status' => $status, 'evidence' => sprintf('%d/%d actions carry an explicit delegation chain (max depth %s, %d authorizing principal(s))', $wc, $total, self::tpl($s['maxDepth']), $s['principals']), 'findings' => $findings];
            case 'iso-42001:A.9.3':
                if ($s['humanOverrides'] > 0) {
                    $status = 'satisfied';
                    $evidence = sprintf('%d step-up(s) approved by a signed human co-signature; %d step-up(s) and %d denial(s) show oversight enforced', $s['humanOverrides'], $s['stepUp'], $s['denied']);
                } elseif ($s['stepUp'] > 0 || $s['denied'] > 0) {
                    $status = 'partial';
                    $evidence = sprintf('oversight boundary enforced (%d step-up(s), %d denial(s)) but no signed human co-signature observed in the period', $s['stepUp'], $s['denied']);
                    $findings[] = 'no human step-up co-signature was exercised in this period';
                } else {
                    $status = 'partial';
                    $evidence = 'all actions were auto-admitted within policy; no oversight event was triggered in the period';
                    $findings[] = 'no higher-impact action required human oversight in this period';
                }
                return ['status' => $status, 'evidence' => $evidence, 'findings' => $findings];
            case 'iso-42001:A.6.2.2':
                $wp = $s['withPlanRoot'];
                $status = $wp === $total ? 'satisfied' : ($wp > 0 ? 'partial' : 'not-evidenced');
                if ($wp < $total) {
                    $findings[] = sprintf('%d entries are not bound to a committed plan root', $total - $wp);
                }
                return ['status' => $status, 'evidence' => sprintf('%d/%d actions are bound to a committed plan root (intended-use binding)', $wp, $total), 'findings' => $findings];
            case 'soc2:CC6.1':
                if ($s['denied'] > 0) {
                    $findings[] = sprintf('%d out-of-scope action(s) denied — access control actively enforced', $s['denied']);
                }
                return ['status' => 'satisfied', 'evidence' => sprintf('deny-by-default access over %d actions (%d allowed, %d step-up, %d denied); all gated by signed predicates + attenuation', $total, $s['allowed'], $s['stepUp'], $s['denied']), 'findings' => $findings];
            case 'soc2:CC6.2':
                $wc = $s['withChain'];
                $status = $wc === $total ? 'satisfied' : ($wc > 0 ? 'partial' : 'not-evidenced');
                if ($wc < $total) {
                    $findings[] = sprintf('%d entries are not traceable to an authorizing principal', $total - $wc);
                }
                return ['status' => $status, 'evidence' => sprintf('%d agent identit(ies) traceable to %d authorizing principal(s) via signed delegation chains', $s['agents'], $s['principals']), 'findings' => $findings];
            case 'soc2:CC6.3':
                $narrowed = self::num($s['maxDepth']) >= 1;
                $status = $narrowed || $s['denied'] > 0 ? 'satisfied' : 'partial';
                if (!$narrowed && $s['denied'] === 0) {
                    $findings[] = 'no attenuating hop or denial observed in the period';
                }
                return ['status' => $status, 'evidence' => sprintf('access narrowed by attenuation (max delegation depth %s) and %d denied action(s)', self::tpl($s['maxDepth']), $s['denied']), 'findings' => $findings];
        }
        return ['status' => 'not-evidenced', 'evidence' => 'no evaluator for this control', 'findings' => ['unmapped control']];
    }

    /** A structured ComplianceReport for `opts.framework` from AuditEvents. `opts.now` (epoch ms) defaults to the clock. */
    public static function toComplianceReport(mixed $events, mixed $opts): Obj
    {
        $framework = self::prop($opts, 'framework');
        self::assertFramework($framework);
        $lst = self::isList($events) ? array_values(array_filter($events, static fn($e) => self::truthy($e))) : [];
        $now = self::own($opts, 'now');
        if (self::nullish($now)) {
            $now = self::nowMs();
        }
        $s = self::computeStats($lst);
        $items = [];
        foreach (self::controlMappingTable() as $m) {
            if ($m->get('framework') !== $framework) {
                continue;
            }
            $r = self::evaluateControl($m->get('controlId'), $s);
            $items[] = Obj::of(['controlId' => $m->get('controlId'), 'controlTitle' => $m->get('controlTitle'), 'clause' => $m->get('clause'), 'framework' => $m->get('framework'),
                'status' => $r['status'], 'pcaEvidence' => $m->get('pcaEvidence'), 'evidence' => $r['evidence'], 'findings' => $r['findings']]);
        }
        $count = static fn(string $st): int => count(array_filter($items, static fn(Obj $i) => $i->get('status') === $st));
        $satisfied = $count('satisfied');
        $partial = $count('partial');
        $notEvidenced = $count('not-evidenced');
        $total = count($items);
        $fraction = $total > 0 ? $satisfied / $total : 0;
        $iats = [];
        foreach ($lst as $e) {
            $x = self::prop(self::prop(self::prop($e, 'timestamps'), 'issuedAt'), 'epochMs');
            if (self::finite($x)) {
                $iats[] = $x;
            }
        }
        $frm = 0;
        $to = 0;
        if ($iats !== []) {
            $frm = $to = $iats[0];
            foreach ($iats as $x) {
                if (Js::num($x) < Js::num($frm)) {
                    $frm = $x;
                }
                if (Js::num($x) > Js::num($to)) {
                    $to = $x;
                }
            }
        }
        $st = $s['total'];
        $assurances = Obj::of([
            'cryptographicallyVerifiable' => $st > 0 && $s['verifiable'] === $st,
            'explicitDelegationChain' => $st > 0 && $s['withChain'] === $st,
            'signedHumanOverrides' => $s['humanOverrides'] > 0,
            'narrative' => $st === 0 ? 'No events in scope.'
                : sprintf('%d/%d entries cite a cryptographically verifiable proof; %d/%d carry an explicit delegation chain; %d step-up(s) carry a signed human co-signature.', $s['verifiable'], $st, $s['withChain'], $st, $s['humanOverrides']),
        ]);
        $summary = sprintf('%s: %d/%d controls satisfied%s%s over %d action(s).', $framework, $satisfied, $total, $partial > 0 ? sprintf(', %d partial', $partial) : '', $notEvidenced > 0 ? sprintf(', %d not evidenced', $notEvidenced) : '', $st);
        return Obj::of([
            'schema' => 'atlas-pca/compliance-report/v1',
            'framework' => $framework,
            'generatedAt' => self::ts($now),
            'period' => Obj::of(['from' => self::ts($frm), 'to' => self::ts($to)]),
            'eventCount' => $st,
            'assurances' => $assurances,
            'items' => $items,
            'coverage' => Obj::of(['total' => $total, 'satisfied' => $satisfied, 'partial' => $partial, 'notEvidenced' => $notEvidenced, 'satisfiedFraction' => $fraction, 'satisfiedPercent' => self::jsRound($fraction * 100)]),
            'summary' => $summary,
        ]);
    }

    // ---- renderers --------------------------------------------------------------------------------------------------------

    /** The report as stable, pretty JSON (`JSON.stringify(report, null, 2)`). */
    public static function renderJson(mixed $report): string
    {
        return self::pretty($report);
    }

    private static function upper(mixed $v): string
    {
        if (!is_string($v)) {
            throw new \TypeError('toUpperCase is not a function');
        }
        return mb_strtoupper($v);
    }

    private static function glyph(mixed $status): string
    {
        return is_string($status) && isset(self::STATUS_GLYPH[$status]) ? self::STATUS_GLYPH[$status] : 'undefined';
    }

    private static function walk(mixed $o, string ...$path): mixed
    {
        foreach ($path as $k) {
            $o = self::prop($o, $k);
        }
        return $o;
    }

    /** The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail). */
    public static function renderMarkdown(mixed $r): string
    {
        $g = static fn(string ...$path): mixed => self::walk($r, ...$path);
        $lines = [];
        $lines[] = '# PCA compliance evidence — ' . self::tpl($g('framework'));
        $lines[] = '';
        $lines[] = sprintf('Generated %s · %s action(s) · coverage: %s/%s satisfied (%s%%)', self::tpl($g('generatedAt', 'iso')), self::tpl($g('eventCount')), self::tpl($g('coverage', 'satisfied')), self::tpl($g('coverage', 'total')), self::tpl($g('coverage', 'satisfiedPercent')));
        if (self::gt($g('eventCount'), 0)) {
            $lines[] = '';
            $lines[] = sprintf('Reporting period: %s → %s', self::tpl($g('period', 'from', 'iso')), self::tpl($g('period', 'to', 'iso')));
        }
        $lines[] = '';
        $lines[] = '## Why this trail is admissible (what PCA uniquely provides)';
        $lines[] = '';
        $lines[] = sprintf('- **Cryptographically verifiable** — %s: every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.', self::truthy($g('assurances', 'cryptographicallyVerifiable')) ? 'YES' : 'PARTIAL');
        $lines[] = sprintf('- **Explicit delegation chain** — %s: each action records who authorized what scope, hop by hop, rooted at a principal.', self::truthy($g('assurances', 'explicitDelegationChain')) ? 'YES' : 'PARTIAL');
        $lines[] = sprintf('- **Signed human-overrides** — %s: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.', self::truthy($g('assurances', 'signedHumanOverrides')) ? 'YES' : 'none in period');
        $lines[] = '';
        $lines[] = '> ' . self::tpl($g('assurances', 'narrative'));
        $lines[] = '';
        $lines[] = '## Coverage summary';
        $lines[] = '';
        $lines[] = '| Satisfied | Partial | Not evidenced | Total |';
        $lines[] = '| --- | --- | --- | --- |';
        $lines[] = sprintf('| %s | %s | %s | %s |', self::tpl($g('coverage', 'satisfied')), self::tpl($g('coverage', 'partial')), self::tpl($g('coverage', 'notEvidenced')), self::tpl($g('coverage', 'total')));
        $lines[] = '';
        $lines[] = '## Controls';
        $lines[] = '';
        $lines[] = '| Control | Clause | Status | Evidence in period |';
        $lines[] = '| --- | --- | --- | --- |';
        $items = $g('items');
        if (!self::isList($items)) {
            throw new \TypeError('items is not iterable');
        }
        foreach ($items as $i) {
            $lines[] = sprintf('| %s (`%s`) | %s | %s %s | %s |', self::tpl(self::prop($i, 'controlTitle')), self::tpl(self::prop($i, 'controlId')), self::tpl(self::prop($i, 'clause')),
                self::glyph(self::prop($i, 'status')), self::upper(self::prop($i, 'status')), self::tpl(self::prop($i, 'evidence')));
        }
        $lines[] = '';
        $lines[] = '## Control detail';
        $lines[] = '';
        foreach ($items as $i) {
            $lines[] = sprintf('### %s — %s', self::tpl(self::prop($i, 'controlId')), self::tpl(self::prop($i, 'controlTitle')));
            $lines[] = '';
            $lines[] = '- Clause: ' . self::tpl(self::prop($i, 'clause'));
            $lines[] = sprintf('- Status: %s %s', self::glyph(self::prop($i, 'status')), self::upper(self::prop($i, 'status')));
            $lines[] = '- PCA evidence basis: ' . self::tpl(self::prop($i, 'pcaEvidence'));
            $lines[] = '- Evidence in period: ' . self::tpl(self::prop($i, 'evidence'));
            $n = self::length(self::prop($i, 'findings'));
            if (!self::isU($n) && $n > 0) {
                $lines[] = '- Findings:';
                foreach (Jsx::iter(self::prop($i, 'findings')) as $f) {
                    $lines[] = '  - ' . self::tpl($f);
                }
            }
            $lines[] = '';
        }
        $lines[] = '---';
        $lines[] = '';
        $lines[] = '_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._';
        return implode("\n", $lines);
    }

    // ---- framework report (console activity stream) -----------------------------------------------------------------------

    private static function safetyBound(mixed $p): int|float
    {
        $kappa = self::prop($p, 'kappa');
        $bMax = self::prop($p, 'bMax');
        if (!self::gt($kappa, 0)) {
            return 0;
        }
        $b = self::num($bMax);
        return (is_nan($b) ? NAN : max(0.0, $b)) / self::num($kappa);
    }

    /** @return array<string,mixed> */
    private static function baseSummary(mixed $inp): array
    {
        $events = self::prop($inp, 'events');
        if (!self::isList($events)) {
            throw new \TypeError('e.filter is not a function');
        }
        $p = self::prop(self::prop($inp, 'policy'), 'riskPolicy');
        $decisions = self::qprop($inp, 'decisions');
        $dlen = self::nullish($decisions) ? 0 : self::length($decisions);
        $taint = 0.0;
        foreach ($events as $x) {
            $t = self::prop($x, 'taint');
            $v = self::isU($t) ? 0.0 : (self::finite($t) ? (float)Js::num($t) : INF);
            $taint = max($taint, $v);
        }
        $agents = new JsSet();
        foreach ($events as $x) {
            $agents->add(self::prop($x, 'agent'));
        }
        $countOutcome = static function (array $names) use ($events): int {
            $n = 0;
            foreach ($events as $x) {
                if (in_array(self::prop($x, 'outcome'), $names, true)) {
                    $n++;
                }
            }
            return $n;
        };
        return [
            'totalActions' => count($events),
            'autonomous' => $countOutcome(['auto', 'executed']),
            'humanOverseen' => $countOutcome(['step_up']) + (self::isU($dlen) ? 0 : $dlen),
            'denied' => $countOutcome(['deny']),
            'attributableAgents' => $agents->size(),
            'autonomousBound' => self::safetyBound($p) * self::num(self::prop($p, 'kappa')),
            'maxTaintObserved' => $taint,
        ];
    }

    private static function period(array $events): Obj
    {
        $ats = [];
        foreach ($events as $e) {
            $a = self::prop($e, 'at');
            if (self::finite($a)) {
                $ats[] = $a;
            }
        }
        $from = 0;
        $to = 0;
        if ($ats !== []) {
            $from = $to = $ats[0];
            foreach ($ats as $a) {
                if (Js::num($a) < Js::num($from)) {
                    $from = $a;
                }
                if (Js::num($a) > Js::num($to)) {
                    $to = $a;
                }
            }
        }
        return Obj::of(['from' => $from, 'to' => $to]);
    }

    private static function ctl(string $id, string $name, string $status, string $evidence): Obj
    {
        return Obj::of(['id' => $id, 'name' => $name, 'status' => $status, 'evidence' => $evidence]);
    }

    private static function fnum(float|int $x): string
    {
        return IntentWb::jsNumStr((float)$x);
    }

    /** @return list<Obj> */
    private static function euAiActControls(mixed $inp, array $s): array
    {
        $logged = $s['totalActions'] > 0;
        $bound = $s['autonomousBound'];
        $oversight = $s['humanOverseen'] > 0 || is_finite((float)$bound);
        $goal = self::truthy(self::own($inp, 'hasGoalCommitment'));
        return [
            self::ctl('art12-record-keeping', 'Automatic logging of events', $logged ? 'pass' : 'warn', sprintf('%d attributable actions recorded', $s['totalActions'])),
            self::ctl('art14-human-oversight', 'Human oversight', $oversight ? 'pass' : 'warn', sprintf('%d human-reviewed actions; autonomous bound %s', $s['humanOverseen'], self::fnum($bound))),
            self::ctl('art15-robustness', 'Bounded autonomy (accuracy/robustness)', is_finite((float)$bound) ? 'pass' : 'fail', sprintf('machine-checked safety bound = %s between human co-signs', self::fnum($bound))),
            self::ctl('art13-transparency', 'Transparency / traceability', $goal ? 'pass' : 'warn', $goal ? 'every action binds to a signed goal commitment (lineage)' : 'no goal commitment supplied'),
        ];
    }

    /** @return list<Obj> */
    private static function soc2Controls(mixed $inp, array $s): array
    {
        $preds = self::qprop(self::own($inp, 'policy'), 'predicates');
        $constrained = self::isList($preds) && count($preds) > 0;
        return [
            self::ctl('cc6.1-access', 'Logical access — least privilege', $constrained ? 'pass' : 'warn', $constrained ? 'actions constrained by signed predicates + capability attenuation (deny by default)' : 'the supplied policy lists no predicates'),
            self::ctl('cc7.2-monitoring', 'Monitoring of anomalies', $s['totalActions'] > 0 ? 'pass' : 'warn', sprintf('%d denied + %d escalated actions captured', $s['denied'], $s['humanOverseen'])),
            self::ctl('cc7.3-audit-trail', 'Audit trail', $s['totalActions'] > 0 ? 'pass' : 'warn', sprintf('%d content-addressed actions across %d agents', $s['totalActions'], $s['attributableAgents'])),
            self::ctl('cc8.1-change', 'Change management (policy integrity)', $constrained ? 'pass' : 'warn', $constrained ? 'policy is signed into the grant; tampering breaks verification' : 'the supplied policy lists no predicates'),
        ];
    }

    /** @return list<Obj> */
    private static function gdprControls(mixed $inp, array $s): array
    {
        $goal = self::truthy(self::own($inp, 'hasGoalCommitment'));
        $erasure = self::truthy(self::own($inp, 'erasureSupported'));
        return [
            self::ctl('art5-purpose', 'Purpose limitation', $goal ? 'pass' : 'warn', $goal ? 'actions bound to a committed goal/purpose' : 'no goal commitment supplied'),
            self::ctl('art5-minimization', 'Data minimisation', $s['totalActions'] > 0 ? 'pass' : 'warn', sprintf('taint-gated data flows; max taint observed = %s', self::fnum($s['maxTaintObserved']))),
            self::ctl('art5-accountability', 'Accountability', $s['attributableAgents'] > 0 ? 'pass' : 'warn', sprintf('%d attributable agent identities', $s['attributableAgents'])),
            self::ctl('art17-erasure', 'Right to erasure', $erasure ? 'pass' : 'warn', $erasure ? 'erasure path wired' : 'erasure path not asserted'),
        ];
    }

    /** A compliance evidence report for a framework from the console activity stream: `inp` is {policy, events, decisions?, hasGoalCommitment?, erasureSupported?}. `now` defaults to the clock when omitted. */
    public static function frameworkReport(mixed ...$a): Obj
    {
        $framework = $a[0] ?? Jsx::$U;
        $inp = $a[1] ?? Jsx::$U;
        $summary = self::baseSummary($inp);
        if (!(is_string($framework) && in_array($framework, self::FRAMEWORK_IDS, true))) {
            throw new \InvalidArgumentException(sprintf("frameworkReport: unknown framework '%s' (have: %s)", self::tpl($framework), implode(', ', self::FRAMEWORK_IDS)));
        }
        $controls = match ($framework) {
            'eu-ai-act' => self::euAiActControls($inp, $summary),
            'soc2' => self::soc2Controls($inp, $summary),
            default => self::gdprControls($inp, $summary),
        };
        $sum = new Obj();
        foreach ($summary as $k => $v) {
            $sum->set($k, $v);
        }
        return Obj::of(['framework' => $framework, 'generatedAt' => array_key_exists(2, $a) ? $a[2] : self::nowMs(), 'period' => self::period($inp->get('events')), 'summary' => $sum,
            'controls' => $controls, 'pass' => count(array_filter($controls, static fn(Obj $c) => $c->get('status') === 'fail')) === 0]);
    }

    private static function dateIso(mixed $v): string
    {
        return self::isoString($v === null ? 0 : (is_bool($v) ? (int)$v : $v));
    }

    /** A short Markdown block of a framework report, for an audit package. */
    public static function frameworkReportToMarkdown(mixed $r): string
    {
        $summary = self::prop($r, 'summary');
        $controls = self::prop($r, 'controls');
        if (!self::isList($controls)) {
            throw new \TypeError('r.controls.map is not a function');
        }
        $lines = [
            '# PCA compliance evidence — ' . self::tpl(self::prop($r, 'framework')),
            '',
            sprintf('Generated %s · %s actions · %s agents · overall: %s', self::dateIso(self::prop($r, 'generatedAt')), self::tpl(self::prop($summary, 'totalActions')),
                self::tpl(self::prop($summary, 'attributableAgents')), self::truthy(self::prop($r, 'pass')) ? 'PASS' : 'FAIL'),
            '',
            '| Control | Status | Evidence |',
            '| --- | --- | --- |',
        ];
        foreach ($controls as $c) {
            $lines[] = sprintf('| %s (%s) | %s | %s |', self::tpl(self::prop($c, 'name')), self::tpl(self::prop($c, 'id')), self::upper(self::prop($c, 'status')), self::tpl(self::prop($c, 'evidence')));
        }
        $lines[] = '';
        $lines[] = '_Evidence mapping, not a legal certification._';
        return implode("\n", $lines);
    }
}
