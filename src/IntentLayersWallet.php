<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentPolicy.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/IntentMulti.php';
require_once __DIR__ . '/IntentMultiAgg.php';

/**
 * Wallet-side layered intent (layers.ts of pca-intent): ceiling admitters, the lattice view of a task learner, owner risk, layer cell
 * sets, and k-of-n quorum-signed approvals of a shared-layer widening. The verifier-side layer decisions (decideLayerCeilings,
 * decideLayers) live in {@see Predicates}. A cell key is an array `['verb' => string, 'cell' => list<int>]`.
 */
final class IntentLayersWallet
{
    public const CEILINGS = ['org', 'site', 'std'];
    public const LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\0";
    private const STATEMENT_KEYS = ['layer', 'session', 'seq', 'map_digest', 'prev'];

    /**
     * Compile the ceiling layers into admitters. ABSENT = no ceiling (null); a ceiling present as null or not an object is malformed (throws).
     * @return array{org:?IntentAdmitter,site:?IntentAdmitter,std:?IntentAdmitter}
     */
    public static function ceilingAdmitters(mixed $layers): array
    {
        if ($layers === null) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        $out = [];
        foreach (self::CEILINGS as $k) {
            if (!Js::has($layers, $k)) {
                $out[$k] = null;
                continue;
            }
            $l = Js::opt($layers, $k);
            if (!($l instanceof Obj)) {
                throw new \InvalidArgumentException("ceilingAdmitters: the $k ceiling is malformed (null or not an object)");
            }
            $out[$k] = IntentPolicy::admitter($l);
        }
        return $out;
    }

    /** The first ceiling that excludes the outcome (null when every ceiling admits it). */
    public static function ceilingOf(array $c, mixed $vs, mixed $o): ?string
    {
        foreach (self::CEILINGS as $k) {
            $a = $c[$k] ?? null;
            if ($a !== null && !$a->admits($vs, $o)) {
                return $k;
            }
        }
        return null;
    }

    private static function byVerb(mixed $omega): array
    {
        $m = [];
        foreach (Js::opt($omega, 'verbs') as $v) {
            $m['v' . Js::opt($v, 'verb')] = $v;
        }
        return $m;
    }

    /**
     * The lattice of a task learner under ceiling layers.
     * @return array{effective:list<array>,uncertain:list<array>,ceiling:list<array>}
     */
    public static function latticeView(IntentLearner $task, array $ceilings): array
    {
        $out = ['effective' => [], 'uncertain' => [], 'ceiling' => []];
        $byVerb = self::byVerb($task->omega);
        foreach ($task->cells() as $c) {
            $vs = $byVerb['v' . $c['verb']];
            $layer = self::ceilingOf($ceilings, $vs, IntentOmega::cellRep($vs, $c['cell']));
            if ($layer !== null) {
                $out['ceiling'][] = ['verb' => $c['verb'], 'cell' => $c['cell'], 'layer' => $layer];
                continue;
            }
            if ($c['vetoed']) {
                continue;
            }
            if ($c['inGrant']) {
                $out['effective'][] = ['verb' => $c['verb'], 'cell' => $c['cell']];
            } elseif ($c['p'] > 1e-12 && $c['p'] < $task->tau - 1e-12) {
                $out['uncertain'][] = ['verb' => $c['verb'], 'cell' => $c['cell']];
            }
        }
        return $out;
    }

    /** @return array{decision:string,layer?:string,by?:int} */
    public static function decideOutcomeLayers(IntentLearner $task, array $ceilings, mixed $o): array
    {
        $vs = IntentPolicy::vsOf($task->omega, $o);
        if ($vs === null) {
            return ['decision' => 'intent_denied'];
        }
        $layer = self::ceilingOf($ceilings, $vs, $o);
        if ($layer !== null) {
            return ['decision' => 'ceiling', 'layer' => $layer];
        }
        if ($task->isVetoed($o) || $task->acceptance($o) <= 1e-12) {
            return ['decision' => 'intent_denied'];
        }
        if ($task->admitsOutcome($o)) {
            return ['decision' => 'admit', 'by' => 0];
        }
        return ['decision' => 'intent_required'];
    }

    private static function key(mixed $c): string
    {
        return Js::str(Js::opt($c, 'verb')) . '|' . implode(',', array_map(static fn($i) => Js::str($i), Js::opt($c, 'cell')));
    }

    /** A question may only be about a cell of U_k (inside every ceiling); throws otherwise. */
    public static function assertAskable(mixed $view, mixed $c): void
    {
        $key = self::key($c);
        foreach (Js::opt($view, 'uncertain') as $u) {
            if (self::key($u) === $key) {
                return;
            }
        }
        throw new \InvalidArgumentException("layers: cell $key is not an uncertain cell inside every ceiling (never a question)");
    }

    /** The layer owner's own risk measure of a set of cells: sum of mu(c) (1 - a(c)) E[h | c]. */
    public static function ownerRisk(mixed $omega, array $cells, \Closure $acceptability, ?HarmModel $harm = null): float
    {
        $harm ??= IntentOmega::defaultHarm();
        $r = 0.0;
        $byVerb = self::byVerb($omega);
        foreach ($cells as $c) {
            $vs = $byVerb['v' . Js::opt($c, 'verb')] ?? null;
            if ($vs === null) {
                continue;
            }
            $st = IntentOmega::cellStats($vs, Js::opt($c, 'cell'), $harm);
            $a = $acceptability($vs, IntentOmega::cellRep($vs, Js::opt($c, 'cell')));
            $r += Jsx::toNum($st['mass']) * (1 - Jsx::toNum($a)) * Jsx::toNum($st['harm']); // the reference's number coercion: a non-number is NaN, not 0
        }
        return $r;
    }

    /** Every cell of the outcome space an admitter admits. @return list<array{verb:mixed,cell:list<int>}> */
    public static function layerCells(mixed $omega, IntentAdmitter $a): array
    {
        $out = [];
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $n = IntentOmega::verbCellCount($vs);
            for ($f = 0; $f < $n; $f++) {
                $cell = IntentOmega::decodeCell($vs, $f);
                if ($a->admits($vs, IntentOmega::cellRep($vs, $cell))) {
                    $out[] = ['verb' => Js::opt($vs, 'verb'), 'cell' => $cell];
                }
            }
        }
        return $out;
    }

    public static function cellKeyOf(mixed $omega, mixed $c): string
    {
        $vs = null;
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === Js::opt($c, 'verb')) {
                $vs = $v;
                break;
            }
        }
        return Js::str(Js::opt($c, 'verb')) . '|' . ($vs !== null ? (string)IntentOmega::encodeCell($vs, Js::opt($c, 'cell'))
            : implode(',', array_map(static fn($i) => Js::str($i), Js::opt($c, 'cell'))));
    }

    /**
     * An org layer that is itself a LEARNED map over a shared omega: the joint grant of the org approvers' maps under the org's rule.
     * @param list<Obj> $maps
     * @return array{map:Obj,policy:mixed}
     */
    public static function orgLayerFromMaps(array $maps, mixed $rule): array
    {
        $m = IntentMultiAgg::aggregateIntentMaps($maps, $rule);
        return ['map' => $m, 'policy' => Js::opt($m, 'grant')];
    }

    // ---- quorum-signed layer approvals -------------------------------------------------------------------------------

    /** The statement of an approval as a PHP array; an absent member is {@see Jsx::$U} (the reference's undefined). */
    private static function statementOf(mixed $a): array
    {
        Jsx::init();
        $out = ['v' => 1, 'kind' => 'pca-intent-layer-approval'];
        foreach (self::STATEMENT_KEYS as $k) {
            $out[$k] = Js::has($a, $k) ? Js::opt($a, $k) : Jsx::$U;
        }
        return $out;
    }

    /** domain || canonicalBytesStrict(statement): an undefined member makes the strict canonical form throw. */
    private static function approvalMessage(array $st): string
    {
        $o = new Obj();
        foreach ($st as $k => $v) {
            if ($v instanceof Undef) {
                throw new \InvalidArgumentException("canonicalBytesStrict: undefined member $k");
            }
            $o->set((string)$k, $v);
        }
        return self::LAYER_APPROVAL_DOMAIN . Json::canonicalizeNative($o);
    }

    private static function strictEq(mixed $a, mixed $b): bool
    {
        if ($a instanceof Undef || $b instanceof Undef) {
            return $a instanceof Undef && $b instanceof Undef;
        }
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) === Js::num($b);
        }
        return is_object($a) ? $a === $b : $a === $b;
    }

    /** Sign an approval of a shared-layer widening (an Ed25519 32-byte seed). */
    public static function signLayerApproval(mixed $s, string $secretKey): Obj
    {
        $st = self::statementOf($s);
        $kp = sodium_crypto_sign_seed_keypair($secretKey);
        $msg = self::approvalMessage($st);
        $o = new Obj();
        foreach ($st as $k => $v) {
            $o->set((string)$k, $v);
        }
        $o->set('signer', Pca::b64u(sodium_crypto_sign_publickey($kp)));
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($kp))));
        return $o;
    }

    /**
     * An approval counts iff its signer is a member, it is that member's first, its statement equals `$expected` field by field and its
     * signature verifies; the rule is the multi-principal one over member keys (IntentMulti::normalizeRule / ruleAdmits).
     * @return array{ok:bool,signers:list<string>,ignored:list<array{index:int,reason:string}>}
     */
    public static function verifyQuorumApprovals(mixed $approvals, mixed $members, mixed $rule, mixed $expected): array
    {
        $isList = static fn($x) => is_array($x) && array_is_list($x);
        if (!$isList($approvals) || !$isList($members) || $expected === null || !($expected instanceof Obj || is_array($expected))) {
            return ['ok' => false, 'signers' => [], 'ignored' => [['index' => -1, 'reason' => 'approvals and members must be arrays and expected an object']]];
        }
        $bad = count(array_unique(array_map(fn($m) => is_string($m) ? 's' . $m : 'x', $members))) !== count($members);
        foreach ($members as $m) {
            if (!is_string($m) || Pca::unb64u($m, 32) === null) {
                $bad = true;
            }
        }
        if ($bad) {
            return ['ok' => false, 'signers' => [], 'ignored' => [['index' => -1, 'reason' => 'members must be distinct 32-byte keys']]];
        }
        try {
            $n = IntentMulti::normalizeRule($rule, $members);
        } catch (\Throwable $e) {
            return ['ok' => false, 'signers' => [], 'ignored' => [['index' => -1, 'reason' => $e->getMessage()]]];
        }
        $want = self::statementOf($expected);
        $counted = [];
        $ignored = [];
        foreach ($approvals as $i => $a) {
            if (!Js::truthy($a) || !($a instanceof Obj || is_array($a))) {
                $ignored[] = ['index' => $i, 'reason' => 'not an object'];
                continue;
            }
            $signer = Js::opt($a, 'signer');
            if (!is_string($signer) || !in_array($signer, $members, true)) {
                $ignored[] = ['index' => $i, 'reason' => 'signer is not a member'];
                continue;
            }
            if (isset($counted[$signer])) {
                $ignored[] = ['index' => $i, 'reason' => 'second approval from the same member'];
                continue;
            }
            $st = self::statementOf($a);
            $same = true;
            foreach ($want as $k => $v) {
                if (!self::strictEq($st[$k], $v)) {
                    $same = false;
                }
            }
            $same = $same && self::strictEq(Js::opt($a, 'v'), 1) && Js::opt($a, 'kind') === 'pca-intent-layer-approval';
            if (!$same) {
                $ignored[] = ['index' => $i, 'reason' => 'approval is for another (layer, session, seq, map_digest, prev)'];
                continue;
            }
            try {
                $ok = Pca::verifyEd25519B64u($signer, self::approvalMessage($st), Js::opt($a, 'sig'));
            } catch (\Throwable) {
                $ok = false;
            }
            if (!$ok) {
                $ignored[] = ['index' => $i, 'reason' => 'bad signature'];
                continue;
            }
            $counted[$signer] = true;
        }
        $signers = array_values(array_filter($members, fn($m) => isset($counted[$m])));
        return ['ok' => IntentMulti::ruleAdmits($n, array_map(fn($m) => isset($counted[$m]), $members)), 'signers' => $signers, 'ignored' => $ignored];
    }
}
