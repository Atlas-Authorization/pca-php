<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * Workflow (DAG) authorization (K5, C-300..C-309): admit ONE step of a principal-signed workflow, or deny / escalate. Total and
 * pure (no clock, no store, no I/O): everything unknown, malformed, unsigned, out of order or unplanned DENIES, and a thrown
 * error is the same `bad_workflow` denial. Integers only: a JSON number is an integer only as an exact safe-integer lexeme
 * (`2500.0` is not one). Values are parsed JSON (Obj, lists, Num, strings, bools, null). Replays
 * packages/pca/conformance/workflow-vectors.json. The shared strict helpers below are also used by ReadSide.
 */
final class Workflow
{
    public const WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\0";
    public const WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\0";
    private const WF_REF = 'atlas-pca/workflow-ref/v1';
    private const WR_REF = 'atlas-pca/wf-receipt-ref/v1';
    private const VAL = 'atlas-pca/wf-value/v1';
    private const MAX_SAFE = 9007199254740991;

    private const L_STEPS = 64;
    private const L_EDGES = 256;
    private const L_DEPS = 16;
    private const L_LABELS = 16;
    private const L_FIELDS = 32;
    private const L_COST = 8;

    public const ID_RE = '/\A(?!__proto__\z)[A-Za-z0-9_.:-]{1,64}\z/D';
    public const LABEL_RE = '/\A(?!__proto__\z)[a-z0-9_.:-]{1,64}\z/D';
    public const NAME_RE = '/\A(?!__proto__\z)[A-Za-z0-9_.-]{1,64}\z/D';
    public const UNIT_RE = '/\A[A-Za-z0-9_.:-]{1,16}\z/D';

    private const STEP_KEYS = ['id', 'verb', 'resource', 'params_digest', 'deps', 'sink', 'deny_labels', 'escalate_labels', 'fresh_ms', 'cost'];
    private const EDGE_KEYS = ['from', 'to', 'op', 'unit', 'deny_labels', 'promise'];
    private const BODY_KEYS = ['v', 'id', 'principal', 'goal_digest', 'plan_root', 'issued_at', 'expires_at', 'steps', 'edges', 'budget'];
    private const OPS = ['eq', 'le', 'ge', 'lt', 'gt'];

    // ---- shared strict helpers ---------------------------------------------------------------------------------------------

    public static function isObj(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    public static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** A non-negative safe integer: an exact integer lexeme (or a native int), never a float, a bool or a string. */
    public static function isUint(mixed $x): bool
    {
        if ($x instanceof Num) {
            return $x->isInt() && $x->strictError() === null && $x->lexeme[0] !== '-';
        }
        return is_int($x) && $x >= 0 && $x <= self::MAX_SAFE;
    }

    /** A safe integer of either sign. */
    public static function isSafeInt(mixed $x): bool
    {
        if ($x instanceof Num) {
            return $x->isInt() && $x->strictError() === null;
        }
        return is_int($x) && abs($x) <= self::MAX_SAFE;
    }

    /** The integer of a value that passed {@see isSafeInt}. */
    public static function iv(mixed $x): int
    {
        return $x instanceof Num ? $x->int() : (int)$x;
    }

    public static function isScalar(mixed $v): bool
    {
        return is_string($v) || is_bool($v) || self::isSafeInt($v);
    }

    public static function isStr(mixed $x, int $max): bool
    {
        return K3Sig::isStr($x, $max);
    }

    public static function isB32(mixed $x): bool
    {
        return is_string($x) && Pca::unb64u($x, 32) !== null;
    }

    public static function matches(string $re, mixed $x): bool
    {
        return is_string($x) && preg_match($re, $x) === 1;
    }

    /** Strictly ascending (bytewise; every member is ASCII) with every member matching `$re`. */
    public static function sortedUnique(mixed $x, string $re, int $max): bool
    {
        if (!self::isList($x) || count($x) > $max) {
            return false;
        }
        foreach ($x as $i => $s) {
            if (!self::matches($re, $s) || ($i > 0 && strcmp($x[$i - 1], $s) >= 0)) {
                return false;
            }
        }
        return true;
    }

    /** @param list<string> $keys */
    public static function onlyKeys(Obj $o, array $keys): bool
    {
        if (count($o->keys()) !== count($keys)) {
            return false;
        }
        foreach ($keys as $k) {
            if (!$o->has($k)) {
                return false;
            }
        }
        return true;
    }

    public static function verifyBody(string $domain, mixed $body, mixed $signer, mixed $sig): bool
    {
        return K3Sig::verifyBody($domain, $body, $signer, $sig);
    }

    public static function hash(string $d, string $k, mixed $v): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => $d, $k => $v]));
    }

    /** The digest of a scalar as it appears in step receipts (domain separated). */
    public static function valueDigest(mixed $v): string
    {
        return self::hash(self::VAL, 'v', $v);
    }

    public static function isScalarMap(mixed $x): bool
    {
        if (!($x instanceof Obj) || count($x->keys()) > self::L_FIELDS) {
            return false;
        }
        foreach ($x->keys() as $k) {
            if (!self::matches(self::NAME_RE, $k) || !self::isScalar($x->get($k))) {
                return false;
            }
        }
        return true;
    }

    // ---- validation --------------------------------------------------------------------------------------------------------

    private static function nullOr(mixed $x, callable $ok): bool
    {
        return $x === null || $ok($x);
    }

    private static function isId(mixed $x): bool
    {
        return self::matches(self::ID_RE, $x);
    }

    private static function isName(mixed $x): bool
    {
        return self::matches(self::NAME_RE, $x);
    }

    private static function isUnit(mixed $x): bool
    {
        return self::matches(self::UNIT_RE, $x);
    }

    private static function uintMap(mixed $x, int $max): bool
    {
        if (!($x instanceof Obj) || count($x->keys()) > $max) {
            return false;
        }
        foreach ($x->keys() as $k) {
            if (!self::isName($k) || !self::isUint($x->get($k))) {
                return false;
            }
        }
        return true;
    }

    private static function validStep(mixed $s): bool
    {
        if (!($s instanceof Obj) || !self::onlyKeys($s, self::STEP_KEYS)) {
            return false;
        }
        return self::isId($s->get('id')) && self::isStr($s->get('verb'), 128) && self::isStr($s->get('resource'), 512)
            && self::nullOr($s->get('params_digest'), [self::class, 'isB32']) && self::sortedUnique($s->get('deps'), self::ID_RE, self::L_DEPS)
            && self::nullOr($s->get('sink'), [self::class, 'isId']) && self::sortedUnique($s->get('deny_labels'), self::LABEL_RE, self::L_LABELS)
            && self::sortedUnique($s->get('escalate_labels'), self::LABEL_RE, self::L_LABELS)
            && self::nullOr($s->get('fresh_ms'), [self::class, 'isUint']) && self::uintMap($s->get('cost'), self::L_COST);
    }

    private static function validEdge(mixed $e): bool
    {
        if (!($e instanceof Obj) || !self::onlyKeys($e, self::EDGE_KEYS)) {
            return false;
        }
        $f = $e->get('from');
        $t = $e->get('to');
        return $f instanceof Obj && self::onlyKeys($f, ['step', 'field']) && self::isId($f->get('step')) && self::isName($f->get('field'))
            && $t instanceof Obj && self::onlyKeys($t, ['step', 'param']) && self::isId($t->get('step')) && self::isName($t->get('param'))
            && is_string($e->get('op')) && in_array($e->get('op'), self::OPS, true) && self::nullOr($e->get('unit'), [self::class, 'isUnit'])
            && self::sortedUnique($e->get('deny_labels'), self::LABEL_RE, self::L_LABELS) && self::nullOr($e->get('promise'), [self::class, 'isId']);
    }

    /** Shape of the body only (no signature, no DAG semantics). */
    public static function validWorkflowBody(mixed $b): bool
    {
        if (!($b instanceof Obj) || !self::onlyKeys($b, self::BODY_KEYS) || !self::isUint($b->get('v')) || self::iv($b->get('v')) !== 1) {
            return false;
        }
        if (!self::isId($b->get('id')) || !self::isB32($b->get('principal')) || !self::nullOr($b->get('goal_digest'), [self::class, 'isB32'])
            || !self::nullOr($b->get('plan_root'), [self::class, 'isB32']) || !self::isUint($b->get('issued_at')) || !self::isUint($b->get('expires_at'))) {
            return false;
        }
        $steps = $b->get('steps');
        if (!self::isList($steps) || count($steps) === 0 || count($steps) > self::L_STEPS) {
            return false;
        }
        foreach ($steps as $s) {
            if (!self::validStep($s)) {
                return false;
            }
        }
        $edges = $b->get('edges');
        if (!self::isList($edges) || count($edges) > self::L_EDGES) {
            return false;
        }
        foreach ($edges as $e) {
            if (!self::validEdge($e)) {
                return false;
            }
        }
        $bg = $b->get('budget');
        if (!($bg instanceof Obj) || !self::onlyKeys($bg, ['max_steps', 'caps']) || !self::isUint($bg->get('max_steps')) || !self::uintMap($bg->get('caps'), self::L_COST)) {
            return false;
        }
        // every cost name must be capped: an uncapped cost is a budget that silently does not exist
        foreach ($steps as $s) {
            foreach ($s->get('cost')->keys() as $k) {
                if (!$bg->get('caps')->has($k)) {
                    return false;
                }
            }
        }
        return true;
    }

    /** DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. Null when sound. */
    public static function dagError(Obj $b): ?string
    {
        $ids = [];
        foreach ($b->get('steps') as $s) {
            if (isset($ids['k' . $s->get('id')])) {
                return 'duplicate step id';
            }
            $ids['k' . $s->get('id')] = $s;
        }
        foreach ($b->get('steps') as $s) {
            foreach ($s->get('deps') as $d) {
                if ($d === $s->get('id') || !isset($ids['k' . $d])) {
                    return 'bad dependency';
                }
            }
        }
        $anc = self::ancestors($b);
        if ($anc === null) {
            return 'cycle';
        }
        foreach ($b->get('edges') as $e) {
            $from = 'k' . $e->get('from')->get('step');
            $to = 'k' . $e->get('to')->get('step');
            if (!isset($ids[$from]) || !isset($ids[$to]) || !isset($anc[$to][$from])) {
                return 'edge does not follow a dependency';
            }
        }
        return null;
    }

    /** @return ?array<string, array<string, true>> 'k'.step id -> set of 'k'.transitive dependency ids; null on a cycle */
    public static function ancestors(Obj $b): ?array
    {
        $byId = [];
        foreach ($b->get('steps') as $s) {
            $byId['k' . $s->get('id')] = $s;
        }
        $out = [];
        $state = [];
        $visit = static function (string $id) use (&$visit, &$out, &$state, $byId): bool {
            if (($state[$id] ?? 0) === 2) {
                return true;
            }
            if (($state[$id] ?? 0) === 1) {
                return false;
            }
            $state[$id] = 1;
            $set = [];
            foreach ($byId[$id]->get('deps') as $d) {
                if (!$visit('k' . $d)) {
                    return false;
                }
                $set['k' . $d] = true;
                foreach ($out['k' . $d] as $x => $_) {
                    $set[$x] = true;
                }
            }
            $out[$id] = $set;
            $state[$id] = 2;
            return true;
        };
        foreach ($byId as $id => $_) {
            if (!$visit($id)) {
                return null;
            }
        }
        return $out;
    }

    public static function workflowDigest(Obj $b): string
    {
        return self::hash(self::WF_REF, 'w', $b);
    }

    public static function receiptRef(mixed $r): string
    {
        return self::hash(self::WR_REF, 'r', $r);
    }

    private static function validReceiptShape(mixed $r): bool
    {
        if (!($r instanceof Obj) || !self::onlyKeys($r, ['v', 'wf', 'step', 'seq', 'prev', 'outcome', 'params_digest', 'outputs', 'issued_at', 'signer', 'sig'])
            || !self::isUint($r->get('v')) || self::iv($r->get('v')) !== 1) {
            return false;
        }
        $prev = $r->get('prev');
        if (!self::isB32($r->get('wf')) || !self::isId($r->get('step')) || !self::isUint($r->get('seq')) || !self::nullOr($prev, [self::class, 'isB32'])
            || (self::iv($r->get('seq')) === 0) !== ($prev === null) || ($r->get('outcome') !== 'ok' && $r->get('outcome') !== 'failed')) {
            return false;
        }
        if (!self::isB32($r->get('params_digest')) || !self::isUint($r->get('issued_at')) || !self::isB32($r->get('signer')) || !is_string($r->get('sig'))) {
            return false;
        }
        $o = $r->get('outputs');
        if (!($o instanceof Obj) || count($o->keys()) > self::L_FIELDS) {
            return false;
        }
        foreach ($o->keys() as $k) {
            $v = $o->get($k);
            if (!self::isName($k) || !($v instanceof Obj) || !self::onlyKeys($v, ['digest', 'num', 'unit', 'labels']) || !self::isB32($v->get('digest'))
                || !self::nullOr($v->get('num'), [self::class, 'isUint']) || !self::nullOr($v->get('unit'), [self::class, 'isUnit'])
                || !self::sortedUnique($v->get('labels'), self::LABEL_RE, self::L_LABELS)) {
                return false;
            }
        }
        return true;
    }

    // ---- admission ---------------------------------------------------------------------------------------------------------

    /** @param list<int> $pending @return array{decision: string, code: ?string, step: ?string, at: ?int, pending: list<int>} */
    private static function res(string $decision, ?string $code, ?string $step, ?int $at = null, array $pending = []): array
    {
        return ['decision' => $decision, 'code' => $code, 'step' => $step, 'at' => $at, 'pending' => $pending];
    }

    private static function deny(string $code, ?string $step = null, ?int $at = null): array
    {
        return self::res('deny', $code, $step, $at);
    }

    /** Is `$root` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? */
    public static function planRootAuthorized(mixed $workflow, mixed $principal, mixed $now, mixed $root): bool
    {
        try {
            if (!($workflow instanceof Obj) || !self::isUint($now) || !is_string($principal)) {
                return false;
            }
            $b = $workflow->get('body');
            return self::validWorkflowBody($b) && self::dagError($b) === null && $b->get('principal') === $principal
                && self::verifyBody(self::WORKFLOW_DOMAIN, $b, $principal, $workflow->get('sig'))
                && self::iv($now) >= self::iv($b->get('issued_at')) && self::iv($now) < self::iv($b->get('expires_at')) && $b->get('plan_root') === $root;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function validRequest(mixed $r): bool
    {
        if (!($r instanceof Obj) || !self::onlyKeys($r, ['step', 'verb', 'resource', 'params', 'units', 'goal_digest', 'plan_root'])
            || !self::isId($r->get('step')) || !self::isStr($r->get('verb'), 128) || !self::isStr($r->get('resource'), 512) || !self::isScalarMap($r->get('params'))) {
            return false;
        }
        $u = $r->get('units');
        if (!($u instanceof Obj)) {
            return false;
        }
        foreach ($u->keys() as $k) {
            if (!self::isName($k) || !self::isUnit($u->get($k))) {
                return false;
            }
        }
        return self::nullOr($r->get('goal_digest'), [self::class, 'isB32']) && self::nullOr($r->get('plan_root'), [self::class, 'isB32']);
    }

    /** The offending receipt index, or null when the chain is sound. */
    private static function receiptError(Obj $w, string $rsSigner, array $receipts, int $now): ?int
    {
        $wd = self::workflowDigest($w);
        $byId = [];
        foreach ($w->get('steps') as $s) {
            $byId['k' . $s->get('id')] = $s;
        }
        $index = [];
        $prev = null;
        foreach ($receipts as $i => $r) {
            if (!self::validReceiptShape($r) || $r->get('signer') !== $rsSigner || $r->get('wf') !== $wd || self::iv($r->get('seq')) !== $i || self::iv($r->get('issued_at')) > $now) {
                return $i;
            }
            $k = 'k' . $r->get('step');
            if (!isset($byId[$k]) || isset($index[$k])) {
                return $i;
            }
            if (($prev === null ? $r->get('prev') !== null : $r->get('prev') !== self::receiptRef($prev)) || !self::verifyBody(self::WF_RECEIPT_DOMAIN, $r->without('sig'), $rsSigner, $r->get('sig'))) {
                return $i;
            }
            // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
            foreach ($byId[$k]->get('deps') as $d) {
                if (isset($index['k' . $d])) {
                    continue;
                }
                $es = self::edgesBetween($w, $d, $r->get('step'));
                if ($es === [] || self::anyUnpromised($es)) {
                    return $i;
                }
            }
            $index[$k] = $i;
            $prev = $r;
        }
        return null;
    }

    /** @return list<Obj> the edges from step `$from` to step `$to`, keyed by their index */
    private static function edgesBetween(Obj $w, string $from, string $to): array
    {
        $es = [];
        foreach ($w->get('edges') as $i => $e) {
            if ($e->get('from')->get('step') === $from && $e->get('to')->get('step') === $to) {
                $es[$i] = $e;
            }
        }
        return $es;
    }

    private static function anyUnpromised(array $es): bool
    {
        foreach ($es as $e) {
            if ($e->get('promise') === null) {
                return true;
            }
        }
        return false;
    }

    /** @return array<string,mixed> */
    private static function evaluate(mixed $inp, bool $bind): array
    {
        if (!($inp instanceof Obj)) {
            return self::deny('bad_workflow');
        }
        $sw = $inp->get('workflow');
        $request = $inp->get('request');
        $receipts = $inp->get('receipts');
        $principal = $inp->get('principal');
        $rsSigner = $inp->get('rsSigner');
        $nowV = $inp->get('now');
        if (!($sw instanceof Obj) || !self::onlyKeys($sw, ['body', 'sig']) || !self::validWorkflowBody($sw->get('body')) || !self::validRequest($request)
            || !self::isList($receipts) || !self::isB32($principal) || !self::isB32($rsSigner) || !self::isUint($nowV)) {
            return self::deny('bad_workflow');
        }
        $now = self::iv($nowV);
        $w = $sw->get('body');
        $q = $request;
        $qs = $q->get('step');
        if (self::dagError($w) !== null) {
            return self::deny('bad_dag', $qs);
        }
        if ($w->get('principal') !== $principal || !self::verifyBody(self::WORKFLOW_DOMAIN, $w, $principal, $sw->get('sig'))) {
            return self::deny('bad_signature', $qs);
        }
        if ($now < self::iv($w->get('issued_at'))) {
            return self::deny('not_yet', $qs);
        }
        if ($now >= self::iv($w->get('expires_at'))) {
            return self::deny('expired', $qs);
        }
        if ($q->get('goal_digest') !== $w->get('goal_digest')) {
            return self::deny('goal_mismatch', $qs);
        }
        if ($q->get('plan_root') !== $w->get('plan_root')) {
            return self::deny('plan_root_mismatch', $qs);
        }
        $bad = self::receiptError($w, $rsSigner, $receipts, $now);
        if ($bad !== null) {
            return self::deny('bad_receipt', $qs, $bad);
        }
        $rec = [];
        foreach ($receipts as $r) {
            $rec['k' . $r->get('step')] = $r;
        }
        $step = null;
        $costOf = [];
        foreach ($w->get('steps') as $s) {
            $costOf['k' . $s->get('id')] = $s->get('cost');
            if ($step === null && $s->get('id') === $qs) {
                $step = $s;
            }
        }
        if ($step === null) {
            return self::deny('unplanned_step', $qs);
        }
        if ($step->get('verb') !== $q->get('verb') || $step->get('resource') !== $q->get('resource')) {
            return self::deny('step_mismatch', $qs);
        }
        $pd = IntentV2::hashCanonical($q->get('params'));
        if ($step->get('params_digest') !== null && $step->get('params_digest') !== $pd) {
            return self::deny('params_mismatch', $qs);
        }
        $sid = 'k' . $step->get('id');
        $mine = $rec[$sid] ?? null;
        if ($bind) {
            if ($mine === null || $mine->get('params_digest') !== $pd) {
                return self::deny('params_mismatch', $qs);
            }
        } else {
            if ($mine !== null) {
                return self::deny('already_done', $qs);
            }
            if (count($receipts) + 1 > self::iv($w->get('budget')->get('max_steps'))) {
                return self::deny('budget_exceeded', $qs);
            }
            $caps = $w->get('budget')->get('caps');
            foreach ($caps->keys() as $name) {
                $spent = 0;
                foreach ($receipts as $r) {
                    $c = $costOf['k' . $r->get('step')];
                    $spent += $c->has($name) ? self::iv($c->get($name)) : 0;
                }
                $c = $step->get('cost');
                $spent += $c->has($name) ? self::iv($c->get($name)) : 0;
                if ($spent > self::iv($caps->get($name))) {
                    return self::deny('budget_exceeded', $qs);
                }
            }
        }
        // dependencies
        $pending = [];
        $unconstrained = false;
        foreach ($step->get('deps') as $d) {
            $dr = $rec['k' . $d] ?? null;
            if ($dr === null) {
                $es = self::edgesBetween($w, $d, $step->get('id'));
                if ($bind || $es === []) {
                    return self::deny('deps_unmet', $qs);
                }
                if (self::anyUnpromised($es)) {
                    $unconstrained = true;
                }
                continue;
            }
            if ($dr->get('outcome') !== 'ok') {
                return self::deny('dep_failed', $qs);
            }
            if ($step->get('fresh_ms') !== null && $now - self::iv($dr->get('issued_at')) > self::iv($step->get('fresh_ms'))) {
                return self::deny('stale_dep', $qs);
            }
        }
        // edge constraints
        foreach ($w->get('edges') as $i => $e) {
            if ($e->get('to')->get('step') !== $step->get('id')) {
                continue;
            }
            $src = $rec['k' . $e->get('from')->get('step')] ?? null;
            if ($src === null) {
                $pending[] = $i;
                continue;
            }
            $param = $e->get('to')->get('param');
            $outs = $src->get('outputs');
            $fld = $e->get('from')->get('field');
            if (!$outs->has($fld) || !$q->get('params')->has($param)) {
                return self::deny('edge_missing', $qs, $i);
            }
            $out = $outs->get($fld);
            $val = $q->get('params')->get($param);
            $unit = $out->get('unit');
            if ($unit !== ($q->get('units')->has($param) ? $q->get('units')->get($param) : null) || $unit !== $e->get('unit')) {
                return self::deny('edge_unit', $qs, $i);
            }
            if ($e->get('op') === 'eq') {
                if (self::valueDigest($val) !== $out->get('digest')) {
                    return self::deny('edge_digest', $qs, $i);
                }
            } else {
                if (!($val instanceof Num) || $out->get('num') === null) {
                    return self::deny('edge_value', $qs, $i);
                }
                $a = self::iv($val);
                $b = self::iv($out->get('num'));
                $ok = match ($e->get('op')) {
                    'le' => $a <= $b,
                    'ge' => $a >= $b,
                    'lt' => $a < $b,
                    default => $a > $b,
                };
                if (!$ok) {
                    return self::deny('edge_relation', $qs, $i);
                }
            }
            foreach ($out->get('labels') as $l) {
                if (in_array($l, $e->get('deny_labels'), true)) {
                    return self::deny('taint_flow', $qs, $i);
                }
            }
        }
        if ($bind && $pending !== []) {
            return self::deny('deps_unmet', $qs);
        }
        // taint across the DAG: every label any executed ancestor produced
        $anc = self::ancestors($w);
        $inherited = [];
        foreach (array_keys($anc[$sid]) as $a) {
            $ar = $rec[$a] ?? null;
            if ($ar === null) {
                continue;
            }
            foreach ($ar->get('outputs')->keys() as $ok) {
                foreach ($ar->get('outputs')->get($ok)->get('labels') as $l) {
                    $inherited[$l] = true;
                }
            }
        }
        foreach ($step->get('deny_labels') as $l) {
            if (isset($inherited[$l])) {
                return self::deny('taint_flow', $qs);
            }
        }
        if ($unconstrained) {
            return self::res('escalate', 'pipeline_unconstrained', $qs);
        }
        foreach ($step->get('escalate_labels') as $l) {
            if (isset($inherited[$l])) {
                return self::res('escalate', 'taint_escalate', $qs);
            }
        }
        return self::res('allow', null, $qs, null, $pending);
    }

    /**
     * Admit ONE step of the committed workflow, or deny / escalate. `$inp` is an Obj with `workflow` (the signed {body, sig}),
     * `principal` and `rsSigner` (the keys the verifier pinned), `receipts` (a list), `now` and `request`.
     *
     * @return array{decision: string, code: ?string, step: ?string, at: ?int, pending: list<int>}
     */
    public static function admitStep(mixed $inp): array
    {
        try {
            return self::evaluate($inp, false);
        } catch (\Throwable) {
            return self::deny('bad_workflow');
        }
    }

    /** Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge. Same input as admitStep. */
    public static function bindPromises(mixed $inp): array
    {
        try {
            return self::evaluate($inp, true);
        } catch (\Throwable) {
            return self::deny('bad_workflow');
        }
    }
}
