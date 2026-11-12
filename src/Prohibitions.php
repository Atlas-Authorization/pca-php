<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Negative authority: a principal-committed CONSTITUTION of invariants the agent must NEVER violate, enforced independently of the
 * permission plan (packages/pca/src/prohibitions.ts is authoritative). Permissions GRANT, prohibitions VETO, prohibitions WIN:
 * `allow = permitted AND prohibitions.ok`.
 *
 * Everything malformed, unknown or unresolvable FAILS CLOSED, and for a prohibition "closed" is the OPPOSITE of the predicate DSL's
 * direction: a permission predicate that cannot be evaluated is not matched (denied), but a prohibition trigger that cannot be evaluated
 * is MATCHED (the veto applies; {@see ForbidCertificate::whenMatches}). A positive precondition (`require_prior.prior`,
 * `never_unless.unless`, `require_approval_over.approved`) must hold AFFIRMATIVELY.
 *
 * Inputs are parsed JSON values (Obj, list arrays, string, Num, bool, null). Numbers are read as floats; states this class builds carry
 * canonical Num values. The state-advancing functions take `$now` omitted for "the state's own time" (an explicit null is a clock regression, as in the reference).
 */
final class Prohibitions
{
    public const CONSTITUTION_VERSION = 1;
    public const CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\0";
    public const EVIDENCE_VERSION = 1;
    public const SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\0";
    public const STATE_DIGEST_DOMAIN = 'atlas-pca/monitor-state/v1';
    public const STATE_CHAIN_DOMAIN = 'atlas-pca/monitor-state-link/v1';
    public const MAX_LEDGER = 10000;
    public const MAX_INVARIANTS = 256;
    public const MAX_STATE_ENTRIES = 100000;
    public const MAX_STATE_KEYS = 1024;
    public const MAX_ID_LEN = 128;
    public const MAX_DEADLINE = 1000000;
    public const UNHASHABLE = '<unhashable>';
    /** Marks an absent `$now` (the TS default parameter); null is a value and is refused as a clock regression. */
    public const UNSET = "\0unset";
    private const FORBIDDEN_IDS = ['__proto__', 'constructor', 'prototype'];

    // ---- numbers ----------------------------------------------------------------------------------------------------

    /** JS Number.isFinite on a JSON value (a boolean is not a number): the float, or null. */
    public static function fin(mixed $x): ?float
    {
        if ($x instanceof Num) {
            $f = $x->float();
        } elseif (is_int($x) || is_float($x)) {
            $f = (float)$x;
        } else {
            return null;
        }
        return is_finite($f) ? $f : null;
    }

    /** JS Number.isInteger. */
    public static function int(mixed $x): ?float
    {
        $f = self::fin($x);
        return $f !== null && $f === floor($f) ? $f : null;
    }

    private static function negZero(mixed $x): bool
    {
        $f = self::fin($x);
        return $f === 0.0 && ($x instanceof Num ? str_starts_with($x->lexeme, '-') : (is_float($x) && 1 / $x < 0));
    }

    /** A canonical Num of a finite float. */
    public static function num(float $x): Num
    {
        return new Num($x === 0.0 ? '0' : IntentV2::jsNumStr($x));
    }

    private static function jsn(float $x): string
    {
        return IntentV2::jsNumStr($x);
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    private static function len(string $s): int
    {
        return SafeRegex::utf16Len($s);
    }

    private static function errSafe(callable $f): string
    {
        try {
            return $f();
        } catch (\Throwable) {
            return self::UNHASHABLE;
        }
    }

    // ---- constitution commitment ------------------------------------------------------------------------------------

    /** Genesis monitor state at time `$now`: empty ledger, no latches, seq 0, no parent. */
    public static function emptyState(float $now): Obj
    {
        return Obj::of(['now' => self::num($now), 'seq' => self::num(0), 'parent' => null, 'ledger' => new Obj(), 'latched' => new Obj()]);
    }

    private static function body(Obj $c): Obj
    {
        return $c->without('id', 'sig');
    }

    private static function domainMessage(string $domain, string $id): string
    {
        return $domain . hash('sha256', $id, true);
    }

    /** Content address of a constitution body. Throws only on non-canonicalizable input (authoring time). */
    public static function constitutionId(Obj $c): string
    {
        return Pca::hashCanonical(self::body($c));
    }

    /** The principal signs the constitution. Refuses a malformed one. */
    public static function signConstitution(Obj $c, KeyPair $key): Obj
    {
        $problems = self::validateConstitution($c);
        if ($problems !== []) {
            throw new \InvalidArgumentException('signConstitution: ' . implode('; ', $problems));
        }
        $id = self::constitutionId($c);
        $out = self::body($c);
        $out->set('id', $id);
        $out->set('sig', Pca::b64u($key->sign(self::domainMessage(self::CONSTITUTION_SIG_DOMAIN, $id))));
        return $out;
    }

    /** Well-formed, id matches content, signature by `$expectedPrincipal` (or the embedded one). Never throws. @return array{ok: bool, reason?: string} */
    public static function verifyConstitution(mixed $sc, ?string $expectedPrincipal = null): array
    {
        try {
            $problems = self::validateConstitution($sc);
            if ($problems !== []) {
                return ['ok' => false, 'reason' => $problems[0]];
            }
            if ($expectedPrincipal !== null && $sc->get('principal') !== $expectedPrincipal) {
                return ['ok' => false, 'reason' => 'principal mismatch'];
            }
            if (!is_string($sc->get('id')) || $sc->get('id') !== self::constitutionId($sc)) {
                return ['ok' => false, 'reason' => 'id does not match content'];
            }
            if (!is_string($sc->get('sig')) || !Pca::verifyEd25519B64u($sc->get('principal'), self::domainMessage(self::CONSTITUTION_SIG_DOMAIN, $sc->get('id')), $sc->get('sig'))) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'verification error (fail closed)'];
        }
    }

    // ---- validation (strict; unknown forms are rejected, never ignored) ---------------------------------------------

    private static function conditionsError(mixed $cs, string $label): ?string
    {
        if (!self::isList($cs) || $cs === []) {
            return "$label must be a non-empty array";
        }
        foreach ($cs as $c) {
            if (($e = ForbidCertificate::conditionError($c)) !== null) {
                return $e;
            }
        }
        return null;
    }

    /** Structural problems with an invariant (empty = well-formed). @return list<string> */
    public static function validateInvariant(mixed $inv): array
    {
        if (!($inv instanceof Obj)) {
            return ['invariant not an object'];
        }
        $id = $inv->get('id');
        if (!is_string($id) || $id === '') {
            return ['<no id>: missing id'];
        }
        $err = static fn(string $m): array => ["$id: $m"];
        if (self::len($id) > self::MAX_ID_LEN) {
            return $err('id too long');
        }
        if (in_array($id, self::FORBIDDEN_IDS, true)) {
            return $err('forbidden id');
        }
        $when = static fn(string $k): ?string => ForbidCertificate::whenError($inv->get($k), $k);
        $amountBad = static fn(): bool => !is_string($inv->get('amount')) || !str_starts_with($inv->get('amount'), 'action.');
        switch ($inv->get('kind')) {
            case 'never':
                $e = $when('when');
                return $e !== null ? $err($e) : [];
            case 'never_unless':
                $e = $when('when') ?? self::conditionsError($inv->get('unless'), 'unless');
                return $e !== null ? $err($e) : [];
            case 'cap':
                if (($e = $when('when')) !== null) {
                    return $err($e);
                }
                if ($amountBad()) {
                    return $err('amount must be an action.* path');
                }
                $max = self::fin($inv->get('max'));
                if ($max === null || $max < 0) {
                    return $err('max must be a finite number >= 0');
                }
                if ($inv->has('window_secs') && (($w = self::fin($inv->get('window_secs'))) === null || $w <= 0)) {
                    return $err('bad window_secs');
                }
                return [];
            case 'rate':
                if (($e = $when('when')) !== null) {
                    return $err($e);
                }
                $m = self::int($inv->get('max'));
                if ($m === null || $m < 0 || self::negZero($inv->get('max')) || $m > self::MAX_LEDGER) {
                    return $err('max must be an integer in [0,10000]');
                }
                $w = self::fin($inv->get('window_secs'));
                if ($w === null || $w <= 0) {
                    return $err('window_secs must be > 0');
                }
                return [];
            case 'never_after':
                $e = $when('after') ?? $when('forbid');
                return $e !== null ? $err($e) : [];
            case 'require_prior':
                $e = $when('when') ?? $when('prior');
                return $e !== null ? $err($e) : [];
            case 'require_approval_over':
                if (($e = $when('when')) !== null) {
                    return $err($e);
                }
                if ($amountBad()) {
                    return $err('amount must be an action.* path');
                }
                $t = self::fin($inv->get('threshold'));
                if ($t === null || $t < 0) {
                    return $err('threshold must be a finite number >= 0');
                }
                $e = self::conditionsError($inv->get('approved'), 'approved');
                return $e !== null ? $err($e) : [];
            default:
                return $err('unknown invariant kind ' . IntentWb::jsStr($inv->get('kind')));
        }
    }

    /** Structural problems with a constitution (empty = well-formed). @return list<string> */
    public static function validateConstitution(mixed $c): array
    {
        if (!($c instanceof Obj)) {
            return ['constitution not an object'];
        }
        $out = [];
        if (self::fin($c->get('version')) !== 1.0 || !($c->get('version') instanceof Num)) {
            $out[] = 'unsupported version ' . IntentWb::jsStr($c->get('version') instanceof Num ? $c->get('version')->float() : $c->get('version'));
        }
        if (!is_string($c->get('principal')) || $c->get('principal') === '') {
            $out[] = 'principal missing';
        }
        $invs = $c->get('invariants');
        if (!self::isList($invs)) {
            return array_merge($out, ['invariants not an array']);
        }
        if (count($invs) > self::MAX_INVARIANTS) {
            $out[] = 'too many invariants';
        }
        $seen = [];
        foreach ($invs as $inv) {
            $out = array_merge($out, self::validateInvariant($inv));
            $id = $inv instanceof Obj ? $inv->get('id') : null;
            if (!is_string($id)) {
                continue;
            }
            if (isset($seen['k' . $id])) {
                $out[] = "$id: duplicate id";
            }
            $seen['k' . $id] = true;
        }
        return $out;
    }

    // ---- canonical monitor state ------------------------------------------------------------------------------------

    /** Structural problem with a monitor state (null = well-formed). Total; never throws. */
    public static function stateProblem(mixed $state): ?string
    {
        try {
            if (!($state instanceof Obj) || ($now = self::fin($state->get('now'))) === null || !($state->get('ledger') instanceof Obj) || !($state->get('latched') instanceof Obj)) {
                return 'malformed monitor state';
            }
            $seq = self::int($state->get('seq'));
            if ($seq === null || $seq < 0 || self::negZero($state->get('seq'))) {
                return 'malformed monitor state: seq';
            }
            $parent = $state->get('parent');
            if ($parent !== null && !is_string($parent)) {
                return 'malformed monitor state: parent';
            }
            if ($seq === 0.0 && $parent !== null) {
                return 'malformed monitor state: genesis has a parent';
            }
            if ($seq > 0 && $parent === null) {
                return 'malformed monitor state: missing chain link';
            }
            $ledger = $state->get('ledger');
            $latched = $state->get('latched');
            if (count($ledger->keys()) > self::MAX_STATE_KEYS || count($latched->keys()) > self::MAX_STATE_KEYS) {
                return 'malformed monitor state: too many keys';
            }
            $total = 0;
            foreach ($ledger->keys() as $k) {
                if (in_array($k, self::FORBIDDEN_IDS, true) || self::len($k) > self::MAX_ID_LEN) {
                    return 'malformed monitor state: bad ledger key';
                }
                $l = $ledger->get($k);
                if (!self::isList($l) || count($l) > self::MAX_LEDGER) {
                    return 'malformed monitor state: bad ledger';
                }
                $total += count($l);
                foreach ($l as $e) {
                    $t = $e instanceof Obj ? self::fin($e->get('t')) : null;
                    $a = $e instanceof Obj ? self::fin($e->get('amount')) : null;
                    if ($t === null || $a === null || $a < 0) {
                        return 'malformed monitor state: bad ledger entry';
                    }
                    if ($t > $now) { // an entry from the "future" would be ignored by the window and so UNDER-count: clock regression
                        return 'malformed monitor state: ledger entry after now (clock regression)';
                    }
                }
            }
            if ($total > self::MAX_STATE_ENTRIES) {
                return 'malformed monitor state: too many entries';
            }
            foreach ($latched->keys() as $k) {
                if (in_array($k, self::FORBIDDEN_IDS, true) || self::len($k) > self::MAX_ID_LEN) {
                    return 'malformed monitor state: bad latch key';
                }
                $t = self::fin($latched->get($k));
                if ($t === null || $t > $now) {
                    return 'malformed monitor state: bad latch';
                }
            }
            if ($state->get('deadlines') !== null) {
                $dl = $state->get('deadlines');
                if (!($dl instanceof Obj)) {
                    return 'malformed monitor state: deadlines';
                }
                if (count($dl->keys()) > self::MAX_STATE_KEYS) {
                    return 'malformed monitor state: too many deadline keys';
                }
                foreach ($dl->keys() as $k) {
                    if (in_array($k, self::FORBIDDEN_IDS, true) || self::len($k) > self::MAX_ID_LEN) {
                        return 'malformed monitor state: bad deadline key';
                    }
                    $d = self::int($dl->get($k));
                    if ($d === null || $d < 1 || $d > self::MAX_DEADLINE) {
                        return 'malformed monitor state: bad deadline';
                    }
                }
            }
            return null;
        } catch (\Throwable) {
            return 'malformed monitor state';
        }
    }

    /** @param array{t: float, amount: float} $a @param array{t: float, amount: float} $b */
    private static function entryCmp(array $a, array $b): int
    {
        return $a['t'] <=> $b['t'] ?: $a['amount'] <=> $b['amount'];
    }

    /** @return list<array{t: float, amount: float}> the ledger of one key, sorted */
    private static function entriesOf(Obj $state, string $id): array
    {
        $l = $state->get('ledger')->get($id);
        $out = [];
        foreach (is_array($l) ? $l : [] as $e) {
            $out[] = ['t' => self::fin($e->get('t')), 'amount' => self::fin($e->get('amount'))];
        }
        usort($out, [self::class, 'entryCmp']);
        return $out;
    }

    /** @param list<array{t: float, amount: float}> $es */
    private static function entriesObj(array $es): array
    {
        return array_map(static fn(array $e): Obj => Obj::of(['t' => self::num($e['t']), 'amount' => self::num($e['amount'])]), $es);
    }

    /** Canonical, digest-committed projection of a monitor state. Throws when malformed. */
    public static function canonicalState(Obj $state): Obj
    {
        $p = self::stateProblem($state);
        if ($p !== null) {
            throw new \InvalidArgumentException($p);
        }
        $ledger = new Obj();
        foreach ($state->get('ledger')->keys() as $k) {
            $es = self::entriesOf($state, $k);
            if ($es !== []) {
                $ledger->set($k, self::entriesObj($es));
            }
        }
        $latched = new Obj();
        foreach ($state->get('latched')->keys() as $k) {
            $latched->set($k, self::num(self::fin($state->get('latched')->get($k))));
        }
        $base = Obj::of(['d' => self::STATE_DIGEST_DOMAIN, 'now' => self::num(self::fin($state->get('now'))), 'seq' => self::num(self::fin($state->get('seq'))),
            'parent' => $state->get('parent'), 'ledger' => $ledger, 'latched' => $latched]);
        $dl = $state->get('deadlines');
        if ($dl instanceof Obj && $dl->keys() !== []) {
            $d = new Obj();
            foreach ($dl->keys() as $k) {
                $d->set($k, self::num(self::fin($dl->get($k))));
            }
            $base->set('deadlines', $d);
        }
        return $base;
    }

    public static function stateDigest(Obj $state): string
    {
        return Pca::hashCanonical(self::canonicalState($state));
    }

    /** The same state at a later `$now`; refuses regression. Never throws. @return array{ok: bool, reason?: string, state?: Obj} */
    public static function tickState(mixed $state, mixed $now): array
    {
        if (self::stateProblem($state) !== null) {
            return ['ok' => false, 'reason' => 'malformed monitor state'];
        }
        $n = self::fin($now);
        if ($n === null || $n < self::fin($state->get('now'))) {
            return ['ok' => false, 'reason' => 'clock regression'];
        }
        $s = $state->without('now');
        $out = new Obj();
        $out->set('now', self::num($n));
        foreach ($s->keys() as $k) {
            $out->set($k, $s->get($k));
        }
        return ['ok' => true, 'state' => $out];
    }

    // ---- matching ---------------------------------------------------------------------------------------------------

    /** Does a prohibition trigger match? Veto polarity, fully fail-closed. */
    public static function whenMatches(mixed $w, Obj $ctx): bool
    {
        return ForbidCertificate::whenMatches($w, $ctx);
    }

    /** AFFIRMATIVE trigger match (plain permission-DSL semantics, unresolvable => not matched). */
    public static function whenAffirmative(mixed $w, Obj $ctx): bool
    {
        try {
            return ForbidCertificate::whenError($w, 'when') === null && Predicates::predicateMatches($w, $ctx);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function allHold(mixed $cs, Obj $ctx): bool
    {
        foreach (is_array($cs) ? $cs : [] as $c) {
            if (!Predicates::evaluateCondition($c, $ctx)) {
                return false;
            }
        }
        return true;
    }

    // ---- the monitor ------------------------------------------------------------------------------------------------

    /** @return list<array{t: float, amount: float}> */
    private static function windowEntries(Obj $state, string $id, ?float $windowSecs): array
    {
        $now = self::fin($state->get('now'));
        $lo = $windowSecs === null ? -INF : $now - ($windowSecs * 1000);
        return array_values(array_filter(self::entriesOf($state, $id), static fn(array $e): bool => $e['t'] > $lo && $e['t'] <= $now));
    }

    private static function desc(Obj $inv, string $default): string
    {
        $d = $inv->get('description');
        return is_string($d) ? $d : $default;
    }

    /** @return array{ok: bool, reason?: string} */
    private static function evalOne(Obj $inv, Obj $ctx, Obj $state): array
    {
        switch ($inv->get('kind')) {
            case 'never':
                return self::whenMatches($inv->get('when'), $ctx) ? ['ok' => false, 'reason' => self::desc($inv, 'forbidden action')] : ['ok' => true];
            case 'never_unless':
                if (!self::whenMatches($inv->get('when'), $ctx)) {
                    return ['ok' => true];
                }
                return self::allHold($inv->get('unless'), $ctx) ? ['ok' => true] : ['ok' => false, 'reason' => self::desc($inv, 'forbidden without required condition')];
            case 'cap':
                if (!self::whenMatches($inv->get('when'), $ctx)) {
                    return ['ok' => true];
                }
                $a = Predicates::resolvePath($ctx, $inv->get('amount'));
                $av = $a['found'] ? self::fin($a['value']) : null;
                if ($av === null || $av < 0) {
                    return ['ok' => false, 'reason' => 'amount unresolvable (fail closed)'];
                }
                $ws = $inv->get('window_secs') === null ? null : self::fin($inv->get('window_secs'));
                $spent = 0.0;
                foreach (self::windowEntries($state, $inv->get('id'), $ws) as $e) {
                    $spent += $e['amount'];
                }
                $max = self::fin($inv->get('max'));
                return $spent + $av <= $max ? ['ok' => true]
                    : ['ok' => false, 'reason' => 'cap exceeded: ' . self::jsn($spent) . ' + ' . self::jsn($av) . ' > ' . self::jsn($max)];
            case 'rate':
                if (!self::whenMatches($inv->get('when'), $ctx)) {
                    return ['ok' => true];
                }
                $ws = self::fin($inv->get('window_secs'));
                $n = count(self::windowEntries($state, $inv->get('id'), $ws));
                $max = self::fin($inv->get('max'));
                return $n + 1 <= $max ? ['ok' => true]
                    : ['ok' => false, 'reason' => 'rate exceeded: ' . ($n + 1) . ' > ' . self::jsn($max) . ' per ' . self::jsn($ws) . 's'];
            case 'never_after':
                if (!$state->get('latched')->has($inv->get('id')) || !self::whenMatches($inv->get('forbid'), $ctx)) {
                    return ['ok' => true];
                }
                return ['ok' => false, 'reason' => self::desc($inv, 'forbidden after trigger')];
            case 'require_prior':
                if (!self::whenMatches($inv->get('when'), $ctx)) {
                    return ['ok' => true];
                }
                return $state->get('latched')->has($inv->get('id')) ? ['ok' => true] : ['ok' => false, 'reason' => self::desc($inv, 'required prior action not admitted')];
            case 'require_approval_over':
                if (!self::whenMatches($inv->get('when'), $ctx)) {
                    return ['ok' => true];
                }
                $a = Predicates::resolvePath($ctx, $inv->get('amount'));
                $av = $a['found'] ? self::fin($a['value']) : null;
                $thr = self::fin($inv->get('threshold'));
                $over = $av === null || $av < 0 || $av > $thr; // unresolvable => over
                if (!$over) {
                    return ['ok' => true];
                }
                return self::allHold($inv->get('approved'), $ctx) ? ['ok' => true] : ['ok' => false, 'reason' => self::desc($inv, 'approval required over ' . self::jsn($thr))];
        }
        return ['ok' => false, 'reason' => 'evaluation error (fail closed)'];
    }

    private static function structuralFail(string $id, string $reason): array
    {
        return ['ok' => false, 'violated' => [$id], 'reasons' => [$reason],
            'evaluated' => [Obj::of(['id' => $id, 'kind' => 'structural', 'result' => 'violated', 'reason' => $reason])]];
    }

    private static function actionOk(mixed $action): bool
    {
        $a = $action instanceof Obj ? $action->get('action') : null;
        return $a instanceof Obj && is_string($a->get('verb')) && is_string($a->get('resource'));
    }

    /**
     * Evaluate EVERY invariant (no short-circuit) against the action and running state. Pure, total, fail-closed. The whole constitution
     * is one document: every invariant and condition shares one regex budget.
     *
     * @return array{ok: bool, violated: list<string>, reasons: list<string>, evaluated: list<Obj>}
     */
    public static function check(mixed $action, mixed $constitution, mixed $state): array
    {
        try {
            return SafeRegex::withBudget(fn(): array => self::checkInner($action, $constitution, $state));
        } catch (\Throwable) {
            return self::structuralFail('<monitor>', 'monitor error (fail closed)');
        }
    }

    private static function checkInner(mixed $action, mixed $constitution, mixed $state): array
    {
        $cp = self::validateConstitution($constitution);
        if ($cp !== []) {
            return self::structuralFail('<constitution>', $cp[0]);
        }
        if (!self::actionOk($action)) {
            return self::structuralFail('<action>', 'malformed action');
        }
        $sp = self::stateProblem($state);
        if ($sp !== null) {
            return self::structuralFail('<state>', $sp);
        }
        $evaluated = [];
        foreach ($constitution->get('invariants') as $inv) {
            try {
                $r = self::evalOne($inv, $action, $state);
            } catch (\Throwable) {
                $r = ['ok' => false, 'reason' => 'evaluation error (fail closed)'];
            }
            $row = Obj::of(['id' => $inv->get('id'), 'kind' => $inv->get('kind'), 'result' => $r['ok'] ? 'pass' : 'violated']);
            if (isset($r['reason']) && $r['reason'] !== '') {
                $row->set('reason', $r['reason']);
            }
            $evaluated[] = $row;
        }
        $bad = array_values(array_filter($evaluated, static fn(Obj $e): bool => $e->get('result') === 'violated'));
        return ['ok' => $bad === [], 'violated' => array_map(static fn(Obj $e): string => $e->get('id'), $bad),
            'reasons' => array_map(static fn(Obj $e): string => $e->get('id') . ': ' . ($e->get('reason') ?? 'violated'), $bad), 'evaluated' => $evaluated];
    }

    /**
     * Pure, deterministic state transition for an ADMITTED action: `['ok' => true, 'state' => Obj]` or `['ok' => false, 'reason']`; never a
     * silently unchanged state (a dropped contribution would UNDER-count a cap). An omitted `$now` is the state's own time; an explicit null is refused (`clock regression`). Never throws.
     *
     * @return array{ok: bool, reason?: string, state?: Obj}
     */
    public static function advanceStrict(mixed $action, mixed $constitution, mixed $state, mixed $now = self::UNSET): array
    {
        try {
            if ($now === self::UNSET) { // TS default parameter: only an ABSENT `now` takes the state's time; an explicit null is refused
                $now = $state instanceof Obj ? $state->get('now') : null;
            }
            return SafeRegex::withBudget(fn(): array => self::advanceInner($action, $constitution, $state, $now));
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'advance error (fail closed)'];
        }
    }

    private static function advanceInner(mixed $action, mixed $constitution, mixed $state, mixed $nowIn): array
    {
        $cp = self::validateConstitution($constitution);
        if ($cp !== []) {
            return ['ok' => false, 'reason' => $cp[0]];
        }
        if (($sp = self::stateProblem($state)) !== null) {
            return ['ok' => false, 'reason' => $sp];
        }
        $now = self::fin($nowIn);
        if ($now === null || $now < self::fin($state->get('now'))) {
            return ['ok' => false, 'reason' => 'clock regression'];
        }
        if (!self::actionOk($action)) {
            return ['ok' => false, 'reason' => 'malformed action'];
        }
        $canon = self::canonicalState($state);
        $prevDigest = Pca::hashCanonical($canon);
        $actionDigest = Pca::hashCanonical($action);
        /** @var array<string, list<array{t: float, amount: float}>> $ledger */
        $ledger = [];
        foreach ($canon->get('ledger')->keys() as $k) {
            $ledger[$k] = self::entriesOf($canon, $k);
        }
        $latched = [];
        foreach ($canon->get('latched')->keys() as $k) {
            $latched[$k] = self::fin($canon->get('latched')->get($k));
        }
        foreach ($constitution->get('invariants') as $inv) {
            $id = $inv->get('id');
            switch ($inv->get('kind')) {
                case 'cap':
                case 'rate':
                    $prev = $ledger[$id] ?? [];
                    $ws = $inv->get('window_secs') === null ? null : self::fin($inv->get('window_secs'));
                    $lo = $ws === null ? -INF : $now - ($ws * 1000);
                    $kept = array_values(array_filter($prev, static fn(array $e): bool => $e['t'] > $lo));
                    if (self::whenMatches($inv->get('when'), $action)) {
                        $amount = 1.0;
                        if ($inv->get('kind') === 'cap') {
                            $r = Predicates::resolvePath($action, $inv->get('amount'));
                            $rv = $r['found'] ? self::fin($r['value']) : null;
                            if ($rv === null || $rv < 0) {
                                return ['ok' => false, 'reason' => "$id: amount unresolvable"];
                            }
                            $amount = $rv;
                        }
                        $kept[] = ['t' => $now, 'amount' => $amount];
                    }
                    usort($kept, [self::class, 'entryCmp']);
                    if (count($kept) > self::MAX_LEDGER) {
                        if ($inv->get('kind') === 'rate') {
                            return ['ok' => false, 'reason' => "$id: rate ledger overflow"];
                        }
                        while (count($kept) > self::MAX_LEDGER) {
                            $x = array_shift($kept);
                            $y = array_shift($kept);
                            array_unshift($kept, ['t' => $y['t'], 'amount' => $x['amount'] + $y['amount']]); // keeps the LATER time: a cap is never under-counted
                        }
                    }
                    if ($kept === []) {
                        unset($ledger[$id]);
                    } else {
                        $ledger[$id] = $kept;
                    }
                    break;
                case 'never_after': // conservative match: an ambiguous trigger latches (stricter)
                    if (!array_key_exists($id, $latched) && self::whenMatches($inv->get('after'), $action)) {
                        $latched[$id] = $now;
                    }
                    break;
                case 'require_prior': // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
                    if (!array_key_exists($id, $latched) && self::whenAffirmative($inv->get('prior'), $action)) {
                        $latched[$id] = $now;
                    }
                    break;
            }
        }
        $lg = new Obj();
        foreach ($ledger as $k => $es) {
            $lg->set((string)$k, self::entriesObj($es));
        }
        $lt = new Obj();
        foreach ($latched as $k => $t) {
            $lt->set((string)$k, self::num($t));
        }
        $nxt = Obj::of(['now' => self::num($now), 'seq' => self::num(self::fin($state->get('seq')) + 1),
            'parent' => Pca::hashCanonical(Obj::of(['d' => self::STATE_CHAIN_DOMAIN, 'state' => $prevDigest, 'action' => $actionDigest])),
            'ledger' => $lg, 'latched' => $lt]);
        if (self::stateProblem($nxt) !== null) {
            return ['ok' => false, 'reason' => 'resulting state invalid'];
        }
        return ['ok' => true, 'state' => $nxt];
    }

    /** advanceStrict that returns the INPUT state on failure (prefer the strict form wherever a no-op would be unsafe). */
    public static function advance(mixed $action, mixed $constitution, mixed $state, mixed $now = self::UNSET): mixed
    {
        $r = self::advanceStrict($action, $constitution, $state, $now);
        return $r['ok'] ? $r['state'] : $state;
    }

    // ---- per-action safety evidence ---------------------------------------------------------------------------------

    public static function proveSafety(mixed $action, mixed $constitution, mixed $state): Obj
    {
        return self::evidenceFrom(self::check($action, $constitution, $state), $action, $constitution, $state);
    }

    public static function evidenceFrom(array $r, mixed $action, mixed $constitution, mixed $state): Obj
    {
        $cid = self::errSafe(static fn(): string => self::constitutionId($constitution));
        $adg = self::errSafe(static fn(): string => Pca::hashCanonical($action));
        $sdg = self::errSafe(static fn(): string => self::stateDigest($state));
        $extra = [];
        if ($cid === self::UNHASHABLE) {
            $extra[] = '<constitution>';
        }
        if ($adg === self::UNHASHABLE) {
            $extra[] = '<action>';
        }
        if ($sdg === self::UNHASHABLE) {
            $extra[] = '<state>';
        }
        $now = $state instanceof Obj && self::fin($state->get('now')) !== null ? self::fin($state->get('now')) : 0.0;
        $violated = $r['violated'];
        foreach ($extra as $x) {
            if (!in_array($x, $r['violated'], true)) {
                $violated[] = $x;
            }
        }
        return Obj::of(['v' => self::num(self::EVIDENCE_VERSION), 'constitution' => $cid, 'action_digest' => $adg, 'state_digest' => $sdg, 'now' => self::num($now),
            'evaluated' => array_map(static fn(Obj $e): Obj => self::copyObj($e), $r['evaluated']), 'ok' => $r['ok'] && $extra === [], 'violated' => $violated]);
    }

    private static function copyObj(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    public static function evidenceDigest(Obj $e): string
    {
        return Pca::hashCanonical($e);
    }

    /** Offline re-check: recompute from (action, constitution, state); the evidence must match EXACTLY. Never throws. @return array{ok: bool, reason?: string} */
    public static function verifySafetyEvidence(mixed $evidence, mixed $action, mixed $constitution, mixed $state): array
    {
        try {
            if (!($evidence instanceof Obj) || self::fin($evidence->get('v')) !== 1.0) {
                return ['ok' => false, 'reason' => 'unsupported evidence version'];
            }
            $fresh = self::proveSafety($action, $constitution, $state);
            if ($fresh->get('constitution') !== $evidence->get('constitution')) {
                return ['ok' => false, 'reason' => 'constitution mismatch'];
            }
            if ($fresh->get('action_digest') !== $evidence->get('action_digest')) {
                return ['ok' => false, 'reason' => 'action digest mismatch'];
            }
            if ($fresh->get('state_digest') !== $evidence->get('state_digest')) {
                return ['ok' => false, 'reason' => 'state digest mismatch'];
            }
            if (Pca::hashCanonical($fresh) !== Pca::hashCanonical($evidence)) {
                return ['ok' => false, 'reason' => 'evidence does not reproduce'];
            }
            if ($fresh->get('ok') !== true) {
                return ['ok' => false, 'reason' => 'prohibition violated: ' . implode(',', $fresh->get('violated'))];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'verification error (fail closed)'];
        }
    }

    // ---- signed + bound safety evidence -----------------------------------------------------------------------------

    /** Binding id: commits to signer + evidence digest + the three bound digests. Throws only on unhashable evidence. */
    public static function safetyBindingId(Obj $evidence, string $signer): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::SAFETY_EVIDENCE_SIG_DOMAIN, 'signer' => $signer, 'evidence' => Pca::hashCanonical($evidence),
            'constitution' => $evidence->get('constitution'), 'action_digest' => $evidence->get('action_digest'), 'state_digest' => $evidence->get('state_digest')]));
    }

    /** Sign evidence (Ed25519, domain-separated). Refuses evidence that could not be digested. */
    public static function signSafetyEvidence(mixed $evidence, KeyPair $key): Obj
    {
        if (!($evidence instanceof Obj) || self::fin($evidence->get('v')) !== 1.0) {
            throw new \InvalidArgumentException('signSafetyEvidence: unsupported evidence');
        }
        foreach (['constitution', 'action_digest', 'state_digest'] as $k) {
            $d = $evidence->get($k);
            if (!is_string($d) || $d === '' || $d === self::UNHASHABLE) {
                throw new \InvalidArgumentException('signSafetyEvidence: unbound evidence');
            }
        }
        $id = self::safetyBindingId($evidence, $key->public);
        return Obj::of(['evidence' => $evidence, 'signer' => $key->public, 'id' => $id,
            'sig' => Pca::b64u($key->sign(self::domainMessage(self::SAFETY_EVIDENCE_SIG_DOMAIN, $id)))]);
    }

    /**
     * Verify signed evidence offline against what the verifier already knows (`$expected`: signer, action | actionDigest, constitution |
     * constitutionId, principal, state | stateDigest, requireOk). Never throws.
     *
     * @return array{ok: bool, reason?: string}
     */
    public static function verifySignedSafetyEvidence(mixed $signed, array $expected): array
    {
        $no = static fn(string $reason): array => ['ok' => false, 'reason' => $reason];
        try {
            if (!($signed instanceof Obj) || !($signed->get('evidence') instanceof Obj)) {
                return $no('malformed input');
            }
            $ev = $signed->get('evidence');
            if (self::fin($ev->get('v')) !== 1.0) {
                return $no('unsupported evidence version');
            }
            $signers = is_array($expected['signer'] ?? null) ? $expected['signer'] : [$expected['signer'] ?? null];
            foreach ($signers as $s) {
                if (!is_string($s) || $s === '') {
                    return $no('no pinned signer');
                }
            }
            if ($signers === [] || !is_string($signed->get('signer')) || !in_array($signed->get('signer'), $signers, true)) {
                return $no($signers === [] ? 'no pinned signer' : 'signer not trusted');
            }
            if (($expected['action'] ?? null) === null && ($expected['actionDigest'] ?? null) === null) {
                return $no('unbound: action not specified');
            }
            if (($expected['constitution'] ?? null) === null && ($expected['constitutionId'] ?? null) === null) {
                return $no('unbound: constitution not specified');
            }
            if (($expected['state'] ?? null) === null && ($expected['stateDigest'] ?? null) === null) {
                return $no('unbound: state not specified');
            }
            if (!is_string($signed->get('id')) || $signed->get('id') !== self::safetyBindingId($ev, $signed->get('signer'))) {
                return $no('binding id mismatch');
            }
            if (!is_string($signed->get('sig')) || !Pca::verifyEd25519B64u($signed->get('signer'), self::domainMessage(self::SAFETY_EVIDENCE_SIG_DOMAIN, $signed->get('id')), $signed->get('sig'))) {
                return $no('bad signature');
            }
            $wantAction = ($expected['action'] ?? null) === null ? $expected['actionDigest'] : Pca::hashCanonical($expected['action']);
            if (($expected['action'] ?? null) !== null && ($expected['actionDigest'] ?? null) !== null && $expected['actionDigest'] !== $wantAction) {
                return $no('expected action and digest disagree');
            }
            if ($ev->get('action_digest') !== $wantAction) {
                return $no('action digest mismatch (evidence bound to another action)');
            }
            if (($expected['principal'] ?? null) !== null) {
                $sc = $expected['constitution'] ?? null;
                if (!($sc instanceof Obj) || !is_string($sc->get('sig'))) {
                    return $no('principal pin requires a signed constitution');
                }
                $vc = self::verifyConstitution($sc, $expected['principal']);
                if (!$vc['ok']) {
                    return $no('constitution not authentic: ' . $vc['reason']);
                }
            }
            $wantConst = ($expected['constitution'] ?? null) === null ? $expected['constitutionId'] : self::constitutionId($expected['constitution']);
            if (($expected['constitution'] ?? null) !== null && ($expected['constitutionId'] ?? null) !== null && $expected['constitutionId'] !== $wantConst) {
                return $no('expected constitution and id disagree');
            }
            if ($ev->get('constitution') !== $wantConst) {
                return $no('constitution mismatch (evidence bound to another constitution)');
            }
            // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
            if (($expected['constitution'] ?? null) !== null && ($cp = self::validateConstitution($expected['constitution'])) !== []) {
                return $no('constitution malformed: ' . $cp[0]);
            }
            $wantState = ($expected['state'] ?? null) === null ? $expected['stateDigest'] : self::stateDigest($expected['state']);
            if (($expected['state'] ?? null) !== null && ($expected['stateDigest'] ?? null) !== null && $expected['stateDigest'] !== $wantState) {
                return $no('expected state and digest disagree');
            }
            if ($ev->get('state_digest') !== $wantState) {
                return $no('state digest mismatch (evidence bound to another state)');
            }
            if (!self::isList($ev->get('evaluated')) || !self::isList($ev->get('violated'))) {
                return $no('malformed evidence');
            }
            foreach ($ev->get('evaluated') as $r) {
                if ($r instanceof Obj && $r->has('id') && !is_string($r->get('id'))) {
                    return $no('malformed evidence');
                }
            }
            $badRows = array_filter($ev->get('evaluated'), static fn($r): bool => !($r instanceof Obj && $r->get('result') === 'pass'));
            if ($ev->get('ok') !== ($badRows === [] && $ev->get('violated') === [])) {
                return $no('evidence verdict inconsistent with rows');
            }
            if (($expected['action'] ?? null) !== null && ($expected['constitution'] ?? null) !== null && ($expected['state'] ?? null) !== null) {
                $full = self::verifySafetyEvidence($ev, $expected['action'], $expected['constitution'], $expected['state']);
                if (!$full['ok'] && $ev->get('ok') === true) {
                    return $no($full['reason'] ?? 'evidence does not reproduce');
                }
                if (!$full['ok'] && $ev->get('ok') !== true && isset($full['reason']) && !str_starts_with($full['reason'], 'prohibition violated')) {
                    return $no($full['reason']);
                }
            } elseif ($ev->get('ok') === true && ($expected['constitution'] ?? null) !== null) {
                $ids = array_map(static fn(Obj $i) => $i->get('id'), $expected['constitution']->get('invariants'));
                $rows = $ev->get('evaluated');
                if (count($rows) !== count($ids)) {
                    return $no('evidence does not cover every invariant');
                }
                foreach ($rows as $i => $r) {
                    if (!($r instanceof Obj) || $r->get('id') !== $ids[$i]) {
                        return $no('evidence does not cover every invariant');
                    }
                }
            }
            if (($expected['requireOk'] ?? null) !== false && $ev->get('ok') !== true) {
                return $no('prohibition violated: ' . implode(',', $ev->get('violated')));
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'verification error (fail closed)'];
        }
    }

    // ---- composition: permissions grant, prohibitions veto ----------------------------------------------------------

    public static function composeAuthority(mixed $permitted, mixed $action, mixed $constitution, mixed $state): array
    {
        return self::composeFrom($permitted, self::check($action, $constitution, $state));
    }

    public static function composeFrom(mixed $permitted, array $prohibition): array
    {
        $p = $permitted === true;
        return ['allow' => $p && $prohibition['ok'], 'decidedBy' => !$prohibition['ok'] ? 'prohibition' : ($p ? 'none' : 'permission'),
            'permitted' => $p, 'prohibition' => $prohibition];
    }

    /**
     * Pure kernel of the server's critical section: guard the head (CAS), compose authority, build evidence against the pre-state, and
     * on allow compute the next state. Persisting `next` iff allow MUST happen in the same atomic step that read `$state`.
     * `$opts`: `expectedSeq`, `expectedStateDigest`. Never throws.
     *
     * @return array{allow: bool, decidedBy: string, evidence: Obj, prohibition: array, next: mixed, reason?: string}
     */
    public static function checkAndAdvance(mixed $permitted, mixed $action, mixed $constitution, mixed $state, array $opts = []): array
    {
        $monitored = self::check($action, $constitution, $state);
        $evidence = self::evidenceFrom($monitored, $action, $constitution, $state);
        $decision = self::composeFrom($permitted, $monitored);
        $refuse = static function (string $by, ?string $reason = null) use ($evidence, $decision, $state): array {
            $r = ['allow' => false, 'decidedBy' => $by, 'evidence' => $evidence, 'prohibition' => $decision['prohibition'], 'next' => $state];
            if ($reason !== null && $reason !== '') {
                $r['reason'] = $reason;
            }
            return $r;
        };
        try {
            if (($opts['expectedSeq'] ?? null) !== null && (!($state instanceof Obj) || self::fin($state->get('seq')) !== (float)$opts['expectedSeq'])) {
                return $refuse('state', 'stale state head (seq)');
            }
            if (($opts['expectedStateDigest'] ?? null) !== null && self::errSafe(static fn(): string => self::stateDigest($state)) !== $opts['expectedStateDigest']) {
                return $refuse('state', 'stale state head (digest)');
            }
            if (!$decision['allow']) {
                return $refuse($decision['decidedBy'] === 'none' ? 'permission' : $decision['decidedBy']);
            }
            if ($evidence->get('ok') !== true) {
                return $refuse('prohibition', 'evidence not attestable');
            }
            $adv = self::advanceStrict($action, $constitution, $state);
            if (!$adv['ok']) {
                return $refuse('state', 'advance failed: ' . $adv['reason']);
            }
            return ['allow' => true, 'decidedBy' => 'none', 'evidence' => $evidence, 'prohibition' => $decision['prohibition'], 'next' => $adv['state']];
        } catch (\Throwable) {
            return $refuse('state', 'check-and-advance error (fail closed)');
        }
    }
}
