<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsRulesValidate.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Predicates.php';

/**
 * A platform's own business rules for one action, compiled into tighten rules and count accumulators (native port of business-rules.ts of
 * the reference actions package). Every compiled rule signals `escalate` or `deny`, never `allow`: a rule can only lower a decision.
 * Anything the evaluator cannot decide fires the rule (fail closed). Validation of a block is {@see ActionsRulesValidate}.
 */
final class ActionsRules
{
    public const RULE_DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
    public const RATE_PERIODS = ['hour' => 3600000, 'day' => 86400000];
    public const MAX_RULE_CURRENCIES = 32;
    public const MAX_RULE_LIST = 64;
    public const MAX_RULE_APPROVERS = 16;
    public const MAX_RULE_EXAMPLES = 32;
    public const BUSINESS_RULES_DOMAIN = 'atlas-pca/action-business-rules/v1';
    public const RULES_REVIEW_DOMAIN = 'atlas-pca/action-rules-review/v1';
    public const DEFAULT_EXAMPLE_AT = '2026-01-07T15:00:00Z';
    public const BUSINESS_RULE_LINTS = [
        ['LR-001', 'error', 'a rules block is malformed or names a parameter the action does not have'],
        ['LR-002', 'error', 'a contradiction: under the rules the action can never be allowed'],
        ['LR-003', 'warning', 'a rule that can never fire or that another rule already covers'],
        ['LR-004', 'error', 'a rules example does not decide as it expects'],
    ];
    private const DEC_RE = '/\A(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?\z/';
    private const AT_RE = '/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/';
    private const DAY_NAMES = ['sun' => 'Sun', 'mon' => 'Mon', 'tue' => 'Tue', 'wed' => 'Wed', 'thu' => 'Thu', 'fri' => 'Fri', 'sat' => 'Sat'];
    private const DECISION_RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];

    private static function bad(string $msg): never
    {
        throw new ActionKitError('bad_rules', $msg);
    }

    private static function n(int|float $x): Num
    {
        return new Num((string)$x);
    }

    private static function isi(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && fmod($f, 1.0) == 0.0 && abs($f) <= 9007199254740991.0;
    }

    private static function negZero(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && $f == 0.0 && fdiv(1.0, $f) < 0;
    }

    /** @return list<string> the names of the params with this role, in UTF-16 order */
    private static function byRole(Obj $d, mixed $role): array
    {
        $hits = [];
        foreach ($d->get('params')->keys() as $n) {
            if ($d->get('params')->get($n)->get('role') === $role) {
                $hits[] = $n;
            }
        }
        usort($hits, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        return $hits;
    }

    /**
     * The parameter a reference names ({param} or {role}), with its definition. Throws bad_rules for none or several.
     *
     * @return array{name:string,p:Obj}
     */
    public static function resolveParamRef(Obj $d, mixed $r, string $at): array
    {
        if (!($r instanceof Obj)) {
            self::bad("$at: name a parameter ({param} or {role})");
        }
        $hasP = is_string($r->get('param'));
        $hasR = is_string($r->get('role'));
        if ($hasP === $hasR) {
            self::bad("$at: give exactly one of param or role");
        }
        if ($hasP) {
            $p = $d->get('params')->get($r->get('param'));
            if ($p === null) {
                self::bad("$at: '" . $d->get('verb') . "' has no parameter '" . IntentWb::jsStr($r->get('param')) . "'");
            }
            return ['name' => $r->get('param'), 'p' => $p];
        }
        $hits = self::byRole($d, $r->get('role'));
        if (count($hits) !== 1) {
            self::bad("$at: '" . $d->get('verb') . "' has " . (!$hits ? 'no' : 'several') . ' parameter' . (!$hits ? '' : 's') . ' with role ' . IntentWb::jsStr($r->get('role')));
        }
        return ['name' => $hits[0], 'p' => $d->get('params')->get($hits[0])];
    }

    /**
     * The money parameters of an action: {amount, exp, ccy: {literal} | {param}}.
     *
     * @return array{amount:string,exp:mixed,ccy:array<string,string>}
     */
    public static function moneyOf(Obj $d): array
    {
        $hits = self::byRole($d, 'money.amount');
        $verb = $d->get('verb');
        if (count($hits) !== 1) {
            self::bad("'$verb' needs exactly one parameter with role money.amount for an amount or approval-above rule (has " . count($hits) . ')');
        }
        $name = $hits[0];
        $p = $d->get('params')->get($name);
        if ($p->get('type') !== 'integer') {
            self::bad("'$verb': the money.amount parameter '$name' must be an integer");
        }
        $u = $p->get('unit');
        if ($u === null || $u->get('kind') !== 'money') {
            self::bad("'$verb': the amount parameter '$name' declares no money unit (its currency)");
        }
        if (is_string($u->get('ccy'))) {
            return ['amount' => $name, 'exp' => $u->get('exp'), 'ccy' => ['literal' => $u->get('ccy')]];
        }
        $frm = $u->get('ccy')->get('from');
        if (!$d->get('params')->has($frm)) {
            self::bad("'$verb': the currency parameter '$frm' does not exist");
        }
        return ['amount' => $name, 'exp' => $u->get('exp'), 'ccy' => ['param' => $frm]];
    }

    /** Integer minor units of a money value under exponent $exp. Throws bad_rules for a non-integer or over-precise value. */
    public static function minorUnits(mixed $v, mixed $exp, string $at): int
    {
        if (Js::isNum($v)) {
            if (!self::isi($v) || Js::num($v) < 0 || self::negZero($v)) {
                self::bad("$at: an amount is a non-negative integer of minor units, or a decimal string");
            }
            return (int)Js::num($v);
        }
        if (!is_string($v)) {
            self::bad("$at: an amount is a number of minor units or a decimal string");
        }
        if (preg_match(self::DEC_RE, $v, $m) !== 1) {
            self::bad("$at: '$v' is not a decimal amount");
        }
        $e = Js::num($exp);
        if ($e === null || !is_finite($e) || $e < 0 || $e > 18 || fmod($e, 1.0) != 0.0) {
            self::bad("$at: the currency exponent is not a small integer");
        }
        $ex = (int)$e;
        $frac = $m[2] ?? '';
        if (strlen($frac) > $ex) {
            self::bad("$at: '$v' has more decimals than the currency's $ex");
        }
        $n = (float)$m[1] * (10.0 ** $ex) + (float)(int)str_pad($frac, $ex, '0');
        if ($n > 9007199254740991.0) {
            self::bad("$at: '$v' is too large");
        }
        return (int)$m[1] * (10 ** $ex) + (int)str_pad($frac, $ex, '0');
    }

    private static function mins(string $hhmm): int
    {
        return (int)substr($hhmm, 0, 2) * 60 + (int)substr($hhmm, 3, 2);
    }

    /** Is this a time zone the runtime knows (IANA name)? */
    public static function knownTimeZone(mixed $tz): bool
    {
        return ActionsRulesValidate::knownZone($tz);
    }

    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    /** Date.parse of an RFC 3339 `...Z` second-precision time: day 1..31 rolls over the month, 24:00:00 is the next day; else null (NaN). */
    public static function parseUtcMs(mixed $s): ?int
    {
        if (!is_string($s) || preg_match(self::AT_RE, $s) !== 1) {
            return null;
        }
        [$y, $mo, $d, $h, $mi, $se] = [(int)substr($s, 0, 4), (int)substr($s, 5, 2), (int)substr($s, 8, 2), (int)substr($s, 11, 2), (int)substr($s, 14, 2), (int)substr($s, 17, 2)];
        if (!($mo >= 1 && $mo <= 12 && $d >= 1 && $d <= 31 && $mi <= 59 && $se <= 59 && ($h <= 23 || ($h === 24 && $mi === 0 && $se === 0)))) {
            return null;
        }
        return (self::daysFromCivil($y, $mo, 1) + $d - 1) * 86400000 + $h * 3600000 + $mi * 60000 + $se * 1000;
    }

    /** Null iff $rules is a well-formed rules block for $d; the reason otherwise. */
    public static function businessRulesError(Obj $d, mixed $rules): ?string
    {
        return ActionsRulesValidate::error($d, $rules);
    }

    private static function validate(Obj $d, mixed $rules): void
    {
        $e = ActionsRulesValidate::error($d, $rules);
        if ($e !== null) {
            self::bad($e);
        }
    }

    // ---- compiled form -----------------------------------------------------------------------------------------------------

    /** Digest of a rules block (examples are tests, not rules). */
    public static function businessRulesDigest(string $verb, Obj $rules): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::BUSINESS_RULES_DOMAIN, 'verb' => $verb, 'rules' => $rules->without('examples')]));
    }

    private static function p(string $n): string
    {
        return 'action.params.' . $n;
    }

    private static function leaf(string $field, string $op, mixed $value): Obj
    {
        return Obj::of(['field' => $field, 'op' => $op, 'value' => $value]);
    }

    private static function ccyCond(array $m, string $c): ?Obj
    {
        if (isset($m['ccy']['param'])) {
            return self::leaf(self::p($m['ccy']['param']), 'eq', $c);
        }
        return $m['ccy']['literal'] === $c ? null : self::leaf('action.verb', 'eq', "\u{0}never");
    }

    /** @param list<?Obj> $cs */
    private static function and(array $cs): Obj
    {
        $xs = array_values(array_filter($cs, static fn($c) => $c !== null));
        return count($xs) === 1 ? $xs[0] : Obj::of(['all_of' => $xs]);
    }

    private static function always(string $verb): Obj
    {
        return self::leaf('action.verb', 'eq', $verb);
    }

    private static function ruleId(string $s): string
    {
        return substr((string)preg_replace('/[^a-z0-9_]/', '_', mb_strtolower($s)), 0, 64);
    }

    /** `12345` minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale). */
    public static function formatMoney(int $minor, string $ccy, int $exp): string
    {
        $s = str_pad((string)$minor, $exp + 1, '0', STR_PAD_LEFT);
        return ($exp > 0 ? substr($s, 0, -$exp) . '.' . substr($s, -$exp) : $s) . " $ccy";
    }

    private static function hoursText(Obj $h): string
    {
        $ds = $h->get('days');
        usort($ds, static fn($a, $b): int => array_search($a, self::RULE_DAYS, true) <=> array_search($b, self::RULE_DAYS, true));
        $idx = array_map(static fn($x) => array_search($x, self::RULE_DAYS, true), $ds);
        $run = count($idx) > 2;
        foreach ($idx as $k => $x) {
            $run = $run && ($k === 0 || $x === $idx[$k - 1] + 1);
        }
        $days = $run ? self::DAY_NAMES[$ds[0]] . '-' . self::DAY_NAMES[$ds[count($ds) - 1]] : implode(', ', array_map(static fn($x) => self::DAY_NAMES[$x], $ds));
        return $days . ' ' . $h->get('from') . '-' . $h->get('to') . ' (' . $h->get('tz') . ')';
    }

    private static function recipientsText(Obj $x): string
    {
        return implode(' or ', array_merge(array_map(static fn($dm) => "addresses at $dm", $x->get('domains') ?? []), $x->get('addresses') ?? []));
    }

    private static function refOf(Obj $s): Obj
    {
        return $s->has('param') ? Obj::of(['param' => $s->get('param')]) : Obj::of(['role' => $s->get('role')]);
    }

    /** @param list<string> $xs @return list<string> */
    private static function u16(array $xs): array
    {
        usort($xs, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        return $xs;
    }

    /** Compile a rules block for $d into tighten rules and accumulators. Throws bad_rules for a malformed block. Deterministic. */
    public static function compileBusinessRules(Obj $d, mixed $rules): Obj
    {
        self::validate($d, $rules);
        $t = [];
        $acc = [];
        $out = Obj::of(['v' => self::n(1), 'verb' => $d->get('verb'), 'rules_digest' => self::businessRulesDigest($d->get('verb'), $rules), 'def_digest' => Actions::defDigest($d)]);
        $ap0 = $rules->get('approval');
        $money = $rules->has('amount') || ($ap0 instanceof Obj && $ap0->has('above')) ? self::moneyOf($d) : null;
        $unlisted = static function (array $listed) use ($money, $d): ?Obj {
            if ($money === null) {
                return null;
            }
            if (isset($money['ccy']['param'])) {
                return Obj::of(['not' => self::leaf(self::p($money['ccy']['param']), 'in', $listed)]);
            }
            return in_array($money['ccy']['literal'], $listed, true) ? null : self::always($d->get('verb'));
        };
        $rule = static fn(string $id, Obj $when, string $signal, string $reason): Obj => Obj::of(['id' => $id, 'when' => $when, 'signal' => $signal, 'reason' => $reason]);

        if ($rules->has('amount')) {
            $listed = self::u16($rules->get('amount')->get('max')->keys());
            foreach ($listed as $c) {
                $mx = self::minorUnits($rules->get('amount')->get('max')->get($c), $money['exp'], 'rules.amount.max.' . $c);
                $t[] = $rule(self::ruleId('amount_max_' . $c), self::and([self::ccyCond($money, $c), self::leaf(self::p($money['amount']), 'gt', self::n($mx))]), 'deny',
                    'the amount is above the ' . self::formatMoney($mx, $c, (int)Js::num($money['exp'])) . ' ceiling');
            }
            $u = $unlisted($listed);
            if ($u) {
                $t[] = $rule('amount_currency', $u, 'deny', 'only ' . implode(', ', $listed) . ' amounts are allowed');
            }
        }
        if ($rules->has('approval')) {
            $ap = $rules->get('approval');
            $out->set('approval', Obj::of(['approvers' => $ap->get('approvers') ?? self::n(1)]));
            if ($ap->has('group')) {
                $out->get('approval')->set('group', $ap->get('group'));
            }
            if (Js::truthy($ap->get('always'))) {
                $t[] = $rule('approval_always', self::always($d->get('verb')), 'escalate', 'this action always needs approval');
            } else {
                $listed = self::u16($ap->get('above')->keys());
                foreach ($listed as $c) {
                    $x = self::minorUnits($ap->get('above')->get($c), $money['exp'], 'rules.approval.above.' . $c);
                    $t[] = $rule(self::ruleId('approval_above_' . $c), self::and([self::ccyCond($money, $c), self::leaf(self::p($money['amount']), 'gt', self::n($x))]), 'escalate',
                        'amounts above ' . self::formatMoney($x, $c, (int)Js::num($money['exp'])) . ' need approval');
                }
                $u = $unlisted($listed);
                if ($u) {
                    $t[] = $rule('approval_currency', $u, 'escalate', 'amounts in a currency other than ' . implode(', ', $listed) . ' need approval');
                }
            }
        }
        foreach ($rules->get('scope') ?? [] as $i => $s) {
            $name = self::resolveParamRef($d, self::refOf($s), "rules.scope[$i]")['name'];
            // `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
            $t[] = $rule("scope_$i", Obj::of(['not' => Obj::of(['field' => self::p($name), 'op' => 'eq', 'ref' => 'subject.' . $s->get('caller')])]), 'deny',
                "$name must be the caller's own " . $s->get('caller'));
        }
        foreach ($rules->get('rate') ?? [] as $i => $r) {
            $rid = "rate_$i";
            $by = $r->get('by') ?? 'principal';
            $mx = $r->get('max');
            $acc[] = Obj::of(['id' => $rid, 'agg' => 'count', 'sel' => Obj::of(['verbs' => [$d->get('verb')]]),
                'win' => Obj::of(['kind' => 'sliding', 'ms' => self::n(self::RATE_PERIODS[$r->get('per')])]), 'key' => null, 'domain_max' => $mx, 'cap' => $mx,
                'holder' => Obj::of(['kind' => 'site_local']), 'scope' => $by]);
            $t[] = $rule($rid, self::leaf('env.acc.' . $rid, 'gte', $mx), 'deny', 'at most ' . (int)Js::num($mx) . ' per ' . $r->get('per') . " per $by");
        }
        if ($rules->has('hours')) {
            $h = $rules->get('hours');
            $frm = self::mins($h->get('from'));
            $to = self::mins($h->get('to'));
            $dows = array_map(static fn($x) => array_search($x, self::RULE_DAYS, true), $h->get('days'));
            sort($dows);
            $nums = static fn(array $xs): array => array_map(static fn($x) => self::n($x), $xs);
            $min = static fn(string $op, int $v): Obj => self::leaf('env.clock.min', $op, self::n($v));
            if ($frm < $to) {
                $inTime = Obj::of(['all_of' => [$min('gte', $frm), $min('lt', $to)]]);
                $day = self::leaf('env.clock.dow', 'in', $nums($dows));
            } else {
                // an overnight window (22:00-06:00): the day named is the day the window starts
                $inTime = Obj::of(['any_of' => [$min('gte', $frm), $min('lt', $to)]]);
                $day = Obj::of(['any_of' => [
                    Obj::of(['all_of' => [self::leaf('env.clock.dow', 'in', $nums($dows)), $min('gte', $frm)]]),
                    Obj::of(['all_of' => [self::leaf('env.clock.dow', 'in', $nums(array_map(static fn($x) => ($x + 1) % 7, $dows))), $min('lt', $to)]]),
                ]]);
            }
            $out->set('clock_tz', $h->get('tz'));
            $t[] = $rule('hours', Obj::of(['not' => Obj::of(['all_of' => [$day, $inTime]])]), $h->get('outside') ?? 'escalate', 'outside ' . self::hoursText($h));
        }
        if ($rules->has('recipients')) {
            $x = $rules->get('recipients');
            $res = self::resolveParamRef($d, self::refOf($x), 'rules.recipients');
            $name = $res['name'];
            $p = $res['p'];
            $okAt = static function (string $path) use ($x): Obj {
                $alts = array_map(static fn($dm) => self::leaf($path, 'like', '*@' . preg_replace_callback('/[\\\\*?]/', static fn($m) => '\\' . $m[0], $dm)), $x->get('domains') ?? []);
                if ($x->get('addresses') !== null) {
                    $alts[] = self::leaf($path, 'in', self::u16($x->get('addresses')));
                }
                return Obj::of(['any_of' => $alts]);
            };
            if ($p->get('type') === 'string') {
                $ok = $okAt(self::p($name));
            } else {
                $n = (int)Js::num($p->get('max_items'));
                $all = [];
                for ($i = 0; $i < $n; $i++) {
                    $all[] = Obj::of(['any_of' => [self::leaf(self::p("$name.$i"), 'exists', false), $okAt(self::p("$name.$i"))]]);
                }
                $all[] = self::leaf(self::p("$name.$n"), 'exists', false);
                $ok = Obj::of(['all_of' => $all]);
            }
            $t[] = $rule('recipients', Obj::of(['not' => $ok]), 'deny', "$name may only name " . self::recipientsText($x));
        }
        foreach ($rules->get('required') ?? [] as $i => $n) {
            $pr = $d->get('params')->get($n);
            $missing = $pr->get('type') === 'string'
                ? Obj::of(['any_of' => [self::leaf(self::p($n), 'exists', false), self::leaf(self::p($n), 'eq', '')]])
                : self::leaf(self::p($n), 'exists', false);
            $t[] = $rule("required_$i", $missing, 'deny', "$n is required");
        }
        foreach ($t as $r) {
            $reason = $r->get('reason');
            if (Js::len($reason) > 256) {
                $u = (string)mb_convert_encoding($reason, 'UTF-16LE', 'UTF-8');
                $r->set('reason', (string)mb_convert_encoding(substr($u, 0, 253 * 2), 'UTF-8', 'UTF-16LE') . '...');
            }
        }
        $out->set('tighten', $t);
        $out->set('accumulators', $acc);
        return $out;
    }

    // ---- evaluation --------------------------------------------------------------------------------------------------------

    /** Meet in the order deny < escalate < allow. */
    public static function meetDecision(string $a, string $b): string
    {
        return self::DECISION_RANK[$a] <= self::DECISION_RANK[$b] ? $a : $b;
    }

    /**
     * Day of week (0 = Sunday) and minute of day at $now (ms since the epoch) in $tz, or null when it cannot be computed.
     *
     * @return array{dow:int,min:int}|null
     */
    public static function clockAt(mixed $now, mixed $tz): ?array
    {
        $f = Js::num($now);
        $name = ActionsRulesValidate::canonicalZone($tz);
        if ($f === null || !is_finite($f) || $name === null) {
            return null;
        }
        try {
            $dt = (new \DateTimeImmutable('@' . (string)(int)floor(((int)$f) / 1000)))->setTimezone(new \DateTimeZone($name));
            return ['dow' => (int)$dt->format('w'), 'min' => (int)$dt->format('G') * 60 + (int)$dt->format('i')];
        } catch (\Throwable) {
            return null;
        }
    }

    /** The predicate context the compiled rules are evaluated in: verifier-computed `env` members only. */
    public static function rulesContext(Obj $c, Obj $i): Obj
    {
        $env = new Obj();
        if ($c->get('clock_tz') !== null) {
            $k = self::clockAt($i->get('now'), $c->get('clock_tz'));
            if ($k) {
                $env->set('clock', Obj::of(['dow' => self::n($k['dow']), 'min' => self::n($k['min'])]));
            }
        }
        $acc = new Obj();
        $counts = $i->get('counts');
        foreach ($c->get('accumulators') as $a) {
            $n = $counts instanceof Obj ? $counts->get($a->get('id')) : null;
            if (self::isi($n) && Js::num($n) >= 0) {
                $acc->set($a->get('id'), $n);
            }
        }
        $env->set('acc', $acc);
        return Obj::of(['action' => Obj::of(['verb' => $c->get('verb'), 'resource' => $i->get('resource') ?? '', 'params' => $i->get('params')]),
            'subject' => $i->get('subject') ?? new Obj(), 'env' => $env]);
    }

    /**
     * Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never throws.
     *
     * @return array<string,mixed>
     */
    public static function evaluateBusinessRules(Obj $c, Obj $i): array
    {
        try {
            $ctx = self::rulesContext($c, $i);
            $decision = 'allow';
            $reasons = [];
            $fired = [];
            $approval = false;
            if (!is_array($c->get('tighten'))) {
                throw new \TypeError('c.tighten is not iterable'); // the reference's text reaches the fail-closed reason
            }
            foreach ($c->get('tighten') as $r) {
                if (Predicates::evaluateConditionTri($r->get('when'), $ctx) === 'false') {
                    continue;
                }
                $decision = self::meetDecision($decision, $r->get('signal'));
                $fired[] = $r->get('id');
                $reasons[] = $r->get('id') . ': ' . ($r->get('reason') ?? $r->get('signal'));
                if ($r->get('signal') === 'escalate' && str_starts_with($r->get('id'), 'approval_')) {
                    $approval = true;
                }
            }
            $out = ['decision' => $decision, 'reasons' => $reasons, 'fired' => $fired];
            if ($approval && Js::truthy($c->get('approval'))) {
                $out['approval'] = $c->get('approval');
            }
            return $out;
        } catch (\Throwable $e) {
            return ['decision' => 'deny', 'reasons' => ['rules: evaluation error (fail closed): ' . $e->getMessage()], 'fired' => []];
        }
    }

    /** The decision with rules applied to a base decision: the meet, so rules never raise it. @param array{decision:string} $v */
    public static function withBusinessRules(string $base, array $v): string
    {
        return self::meetDecision($base, $v['decision']);
    }

    /** Run a rules block's examples. @return list<array<string,mixed>> */
    public static function runRuleExamples(Obj $d, mixed $rules): array
    {
        $c = self::compileBusinessRules($d, $rules);
        $out = [];
        foreach ($rules->get('examples') ?? [] as $index => $e) {
            $counts = new Obj();
            foreach ($c->get('accumulators') as $k => $a) {
                $recent = $e->get('recent');
                $counts->set($a->get('id'), $recent instanceof Obj && $recent->has((string)$k) ? $recent->get((string)$k) : self::n(0));
            }
            $ms = self::parseUtcMs($e->has('at') ? $e->get('at') : self::DEFAULT_EXAMPLE_AT);
            $inp = Obj::of(['params' => $e->get('params'), 'now' => $ms === null ? null : self::n($ms), 'counts' => $counts]);
            if ($e->get('caller') !== null) {
                $inp->set('subject', $e->get('caller'));
            }
            $v = self::evaluateBusinessRules($c, $inp);
            $out[] = ['index' => $index, 'expect' => $e->get('expect'), 'got' => $v['decision'], 'ok' => $v['decision'] === $e->get('expect'), 'why' => implode('; ', $v['reasons']) ?: 'no rule fired'];
        }
        return $out;
    }

    /** One plain sentence per rule, for the policy card and the dashboard. Throws bad_rules for a malformed block. @return list<string> */
    public static function explainBusinessRules(Obj $d, mixed $rules): array
    {
        self::validate($d, $rules);
        $out = [];
        $ap0 = $rules->get('approval');
        $m = $rules->has('amount') || ($ap0 instanceof Obj && $ap0->has('above')) ? self::moneyOf($d) : null;
        $lst = static function (Obj $mp) use ($m): string {
            return implode(', ', array_map(static fn($c) => self::formatMoney(self::minorUnits($mp->get($c), $m['exp'], $c), $c, (int)Js::num($m['exp'])), self::u16($mp->keys())));
        };
        if ($rules->has('amount')) {
            $out[] = 'Refuses amounts above ' . $lst($rules->get('amount')->get('max')) . '; any other currency is refused.';
        }
        if ($rules->has('approval')) {
            $ap = $rules->get('approval');
            $n = $ap->get('approvers') !== null ? (int)Js::num($ap->get('approvers')) : 1;
            $who = "$n approver" . ($n === 1 ? '' : 's') . ($ap->get('group') ? ' from the ' . $ap->get('group') . ' group' : '');
            $out[] = Js::truthy($ap->get('always')) ? "Always needs approval by $who." : "Needs approval by $who when the amount is above " . $lst($ap->get('above')) . ' (or in another currency).';
        }
        foreach ($rules->get('scope') ?? [] as $s) {
            $name = self::resolveParamRef($d, self::refOf($s), 'rules.scope')['name'];
            $out[] = "Only the caller's own records: $name must be the caller's " . $s->get('caller') . '.';
        }
        foreach ($rules->get('rate') ?? [] as $r) {
            $out[] = 'At most ' . (int)Js::num($r->get('max')) . ' per ' . $r->get('per') . ' per ' . ($r->get('by') === 'org' ? 'organisation' : 'principal') . '.';
        }
        if ($rules->has('hours')) {
            $out[] = 'Only ' . self::hoursText($rules->get('hours')) . '; outside those hours it ' . ($rules->get('hours')->get('outside') === 'deny' ? 'is refused' : 'needs approval') . '.';
        }
        if ($rules->has('recipients')) {
            $x = $rules->get('recipients');
            $name = self::resolveParamRef($d, self::refOf($x), 'rules.recipients')['name'];
            $out[] = "$name may only name " . self::recipientsText($x) . '.';
        }
        if ($rules->has('required')) {
            $out[] = 'Requires ' . implode(', ', $rules->get('required')) . '.';
        }
        return $out;
    }

    // ---- lint (contradictions and dead rules) ------------------------------------------------------------------------------

    /** Lint one action's rules. @return list<array<string,mixed>> */
    public static function lintBusinessRules(Obj $d, mixed $rules): array
    {
        $f = static fn(string $rule, string $severity, string $message): array => ['rule' => $rule, 'severity' => $severity, 'verb' => $d->get('verb'), 'message' => $message];
        $e = self::businessRulesError($d, $rules);
        if ($e) {
            return [$f('LR-001', 'error', $e)];
        }
        $r = $rules;
        $out = [];
        $ap0 = $r->get('approval');
        $m = $r->has('amount') || ($ap0 instanceof Obj && $ap0->has('above')) ? self::moneyOf($d) : null;
        $amt = $m ? $d->get('params')->get($m['amount']) : null;
        $ccyValues = null;
        if ($m) {
            $ccyValues = isset($m['ccy']['param']) ? $d->get('params')->get($m['ccy']['param'])->get('values') : [$m['ccy']['literal']];
        }
        $exp = $m ? (int)Js::num($m['exp']) : 0;
        if ($r->has('amount') && $m) {
            $listed = $r->get('amount')->get('max')->keys();
            if ($ccyValues !== null && count(array_filter($ccyValues, static fn($c) => in_array($c, $listed, true))) === 0) {
                $out[] = $f('LR-002', 'error', "rules.amount: none of the action's currencies (" . implode(', ', $ccyValues) . ') has a ceiling, so every call is refused');
            }
            foreach ($listed as $c) {
                $mx = self::minorUnits($r->get('amount')->get('max')->get($c), $m['exp'], $c);
                if ($ccyValues !== null && !in_array($c, $ccyValues, true)) {
                    $out[] = $f('LR-003', 'warning', "rules.amount.max.$c: the action never uses $c");
                }
                if ($amt !== null && $amt->get('min') !== null && $mx < Js::num($amt->get('min'))) {
                    $out[] = $f('LR-002', 'error', "rules.amount.max.$c: the ceiling " . self::formatMoney($mx, $c, $exp) . " is below the parameter's minimum, so every $c call is refused");
                }
                if ($amt !== null && $amt->get('max') !== null && $mx >= Js::num($amt->get('max'))) {
                    $out[] = $f('LR-003', 'warning', "rules.amount.max.$c: the parameter's own maximum already bounds the amount below this ceiling");
                }
            }
        }
        if ($ap0 instanceof Obj && $ap0->has('above') && $m) {
            foreach ($ap0->get('above')->keys() as $c) {
                $x = self::minorUnits($ap0->get('above')->get($c), $m['exp'], $c);
                $ceil = $r->has('amount') ? $r->get('amount')->get('max')->get($c) : null;
                if ($ceil !== null && $x >= self::minorUnits($ceil, $m['exp'], $c)) {
                    $out[] = $f('LR-003', 'warning', "rules.approval.above.$c: above the amount ceiling, so the approval can never be asked for");
                }
                if ($r->has('amount') && $ceil === null) {
                    $out[] = $f('LR-003', 'warning', "rules.approval.above.$c: $c has no ceiling, so it is always refused before an approval");
                }
            }
        }
        if ($r->has('hours') && $r->get('hours')->get('from') === $r->get('hours')->get('to')) {
            $h = $r->get('hours');
            $out[] = $f('LR-002', 'error', 'rules.hours: the window ' . $h->get('from') . '-' . $h->get('to') . ' is empty, so the action is ' . ($h->get('outside') === 'deny' ? 'always refused' : 'always escalated'));
        }
        if ($r->has('required')) {
            foreach ($r->get('required') as $n) {
                if ($d->get('params')->get($n)->get('required') !== false && $d->get('params')->get($n)->get('type') !== 'string') {
                    $out[] = $f('LR-003', 'warning', "rules.required: '$n' is already required by the definition");
                }
            }
        }
        if ($r->has('rate')) {
            $seen = [];
            foreach ($r->get('rate') as $x) {
                $k = $x->get('per') . '|' . ($x->get('by') ?? 'principal');
                $mx = (int)Js::num($x->get('max'));
                if (isset($seen[$k])) {
                    $out[] = $f('LR-003', 'warning', 'rules.rate: two limits per ' . $x->get('per') . ' per ' . ($x->get('by') ?? 'principal') . '; only the lower (' . min($seen[$k], $mx) . ') matters');
                }
                $seen[$k] = min($seen[$k] ?? PHP_INT_MAX, $mx);
            }
            $h = $seen['hour|principal'] ?? null;
            $dd = $seen['day|principal'] ?? null;
            if ($h !== null && $dd !== null && $dd <= $h) {
                $out[] = $f('LR-003', 'warning', 'rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires');
            }
        }
        try {
            foreach (self::runRuleExamples($d, $r) as $x) {
                if (!$x['ok']) {
                    $out[] = $f('LR-004', 'error', 'rules.examples[' . $x['index'] . ']: expected ' . $x['expect'] . ', got ' . $x['got'] . ' (' . $x['why'] . ')');
                }
            }
        } catch (\Throwable $err) {
            $out[] = $f('LR-001', 'error', $err->getMessage());
        }
        return $out;
    }

    // ---- semantic diff of rules (widening needs a reviewer) ----------------------------------------------------------------

    /** @param list<mixed> $a @param list<mixed> $b */
    private static function setRel(array $a, array $b): string
    {
        $aInB = array_filter($a, static fn($x) => !in_array($x, $b, true)) === [];
        $bInA = array_filter($b, static fn($x) => !in_array($x, $a, true)) === [];
        return $aInB && $bInA ? 'eq' : ($bInA ? 'narrow' : ($aInB ? 'widen' : 'inc'));
    }

    private static function numRel(float $a, float $b): string
    {
        return $a == $b ? 'eq' : ($b < $a ? 'narrow' : 'widen');
    }

    /** Presence relation of an optional block, or null when both are present. */
    private static function presence(bool $a, bool $b): ?string
    {
        return !$a && !$b ? 'eq' : (!$a ? 'narrow' : (!$b ? 'widen' : null));
    }

    /** @param list<string> $rs */
    private static function combine(array $rs): string
    {
        $has = static fn(string $x): bool => in_array($x, $rs, true);
        return $has('inc') || ($has('narrow') && $has('widen')) ? 'inc' : ($has('widen') ? 'widen' : ($has('narrow') ? 'narrow' : 'eq'));
    }

    private static function flip(string $r): string
    {
        return $r === 'narrow' ? 'widen' : ($r === 'widen' ? 'narrow' : $r);
    }

    /** @return array<int,true> */
    private static function minutesOfWeek(Obj $h): array
    {
        $s = [];
        $frm = self::mins($h->get('from'));
        $to = self::mins($h->get('to'));
        foreach ($h->get('days') as $day) {
            $base = array_search($day, self::RULE_DAYS, true) * 1440;
            if ($frm < $to) {
                for ($x = $frm; $x < $to; $x++) {
                    $s[$base + $x] = true;
                }
            } elseif ($frm > $to) {
                for ($x = $frm; $x < 1440; $x++) {
                    $s[$base + $x] = true;
                }
                for ($x = 0; $x < $to; $x++) {
                    $s[(($base + 1440) % 10080) + $x] = true;
                }
            }
        }
        return $s;
    }

    /**
     * The semantic diff of two rules blocks of one action (either may be absent): {class, reasons}. Conservative: unordered = incomparable.
     *
     * @return array{class:string,reasons:list<string>}
     */
    public static function diffBusinessRules(Obj $d, mixed $prev, mixed $next): array
    {
        // a value that is not an object has none of the rule members (the reference reads them as undefined)
        $o = $prev instanceof Obj ? $prev : new Obj();
        $n = $next instanceof Obj ? $next : new Obj();
        $ab = static fn(Obj $x): bool => $x->get('approval') instanceof Obj && $x->get('approval')->has('above');
        $m = $o->has('amount') || $n->has('amount') || $ab($o) || $ab($n) ? self::moneyOf($d) : null;
        $rels = [];
        $ccyMapRel = static function (Obj $a, Obj $b) use ($m): string {
            $rs = [self::setRel($a->keys(), $b->keys())];
            foreach ($a->keys() as $c) {
                if ($b->has($c)) {
                    $rs[] = self::numRel(self::minorUnits($a->get($c), $m['exp'], $c), self::minorUnits($b->get($c), $m['exp'], $c));
                }
            }
            return self::combine($rs);
        };
        $p = self::presence($o->has('amount'), $n->has('amount'));
        $rels[] = ['amount', $p ?? $ccyMapRel($o->get('amount')->get('max'), $n->get('amount')->get('max'))];
        $p = self::presence($o->has('approval'), $n->has('approval'));
        if ($p === null) {
            $a = $o->get('approval');
            $b = $n->get('approval');
            $rs = [];
            if (Js::truthy($a->get('always')) && Js::truthy($b->get('always'))) {
                $rs[] = 'eq';
            } elseif (Js::truthy($a->get('always'))) {
                $rs[] = 'widen';
            } elseif (Js::truthy($b->get('always'))) {
                $rs[] = 'narrow';
            } else {
                $rs[] = $ccyMapRel($a->get('above'), $b->get('above'));
            }
            $rs[] = self::numRel(-(float)Js::num($a->get('approvers') ?? self::n(1)), -(float)Js::num($b->get('approvers') ?? self::n(1)));
            $rs[] = $a->get('group') === $b->get('group') ? 'eq' : 'inc';
            $p = self::combine($rs);
        }
        $rels[] = ['approval', $p];
        $skey = static fn(mixed $s): string => !($s instanceof Obj) ? '||undefined' : ($s->get('param') ?? '') . '|' . ($s->get('role') ?? '') . '|' . $s->get('caller');
        $rels[] = ['scope', self::flip(self::setRel(array_map($skey, $o->get('scope') ?? []), array_map($skey, $n->get('scope') ?? [])))];
        $best = static function (?array $rs): array {
            $mp = [];
            foreach ($rs ?? [] as $x) {
                $k = $x->get('per') . '|' . ($x->get('by') ?? 'principal');
                $mp[$k] = min($mp[$k] ?? PHP_INT_MAX, (int)Js::num($x->get('max')));
            }
            return $mp;
        };
        $A = $best($o->get('rate'));
        $B = $best($n->get('rate'));
        $rs = [];
        foreach (array_merge(array_keys($A), array_filter(array_keys($B), static fn($k) => !isset($A[$k]))) as $k) {
            $rs[] = !isset($A[$k]) ? 'narrow' : (!isset($B[$k]) ? 'widen' : self::numRel($A[$k], $B[$k]));
        }
        $rels[] = ['rate', self::combine($rs)];
        $p = self::presence($o->has('hours'), $n->has('hours'));
        if ($p === null) {
            $a = $o->get('hours');
            $b = $n->get('hours');
            if ($a->get('tz') !== $b->get('tz')) {
                $p = 'inc';
            } else {
                $sa = self::minutesOfWeek($a);
                $sb = self::minutesOfWeek($b);
                $bInA = array_diff_key($sb, $sa) === [];
                $aInB = array_diff_key($sa, $sb) === [];
                $inner = $bInA && $aInB ? 'eq' : ($bInA ? 'narrow' : ($aInB ? 'widen' : 'inc'));
                $p = self::combine([$inner, self::numRel($a->get('outside') === 'deny' ? 0 : 1, $b->get('outside') === 'deny' ? 0 : 1)]);
            }
        }
        $rels[] = ['hours', $p];
        $p = self::presence($o->has('recipients'), $n->has('recipients'));
        if ($p === null) {
            $a = $o->get('recipients');
            $b = $n->get('recipients');
            if ($a->get('param') !== $b->get('param') || $a->get('role') !== $b->get('role')) {
                $p = 'inc';
            } else {
                $allowedA = array_merge(array_map(static fn($x) => "@$x", $a->get('domains') ?? []), $a->get('addresses') ?? []);
                $allowedB = array_merge(array_map(static fn($x) => "@$x", $b->get('domains') ?? []), $b->get('addresses') ?? []);
                $covered = static fn(string $x, array $st): bool => in_array($x, $st, true) || (!str_starts_with($x, '@') && in_array('@' . (explode('@', $x)[1] ?? 'undefined'), $st, true));
                $bInA = array_filter($allowedB, static fn($x) => !$covered($x, $allowedA)) === [];
                $aInB = array_filter($allowedA, static fn($x) => !$covered($x, $allowedB)) === [];
                $p = $bInA && $aInB ? 'eq' : ($bInA ? 'narrow' : ($aInB ? 'widen' : 'inc'));
            }
        }
        $rels[] = ['recipients', $p];
        $rels[] = ['required', self::flip(self::setRel($o->get('required') ?? [], $n->get('required') ?? []))];
        $diffs = array_values(array_filter($rels, static fn(array $x) => $x[1] !== 'eq'));
        $reasons = array_map(static fn(array $x): string => "rules.{$x[0]}: " . ($x[1] === 'inc' ? 'incomparable' : $x[1]), $diffs);
        sort($reasons, SORT_STRING);
        $cls = self::combine(array_map(static fn(array $x) => $x[1], $diffs));
        return ['class' => $cls === 'eq' ? 'equal' : ($cls === 'inc' ? 'incomparable' : $cls), 'reasons' => $reasons];
    }

    // ---- the reviewer's signature over a widened rules block ---------------------------------------------------------------

    public static function rulesReviewMessage(Obj $b): string
    {
        return self::RULES_REVIEW_DOMAIN . "\0" . Json::canonicalizeNative(Obj::of(['verb' => $b->get('verb'), 'def_digest' => $b->get('def_digest'),
            'rules_digest' => $b->get('rules_digest'), 'reviewer_kid' => $b->get('reviewer_kid'), 'ts' => $b->get('ts')]));
    }

    public static function signRulesReview(Obj $b, string $secret): Obj
    {
        $o = $b->without();
        $o->set('sig', Pca::b64u((new KeyPair($secret))->sign(self::rulesReviewMessage($b))));
        return $o;
    }

    /** Null iff $r is a valid review of exactly these rules on exactly this def (digests, pinned reviewer key, validity, signature). Never throws. */
    public static function rulesReviewError(mixed $r, Obj $d, Obj $rules, mixed $pins): ?string
    {
        try {
            if ($pins === null) {
                return 'no reviewer keys are pinned';
            }
            $pe = Actions::reviewerPinsError($pins);
            if ($pe) {
                return 'bad pins: ' . $pe;
            }
            if (!($r instanceof Obj)) {
                return 'no rules review';
            }
            if ($r->get('verb') !== $d->get('verb')) {
                return 'the rules review names another action';
            }
            if ($r->get('def_digest') !== Actions::defDigest($d)) {
                return 'the rules review covers another version of the action';
            }
            if ($r->get('rules_digest') !== self::businessRulesDigest($d->get('verb'), $rules)) {
                return 'the rules review covers other rules';
            }
            $ts = $r->get('ts');
            if (!is_string($r->get('sig')) || !is_string($r->get('reviewer_kid')) || !self::isi($ts) || self::negZero($ts)) {
                return 'malformed rules review';
            }
            $key = null;
            foreach ($pins->get('keys') as $k) {
                if ($k->get('kid') === $r->get('reviewer_kid')) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null) {
                return "no pinned key '" . $r->get('reviewer_kid') . "'";
            }
            if (!in_array('reviewer', $key->get('roles'), true)) {
                return "key '" . $key->get('kid') . "' does not hold the reviewer role";
            }
            $t = Js::num($ts);
            if (($key->get('not_before') !== null && $t < Js::num($key->get('not_before'))) || ($key->get('not_after') !== null && $t > Js::num($key->get('not_after')))) {
                return 'the review time is outside the key validity';
            }
            return Pca::verifyEd25519B64u($key->get('pk'), self::rulesReviewMessage($r->without('sig')), $r->get('sig')) ? null : 'the rules review signature is invalid';
        } catch (\Throwable $e) {
            return 'malformed rules review: ' . $e->getMessage();
        }
    }
}
