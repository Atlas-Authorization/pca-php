<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The shape check of a platform's business-rules block for one action (the `rules` member of an authoring entry): amount caps, approval,
 * scope bindings, rate limits, hours, recipients, required parameters and examples. Never decides a call: it only says whether the
 * block is well formed for the expanded def, with the reference's wording. Values are the package JSON model (Obj, list, string, Num, bool,
 * null; a raw float only for NaN and the infinities).
 */
final class ActionsRulesValidate
{
    private const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
    private const PERIODS = ['hour', 'day'];
    private const MAX_CURRENCIES = 32;
    private const MAX_LIST = 64;
    private const MAX_APPROVERS = 16;
    private const MAX_EXAMPLES = 32;
    private const MAX_SAFE = 9007199254740991.0;
    private const KEYS = ['amount', 'approval', 'scope', 'rate', 'hours', 'recipients', 'required', 'examples'];
    private const DOMAIN_RE = '/\A(?=.{1,253}\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z/';
    private const ADDRESS_RE = '/\A[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\z/';
    private const DEC_RE = '/\A(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?\z/';
    private const AT_RE = '/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z/';

    /** @var array<string,bool>|null lower-case zone name => true */
    private static ?array $zones = null;

    /** Null iff `$rules` is a well-formed rules block for the expanded def `$d`; the reason otherwise. */
    public static function error(Obj $d, mixed $rules): ?string
    {
        try {
            self::check($d, $rules);
            return null;
        } catch (ActionKitError $e) {
            return $e->getMessage();
        } catch (\Throwable) {
            return 'rules: malformed block';
        }
    }

    // ---- helpers -----------------------------------------------------------------------------------------------------------

    private static function bad(string $m): never
    {
        throw new ActionKitError('bad_rules', $m);
    }

    private static function f(mixed $v): ?float
    {
        return $v instanceof Num ? $v->float() : (is_float($v) ? $v : null);
    }

    /** Number.isSafeInteger. */
    private static function isi(mixed $v): bool
    {
        $f = self::f($v);
        return $f !== null && is_finite($f) && fmod($f, 1.0) === 0.0 && abs($f) <= self::MAX_SAFE;
    }

    private static function negZero(mixed $v): bool
    {
        $f = self::f($v);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) === -INF;
    }

    private static function closed(Obj $o, array $allowed, string $at): void
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                self::bad("$at: unknown member '$k'");
            }
        }
    }

    private static function str(mixed $v): string
    {
        return IntentWb::jsStr($v);
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** @return array{name:string,p:Obj} */
    private static function resolveRef(Obj $d, Obj $r, string $at): array
    {
        $hasP = is_string($r->get('param'));
        $hasR = is_string($r->get('role'));
        if ($hasP === $hasR) {
            self::bad("$at: give exactly one of param or role");
        }
        $params = $d->get('params');
        if ($hasP) {
            $p = $params instanceof Obj && $params->has($r->get('param')) ? $params->get($r->get('param')) : null;
            if (!($p instanceof Obj)) {
                self::bad("$at: '" . $d->get('verb') . "' has no parameter '" . self::str($r->get('param')) . "'");
            }
            return ['name' => $r->get('param'), 'p' => $p];
        }
        $hits = self::byRole($d, $r->get('role'));
        if (count($hits) !== 1) {
            self::bad("$at: '" . $d->get('verb') . "' has " . ($hits === [] ? 'no' : 'several') . ' parameter' . ($hits === [] ? '' : 's') . ' with role ' . self::str($r->get('role')));
        }
        return ['name' => $hits[0], 'p' => $d->get('params')->get($hits[0])];
    }

    /** @return list<string> the names of the params with this role, in JavaScript's string order */
    private static function byRole(Obj $d, mixed $role): array
    {
        $hits = [];
        $params = $d->get('params');
        if ($params instanceof Obj) {
            foreach ($params->keys() as $n) {
                $p = $params->get($n);
                if ($p instanceof Obj && $p->get('role') === $role) {
                    $hits[] = $n;
                }
            }
        }
        usort($hits, static fn(string $a, string $b): int => strcmp(AnalyzerJs::u16key($a), AnalyzerJs::u16key($b)));
        return $hits;
    }

    /** @return array{amount:string,exp:mixed} the money parameter of an action */
    private static function moneyOf(Obj $d): array
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
        if (!($u instanceof Obj) || $u->get('kind') !== 'money') {
            self::bad("'$verb': the amount parameter '$name' declares no money unit (its currency)");
        }
        $ccy = $u->get('ccy');
        if ($ccy instanceof Obj) {
            $from = $ccy->get('from');
            $params = $d->get('params');
            if (!is_string($from) || !$params->has($from)) {
                self::bad("'$verb': the currency parameter '" . self::str($from) . "' does not exist");
            }
        }
        return ['amount' => $name, 'exp' => $u->get('exp')];
    }

    /** Fails unless `$v` is a non-negative integer of minor units or a decimal string with at most `$exp` decimals. */
    private static function minorUnits(mixed $v, mixed $exp, string $at): void
    {
        $f = self::f($v);
        if ($f !== null) {
            if (!self::isi($v) || $f < 0 || self::negZero($v)) {
                self::bad("$at: an amount is a non-negative integer of minor units, or a decimal string");
            }
            return;
        }
        if (!is_string($v)) {
            self::bad("$at: an amount is a number of minor units or a decimal string");
        }
        if (preg_match(self::DEC_RE, $v, $m) !== 1) {
            self::bad("$at: '$v' is not a decimal amount");
        }
        $e = self::f($exp);
        $ex = $exp instanceof Num ? $exp->float() : $e;
        if ($ex === null || !is_finite($ex) || $ex < 0 || $ex > 18 || fmod($ex, 1.0) !== 0.0) {
            self::bad("$at: the currency exponent is not a small integer");
        }
        $ex = (int)$ex;
        $frac = $m[2] ?? '';
        if (strlen($frac) > $ex) {
            self::bad("$at: '$v' has more decimals than the currency's $ex");
        }
        $n = (float)$m[1] * (10.0 ** $ex) + (float)(int)str_pad($frac, $ex, '0');
        if ($n > self::MAX_SAFE) {
            self::bad("$at: '$v' is too large");
        }
    }

    private static function ccyMap(Obj $d, mixed $m, string $at): void
    {
        if (!($m instanceof Obj) || count($m->keys()) === 0 || count($m->keys()) > self::MAX_CURRENCIES) {
            self::bad("$at: a map of 1.." . self::MAX_CURRENCIES . ' currencies to amounts');
        }
        $money = self::moneyOf($d);
        foreach ($m->keys() as $c) {
            if (preg_match('/\A[A-Z]{3}\z/', $c) !== 1) {
                self::bad("$at: '$c' is not an ISO 4217 currency code");
            }
            self::minorUnits($m->get($c), $money['exp'], "$at.$c");
        }
    }

    private static function refOf(Obj $s): Obj
    {
        $o = new Obj();
        foreach (['param', 'role'] as $k) {
            if ($s->has($k)) {
                $o->set($k, $s->get($k));
            }
        }
        return $o;
    }

    /** The canonical name of an IANA zone (matched case-insensitively), or null. */
    public static function canonicalZone(mixed $tz): ?string
    {
        if (!is_string($tz) || $tz === '' || strlen($tz) > 64 || preg_match('/\A[A-Za-z0-9_+\-\/]+\z/', $tz) !== 1) {
            return null;
        }
        if (self::$zones === null) {
            self::$zones = [];
            foreach (\DateTimeZone::listIdentifiers(\DateTimeZone::ALL_WITH_BC) as $z) {
                self::$zones[strtolower($z)] = $z;
            }
            self::$zones['utc'] = 'UTC';
            foreach (['EST', 'MST', 'HST'] as $z) { // legacy IANA zone ids the runtime knows that PHP's list leaves out
                self::$zones[strtolower($z)] ??= $z;
            }
        }
        return self::$zones[strtolower($tz)] ?? null;
    }

    /** Is this a time zone the runtime knows (the reference's knownTimeZone)? */
    public static function knownZone(mixed $tz): bool
    {
        return self::canonicalZone($tz) !== null;
    }

    /** Date.parse of an RFC 3339 `...Z` second-precision time is a number (day 1..31 rolls over, 24:00:00 is the next day). */
    private static function utcTime(mixed $s): bool
    {
        if (!is_string($s) || preg_match(self::AT_RE, $s, $m) !== 1) {
            return false;
        }
        [$mo, $d, $h, $mi, $se] = [(int)$m[2], (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]];
        return $mo >= 1 && $mo <= 12 && $d >= 1 && $d <= 31 && $mi <= 59 && $se <= 59 && ($h <= 23 || ($h === 24 && $mi === 0 && $se === 0));
    }

    // ---- the check ---------------------------------------------------------------------------------------------------------

    private static function check(Obj $d, mixed $r): void
    {
        if (!($r instanceof Obj)) {
            self::bad('rules must be an object');
        }
        self::closed($r, self::KEYS, 'rules');
        if (count(array_diff($r->keys(), ['examples'])) === 0) {
            self::bad('rules: name at least one rule');
        }
        if ($r->has('amount')) {
            $a = $r->get('amount');
            if (!($a instanceof Obj)) {
                self::bad('rules.amount must be {max: {CCY: amount}}');
            }
            self::closed($a, ['max'], 'rules.amount');
            self::ccyMap($d, $a->get('max'), 'rules.amount.max');
        }
        if ($r->has('approval')) {
            self::approval($d, $r->get('approval'));
        }
        if ($r->has('scope')) {
            self::scope($d, $r->get('scope'));
        }
        if ($r->has('rate')) {
            self::rate($r->get('rate'));
        }
        if ($r->has('hours')) {
            self::hours($r->get('hours'));
        }
        if ($r->has('recipients')) {
            self::recipients($d, $r->get('recipients'));
        }
        if ($r->has('required')) {
            $rq = $r->get('required');
            $seen = [];
            $distinct = true;
            if (self::isList($rq)) {
                foreach ($rq as $x) {
                    $key = is_string($x) ? 's:' . $x : 'o:' . self::safeStringify($x);
                    $distinct = $distinct && !isset($seen[$key]);
                    $seen[$key] = true;
                }
            }
            if (!self::isList($rq) || count($rq) === 0 || count($rq) > self::MAX_LIST || !$distinct) {
                self::bad('rules.required is a list of distinct parameter names');
            }
            $params = $d->get('params');
            foreach ($rq as $n) {
                if (!is_string($n) || !($params instanceof Obj) || !$params->has($n)) {
                    self::bad("rules.required: '" . $d->get('verb') . "' has no parameter '" . self::str($n) . "'");
                }
            }
        }
        if ($r->has('examples')) {
            self::examples($r->get('examples'));
        }
    }

    private static function safeStringify(mixed $x): string
    {
        try {
            return Js::stringify($x);
        } catch (\Throwable) {
            return 'unrepresentable:' . spl_object_id(new \stdClass());
        }
    }

    private static function approval(Obj $d, mixed $ap): void
    {
        if (!($ap instanceof Obj)) {
            self::bad('rules.approval must be an object');
        }
        self::closed($ap, ['above', 'always', 'approvers', 'group'], 'rules.approval');
        if ($ap->has('always') && $ap->get('always') !== true) {
            self::bad('rules.approval.always is true or absent');
        }
        if (!$ap->has('above') === !$ap->has('always')) {
            self::bad('rules.approval: give exactly one of above or always');
        }
        if ($ap->has('above')) {
            self::ccyMap($d, $ap->get('above'), 'rules.approval.above');
        }
        if ($ap->has('approvers')) {
            $n = $ap->get('approvers');
            if (!self::isi($n) || self::f($n) < 1 || self::f($n) > self::MAX_APPROVERS) {
                self::bad('rules.approval.approvers is 1..' . self::MAX_APPROVERS);
            }
        }
        if ($ap->has('group') && (!is_string($ap->get('group')) || preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', $ap->get('group')) !== 1)) {
            self::bad('rules.approval.group is a lowercase name');
        }
    }

    private static function scope(Obj $d, mixed $sc): void
    {
        if (!self::isList($sc) || count($sc) === 0 || count($sc) > self::MAX_LIST) {
            self::bad('rules.scope is a list of 1..' . self::MAX_LIST . ' bindings');
        }
        foreach ($sc as $i => $s) {
            if (!($s instanceof Obj)) {
                self::bad("rules.scope[$i] must be an object");
            }
            self::closed($s, ['param', 'role', 'caller'], "rules.scope[$i]");
            $p = self::resolveRef($d, self::refOf($s), "rules.scope[$i]")['p'];
            if (!in_array($p->get('type'), ['string', 'integer'], true)) {
                self::bad("rules.scope[$i]: the bound parameter must be a string or integer id");
            }
            if (!is_string($s->get('caller')) || preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', $s->get('caller')) !== 1) {
                self::bad("rules.scope[$i].caller is a lowercase attribute name of the caller");
            }
        }
    }

    private static function rate(mixed $rt): void
    {
        if (!self::isList($rt) || count($rt) === 0 || count($rt) > 4) {
            self::bad('rules.rate is a list of 1..4 limits');
        }
        foreach ($rt as $i => $x) {
            if (!($x instanceof Obj)) {
                self::bad("rules.rate[$i] must be an object");
            }
            self::closed($x, ['max', 'per', 'by'], "rules.rate[$i]");
            if (!self::isi($x->get('max')) || self::f($x->get('max')) < 1 || self::f($x->get('max')) > 1000000) {
                self::bad("rules.rate[$i].max is 1..1000000");
            }
            if (!is_string($x->get('per')) || !in_array($x->get('per'), self::PERIODS, true)) {
                self::bad("rules.rate[$i].per is hour or day");
            }
            if ($x->has('by') && !in_array($x->get('by'), ['principal', 'org'], true)) {
                self::bad("rules.rate[$i].by is principal or org");
            }
        }
    }

    private static function hours(mixed $h): void
    {
        if (!($h instanceof Obj)) {
            self::bad('rules.hours must be an object');
        }
        self::closed($h, ['days', 'from', 'to', 'tz', 'outside'], 'rules.hours');
        $days = $h->get('days');
        $ok = self::isList($days) && count($days) > 0;
        if ($ok) {
            foreach ($days as $x) {
                $ok = $ok && is_string($x) && in_array($x, self::DAYS, true);
            }
            $ok = $ok && count(array_unique($days)) === count($days);
        }
        if (!$ok) {
            self::bad('rules.hours.days is a list of distinct days (' . implode(', ', self::DAYS) . ')');
        }
        $hhmm = '/\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z/';
        if (!is_string($h->get('from')) || preg_match($hhmm, $h->get('from')) !== 1 || !is_string($h->get('to')) || preg_match($hhmm, $h->get('to')) !== 1) {
            self::bad('rules.hours.from and .to are HH:MM (24 h)');
        }
        if (!is_string($h->get('tz')) || !self::knownZone($h->get('tz'))) {
            self::bad("rules.hours.tz '" . ($h->has('tz') ? self::str($h->get('tz')) : 'undefined') . "' is not a known IANA time zone");
        }
        if ($h->has('outside') && !in_array($h->get('outside'), ['escalate', 'deny'], true)) {
            self::bad('rules.hours.outside is escalate or deny');
        }
    }

    private static function recipients(Obj $d, mixed $x): void
    {
        if (!($x instanceof Obj)) {
            self::bad('rules.recipients must be an object');
        }
        self::closed($x, ['param', 'role', 'domains', 'addresses'], 'rules.recipients');
        $res = self::resolveRef($d, self::refOf($x), 'rules.recipients');
        $name = $res['name'];
        $p = $res['p'];
        $type = $p->get('type');
        if ($type === 'array' || $type === 'set') {
            if ($p->get('items') !== null && $p->get('items') !== 'string') {
                self::bad("rules.recipients: '$name' must hold strings");
            }
            $mi = $p->get('max_items');
            if (!self::isi($mi) || self::negZero($mi) || self::f($mi) > self::MAX_LIST) {
                self::bad("rules.recipients: the list parameter '$name' needs max_items <= " . self::MAX_LIST . ' so every entry can be checked');
            }
        } elseif ($type !== 'string') {
            self::bad("rules.recipients: '$name' must be a string or a bounded list of strings");
        }
        if (!$x->has('domains') && !$x->has('addresses')) {
            self::bad('rules.recipients: give domains and/or addresses');
        }
        if ($x->has('domains') && !self::allMatch($x->get('domains'), self::DOMAIN_RE)) {
            self::bad('rules.recipients.domains is a list of lowercase domain names');
        }
        if ($x->has('addresses') && !self::allMatch($x->get('addresses'), self::ADDRESS_RE)) {
            self::bad('rules.recipients.addresses is a list of lowercase email addresses');
        }
    }

    private static function allMatch(mixed $v, string $re): bool
    {
        if (!self::isList($v) || count($v) === 0 || count($v) > self::MAX_LIST) {
            return false;
        }
        foreach ($v as $s) {
            if (!is_string($s) || preg_match($re, $s) !== 1) {
                return false;
            }
        }
        return true;
    }

    private static function examples(mixed $ex): void
    {
        if (!self::isList($ex) || count($ex) > self::MAX_EXAMPLES) {
            self::bad('rules.examples is a list of at most ' . self::MAX_EXAMPLES);
        }
        foreach ($ex as $i => $e) {
            if (!($e instanceof Obj)) {
                self::bad("rules.examples[$i] must be an object");
            }
            self::closed($e, ['params', 'caller', 'at', 'recent', 'expect'], "rules.examples[$i]");
            if (!($e->get('params') instanceof Obj)) {
                self::bad("rules.examples[$i].params must be an object");
            }
            if ($e->has('caller') && !($e->get('caller') instanceof Obj)) {
                self::bad("rules.examples[$i].caller must be an object");
            }
            if ($e->has('at') && !self::utcTime($e->get('at'))) {
                self::bad("rules.examples[$i].at is an RFC 3339 UTC time (…Z)");
            }
            if ($e->has('recent')) {
                $rc = $e->get('recent');
                $ok = $rc instanceof Obj;
                if ($ok) {
                    foreach ($rc->keys() as $k) {
                        $n = $rc->get($k);
                        $ok = $ok && self::isi($n) && self::f($n) >= 0 && !self::negZero($n);
                    }
                }
                if (!$ok) {
                    self::bad("rules.examples[$i].recent maps rate indexes to counts");
                }
            }
            if (!in_array($e->get('expect'), ['allow', 'escalate', 'deny'], true)) {
                self::bad("rules.examples[$i].expect is allow, escalate or deny");
            }
        }
    }
}
