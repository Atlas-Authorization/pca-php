<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/AnalyzerCoverage.php';
require_once __DIR__ . '/AnalyzerExposure.php';
require_once __DIR__ . '/AnalyzerResidual.php';
require_once __DIR__ . '/AnalyzerNarrowing.php';

/**
 * Lints a policy against the action schema or ActionDefs it is written for, and runs policy-as-code tests: boundary-test
 * generation and signed test documents.
 */
final class AnalyzerValidate
{
    public const POLICY_TESTS_KIND = 'pca-policy-tests';
    public const POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\0";

    private const DEF_TYPE = ['string' => 'string', 'integer' => 'integer', 'boolean' => 'boolean', 'date' => 'date', 'set' => 'set', 'array' => 'array'];
    private const NUMERIC_OPS = ['lt', 'lte', 'gt', 'gte'];

    private static function defShape(mixed $p): Obj
    {
        $t = AnalyzerJs::jget($p, 'type');
        $out = new Obj();
        if (is_string($t) && isset(self::DEF_TYPE[$t])) {
            $out->set('type', self::DEF_TYPE[$t]);
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($p, 'role'))) {
            $out->set('semantic', AnalyzerJs::jget($p, 'role'));
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($p, 'values'))) {
            $out->set('values', AnalyzerJs::jget($p, 'values'));
        }
        if (!(AnalyzerJs::jget($p, 'min') instanceof Undef)) {
            $out->set('min', AnalyzerJs::jget($p, 'min'));
        }
        if (!(AnalyzerJs::jget($p, 'max') instanceof Undef)) {
            $out->set('max', AnalyzerJs::jget($p, 'max'));
        }
        if (AnalyzerJs::truthy(AnalyzerJs::jget($p, 'sensitivity'))) {
            $out->set('sensitivity', AnalyzerJs::jget($p, 'sensitivity'));
        }
        if (!(AnalyzerJs::jget($p, 'required') instanceof Undef)) {
            $out->set('required', AnalyzerJs::jget($p, 'required'));
        }
        return $out;
    }

    /** Object.entries. @return list<array{0: string, 1: mixed}> */
    private static function entries(mixed $o): array
    {
        $o = AnalyzerJs::nn($o, new Obj());
        if (!($o instanceof Obj)) {
            throw new \TypeError('Object.entries requires an object');
        }
        return array_map(static fn(string $k): array => [$k, $o->get($k)], AnalyzerJs::keyOrder($o));
    }

    /** @return list<Obj> */
    public static function verbShapesFromActionDefs(mixed $defs): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList($defs) as $d) {
            $params = new Obj();
            foreach (self::entries(AnalyzerJs::jget($d, 'params')) as [$k, $p]) {
                $params->set($k, self::defShape($p));
            }
            $out[] = AnalyzerJs::uobj(['verb' => AnalyzerJs::jget($d, 'verb'), 'params' => $params]);
        }
        return $out;
    }

    /**
     * The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs.
     * @return list<Obj>
     */
    public static function verbShapes(mixed $src): array
    {
        if ($src instanceof Obj && $src->has('verbs')) {
            $out = [];
            foreach (AnalyzerJs::reqList($src->get('verbs')) as $v) {
                $params = new Obj();
                foreach (self::entries(AnalyzerJs::jget($v, 'params')) as [$k, $d]) {
                    $s = ['type' => AnalyzerJs::jget($d, 'type')];
                    if (AnalyzerJs::truthy(AnalyzerJs::jget($d, 'values'))) {
                        $s['values'] = AnalyzerJs::jget($d, 'values');
                    }
                    if (!(AnalyzerJs::jget($d, 'min') instanceof Undef)) {
                        $s['min'] = AnalyzerJs::jget($d, 'min');
                    }
                    if (!(AnalyzerJs::jget($d, 'max') instanceof Undef)) {
                        $s['max'] = AnalyzerJs::jget($d, 'max');
                    }
                    if (AnalyzerJs::truthy(AnalyzerJs::jget($d, 'unit'))) {
                        $s['unit'] = AnalyzerJs::jget($d, 'unit');
                    }
                    $s['semantic'] = AnalyzerJs::jget($d, 'semantic');
                    $s['sensitivity'] = AnalyzerJs::jget($d, 'sensitivity');
                    if (!(AnalyzerJs::jget($d, 'required') instanceof Undef)) {
                        $s['required'] = AnalyzerJs::jget($d, 'required');
                    }
                    $params->set($k, AnalyzerJs::uobj($s));
                }
                $out[] = AnalyzerJs::uobj(['verb' => AnalyzerJs::jget($v, 'verb'), 'params' => $params]);
            }
            return $out;
        }
        $lst = AnalyzerJs::reqList($src);
        $shapes = [];
        foreach ($lst as $d) {
            $v = ($d instanceof Obj && $d->has('verb')) ? $d->get('verb') : false;
            if (!AnalyzerJs::truthy($v)) {
                $v = ($d instanceof Obj && $d->has('id')) ? $d->get('id') : false;
            }
            if (!AnalyzerJs::truthy($v)) {
                $v = '';
            }
            $params = new Obj();
            foreach (self::entries(AnalyzerJs::jget($d, 'params')) as [$k, $p]) {
                $params->set($k, self::defShape($p));
            }
            $shapes[] = Obj::of(['verb' => $v, 'params' => $params]);
        }
        foreach ($shapes as $i => $v) {
            $orig = AnalyzerJs::nn(AnalyzerJs::jget($lst[$i], 'params'), new Obj());
            foreach ($v->get('params')->keys() as $k) {
                foreach (['semantic', 'unit'] as $f) {
                    if (!(AnalyzerJs::oget(AnalyzerJs::own($orig, $k), $f) instanceof Undef)) {
                        $v->get('params')->get($k)->set($f, $orig->get($k)->get($f));
                    }
                }
            }
        }
        return $shapes;
    }

    /** @param list<mixed> $into @return list<mixed> */
    private static function leaves(mixed $c, array $into): array
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            return $into;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && AnalyzerJs::isArr($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    $into = self::leaves($x, $into);
                }
            } elseif ($c->has('any_of') && AnalyzerJs::isArr($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    $into = self::leaves($x, $into);
                }
            } elseif ($c->has('not')) {
                $into = self::leaves($c->get('not'), $into);
            }
        } else {
            $into[] = $c;
        }
        return $into;
    }

    private static function typeOf(mixed $x): string
    {
        if (is_bool($x)) {
            return 'boolean';
        }
        if (AnalyzerJs::isNum($x)) {
            return 'number';
        }
        if (is_string($x)) {
            return 'string';
        }
        return $x instanceof Undef ? 'undefined' : 'object';
    }

    private static function typeOk(mixed $t, mixed $v): bool
    {
        if ($t instanceof Undef) {
            return true;
        }
        if ($t === 'integer') {
            return AnalyzerJs::isFin($v);
        }
        if ($t === 'boolean') {
            return is_bool($v);
        }
        if ($t === 'string' || $t === 'date') {
            return is_string($v);
        }
        return true;
    }

    private static function semanticMoney(mixed $d): bool
    {
        $s = AnalyzerJs::nn(AnalyzerJs::jget($d, 'semantic'), '');
        if (!is_string($s)) {
            throw new \TypeError('startsWith is not a function');
        }
        return str_starts_with($s, 'money.');
    }

    private static function grants(mixed $p, mixed $verb): bool
    {
        $pv = AnalyzerJs::jget($p, 'verb');
        return AnalyzerJs::strictEq($pv, '*') || AnalyzerJs::strictEq($pv, $verb)
            || (AnalyzerJs::isArr($pv) && (AnalyzerJs::includes($pv, '*') || AnalyzerJs::includes($pv, $verb)));
    }

    private static function num(mixed $v): string
    {
        if (!AnalyzerJs::isNum($v)) {
            throw new \TypeError('not a number');
        }
        return AnalyzerJs::numStr(AnalyzerJs::jsnum($v));
    }

    private static function gt(mixed $a, mixed $b): bool
    {
        return AnalyzerJs::toNumber($a) > AnalyzerJs::toNumber($b);
    }

    private static function ge(mixed $a, mixed $b): bool
    {
        return AnalyzerJs::toNumber($a) >= AnalyzerJs::toNumber($b);
    }

    private static function lt(mixed $a, mixed $b): bool
    {
        return AnalyzerJs::toNumber($a) < AnalyzerJs::toNumber($b);
    }

    private static function le(mixed $a, mixed $b): bool
    {
        return AnalyzerJs::toNumber($a) <= AnalyzerJs::toNumber($b);
    }

    /** A dictionary key for a verb value (equal keys for values equal as dictionary keys); null for an unhashable value. */
    private static function verbKey(mixed $v): ?string
    {
        if ($v instanceof Undef) {
            return 'u';
        }
        if ($v === null) {
            return 'z';
        }
        if (is_bool($v)) {
            return 'd' . ($v ? '1' : '0');
        }
        if (AnalyzerJs::isNum($v)) {
            return 'd' . AnalyzerJs::numStr(AnalyzerJs::jsnum($v));
        }
        return is_string($v) ? 's' . $v : null;
    }

    /** @param array<string, Obj> $byVerb */
    private static function hasVerb(array $byVerb, mixed $v): bool
    {
        $k = self::verbKey($v);
        return $k !== null && isset($byVerb[$k]);
    }

    /**
     * Lint a policy against the schema it is written for: {ok, findings: [{code, severity, where, message}]}; ok is false when a
     * finding is an error.
     */
    public static function validatePolicyAgainstSchema(mixed $policy, mixed $src, mixed $o = null): Obj
    {
        $o = self::optsOf($o);
        $shapes = self::verbShapes($src);
        $byVerb = [];
        foreach ($shapes as $s) {
            $k = self::verbKey(AnalyzerJs::own($s, 'verb'));
            if ($k === null) {
                throw new \TypeError('unhashable verb');
            }
            $byVerb[$k] = $s;
        }
        $schemaUnits = AnalyzerJs::jget($o, 'schemaUnits');
        if ($schemaUnits instanceof Undef || $schemaUnits === null) {
            $schemaUnits = ($src instanceof Obj && $src->has('units')) ? $src->get('units') : AnalyzerJs::undef();
        }
        $model = AnalyzerCore::toModel($policy);
        $findings = [];
        $units = AnalyzerJs::jget($o, 'units');
        $listUngranted = AnalyzerJs::truthy(AnalyzerJs::jget($o, 'listUngranted'));

        $add = static function (string $code, string $severity, string $where, string $message) use (&$findings): void {
            $findings[] = Obj::of(['code' => $code, 'severity' => $severity, 'where' => $where, 'message' => $message]);
        };

        $check = function (mixed $p, string $where, bool $isVeto) use ($shapes, $byVerb, $schemaUnits, $units, $add): void {
            $pv = AnalyzerJs::jget($p, 'verb');
            if (AnalyzerJs::strictEq($pv, '*') || (AnalyzerJs::isArr($pv) && AnalyzerJs::includes($pv, '*'))) {
                $verbs = array_map(static fn(Obj $s) => AnalyzerJs::own($s, 'verb'), $shapes);
            } elseif (AnalyzerJs::isArr($pv)) {
                $verbs = $pv;
            } else {
                $verbs = [$pv];
            }
            foreach ($verbs as $v) {
                if (!self::hasVerb($byVerb, $v)) {
                    $add('undeclared-verb', $isVeto ? 'warn' : 'error', $where, sprintf("verb '%s' is not declared by the schema", AnalyzerJs::jsStr($v)));
                }
            }
            $declared = [];
            foreach ($verbs as $v) {
                if (self::hasVerb($byVerb, $v)) {
                    $declared[] = $byVerb[self::verbKey($v)];
                }
            }
            if (!$declared) {
                return;
            }
            $pw = AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), []);
            foreach (AnalyzerJs::reqList($pw) as $wi => $w) {
                foreach (self::leaves($w, []) as $c) {
                    if (!Predicates::isLeafCondition($c) || !str_starts_with($c->get('field'), 'action.params.')) {
                        continue;
                    }
                    $name = explode('.', substr($c->get('field'), strlen('action.params.')))[0];
                    $at = sprintf('%s.where[%d]', $where, $wi);
                    $having = array_values(array_filter($declared, static fn(Obj $s): bool => $s->get('params')->has($name)));
                    if (!$having) {
                        $add('undeclared-param', 'error', $at, sprintf("parameter '%s' is declared by none of %s", $name,
                            implode(', ', array_map(static fn(Obj $s): string => AnalyzerJs::jsStr(AnalyzerJs::own($s, 'verb')), $declared))));
                        continue;
                    }
                    if (count($having) < count($declared)) {
                        $rest = array_filter($declared, static function (Obj $s) use ($having): bool {
                            foreach ($having as $h) {
                                if ($s === $h) {
                                    return false;
                                }
                            }
                            return true;
                        });
                        $add('undeclared-param', 'warn', $at, sprintf("parameter '%s' is not declared by %s", $name,
                            implode(', ', array_map(static fn(Obj $s): string => AnalyzerJs::jsStr(AnalyzerJs::own($s, 'verb')), $rest))));
                    }
                    $d = $having[0]->get('params')->get($name);
                    $op = AnalyzerJs::own($c, 'op');
                    $val = AnalyzerJs::own($c, 'value');
                    $isStrOp = is_string($op);
                    $vals = (AnalyzerJs::isArr($val) && ($op === 'in' || $op === 'nin')) ? $val : [$val];
                    $dtype = AnalyzerJs::own($d, 'type');
                    if (!$c->has('ref') && $isStrOp && ($op === 'eq' || $op === 'ne' || $op === 'in' || $op === 'nin' || in_array($op, self::NUMERIC_OPS, true))) {
                        foreach ($vals as $x) {
                            if (!self::typeOk($dtype, $x)) {
                                $add('type-mismatch', 'error', $at, sprintf("'%s' is %s but is compared (%s) with %s", $name, AnalyzerJs::jsStr($dtype), $op, self::typeOf($x)));
                            }
                        }
                    }
                    if ($isStrOp && in_array($op, self::NUMERIC_OPS, true) && !($dtype instanceof Undef) && $dtype !== 'integer') {
                        if ($dtype === 'string' || $dtype === 'date') {
                            $add('ordering-on-string', 'warn', $at, sprintf("'%s' is %s: ordering follows UTF-8 byte order", $name, $dtype));
                        } else {
                            $add('type-mismatch', 'error', $at, sprintf("ordering operator %s on %s parameter '%s'", $op, AnalyzerJs::jsStr($dtype), $name));
                        }
                    }
                    $dvals = AnalyzerJs::own($d, 'values');
                    if (AnalyzerJs::truthy($dvals) && ($op === 'eq' || $op === 'in') && is_string($vals ? $vals[0] : null)) {
                        $missing = [];
                        foreach ($vals as $x) {
                            if (is_string($x) && !AnalyzerJs::includes($dvals, $x)) {
                                $missing[] = $x;
                            }
                        }
                        if (count($missing) === count($vals)) {
                            $add('value-not-in-enum', 'error', $at, sprintf("no value of %s %s is in the schema's set for '%s'", $op, AnalyzerJs::jsJson($vals), $name));
                        } elseif ($missing) {
                            $add('value-not-in-enum', 'warn', $at, sprintf("%s are not in the schema's set for '%s'", AnalyzerJs::jsJson($missing), $name));
                        }
                    }
                    $dmin = AnalyzerJs::own($d, 'min');
                    $dmax = AnalyzerJs::own($d, 'max');
                    if ($dtype === 'integer' && AnalyzerJs::isNum($val) && !$c->has('ref')) {
                        $v = $val;
                        $hasMin = !($dmin instanceof Undef);
                        $hasMax = !($dmax instanceof Undef);
                        $dead = ($op === 'eq' && (($hasMax && self::gt($v, $dmax)) || ($hasMin && self::lt($v, $dmin))))
                            || ($op === 'gt' && $hasMax && self::ge($v, $dmax))
                            || ($op === 'gte' && $hasMax && self::gt($v, $dmax))
                            || ($op === 'lt' && $hasMin && self::le($v, $dmin))
                            || ($op === 'lte' && $hasMin && self::lt($v, $dmin));
                        $lo = ($dmin instanceof Undef || $dmin === null) ? '-inf' : self::num($dmin);
                        $hi = ($dmax instanceof Undef || $dmax === null) ? 'inf' : self::num($dmax);
                        if ($dead) {
                            $add('out-of-range', 'error', $at, sprintf("'%s' %s %s can never hold: the schema bounds it to [%s, %s]", $name, $op, self::num($v), $lo, $hi));
                        } elseif (($op === 'lte' && $hasMax && self::ge($v, $dmax)) || ($op === 'gte' && $hasMin && self::le($v, $dmin))) {
                            $add('redundant-bound', 'info', $at, sprintf("'%s' %s %s never binds: the schema already bounds it to [%s, %s]", $name, $op, self::num($v), $lo, $hi));
                        }
                    }
                    $dunit = AnalyzerJs::own($d, 'unit');
                    if (AnalyzerJs::truthy($dunit) && !($units instanceof Undef) && ($op === 'eq' || ($isStrOp && in_array($op, self::NUMERIC_OPS, true))) && !$isVeto) {
                        $tag = AnalyzerJs::own($units, $c->get('field'));
                        if ($tag instanceof Undef || $tag === null) {
                            $tag = AnalyzerJs::own($units, 'action.params.' . $name);
                        }
                        $sch = ($schemaUnits instanceof Obj && is_string($dunit)) ? AnalyzerJs::own($schemaUnits, $dunit) : AnalyzerJs::undef();
                        if ($tag instanceof Undef || $tag === null) {
                            $add('unit-missing', 'error', $at, sprintf("'%s' carries unit '%s' but the policy has no unit tag for it (rule 20)", $name, AnalyzerJs::jsStr($dunit)));
                        } elseif (AnalyzerJs::truthy($sch) && (!AnalyzerJs::strictEq(AnalyzerJs::jget($tag, 'kind'), AnalyzerJs::jget($sch, 'kind'))
                                || !AnalyzerJs::strictEq(AnalyzerJs::jget($tag, 'currency'), AnalyzerJs::jget($sch, 'currency'))
                                || !AnalyzerJs::strictEq(AnalyzerJs::jget($tag, 'exponent'), AnalyzerJs::jget($sch, 'exponent')))) {
                            $add('unit-mismatch', 'error', $at, sprintf("'%s': policy unit %s differs from the schema's %s (rule 20)", $name, AnalyzerJs::jsJson($tag), AnalyzerJs::jsJson($sch)));
                        }
                    }
                }
            }
        };

        foreach (AnalyzerJs::reqList($model->get('predicates')) as $i => $p) {
            if (!($p instanceof Obj) && !AnalyzerJs::isArr($p)) {
                continue;
            }
            $check($p, sprintf('predicates[%d]', $i), false);
            $r = AnalyzerCore::alwaysDenies(Obj::of(['predicates' => [$p]]));
            if (AnalyzerJs::truthy($r->get('alwaysDenies')) && !AnalyzerJs::truthy($r->get('approximate'))) {
                $add('unreachable-predicate', 'warn', sprintf('predicates[%d]', $i), 'no action can ever match this predicate');
            }
        }
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $i => $v) {
            $check(AnalyzerJs::jget($v, 'when'), sprintf('vetoes[%d]', $i), true);
        }

        // a money verb with no ceiling in any predicate that grants it
        $predicates = AnalyzerJs::reqList($model->get('predicates'));
        foreach ($shapes as $s) {
            $sverb = AnalyzerJs::own($s, 'verb');
            $money = [];
            foreach (AnalyzerJs::keyOrder($s->get('params')) as $name) {
                if (self::semanticMoney($s->get('params')->get($name))) {
                    $money[] = $name;
                }
            }
            if (!$money) {
                continue;
            }
            $granting = [];
            foreach ($predicates as $p) {
                if (self::grants($p, $sverb)) {
                    $granting[] = $p;
                }
            }
            if (!$granting) {
                if ($listUngranted) {
                    $add('verb-not-granted', 'info', AnalyzerJs::jsStr($sverb), sprintf("the schema declares '%s' but no predicate grants it", AnalyzerJs::jsStr($sverb)));
                }
                continue;
            }
            foreach ($money as $name) {
                $path = 'action.params.' . $name;
                $allBounded = true;
                foreach ($granting as $p) {
                    if (!self::bounded($p, $path)) {
                        $allBounded = false;
                        break;
                    }
                }
                if (!$allBounded) {
                    $add('unbounded-money', 'warn', AnalyzerJs::jsStr($sverb), sprintf("'%s' can move '%s' with no per-action ceiling in at least one granting predicate", AnalyzerJs::jsStr($sverb), $name));
                }
            }
        }
        if ($listUngranted) {
            foreach ($shapes as $s) {
                $anyMoney = false;
                foreach ($s->get('params')->keys() as $k) {
                    if (self::semanticMoney($s->get('params')->get($k))) {
                        $anyMoney = true;
                        break;
                    }
                }
                if ($anyMoney) {
                    continue;
                }
                $sverb = AnalyzerJs::own($s, 'verb');
                $granted = false;
                foreach ($predicates as $p) {
                    if (self::grants($p, $sverb)) {
                        $granted = true;
                        break;
                    }
                }
                if (!$granted) {
                    $add('verb-not-granted', 'info', AnalyzerJs::jsStr($sverb), sprintf("the schema declares '%s' but no predicate grants it", AnalyzerJs::jsStr($sverb)));
                }
            }
        }
        $ok = true;
        foreach ($findings as $f) {
            if ($f->get('severity') === 'error') {
                $ok = false;
            }
        }
        return Obj::of(['ok' => $ok, 'findings' => $findings]);
    }

    private static function bounded(mixed $p, string $path): bool
    {
        foreach (AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), [])) as $w) {
            $srcW = Predicates::isGroupCondition($w) ? Obj::of(['all_of' => $w->has('all_of') ? $w->get('all_of') : []]) : $w;
            foreach (self::leaves($srcW, []) as $c) {
                if (Predicates::isLeafCondition($c) && $c->get('field') === $path && in_array($c->get('op'), ['lt', 'lte', 'eq', 'in'], true)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Options: null, an Obj, or a PHP assoc array keyed by the option names. */
    private static function optsOf(mixed $o): mixed
    {
        if ($o === null || $o === []) {
            return new Obj();
        }
        return (is_array($o) && !array_is_list($o)) ? Obj::of($o) : $o;
    }

    // ---- policy-as-code test runner ---------------------------------------------------------------------------------------------

    public static function policyTestsDoc(mixed $policy, mixed $cases): Obj
    {
        return Obj::of(['v' => 1, 'kind' => self::POLICY_TESTS_KIND, 'policy_digest' => AnalyzerResidual::policyDigestOf(AnalyzerCore::toModel($policy)), 'cases' => $cases]);
    }

    /**
     * Run a test document against a policy: {total, passed, failures, digestMatch, ok}. With `requireDigest` a changed policy fails
     * even if every case still passes.
     */
    public static function runPolicyTests(mixed $policy, mixed $doc, mixed $opts = null): Obj
    {
        $opts = self::optsOf($opts);
        $model = AnalyzerCore::toModel($policy);
        $failures = [];
        $cases = AnalyzerJs::reqList(AnalyzerJs::jget($doc, 'cases'));
        foreach ($cases as $c) {
            $w = AnalyzerCoverage::witnessOf($model, AnalyzerJs::jget($c, 'action'));
            $decidedBy = $w->get('winner')->get('id');
            $expBy = AnalyzerJs::jget($c, 'decidedBy');
            if (!AnalyzerJs::strictEq($w->get('decision'), AnalyzerJs::jget($c, 'expect')) || (!($expBy instanceof Undef) && !AnalyzerJs::strictEq($expBy, $decidedBy))) {
                $f = AnalyzerJs::uobj(['name' => AnalyzerJs::jget($c, 'name'), 'expected' => AnalyzerJs::jget($c, 'expect'), 'got' => $w->get('decision'), 'decidedBy' => $decidedBy]);
                if (!($expBy instanceof Undef)) {
                    $f->set('expectedDecidedBy', $expBy);
                }
                $failures[] = $f;
            }
        }
        $digestMatch = AnalyzerJs::strictEq(AnalyzerJs::jget($doc, 'policy_digest'), AnalyzerResidual::policyDigestOf($model));
        return Obj::of([
            'total' => count($cases), 'passed' => count($cases) - count($failures), 'failures' => $failures, 'digestMatch' => $digestMatch,
            'ok' => count($failures) === 0 && (AnalyzerJs::jget($opts, 'requireDigest') !== true || $digestMatch),
        ]);
    }

    private static function message(mixed $doc): string
    {
        return self::POLICY_TESTS_SIG_DOMAIN . hash('sha256', Pca::hashCanonical(AnalyzerNarrowing::modelOf($doc)), true);
    }

    /** The principal signs the confirmed examples. `$secret` is the Ed25519 seed. */
    public static function signPolicyTests(mixed $doc, string $secret, string $signerPublic): Obj
    {
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($secret));
        return Obj::of(['doc' => $doc, 'signer' => $signerPublic, 'sig' => Pca::b64u(sodium_crypto_sign_detached(self::message($doc), $sk))]);
    }

    public static function verifyPolicyTests(mixed $s, mixed $expectedSigner): bool
    {
        try {
            if (!AnalyzerJs::strictEq(AnalyzerJs::jget($s, 'signer'), $expectedSigner)) {
                return false;
            }
            $d = AnalyzerJs::jget($s, 'doc');
            if ($d instanceof Undef || $d === null || AnalyzerJs::jget($d, 'kind') !== self::POLICY_TESTS_KIND) {
                return false;
            }
            $sig = AnalyzerJs::jget($s, 'sig');
            if (!is_string($sig)) {
                return false;
            }
            $pk = Pca::unb64u(AnalyzerJs::jget($s, 'signer'), 32);
            $msg = self::message($d);
            $sg = Pca::unb64u($sig, 64);
            if ($pk === null || $sg === null) {
                return false;
            }
            return sodium_crypto_sign_verify_detached($sg, $msg, $pk);
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return list<string> */
    private static function paramPaths(mixed $p): array
    {
        $out = [];
        $walk = function (mixed $c) use (&$walk, &$out): void {
            if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
                return;
            }
            $o = $c instanceof Obj ? $c : new Obj();
            $f = $o->get('field');
            if (is_string($f) && str_starts_with($f, 'action.params.')) {
                $out['k' . $f] = $f;
            }
            foreach (['all_of', 'any_of'] as $k) {
                if (AnalyzerJs::isArr($o->get($k))) {
                    foreach ($o->get($k) as $x) {
                        $walk($x);
                    }
                }
            }
            if (AnalyzerJs::truthy(AnalyzerJs::own($o, 'not'))) {
                $walk($o->get('not'));
            }
        };
        $w = AnalyzerJs::jget($p, 'where');
        if (AnalyzerJs::isArr($w)) {
            foreach ($w as $c) {
                $walk($c);
            }
        }
        return array_values($out);
    }

    /**
     * Boundary examples for every clause and numeric threshold: one minimal allow per permit, one trigger per prohibition, and the
     * points just below, at and just above each threshold. Expectations are the policy's CURRENT behaviour, to be confirmed.
     */
    public static function generateBoundaryTests(mixed $policy, mixed $o = null): Obj
    {
        $o = self::optsOf($o);
        $eps = AnalyzerJs::nn(AnalyzerJs::jget($o, 'epsilon'), 1);
        if (!AnalyzerJs::isNum($eps)) {
            throw new \TypeError('epsilon must be a number');
        }
        $eps = AnalyzerJs::jsnum($eps);
        $model = AnalyzerCore::toModel($policy);
        $cases = [];
        $seen = [];

        $add = function (string $name, Obj $action) use (&$cases, &$seen, $model): void {
            $key = AnalyzerJs::jsJson($action);
            if (isset($seen['k' . $key])) {
                return;
            }
            $seen['k' . $key] = true;
            $w = AnalyzerCoverage::witnessOf($model, $action);
            $c = Obj::of(['name' => $name, 'action' => $action, 'expect' => $w->get('decision')]);
            if ($w->get('winner')->get('id') !== null) {
                $c->set('decidedBy', $w->get('winner')->get('id'));
            }
            $cases[] = $c;
        };

        foreach (AnalyzerJs::reqList($model->get('predicates')) as $i => $p) {
            $r = AnalyzerCore::alwaysDenies(Obj::of([
                'predicates' => [$p], 'caveats' => $model->get('caveats'), 'vetoes' => $model->get('vetoes'), 'tighten' => $model->get('tighten'),
            ]));
            $base = $r->get('witness');
            if ($base === null) {
                $base = AnalyzerCore::alwaysDenies(Obj::of(['predicates' => [$p], 'caveats' => $model->get('caveats')]))->get('witness');
            }
            if ($base === null || ($base instanceof Obj && !$base->keys())) {
                continue;
            }
            if (!($base instanceof Obj)) {
                throw new \TypeError('witness must be an object');
            }
            $add(sprintf('%s: minimal admitted action', AnalyzerCoverage::permitId($i)), $base);
            foreach (self::paramPaths($p) as $path) {
                $name = substr($path, strlen('action.params.'));
                foreach (AnalyzerExposure::thresholdsOf(AnalyzerCore::toModel(Obj::of(['predicates' => [$p]])), $path) as $t) {
                    if (!AnalyzerJs::isNum($t)) {
                        throw new \TypeError('threshold must be a number');
                    }
                    $tf = AnalyzerJs::jsnum($t);
                    foreach ([['below', $tf - $eps], ['at', $t], ['above', $tf + $eps]] as [$tag, $v]) {
                        $a = AnalyzerJs::copy($base);
                        $bp = $base->get('params');
                        $params = new Obj();
                        if ($bp instanceof Obj) {
                            foreach ($bp->keys() as $k) {
                                $params->set($k, $bp->get($k));
                            }
                        }
                        $params->set($name, $v);
                        $a->set('params', $params);
                        $add(sprintf('%s: %s %s %s', AnalyzerCoverage::permitId($i), $name, $tag, AnalyzerJs::numStr($tf)), $a);
                    }
                }
            }
            $res = $base->get('resource');
            if (!is_string($res)) {
                throw new \TypeError('witness resource must be a string');
            }
            $other = AnalyzerJs::copy($base);
            $other->set('resource', $res . '/__other__');
            $add(sprintf('%s: unmentioned resource', AnalyzerCoverage::permitId($i)), $other);
        }
        // a trigger per prohibition: an action some permit would allow and this prohibition stops
        $permitOnly = AnalyzerJs::copy($model);
        $permitOnly->set('vetoes', []);
        $permitOnly->set('tighten', []);
        $pr = AnalyzerCore::collectProbes(Obj::of(['predicateSets' => [AnalyzerCore::probeSet($model)], 'varyReversibility' => $model->has('revCap')]));
        foreach (AnalyzerJs::reqList($model->get('vetoes')) as $v) {
            $hits = AnalyzerCore::collect(
                $pr,
                static fn($rep): bool => AnalyzerCore::decide($permitOnly, $rep) !== 'deny'
                    && AnalyzerCore::vetoApplies($v, AnalyzerCore::contextOfAction(AnalyzerCore::repToAction($rep))),
                AnalyzerCore::DEFAULT_MAX_COMBINATIONS,
                1,
            )->get('hits');
            if ($hits) {
                $add(sprintf('%s: trigger', AnalyzerJs::jsStr(AnalyzerJs::jget($v, 'id'))), AnalyzerCore::repToAction($hits[0]));
            }
        }
        return self::policyTestsDoc($policy, $cases);
    }

    /**
     * Decision of every case of a test document under `$policy`.
     * @return list<string>
     */
    public static function decideAll(mixed $policy, mixed $doc): array
    {
        $model = AnalyzerCore::toModel($policy);
        return array_map(static fn($c) => AnalyzerCore::decideAction($model, AnalyzerJs::jget($c, 'action')), AnalyzerJs::reqList(AnalyzerJs::jget($doc, 'cases')));
    }
}
