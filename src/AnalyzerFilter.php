<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Predicates.php';

/** An expression the filter cannot express exactly (the caller falls back to per-row authorization). */
final class AnalyzerUnsupported extends \Exception
{
}

/**
 * Data filtering: a residual policy compiled to a parameterized SQL WHERE fragment and to a UCAST tree, plus evaluators for both
 * (used to check the compiled forms against the policy evaluator). The filter may only ever select a subset of what the policy
 * admits: anything it cannot express exactly makes the whole compile fail with a reason and the caller authorizes per row.
 * Advisory: the verifier stays authoritative. Filter expressions and UCAST nodes are Obj trees.
 */
final class AnalyzerFilter
{
    private const COL_RE = '/\A[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?\z/';
    private const SQL_OPS = ['eq' => '=', 'ne' => '<>', 'lt' => '<', 'lte' => '<=', 'gt' => '>', 'gte' => '>='];
    private const INV = ['eq' => 'ne', 'ne' => 'eq', 'lt' => 'gte', 'lte' => 'gt', 'gt' => 'lte', 'gte' => 'lt'];

    private static function scalar(mixed $v): bool
    {
        return is_bool($v) || is_string($v) || (AnalyzerJs::isNum($v) && AnalyzerJs::fin($v) !== null);
    }

    private static function colOf(mixed $path, mixed $cols): string
    {
        if (!($cols instanceof Obj)) {
            throw new \TypeError('columns is not an object');
        }
        $c = is_string($path) && $cols->has($path) ? $cols->get($path) : AnalyzerJs::undef();
        if (!is_string($c) || preg_match(self::COL_RE, $c) !== 1) {
            throw new AnalyzerUnsupported("field '" . AnalyzerJs::jsStr($path) . "' has no usable column");
        }
        return $c;
    }

    /** @param list<mixed> $xs */
    private static function and(array $xs): Obj
    {
        return count($xs) === 0 ? Obj::of(['t' => 'true']) : (count($xs) === 1 ? $xs[0] : Obj::of(['t' => 'and', 'xs' => $xs]));
    }

    /** @param list<mixed> $xs */
    private static function or(array $xs): Obj
    {
        return count($xs) === 0 ? Obj::of(['t' => 'false']) : (count($xs) === 1 ? $xs[0] : Obj::of(['t' => 'or', 'xs' => $xs]));
    }

    private static function coalesce(Obj $x, bool $def): Obj
    {
        return Obj::of(['t' => 'coalesce', 'x' => $x, 'def' => $def]);
    }

    private static function cond(mixed $c, mixed $cols): Obj
    {
        if (!($c instanceof Obj) && !AnalyzerJs::isArr($c)) {
            throw new AnalyzerUnsupported('malformed condition');
        }
        if (Predicates::isGroupCondition($c)) {
            /** @var Obj $c */
            if ($c->has('all_of') && AnalyzerJs::isArr($c->get('all_of')) && count($c->get('all_of')) > 0) {
                return self::and(array_map(static fn($x) => self::cond($x, $cols), $c->get('all_of')));
            }
            if ($c->has('any_of') && AnalyzerJs::isArr($c->get('any_of')) && count($c->get('any_of')) > 0) {
                return self::or(array_map(static fn($x) => self::cond($x, $cols), $c->get('any_of')));
            }
            if ($c->has('not')) {
                return Obj::of(['t' => 'not', 'x' => self::cond($c->get('not'), $cols)]);
            }
            throw new AnalyzerUnsupported('empty condition group');
        }
        if (!Predicates::isLeafCondition($c)) {
            throw new AnalyzerUnsupported('malformed condition');
        }
        /** @var Obj $c */
        if ($c->has('ref')) {
            throw new AnalyzerUnsupported('cross-field ref');
        }
        $col = self::colOf($c->get('field'), $cols);
        $v = AnalyzerJs::own($c, 'value');
        $op = AnalyzerJs::own($c, 'op');
        if ($op === 'eq' || $op === 'ne') {
            if (!self::scalar($v)) {
                throw new AnalyzerUnsupported("$op against a non-scalar");
            }
            return Obj::of(['t' => 'cmp', 'col' => $col, 'op' => $op, 'v' => $v]);
        }
        if ($op === 'lt' || $op === 'lte' || $op === 'gt' || $op === 'gte') {
            if (!AnalyzerJs::isNum($v) || AnalyzerJs::fin($v) === null) {
                throw new AnalyzerUnsupported('string ordering follows UTF-8 byte order, which SQL collations do not guarantee');
            }
            return Obj::of(['t' => 'cmp', 'col' => $col, 'op' => $op, 'v' => $v]);
        }
        if ($op === 'in' || $op === 'nin') {
            if (!AnalyzerJs::isArr($v) || count($v) === 0) {
                throw new AnalyzerUnsupported("$op needs a non-empty list of scalars");
            }
            foreach ($v as $x) {
                if (!self::scalar($x)) {
                    throw new AnalyzerUnsupported("$op needs a non-empty list of scalars");
                }
            }
            return Obj::of(['t' => 'in', 'col' => $col, 'vs' => $v, 'neg' => $op === 'nin']);
        }
        if ($op === 'prefix') {
            if (!is_string($v)) {
                throw new AnalyzerUnsupported('prefix needs a string');
            }
            return Obj::of(['t' => 'prefix', 'col' => $col, 'prefix' => $v]);
        }
        if ($op === 'exists') {
            return Obj::of(['t' => 'null', 'col' => $col, 'isNull' => $v === false]);
        }
        throw new AnalyzerUnsupported("operator '" . AnalyzerJs::jsStr($op) . "' has no exact SQL form");
    }

    private static function resourceExpr(mixed $p, mixed $cols): Obj
    {
        $r = AnalyzerJs::jget($p, 'resource');
        if ($r instanceof Undef || AnalyzerJs::strictEq($r, '*')) {
            return Obj::of(['t' => 'true']);
        }
        $col = self::colOf('action.resource', $cols);
        if (!is_string($r)) {
            throw new \TypeError('resource.startsWith is not a function');
        }
        if (str_starts_with($r, 're:')) {
            throw new AnalyzerUnsupported('regex resource matcher');
        }
        if (str_ends_with($r, '*')) {
            return Obj::of(['t' => 'prefix', 'col' => $col, 'prefix' => substr($r, 0, -1)]);
        }
        return Obj::of(['t' => 'cmp', 'col' => $col, 'op' => 'eq', 'v' => $r]);
    }

    private static function vetoExpr(mixed $v, mixed $cols): Obj
    {
        $wh = AnalyzerJs::jget($v, 'when');
        $xs = [];
        if (!(AnalyzerJs::jget($wh, 'resource') instanceof Undef)) {
            $xs[] = self::coalesce(self::resourceExpr($wh, $cols), true);
        }
        $where = AnalyzerJs::nn(AnalyzerJs::jget($wh, 'where'), []);
        foreach (AnalyzerJs::reqList($where) as $c) {
            $xs[] = self::coalesce(self::cond($c, $cols), true);
        }
        $parts = [self::and($xs)];
        $over = AnalyzerJs::jget($v, 'over');
        if (AnalyzerJs::truthy($over)) {
            $col = self::colOf(AnalyzerJs::jget($over, 'path'), $cols);
            $parts[] = self::or([
                Obj::of(['t' => 'null', 'col' => $col, 'isNull' => true]),
                Obj::of(['t' => 'cmp', 'col' => $col, 'op' => 'lt', 'v' => new Num('0')]),
                Obj::of(['t' => 'cmp', 'col' => $col, 'op' => 'gt', 'v' => AnalyzerJs::jget($over, 'threshold')]),
            ]);
        }
        $unless = AnalyzerJs::jget($v, 'unless');
        if (AnalyzerJs::jget($v, 'kind') !== 'approval' && AnalyzerJs::truthy($unless)) {
            // `unless.length > 0`: only an array (or a string, whose `.map` then throws) has a length
            if (is_string($unless)) {
                throw new \TypeError('unless.map is not a function');
            }
            if (AnalyzerJs::isArr($unless) && count($unless) > 0) {
                $parts[] = Obj::of(['t' => 'not', 'x' => self::and(array_map(static fn($c) => self::coalesce(self::cond($c, $cols), false), $unless))]);
            }
        }
        return self::and($parts);
    }

    private static function partExpr(mixed $p, mixed $cols, mixed $include): Obj
    {
        $permits = [];
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($p, 'predicates')) as $x) {
            $terms = [self::resourceExpr($x, $cols)];
            foreach (AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($x, 'where'), [])) as $c) {
                $terms[] = self::cond($c, $cols);
            }
            $permits[] = self::and($terms);
        }
        $gates = [self::or($permits)];
        foreach (AnalyzerJs::reqList(AnalyzerJs::jget($p, 'vetoes')) as $v) {
            $e = self::vetoExpr($v, $cols);
            // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
            if (AnalyzerJs::jget($v, 'kind') === 'deny' || $include === 'autonomous') {
                $gates[] = Obj::of(['t' => 'not', 'x' => $e]);
            }
        }
        if ($include === 'autonomous') {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($p, 'tighten')) as $t) {
                $gates[] = Obj::of(['t' => 'not', 'x' => self::coalesce(self::cond(AnalyzerJs::jget($t, 'when'), $cols), true)]);
            }
        } else {
            foreach (AnalyzerJs::reqList(AnalyzerJs::jget($p, 'tighten')) as $t) {
                if (AnalyzerJs::jget($t, 'signal') === 'deny') {
                    $gates[] = Obj::of(['t' => 'not', 'x' => self::coalesce(self::cond(AnalyzerJs::jget($t, 'when'), $cols), true)]);
                }
            }
        }
        return self::and($gates);
    }

    /** @param list<mixed> $params */
    private static function ph(mixed $v, mixed $dialect, array &$params): string
    {
        $params[] = $v;
        return $dialect === 'postgres' ? '$' . count($params) : '?';
    }

    /** @param list<mixed> $params */
    private static function render(mixed $x, mixed $dialect, array &$params): string
    {
        $t = AnalyzerJs::jget($x, 't');
        if ($t === 'true') {
            return 'TRUE';
        }
        if ($t === 'false') {
            return 'FALSE';
        }
        if ($t === 'cmp') {
            $op = $x->get('op');
            if (!is_string($op) || !isset(self::SQL_OPS[$op])) {
                throw new \RuntimeException('unknown comparison operator');
            }
            return $x->get('col') . ' ' . self::SQL_OPS[$op] . ' ' . self::ph($x->get('v'), $dialect, $params);
        }
        if ($t === 'in') {
            $items = [];
            foreach (AnalyzerJs::reqList($x->get('vs')) as $v) {
                $items[] = self::ph($v, $dialect, $params);
            }
            return $x->get('col') . ' ' . ($x->get('neg') ? 'NOT IN' : 'IN') . ' (' . implode(', ', $items) . ')';
        }
        if ($t === 'prefix') {
            $esc = preg_replace('/[!%_]/', '!$0', (string)$x->get('prefix')) . '%';
            return $x->get('col') . ' LIKE ' . self::ph($esc, $dialect, $params) . " ESCAPE '!'";
        }
        if ($t === 'null') {
            return $x->get('col') . ' IS ' . ($x->get('isNull') ? '' : 'NOT ') . 'NULL';
        }
        if ($t === 'and' || $t === 'or') {
            $parts = [];
            foreach (AnalyzerJs::reqList($x->get('xs')) as $y) {
                $parts[] = self::render($y, $dialect, $params);
            }
            return '(' . implode($t === 'and' ? ' AND ' : ' OR ', $parts) . ')';
        }
        if ($t === 'not') {
            return 'NOT (' . self::render($x->get('x'), $dialect, $params) . ')';
        }
        return 'COALESCE(' . self::render($x->get('x'), $dialect, $params) . ', ' . ($x->get('def') ? 'TRUE' : 'FALSE') . ')';
    }

    /**
     * Compile a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or {ok: false, reason} when it cannot be
     * done exactly (the caller then falls back to per-row authorization).
     */
    public static function toFilter(mixed $res, mixed $o): Obj
    {
        try {
            if (AnalyzerJs::jget($res, 'decision') === 'never') {
                return Obj::of(['ok' => true, 'expr' => Obj::of(['t' => 'false']), 'sql' => 'FALSE', 'params' => [], 'ucast' => self::toUcast(Obj::of(['t' => 'false']))]);
            }
            $include = AnalyzerJs::nn(AnalyzerJs::jget($o, 'include'), 'autonomous');
            $pol = AnalyzerJs::jget($res, 'policy');
            if (!($pol instanceof Obj)) {
                throw new \TypeError('policy is not an object');
            }
            $own = $pol->without('meet');
            $meet = $pol->get('meet');
            $cols = AnalyzerJs::jget($o, 'columns');
            $parts = [$own];
            foreach (AnalyzerJs::reqList(AnalyzerJs::nn($meet, [])) as $m) {
                $parts[] = $m;
            }
            $expr = self::and(array_map(static fn($p) => self::partExpr($p, $cols, $include), $parts));
            $params = [];
            $sql = self::render($expr, AnalyzerJs::nn(AnalyzerJs::jget($o, 'dialect'), 'postgres'), $params);
            return Obj::of(['ok' => true, 'expr' => $expr, 'sql' => $sql, 'params' => $params, 'ucast' => self::toUcast($expr)]);
        } catch (AnalyzerUnsupported $e) {
            return Obj::of(['ok' => false, 'reason' => $e->getMessage()]);
        } catch (\Throwable) { // any other failure is a compile error, never a looser filter
            return Obj::of(['ok' => false, 'reason' => 'filter compilation error']);
        }
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

    private static function rowGet(mixed $row, string $c): mixed
    {
        return $row instanceof Obj && $row->has($c) ? $row->get($c) : null;
    }

    /** `a op b` over two values of the same typeof (relational operators only). */
    private static function relate(string $op, mixed $a, mixed $b): bool
    {
        $t = self::typeOf($a);
        if ($t === 'object' || $t === 'undefined') {
            return false;
        }
        if ($t === 'number') {
            $c = AnalyzerJs::jsnum($a) <=> AnalyzerJs::jsnum($b);
            $nan = is_nan(AnalyzerJs::jsnum($a)) || is_nan(AnalyzerJs::jsnum($b));
        } elseif ($t === 'string') {
            $c = AnalyzerJs::u16cmp($a, $b);
            $nan = false;
        } else {
            $c = ((int)$a) <=> ((int)$b);
            $nan = false;
        }
        if ($nan) {
            return false;
        }
        return match ($op) {
            'lt' => $c < 0,
            'lte' => $c <= 0,
            'gt' => $c > 0,
            default => $c >= 0,
        };
    }

    /** Evaluate a filter expression over one row with SQL's three-valued (Kleene) logic: true, false or null (NULL). */
    public static function evalFilter(mixed $e, mixed $row): ?bool
    {
        return self::kleene($e, $row);
    }

    private static function kleene(mixed $x, mixed $row): ?bool
    {
        $t = AnalyzerJs::jget($x, 't');
        if ($t === 'true') {
            return true;
        }
        if ($t === 'false') {
            return false;
        }
        if ($t === 'cmp') {
            $a = self::rowGet($row, (string)$x->get('col'));
            $b = $x->get('v');
            if ($a === null || self::typeOf($a) !== self::typeOf($b)) {
                return null;
            }
            $op = $x->get('op');
            if ($op === 'eq') {
                return AnalyzerJs::strictEq($a, $b);
            }
            if ($op === 'ne') {
                return !AnalyzerJs::strictEq($a, $b);
            }
            return self::relate((string)$op, $a, $b);
        }
        if ($t === 'in') {
            $a = self::rowGet($row, (string)$x->get('col'));
            if ($a === null) {
                return null;
            }
            $hit = false;
            foreach (AnalyzerJs::reqList($x->get('vs')) as $v) {
                if (AnalyzerJs::strictEq($v, $a)) {
                    $hit = true;
                    break;
                }
            }
            return $x->get('neg') ? !$hit : $hit;
        }
        if ($t === 'prefix') {
            $a = self::rowGet($row, (string)$x->get('col'));
            return is_string($a) ? str_starts_with($a, (string)$x->get('prefix')) : null;
        }
        if ($t === 'null') {
            return (self::rowGet($row, (string)$x->get('col')) === null) === ($x->get('isNull') === true);
        }
        if ($t === 'and') {
            $unk = false;
            foreach (AnalyzerJs::reqList($x->get('xs')) as $y) {
                $v = self::kleene($y, $row);
                if ($v === false) {
                    return false;
                }
                if ($v === null) {
                    $unk = true;
                }
            }
            return $unk ? null : true;
        }
        if ($t === 'or') {
            $unk = false;
            foreach (AnalyzerJs::reqList($x->get('xs')) as $y) {
                $v = self::kleene($y, $row);
                if ($v === true) {
                    return true;
                }
                if ($v === null) {
                    $unk = true;
                }
            }
            return $unk ? null : false;
        }
        if ($t === 'not') {
            $v = self::kleene($x->get('x'), $row);
            return $v === null ? null : !$v;
        }
        $v = self::kleene($x->get('x'), $row);
        return $v ?? ($x->get('def') === true);
    }

    // ---- UCAST -------------------------------------------------------------------------------------------------------------------

    private static function isEmpty(Obj $u, string $op): bool
    {
        return $u->get('type') === 'compound' && $u->get('operator') === $op && count($u->get('value')) === 0;
    }

    /** @param list<Obj> $xs */
    private static function join(string $op, array $xs): Obj
    {
        $other = $op === 'and' ? 'or' : 'and';
        $flat = [];
        foreach ($xs as $x) {
            if ($x->get('type') === 'compound' && $x->get('operator') === $op) {
                foreach ($x->get('value') as $y) {
                    $flat[] = $y;
                }
            } else {
                $flat[] = $x;
            }
        }
        foreach ($flat as $x) {
            if (self::isEmpty($x, $other)) {
                return Obj::of(['type' => 'compound', 'operator' => $other, 'value' => []]);
            }
        }
        $kept = [];
        foreach ($flat as $x) {
            if (!self::isEmpty($x, $op)) {
                $kept[] = $x;
            }
        }
        if (count($kept) === 1) {
            return $kept[0];
        }
        return Obj::of(['type' => 'compound', 'operator' => $op, 'value' => $kept]);
    }

    /** @param list<Obj> $xs */
    private static function and2(array $xs): Obj
    {
        return self::join('and', $xs);
    }

    /** @param list<Obj> $xs */
    private static function or2(array $xs): Obj
    {
        return self::join('or', $xs);
    }

    private static function not2(Obj $x): Obj
    {
        return Obj::of(['type' => 'compound', 'operator' => 'not', 'value' => [$x]]);
    }

    private static function f(string $field, string $operator, mixed $value): Obj
    {
        return Obj::of(['type' => 'field', 'field' => $field, 'operator' => $operator, 'value' => $value]);
    }

    private static function notNull(string $c): Obj
    {
        return self::f($c, 'ne', null);
    }

    private static function inv(mixed $op): string
    {
        if (!is_string($op) || !isset(self::INV[$op])) {
            throw new \RuntimeException('unknown comparison operator');
        }
        return self::INV[$op];
    }

    /** "x is definitely true". */
    private static function tt(mixed $x): Obj
    {
        $t = AnalyzerJs::jget($x, 't');
        $col = (string)$x->get('col');
        if ($t === 'true') {
            return self::and2([]);
        }
        if ($t === 'false') {
            return self::or2([]);
        }
        if ($t === 'cmp') {
            return $x->get('op') === 'ne'
                ? self::and2([self::notNull($col), self::f($col, 'ne', $x->get('v'))])
                : self::f($col, (string)$x->get('op'), $x->get('v'));
        }
        if ($t === 'in') {
            return $x->get('neg') ? self::and2([self::notNull($col), self::f($col, 'nin', $x->get('vs'))]) : self::f($col, 'in', $x->get('vs'));
        }
        if ($t === 'prefix') {
            return self::f($col, 'startswith', $x->get('prefix'));
        }
        if ($t === 'null') {
            return $x->get('isNull') === true ? self::f($col, 'eq', null) : self::notNull($col);
        }
        if ($t === 'and') {
            return self::and2(array_map(self::tt(...), AnalyzerJs::reqList($x->get('xs'))));
        }
        if ($t === 'or') {
            return self::or2(array_map(self::tt(...), AnalyzerJs::reqList($x->get('xs'))));
        }
        if ($t === 'not') {
            return self::ff($x->get('x'));
        }
        return $x->get('def') === true ? self::not2(self::ff($x->get('x'))) : self::tt($x->get('x'));
    }

    /** "x is definitely false" (both false when a referenced column is NULL). */
    private static function ff(mixed $x): Obj
    {
        $t = AnalyzerJs::jget($x, 't');
        $col = (string)$x->get('col');
        if ($t === 'true') {
            return self::or2([]);
        }
        if ($t === 'false') {
            return self::and2([]);
        }
        if ($t === 'cmp') {
            return self::and2([self::notNull($col), self::f($col, self::inv($x->get('op')), $x->get('v'))]);
        }
        if ($t === 'in') {
            return $x->get('neg') ? self::f($col, 'in', $x->get('vs')) : self::and2([self::notNull($col), self::f($col, 'nin', $x->get('vs'))]);
        }
        if ($t === 'prefix') {
            return self::and2([self::notNull($col), self::not2(self::f($col, 'startswith', $x->get('prefix')))]);
        }
        if ($t === 'null') {
            return $x->get('isNull') === true ? self::notNull($col) : self::f($col, 'eq', null);
        }
        if ($t === 'and') {
            return self::or2(array_map(self::ff(...), AnalyzerJs::reqList($x->get('xs'))));
        }
        if ($t === 'or') {
            return self::and2(array_map(self::ff(...), AnalyzerJs::reqList($x->get('xs'))));
        }
        if ($t === 'not') {
            return self::tt($x->get('x'));
        }
        // coalesce(x, FALSE) is false exactly when x is not definitely true
        return $x->get('def') === true ? self::ff($x->get('x')) : self::not2(self::tt($x->get('x')));
    }

    /** The filter as a UCAST tree whose rows are exactly those the SQL form selects. */
    public static function toUcast(mixed $e): Obj
    {
        return self::tt($e);
    }

    /** Evaluate a UCAST tree over one row (two-valued; a comparison with NULL is false). */
    public static function evalUcast(mixed $u, mixed $row): bool
    {
        if ($u->get('type') === 'compound') {
            $vals = AnalyzerJs::reqList($u->get('value'));
            if ($u->get('operator') === 'and') {
                foreach ($vals as $c) {
                    if (!self::evalUcast($c, $row)) {
                        return false;
                    }
                }
                return true;
            }
            if ($u->get('operator') === 'or') {
                foreach ($vals as $c) {
                    if (self::evalUcast($c, $row)) {
                        return true;
                    }
                }
                return false;
            }
            return !self::evalUcast($vals[0], $row);
        }
        $a = self::rowGet($row, (string)$u->get('field'));
        $v = $u->get('value');
        $op = $u->get('operator');
        if ($op === 'eq' && $v === null) {
            return $a === null;
        }
        if ($op === 'ne' && $v === null) {
            return $a !== null;
        }
        if ($a === null) {
            return false;
        }
        if ($op === 'eq') {
            return AnalyzerJs::strictEq($a, $v);
        }
        if ($op === 'ne' || $op === 'lt' || $op === 'lte' || $op === 'gt' || $op === 'gte') {
            if (self::typeOf($a) !== self::typeOf($v)) {
                return false;
            }
            if ($op === 'ne') {
                return !AnalyzerJs::strictEq($a, $v);
            }
            return self::relate($op, $a, $v);
        }
        if ($op === 'in' || $op === 'nin') {
            $hit = false;
            foreach (AnalyzerJs::reqList($v) as $e) {
                if (AnalyzerJs::strictEq($e, $a)) {
                    $hit = true;
                    break;
                }
            }
            return $op === 'in' ? $hit : !$hit;
        }
        if ($op === 'startswith') {
            return is_string($a) && str_starts_with($a, AnalyzerJs::jsStr($v));
        }
        return false;
    }
}
