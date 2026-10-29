<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Predicates.php';

/**
 * Typed missing context and the stored-wins merge (packages/pca/src/missing-context.ts). A condition that cannot be decided because
 * a value is absent names what is missing and who may supply it; a request-supplied value never replaces a bound one. Total.
 * Replays packages/pca/conformance/missing-context-vectors.json. Values are parsed JSON (Obj, lists, Num).
 */
final class MissingContext
{
    public const SUPPLIERS = ['principal', 'discharge_issuer', 'rs_observation', 'agent_declared_untrusted'];
    private const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];
    private const PATH_RE = '/\A(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*\z/D';

    /** Longest matching prefix (at a segment boundary) wins; a path matching nothing is `principal`. */
    public static function supplierOf(string $path, Obj $table): string
    {
        $best = null;
        foreach ($table->keys() as $k) {
            if (($path === $k || str_starts_with($path, $k . '.')) && ($best === null || strlen($k) > strlen($best))) {
                $best = $k;
            }
        }
        return $best === null ? 'principal' : (string)$table->get($best);
    }

    public static function supplierTableError(mixed $t): ?string
    {
        if (!($t instanceof Obj)) {
            return 'the supplier table must be an object';
        }
        foreach ($t->keys() as $k) {
            if (preg_match(self::PATH_RE, $k) !== 1 || array_intersect(explode('.', $k), self::FORBIDDEN) !== []) {
                return "bad supplier path '$k'";
            }
            if (!is_string($t->get($k)) || !in_array($t->get($k), self::SUPPLIERS, true)) {
                return "bad supplier for '$k'";
            }
        }
        return null;
    }

    private static function copy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::copy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::copy(...), $v) : $v;
    }

    /** @param array<string,mixed> $out */
    private static function leaves(mixed $v, string $prefix, array &$out, int $depth = 0): void
    {
        if ($depth > 16 || !($v instanceof Obj) || $v->keys() === []) {
            $out[$prefix] = $v;
            return;
        }
        foreach (K3Sig::sortedUtf16($v->keys()) as $k) {
            in_array($k, self::FORBIDDEN, true) || self::leaves($v->get($k), "$prefix.$k", $out, $depth + 1);
        }
    }

    /** @param list<string> $segs */
    private static function setPath(Obj $root, array $segs, mixed $value): void
    {
        $cur = $root;
        for ($i = 0; $i < count($segs) - 1; $i++) {
            if (!($cur->get($segs[$i]) instanceof Obj)) {
                $cur->set($segs[$i], new Obj());
            }
            $cur = $cur->get($segs[$i]);
        }
        $cur->set($segs[count($segs) - 1], $value);
    }

    /** @return array{context: mixed, conflicts: list<string>, dropped: list<string>} bound wins */
    public static function bindContext(mixed $bound, mixed $supplied, ?Obj $table = null): array
    {
        $table ??= new Obj();
        $ctx = self::copy($bound);
        $conflicts = [];
        $dropped = [];
        if (!($supplied instanceof Obj) || !($ctx instanceof Obj)) {
            return ['context' => $ctx, 'conflicts' => $conflicts, 'dropped' => $dropped];
        }
        $flat = [];
        $a = $supplied->get('action');
        $a instanceof Obj && $a->get('params') instanceof Obj && self::leaves($a->get('params'), 'action.params', $flat);
        foreach (['subject', 'env'] as $root) {
            $supplied->get($root) instanceof Obj && self::leaves($supplied->get($root), $root, $flat);
        }
        foreach (K3Sig::sortedUtf16(array_map('strval', array_keys($flat))) as $path) {
            $value = $flat[$path];
            if (self::supplierOf($path, $table) === 'agent_declared_untrusted') {
                $dropped[] = $path;
                continue;
            }
            $r = Predicates::resolvePath($ctx, $path);
            if ($r['found']) {
                Pca::hashCanonical(Obj::of(['v' => $r['value']])) !== Pca::hashCanonical(Obj::of(['v' => $value])) && $conflicts[] = $path;
                continue;
            }
            $segs = explode('.', $path);
            $blocked = false;
            for ($i = 2; $i < count($segs); $i++) {
                $r2 = Predicates::resolvePath($ctx, implode('.', array_slice($segs, 0, $i)));
                $blocked = $blocked || ($r2['found'] && !($r2['value'] instanceof Obj));
            }
            if ($blocked) {
                $conflicts[] = $path;
                continue;
            }
            if (str_starts_with($path, 'action.params')) {
                $act = $ctx->get('action');
                if ($act === null) {
                    $act = Obj::of(['verb' => '', 'resource' => '']);
                    $ctx->set('action', $act);
                }
                $act instanceof Obj && !($act->get('params') instanceof Obj) && $act->set('params', new Obj());
            }
            self::setPath($ctx, $segs, self::copy($value));
        }
        return ['context' => $ctx, 'conflicts' => $conflicts, 'dropped' => $dropped];
    }

    /** @param array<string,true> $out @param array{v: bool} $ill */
    private static function collect(mixed $c, Obj $ctx, array &$out, array &$ill, int $depth = 0): void
    {
        if ($depth > 64 || !($c instanceof Obj)) {
            $ill['v'] = true;
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            $kids = $c->has('all_of') ? $c->get('all_of') : ($c->has('any_of') ? $c->get('any_of') : [$c->get('not')]);
            if (!K3Sig::isList($kids) || $kids === []) {
                $ill['v'] = true;
                return;
            }
            foreach ($kids as $k) {
                self::collect($k, $ctx, $out, $ill, $depth + 1);
            }
            return;
        }
        if (Predicates::evaluateConditionTri($c, $ctx) !== 'unknown') {
            return;
        }
        $absent = false;
        foreach ([$c->get('field'), $c->get('ref')] as $p) {
            if (is_string($p) && $p !== '' && !Predicates::resolvePath($ctx, $p)['found']) {
                $out[$p] = true;
                $absent = true;
            }
        }
        $f = $c->get('field');
        if ($f === 'action.params' || (is_string($f) && str_starts_with($f, 'action.params.'))) {
            $act = $ctx->get('action');
            $p = $act instanceof Obj ? $act->get('params') : null;
            if (!($p instanceof Obj) && !is_array($p)) {
                $out[$f] = true;
                $absent = true;
            }
        }
        $absent || $ill['v'] = true;
    }

    /** @return array{decision: string, reason?: string, missing: list<array{path: string, supplier: string}>} */
    public static function decide(mixed $where, mixed $bound, mixed $supplied = null, mixed $suppliers = null): array
    {
        $deny = static fn (string $reason, array $missing = []): array => ['decision' => 'deny', 'reason' => $reason, 'missing' => $missing];
        try {
            if (!($bound instanceof Obj) || !($bound->get('action') instanceof Obj)) {
                return $deny('bad_context');
            }
            $table = $suppliers ?? new Obj();
            if (($te = self::supplierTableError($table)) !== null) {
                return $deny("bad supplier table: $te");
            }
            if (!K3Sig::isList($where) || $where === []) {
                return $deny('condition_false');
            }
            $b = self::bindContext($bound, $supplied, $table);
            if ($b['conflicts'] !== []) {
                return $deny('context_shadow: ' . implode(',', $b['conflicts']));
            }
            $t = Predicates::evaluateConditionTri(Obj::of(['all_of' => $where]), $b['context']);
            if ($t === 'true') {
                return ['decision' => 'allow', 'missing' => []];
            }
            if ($t === 'false') {
                return $deny('condition_false');
            }
            $paths = [];
            $ill = ['v' => false];
            foreach ($where as $c) {
                self::collect($c, $b['context'], $paths, $ill);
            }
            if ($paths === [] || $ill['v']) {
                return $deny('ill_typed_context');
            }
            $missing = array_map(static fn (string $p): array => ['path' => $p, 'supplier' => self::supplierOf($p, $table)], K3Sig::sortedUtf16(array_map('strval', array_keys($paths))));
            $untrusted = array_values(array_filter($missing, static fn (array $m): bool => $m['supplier'] === 'agent_declared_untrusted'));
            if ($untrusted !== []) {
                return $deny('missing_context_untrusted: ' . implode(',', array_column($untrusted, 'path')), $missing);
            }
            return ['decision' => 'escalate', 'reason' => 'escalate: missing_context ' . implode(',', array_map(static fn (array $m): string => $m['supplier'] . ':' . $m['path'], $missing)), 'missing' => $missing];
        } catch (\Throwable) {
            return $deny('evaluation error (fail closed)');
        }
    }
}
