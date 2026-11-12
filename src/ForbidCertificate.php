<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Predicates.php';

/**
 * Forbid-wins certificate check (security contract C-241): a port of `certificateConsistent` in
 * packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative). The certificate's own table entails its decision:
 * any matched forbid denies (the most authoritative signer is named, ties by id); otherwise no matched permit denies; otherwise
 * a matched escalate clause escalates; otherwise allow. No predicate evaluator is needed. Total: never throws; a certificate
 * that cannot be read is not consistent.
 */
final class ForbidCertificate
{
    private const KINDS = ['permit', 'forbid', 'escalate'];
    private const VALUES = ['true', 'false', 'unknown'];

    /** @param list<string> $precedence signers, most authoritative first */
    public static function consistent(mixed $cert, array $precedence = []): bool
    {
        try {
            if (!($cert instanceof Obj) || !self::isOne($cert->get('v')) || $cert->get('kind') !== 'forbid-wins' || !is_array($cert->get('clauses')) || !array_is_list($cert->get('clauses'))) {
                return false;
            }
            $rows = $cert->get('clauses');
            $winner = $cert->get('winner');
            $shadowed = $cert->get('shadowed');
            if (!($winner instanceof Obj) || !is_array($shadowed)) {
                return false;
            }
            if ($winner->get('kind') === 'malformed') {
                return $rows === [] && $cert->get('decision') === 'deny' && $winner->get('id') === null && $shadowed === [];
            }
            foreach ($rows as $r) {
                if (!($r instanceof Obj) || !is_string($r->get('id')) || !in_array($r->get('kind'), self::KINDS, true) || !in_array($r->get('value'), self::VALUES, true)) {
                    return false;
                }
            }
            $rank = static function (Obj $r) use ($precedence): int {
                $i = is_string($r->get('signer')) ? array_search($r->get('signer'), $precedence, true) : false;
                return $i === false ? count($precedence) : $i; // an unlisted (or absent) signer ranks last
            };
            $hit = static fn (string $kind): array => array_values(array_filter($rows, static fn (Obj $r): bool => $r->get('kind') === $kind && $r->get('value') !== 'false'));
            $forbids = $hit('forbid');
            usort($forbids, static function (Obj $a, Obj $b) use ($rank): int {
                return $rank($a) <=> $rank($b) ?: strcmp(self::u16($a->get('id')), self::u16($b->get('id')));
            });
            $permits = $hit('permit');
            $escalates = $hit('escalate');
            if ($forbids !== []) {
                [$win, $decision, $kind] = [$forbids[0], 'deny', 'forbid'];
            } elseif ($permits === []) {
                [$win, $decision, $kind] = [null, 'deny', 'none'];
            } elseif ($escalates !== []) {
                [$win, $decision, $kind] = [$escalates[0], 'escalate', 'escalate'];
            } else {
                [$win, $decision, $kind] = [$permits[0], 'allow', 'permit'];
            }
            $others = [];
            foreach (array_merge($forbids, $permits, $escalates) as $r) {
                if ($r !== $win) {
                    $others[] = $r->get('id');
                }
            }
            return $cert->get('decision') === $decision
                && $winner->get('kind') === $kind
                && $winner->get('id') === ($win?->get('id'))
                && $shadowed === $others;
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- the evaluators (decideClauses / certify / checkForbidCertificate of forbid-certificate.ts) ------------------------------------

    public const VERSION = 1;
    public const KIND = 'forbid-wins';
    public const MAX_CLAUSES = 512;
    private const CONDITION_OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists', 'like', 'matches', 'is_a', 'member_of'];
    private const MAX_CONDITION_DEPTH = 32;

    /** Null = the clause list is well formed (distinct ids, known kinds, a predicate for each). */
    public static function clausesError(mixed $clauses): ?string
    {
        if (!is_array($clauses) || !array_is_list($clauses)) {
            return 'clauses must be an array';
        }
        if (count($clauses) > self::MAX_CLAUSES) {
            return 'more than ' . self::MAX_CLAUSES . ' clauses';
        }
        $seen = [];
        foreach ($clauses as $i => $c) {
            if (!($c instanceof Obj)) {
                return "clauses[$i] must be an object";
            }
            $id = $c->get('id');
            if (!is_string($id) || $id === '' || \Atlas\Pca\SafeRegex::utf16Len($id) > 128) {
                return "clauses[$i].id must be a string of 1..128 characters";
            }
            if (isset($seen['k' . $id])) {
                return "clauses[$i].id '$id' is a duplicate";
            }
            $seen['k' . $id] = true;
            if (!is_string($c->get('kind')) || !in_array($c->get('kind'), self::KINDS, true)) {
                return "clauses[$i].kind must be permit, forbid or escalate";
            }
            if ($c->has('signer') && (!is_string($c->get('signer')) || \Atlas\Pca\SafeRegex::utf16Len($c->get('signer')) > 256)) {
                return "clauses[$i].signer must be a string of at most 256 characters";
            }
            if (!($c->get('when') instanceof Obj)) {
                return "clauses[$i].when must be a predicate object";
            }
        }
        return null;
    }

    public static function conditionError(mixed $c, int $depth = 0): ?string
    {
        if (!($c instanceof Obj)) {
            return 'condition not an object';
        }
        if ($depth > self::MAX_CONDITION_DEPTH) {
            return 'condition nesting too deep';
        }
        if ($c->has('all_of') || $c->has('any_of') || $c->has('not')) {
            if ($c->has('not')) {
                return self::conditionError($c->get('not'), $depth + 1);
            }
            $key = $c->has('all_of') ? 'all_of' : 'any_of';
            $arr = $c->get($key);
            if (!is_array($arr) || !array_is_list($arr) || $arr === []) {
                return "condition.$key must be a non-empty array";
            }
            foreach ($arr as $child) {
                if (($e = self::conditionError($child, $depth + 1)) !== null) {
                    return $e;
                }
            }
            return null;
        }
        if (!is_string($c->get('field')) || $c->get('field') === '') {
            return 'condition.field missing';
        }
        if (!is_string($c->get('op')) || !in_array($c->get('op'), self::CONDITION_OPS, true)) {
            return 'unknown condition op ' . IntentWb::jsStr($c->get('op'));
        }
        if ($c->has('ref') && (!is_string($c->get('ref')) || $c->get('ref') === '')) {
            return 'bad condition.ref';
        }
        if ($c->get('op') === 'member_of' && $c->has('collection') && (!is_string($c->get('collection')) || $c->get('collection') === '')) {
            return 'bad condition.collection';
        }
        return null;
    }

    /** The structural problem of a prohibition trigger (`when`), or null. */
    public static function whenError(mixed $w, string $label = 'when'): ?string
    {
        if (!($w instanceof Obj)) {
            return "$label: not an object";
        }
        $v = $w->get('verb');
        $verbOk = (is_string($v) && $v !== '') || (is_array($v) && array_is_list($v) && $v !== [] && count(array_filter($v, static fn($x): bool => is_string($x) && $x !== '')) === count($v));
        if (!$verbOk) {
            return "$label: bad verb";
        }
        if ($w->has('resource')) {
            $res = $w->get('resource');
            if (!is_string($res)) {
                return "$label: bad resource";
            }
            if (str_starts_with($res, 're:')) {
                $src = substr($res, 3);
                if (\Atlas\Pca\SafeRegex::utf16Len($src) > 200 || !\Atlas\Pca\SafeRegex::isSafeRegexSource($src)) {
                    return "$label: unsafe regex resource";
                }
                if (\Atlas\Pca\SafeRegex::compile($src) === null) {
                    return "$label: invalid regex resource";
                }
            }
        }
        if ($w->has('where')) {
            $where = $w->get('where');
            if (!is_array($where) || !array_is_list($where)) {
                return "$label: where not an array";
            }
            foreach ($where as $c) {
                if (($e = self::conditionError($c)) !== null) {
                    return "$label: $e";
                }
            }
        }
        return null;
    }

    /**
     * Does a prohibition trigger match, in veto polarity: verb and resource as the permission DSL, the where-conditions conservatively (anything
     * that cannot be decided counts as MATCHED). Fully fail-closed: a malformed trigger, an unsafe regex, an oversized regex subject, an
     * unknown op, a missing field or an undecidable regex all count as matched. Never throws.
     */
    public static function whenMatches(mixed $w, Obj $ctx): bool
    {
        try {
            if (self::whenError($w) !== null) {
                return true;
            }
            $a = $ctx->get('action');
            if (!($a instanceof Obj) || !is_string($a->get('verb')) || !is_string($a->get('resource'))) {
                return true;
            }
            $res = $w->get('resource');
            $oversized = is_string($res) && str_starts_with($res, 're:') && \Atlas\Pca\SafeRegex::utf16Len($a->get('resource')) > Predicates::MAX_RE_RESOURCE_LEN;
            $refused0 = \Atlas\Pca\SafeRegex::regexRefusals();
            $trigger = Obj::of(['verb' => $w->get('verb')]);
            if (!$oversized && $w->has('resource')) {
                $trigger->set('resource', $res);
            }
            if (!Predicates::predicateMatches($trigger, $ctx)) {
                if (\Atlas\Pca\SafeRegex::regexRefusals() === $refused0) {
                    return false;
                }
            }
            foreach ($w->has('where') ? $w->get('where') : [] as $c) {
                if (Predicates::evaluateConditionTri($c, $ctx) === 'false') {
                    return false;
                }
            }
            return true;
        } catch (\Throwable) {
            return true; // cannot evaluate => the veto applies
        }
    }

    private static function valueOf(Obj $c, Obj $ctx): string
    {
        if ($c->get('kind') === 'permit') {
            return Predicates::predicateMatches($c->get('when'), $ctx) ? 'true' : 'false';
        }
        if (!self::whenMatches($c->get('when'), $ctx)) {
            return 'false';
        }
        return Predicates::predicateMatches($c->get('when'), $ctx) ? 'true' : 'unknown';
    }

    /** @param list<string> $precedence */
    private static function rankOf(Obj $c, array $precedence): int
    {
        $i = is_string($c->get('signer')) ? array_search($c->get('signer'), $precedence, true) : false;
        return $i === false ? count($precedence) : $i;
    }

    private static function malformedDecision(): array
    {
        return ['decision' => 'deny', 'witness' => ['winner' => ['kind' => 'malformed', 'id' => null], 'shadowed' => []], 'values' => []];
    }

    /**
     * Decide a clause list against an action context (an Obj `{action: {verb, resource, params?}, subject?, env?}`); order-independent for the
     * decision, the named winner deterministic. `$opts`: `precedence` (signers, most authoritative first) and `permitSigners` (a permit from any
     * other signer is ignored). Total: a malformed clause list or action is a `deny` naming the `malformed` winner.
     * @param list<Obj> $clauses
     * @return array{decision: string, witness: array{winner: array{kind: string, id: ?string}, shadowed: list<string>}, values: list<array{id: string, kind: string, value: string}>}
     */
    public static function decide(mixed $clauses, mixed $ctx, array $opts = []): array
    {
        try {
            if (!($ctx instanceof Obj) || self::clausesError($clauses) !== null) {
                return self::malformedDecision();
            }
            $a = $ctx->get('action');
            if (!($a instanceof Obj) || !is_string($a->get('verb')) || !is_string($a->get('resource'))) {
                return self::malformedDecision();
            }
            $precedence = $opts['precedence'] ?? [];
            $permitSigners = $opts['permitSigners'] ?? null;
            $values = [];
            foreach ($clauses as $c) {
                $active = $c->get('kind') !== 'permit' || $permitSigners === null || (is_string($c->get('signer')) && in_array($c->get('signer'), $permitSigners, true));
                $values[] = ['id' => $c->get('id'), 'kind' => $c->get('kind'), 'value' => $active ? self::valueOf($c, $ctx) : 'false'];
            }
            $hit = static function (string $k) use ($clauses, $values): array {
                $out = [];
                foreach ($clauses as $i => $c) {
                    if ($c->get('kind') === $k && $values[$i]['value'] !== 'false') {
                        $out[] = $c;
                    }
                }
                return $out;
            };
            $forbids = $hit('forbid');
            usort($forbids, static fn(Obj $x, Obj $y): int => self::rankOf($x, $precedence) <=> self::rankOf($y, $precedence) ?: strcmp(self::u16($x->get('id')), self::u16($y->get('id'))));
            $permits = $hit('permit');
            $escalates = $hit('escalate');
            $others = static function (?Obj $win) use ($forbids, $permits, $escalates): array {
                $out = [];
                foreach (array_merge($forbids, $permits, $escalates) as $c) {
                    if ($c !== $win) {
                        $out[] = $c->get('id');
                    }
                }
                return $out;
            };
            if ($forbids !== []) {
                return ['decision' => 'deny', 'witness' => ['winner' => ['kind' => 'forbid', 'id' => $forbids[0]->get('id')], 'shadowed' => $others($forbids[0])], 'values' => $values];
            }
            if ($permits === []) {
                return ['decision' => 'deny', 'witness' => ['winner' => ['kind' => 'none', 'id' => null], 'shadowed' => $others(null)], 'values' => $values];
            }
            if ($escalates !== []) {
                return ['decision' => 'escalate', 'witness' => ['winner' => ['kind' => 'escalate', 'id' => $escalates[0]->get('id')], 'shadowed' => $others($escalates[0])], 'values' => $values];
            }
            return ['decision' => 'allow', 'witness' => ['winner' => ['kind' => 'permit', 'id' => $permits[0]->get('id')], 'shadowed' => $others($permits[0])], 'values' => $values];
        } catch (\Throwable) {
            return self::malformedDecision();
        }
    }

    /** The canonical certificate for a decision. */
    public static function certify(mixed $clauses, Obj $ctx, array $opts = []): Obj
    {
        $d = self::decide($clauses, $ctx, $opts);
        $byId = [];
        foreach (is_array($clauses) ? $clauses : [] as $c) {
            if ($c instanceof Obj && is_string($c->get('id'))) {
                $byId['k' . $c->get('id')] = $c;
            }
        }
        $rows = [];
        foreach ($d['values'] as $v) {
            $row = Obj::of(['id' => $v['id'], 'kind' => $v['kind']]);
            $sg = ($byId['k' . $v['id']] ?? null)?->get('signer');
            if ($sg !== null) {
                $row->set('signer', $sg);
            }
            $row->set('value', $v['value']);
            $rows[] = $row;
        }
        return Obj::of(['v' => new Num((string)self::VERSION), 'kind' => self::KIND, 'policy' => Pca::hashCanonical($clauses), 'action' => Pca::hashCanonical($ctx),
            'decision' => $d['decision'], 'winner' => Obj::of($d['witness']['winner']), 'shadowed' => $d['witness']['shadowed'], 'clauses' => $rows]);
    }

    /**
     * Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form).
     * @return array{ok: bool, reason?: string}
     */
    public static function check(mixed $cert, mixed $clauses, Obj $ctx, array $opts = []): array
    {
        try {
            if (self::clausesError($clauses) !== null) {
                return ['ok' => false, 'reason' => 'malformed clauses'];
            }
            if (!self::consistent($cert, $opts['precedence'] ?? [])) {
                return ['ok' => false, 'reason' => 'certificate table does not entail its decision'];
            }
            if (Pca::hashCanonical(self::certify($clauses, $ctx, $opts)) !== Pca::hashCanonical($cert)) {
                return ['ok' => false, 'reason' => 'certificate does not match the recomputed decision'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'certificate check error (fail closed)'];
        }
    }

    private static function isOne(mixed $v): bool
    {
        return $v instanceof Num && $v->lexeme === '1';
    }

    /** UTF-16BE bytes: the reference orders ids by UTF-16 code unit (JavaScript `<`). */
    private static function u16(string $s): string
    {
        return mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }
}
