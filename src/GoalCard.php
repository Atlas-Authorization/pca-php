<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalNormalize.php';

/**
 * The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers. Two different goals
 * never print the same card.
 */
final class GoalCard
{
    public const OPW = ['eq' => '=', 'ne' => '!=', 'lt' => '<', 'lte' => '<=', 'gt' => '>', 'gte' => '>=', 'in' => 'is one of', 'nin' => 'is none of'];

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    private static function s(mixed $v): string
    {
        return AnalyzerJs::jsStr($v);
    }

    /** @return list<mixed> */
    private static function lst(mixed $o, string $k): array
    {
        return AnalyzerJs::reqList(self::g($o, $k));
    }

    /** @param list<mixed> $xs */
    private static function qs(array $xs): string
    {
        return implode(', ', array_map(fn($x) => self::q($x), $xs));
    }

    public static function q(mixed $x): string
    {
        return AnalyzerJs::isUndef($x) ? 'undefined' : GoalNormalize::jq($x);
    }

    public static function unit(mixed $u): string
    {
        return self::g($u, 'k') === 'money' ? self::s(self::g($u, 'ccy')) . ' minor units' : self::s(self::g($u, 'k'));
    }

    public static function quantity(mixed $x): string
    {
        return self::s(self::g($x, 'n')) . ' ' . self::unit(self::g($x, 'u'));
    }

    public static function value(mixed $v): string
    {
        $k = self::g($v, 'k');
        if ($k === 'q') {
            return self::quantity(self::g($v, 'q'));
        }
        if ($k === 's') {
            return self::q(self::g($v, 's'));
        }
        return '{' . implode(', ', array_map(fn($i) => self::value($i), self::lst($v, 'items'))) . '}';
    }

    public static function term(mixed $t): string
    {
        $k = self::g($t, 'k');
        if ($k === 'param') {
            $ty = self::g($t, 'ty');
            return 'param ' . self::q(self::g($t, 'path')) . ' (' . (self::g($ty, 'k') === 'q' ? self::unit(self::g($ty, 'u')) : 'text') . ')';
        }
        if ($k === 'lit') {
            return self::value(self::g($t, 'v'));
        }
        return 'running total of bound ' . self::q(self::g($t, 'bid')) . ' (' . self::unit(self::g($t, 'u')) . ')';
    }

    public static function cond(mixed $c): string
    {
        $k = self::g($c, 'k');
        switch ($k) {
            case 'true':
                return 'always';
            case 'cmp':
                $op = self::g($c, 'op');
                return self::term(self::g($c, 'l')) . ' ' . (is_string($op) && isset(self::OPW[$op]) ? self::OPW[$op] : 'undefined') . ' ' . self::term(self::g($c, 'r'));
            case 'and':
                return '(' . self::cond(self::g($c, 'a')) . ') AND (' . self::cond(self::g($c, 'b')) . ')';
            case 'or':
                return '(' . self::cond(self::g($c, 'a')) . ') OR (' . self::cond(self::g($c, 'b')) . ')';
            case 'not':
                return 'NOT (' . self::cond(self::g($c, 'c')) . ')';
            default:
                return 'undefined'; // the reference switch has no default
        }
    }

    public static function res(mixed $s): string
    {
        $k = self::g($s, 'k');
        switch ($k) {
            case 'exact':
                return 'exactly ' . self::q(self::g($s, 'id'));
            case 'oneof':
                return 'one of [' . self::qs(self::lst($s, 'ids')) . ']';
            case 'related':
                return self::s(self::g($s, 'rel')) . ' of ' . self::q(self::g($s, 'anchor'));
            case 'all_of':
                return 'ALL OF (' . implode(' AND ', array_map(fn($p) => self::res($p), self::lst($s, 'parts'))) . ')';
            default:
                return 'ANY RESOURCE (reason: ' . self::q(self::g($s, 'reason')) . ')';
        }
    }

    public static function win(mixed $w): string
    {
        $k = self::g($w, 'k');
        if ($k === 'task') {
            return 'per task';
        }
        if ($k === 'lifetime') {
            return 'over the lifetime';
        }
        if ($k === 'sliding') {
            return 'in any ' . self::s(self::g($w, 'ms')) . ' ms window';
        }
        return 'per ' . self::s(self::g($w, 'ms')) . ' ms period starting at ' . self::s(self::g($w, 't0'));
    }

    public static function scope(mixed $s): string
    {
        if (self::g($s, 'k') === 'fleet') {
            return 'fleet [' . self::qs(self::lst($s, 'agents')) . ']';
        }
        return self::s(self::g($s, 'k'));
    }

    public static function grantLine(mixed $x): string
    {
        return 'ALLOW ' . self::q(self::g($x, 'gid')) . ': verb ' . self::q(self::g($x, 'verb')) . ' on ' . self::res(self::g($x, 'res')) . ' when ' . self::cond(self::g($x, 'cond'));
    }

    public static function prohibitLine(mixed $x): string
    {
        $t = self::g($x, 'target');
        $tgt = self::g($t, 'k') === 'verb' ? 'verb ' . self::q(self::g($t, 'verb')) : 'every verb of effect class ' . self::q(self::g($t, 'cls'));
        return 'NEVER ' . self::q(self::g($x, 'pid')) . ': ' . $tgt . ' on ' . self::res(self::g($x, 'res')) . ' when ' . self::cond(self::g($x, 'cond'));
    }

    public static function boundLine(mixed $b): string
    {
        $sel = self::g($b, 'sel');
        $over = self::g($sel, 'k') === 'gids' ? 'grants [' . self::qs(self::lst($sel, 'gids')) . ']' : 'effect class ' . self::q(self::g($sel, 'cls'));
        $agg = self::g($b, 'agg');
        $mid = $agg === 'count' ? '' : ($agg === 'distinct' ? ' of ' . self::q(self::g($b, 'key')) : ' of ' . self::term(self::g($b, 'value')));
        $exc = self::g($b, 'onExceed') === 'deny' ? 'deny' : 'ask the principal';
        return 'LIMIT ' . self::q(self::g($b, 'bid')) . ': ' . self::s($agg) . $mid . ' over ' . $over . ', ' . self::win(self::g($b, 'window'))
            . ', scope ' . self::scope(self::g($b, 'scope')) . ', at most ' . self::quantity(self::g($b, 'cap')) . '; beyond that: ' . $exc;
    }

    public static function validityLine(mixed $v): string
    {
        $mi = self::g($v, 'maxIdle');
        return 'VALID from ' . self::s(self::g($v, 'notBefore')) . ' to ' . self::s(self::g($v, 'notAfter')) . '; idle limit '
            . (AnalyzerJs::jsGt($mi, 0) ? self::s($mi) . ' ms' : 'none');
    }

    public static function delegationLine(mixed $d): string
    {
        return 'DELEGATION depth at most ' . self::s(self::g($d, 'maxDepth')) . ', narrow only ' . self::s(self::g($d, 'narrowOnly'))
            . ', delegates may use grants [' . self::qs(self::lst($d, 'mayTouch')) . ']';
    }

    public static function escalateLine(mixed $c): string
    {
        return 'ASK THE PRINCIPAL when ' . self::cond($c);
    }

    public static function holeLine(mixed $h): string
    {
        $aff = AnalyzerJs::truthy(self::g($h, 'global')) ? 'everything' : '[' . self::qs(self::lst($h, 'affects')) . ']';
        return 'UNRESOLVED ' . self::q(self::g($h, 'hid')) . ': ' . self::q(self::g($h, 'q')) . ' options [' . self::qs(self::lst($h, 'domain')) . '] affects ' . $aff;
    }

    /** One line per clause, in the goal's canonical order; `warnings` lists what the principal must look at twice. */
    public static function renderCard(mixed $g): Obj
    {
        $lines = ['Goal v' . self::s(self::g($g, 'v')) . ' for principal ' . self::q(self::g($g, 'principal')) . '; ontology ' . self::q(self::g($g, 'ontDigest'))
            . '; request text digest ' . self::q(self::g($g, 'nlDigest'))];
        $warnings = [];
        foreach (self::lst($g, 'sources') as $s) {
            $lines[] = 'Source ' . self::q($s);
        }
        foreach (self::lst($g, 'grants') as $x) {
            $lines[] = self::grantLine($x);
            if (self::g(self::g($x, 'res'), 'k') !== 'any') {
                continue;
            }
            $ack = AnalyzerJs::includes(self::g($g, 'wildcardAck'), self::g($x, 'gid'));
            $warnings[] = 'grant ' . self::q(self::g($x, 'gid')) . ' applies to every resource' . ($ack ? ' (acknowledged)' : ' (NOT acknowledged)');
        }
        foreach (self::lst($g, 'prohibits') as $x) {
            $lines[] = self::prohibitLine($x);
        }
        foreach (self::lst($g, 'bounds') as $b) {
            $lines[] = self::boundLine($b);
        }
        $lines[] = self::validityLine(self::g($g, 'validity'));
        $lines[] = self::delegationLine(self::g($g, 'deleg'));
        foreach (self::lst($g, 'escalateOn') as $c) {
            $lines[] = self::escalateLine($c);
        }
        foreach (self::lst($g, 'wildcardAck') as $a) {
            $lines[] = 'Wildcard acknowledged for ' . self::q($a);
        }
        foreach (self::lst($g, 'holes') as $h) {
            $lines[] = self::holeLine($h);
        }
        if (count(self::lst($g, 'holes')) > 0) {
            $warnings[] = 'this goal has unresolved questions and cannot be signed';
        }
        return Obj::of(['lines' => $lines, 'warnings' => $warnings]);
    }
}
