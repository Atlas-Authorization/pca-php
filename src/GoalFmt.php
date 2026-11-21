<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalNormalize.php';

/** Rendering helpers for quantities, values and actions. */
final class GoalFmt
{
    /** An unknown currency is shown in raw minor units, never guessed. */
    public const CCY_EXPONENT = ['USD' => 2, 'EUR' => 2, 'GBP' => 2, 'CAD' => 2, 'AUD' => 2, 'CHF' => 2, 'JPY' => 0, 'KRW' => 0];

    public static function fmtMoney(mixed $ccy, mixed $minor): string
    {
        $e = is_string($ccy) ? (self::CCY_EXPONENT[$ccy] ?? null) : null;
        $c = AnalyzerJs::jsStr($ccy);
        $m = AnalyzerJs::jsStr($minor);
        if ($e === null) {
            return "$c $m (minor units)";
        }
        if ($e === 0) {
            return "$c $m";
        }
        $u = GoalJs::units($m);
        $u = array_merge(array_fill(0, max(0, $e + 1 - count($u)), 0x30), $u); // padStart(e + 1, '0')
        $n = count($u);
        return "$c " . GoalJs::fromUnits(array_slice($u, 0, $n - $e)) . '.' . GoalJs::fromUnits(array_slice($u, $n - $e));
    }

    /** The rendered text; undefined for an unknown unit tag. */
    public static function fmtQuantity(mixed $q): mixed
    {
        $u = AnalyzerJs::jget($q, 'u');
        $k = AnalyzerJs::jget($u, 'k');
        $n = AnalyzerJs::jget($q, 'n');
        return match ($k) {
            'money' => self::fmtMoney(AnalyzerJs::jget($u, 'ccy'), $n),
            'count' => AnalyzerJs::jsStr($n),
            'duration' => AnalyzerJs::jsStr($n) . 'ms',
            'instant' => '@' . AnalyzerJs::jsStr($n),
            'bytes' => AnalyzerJs::jsStr($n) . 'B',
            'ratio' => AnalyzerJs::jsStr($n) . 'ppm',
            default => AnalyzerJs::undef(),
        };
    }

    public static function fmtValue(mixed $v): mixed
    {
        $k = AnalyzerJs::jget($v, 'k');
        if ($k === 'q') {
            return self::fmtQuantity(AnalyzerJs::jget($v, 'q'));
        }
        if ($k === 's') {
            $s = AnalyzerJs::jget($v, 's');
            return AnalyzerJs::isUndef($s) ? $s : GoalNormalize::jq($s);
        }
        $items = array_map(function ($i) {
            $x = self::fmtValue($i);
            return AnalyzerJs::isUndef($x) ? '' : $x;
        }, AnalyzerJs::reqList(AnalyzerJs::jget($v, 'items')));
        return '{' . implode(', ', $items) . '}';
    }

    public static function fmtAct(mixed $a): string
    {
        $params = AnalyzerJs::jget($a, 'params');
        $keys = GoalJs::okeys($params);
        usort($keys, fn($x, $y) => AnalyzerJs::u16cmp($x, $y));
        $ps = implode(', ', array_map(fn($k) => $k . '=' . AnalyzerJs::jsStr(self::fmtValue(GoalJs::kget($params, $k))), $keys));
        return AnalyzerJs::jsStr(AnalyzerJs::jget($a, 'verb')) . ' on ' . AnalyzerJs::jsStr(AnalyzerJs::jget($a, 'res')) . ($ps === '' ? '' : " ($ps)");
    }
}
