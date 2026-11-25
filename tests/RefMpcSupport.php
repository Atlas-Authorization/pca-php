<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;

/** Argument decoding and result encoding shared by the MPC replay tests (bigints travel as decimal strings). */
final class RefMpcSupport
{
    public static function b(mixed $o): \GMP
    {
        if (!is_string($o)) {
            throw new \InvalidArgumentException('bigint arg');
        }
        return gmp_init($o);
    }

    /** A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure); huge magnitudes clamp to int32. */
    public static function i(mixed $o): int
    {
        if (!($o instanceof Num)) {
            throw new \InvalidArgumentException('not an integer');
        }
        $d = $o->float();
        if (!is_finite($d) || $d !== floor($d)) {
            throw new \InvalidArgumentException('not an integer');
        }
        if (abs($d) > 1e9) {
            return $d > 0 ? 2147483647 : -2147483648;
        }
        return (int) $d;
    }

    public static function d(mixed $o): float
    {
        if (!($o instanceof Num)) {
            throw new \InvalidArgumentException('not a number');
        }
        return $o->float();
    }

    public static function rng(mixed $seed): \Atlas\Pca\MpcFieldRng
    {
        return new \Atlas\Pca\MpcFieldRng(self::b($seed));
    }

    /** @return list<?\GMP> */
    public static function ba(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        return array_map(static fn($x) => $x === null ? null : self::b($x), $o);
    }

    /** @return list<list<?\GMP>> */
    public static function baa(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        return array_map(self::ba(...), $o);
    }

    /** @return list<int> */
    public static function ia(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        return array_map(self::i(...), $o);
    }

    public static function obj(mixed $o): Obj
    {
        if (!($o instanceof Obj)) {
            throw new \InvalidArgumentException('not an object');
        }
        return $o;
    }

    /** @return list<array{allow:int,t:int,rQuant:int}> */
    public static function vectors(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('decision vectors must be an array');
        }
        $out = [];
        foreach ($o as $e) {
            $m = self::obj($e);
            $out[] = ['allow' => self::i($m->get('allow')), 't' => self::i($m->get('t')), 'rQuant' => self::i($m->get('rQuant'))];
        }
        return $out;
    }

    /** @param list<?\GMP> $a @return list<?string> */
    public static function s(array $a): array
    {
        return array_map(static fn($x) => $x === null ? null : gmp_strval($x), $a);
    }

    /** @param list<list<\GMP>> $a */
    public static function ss(array $a): array
    {
        return array_map(self::s(...), $a);
    }

    public static function authSV(array $x): array
    {
        return ['value' => self::s($x['value']), 'mac' => self::s($x['mac']), 'extraMac' => self::ss($x['extraMac'])];
    }

    public static function triple(array $t): array
    {
        return ['a' => self::authSV($t['a']), 'b' => self::authSV($t['b']), 'c' => self::authSV($t['c'])];
    }

    public static function key(array $k): array
    {
        return ['alphaShares' => self::s($k['alphaShares']), 'alpha' => gmp_strval($k['alpha'])];
    }

    public static function ctx(array $c): array
    {
        return ['n' => $c['n'], 'alphaShares' => self::s($c['alphaShares']), 'alpha' => gmp_strval($c['alpha']), 'extraKeys' => array_map(self::key(...), $c['extraKeys'])];
    }

    /** @return list<array> */
    public static function devs(mixed $o): array
    {
        if (!is_array($o)) {
            throw new \InvalidArgumentException('not a list');
        }
        $out = [];
        foreach ($o as $d) {
            if (!is_array($d)) {
                throw new \InvalidArgumentException('not a list');
            }
            $out[] = ['openIndex' => self::i($d[0]), 'party' => self::i($d[1]), 'valueDelta' => $d[2] === null ? null : self::b($d[2]),
                'macDelta' => $d[3] === null ? null : self::b($d[3]), 'macKey' => $d[4] === null ? null : self::i($d[4])];
        }
        return $out;
    }

    public static function fault(mixed $o): ?array
    {
        if ($o === null) {
            return null;
        }
        $m = self::obj($o);
        $p = null;
        if ($m->get('partnerCDelta') !== null) {
            $p = array_map(static fn($x) => $x === null ? null : self::b($x), $m->get('partnerCDelta'));
        }
        return ['keepCDelta' => $m->get('keepCDelta') === null ? null : self::b($m->get('keepCDelta')), 'partnerCDelta' => $p];
    }
}
