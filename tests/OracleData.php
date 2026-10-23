<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;

/** Loader for the shared TS-generated oracles (test-data/): the lax parser, so lone surrogates survive, as plain arrays. */
final class OracleData
{
    /** @var array<string,mixed> */
    private static array $cache = [];

    /** @return array<string,mixed> */
    public static function load(string $file): array
    {
        if (!isset(self::$cache[$file])) {
            $raw = (string) file_get_contents(__DIR__ . '/../test-data/' . $file);
            self::$cache[$file] = self::plain(Json::parseLax(str_ends_with($file, '.gz') ? (string) gzdecode($raw) : $raw));
        }
        return self::$cache[$file];
    }

    /** The parsed oracle itself (Obj / Num / list), numbers keep their lexeme; `$deep`: no nesting limit (the oracle holds deep values). */
    public static function raw(string $file, bool $deep = false): mixed
    {
        $raw = (string) file_get_contents(__DIR__ . '/../test-data/' . $file);
        $text = str_ends_with($file, '.gz') ? (string) gzdecode($raw) : $raw;
        return $deep ? (new \Atlas\Pca\Parser($text, PHP_INT_MAX))->run() : Json::parseLax($text);
    }

    /** A PHP result (int, assoc array, list, Obj) as a parsed JSON value, canonicalizable and comparable to raw(). */
    public static function asJson(mixed $v): mixed
    {
        if (is_int($v)) {
            return new Num((string) $v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::asJson($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::asJson(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string) $k, self::asJson($x));
            }
            return $o;
        }
        return $v;
    }

    /** Text of a parsed value with member ORDER kept and every number by its binary64 value (lexemes 1.0 / 1e3 agree). */
    public static function ordered(mixed $v): string
    {
        $v = self::asJson($v);
        if ($v instanceof Obj) {
            return '{' . implode(',', array_map(fn($k) => json_encode((string) $k) . ':' . self::ordered($v->get($k)), $v->keys())) . '}';
        }
        if (is_array($v)) {
            return '[' . implode(',', array_map(self::ordered(...), $v)) . ']';
        }
        return $v instanceof Num ? (string) $v->float() : (json_encode($v, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: 'invalid');
    }

    /** Obj to an associative array, a number to its lexeme. */
    public static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return $o;
        }
        if ($v instanceof Num) {
            return $v->lexeme;
        }
        return is_array($v) ? array_map(self::plain(...), $v) : $v;
    }

    /** A raw JSON text as the verifier sees it. */
    public static function j(mixed $raw): mixed
    {
        return Json::parseLax((string) $raw);
    }

    /** True when this runtime lacks a post-quantum suite (distro OpenSSL < 3.5): cases that name one cannot agree. */
    public static function pqMissing(): bool
    {
        return !\Atlas\Pca\Pca::suiteAvailable('ml-dsa-65');
    }

    /** Does the value (a case, its text or a parsed tree) mention a post-quantum suite or key material? */
    public static function mentionsPq(mixed $v): bool
    {
        $t = is_string($v) ? $v : (string) json_encode(self::plain($v), JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        return preg_match('/ml-dsa|slh-dsa|less-cat|"pq_|pq_pk|pq_sig|pqPins|hybrid/', $t) === 1;
    }
}
