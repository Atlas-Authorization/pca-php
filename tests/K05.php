<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Assert;

/**
 * Replays the k05 shared TS-reference oracles (test-data/k05-<module>.json.gz, one case per line: {fn, name, args, out}).
 * Cases are streamed (the bigger files are 100+ MB of JSON) and split into datasets of at most CHUNK cases per fn, so each
 * PHPUnit test stays short and Infection's per-test coverage stays narrow. Comparison: canonical JSON (lenient: numbers by
 * value); {$throws, code?} = the native must throw (with that code when present); `textPrefix` = a message starting with
 * the prefix is equal; `cmp: "code"` = only the `<code>:` prefix is compared; an `@suspect` fn is reported, never failed.
 */
final class K05
{
    public const CHUNK = 1500;

    /** A mapper returns this (or `[K05::SKIP, reason]`) when the case is out of scope for the PHP port. */
    public const SKIP = "\0skip";

    /** @return \Generator<int,string> the raw case lines */
    private static function lines(string $file): \Generator
    {
        $h = gzopen(__DIR__ . '/../test-data/' . $file, 'rb');
        if ($h === false) {
            throw new \RuntimeException("cannot open $file");
        }
        try {
            gzgets($h); // the header line: {"about":...,"cases":[
            while (($l = gzgets($h)) !== false) {
                $l = rtrim($l, "\r\n");
                if ($l === '' || $l[0] !== '{') {
                    continue;
                }
                yield str_ends_with($l, ',') ? substr($l, 0, -1) : $l;
            }
        } finally {
            gzclose($h);
        }
    }

    private static function fnOf(string $line): string
    {
        // every case line starts with {"fn":"<fn>", (lib.mjs ser keeps member order)
        $e = strpos($line, '"', 7);
        return substr($line, 7, $e - 7);
    }

    /** @return array<string,array{0:string,1:string,2:int}> datasets: "<fn> #k" => [file, fn, k] */
    public static function datasets(string $file): array
    {
        $n = [];
        foreach (self::lines($file) as $l) {
            $f = self::fnOf($l);
            $n[$f] = ($n[$f] ?? 0) + 1;
        }
        $out = [];
        foreach ($n as $f => $c) {
            for ($k = 0; $k * self::CHUNK < $c; $k++) {
                $out["$f #$k"] = [$file, $f, $k];
            }
        }
        return $out;
    }

    /** @return list<Obj> the cases of chunk k of fn */
    public static function cases(string $file, string $fn, int $k): array
    {
        $i = 0;
        $out = [];
        $lo = $k * self::CHUNK;
        foreach (self::lines($file) as $l) {
            if (self::fnOf($l) !== $fn) {
                continue;
            }
            if ($i >= $lo && $i < $lo + self::CHUNK) {
                $out[] = (new Parser($l, PHP_INT_MAX))->run();
            }
            $i++;
        }
        return $out;
    }

    /** Bytes argument ({$bytes: b64url}) to raw bytes; any other value unchanged. */
    public static function bytes(mixed $v): mixed
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'] ? Pca::unb64u($v->get('$bytes')) : $v;
    }

    /** Loose JSON text of a parsed value, for pattern checks on a case. */
    public static function text(mixed $v): string
    {
        return (string) json_encode(OracleData::plain($v), JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /** Raw bytes as the oracle writes them. */
    public static function outBytes(string $raw): Obj
    {
        return Obj::of(['$bytes' => Pca::b64u($raw)]);
    }

    /** Lenient canonical JSON of a PHP or parsed value (assoc arrays = objects; floats / ints / Num by value). */
    public static function canon(mixed $v): string
    {
        return Json::canonicalizeLenient(self::json($v));
    }

    private static function json(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::json($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::json(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string) $k, self::json($x));
            }
            return $o;
        }
        if ($v instanceof \BackedEnum) {
            return $v->value;
        }
        if ($v instanceof \JsonSerializable) {
            return self::json($v->jsonSerialize());
        }
        if (is_object($v) && !($v instanceof Num)) {
            return self::json(get_object_vars($v));
        }
        return $v;
    }

    /** The thrown code of a native refusal (ActionKitError::codeName, an UndoError code, ...), or null. */
    private static function codeOf(\Throwable $e): ?string
    {
        foreach (['codeName', 'refusal', 'errorCode'] as $p) {
            if (property_exists($e, $p) && is_string($e->{$p})) {
                return $e->{$p};
            }
        }
        return is_string($e->getCode()) ? $e->getCode() : null;
    }

    /** Every string in v that starts with `$prefix` becomes exactly `$prefix`. */
    private static function cut(mixed $v, string $prefix): mixed
    {
        if (is_string($v)) {
            return str_starts_with($v, $prefix) ? $prefix : $v;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::cut($v->get($k), $prefix));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(fn($x) => self::cut($x, $prefix), $v);
        }
        return $v;
    }

    /**
     * Run one dataset. `$map[fn]` = fn(list $args, Obj $case): mixed — the native result in the oracle's out form; it may
     * return SKIP / [SKIP, reason]. A fn absent from `$map` fails the test (every fn must be mapped or skipped explicitly).
     *
     * @param array<string,callable> $map
     */
    public static function run(string $file, string $fn, int $k, array $map): void
    {
        $base = str_ends_with($fn, '@suspect') ? substr($fn, 0, -8) : $fn;
        Assert::assertArrayHasKey($base, $map, "fn $fn is not mapped");
        $bad = [];
        $suspect = [];
        $skipped = [];
        $ran = 0;
        foreach (self::cases($file, $fn, $k) as $c) {
            $name = (string) $c->get('name');
            if (OracleData::pqMissing() && OracleData::mentionsPq($c)) {
                $skipped['no PQ suite on this runtime'] = ($skipped['no PQ suite on this runtime'] ?? 0) + 1;
                continue;
            }
            $threw = null;
            try {
                $have = ($map[$base])($c->get('args') ?? [], $c);
            } catch (\Throwable $e) {
                $threw = $e;
                $have = null;
            }
            $want = $c->get('out'); // after the mapper: a mapper may normalize the expectation (documented per fn)
            if ($have === self::SKIP || (is_array($have) && ($have[0] ?? null) === self::SKIP)) {
                $why = is_array($have) ? (string) $have[1] : 'not ported';
                $skipped[$why] = ($skipped[$why] ?? 0) + 1;
                continue;
            }
            $ran++;
            $wantThrow = $want instanceof Obj && $want->has('$throws');
            if ($wantThrow) {
                $code = $want->get('code');
                if ($threw === null) {
                    $msg = 'want throw ' . self::canon($want) . "\n   have " . self::show($have);
                } elseif (is_string($code) && self::codeOf($threw) !== $code) {
                    $msg = "want throw code $code\n   have " . get_class($threw) . ' code ' . var_export(self::codeOf($threw), true) . ': ' . $threw->getMessage();
                } else {
                    continue;
                }
            } elseif ($threw !== null) {
                $msg = 'want ' . self::canon($want) . "\n   threw " . get_class($threw) . ': ' . $threw->getMessage();
            } else {
                $p = $c->get('textPrefix');
                if (is_string($p)) {
                    $want = self::cut($want, $p);
                    $have = self::cut($have, $p);
                }
                if ($c->get('cmp') === 'code' && is_string($want) && is_string($have)) {
                    $want = strstr($want, ':', true) ?: $want;
                    $have = strstr($have, ':', true) ?: $have;
                }
                try {
                    $w = self::canon($want);
                    $h = self::canon($have);
                } catch (\Throwable $e) {
                    $w = 'uncanonicalizable';
                    $h = $e->getMessage();
                }
                if ($w === $h) {
                    continue;
                }
                $msg = "want $w\n   have $h";
            }
            if ($fn !== $base) {
                $suspect[] = $name;
                continue;
            }
            $bad[] = $name . "\n   " . $msg;
        }
        $note = "$file $fn #$k: ran $ran, skipped " . json_encode($skipped) . ', @suspect differences ' . count($suspect);
        Assert::assertSame([], array_slice($bad, 0, 25), count($bad) . " mismatches; $note");
        Assert::assertTrue(true, $note);
    }

    private static function show(mixed $v): string
    {
        try {
            return self::canon($v);
        } catch (\Throwable) {
            return get_debug_type($v);
        }
    }
}
