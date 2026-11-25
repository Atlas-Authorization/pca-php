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
 * Replays the base shared TS-reference oracles (test-data/base-<module>.json.gz, one case per line: {fn, name, args, out}).
 * Cases are streamed (the bigger files are 100+ MB of JSON) and split into datasets of at most CHUNK cases per fn, so each
 * PHPUnit test stays short and Infection's per-test coverage stays narrow. Comparison: canonical JSON (lenient: numbers by
 * value); {$throws, code?} = the native must throw (with that code when present); `textPrefix` = a message starting with
 * the prefix is equal; `cmp: "code"` = only the `<code>:` prefix is compared; an `@suspect` fn is reported, never failed.
 */
final class Base
{
    public const CHUNK = 1500;

    /** A mapper returns this (or `[Base::SKIP, reason]`) when the case is out of scope for the PHP port. */
    public const SKIP = "\0skip";

    /** The corpus file; a ref-<name>-gen.json.gz (CI-generated, never committed) is looked up in PCA_SECRET_CORPUS_DIR when set. */
    public static function path(string $file): string
    {
        $dir = str_ends_with($file, '-gen.json.gz') && getenv('PCA_SECRET_CORPUS_DIR') ? getenv('PCA_SECRET_CORPUS_DIR') : __DIR__ . '/../test-data';
        return $dir . '/' . $file;
    }

    /** The datasets of $file plus those of its ref-<name>-gen.json.gz (the cases that carry private keys), or a "gen missing" placeholder (fn '') when that is absent. */
    public static function datasetsWithGen(string $file): array
    {
        $gen = str_replace('.json.gz', '-gen.json.gz', $file);
        $out = self::datasets($file);
        if (!is_file(self::path($gen))) {
            return $out + ['gen missing' => [$gen, '', 0]];
        }
        foreach (self::datasets($gen) as $k => $v) {
            $out["gen $k"] = $v;
        }
        return $out;
    }

    /** A missing -gen corpus FAILS when CI is "true"/"1", else skips. */
    public static function missingGen(string $gen): never
    {
        $msg = "$gen not found at " . self::path($gen) . ' (generate with .github/scripts/gen-secret-corpus.sh or set PCA_SECRET_CORPUS_DIR)';
        if (in_array(getenv('CI'), ['true', '1'], true)) {
            Assert::fail($msg);
        }
        throw new \PHPUnit\Framework\SkippedWithMessageException($msg);
    }

    /** @var array<string,float> */
    private static array $clocks = [];

    /** The frozen clock a corpus records when its header has no "clockMs" (the contract's default). */
    public const DEFAULT_CLOCK_MS = 1700000000000.0;

    /** The frozen clock a corpus header line (everything up to the opening bracket of "cases") records as "clockMs", else the contract's default. */
    public static function clockOfHeader(string $header): float
    {
        $h = Json::parseLax(rtrim($header) . ']}');
        $v = $h instanceof Obj ? $h->get('clockMs') : null;
        return $v instanceof Num && is_finite($v->float()) ? $v->float() : self::DEFAULT_CLOCK_MS;
    }

    /** The case names a corpus header lists as "clockCases" (results that depend on the frozen clock), as a name => true set. @return array<string,true> */
    public static function clockCasesOfHeader(string $header): array
    {
        $h = Json::parseLax(rtrim($header) . ']}');
        $l = $h instanceof Obj ? $h->get('clockCases') : null;
        $out = [];
        foreach (is_array($l) ? $l : [] as $n) {
            if (is_string($n)) {
                $out[$n] = true;
            }
        }
        return $out;
    }

    /** @var array<string,array<string,true>> */
    private static array $clockCaseSets = [];

    private static function header(string $file): string
    {
        $h = gzopen(self::path($file), 'rb');
        if ($h === false) {
            throw new \RuntimeException("cannot open $file");
        }
        try {
            return (string) gzgets($h);
        } finally {
            gzclose($h);
        }
    }

    /** The one clock accessor of the replays: the frozen clock of the corpus $file (its first line is the header). */
    public static function clockMs(string $file): float
    {
        return self::$clocks[$file] ??= self::clockOfHeader(self::header($file));
    }

    /** Is the case `$name` of the corpus `$file` one whose expected result depends on the frozen clock? */
    public static function isClockCase(string $file, string $name): bool
    {
        return isset((self::$clockCaseSets[$file] ??= self::clockCasesOfHeader(self::header($file)))[$name]);
    }

    /**
     * `$opts` (an Obj of options, or null) with `$key` set to the frozen clock (in units of `$unitMs` ms) when the case is a clock case, so a function that reads the wall clock
     * when it is not given one runs under the generator's clock. Any other case, and any non-Obj, is returned as it is.
     */
    public static function withClock(string $file, Obj $case, mixed $opts, string $key = 'now', int $unitMs = 1): mixed
    {
        if (($opts !== null && !($opts instanceof Obj)) || !self::isClockCase($file, (string) $case->get('name'))) {
            return $opts;
        }
        $c = $opts === null ? new Obj() : $opts->without(); // an absent options argument is the same as no `now`: the clock case still runs under the frozen clock
        $c->set($key, new Num((string) intdiv((int) self::clockMs($file), $unitMs)));
        return $c;
    }

    /** @return \Generator<int,string> the raw case lines */
    private static function lines(string $file): \Generator
    {
        $h = gzopen($file === 'ref-dpop-rsa.json.gz' && getenv('PCA_DPOP_RSA_CORPUS') ? getenv('PCA_DPOP_RSA_CORPUS') : self::path($file), 'rb');
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

    /**
     * Cases per dataset. A function whose every case runs a whole mutation search (one case takes seconds) gets smaller datasets, so each
     * stays inside the per-test deadline of the mutation job; the same cases run, only in more datasets.
     */
    private const SLOW_CHUNK = ['ref-analyzer.json.gz' => ['coverage' => 4, 'suggestNarrowing' => 16]];

    private static function chunkOf(string $file, string $fn): int
    {
        return self::SLOW_CHUNK[$file][$fn] ?? self::CHUNK;
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
            $size = self::chunkOf($file, $f);
            for ($k = 0; $k * $size < $c; $k++) {
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
        $size = self::chunkOf($file, $fn);
        $lo = $k * $size;
        foreach (self::lines($file) as $l) {
            if (self::fnOf($l) !== $fn) {
                continue;
            }
            if ($i >= $lo && $i < $lo + $size) {
                $c = (new Parser($l, PHP_INT_MAX))->run();
                $out[] = in_array($file, self::SEEDED, true) ? self::unseed($c) : $c;
            }
            $i++;
        }
        return $out;
    }

    /** Corpora whose key members are {"$seed": label[, "es256": true]} (no private key material is committed); the other corpora keep their own "$seed" shapes. */
    private const SEEDED = ['ref-policy-bridge.json.gz', 'ref-agentcard.json.gz', 'ref-ap2.json.gz', 'ref-attest-eat.json.gz', 'ref-dpop.json.gz', 'ref-idjag.json.gz',
        'ref-oidc.json.gz', 'ref-oidc-java.json.gz', 'ref-sdjwt.json.gz', 'ref-signals.json.gz', 'ref-txn-tokens.json.gz', 'ref-webbotauth.json.gz',
        'ref-gnap.json.gz', 'ref-rotate.json.gz', 'ref-connect-v2.json.gz', 'ref-pq-threshold.json.gz', 'ref-pq-threshold-java-extra.json.gz',
        'ref-oprf.json.gz', 'ref-actions-review.json.gz', 'ref-dpop-rsa.json.gz', 'ref-oprf-gen.json.gz', 'ref-attest-eat-gen.json.gz',
        'base-undo.json.gz', 'base-approval.json.gz', 'base-argprov.json.gz', 'ref-ratchet.json.gz', 'ref-invariants.json.gz', 'ref-payments.json.gz',
        'ref-payments-java-extra.json.gz', 'ref-intent-layers.json.gz', 'ref-intent-statement.json.gz', 'ref-fhe.json.gz', 'ref-actions-evolve.json.gz', 'ref-actions-rules-py.json.gz', 'ref-actions-build-py.json.gz', 'ref-actions-pack.json.gz', 'ref-actions-pack-log.json.gz', 'ref-fndsa.json.gz', 'base-prohibitions.json.gz', 'ref-intent-profile.json.gz'];

    /** {"$seed": label[, "es256": true]} -> base64url(sha256("atlas-pca-conformance/" . label)), the top bit of byte 0 cleared for es256; any other value is walked unchanged. */
    /** A UTF-16 code unit of the corpus (a JSON number, a Num here). */
    private static function cu(mixed $x): int
    {
        return (int) \Atlas\Pca\Js::num($x);
    }

    public static function unseed(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $ks = $v->keys();
            if ($ks === ['$utf16'] && is_array($v->get('$utf16'))) {
                // {"$utf16": [code units]}: PHP strings are bytes, so a lone surrogate is its WTF-8 form (the form the lane's JSON reader keeps)
                $u = array_values($v->get('$utf16'));
                $s = '';
                for ($i = 0, $n = count($u); $i < $n; $i++) {
                    $c = self::cu($u[$i]);
                    if ($c >= 0xD800 && $c <= 0xDBFF && $i + 1 < $n && self::cu($u[$i + 1]) >= 0xDC00 && self::cu($u[$i + 1]) <= 0xDFFF) {
                        $c = 0x10000 + (($c - 0xD800) << 10) + (self::cu($u[++$i]) - 0xDC00);
                    }
                    $s .= $c < 0x80 ? chr($c) : ($c < 0x800 ? chr(0xC0 | ($c >> 6)) . chr(0x80 | ($c & 0x3F))
                        : ($c < 0x10000 ? chr(0xE0 | ($c >> 12)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F))
                        : chr(0xF0 | ($c >> 18)) . chr(0x80 | (($c >> 12) & 0x3F)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F))));
                }
                return $s;
            }
            if (in_array('$seed', $ks, true) && array_diff($ks, ['$seed', 'es256', 'ec', 'ed448']) === []) {
                $pre = 'atlas-pca-conformance/' . $v->get('$seed');
                if ($v->has('ed448')) {
                    $raw = hash('sha256', $pre, true) . substr(hash('sha256', $pre . '/2', true), 0, 25);
                } elseif ($v->has('ec')) {
                    // plain SHA-256 stretch, no bignum: P-384 -> 48 bytes (&0x7F), P-521 -> 66 bytes (&0x01)
                    $p521 = $v->get('ec') === 'P-521';
                    $raw = substr(hash('sha256', $pre, true) . hash('sha256', $pre . '/2', true) . hash('sha256', $pre . '/3', true), 0, $p521 ? 66 : 48);
                    $raw[0] = chr(ord($raw[0]) & ($p521 ? 0x01 : 0x7F));
                } else {
                    $raw = hash('sha256', $pre, true);
                    if ($v->get('es256') === true) {
                        $raw[0] = chr(ord($raw[0]) & 0x7F);
                    }
                }
                return Pca::b64u($raw);
            }
            $o = new Obj();
            foreach ($ks as $k) {
                $o->set($k, self::unseed($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::unseed(...), $v) : $v;
    }

    /** Bytes argument ({$bytes: b64url}) to raw bytes; any other value unchanged. */
    public static function bytes(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            $b = $v->get('$bytes');
            // {"$bytes":{"$seed":label}}: the corpus carries no key bytes, only the label they derive from
            return $b instanceof Obj && $b->keys() === ['$seed'] ? hash('sha256', 'atlas-pca-conformance/' . $b->get('$seed'), true) : Pca::unb64u($b);
        }
        return $v;
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
        if (is_float($v) && !is_finite($v)) { // the corpus writes a non-finite number as {"$num": "NaN" | "Infinity" | "-Infinity"}
            return Obj::of(['$num' => is_nan($v) ? 'NaN' : ($v > 0 ? 'Infinity' : '-Infinity')]);
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

    /** The 32 seed bytes behind a corpus seed label: {"$seed": label} or the string "$seed:label". */
    public static function seedBytes(mixed $v): string
    {
        $label = $v instanceof Obj && $v->keys() === ['$seed'] ? $v->get('$seed') : (is_string($v) && str_starts_with($v, '$seed:') ? substr($v, 6) : null);
        if (!is_string($label)) {
            throw new \InvalidArgumentException('seed placeholder expected');
        }
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
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
                if ($e instanceof \RuntimeException && preg_match('/^test (deadline of|memory above) /', $e->getMessage()) === 1) {
                    throw $e;   // the suite's own loop guard: end this test now, never count it as a case result
                }
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
                if (self::isEngineCrash($want->get('$throws'))) {
                    // the reference died inside the JS engine on hostile input: the native must refuse (throw or return a refusal); wording is not compared
                    if ($threw !== null || self::isRefusal($have)) {
                        continue;
                    }
                    $msg = 'want a refusal (engine crash: ' . self::canon($want) . ")\n   have " . self::show($have);
                } elseif ($threw === null) {
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
                if ($w === $h || (!self::isExactCase($base) && self::approxEqual($w, $h))) {
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

    /** The one shared definition of a raw JS-engine TypeError message; never a Node error code (ERR_*), those are matched. */
    public const ENGINE_CRASH = "/Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack/";

    public static function isEngineCrash(mixed $msg): bool
    {
        return is_string($msg) && preg_match(self::ENGINE_CRASH, $msg) === 1;
    }

    /** A returned value that is the language's refusal: null, false, or a result object saying ok:false / carrying an error. */
    private static function isRefusal(mixed $v): bool
    {
        if ($v === null || $v === false) {
            return true;
        }
        if ($v instanceof Obj) {
            return $v->get('ok') === false || ($v->has('error') && $v->get('error') !== null) || $v->get('allow') === false || $v->get('allowed') === false;
        }
        return is_array($v) && !array_is_list($v) && (($v['ok'] ?? null) === false || ($v['error'] ?? null) !== null);
    }

    /**
     * Functions whose result gates a decision (the next question, the drift freeze, an integer cutoff, an admission or a Clopper-Pearson
     * bound) are compared EXACTLY: the reference computes them in integer arithmetic or with exactly rounded IEEE operations, so every
     * double is the same bit pattern on every platform. The 1e-12 relative tolerance below remains only for the diagnostic statistics
     * (binomialCdf, Hoeffding, Wilson, lnGamma, betacf, betaInc, betaQuantile and the wallet population noise).
     */
    private const EXACT_FNS = ['clopperPearsonUpper', 'clopperPearsonCertified', 'proportionCutoff', 'repetitionCutoff', 'healthTestBytes', 'admissionPolicy',
        'etaUnderLoad', 'estimateNoise', 'noiseState', 'scenario', 'mapScenario', 'rampScenario', 'driftRun'];

    private static function isExactCase(string $fn): bool
    {
        return in_array($fn, self::EXACT_FNS, true);
    }

    /** Lead ruling: doubles that differ only in the last digits (the platform's libm) compare with a relative tolerance of 1e-12; everything else is exact. */
    private static function approxEqual(string $w, string $h): bool
    {
        $a = json_decode($w, true);
        $b = json_decode($h, true);
        if ($a === null || $b === null) {
            return false;
        }
        $eq = static function (mixed $x, mixed $y) use (&$eq): bool {
            if (is_float($x) && is_float($y)) {
                return $x === $y || (is_finite($x) && is_finite($y) && abs($x - $y) <= 1e-12 * max(abs($x), abs($y)));
            }
            if (is_array($x) && is_array($y)) {
                if (array_keys($x) !== array_keys($y)) {
                    return false;
                }
                foreach ($x as $k => $v) {
                    if (!$eq($v, $y[$k])) {
                        return false;
                    }
                }
                return true;
            }
            return $x === $y;
        };
        return $eq($a, $b);
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
