<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';

/**
 * The verifier conformance harness (the harness half of the reference's pca-conformance package): run a set of vectors through any verifier
 * under test and report, per vector, whether its verdict matched the authored expectation exactly (allow, first failed check, every check).
 * The package-root `conformance.php` / `conformance-vectors.php` runners are the CLI over the shared `vectors.json`; this is the library form.
 */
final class Conformance
{
    /** The earliest 'fail' in a verdict's checks (in their order), or null. @param Obj|array<string,mixed> $checks */
    public static function firstFailedCheck(mixed $checks): ?string
    {
        foreach (self::entries($checks) as $name => $status) {
            if ($status === 'fail') {
                return (string)$name;
            }
        }
        return null;
    }

    /** @return array<string,mixed> */
    private static function entries(mixed $checks): array
    {
        if ($checks instanceof Obj) {
            $out = [];
            foreach ($checks->keys() as $k) {
                $out[$k] = $checks->get($k);
            }
            return $out;
        }
        return is_array($checks) ? $checks : [];
    }

    private static function sameChecks(mixed $a, mixed $b): bool
    {
        $x = self::entries($a);
        $y = self::entries($b);
        if (array_keys($x) !== array_keys($y)) {
            return false;
        }
        foreach ($x as $k => $v) {
            if ($v !== $y[$k]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Run every vector through `$verify` and return a structured pass/fail report {version, total, passed, failed, ok, results}. A vector MATCHES when the
     * verifier's `allow`, its first failed check and its full per-check map all equal the authored expectation. A vector is an Obj {id, pcactn, aud,
     * verifyOptions: {nowEpoch, enforce?, intent?}, expect: {ok, firstFailedCheck, perCheck}}; `$verify` is `fn(Obj $pcactn, Obj $input): array|Obj`
     * with `$input` {grant, audience, nowEpoch, enforce?, intent?} and the verdict {allow, checks, reason?}.
     *
     * @param callable(Obj,Obj):mixed $verify
     * @param list<Obj> $vectors
     */
    public static function runConformance(callable $verify, array $vectors, string $version = '1.2.0'): Obj
    {
        $results = [];
        foreach ($vectors as $v) {
            $pcactn = $v->get('pcactn');
            $chain = $pcactn->get('cap_chain');
            $opts = $v->get('verifyOptions');
            $input = Obj::of(['grant' => is_array($chain) && $chain !== [] ? $chain[0] : null, 'audience' => $v->get('aud'), 'nowEpoch' => $opts->get('nowEpoch')]);
            foreach (['enforce', 'intent'] as $k) {
                if ($opts->has($k) && Js::truthy($opts->get($k))) {
                    $input->set($k, $opts->get($k));
                }
            }
            $verdict = $verify($pcactn, $input);
            $allow = Js::opt($verdict, 'allow');
            $checks = Js::opt($verdict, 'checks');
            $actualFirst = self::firstFailedCheck($checks);
            $expect = $v->get('expect');
            $div = [];
            if ($allow !== $expect->get('ok')) {
                $div[] = 'allow: expected ' . Js::str($expect->get('ok')) . ', got ' . Js::str($allow);
            }
            if ($actualFirst !== $expect->get('firstFailedCheck')) {
                $div[] = 'firstFailedCheck: expected ' . Js::str($expect->get('firstFailedCheck')) . ', got ' . Js::str($actualFirst);
            }
            if (!self::sameChecks($checks, $expect->get('perCheck'))) {
                $div[] = 'perCheck: expected ' . Js::stringify($expect->get('perCheck')) . ', got ' . Js::stringify($checks instanceof Obj ? $checks : Obj::of(self::entries($checks)));
            }
            $actual = Obj::of(['allow' => $allow, 'firstFailedCheck' => $actualFirst, 'checks' => $checks]);
            if (Js::opt($verdict, 'reason') !== null) {
                $actual->set('reason', Js::opt($verdict, 'reason'));
            }
            $results[] = Obj::of(['id' => $v->get('id'), 'matched' => $div === [], 'expected' => $expect, 'actual' => $actual, 'divergences' => $div]);
        }
        $passed = count(array_filter($results, static fn(Obj $r): bool => $r->get('matched') === true));
        return Obj::of(['version' => $version, 'total' => new Num((string)count($results)), 'passed' => new Num((string)$passed),
            'failed' => new Num((string)(count($results) - $passed)), 'ok' => $passed === count($results), 'results' => $results]);
    }
}
