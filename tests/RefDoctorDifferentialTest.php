<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ControlEvals;
use Atlas\Pca\Doctor;
use Atlas\Pca\DoctorPca;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The deployment doctor (scrubbing, the clock / proxy / suites / root-caveat / enforcement checks, result formatting, configuration,
 * the CLI and the full run) against the TS reference: test-data/ref-doctor.json.gz. Network, clock and the deployed library are
 * replayed from the named fakes the reference used (a table of responses per url, a clock that advances by `rtt` before answering,
 * and a library that decides a payment by named behaviour).
 */
final class RefDoctorDifferentialTest extends TestCase
{
    private const FILE = 'ref-doctor.json.gz';
    private const URL1 = 'https://api.example.com';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /**
     * A fake network and clock: every fetch pops the next entry of its url (the last one repeats), advances the clock by `rtt`
     * BEFORE answering and throws when the entry says so.
     *
     * @return array{0:\Closure,1:\Closure} fetch, now
     */
    private static function env(Obj $spec): array
    {
        $t = (float)Js::num($spec->get('now'));
        $idx = [];
        $responses = $spec->get('responses');
        $fetch = static function (string $url, string $method = 'GET', array $headers = [], float $timeoutMs = 0.0) use (&$t, &$idx, $responses): array {
            if (!$responses->has($url)) {
                throw new \Exception('no route ' . $url);
            }
            $lst = $responses->get($url);
            $i = $idx[$url] ?? 0;
            $idx[$url] = $i + 1;
            $rsp = $lst[min($i, count($lst) - 1)];
            $rtt = $rsp->get('rtt');
            $t += Js::truthy($rtt) ? (float)Js::num($rtt) : 0.0;
            if (Js::truthy($rsp->get('throw'))) {
                throw new \Exception((string)$rsp->get('throw'));
            }
            return ['status' => 200, 'headers' => ['date' => $rsp->get('date'), 'ratelimit-remaining' => $rsp->get('rl')]];
        };
        return [$fetch, static function () use (&$t): float {
            return $t;
        }];
    }

    /** The reference's named fake library: it decides a payment under the root caveat the way each behaviour says. */
    private static function fakePca(string $behavior): \Closure
    {
        return static function (array $cav, int|float $amount) use ($behavior): array {
            if ($behavior === 'throws') {
                throw new \Exception('boom');
            }
            if ($behavior === 'allow-all') {
                return ['allowed' => true, 'reasons' => []];
            }
            if ($behavior === 'deny-all') {
                return ['allowed' => false, 'reasons' => ['denied', 7]];
            }
            if ($behavior === 'nonarray-reasons') {
                return ['allowed' => false, 'reasons' => 'x'];
            }
            if ($cav['type'] === 'max_spend') {
                if ($behavior === 'ignore-max') {
                    return ['allowed' => true, 'reasons' => []];
                }
                return $amount <= $cav['usd'] ? ['allowed' => true, 'reasons' => []] : ['allowed' => false, 'reasons' => ['over max_spend']];
            }
            if ($behavior === 'ignore-unknown') {
                return ['allowed' => true, 'reasons' => []];
            }
            return ['allowed' => false, 'reasons' => ['unknown caveat type']];
        };
    }

    private static function loader(Obj $spec): \Closure
    {
        return static function (?string $dir) use ($spec): DoctorPca {
            if (Js::truthy($spec->get('throws'))) {
                throw new \Exception((string)$spec->get('throws'));
            }
            return new DoctorPca((string)$spec->get('version'), (string)$spec->get('path'), self::fakePca((string)$spec->get('behavior')));
        };
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'consts' => fn(array $a) => [
                'USAGE' => Doctor::USAGE, 'CHECK_GROUPS' => Doctor::CHECK_GROUPS, 'DEFAULT_REQUIRED' => Doctor::DEFAULT_REQUIRED,
                'ROOT_CAVEAT_MIN_VERSION' => Doctor::ROOT_CAVEAT_MIN_VERSION, 'DEFAULT_REFERENCE_URL' => Doctor::DEFAULT_REFERENCE_URL,
                'SUITES_REMEDIATION' => Doctor::SUITES_REMEDIATION, 'PQ_REMEDIATION' => Doctor::PQ_REMEDIATION, 'CLOCK_REMEDIATION' => Doctor::CLOCK_REMEDIATION,
                'PROXY_REMEDIATION' => Doctor::PROXY_REMEDIATION, 'ATOMICITY_REMEDIATION' => Doctor::ATOMICITY_REMEDIATION,
                'DURABILITY_REMEDIATION' => Doctor::DURABILITY_REMEDIATION, 'CAVEAT_REMEDIATION' => Doctor::CAVEAT_REMEDIATION,
            ],
            'scrubText' => fn(array $a) => Doctor::scrubText($a[0]),
            'scrubDeep' => fn(array $a) => Doctor::scrubDeep($a[0]),
            'checkAllowedSuites' => fn(array $a) => Doctor::checkAllowedSuites($a[0]),
            'checkPqBinding' => fn(array $a) => Doctor::checkPqBinding($a[0]),
            'checkProxyConfig' => fn(array $a) => Doctor::checkProxyConfig($a[0]),
            'testNetIp' => fn(array $a) => Doctor::testNetIp(ControlEvals::mulberry32($a[0])),
            'forgedHeaders' => fn(array $a) => Doctor::forgedHeaders(ControlEvals::mulberry32($a[0])),
            'checkClock' => function (array $a) {
                [$fetch, $now] = self::env($a[1]);
                return Doctor::checkClock($a[0], $fetch, $now);
            },
            'readDate' => function (array $a) {
                [$fetch, $now] = self::env($a[1]);
                return Doctor::readDate(self::URL1, $fetch, $now, 1000.0);
            },
            'checkProxyProbe' => function (array $a) {
                [$fetch] = self::env($a[1]);
                return Doctor::checkProxyProbe($a[0], $fetch, ControlEvals::mulberry32(7));
            },
            'compareVersion' => fn(array $a) => Doctor::compareVersion($a[0], $a[1]),
            'checkRootCaveats' => fn(array $a) => Doctor::checkRootCaveats($a[0], self::loader($a[1])),
            'checkEnforcement' => fn(array $a) => Doctor::checkEnforcement($a[0]),
            'configProblems' => fn(array $a) => Doctor::configProblems($a[0]),
            'verdictOf' => fn(array $a) => Doctor::verdictOf(...$a),
            'formatResults' => fn(array $a) => Doctor::formatResults($a[0], $a[1], $a[2]),
            'configFromEnv' => fn(array $a) => Doctor::configFromEnv($a[0]),
            'mergeConfig' => fn(array $a) => Doctor::mergeConfig(...$a),
            'parseDoctorArgs' => fn(array $a) => Doctor::parseDoctorArgs($a[0]),
            'main' => function (array $a) {
                $out = [];
                $err = [];
                $code = Doctor::main($a[0], $a[1], static function (string $s) use (&$out): void {
                    $out[] = $s;
                }, static function (string $s) use (&$err): void {
                    $err[] = $s;
                });
                return ['code' => $code, 'out' => $out, 'err' => $err];
            },
            'runDoctor' => function (array $a) {
                [$cfg, $only, $spec, $caveat] = $a;
                [$fetch, $now] = self::env($spec);
                return Doctor::runDoctor($cfg, $only, ['fetch' => $fetch, 'now' => $now, 'load' => self::loader($caveat)]);
            },
        ]);
    }
}
