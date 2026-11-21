<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/Factory.php';

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Attest\Maa;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** 0.5 hardening, slice B: attestation verifier configuration typing (H9, H10, H11, H20) and the JSON segment size cap (H7). */
final class K05HardConfigTest extends TestCase
{
    private const MAX = 16 * 1024 * 1024;

    private static function err(callable $f): string
    {
        try {
            $f();
        } catch (AttestConstructError $e) {
            return $e->getMessage();
        }
        return '(no error)';
    }

    private static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    // ---------------------------------------------------------------------------------------------------------- H7 size cap

    public function testJsonAtTheCapIsParsedAndOneByteMoreIsRefusedBeforeParsing(): void
    {
        $ok = str_repeat(' ', self::MAX - 1) . '1';
        $this->assertSame(self::MAX, strlen($ok));
        $v = JsJson::parse($ok);
        $this->assertSame('1', $v instanceof \Atlas\Pca\Num ? $v->lexeme : (string)$v);
        // 'x' is not JSON: a parse would say "Unexpected token", the cap must answer first
        try {
            JsJson::parse(str_repeat('x', self::MAX + 1));
            $this->fail('parsed an oversized document');
        } catch (JsError $e) {
            $this->assertSame('input too large', $e->getMessage());
        }
    }

    public function testJwsSegmentOverTheCapKeepsTheContextPrefix(): void
    {
        $h = self::b64u('{}');
        $big = self::b64u(str_repeat(' ', self::MAX + 1));
        foreach ([[$big, $h], [$h, $big]] as [$a, $b]) {
            try {
                Common::parseJws("$a.$b.AA", 'parseMaaJwt');
                $this->fail('accepted an oversized segment');
            } catch (\TypeError $e) {
                $this->assertSame('parseMaaJwt: malformed JSON segment: input too large', $e->getMessage());
            }
        }
        $small = Common::parseJws(self::b64u('{"alg":"RS256"}') . '.' . self::b64u('{"a":1}') . '.AA', 'parseMaaJwt');
        $this->assertInstanceOf(Obj::class, $small['payload']);
    }

    // -------------------------------------------------------------------------------------------------------------- H9 NVIDIA

    private static function nv(array $config): Nvidia
    {
        return Nvidia::fromConfig($config, static fn($d) => null);
    }

    private static function nvCfg(array $over = []): array
    {
        return array_replace(['rootSpkiSha256' => ['aa'], 'policy' => ['measurements' => ['1' => 'ab']]], $over);
    }

    private static function hook(array $over): \Closure
    {
        return Nvidia::collateralHook(array_replace(['rimRootSpkiSha256' => ['aa']], $over), static fn(array $ids, mixed $ev): array => []);
    }

    public function testNvidiaCollateralMustBeAnObjectButNullStillBuilds(): void
    {
        $msg = 'createNvidiaSpdmVerifier: collateral must be an object';
        foreach (['required', false, 5, ['a']] as $c) {
            $this->assertSame($msg, self::err(static fn() => self::nv(self::nvCfg(['collateral' => $c]))), json_encode($c));
        }
        $this->assertInstanceOf(Nvidia::class, self::nv(self::nvCfg(['collateral' => null])));
        $this->assertInstanceOf(Nvidia::class, self::nv(self::nvCfg()));
        $this->assertInstanceOf(Nvidia::class, self::nv(self::nvCfg(['collateral' => ['rimRootSpkiSha256' => ['aa']]])));
    }

    public function testNvidiaLeafSubjectIncludesMustBeAString(): void
    {
        $msg = 'createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string';
        foreach ([5, false, ['x'], 0] as $v) {
            $this->assertSame($msg, self::err(static fn() => self::nv(self::nvCfg(['policy' => ['measurements' => ['1' => 'ab'], 'leafSubjectIncludes' => $v]]))), json_encode($v));
        }
        $this->assertInstanceOf(Nvidia::class, self::nv(self::nvCfg(['policy' => ['measurements' => ['1' => 'ab'], 'leafSubjectIncludes' => 'NVIDIA']])));
        $this->assertInstanceOf(Nvidia::class, self::nv(self::nvCfg(['policy' => ['measurements' => ['1' => 'ab'], 'leafSubjectIncludes' => null]])));
    }

    public function testNvidiaFirmwareMustBeAnObject(): void
    {
        $msg = 'nvidiaCollateralHook: firmware must be an object';
        foreach (['x', 5, true, [], ['a']] as $fw) {
            $this->assertSame($msg, self::err(static fn() => self::hook(['firmware' => $fw])), json_encode($fw));
        }
        foreach ([null, false, '', 0] as $fw) { // falsy = no firmware policy, as in the reference
            $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => $fw]));
        }
        $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => ['minDriverVersion' => '535.1']]));
        $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => Obj::of([])]));
    }

    public function testNvidiaFirmwareFloorsMustBeParseableStrings(): void
    {
        $this->assertSame("nvidiaCollateralHook: malformed minDriverVersion '535'", self::err(static fn() => self::hook(['firmware' => ['minDriverVersion' => 535]])));
        $this->assertSame("nvidiaCollateralHook: malformed minDriverVersion 'abc'", self::err(static fn() => self::hook(['firmware' => ['minDriverVersion' => 'abc']])));
        $this->assertSame("nvidiaCollateralHook: malformed minVbiosVersion 'xyz'", self::err(static fn() => self::hook(['firmware' => ['minVbiosVersion' => 'xyz']])));
        $this->assertSame("nvidiaCollateralHook: malformed minVbiosVersion 'true'", self::err(static fn() => self::hook(['firmware' => ['minVbiosVersion' => true]])));
        foreach ([null, false, '', 0] as $f) { // falsy floors are no floor
            $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => ['minDriverVersion' => $f, 'minVbiosVersion' => $f]]));
        }
        $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => ['minDriverVersion' => '535.104', 'minVbiosVersion' => '96.00.9f']]));
    }

    public function testNvidiaFirmwareDenyListsMustBeArraysOfParseableStrings(): void
    {
        $e = static fn(array $fw) => self::err(static fn() => self::hook(['firmware' => $fw]));
        $this->assertSame("nvidiaCollateralHook: malformed denyDriverVersions entry '5'", $e(['denyDriverVersions' => ['535.1', 5]]));
        $this->assertSame("nvidiaCollateralHook: malformed denyDriverVersions entry 'x'", $e(['denyDriverVersions' => 'x']));
        $this->assertSame("nvidiaCollateralHook: malformed denyVbiosVersions entry 'zz'", $e(['denyVbiosVersions' => ['96.00', 'zz']]));
        $this->assertSame("nvidiaCollateralHook: malformed denyVbiosVersions entry 'x'", $e(['denyVbiosVersions' => 'x']));
        $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => ['denyDriverVersions' => ['535.1'], 'denyVbiosVersions' => ['96.00'], ]]));
        $this->assertInstanceOf(\Closure::class, self::hook(['firmware' => ['denyDriverVersions' => null, 'denyVbiosVersions' => null]]));
    }

    public function testNvidiaRequireCrlIssuersMustListOnlyStrings(): void
    {
        $msg = 'nvidiaCollateralHook: requireCrlIssuers must list only strings';
        foreach (['NVIDIA GH100', ['a', 5], [['a']], 5, false] as $v) {
            $this->assertSame($msg, self::err(static fn() => self::hook(['requireCrlIssuers' => $v])), json_encode($v));
        }
        $this->assertInstanceOf(\Closure::class, self::hook(['requireCrlIssuers' => ['NVIDIA GH100']]));
        $this->assertInstanceOf(\Closure::class, self::hook(['requireCrlIssuers' => []]));
        $this->assertInstanceOf(\Closure::class, self::hook(['requireCrlIssuers' => null]));
    }

    // ---------------------------------------------------------------------------------------------------------- H10 allowlists

    public function testAmdAllowlistsMustBeArraysOfStrings(): void
    {
        $mk = static fn(array $extra) => new Amd(['family' => 'genoa', 'binding' => 'report-data', 'policy' => ['measurements' => ['00']] + $extra], static fn($d) => null);
        foreach (['hostData', 'chipIds'] as $k) {
            $msg = "createAmdSnpVerifier: policy.$k must be an array of strings";
            $this->assertSame($msg, self::err(static fn() => $mk([$k => 'aa'])));
            $this->assertSame($msg, self::err(static fn() => $mk([$k => ['aa', 1]])));
            $this->assertSame($msg, self::err(static fn() => $mk([$k => false])));
            $this->assertInstanceOf(Amd::class, $mk([$k => ['aa']]));
            $this->assertInstanceOf(Amd::class, $mk([$k => []]));
            $this->assertInstanceOf(Amd::class, $mk([$k => null]));
        }
        $this->assertInstanceOf(Amd::class, $mk([]));
    }

    public function testIntelAllowlistsMustBeArraysOfStrings(): void
    {
        $mk = static fn(array $extra) => new Intel(['binding' => 'report-data', 'policy' => ['mrtds' => [str_repeat('ab', 48)]] + $extra], static fn() => null);
        foreach (['fmspcs', 'rtmrs'] as $k) {
            $msg = "createIntelDcapVerifier: policy.$k must be an array of strings";
            $this->assertSame($msg, self::err(static fn() => $mk([$k => 'aa'])));
            $this->assertSame($msg, self::err(static fn() => $mk([$k => ['aa', 1]])));
            $this->assertInstanceOf(Intel::class, $mk([$k => ['aa']]));
            $this->assertInstanceOf(Intel::class, $mk([$k => []]));
            $this->assertInstanceOf(Intel::class, $mk([$k => null]));
        }
    }

    public function testMaaAllowlistsMustBeArraysOfStrings(): void
    {
        $mk = static fn(array $extra) => new Maa(['trustedIssuers' => ['https://x.attest.azure.net'], 'trustAnchors' => ['rootSpkiSha256' => ['aa']],
            'policy' => ['tdxMrtds' => ['aa']] + $extra], static fn($d) => null);
        foreach (['sevSnpHostData', 'tdxRtmrs', 'tdxAllowedTcbStatuses'] as $k) {
            $msg = "createAzureMaaVerifier: policy.$k must be an array of strings";
            $this->assertSame($msg, self::err(static fn() => $mk([$k => 'aa'])));
            $this->assertSame($msg, self::err(static fn() => $mk([$k => ['aa', 1]])));
            $this->assertInstanceOf(Maa::class, $mk([$k => ['aa']]));
            $this->assertInstanceOf(Maa::class, $mk([$k => null]));
        }
    }

    // ---------------------------------------------------------------------------------------------------------- H11 Intel collateral

    public function testIntelPolicyCollateralMustBeAnObject(): void
    {
        $mk = static fn(array $extra) => new Intel(['binding' => 'report-data', 'policy' => ['mrtds' => [str_repeat('ab', 48)]] + $extra], static fn() => null);
        $msg = 'createIntelDcapVerifier: policy.collateral must be an object';
        foreach (['x', 5, false, ['a'], []] as $c) {
            $this->assertSame($msg, self::err(static fn() => $mk(['collateral' => $c])), json_encode($c));
        }
        $this->assertInstanceOf(Intel::class, $mk([]));
        $this->assertInstanceOf(Intel::class, $mk(['collateral' => null]));
        $this->assertInstanceOf(Intel::class, $mk(['collateral' => Obj::of([])]));
        $this->assertInstanceOf(Intel::class, $mk(['collateral' => ['minTcbEvaluationDataNumber' => 7]]));
    }

    // ---------------------------------------------------------------------------------------------------------- H20 MAA SVN floors

    public function testMaaSvnFloorsMustBeFiniteNumbersAtConstruction(): void
    {
        $mk = static fn(mixed $floors) => new Maa(['trustedIssuers' => ['https://x.attest.azure.net'], 'trustAnchors' => ['rootSpkiSha256' => ['aa']],
            'policy' => ['tdxMrtds' => ['aa'], 'sevSnpMinTcb' => $floors]], static fn($d) => null);
        foreach (['snp', 'tee', 'microcode', 'bootloader'] as $k) {
            foreach ([[5], '5', null, true, NAN, INF, -1, 1.5] as $v) {
                $this->assertSame("createAzureMaaVerifier: policy.sevSnpMinTcb.$k must be a non-negative integer", self::err(static fn() => $mk([$k => $v])), $k . var_export($v, true));
            }
            $this->assertInstanceOf(Maa::class, $mk([$k => 5]));
        }
        $this->assertSame('createAzureMaaVerifier: policy.sevSnpMinTcb.x is not a known field (bootloader | snp | microcode | tee)', self::err(static fn() => $mk(['x' => [5]])));
    }
}
