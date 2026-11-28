<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\SafetyCertificate;
use PHPUnit\Framework\TestCase;

/** Mutation kills for SafetyCertificate: the short names, policy reading, the clock defaults, requireChecks, evidence URLs and decode limits. */
final class SigSurvivorKill29SafetyCertificateTest extends TestCase
{
    private const URL_REFUSED = "check 'c1' evidence URL must be a plain https URL";

    protected function tearDown(): void
    {
        SafetyCertificate::$clockHook = null;
    }

    private static function guardian(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/g29-safety', true));
    }

    private static function weights(callable $n): Obj
    {
        return Obj::of(['alpha' => $n('0.25'), 'beta' => $n('0.2'), 'gamma' => $n('0.2'), 'delta' => $n('0.2'), 'epsilon' => $n('0.1'), 'zeta' => $n('0.05')]);
    }

    /** bMax 1, kappa 2 (bound 0.5); numbers as Num by default, or as `$n` makes them. */
    private static function policy(?callable $n = null): Obj
    {
        $n ??= static fn (string $s): Num => new Num($s);
        return Obj::of(['bMax' => $n('1'), 'kappa' => $n('2'), 'theta1' => $n('0.25'), 'theta2' => $n('0.6'), 'lambda' => $n('0.0005'), 'rho' => $n('0.5'),
            'weights' => self::weights($n)]);
    }

    private static function cert(mixed $issuedAt = null): Obj
    {
        return SafetyCertificate::issueSafetyCertificate(self::policy(), self::guardian(), $issuedAt ?? new Num('1000'));
    }

    private static function urlCheck(string $ref): ?string
    {
        return SafetyCertificate::validateSafetyChecks([Obj::of(['id' => 'c1', 'status' => 'passed',
            'evidence' => Obj::of(['kind' => 'url', 'ref' => $ref]), 'at' => new Num('0')])]);
    }

    /** issue() and verify() are public short names for the long ones. */
    public function testTheShortNamesArePublic(): void
    {
        $c = SafetyCertificate::issue(self::policy(), self::guardian(), new Num('1000'));
        $this->assertSame(['ok' => true, 'recomputedBound' => 0.5], SafetyCertificate::verify($c));
    }

    /** A policy may hold plain PHP numbers; the issued certificate verifies. */
    public function testAPolicyOfPhpNumbersIssues(): void
    {
        $c = SafetyCertificate::issueSafetyCertificate(self::policy(static fn (string $s): float => (float)$s), self::guardian(), new Num('1000'));
        $this->assertSame(['ok' => true, 'recomputedBound' => 0.5], SafetyCertificate::verifySafetyCertificate($c));
    }

    /** Parameters nested as PHP arrays are read by value (numbers inside them too), so they are not refused as invalid. */
    public function testNestedArrayParametersAreReadByValue(): void
    {
        $c = self::cert();
        $w = [];
        foreach (self::weights(static fn (string $s): Num => new Num($s))->keys() as $k) {
            $w[$k] = $c->get('params')->get('weights')->get($k);
        }
        $c->get('params')->set('weights', $w);
        // the parameters pass (read by value); only the signed message then refuses the PHP array, which has no canonical form
        $this->assertSame(['ok' => false, 'reason' => 'malformed certificate: canonicalize: unsupported type array'], SafetyCertificate::verifySafetyCertificate($c));
    }

    /** A bound that is not a number is printed as given in the statement. */
    public function testTheStatementOfANonNumber(): void
    {
        $this->assertSame('Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ '
            . 'x (= B_max / κ). This is not a claim that the agent or the system is safe.', SafetyCertificate::safetyCertificateStatement('x'));
        $this->assertStringContainsString('≤ 0.5 (= B_max', SafetyCertificate::safetyCertificateStatement(0.5));
    }

    /** Only a certificate object has a message; an unknown suite is refused at issue. */
    public function testMessageAndSuiteRefusals(): void
    {
        try {
            SafetyCertificate::safetyCertificateMessage('x');
            $this->fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('safetyCertificateMessage: not a certificate', $e->getMessage());
        }
        try {
            SafetyCertificate::issueSafetyCertificate(self::policy(), self::guardian(), null, SafetyCertificate::UNSET, SafetyCertificate::UNSET, SafetyCertificate::UNSET, 'nope');
            $this->fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame("issueSafetyCertificate: unknown signature alg 'nope'", $e->getMessage());
        }
    }

    /** With no issuedAt the clock is read as whole milliseconds rounded down, printed as integer digits. */
    public function testIssuedAtDefaultsToFlooredClockMilliseconds(): void
    {
        SafetyCertificate::$clockHook = static fn (): float => 1.0009765625; // 1000.9765625 ms exactly
        $this->assertSame('1000', SafetyCertificate::issueSafetyCertificate(self::policy(), self::guardian())->get('issued_at')->lexeme);
        SafetyCertificate::$clockHook = static fn (): float => 1e14; // 1e17 ms: integer digits, never a float's exponent form
        $this->assertSame('100000000000000000', SafetyCertificate::issueSafetyCertificate(self::policy(), self::guardian())->get('issued_at')->lexeme);
    }

    /** Without the seam the wall clock is read. */
    public function testIssuedAtReadsTheWallClock(): void
    {
        $at = (int)SafetyCertificate::issueSafetyCertificate(self::policy(), self::guardian())->get('issued_at')->lexeme;
        $this->assertLessThan(60_000, abs($at - (int)floor(microtime(true) * 1000)));
    }

    /** maxAgeMs without `now` reads the clock in floored milliseconds: a certificate issued at exactly that instant is 0 ms old. */
    public function testMaxAgeReadsTheFlooredClock(): void
    {
        SafetyCertificate::$clockHook = static fn (): float => 1.0009765625;
        $c = self::cert(new Num('1000'));
        $this->assertSame(['ok' => true, 'recomputedBound' => 0.5], SafetyCertificate::verifySafetyCertificate($c, ['maxAgeMs' => 0]));
        $this->assertSame('certificate is issued in the future', SafetyCertificate::verifySafetyCertificate(self::cert(new Num('1001')), ['maxAgeMs' => 0])['reason']);
    }

    /** requireChecks must be a list. */
    public function testRequireChecksMustBeAList(): void
    {
        $c = self::cert();
        $this->assertSame(['ok' => false, 'reason' => 'malformed certificate: requireChecks is not a list'],
            SafetyCertificate::verifySafetyCertificate($c, ['requireChecks' => 'c1']));
        $this->assertSame(['ok' => false, 'reason' => 'malformed certificate: requireChecks is not a list'],
            SafetyCertificate::verifySafetyCertificate($c, ['requireChecks' => ['a' => 'c1']]));
    }

    /** Evidence URLs: empty credentials (also around a tab) and an @ in the path pass; any username is refused. */
    public function testEvidenceUrlCredentials(): void
    {
        $this->assertNull(self::urlCheck('https://host.example/doc'));
        $this->assertNull(self::urlCheck('https://@host.example/doc'));
        $this->assertNull(self::urlCheck("https://\t@host.example/doc"));
        $this->assertNull(self::urlCheck('https://:@host.example/doc'));
        $this->assertNull(self::urlCheck('https://host.example/p@x'));
        $this->assertSame(self::URL_REFUSED, self::urlCheck('https://u@host.example/doc'));
        $this->assertSame(self::URL_REFUSED, self::urlCheck('https://u:p@host.example/doc'));
    }

    /** An evidence URL of exactly 2048 characters is allowed; one more is refused. */
    public function testEvidenceUrlLengthLimit(): void
    {
        $base = 'https://host.example/';
        $this->assertNull(self::urlCheck($base . str_repeat('a', 2048 - strlen($base))));
        $this->assertSame(self::URL_REFUSED, self::urlCheck($base . str_repeat('a', 2049 - strlen($base))));
    }

    /** decode accepts a text of exactly MAX_JSON_BYTES and refuses one byte more. */
    public function testDecodeSizeLimit(): void
    {
        $head = '{"v":1,"sig":"s","guardian":"g","params":{},"pad":"';
        $text = $head . str_repeat('a', SafetyCertificate::MAX_JSON_BYTES - strlen($head) - 2) . '"}';
        $this->assertSame(SafetyCertificate::MAX_JSON_BYTES, strlen($text));
        $this->assertNotNull(SafetyCertificate::decodeSafetyCertificate($text));
        $this->assertNull(SafetyCertificate::decodeSafetyCertificate(substr($text, 0, -2) . 'a"}'));
    }
}
