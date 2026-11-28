<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEat;
use Atlas\Pca\Bytes;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Js;
use Atlas\Pca\Jsx;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for AttestEat.php (group 7): the JavaScript value helpers, the tolerant SEV-SNP parse, EAT build / verify refusals,
 * freshness / channel-binding edges, the TCB packing and the nonce. Private helpers are reached by reflection where the public
 * API cannot pin their exact result.
 */
final class AttestSurvivorKill7EatCoreTest extends TestCase
{
    private static function m(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(AttestEat::class, $name))->invoke(null, ...$args);
    }

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        throw new \LogicException('nothing was thrown');
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/kill7-eat-core', true);
    }

    private static function pub(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function tok(array $header, array $payload): string
    {
        return Pca::b64u(Js::stringify(Obj::of($header))) . '.' . Pca::b64u(Js::stringify(Obj::of($payload))) . '.' . Pca::b64u(str_repeat("\x01", 64));
    }

    private static function tcb(mixed $v): ?string
    {
        $g = self::m('packTcb', $v);
        return $g === null ? null : gmp_strval($g);
    }

    // ---- JavaScript value helpers --------------------------------------------------------------------------------------------

    /** Reading a member of null / undefined is the JavaScript TypeError with the exact text; absent members of objects are undefined. */
    public function testReadingMembersOfNullAndUndefined(): void
    {
        foreach ([[null, 'null'], [Jsx::$U, 'undefined']] as [$v, $what]) {
            $e = self::thrown(fn() => AttestEat::verifyFreshness(new Obj(), $v));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame("Cannot read properties of $what (reading 'now')", $e->getMessage());
            $e = self::thrown(fn() => self::m('g', $v, 'zz'));
            $this->assertSame("Cannot read properties of $what (reading 'zz')", $e->getMessage());
        }
        $this->assertInstanceOf(Undef::class, self::m('g', Obj::of(['a' => 1]), 'b'));
        $this->assertSame(1, self::m('g', Obj::of(['a' => 1]), 'a'));
        $this->assertNull(self::m('g', Obj::of(['a' => null]), 'a'));
        $this->assertInstanceOf(Undef::class, self::m('g', ['a'], '0')); // a list has no members
        $this->assertInstanceOf(Undef::class, self::m('g', 'str', 'length'));
    }

    /** A PHP assoc array is an object (member reads work, absent keys are undefined with no warning); a list is not. */
    public function testAssocArraysAreObjects(): void
    {
        $r = AttestEat::verifyFreshness(['eat_nonce' => 'n', 'iat' => 100], ['expectedNonce' => 'n', 'now' => 100000, 'maxAgeMs' => 1000]);
        $this->assertTrue($r->get('ok'));
        $this->assertSame(5, self::m('g', ['k' => 5], 'k'));
        $this->assertInstanceOf(Undef::class, self::m('g', ['k' => 5], 'other'));
    }

    /** A finite float / int / Num is a number; INF, NAN, strings and non-numbers are not; num() widens to float. */
    public function testIsNumberAndNum(): void
    {
        foreach ([1, 0, -3, 1.5, new Num('2'), new Num('-0.5')] as $v) {
            $this->assertTrue(self::m('isNumber', $v));
        }
        foreach ([INF, -INF, NAN, '1', null, true, [], new Num('1e999'), Jsx::$U] as $v) {
            $this->assertFalse(self::m('isNumber', $v));
        }
        $this->assertSame(5.0, self::m('num', 5));
        $this->assertSame(2.5, self::m('num', new Num('2.5')));
        $this->assertSame(1.5, self::m('num', 1.5));
    }

    /** jsString: undefined / null / values print as JavaScript does (an undefined is not "[object Object]"). */
    public function testJsString(): void
    {
        $this->assertSame('undefined', self::m('jsString', Jsx::$U));
        $this->assertSame('null', self::m('jsString', null));
        $this->assertSame('5', self::m('jsString', 5));
        $this->assertSame('x', self::m('jsString', 'x'));
    }

    /** strictEq is JavaScript ===: numbers by value, no cross-type equality, null / undefined / object identity. */
    public function testStrictEqualityTable(): void
    {
        $o = new Obj();
        $true = [[1, 1.0], [new Num('1'), 1], ['a', 'a'], [true, true], [false, false], [null, null], [Jsx::$U, Jsx::$U],
            [new Undef(), new Undef()], [$o, $o]];
        foreach ($true as $i => [$a, $b]) {
            $this->assertTrue(self::m('strictEq', $a, $b), "true row $i");
        }
        $false = [[0, 'abc'], ['abc', 0], [1, 2], ['1', 1], [1, true], [true, 1], [true, false], [false, true], [true, 'x'], ['x', false], [null, false], [null, 0],
            [0, null], [Jsx::$U, null], [null, Jsx::$U], [Jsx::$U, 5], [5, Jsx::$U], ['a', 'b'], ['a', null], [new Obj(), new Obj()], [new Undef(), null], [null, new Undef()]];
        foreach ($false as $i => [$a, $b]) {
            $this->assertFalse(self::m('strictEq', $a, $b), "false row $i");
        }
    }

    /** The constant-time compare refuses non-strings with the exact error, and compares by content and length. */
    public function testCtEq(): void
    {
        foreach ([[1, 'a'], ['a', 1], [null, 'a'], ['a', null]] as [$a, $b]) {
            $e = self::thrown(fn() => self::m('ctEq', $a, $b));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('the first argument must be of type string', $e->getMessage());
        }
        $this->assertTrue(self::m('ctEq', 'abc', 'abc'));
        $this->assertTrue(self::m('ctEq', "\u{e9}", "\u{e9}"));
        $this->assertFalse(self::m('ctEq', 'abc', 'abd'));
        $this->assertFalse(self::m('ctEq', 'abc', 'abcd'));
        $this->assertFalse(self::m('ctEq', '', 'a'));
    }

    /** The clock is whole milliseconds of the real wall clock (floored, not scaled). */
    public function testNowMsIsTheFlooredWallClock(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $lo = microtime(true) * 1000;
            $n = self::m('nowMs');
            $hi = microtime(true) * 1000;
            $this->assertIsFloat($n);
            $this->assertSame(floor($n), $n);
            $this->assertLessThanOrEqual($hi, $n);
            $this->assertGreaterThanOrEqual($lo - 1, $n);
        }
    }

    /** numObj prints a float in the JavaScript number form, an int as its digits. */
    public function testNumObjUsesTheJavaScriptNumberForm(): void
    {
        $this->assertSame('5', self::m('numObj', 5)->lexeme);
        $this->assertSame('-3', self::m('numObj', -3)->lexeme);
        $this->assertSame(IntentWb::jsStr(1e25), self::m('numObj', 1e25)->lexeme);
        $this->assertNotSame('1.0E+25', self::m('numObj', 1e25)->lexeme);
        $this->assertSame(IntentWb::jsStr(0.1 + 0.2), self::m('numObj', 0.1 + 0.2)->lexeme);
        $this->assertNotSame('0.3', self::m('numObj', 0.1 + 0.2)->lexeme);
    }

    // ---- evidence projection and the tolerant parse ----------------------------------------------------------------------

    /** evidenceFromReport is public and projects exactly the six evidence members. */
    public function testEvidenceFromReportIsPublicAndExact(): void
    {
        $r = ['version' => 2, 'measurement' => str_repeat("\xAB", 48), 'reported_tcb' => gmp_init('123456789'), 'guest_svn' => 7,
            'chip_id' => str_repeat("\x11", 64), 'policy' => gmp_init(0x80000)];
        $e = AttestEat::evidenceFromReport($r);
        $this->assertSame(['version', 'measurement', 'reported_tcb', 'guest_svn', 'chip_id', 'debug'], $e->keys());
        $this->assertSame('2', $e->get('version')->lexeme);
        $this->assertSame(str_repeat('ab', 48), $e->get('measurement'));
        $this->assertSame('123456789', $e->get('reported_tcb'));
        $this->assertSame('7', $e->get('guest_svn')->lexeme);
        $this->assertSame(str_repeat('11', 64), $e->get('chip_id'));
        $this->assertTrue($e->get('debug'));
        $r['policy'] = gmp_init(0x7FFFF);
        $this->assertFalse(AttestEat::evidenceFromReport($r)->get('debug'));
    }

    /** A non-Uint8Array input is refused with the exact degraded result; a Bytes wrapper is unwrapped. */
    public function testParseReportTolerantInputTypes(): void
    {
        $r = AttestEat::parseReportTolerant(5);
        $this->assertSame(['ok', 'version', 'known', 'degraded', 'notes'], $r->keys());
        $this->assertFalse($r->get('ok'));
        $this->assertSame('0', $r->get('version')->lexeme);
        $this->assertFalse($r->get('known'));
        $this->assertTrue($r->get('degraded'));
        $this->assertSame(['input is not a Uint8Array'], $r->get('notes'));

        $r = AttestEat::parseReportTolerant(new Bytes('ab'));
        $this->assertSame(['ok', 'version', 'known', 'degraded', 'notes'], $r->keys());
        $this->assertFalse($r->get('ok'));
        $this->assertSame('0', $r->get('version')->lexeme);
        $this->assertFalse($r->get('known'));
        $this->assertTrue($r->get('degraded'));
        $this->assertSame(['buffer too short to read the report version'], $r->get('notes'));
    }

    private static function buf(int $len, array $put = []): string
    {
        $b = str_repeat("\0", max($len, 816));
        foreach ($put as $off => $bytes) {
            $b = substr_replace($b, $bytes, $off, strlen($bytes));
        }
        return substr($b, 0, $len);
    }

    /** A known version with a complete buffer gets the full parse (not degraded, with the report and its evidence). */
    public function testParseReportTolerantFullParse(): void
    {
        $put = [0 => pack('V', 2), 4 => pack('V', 7), 8 => pack('P', 0x80000), 0x90 => str_repeat("\xAB", 48), 0x180 => pack('P', 5), 0x1A0 => str_repeat("\x11", 64)];
        $r = AttestEat::parseReportTolerant(self::buf(816, $put));
        $this->assertSame(['ok', 'version', 'known', 'degraded', 'notes', 'hasReport', 'evidence', 'report'], $r->keys());
        $this->assertTrue($r->get('ok'));
        $this->assertSame('2', $r->get('version')->lexeme);
        $this->assertTrue($r->get('known'));
        $this->assertFalse($r->get('degraded'));
        $this->assertSame([], $r->get('notes'));
        $this->assertTrue($r->get('hasReport'));
        $this->assertSame(2, $r->get('report')['version']);
        $ev = $r->get('evidence');
        $this->assertSame(str_repeat('ab', 48), $ev->get('measurement'));
        $this->assertSame('5', $ev->get('reported_tcb'));
        $this->assertSame('7', $ev->get('guest_svn')->lexeme);
        $this->assertSame(str_repeat('11', 64), $ev->get('chip_id'));
        $this->assertTrue($ev->get('debug'));
    }

    /** A known version one byte short of the full report degrades to the stable header with the length note. */
    public function testParseReportTolerantKnownVersionJustShort(): void
    {
        $r = AttestEat::parseReportTolerant(self::buf(815, [0 => pack('V', 2)]));
        $this->assertTrue($r->get('ok'));
        $this->assertTrue($r->get('known'));
        $this->assertTrue($r->get('degraded'));
        $this->assertFalse($r->has('report'));
        $this->assertSame(["buffer length 815 < full report 816 \u{2014} degraded header-only parse"], $r->get('notes'));
        $full = AttestEat::parseReportTolerant(self::buf(816, [0 => pack('V', 2)]));
        $this->assertFalse($full->get('degraded'));
    }

    /** The version-stable header fields appear at exactly their offsets plus lengths (measurement 192, tcb 392, chip id 480). */
    public function testParseReportTolerantHeaderOnlyBoundaries(): void
    {
        $put = [0 => pack('V', 99), 4 => pack('V', 7), 0x90 => str_repeat("\xCD", 48), 0x180 => pack('P', 123456789012), 0x1A0 => str_repeat("\x5A", 64)];
        $r = AttestEat::parseReportTolerant(self::buf(191, $put));
        $this->assertFalse($r->get('ok'));
        $this->assertFalse($r->get('known'));
        $this->assertTrue($r->get('degraded'));
        $this->assertSame('99', $r->get('version')->lexeme);
        $this->assertCount(2, $r->get('notes'));
        $this->assertSame('buffer too short to read the launch measurement', $r->get('notes')[1]);
        $this->assertFalse($r->has('evidence'));

        $base = ['version', 'measurement', 'degraded', 'guest_svn', 'debug'];
        foreach ([192, 391] as $len) {
            $r = AttestEat::parseReportTolerant(self::buf($len, $put));
            $this->assertTrue($r->get('ok'), "len $len");
            $this->assertTrue($r->get('degraded'));
            $ev = $r->get('evidence');
            $this->assertSame($base, $ev->keys(), "len $len");
            $this->assertSame(str_repeat('cd', 48), $ev->get('measurement'));
            $this->assertSame('7', $ev->get('guest_svn')->lexeme);
            $this->assertFalse($ev->get('debug'));
            $this->assertTrue($ev->get('degraded'));
        }
        foreach ([392, 479] as $len) {
            $ev = AttestEat::parseReportTolerant(self::buf($len, $put))->get('evidence');
            $this->assertSame([...$base, 'reported_tcb'], $ev->keys(), "len $len");
            $this->assertSame('123456789012', $ev->get('reported_tcb'));
        }
        $ev = AttestEat::parseReportTolerant(self::buf(480, $put))->get('evidence');
        $this->assertSame([...$base, 'reported_tcb', 'chip_id'], $ev->keys());
        $this->assertSame(str_repeat('5a', 64), $ev->get('chip_id'));
    }

    /** The debug bit (policy bit 19) is read from the little-endian u64 at 8..15: byte 10, bit 3, and nothing else. */
    public function testParseReportTolerantDebugBitPosition(): void
    {
        $dbg = static fn(array $bytes): bool => AttestEat::parseReportTolerant(self::buf(192, [0 => pack('V', 99)] + $bytes))->get('evidence')->get('debug');
        $this->assertTrue($dbg([10 => "\x08"]));
        $this->assertTrue($dbg([10 => "\xFF"]));
        $this->assertFalse($dbg([9 => "\x08", 11 => "\x08"])); // the neighbouring bytes
        $this->assertFalse($dbg([10 => "\x07"])); // every other bit of byte 10
        $this->assertFalse($dbg([14 => "\x08"]));
        $this->assertFalse($dbg([]));
    }

    // ---- build / verify ----------------------------------------------------------------------------------------------------------

    /** An algorithm outside EdDSA / ES256 is refused with the exact text (any string, any type). */
    public function testBuildEatRefusesUnsupportedAlgorithms(): void
    {
        foreach ([['RS256', 'RS256'], ['none', 'none'], [5, '5'], ['', '']] as [$alg, $text]) {
            $e = self::thrown(fn() => AttestEat::buildEat(Obj::of(['issuer' => 'i', 'nonce' => 'n', 'channelId' => 'c', 'key' => self::seed(), 'alg' => $alg])));
            $this->assertInstanceOf(\InvalidArgumentException::class, $e);
            $this->assertSame("buildEAT: unsupported alg '$text'", $e->getMessage());
        }
        $ok = AttestEat::buildEat(Obj::of(['issuer' => 'i', 'nonce' => 'n', 'channelId' => 'c', 'key' => self::seed(), 'alg' => null, 'now' => 1700000000000]));
        $this->assertCount(3, explode('.', $ok));
    }

    /** The typ comparison lowercases with Unicode rules and defaults a bare name to application/. */
    public function testNormalizeTyp(): void
    {
        $this->assertSame("application/\u{e0}b", self::m('normalizeTyp', "\u{c0}B"));
        $this->assertSame('application/eat+jwt', self::m('normalizeTyp', 'EAT+JWT'));
        $this->assertSame('application/eat+jwt', self::m('normalizeTyp', 'Application/EAT+JWT'));
        $this->assertSame('x/y', self::m('normalizeTyp', 'X/Y'));
    }

    /** verifyEat refuses an unsupported alg header, a bad allow-list, a missing or non-string typ, each with its exact text. */
    public function testVerifyEatHeaderRefusals(): void
    {
        $payload = ['iss' => 'x', 'iat' => 1];
        $e = self::thrown(fn() => AttestEat::verifyEat(self::tok(['alg' => 'none', 'typ' => 'eat+jwt'], $payload), 'k'));
        $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        $this->assertSame('EAT invalid: missing or unsupported `alg` header', $e->getMessage());

        $good = self::tok(['alg' => 'EdDSA', 'typ' => 'eat+jwt'], $payload);
        foreach ([5, ['x' => 'EdDSA'], true] as $allowed) {
            $e = self::thrown(fn() => AttestEat::verifyEat($good, 'k', Obj::of(['algorithms' => $allowed])));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('allowed.includes is not a function', $e->getMessage());
        }
        $e = self::thrown(fn() => AttestEat::verifyEat($good, 'k', Obj::of(['algorithms' => ['ES256']])));
        $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        $this->assertSame('EAT invalid: alg EdDSA not in the allowed set', $e->getMessage());

        $e = self::thrown(fn() => AttestEat::verifyEat(self::tok(['alg' => 'EdDSA'], $payload), 'k'));
        $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        $this->assertSame('EAT invalid: typ undefined is not eat+jwt', $e->getMessage());

        $e = self::thrown(fn() => AttestEat::verifyEat($good, 'k', Obj::of(['typ' => 5])));
        $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        $this->assertSame('EAT invalid: typ eat+jwt is not 5', $e->getMessage());

        $e = self::thrown(fn() => AttestEat::verifyEat(self::tok(['alg' => 'EdDSA', 'typ' => 'other'], $payload), 'k'));
        $this->assertSame('EAT invalid: typ other is not eat+jwt', $e->getMessage());
    }

    /** A measured claim is kept only when all four identity members are strings. */
    public function testMeasuredClaimNeedsAllFourMembers(): void
    {
        $full = ['model_id' => 'm', 'weights_digest' => 'w', 'runtime_measurement' => 'r', 'operator' => 'o'];
        $verify = function (array $measured): Obj {
            $eat = AttestEat::buildEat(Obj::of(['issuer' => 'iss', 'nonce' => 'n', 'channelId' => 'c', 'key' => self::seed(), 'now' => 1700000000000, 'measured' => Obj::of($measured)]));
            return AttestEat::verifyEat($eat, self::pub());
        };
        $claims = $verify($full);
        $this->assertSame('1700000000', $claims->get('iat')->lexeme);
        $this->assertTrue($claims->has('measured'));
        $this->assertSame(['model_id', 'weights_digest', 'runtime_measurement', 'operator'], $claims->get('measured')->keys());
        foreach (array_keys($full) as $drop) {
            $m = $full;
            unset($m[$drop]);
            $this->assertFalse($verify($m)->has('measured'), $drop);
        }
    }

    // ---- freshness and channel binding ----------------------------------------------------------------------------------------

    /** A present clockSkewMs of 0 is zero (not floored up to 1 ms): an iat half a millisecond ahead is in the future. */
    public function testFreshnessSkewIsFlooredAtZeroNotOne(): void
    {
        $eat = ['eat_nonce' => 'n', 'iat' => 100.0005];
        $base = ['expectedNonce' => 'n', 'now' => 100000, 'maxAgeMs' => 60000];
        foreach ([0, -5, 0.0] as $skew) {
            $r = AttestEat::verifyFreshness($eat, $base + ['clockSkewMs' => $skew]);
            $this->assertFalse($r->get('ok'), (string)$skew);
            $this->assertSame('EAT iat is in the future', $r->get('reason'));
        }
        $this->assertTrue(AttestEat::verifyFreshness($eat, $base + ['clockSkewMs' => 5])->get('ok'));
        $this->assertTrue(AttestEat::verifyFreshness($eat, $base)->get('ok') === false);
    }

    /** A finite float is a number and an infinite one is not (it falls back to the clock): the window follows the real now. */
    public function testFreshnessNumbersAreFiniteFloatsOnly(): void
    {
        $nowS = (int)floor(microtime(true));
        $opts = ['expectedNonce' => 'n', 'maxAgeMs' => 600000, 'now' => INF];
        $this->assertTrue(AttestEat::verifyFreshness(['eat_nonce' => 'n', 'iat' => $nowS], $opts)->get('ok'));
        $this->assertTrue(AttestEat::verifyFreshness(['eat_nonce' => 'n', 'iat' => (float)$nowS], ['now' => NAN] + $opts)->get('ok'));
        $eat = ['eat_nonce' => 'n', 'iat' => 1.49999e9]; // exactly 1e7 ms before now
        $r = AttestEat::verifyFreshness($eat, ['now' => 1.5e12, 'maxAgeMs' => 9999999.5] + $opts);
        $this->assertFalse($r->get('ok'));
        $this->assertSame("EAT is stale (iat older than maxAgeMs) \u{2014} expired/replayed attestation", $r->get('reason'));
        $this->assertTrue(AttestEat::verifyFreshness($eat, ['now' => 1.5e12, 'maxAgeMs' => 1.0e7] + $opts)->get('ok'));
    }

    /** A null cnf is "no binding" (a refusal), never a TypeError. */
    public function testChannelBindingWithANullCnfFailsClosed(): void
    {
        $r = AttestEat::verifyChannelBinding(Obj::of(['cnf' => null]), Obj::of(['channelId' => 'chan']));
        $this->assertFalse($r->get('ok'));
        $this->assertSame("EAT carries no channel/key binding (cnf) \u{2014} evidence is not bound to a live channel (RA-TLS)", $r->get('reason'));
        $r = AttestEat::verifyChannelBinding(['cnf' => null], ['channelId' => 'chan']);
        $this->assertFalse($r->get('ok'));
        $this->assertSame("EAT carries no channel/key binding (cnf) \u{2014} evidence is not bound to a live channel (RA-TLS)", $r->get('reason'));
    }

    // ---- TCB packing ---------------------------------------------------------------------------------------------------------------

    /** A numeric TCB is floored to an integer (zero allowed, base 10); a string must be decimal digits. */
    public function testPackTcbNumbersAndStrings(): void
    {
        $this->assertSame('0', self::tcb(0));
        $this->assertSame('1', self::tcb(1.5));
        $this->assertSame('1', self::tcb(1.9));
        $this->assertSame('10', self::tcb(10));
        $this->assertSame('255', self::tcb(new Num('255')));
        $this->assertNull(self::tcb(-1));
        $this->assertNull(self::tcb(-0.5));
        $this->assertSame('10', self::tcb('10'));
        $this->assertSame('7', self::tcb(" 7 "));
        $this->assertSame('0', self::tcb('0'));
        foreach (['', '1.5', '-5', '0x10', '1e3', 'abc'] as $bad) {
            $this->assertNull(self::tcb($bad), $bad);
        }
        foreach ([true, false, null, [], Jsx::$U] as $bad) {
            $this->assertNull(self::tcb($bad));
        }
    }

    /** An object TCB packs bootloader | tee << 8 | snp << 48 | microcode << 56, each component an exact byte. */
    public function testPackTcbObject(): void
    {
        $this->assertSame('289074801081844225', self::tcb(Obj::of(['bootloader' => 1, 'tee' => 2, 'snp' => 3, 'microcode' => 4])));
        $this->assertSame('1', self::tcb(Obj::of(['bootloader' => 1]))); // absent components are zero
        $this->assertSame('0', self::tcb(new Obj()));
        $this->assertSame('0', self::tcb(Obj::of(['bootloader' => 0, 'tee' => 0, 'snp' => 0, 'microcode' => 0])));
        $this->assertSame('255', self::tcb(Obj::of(['bootloader' => 255])));
        $this->assertSame('65280', self::tcb(Obj::of(['tee' => 255])));
        $this->assertSame('3', self::tcb(Obj::of(['bootloader' => new Num('3')])));
        $this->assertSame((string)(1 << 48), self::tcb(Obj::of(['snp' => 1])));
        $this->assertSame((string)(1 << 56), self::tcb(Obj::of(['microcode' => 1])));
        foreach ([256, 1.5, -1, -0.0, '3', true, null] as $bad) {
            $this->assertNull(self::tcb(Obj::of(['bootloader' => $bad])), var_export($bad, true));
        }
        $this->assertNull(self::tcb(Obj::of(['microcode' => 256])));
    }

    // ---- lowercase / find ------------------------------------------------------------------------------------------------------------

    /** lc lowercases with Unicode rules and refuses a non-string like JavaScript; find handles lists, absent lists and non-lists. */
    public function testLcAndFind(): void
    {
        $this->assertSame("\u{e0}b", self::m('lc', "\u{c0}B"));
        $e = self::thrown(fn() => self::m('lc', 5));
        $this->assertInstanceOf(\TypeError::class, $e);
        $this->assertSame('s.toLowerCase is not a function', $e->getMessage());

        $pred = static fn($x): bool => $x === 2;
        $this->assertSame(2, self::m('find', [1, 2, 3], $pred));
        $this->assertInstanceOf(Undef::class, self::m('find', [1, 3], $pred));
        $this->assertInstanceOf(Undef::class, self::m('find', null, $pred));
        $this->assertInstanceOf(Undef::class, self::m('find', Jsx::$U, $pred));
        foreach ([5, ['x' => 1], 'abc', Obj::of(['a' => 1])] as $bad) {
            $e = self::thrown(fn() => self::m('find', $bad, $pred));
            $this->assertInstanceOf(\TypeError::class, $e);
            $this->assertSame('eat.measurements?.find is not a function', $e->getMessage());
        }
    }

    // ---- certificate glue ------------------------------------------------------------------------------------------------------------

    /** certToDer unwraps Bytes, passes DER through, and refuses a non-string with the exact text. */
    public function testCertToDer(): void
    {
        $this->assertSame("\x30\x03abc", self::m('certToDer', new Bytes("\x30\x03abc")));
        $this->assertSame("\x30\x03abc", self::m('certToDer', "\x30\x03abc"));
        $e = self::thrown(fn() => self::m('certToDer', 5));
        $this->assertInstanceOf(\TypeError::class, $e);
        $this->assertSame('a certificate is DER bytes or a PEM string', $e->getMessage());
        $e = self::thrown(fn() => self::m('certToDer', null));
        $this->assertSame('a certificate is DER bytes or a PEM string', $e->getMessage());
        $e = self::thrown(fn() => self::m('certToDer', new Bytes('')));
        $this->assertInstanceOf(\InvalidArgumentException::class, $e);
    }

    /** derToPem wraps the base64 at 64 columns with no trailing blank line. */
    public function testDerToPemLayout(): void
    {
        $b64 = base64_encode(str_repeat("\x01", 100));
        $this->assertSame(136, strlen($b64));
        $this->assertSame("-----BEGIN CERTIFICATE-----\n" . substr($b64, 0, 64) . "\n" . substr($b64, 64, 64) . "\n" . substr($b64, 128) . "\n-----END CERTIFICATE-----\n",
            self::m('derToPem', str_repeat("\x01", 100)));
        $b48 = base64_encode(str_repeat("\x02", 48));
        $this->assertSame("-----BEGIN CERTIFICATE-----\n$b48\n-----END CERTIFICATE-----\n", self::m('derToPem', str_repeat("\x02", 48)));
    }

    /** A Bytes report is unwrapped before the type check; a non-bytes report has the reference's refusal; a throw is labelled fail-closed. */
    public function testVerifyAmdAttestationInputHandling(): void
    {
        $label = AttestEat::AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
        $opts = Obj::of(['family' => 'milan', 'vcek' => 'v', 'ask' => 'a', 'ark' => 'k']);
        $r = AttestEat::verifyAmdAttestation(new Bytes('abc'), $opts);
        $this->assertFalse($r->get('ok'));
        $this->assertSame('report parse failed: parseSevSnpReport: report too short (3 < 816)', $r->get('reason'));
        $this->assertSame($label, $r->get('hardwareRoot'));
        $r = AttestEat::verifyAmdAttestation('abc', $opts);
        $this->assertSame('report parse failed: parseSevSnpReport: report too short (3 < 816)', $r->get('reason'));
        $r = AttestEat::verifyAmdAttestation(5, $opts);
        $this->assertSame('report parse failed: parseSevSnpReport: expected Uint8Array', $r->get('reason'));
        $this->assertSame($label, $r->get('hardwareRoot'));

        $r = AttestEat::verifyAmdAttestation('abc', null);
        $this->assertFalse($r->get('ok'));
        $this->assertSame("AMD attestation verification error (fail closed): Cannot read properties of null (reading 'family')", $r->get('reason'));
        $this->assertSame($label, $r->get('hardwareRoot'));
    }

    // ---- nonce ---------------------------------------------------------------------------------------------------------------------------

    /** issueNonce is public: `<b64u random>.<time in base 36>`, 32 random bytes by default, never fewer than 16, time = now when given. */
    public function testIssueNonceShape(): void
    {
        $n = AttestEat::issueNonce(1000000);
        $this->assertSame(['value', 'issuedAt'], array_keys($n));
        $this->assertSame(1000000, $n['issuedAt']);
        $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{43}\.lfls\z/', $n['value']);
        foreach ([[16, 22], [15, 22], [0, 22], [17, 23], [32, 43], [64, 86]] as [$bytes, $chars]) {
            $v = AttestEat::issueNonce(1000000, $bytes)['value'];
            $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{' . $chars . '}\.lfls\z/', $v, "bytes $bytes");
        }
        $this->assertNotSame(AttestEat::issueNonce(1)['value'], AttestEat::issueNonce(1)['value']);
        $this->assertStringEndsWith('.1', AttestEat::issueNonce(1)['value']);
        $this->assertStringEndsWith('.z', AttestEat::issueNonce(35)['value']);
        $this->assertStringEndsWith('.10', AttestEat::issueNonce(36)['value']);
    }

    /** Without an explicit time the nonce is stamped with the wall clock in whole milliseconds (an int). */
    public function testIssueNonceDefaultsToTheWallClock(): void
    {
        $lo = (int)(microtime(true) * 1000);
        $n = AttestEat::issueNonce();
        $hi = (int)(microtime(true) * 1000);
        $this->assertIsInt($n['issuedAt']);
        $this->assertGreaterThanOrEqual($lo, $n['issuedAt']);
        $this->assertLessThanOrEqual($hi, $n['issuedAt']);
        $this->assertStringEndsWith('.' . base_convert((string)$n['issuedAt'], 10, 36), $n['value']);
        $this->assertSame(1234, AttestEat::issueNonce(1234)['issuedAt']);
    }
}
