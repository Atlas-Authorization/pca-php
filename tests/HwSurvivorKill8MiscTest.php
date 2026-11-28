<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Attest\Maa;
use Atlas\Pca\Attest\PubKey;
use PHPUnit\Framework\TestCase;

/** Group 8 (Misc lane) survivor kills: JsJson error positions, Ed25519 certificate signatures, MAA JWKS fetch guard. */
final class HwSurvivorKill8MiscTest extends TestCase
{
    private const ED_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    private static function msg(string $text): string
    {
        try {
            JsJson::parse($text);
        } catch (JsError $e) {
            return $e->getMessage();
        }
        self::fail('parsed ' . json_encode($text));
    }

    /** The position carried by a refusal selects V8's wording, so each refusal must name the position it was detected at. */
    public function testUnterminatedStringNamesItsOpeningQuote(): void
    {
        $this->assertSame('Unexpected string in JSON at position 0', self::msg('"abc'));
    }

    public function testBadUnicodeEscapeNamesTheBackslashUPosition(): void
    {
        $text = '"\\u12"';
        $this->assertSame("Unexpected token 'u', \"" . $text . "\" is not valid JSON", self::msg($text));
    }

    public function testUnknownEscapeNamesTheBackslashPosition(): void
    {
        $text = '"\\x"';
        $this->assertSame("Unexpected token '\\', \"" . $text . "\" is not valid JSON", self::msg($text));
    }

    public function testSurrogatePairCombinesToTheSupplementaryCodePoint(): void
    {
        $this->assertSame("\u{1F600}", JsJson::parse('"\\ud83d\\ude00"'));
        $this->assertSame("\u{10FFFF}", JsJson::parse('"\\udbff\\udfff"'));
    }

    private static function fakeKey(): \OpenSSLAsymmetricKey
    {
        static $key = null;
        if ($key === null) {
            $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
            file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
            $key = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
            unlink($cnf);
        }
        return $key;
    }

    private static function edKey(string $spki): PubKey
    {
        return new PubKey(self::fakeKey(), $spki, 'ed25519', null, []);
    }

    /** Only an exactly 44-byte Ed25519 SubjectPublicKeyInfo (fixed prefix + 32 key bytes) yields a raw key; the accessor is public. */
    public function testEd25519RawNeedsTheExactLengthAndPrefix(): void
    {
        $pub = str_repeat("\x07", 32);
        $this->assertSame($pub, Cert::ed25519Raw(self::edKey(self::ED_PREFIX . $pub)));
        $this->assertNull(Cert::ed25519Raw(self::edKey(str_repeat("\x00", 44)))); // right length, wrong prefix
        $this->assertNull(Cert::ed25519Raw(self::edKey(self::ED_PREFIX . $pub . 'x'))); // right prefix, 45 bytes
        $this->assertNull(Cert::ed25519Raw(self::edKey(self::ED_PREFIX . substr($pub, 1)))); // right prefix, 43 bytes
    }

    /** An Ed25519 signature verifies only with parameter-less algorithm bytes, an Ed25519 issuer key and a good 64-byte signature. */
    public function testEd25519SignatureRequiresEveryCondition(): void
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/hw8-misc', true));
        $pk = sodium_crypto_sign_publickey($kp);
        $sk = sodium_crypto_sign_secretkey($kp);
        $msg = 'tbs-bytes';
        $sig = sodium_crypto_sign_detached($msg, $sk);
        $key = self::edKey(self::ED_PREFIX . $pk);
        $plain = "\x30\x05\x06\x03\x2b\x65\x70";
        $withNull = "\x30\x07\x06\x03\x2b\x65\x70\x05\x00";

        $this->assertTrue(Cert::verifyWithAlg($plain, $msg, $sig, $key)); // control
        $this->assertFalse(Cert::verifyWithAlg($withNull, $msg, $sig, $key)); // parameters present: refused though the signature is good
        $this->assertFalse(Cert::verifyWithAlg($plain, $msg, $sig, self::edKey(str_repeat("\x00", 44)))); // not an Ed25519 issuer key
        $this->assertFalse(Cert::verifyWithAlg($plain, $msg, substr($sig, 0, 63), $key)); // short signature
        $this->assertFalse(Cert::verifyWithAlg($plain, $msg, $sig . "\x00", $key)); // long signature
        $bad = $sig;
        $bad[0] = chr(ord($bad[0]) ^ 1);
        $this->assertFalse(Cert::verifyWithAlg($plain, $msg, $bad, $key));
        $this->assertFalse(Cert::verifyWithAlg($plain, 'other', $sig, $key));
    }

    /** Fetching an MAA JWKS without a fetch implementation is a plain RuntimeException with the exact text, never a later error. */
    public function testFetchJwksWithoutAFetchImplementationThrowsRuntimeException(): void
    {
        foreach ([null, [], ['fetch' => 'no_such_function_hw8']] as $opts) {
            try {
                Maa::fetchJwks('https://maa.example', $opts);
                $this->fail('fetched');
            } catch (\Throwable $e) {
                $this->assertSame(\RuntimeException::class, $e::class);
                $this->assertSame('fetchMaaJwks: no fetch implementation available', $e->getMessage());
            }
        }
    }
}
