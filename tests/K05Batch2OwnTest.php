<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\JsJson;
use PHPUnit\Framework\TestCase;

final class K05Batch2OwnTest extends TestCase
{
    public function testAnEcdsaVerifyLeavesNoOpenSslErrorBehind(): void
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $k = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        unlink($cnf);
        $pem = openssl_pkey_get_details($k)['key'];
        $pub = Common::loadPublicKey(base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s/', '', $pem)));
        while (openssl_error_string() !== false) {
        }
        foreach (['not a DER signature', '', "\x30", "\x30\x05\x02\x01", "\x30\x06\x02\x01\x01\x02\x01\x01\xff\xff", "\x30\x80\x00\x00", str_repeat("\xff", 80)] as $sig) {
            $this->assertFalse(Common::ecdsaVerifyDer($pub, $sig, 'msg', 'sha256'));
            $this->assertFalse(openssl_error_string(), 'the error a failed verify queued is drained: ' . bin2hex($sig));
        }
    }

    public function testASurrogatePairEscapeIsOneAstralCharacter(): void
    {
        $this->assertSame("\u{1F600}", JsJson::parse('"\\ud83d\\ude00"'));
        $this->assertSame("\u{10000}", JsJson::parse('"\\ud800\\udc00"'));
        $this->assertSame("\u{10FFFF}", JsJson::parse('"\\udbff\\udfff"'));
    }
}
