<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Webauthn;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The WebAuthn step-up co-sign against the TS reference: test-data/ref-webauthn.json.gz (COSE_Key reader, authenticatorData
 * header, step-up / approval challenges, SPC payment check, verifyAssertion). {"$bytes"} anywhere becomes a Bytes value; a
 * JSON string where the reference only takes a Uint8Array is "not bytes" (a PHP string would be read as the bytes).
 */
final class RefWebauthnDifferentialTest extends TestCase
{
    private const FILE = 'ref-webauthn.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function rev(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return new Bytes((string)Pca::unb64u($v->get('$bytes')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::rev($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::rev(...), $v) : $v;
    }

    /** A JSON string in a Uint8Array-only position is not bytes. */
    private static function onlyBytes(mixed $v): mixed
    {
        $v = self::rev($v);
        return is_string($v) ? new \stdClass() : $v;
    }

    private static function out(mixed $v): mixed
    {
        if ($v instanceof Bytes) {
            return Base::outBytes($v->raw);
        }
        if (is_array($v)) {
            return array_map(self::out(...), $v);
        }
        return $v;
    }

    private static function verify(mixed $a, mixed $e): array
    {
        $as = $a;
        if ($a instanceof Obj) {
            $as = new Obj();
            foreach ($a->keys() as $k) {
                $as->set($k, in_array($k, ['authenticatorData', 'clientDataJSON', 'signature'], true) ? self::onlyBytes($a->get($k)) : self::rev($a->get($k)));
            }
        }
        $calls = [];
        $ex = self::rev($e);
        if ($ex instanceof Obj && $ex->get('hook') === true) {
            $o = new Obj();
            foreach ($ex->keys() as $k) {
                if ($k !== 'hook') {
                    $o->set($k, $ex->get($k));
                }
            }
            $o->set('onSignCountRegression', static function (array $i) use (&$calls): void {
                $calls[] = $i;
            });
            $ex = $o;
        }
        $r = Webauthn::verifyAssertion($as, $ex);
        if (isset($r['reason'])) {
            $r['reason'] = (string)preg_replace('/\A(public key could not be resolved|verification error \(fail closed\)):.*\z/s', '$1', $r['reason']);
        }
        return ['result' => $r, 'hook' => $calls];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn() => ['MAX_AUTHENTICATOR_DATA_BYTES' => Webauthn::MAX_AUTHENTICATOR_DATA_BYTES, 'MAX_CLIENT_DATA_BYTES' => Webauthn::MAX_CLIENT_DATA_BYTES,
                'MAX_SIGNATURE_BYTES' => Webauthn::MAX_SIGNATURE_BYTES],
            'coseKeyToJwk' => fn(array $a) => Webauthn::coseKeyToJwk(self::onlyBytes($a[0] ?? null)),
            'parseAuthenticatorData' => fn(array $a) => self::out(Webauthn::parseAuthenticatorData(self::onlyBytes($a[0] ?? null))),
            'buildStepUpChallenge' => fn(array $a) => Base::outBytes(Webauthn::buildStepUpChallenge(self::rev($a[0] ?? null))),
            'stepUpChallengeB64u' => fn(array $a) => Webauthn::stepUpChallengeB64u(self::rev($a[0] ?? null)),
            'buildApprovalChallenge' => fn(array $a) => Base::outBytes(Webauthn::buildApprovalChallenge(self::rev($a[0] ?? null), $a[1] ?? null)),
            'approvalChallengeForActn' => fn(array $a) => Webauthn::approvalChallengeForActn(self::rev($a[0] ?? null), $a[1] ?? null),
            'spcPaymentError' => fn(array $a) => Webauthn::spcPaymentError($a[0] ?? null, $a[1] ?? null, $a[2] ?? null),
            'verifyAssertion' => fn(array $a) => self::verify($a[0] ?? null, $a[1] ?? null),
        ]);
    }
}
