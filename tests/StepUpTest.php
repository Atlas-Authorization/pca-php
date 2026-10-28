<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemorySecretStore;
use Atlas\Pca\Pca;
use Atlas\Pca\PendingStepUp;
use Atlas\Pca\PrincipalDeviceKey;
use Atlas\Pca\StepUpClient;
use Atlas\Pca\StepUpException;
use PHPUnit\Framework\TestCase;

/** The principal device key and the step-up client (list, approve, deny) against a recording fake transport; no network. */
final class StepUpTest extends TestCase
{
    private const NOW = 1_800_000_000_000;

    private function key(): array
    {
        $k = new PrincipalDeviceKey(new MemorySecretStore());
        return [$k, $k->generate()];
    }

    private static function verifies(string $pub, string $msg, string $sig): bool
    {
        $p = Pca::unb64u($pub, 32);
        $s = Pca::unb64u($sig, 64);
        return $p !== null && $s !== null && sodium_crypto_sign_verify_detached($s, $msg, $p);
    }

    private function client(callable $http, ?PrincipalDeviceKey $key = null): StepUpClient
    {
        return new StepUpClient('https://dash.example', 'https://inst.example', 'acc', 'ins', $key ?? $this->key()[0], fn () => 'dsk_x', $http, fn () => self::NOW);
    }

    public function testDeviceKeyGenerateExportImportSign(): void
    {
        $k = new PrincipalDeviceKey(new MemorySecretStore());
        $this->assertFalse($k->exists());
        $pub = $k->generate();
        $this->assertTrue($k->exists());
        $k2 = new PrincipalDeviceKey(new MemorySecretStore());
        $this->assertSame($pub, $k2->importSecret($k->exportSecret()));
        $this->assertTrue(self::verifies($pub, 'hello', $k2->sign('hello')));
        try {
            $k2->importSecret('AAAA');
            $this->fail('short secret accepted');
        } catch (StepUpException $e) {
            $this->assertSame(StepUpException::INVALID_SECRET, $e->kind);
        }
        try {
            (new PrincipalDeviceKey(new MemorySecretStore()))->sign('x');
            $this->fail('signed without a key');
        } catch (StepUpException $e) {
            $this->assertSame(StepUpException::NO_DEVICE_KEY, $e->kind);
        }
        $k->delete();
        $this->assertFalse($k->exists());
    }

    /** RFC 8032 test vector 1 (empty message): the signature matches the Ed25519 the server verifies with. */
    public function testRfc8032Vector1(): void
    {
        $k = new PrincipalDeviceKey(new MemorySecretStore());
        $pub = $k->importSecret(Pca::b64u(hex2bin('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')));
        $this->assertSame('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', bin2hex(Pca::unb64u($pub, 32)));
        $this->assertSame('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
            bin2hex(Pca::unb64u($k->sign(''), 64)));
    }

    public function testListApproveDeny(): void
    {
        [$key, $pub] = $this->key();
        $msg = "\x01\x02\x03\xfa\xfb";
        $future = gmdate('Y-m-d\TH:i:s', intdiv(self::NOW, 1000) + 600) . '.000Z';
        $calls = [];
        $http = function (string $method, string $url, array $headers, ?string $body) use (&$calls, $msg, $future): array {
            $calls[] = [$method, $url, $headers, $body];
            if (str_contains($url, '/cosign')) {
                return [200, '{"status":"approved","allow":true}'];
            }
            if (str_ends_with($url, '/deny')) {
                return [200, '{}'];
            }
            return [200, json_encode(['stepups' => [
                ['id' => 'su_1', 'grant_ref' => 'g1', 'action' => ['verb' => 'pay', 'resource' => 'order/1'], 'required_t' => 3,
                    'threshold_message' => Pca::b64u($msg), 'created_at' => 'x', 'expires_at' => $future, 'status' => 'pending'],
                ['id' => 'old', 'grant_ref' => 'g', 'action' => ['verb' => 'v', 'resource' => 'r'], 'required_t' => 3,
                    'threshold_message' => 'AA', 'created_at' => 'x', 'expires_at' => '2001-01-01T00:00:00.000Z', 'status' => 'pending'],
            ]])];
        };
        $c = $this->client($http, $key);
        $items = $c->pending();
        $this->assertCount(1, $items);
        $this->assertSame(['su_1', 'pay', 'pay on order/1'], [$items[0]->id, $items[0]->actionVerb, $items[0]->summary()]);
        $this->assertSame(['GET', 'https://dash.example/v1/dashboard/accounts/acc/instances/ins/pca/stepups?status=pending'], [$calls[0][0], $calls[0][1]]);
        $this->assertSame('Bearer dsk_x', $calls[0][2]['Authorization']);

        $res = $c->approve($items[0]);
        $this->assertSame(['approved', true, 200], [$res->status, $res->anchored, $res->httpStatus]);
        $this->assertSame('https://inst.example/v1/pca/stepups/su_1/cosign', $calls[1][1]);
        $this->assertArrayNotHasKey('Authorization', $calls[1][2]);
        $body = json_decode($calls[1][3], true);
        $this->assertSame(['principal', $pub], [$body['role'], $body['publicKey']]);
        $this->assertTrue(self::verifies($pub, $msg, $body['sig']), 'the cosign body carries the device signature over the exact message');

        $c->deny($items[0], 'no');
        $this->assertSame('https://dash.example/v1/dashboard/accounts/acc/instances/ins/pca/stepups/su_1/deny', $calls[2][1]);
        $this->assertSame('{"reason":"no"}', $calls[2][3]);
    }

    public function testPrincipalMismatchSurfacesGuidance(): void
    {
        $c = $this->client(fn () => [403, '{"errors":[{"code":"forbidden","message":"The share is not from this grant\'s principal key."}]}']);
        try {
            $c->approve(new PendingStepUp('s', 'g', 'v', 'r', 1, 'AAEC', 1));
            $this->fail('approved');
        } catch (StepUpException $e) {
            $this->assertSame([StepUpException::PRINCIPAL_MISMATCH, 403], [$e->kind, $e->status]);
            $this->assertStringContainsString('principal key', $e->getMessage());
        }
    }

    public function testOtherErrorsFailClosed(): void
    {
        $sent = 0;
        $status = 409;
        $c = $this->client(function () use (&$sent, &$status): array {
            $sent++;
            return [$status, 'not json'];
        });
        $su = new PendingStepUp('s', 'g', 'v', 'r', 1, 'AAEC', 1);
        $expect = function (callable $f, string $kind) {
            try {
                $f();
                $this->fail("no $kind");
            } catch (StepUpException $e) {
                $this->assertSame($kind, $e->kind);
                return $e;
            }
        };
        $e = $expect(fn () => $c->approve($su), StepUpException::API);
        $this->assertSame('HTTP 409: The request failed.', $e->getMessage());
        $sent = 0;
        // a threshold message that is not canonical base64url is never signed; an id that could rewrite the path is refused first
        $expect(fn () => $c->approve(new PendingStepUp('s', 'g', 'v', 'r', 1, 'a', 1)), StepUpException::INVALID_THRESHOLD_MESSAGE);
        $expect(fn () => $c->approve(new PendingStepUp('../x', 'g', 'v', 'r', 1, 'AAEC', 1)), StepUpException::INVALID_STEP_UP);
        $expect(fn () => $c->deny(new PendingStepUp('a/b', 'g', 'v', 'r', 1, 'AAEC', 1)), StepUpException::INVALID_STEP_UP);
        $this->assertSame(0, $sent, 'nothing is sent for an invalid id or message');
        // an unreadable list is a transport error, never an empty list
        $status = 200;
        $expect(fn () => $c->pending(), StepUpException::TRANSPORT);
        // no key stored: nothing is sent
        $sent = 0;
        $empty = $this->client(function () use (&$sent): array {
            $sent++;
            return [200, '{}'];
        }, new PrincipalDeviceKey(new MemorySecretStore()));
        $expect(fn () => $empty->approve($su), StepUpException::NO_DEVICE_KEY);
        $this->assertSame(0, $sent);
        // a failing transport is a transport error
        $down = $this->client(function (): array {
            throw new \RuntimeException('connection refused');
        });
        $expect(fn () => $down->approve($su), StepUpException::TRANSPORT);
        $this->expectException(\InvalidArgumentException::class);
        new StepUpClient('ftp://x', 'https://i', 'a', 'b', $this->key()[0], fn () => 't');
    }
}
