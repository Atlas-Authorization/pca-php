<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostHttp.php';

use Atlas\Pca\CoordinatorError;
use Atlas\Pca\Frost;
use Atlas\Pca\FrostNet;
use Atlas\Pca\GuardianSignerService;
use Atlas\Pca\HttpSignerTransport;
use Atlas\Pca\NetworkCoordinator;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SignerHttpServer;
use PHPUnit\Framework\TestCase;

/**
 * A 2-of-3 network signing session over the loopback HTTP transport, each signer in its own OS process (`bin/pca-frost-signer`): the aggregate is an ordinary
 * Ed25519 signature under the group key, a token for another action is refused by every signer, and the request handler answers the malformed cases.
 */
final class FrostNetHttpTest extends TestCase
{
    /** @var list<resource> */
    private array $procs = [];
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->procs as $p) {
            @proc_terminate($p, 9);   // SIGKILL: a signer that ignores SIGTERM would make proc_close wait forever
            @proc_close($p);
        }
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    /** The URL of a signer process started from this config. */
    private function spawn(array $cfg): string
    {
        $path = tempnam(sys_get_temp_dir(), 'frost-signer');
        $this->files[] = $path;
        file_put_contents($path, json_encode($cfg));
        // stdout and stderr go to files: a Windows pipe cannot be read without blocking
        $out = tempnam(sys_get_temp_dir(), 'frost-out');
        $err = tempnam(sys_get_temp_dir(), 'frost-err');
        $this->files[] = $out;
        $this->files[] = $err;
        $proc = proc_open([PHP_BINARY, __DIR__ . '/../bin/pca-frost-signer', $path], [1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
        $this->assertIsResource($proc);
        $this->procs[] = $proc;
        $line = '';
        $until = microtime(true) + 20;
        while (microtime(true) < $until && !str_contains($line, "\n")) {
            $line = (string)@file_get_contents($out);
            usleep(20000);
        }
        $this->assertStringStartsWith('FROST_SIGNER_READY ', $line, 'the signer process did not come up: ' . (string)@file_get_contents($err));
        $ready = json_decode(substr(trim($line), strlen('FROST_SIGNER_READY ')), true);
        return $ready['url'];
    }

    public function testASessionOverHttpSignsAndAnUnauthorizedOneRefuses(): void
    {
        $kg = Frost::trustedDealerKeygen(2, 3);
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $policyPk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $message = 'transfer 10 USD to alice';
        $transports = [];
        $shares = [];
        foreach ($kg['participantShares'] as $p) {
            $url = $this->spawn(['identifier' => $p['identifier'], 'share' => Pca::b64u($p['share']), 'groupPublicKey' => Pca::b64u($kg['groupPublicKey']),
                'threshold' => 2, 'policyAuthorityPublicKey' => Pca::b64u($policyPk)]);
            $transports[] = new HttpSignerTransport($url, $p['identifier'], 5000);
            $shares[] = ['identifier' => $p['identifier'], 'publicKey' => $p['publicKey']];
        }
        $coordinator = new NetworkCoordinator(['groupPublicKey' => $kg['groupPublicKey'], 'threshold' => 2, 'signers' => $transports, 'verificationShares' => $shares]);
        $allow = FrostNet::issueAllowToken($seed, Obj::of(['message' => $message, 'groupPublicKey' => $kg['groupPublicKey']]));
        $res = $coordinator->sign($message, $allow);
        $this->assertTrue(sodium_crypto_sign_verify_detached($res['signature'], $message, $kg['groupPublicKey']));
        $this->assertCount(2, $res['signers']);
        // a token for another action is refused by every signer: the coordinator cannot sign without the policy authority
        $other = FrostNet::issueAllowToken($seed, Obj::of(['message' => 'something else', 'groupPublicKey' => $kg['groupPublicKey']]));
        try {
            $coordinator->sign($message, $other);
            $this->fail('a token for another message must not sign');
        } catch (CoordinatorError $e) {
            $this->assertStringContainsString('round 2', $e->getMessage());
        }
    }

    public function testAnUnreachableSignerIsARefusalNotACrash(): void
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0');
        $name = (string)stream_socket_get_name($sock, false);
        fclose($sock); // nothing listens on this port any more
        $t = new HttpSignerTransport('http://127.0.0.1:' . substr($name, (int)strrpos($name, ':') + 1), 1, 500);
        $this->expectException(\RuntimeException::class);
        $t->round1(Obj::of(['typ' => 'pca.frost.round1.v1', 'session_id' => 's']));
    }

    public function testTheHandlerAnswersMalformedRequests(): void
    {
        $kg = Frost::trustedDealerKeygen(1, 1);
        $svc = new GuardianSignerService(['identifier' => 1, 'share' => $kg['participantShares'][0]['share'], 'groupPublicKey' => $kg['groupPublicKey'],
            'threshold' => 1, 'policyAuthorityPublicKey' => str_repeat("\x07", 32)]);
        [$s, $b] = SignerHttpServer::respond($svc, 'GET', '/round1', '');
        $this->assertSame([405, 'method not allowed'], [$s, $b->get('reason')]);
        [$s, $b] = SignerHttpServer::respond($svc, 'POST', '/other', '');
        $this->assertSame([404, 'not found'], [$s, $b->get('reason')]);
        [$s, $b] = SignerHttpServer::respond($svc, 'POST', '/round1', '{nope');
        $this->assertSame(400, $s);
        $this->assertTrue($b->get('refused'));
        [$s, $b] = SignerHttpServer::respond($svc, 'POST', '/round1', str_repeat(' ', SignerHttpServer::BODY_LIMIT + 1));
        $this->assertSame([400, 'request body too large'], [$s, $b->get('reason')]);
        // an empty body is the empty request: the service refuses it as a value
        [$s, $b] = SignerHttpServer::respond($svc, 'POST', '/round2', '');
        $this->assertSame(200, $s);
        $this->assertFalse($b->get('ok'));
    }
}
