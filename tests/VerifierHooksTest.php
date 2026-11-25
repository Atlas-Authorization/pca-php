<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PcaMiddleware.php';
require_once __DIR__ . '/../src/Fetch.php';

use Atlas\Pca\Fetch;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Sign;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The attestation and zk verifier hooks of the core verifier and of the signature-only guards: a carried zk_compliance proof is
 * verified by the zk hook and refused when no hook enforced it (the fail-closed default); an attestation hook passes, fails or is
 * reported as not enforced. The authorize path is covered in BaseKillAuthorize2Test.
 */
final class VerifierHooksTest extends TestCase
{
    private const NOW = 1_800_000_000_000;
    private const ZK = 'zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof';
    private const PLAN = [['id' => 'a', 'verb' => 'v', 'resource' => 'r']];

    /** @return array{0: Obj, 1: Obj} grant, signed PCActn */
    private static function signed(array $extra = []): array
    {
        $k = KeyPair::generate();
        $grant = Sign::mintRoot(KeyPair::generate(), $k->public, []);
        return [$grant, Sign::buildPcactn($grant, [$grant], self::PLAN, 'a', 1, $k, 'aud', null, self::NOW, null, 1000, $extra)];
    }

    private static function core(array $signed, ?array $hooks): array
    {
        return Pca::verifyPcactnCore($signed[1], $signed[0], self::NOW, 'aud', insecureSkipPlanRootCheck: true, hooks: $hooks);
    }

    public function testACarriedZkProofPassesOnlyWhenAHookVerifiedIt(): void
    {
        $signed = self::signed(['zk_compliance' => ['proof' => 'x']]);
        // the fail-closed default: no hooks, an empty hook set, a hook that is not callable
        foreach ([null, [], ['zk' => 'not a function'], ['attestation' => static fn(): array => ['enforced' => true, 'ok' => true]]] as $hooks) {
            $r = self::core($signed, $hooks);
            $this->assertSame([false, false, self::ZK], [$r['allow'], $r['checks']['zk_compliance'], $r['reason']]);
        }
        // a hook that does not enforce, or answers with something else, verified nothing
        foreach ([['enforced' => false], ['enforced' => false, 'ok' => true], ['ok' => true], ['enforced' => 1, 'ok' => true], null, true] as $answer) {
            $r = self::core($signed, ['zk' => static fn(): mixed => $answer]);
            $this->assertSame([false, false, self::ZK], [$r['allow'], $r['checks']['zk_compliance'], $r['reason']]);
        }
        // enforced and accepted: the hook saw the presented PCActn, the grant and the verifier's clock
        $seen = null;
        $r = self::core($signed, ['zk' => static function (array $ctx) use (&$seen): array {
            $seen = $ctx;
            return ['enforced' => true, 'ok' => true];
        }]);
        $this->assertSame([true, true, ''], [$r['allow'], $r['checks']['zk_compliance'], $r['reason']]);
        $this->assertSame([$signed[1], $signed[0], self::NOW], [$seen['pcactn'], $seen['grant'], $seen['nowEpoch']]);
        // enforced and refused: the hook's reason, or `rejected`; `ok` must be exactly true
        $r = self::core($signed, ['zk' => static fn(): array => ['enforced' => true, 'ok' => false, 'reason' => 'bad proof']]);
        $this->assertSame([false, false, 'zk_compliance: bad proof', ['zk_compliance: bad proof']], [$r['allow'], $r['checks']['zk_compliance'], $r['reason'], $r['reasons']]);
        $r = self::core($signed, ['zk' => static fn(): array => ['enforced' => true, 'ok' => 1]]);
        $this->assertSame([false, false, 'zk_compliance: rejected'], [$r['allow'], $r['checks']['zk_compliance'], $r['reason']]);
        // a hook that throws is a refusal, never an exception or a pass
        $r = self::core($signed, ['zk' => static fn(): array => throw new \RuntimeException('boom')]);
        $this->assertFalse($r['allow']);
    }

    public function testTheZkHookIsNotAskedWithoutAProof(): void
    {
        $calls = 0;
        $r = self::core(self::signed(), ['zk' => static function () use (&$calls): array {
            $calls++;
            return ['enforced' => true, 'ok' => false];
        }]);
        $this->assertSame([true, 0], [$r['allow'], $calls]);
        $this->assertArrayNotHasKey('zk_compliance', $r['checks']);
    }

    public function testTheAttestationHookIsTriState(): void
    {
        $signed = self::signed();
        $r = self::core($signed, null);
        $this->assertArrayNotHasKey('attestation', $r['checks']);
        $this->assertNotContains('attestation', $r['not_enforced'] ?? []);
        $r = self::core($signed, ['attestation' => static fn(array $ctx): array => ['enforced' => true, 'ok' => $ctx['pcactn'] === $signed[1]]]);
        $this->assertSame([true, true], [$r['allow'], $r['checks']['attestation']]);
        $r = self::core($signed, ['attestation' => static fn(): array => ['enforced' => true, 'ok' => false, 'reason' => 'unbound quote']]);
        $this->assertSame([false, false, 'attestation: unbound quote'], [$r['allow'], $r['checks']['attestation'], $r['reason']]);
        $r = self::core($signed, ['attestation' => static fn(): array => ['enforced' => false]]);
        $this->assertTrue($r['allow']);
        $this->assertArrayNotHasKey('attestation', $r['checks']);
        $this->assertContains('attestation', $r['not_enforced']);
    }

    public function testVerifyJsonTakesTheHooks(): void
    {
        [$g, $p] = self::signed(['zk_compliance' => ['proof' => 'x']]);
        $text = Json::canonicalizeStrict($p);
        $this->assertSame(self::ZK, Pca::verifyJson($text, $g, self::NOW, 'aud', insecureSkipPlanRootCheck: true)['reason']);
        $r = Pca::verifyJson($text, $g, self::NOW, 'aud', insecureSkipPlanRootCheck: true, hooks: ['zk' => static fn(): array => ['enforced' => true, 'ok' => true]]);
        $this->assertSame([true, true], [$r['allow'], $r['checks']['zk_compliance']]);
    }

    /** @return array{0:int,1:int,2:mixed} status, handler calls, body */
    private static function middleware(array $signed, mixed ...$o): array
    {
        [$grant, $p] = $signed;
        $f = new HttpFactory();
        $h = new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(200);
            }
        };
        $mw = new PcaMiddleware('aud', static fn() => $grant, static fn() => self::NOW, $f, $f, ...$o);
        $res = $mw->process(new ServerRequest('POST', '/', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]), $h);
        return [$res->getStatusCode(), $h->calls, json_decode((string)$res->getBody(), true)];
    }

    public function testTheSignatureOnlyMiddlewareForwardsTheHooks(): void
    {
        $signed = self::signed(['zk_compliance' => ['proof' => 'x']]);
        [$st, $calls, $b] = self::middleware($signed, signatureOnly: true);
        $this->assertSame([403, 0, self::ZK], [$st, $calls, $b['error_description']]);
        $ok = ['zk' => static fn(): array => ['enforced' => true, 'ok' => true]];
        $this->assertSame([200, 1], array_slice(self::middleware($signed, signatureOnly: true, hooks: $ok), 0, 2));
        [$st, $calls, $b] = self::middleware($signed, signatureOnly: true, hooks: ['zk' => static fn(): array => ['enforced' => true, 'ok' => false, 'reason' => 'no']]);
        $this->assertSame([403, 0, 'zk_compliance: no'], [$st, $calls, $b['error_description']]);
        [$st, $calls, $b] = self::middleware(self::signed(), signatureOnly: true, hooks: ['attestation' => static fn(): array => ['enforced' => true, 'ok' => false, 'reason' => 'no quote']]);
        $this->assertSame([403, 0, 'attestation: no quote'], [$st, $calls, $b['error_description']]);
        // the authorize path takes its hooks in the authorize options
        $this->expectException(\InvalidArgumentException::class);
        self::middleware($signed, hooks: $ok);
    }

    public function testTheSignatureOnlyFetchGuardForwardsTheHooks(): void
    {
        [$grant, $p] = self::signed(['zk_compliance' => ['proof' => 'x']]);
        $headers = ['PCA-Action' => Pca::b64u(Json::canonicalizeStrict($p))];
        $o = ['audience' => 'aud', 'resolveGrant' => static fn() => $grant, 'now' => self::NOW, 'signatureOnly' => true];
        $r = Fetch::createPcaFetchGuard($o)($headers);
        $this->assertSame([false, 403], [$r['ok'], $r['status']]);
        $r = Fetch::createPcaFetchGuard($o + ['hooks' => ['zk' => static fn(): array => ['enforced' => true, 'ok' => true]]])($headers);
        $this->assertSame([true, true], [$r['ok'], $r['verdict']['checks']['zk_compliance']]);
        $this->expectException(\InvalidArgumentException::class);
        Fetch::createPcaFetchGuard(['audience' => 'aud', 'operation' => static fn() => null, 'hooks' => []]);
    }
}
