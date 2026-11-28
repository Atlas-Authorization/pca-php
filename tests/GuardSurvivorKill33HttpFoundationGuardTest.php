<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/HttpFoundationGuard.php';

use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\ExecutorOptions;
use Atlas\Pca\HttpFoundationGuard;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * group 33 kills for src/HttpFoundationGuard.php: factory defaults and overrides, PSR-17 discovery, the sentinel check and the
 * [denial, verdict] shape. Needs symfony/psr-http-message-bridge, which the mutation run installs (Infection reflects the Laravel
 * and Symfony integrations, so a mutation run without it cannot start).
 */
final class GuardSurvivorKill33HttpFoundationGuardTest extends TestCase
{
    private string $json;
    private mixed $grant;
    private string $grantRef;
    private string $aud;
    private int $now;

    protected function setUp(): void
    {
        if (!class_exists(Request::class) || !class_exists(PsrHttpFactory::class)) {
            $this->markTestSkipped('needs symfony/psr-http-message-bridge (installed by the mutation run)');
        }
        $doc = Json::parseLax((string)file_get_contents(__DIR__ . '/../conformance/vectors.json'));
        foreach ($doc->get('vectors') as $v) {
            if ($v->get('name') === 'valid-raw-json-format-insensitive') {
                $this->json = $v->get('pcactn_json');
                $this->grant = $v->get('grant');
                $this->aud = $v->get('context')->get('aud');
                $this->now = $v->get('context')->get('now')->int();
                $this->grantRef = Json::parseLax($this->json)->get('grant_ref');
                return;
            }
        }
        $this->fail('conformance vector not found');
    }

    protected function tearDown(): void
    {
        HttpFoundationGuard::$classExistsHook = null;
    }

    private function mw(): PcaMiddleware
    {
        $f = new HttpFactory();
        return new PcaMiddleware($this->aud, fn (string $ref): mixed => $ref === $this->grantRef ? $this->grant : null, fn (): int => $this->now, $f, $f,
            signatureOnly: true);
    }

    private function pass(): Request
    {
        return Request::create('/resource', 'POST', [], [], [], ['HTTP_PCA_ACTION' => Pca::b64u($this->json)]);
    }

    private static function recorder(): ResponseFactoryInterface
    {
        return new class implements ResponseFactoryInterface {
            /** @var list<int> */
            public array $codes = [];

            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface
            {
                $this->codes[] = $code;
                return (new HttpFactory())->createResponse($code, $reasonPhrase);
            }
        };
    }

    /** With the default factories a verified request yields [null, verdict] and a refused one [the denial, null]. */
    public function testDefaultsPassAndDeny(): void
    {
        $g = new HttpFoundationGuard($this->mw());
        $ok = $g->check($this->pass());
        $this->assertCount(2, $ok);
        $this->assertNull($ok[0]);
        $this->assertIsArray($ok[1]);
        $this->assertTrue($ok[1]['allow']);
        $no = $g->check(Request::create('/resource', 'POST'));
        $this->assertCount(2, $no);
        $this->assertInstanceOf(Response::class, $no[0]);
        $this->assertSame(401, $no[0]->getStatusCode());
        $this->assertNull($no[1]);
    }

    /** A caller's response factory makes the 204 sentinel, with or without a caller's PSR-7 converter; a converter alone works too. */
    public function testFactoryOverrides(): void
    {
        $hf = new HttpFactory();
        $rec = self::recorder();
        $this->assertNull((new HttpFoundationGuard($this->mw(), 'pca', null, null, $rec))->check($this->pass())[0]);
        $this->assertSame([204], $rec->codes);
        $rec2 = self::recorder();
        $this->assertNull((new HttpFoundationGuard($this->mw(), 'pca', new PsrHttpFactory($hf, $hf, $hf, $hf), null, $rec2))->check($this->pass())[0]);
        $this->assertSame([204], $rec2->codes);
        $this->assertNull((new HttpFoundationGuard($this->mw(), 'pca', new PsrHttpFactory($hf, $hf, $hf, $hf)))->check($this->pass())[0]);
    }

    /** A caller's converters are the ones kept, never replaced by fresh defaults. */
    public function testConverterOverridesAreKept(): void
    {
        $hf = new HttpFactory();
        $to = new PsrHttpFactory($hf, $hf, $hf, $hf);
        $from = new HttpFoundationFactory();
        $g = new HttpFoundationGuard($this->mw(), 'pca', $to, $from, $hf);
        $this->assertSame($to, (new \ReflectionProperty(HttpFoundationGuard::class, 'toPsr'))->getValue($g));
        $this->assertSame($from, (new \ReflectionProperty(HttpFoundationGuard::class, 'fromPsr'))->getValue($g));
        $this->assertSame($hf, (new \ReflectionProperty(HttpFoundationGuard::class, 'responses'))->getValue($g));
        $no = $g->check(Request::create('/resource', 'POST'));
        $this->assertSame(401, $no[0]?->getStatusCode());
    }

    /** Discovery prefers nyholm, falls back to guzzle, and refuses with a clear error when neither is installed. */
    public function testPsr17Discovery(): void
    {
        HttpFoundationGuard::$classExistsHook = static fn (string $c): bool => $c === HttpFactory::class;
        $g = new HttpFoundationGuard($this->mw());
        $this->assertInstanceOf(HttpFactory::class, (new \ReflectionProperty(HttpFoundationGuard::class, 'responses'))->getValue($g));
        HttpFoundationGuard::$classExistsHook = static fn (string $c): bool => false;
        try {
            new HttpFoundationGuard($this->mw());
            $this->fail('built without a PSR-17 implementation');
        } catch (\RuntimeException $e) {
            $this->assertSame('HttpFoundationGuard needs a PSR-17 implementation: install nyholm/psr7 or guzzlehttp/psr7, or pass the factories', $e->getMessage());
        }
    }

    /** The executor path answers with a rebuilt response (not the handler's own object): that is returned, never a pass. */
    public function testRebuiltResponseIsNotAPass(): void
    {
        $fix = Json::parseLax((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $case = $fix->get('cases')[0];
        $grant = $case->get('grant');
        $op = $case->get('steps')[0]->get('operation');
        $now = $fix->get('now')->int();
        $f = new HttpFactory();
        $mw = new PcaMiddleware($fix->get('audience'), fn ($ref) => $grant, fn () => $now, $f, $f,
            authorize: new AuthorizeOptions(...(['executor' => new ExecutorOptions(new MemoryOperationStore()), 'stateStore' => new MemoryStateStore(),
                'isRevoked' => fn () => false, 'operation' => fn () => $op, 'plan' => 'single-step'] + ProvHarness::options())));
        $header = Pca::b64u(Json::canonicalizeStrict($case->get('steps')[0]->get('pcactn')));
        $r = (new HttpFoundationGuard($mw))->check(Request::create('/pay', 'POST', [], [], [], ['HTTP_PCA_ACTION' => $header]));
        $this->assertInstanceOf(Response::class, $r[0]);
        $this->assertSame(204, $r[0]->getStatusCode());
        $this->assertNull($r[1]);
    }
}
