<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

/** F8: the guard's 401 error codes are the reference's (missing_pcactn, invalid_pcactn, unknown_grant). */
final class K05HardGuardCodesTest extends TestCase
{
    private function run401(ServerRequest $request): array
    {
        $f = new HttpFactory();
        $mw = new PcaMiddleware('aud', static fn(string $ref) => null, static fn(): int => 1, $f, $f, signatureOnly: true);
        $handler = new class () implements RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                throw new \LogicException('the handler must not run');
            }
        };
        $r = $mw->process($request, $handler);
        return [$r->getStatusCode(), json_decode((string)$r->getBody(), true)['error'], $r->getHeaderLine('WWW-Authenticate')];
    }

    public function testNothingPresentedIsMissingPcactn(): void
    {
        [$status, $error, $challenge] = $this->run401(new ServerRequest('GET', '/r'));
        $this->assertSame([401, 'missing_pcactn'], [$status, $error]);
        $this->assertStringContainsString('error="missing_pcactn"', $challenge);
    }

    public function testABodyWithoutAPcactnMemberIsMissingPcactn(): void
    {
        $r = (new ServerRequest('POST', '/r'))->withBody((new HttpFactory())->createStream('{"other":1}'));
        $this->assertSame([401, 'missing_pcactn'], array_slice($this->run401($r), 0, 2));
    }

    public function testUndecodableAndMalformedPcactnsAreInvalidPcactn(): void
    {
        $this->assertSame([401, 'invalid_pcactn'], array_slice($this->run401(new ServerRequest('POST', '/r', [PcaMiddleware::HEADER => 'not valid base64url!!'])), 0, 2));
        $bad = (new ServerRequest('POST', '/r'))->withBody((new HttpFactory())->createStream('{not json'));
        $this->assertSame([401, 'invalid_pcactn'], array_slice($this->run401($bad), 0, 2));
        $notObject = (new ServerRequest('POST', '/r'))->withBody((new HttpFactory())->createStream('{"pcactn":5}'));
        $this->assertSame([401, 'invalid_pcactn'], array_slice($this->run401($notObject), 0, 2));
    }
}
