<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PcaMiddleware.php';

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaAgentError;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;

/** require-pca.ts defaultEscalationAnswer / defaultProvenanceBundle and the PcaAgentError class. */
final class RequestReadersTest extends TestCase
{
    public function testEscalationAnswerFromHeaderOrBody(): void
    {
        $json = '{"decision":"allow"}';
        $h = (new ServerRequest('POST', 'https://x/'))->withHeader('PCA-Escalation-Answer', Pca::b64u($json));
        self::assertInstanceOf(Obj::class, PcaMiddleware::defaultEscalationAnswer($h));
        self::assertSame('allow', PcaMiddleware::defaultEscalationAnswer($h)->get('decision'));
        $b = (new ServerRequest('POST', 'https://x/'))->withBody(Utils::streamFor('{"escalation_answer":' . $json . '}'));
        self::assertSame('allow', PcaMiddleware::defaultEscalationAnswer($b)->get('decision'));
        self::assertNull(PcaMiddleware::defaultEscalationAnswer(new ServerRequest('POST', 'https://x/')));
        self::assertNull(PcaMiddleware::defaultEscalationAnswer($h->withHeader('PCA-Escalation-Answer', '!!not-base64!!')));
        self::assertNull(PcaMiddleware::defaultEscalationAnswer((new ServerRequest('POST', 'https://x/'))->withBody(Utils::streamFor('not json'))));
    }

    public function testProvenanceBundleFromHeaderOrBody(): void
    {
        $h = (new ServerRequest('POST', 'https://x/'))->withHeader('PCA-Provenance', Pca::b64u('{"k":1}'));
        self::assertInstanceOf(Obj::class, PcaMiddleware::defaultProvenanceBundle($h));
        $b = (new ServerRequest('POST', 'https://x/'))->withBody(Utils::streamFor('{"pca_provenance":{"k":2}}'));
        self::assertInstanceOf(Obj::class, PcaMiddleware::defaultProvenanceBundle($b));
        self::assertNull(PcaMiddleware::defaultProvenanceBundle(new ServerRequest('POST', 'https://x/')));
        $this->expectException(\UnexpectedValueException::class);
        PcaMiddleware::defaultProvenanceBundle($h->withHeader('PCA-Provenance', '!!'));
    }

    public function testAgentError(): void
    {
        $e = new PcaAgentError('network', 'down', 502);
        self::assertSame('network', $e->errorCode);
        self::assertSame(502, $e->httpStatus);
        self::assertNull((new PcaAgentError('no_plan', 'x'))->httpStatus);
        $this->expectException(\InvalidArgumentException::class);
        new PcaAgentError('bogus', 'x');
    }
}
