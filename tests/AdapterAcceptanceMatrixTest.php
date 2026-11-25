<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaTesting;
use PHPUnit\Framework\TestCase;

/** runAdapterAcceptance through a tiny in-process adapter built on authorize(): the matrix must equal the expected table. */
final class AdapterAcceptanceMatrixTest extends TestCase
{
    /** @param array<string,mixed> $options */
    private static function harness(array $options): callable
    {
        return static function (array $req) use ($options): array {
            $op = PcaTesting::acceptanceOperation(Obj::of(['method' => $req['method'], 'url' => $req['path'], 'body' => $req['body']]));
            if ($op === null) {
                return ['status' => 403, 'handlerRan' => false];
            }
            $h = $req['headers'];
            $text = Pca::decodePcaHeader($h['PCA-Action'] ?? null);
            if ($text === null) {
                return ['status' => 401, 'handlerRan' => false];
            }
            $bundle = isset($h[ArgProvenance::HEADER]) ? Json::parseStrict((string)Pca::unb64u($h[ArgProvenance::HEADER])) : null;
            $r = Authorize::authorize(...$options, pcactn: Json::parseStrict($text), operation: $op, provenance: $bundle);
            if (!$r->allow) {
                return ['status' => in_array($r->status, [401, 403], true) ? $r->status : 403, 'handlerRan' => false];
            }
            return ['status' => 200, 'handlerRan' => true, 'operation' => $r->operation];
        };
    }

    public function testTheAcceptanceMatrixEqualsTheExpectedTable(): void
    {
        $got = PcaTesting::runAdapterAcceptance(static fn(array $o): callable => self::harness($o));
        $this->assertSame(Base::canon(PcaTesting::adapterAcceptanceExpected()), Base::canon($got));
    }

    public function testAFailOpenAdapterDoesNotEqualTheTable(): void
    {
        $got = PcaTesting::runAdapterAcceptance(static fn(array $o): callable => static fn(array $req): array => ['status' => 200, 'handlerRan' => true]);
        $this->assertNotSame(Base::canon(PcaTesting::adapterAcceptanceExpected()), Base::canon($got));
    }
}
