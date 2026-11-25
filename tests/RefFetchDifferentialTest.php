<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Fetch;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The Web-Fetch-shaped guard (construction guards and the pre-verification refusals) against the TS reference: test-data/ref-fetch.json.gz.
 * Compared by shape: the core verifier's reason text and challenge string are its own.
 */
final class RefFetchDifferentialTest extends TestCase
{
    private const FILE = 'ref-fetch.json.gz';
    private const AUD = 'rs_fetch';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function construct(string $kind): Obj
    {
        $handler = static fn() => 'ok';
        $resolve = static fn(string $ref) => null;
        $o = ['audience' => $kind === 'noaudience' ? '' : self::AUD, 'resolveGrant' => $resolve];
        if ($kind !== 'nooperation') {
            $o['insecureAllowUnboundOperation'] = true;
        }
        if (!in_array($kind, ['ok', 'noaudience', 'nooperation'], true)) {
            throw new \InvalidArgumentException('unknown kind');
        }
        Fetch::withPca($o, $handler);
        return Obj::of(['built' => true]);
    }

    private static function request(Obj $spec): Obj
    {
        $ran = false;
        $throws = $spec->get('resolve') === 'throws';
        $guarded = Fetch::withPca([
            'audience' => self::AUD,
            'resolveGrant' => static function (string $ref) use ($throws) {
                if ($throws) {
                    throw new \RuntimeException('store down');
                }
                return null;
            },
            'insecureAllowUnboundOperation' => true,
        ], static function () use (&$ran): array {
            $ran = true;
            return ['status' => 200, 'headers' => [], 'body' => '{"ok":true}'];
        });
        $res = $guarded(Obj::of(['method' => 'POST', 'url' => 'http://localhost/refunds', 'headers' => $spec->get('headers') ?? new Obj(), 'body' => $spec->get('body')]));
        try {
            $body = Js::parse($res['body']);
        } catch (\Throwable) {
            $body = null;
        }
        $www = $res['headers']['WWW-Authenticate'] ?? null;
        $keys = $body instanceof Obj ? $body->keys() : null;
        if ($keys !== null) {
            sort($keys, SORT_STRING);
        }
        return Obj::of([
            'status' => $res['status'], 'handlerRan' => $ran, 'decision' => $body instanceof Obj ? $body->get('decision') : null,
            'challenge' => $res['status'] === 401 ? ($www !== null && str_starts_with($www, 'PCA realm="')) : null,
            'contentType' => $res['headers']['content-type'] ?? null, 'bodyKeys' => $keys,
            'errorIsString' => $body instanceof Obj && is_string($body->get('error')),
        ]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constructScenario' => fn(array $a) => self::construct($a[0]),
            'requestScenario' => fn(array $a) => self::request($a[0]),
        ]);
    }
}
