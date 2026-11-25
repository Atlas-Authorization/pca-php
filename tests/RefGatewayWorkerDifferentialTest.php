<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Gateway;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The gateway's Cloudflare Worker adapter (decision, the strip of inbound x-pca-* headers before the upstream, the deny JSON and the
 * forged-header 400, over injected next / respond) against the TS reference: test-data/ref-gateway-worker.json.gz.
 */
final class RefGatewayWorkerDifferentialTest extends TestCase
{
    private const FILE = 'ref-gateway-worker.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function view(mixed $r): Obj
    {
        $names = [];
        foreach (Js::opt($r, 'headers')->keys() as $k) {
            $names[strtolower($k)] = Js::opt($r, 'headers')->get($k);
        }
        ksort($names, SORT_STRING);
        return Obj::of(['method' => Js::opt($r, 'method'), 'url' => Js::opt($r, 'url'), 'headers' => Obj::of($names)]);
    }

    private static function worker(Obj $spec): mixed
    {
        $ev = $spec->get('events')[0];
        $rewrite = match ($ev->get('rewrite')) {
            'null' => null,
            'custom' => static function (mixed $r, array $drop): Obj {
                $h = new Obj();
                foreach (Js::opt($r, 'headers')->keys() as $k) {
                    if (!in_array(strtolower($k), $drop, true)) {
                        $h->set($k, Js::opt($r, 'headers')->get($k));
                    }
                }
                $h->set('x-rewritten', implode(',', $drop));
                return Obj::of(['method' => Js::opt($r, 'method'), 'url' => Js::opt($r, 'url'), 'headers' => $h]);
            },
            default => 'default',
        };
        try {
            $w = Gateway::cloudflareWorker(
                RefGatewayDifferentialTest::build($spec),
                static fn(mixed $r) => Obj::of(['forwarded' => self::view($r)]),
                static function (string $body, array $init): Obj {
                    return Obj::of(['status' => $init['status'], 'headers' => Obj::of($init['headers']), 'body' => Js::parse($body)]);
                },
                $rewrite,
            );
        } catch (\TypeError | \InvalidArgumentException $e) {
            return Obj::of(['create' => $e->getMessage()]);
        }
        return RefGatewayDifferentialTest::mask($w(Obj::of(['method' => $ev->get('method'), 'url' => $ev->get('url'), 'headers' => $ev->get('headers')])));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, ['workerScenario' => fn(array $a) => self::worker($a[0])]);
    }
}
