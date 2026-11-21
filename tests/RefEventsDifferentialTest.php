<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Events;
use Atlas\Pca\Js;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Step-up events and signed webhooks against the TS reference: test-data/ref-events.json.gz. A byte secret arrives as
 * {"$bytes"} (raw bytes here); a text secret is its UTF-8 bytes (a lone surrogate encodes as U+FFFD, as TextEncoder does).
 */
final class RefEventsDifferentialTest extends TestCase
{
    private const FILE = 'ref-events.json.gz';
    private const SECRET = 'whsec_0123456789abcdef0123456789';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function secret(mixed $s): mixed
    {
        if ($s instanceof Obj && $s->keys() === ['$bytes']) {
            return Pca::unb64u($s->get('$bytes'));
        }
        return is_string($s) ? Js::utf8($s) : $s;
    }

    /** The generator's reason mapping: engine-specific JSON syntax texts and canonicalize texts are compared by class only. */
    private static function reason(array $v): array
    {
        if ($v['ok'] !== false) {
            return $v;
        }
        if (str_starts_with($v['reason'], 'canonicalize:')) {
            $v['reason'] = '<canonicalize>';
        } elseif (preg_match('/\A(a replay store|bad signature|replayed|replay store|parseEvent: )/', $v['reason']) !== 1) {
            $v['reason'] = '<json>';
        }
        return $v;
    }

    private static function scenario(Obj $spec): array
    {
        $store = match ($spec->get('store')) {
            'throws' => new class {
                public function consumeOnce(string $k, int $u, int $n): bool
                {
                    throw new \RuntimeException('down');
                }
            },
            'refuses' => new class {
                public function consumeOnce(string $k, int $u, int $n): bool
                {
                    return false;
                }
            },
            default => new MemoryStateStore(),
        };
        $out = [];
        foreach ($spec->get('deliveries') as $d) {
            $opts = null;
            if ($spec->get('noOpts') !== true) {
                $opts = $spec->get('noReplay') === true ? [] : ['replay' => $store];
                $o = $d->get('opts');
                foreach ($o instanceof Obj ? $o->keys() : [] as $k) {
                    $opts[$k] = $o->get($k);
                }
            }
            $secret = self::secret($d->has('secret') ? $d->get('secret') : self::SECRET);
            $out[] = self::reason(Events::verifyDelivery($secret, $d->get('payload'), $d->get('header'), $opts));
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'buildStepUpEvent' => fn(array $a) => Events::buildStepUpEvent($a[0], $a[1]),
            'serializeEvent' => fn(array $a) => Events::serializeEvent($a[0]),
            'parseEvent' => fn(array $a) => Events::parseEvent($a[0]),
            'signWebhook' => fn(array $a) => Events::signWebhook(self::secret($a[0]), $a[1], $a[2] ?? null),
            'verifyWebhook' => fn(array $a) => Events::verifyWebhook(self::secret($a[0]), $a[1], $a[2], $a[3] ?? null),
            'webhookHeaders' => fn(array $a) => Events::webhookHeaders(self::secret($a[0]), $a[1], $a[2] ?? null),
            'deliveryScenario' => fn(array $a) => self::scenario($a[0]),
            'minSecretBytes' => fn() => Events::MIN_SECRET_BYTES,
        ]);
    }
}
