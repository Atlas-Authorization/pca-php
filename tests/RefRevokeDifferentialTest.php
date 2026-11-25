<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FileRevocationStore;
use Atlas\Pca\InMemoryRevocationStore;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\RevocationRegistry;
use Atlas\Pca\RevocationStore;
use Atlas\Pca\Revoke;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The revocation registry, chain check and CAEP bridge against the TS reference: test-data/ref-revoke.json.gz. */
final class RefRevokeDifferentialTest extends TestCase
{
    private const FILE = 'ref-revoke.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private static function clock(): float
    {
        return Base::clockMs(self::FILE);
    }

    /** An entry whose revokedAt is within two minutes of the wall clock (live, or the corpus generator's frozen clock) is printed "<now>" (the reference does the same). */
    private static function norm(mixed $v): mixed
    {
        if (is_array($v)) {
            $o = [];
            foreach ($v as $k => $x) {
                $o[$k] = $k === 'revokedAt' && Js::isNum($x) && (abs(Js::num($x) - Revoke::nowMs()) < 120000 || abs(Js::num($x) - self::clock()) < 120000) ? '<now>' : self::norm($x);
            }
            return $o;
        }
        return $v;
    }

    private static function failing(string $mode): RevocationStore
    {
        return new class ($mode) extends InMemoryRevocationStore {
            public function __construct(private readonly string $mode)
            {
            }

            public function get(string $kind, string $value): ?array
            {
                if ($this->mode === 'failGet') {
                    throw new \RuntimeException('boom');
                }
                return parent::get($kind, $value);
            }

            public function all(): array
            {
                if ($this->mode === 'failAll') {
                    throw new \RuntimeException('boom');
                }
                return parent::all();
            }
        };
    }

    private static function step(RevocationRegistry $reg, Obj $s): mixed
    {
        $o = $s->get('opts');
        $opt = static fn(string $k): mixed => $o instanceof Obj ? $o->get($k) : null;
        return match ($s->get('op')) {
            'revoke' => $reg->revoke($s->get('input')),
            'revokeSubtree' => $reg->revokeSubtree($s->get('target'), $o),
            'unrevoke' => $reg->unrevoke($s->get('key')),
            'list' => $reg->list(),
            'lookup' => $reg->lookup($s->get('kind'), $s->get('value')),
            'prefixes' => $reg->prefixes(),
            'clear' => $reg->clear(),
            'killAgent' => $reg->killAgent($s->get('holder'), $opt('reason'), $opt('revokedAt')),
            'killSubtree' => $reg->killSubtree($s->get('root'), $opt('reason'), $opt('revokedAt')),
            'check' => Revoke::checkRevocation($s->get('p'), $reg, $opt('now')),
            'verify' => Revoke::verifyWithRevocation($s->get('p'), $s->get('core'), $reg, $opt('now')),
            'ingest' => Revoke::ingestCaepEvent($s->get('event'), $reg),
        };
    }

    private static function scenario(Obj $spec): mixed
    {
        $mode = $spec->get('store');
        $reg = new RevocationRegistry(in_array($mode, ['failGet', 'failAll'], true) ? self::failing($mode) : new InMemoryRevocationStore());
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                $out[] = self::norm(self::step($reg, $s));
            } catch (\Throwable) {   // only the refusal is compared, not its message
                $out[] = ['$err' => true];
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            // the reference stores a kind-less entry that no lookup can match; this port refuses it
            'scenario' => fn(array $a, Obj $c) => str_starts_with((string)$c->get('name'), 'scenario/revoke/34#') ? [Base::SKIP, 'kind-less entry'] : self::scenario($a[0]),
            'isActiveAt' => fn(array $a) => Revoke::isActiveAt($a[0], $a[1]),
            'caepEventTypes' => fn() => Revoke::CAEP_EVENT_TYPES,
        ]);
    }

    public function testTheInMemoryStoreConforms(): void
    {
        self::assertSame([], Revoke::runRevocationStoreConformance(static fn() => new InMemoryRevocationStore()));
    }

    public function testTheFileStoreConformsAndSurvivesReopen(): void
    {
        $dir = sys_get_temp_dir() . '/pca-revoke-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $n = 0;
        $paths = new \WeakMap();
        try {
            $make = static function () use ($dir, &$n, $paths): FileRevocationStore {
                $p = $dir . '/r' . (++$n) . '.json';
                $s = new FileRevocationStore($p);
                $paths[$s] = $p;
                return $s;
            };
            self::assertSame([], Revoke::runRevocationStoreConformance($make, static fn(RevocationStore $prev) => new FileRevocationStore($paths[$prev])));
        } finally {
            array_map('unlink', glob("$dir/*") ?: []);
            rmdir($dir);
        }
    }

    public function testTheFileStoreRefusesACorruptFile(): void
    {
        $p = tempnam(sys_get_temp_dir(), 'pca-revoke');
        try {
            foreach (['{not json', '{"entries":"x"}', '{"v":1,"entries":[{"kind":"cap"}]}', '{"entries":[],"x":NaN}'] as $body) {
                file_put_contents($p, $body);
                try {
                    new FileRevocationStore($p);
                    self::fail("accepted $body");
                } catch (\UnexpectedValueException) {
                    self::assertTrue(true);
                }
            }
        } finally {
            @unlink($p);
        }
    }
}
