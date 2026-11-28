<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\ListAuthorized;
use Atlas\Pca\ListError;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/ListAuthorized.php: what the candidate, relation and read sources are asked, the scan cap and the refusals. */
final class CoreSurvivorKill1ListAuthorizedTest extends TestCase
{
    /** A candidate source whose page `$n` (0-based) is `$pages($n)`; it records every query. */
    private static function candidates(\Closure $pages): object
    {
        return new class ($pages) {
            /** @var list<array<string,mixed>> */
            public array $queries = [];

            public function __construct(private readonly \Closure $pages)
            {
            }

            public function page(array $q): array
            {
                $this->queries[] = $q;
                return ($this->pages)(count($this->queries) - 1);
            }
        };
    }

    private static function reads(): object
    {
        return new class {
            /** @var list<array{0:string,1:mixed}> */
            public array $log = [];

            public function charge(string $key, mixed $units, mixed $now): bool
            {
                $this->log[] = [$key, $units];
                return true;
            }
        };
    }

    private static function opts(object $cand, object $reads, int $limit, array $over = []): array
    {
        return $over + ['subject' => 'S', 'resourceType' => 'T', 'permits' => static fn(mixed $x): bool => true, 'candidates' => $cand, 'filterId' => 'f',
            'policyDigest' => 'p', 'freshAtDigest' => 'fa', 'page' => ['limit' => $limit], 'reads' => $reads, 'now' => 1,
            'signingSecret' => new KeyPair(str_repeat("\x07", 32))];
    }

    private static function listError(array $o): ListError
    {
        try {
            ListAuthorized::listAuthorized($o);
        } catch (ListError $e) {
            return $e;
        }
        self::fail('expected ListError');
    }

    /** The limit refusal carries its code and message. */
    public function testBadLimit(): void
    {
        $e = self::listError(self::opts(self::candidates(static fn(int $n): array => ['objects' => []]), self::reads(), 0));
        self::assertSame('bad_limit', $e->errorCode);
        self::assertSame('limit must be 1..500', $e->getMessage());
    }

    /** The source is asked for the type and limit; an empty page still charges one unit to the subject+type key. */
    public function testEmptyPageQueryAndCharge(): void
    {
        $cand = self::candidates(static fn(int $n): array => ['objects' => []]);
        $reads = self::reads();
        ListAuthorized::listAuthorized(self::opts($cand, $reads, 2));
        self::assertSame([['type' => 'T', 'limit' => 2]], $cand->queries);
        self::assertSame([[Pca::hashCanonical(Obj::of(['s' => 'S', 't' => 'T'])), 1]], $reads->log);
    }

    /** A page whose objects come keyed by name is read as a list. */
    public function testKeyedPageIsReadAsAList(): void
    {
        $cand = self::candidates(static fn(int $n): array => ['objects' => ['a' => 'x', 'b' => 'y']]);
        self::assertSame(['x', 'y'], ListAuthorized::listAuthorized(self::opts($cand, self::reads(), 5))->get('objects'));
    }

    /** A resumed page charges only what it has not skipped; a cursor reused with another filter, or a forged one, is refused by name. */
    public function testResumedPageAndCursorRefusals(): void
    {
        $cand = self::candidates(static fn(int $n): array => ['objects' => ['x', 'y', 'z']]);
        $reads = self::reads();
        $first = ListAuthorized::listAuthorized(self::opts($cand, $reads, 1));
        self::assertSame(['x'], $first->get('objects'));
        $cursor = $first->get('next_cursor');
        $second = ListAuthorized::listAuthorized(self::opts($cand, $reads, 1, ['page' => ['limit' => 1, 'cursor' => $cursor]]));
        self::assertSame(['y'], $second->get('objects'));
        self::assertSame([3, 2], array_column($reads->log, 1));
        $e = self::listError(self::opts($cand, $reads, 1, ['filterId' => 'g', 'page' => ['limit' => 1, 'cursor' => $cursor]]));
        self::assertSame('bad_cursor', $e->errorCode);
        self::assertSame('subject, type, filter, policy or limit changed between pages', $e->getMessage());
        $e = self::listError(self::opts($cand, $reads, 1, ['page' => ['limit' => 1, 'cursor' => 'x']]));
        self::assertSame('the page cursor is malformed, forged or from another signer', $e->getMessage());
    }

    private static function scanPages(int $perPage): int
    {
        $cand = self::candidates(static fn(int $n): array => ['objects' => array_map(static fn(int $i): string => "o$n-$i", range(1, $perPage)), 'next' => 'n' . ($n + 1)]);
        ListAuthorized::listAuthorized(self::opts($cand, self::reads(), 500, ['maxScan' => 5000, 'permits' => static fn(mixed $x): bool => false]));
        return count($cand->queries);
    }

    /** One call scans at most 1000 objects, checked at page boundaries: 999 scanned goes on, 1000 stops. */
    public function testScanCapIsOneThousand(): void
    {
        self::assertSame(2, self::scanPages(500));
        self::assertSame(4, self::scanPages(333));
    }

    /** The relation adapter asks for the subject and relation plus the query; the narrowing check is asked about the subject. */
    public function testRelationQueries(): void
    {
        $rel = new class {
            /** @var list<array<string,mixed>> */
            public array $lists = [];
            /** @var list<array<string,mixed>> */
            public array $checks = [];

            public function listObjects(array $q): array
            {
                $this->lists[] = $q;
                return ['objects' => ['x']];
            }

            public function check(array $q): bool
            {
                $this->checks[] = $q;
                return true;
            }
        };
        $src = ListAuthorized::candidatesFromRelation($rel, 'S', 'R');
        self::assertSame(['objects' => ['x']], $src->page(['type' => 'T', 'limit' => 2]));
        self::assertSame([['subject' => 'S', 'relation' => 'R', 'type' => 'T', 'limit' => 2]], $rel->lists);
        $out = ListAuthorized::listAuthorized(self::opts($src, self::reads(), 2, ['relation' => ['source' => $rel, 'relation' => 'R']]));
        self::assertSame(['x'], $out->get('objects'));
        self::assertSame([['subject' => 'S', 'relation' => 'R', 'object' => 'x']], $rel->checks);
        try {
            ListAuthorized::candidatesFromRelation(new \stdClass(), 'S', 'R');
            self::fail('expected TypeError');
        } catch (\TypeError $e) {
            self::assertSame('candidatesFromRelation: the relation source has no listObjects', $e->getMessage());
        }
    }
}
