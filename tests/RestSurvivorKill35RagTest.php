<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Rag.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\Rag;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the retrieval filter (pca-rag). */
final class RestSurvivorKill35RagTest extends TestCase
{
    private static function policy(array $where = []): Obj
    {
        $p = ['verb' => 'viewer', 'resource' => '*'];
        if ($where !== []) {
            $p['where'] = $where;
        }
        return Sign::n(['predicates' => [$p]]);
    }

    private static function acl(): Obj
    {
        return Obj::of(['relation' => 'viewer', 'object' => 'doc:1']);
    }

    private static function eq(string $field, string $value): array
    {
        return ['field' => $field, 'op' => 'eq', 'value' => $value];
    }

    private static function allowed(mixed $attributes, array $where): bool
    {
        $principal = Obj::of(['id' => 'alice', 'attributes' => $attributes]);
        $r = Rag::filterDocuments($principal, [Obj::of(['id' => 'd1', 'acl' => self::acl()])], self::policy($where));
        return $r['decision']->get('allowedIds') === ['d1'];
    }

    /** A PCActn that is not an object, or whose leaf is not an object, is refused with the holder reason. */
    public function testPrincipalFromPcactnRefusesNonObjects(): void
    {
        foreach (['x', Obj::of(['cap_chain' => ['x']])] as $p) {
            try {
                Rag::principalFromPCActn($p);
                $this->fail('a principal was produced');
            } catch (\TypeError $e) {
                $this->assertSame('principalFromPCActn: PCActn has no leaf capability holder', $e->getMessage());
            }
        }
    }

    /** report.errors.length > 0 is read like JavaScript: arrays/strings by size, objects by their length member, anything else is not positive. */
    public function testReportErrorsLength(): void
    {
        $inc = static fn(mixed $errors): mixed => Rag::compilePolicy(Obj::of(['predicates' => [], 'report' => Obj::of(['errors' => $errors])]))->get('incomplete');
        $this->assertFalse($inc(5));
        $this->assertFalse($inc(true));
        $this->assertFalse($inc([]));
        $this->assertTrue($inc(['e']));
        $this->assertTrue($inc('x'));
        $this->assertFalse($inc(Obj::of(['length' => 0])));
        $this->assertTrue($inc(Obj::of(['length' => 1])));
        $this->assertFalse($inc(Obj::of([])));
    }

    /** A report that is not an object is a TypeError with its reason. */
    public function testANonObjectReportIsRefused(): void
    {
        try {
            Rag::compilePolicy(Obj::of(['predicates' => [], 'report' => 5]));
            $this->fail('compiled');
        } catch (\TypeError $e) {
            $this->assertSame('compilePolicy: report.errors is required', $e->getMessage());
        }
    }

    /** List attributes spread by index and string attributes by UTF-8 character into the subject. */
    public function testAttributeSpreads(): void
    {
        $this->assertTrue(self::allowed(['a', 'b'], [self::eq('subject.0', 'a'), self::eq('subject.1', 'b')]));
        $this->assertTrue(self::allowed('ab', [self::eq('subject.0', 'a'), self::eq('subject.1', 'b')]));
        $this->assertTrue(self::allowed("\u{e9}x", [self::eq('subject.0', "\u{e9}"), self::eq('subject.1', 'x')]));
        $this->assertFalse(self::allowed('ab', [self::eq('subject.0', 'ab')]));
    }

    /** withPcaFilter uses the caller's id and ACL readers when given. */
    public function testCustomReaders(): void
    {
        $doc = Obj::of(['id' => 'd1']);
        $f = Rag::withPcaFilter(static fn(string $q, ?int $k): array => [$doc], 'alice', self::policy(), null,
            static fn(mixed $d, int $i): string => 'X', static fn(mixed $d): array => [self::acl()]);
        $this->assertSame([$doc], $f->retrieve('q'));
        $this->assertSame(['X'], $f->lastDecision()->get('allowedIds'));
    }

    /** Every admitted document is recorded as retrieval content under its id, or doc#i when it has none. */
    public function testRetrievalsAreRecorded(): void
    {
        $rec = new ProvenanceRecorder('m', 'k1', new KeyPair(str_repeat("\x03", 32)), null, static fn(): int => 1000);
        $docs = [Obj::of(['id' => 'd1', 'acl' => self::acl()]), Obj::of(['acl' => self::acl()])];
        $f = Rag::withPcaFilter(static fn(string $q, ?int $k): array => $docs, 'alice', self::policy(), $rec);
        $this->assertSame($docs, $f->retrieve('q'));
        $this->assertSame(['d1', 'doc#1'], array_map(static fn(Obj $r): mixed => $r->get('source'), $rec->receipts()));
        $this->assertSame(['retrieval', 'retrieval'], array_map(static fn(Obj $r): mixed => $r->get('origin'), $rec->receipts()));
    }
}
