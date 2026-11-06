<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\ProvenanceGate;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for ProvenanceGate: RFC 9162 inclusion edges, the gate's Obj check, the caveat's builder list. */
final class K05KillProvenanceGateTest extends TestCase
{
    private static function node(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    public function testInclusionShapes(): void
    {
        $l = str_repeat("\x11", 32);
        $s = str_repeat("\x22", 32);
        $inc = [ProvenanceGate::class, 'verifyRfc9162Inclusion'];
        $this->assertTrue($inc($l, 0, 1, [], $l));
        $this->assertTrue($inc($l, 0, 2, [$s], self::node($l, $s)));
        // 31-byte hashes are not hashes
        $l31 = str_repeat("\x11", 31);
        $this->assertFalse($inc($l31, 0, 1, [], $l31));
        $s31 = str_repeat("\x22", 31);
        $this->assertFalse($inc($l, 0, 2, [$s31], self::node($l, $s31)));
        // a proof must be a list
        $this->assertFalse($inc($l, 0, 2, ['x' => $s], self::node($l, $s)));
        // a proof longer than the path is refused (tree of one leaf, one extra sibling)
        $this->assertFalse($inc($l, 0, 1, [$s], self::node($s, $l)));
    }

    public function testInclusionNumberForms(): void
    {
        $l = str_repeat("\x11", 32);
        $inc = [ProvenanceGate::class, 'verifyRfc9162Inclusion'];
        $this->assertTrue($inc($l, 0, 1.0, [], $l));         // a native float integer
        $this->assertTrue($inc($l, 0, new Num('1.0'), [], $l)); // a non-integer lexeme with an integer value
        $this->assertFalse($inc($l, 0, 1.5, [], $l));       // not a safe integer
        $this->assertFalse($inc($l, 0, new Num('1.5'), [], $l));
    }

    private static function input(): Obj
    {
        $policy = Obj::of(['roots' => [Obj::of(['oidc_issuer' => 'https://iss.example', 'builder_id' => 'https://builder.example',
            'identity' => 'id-1', 'level' => 2])], 'min_level' => 1]);
        $facts = Obj::of(['v' => 1, 'predicate_type' => ProvenanceGate::SLSA_PROVENANCE_V1, 'build_type' => 'bt',
            'builder_id' => 'https://builder.example', 'subjects' => [Obj::of(['alg' => 'sha256', 'digest' => str_repeat('a', 64)])],
            'identity' => 'id-1', 'oidc_issuer' => 'https://iss.example', 'integrated_time' => 10, 'rekor_log_index' => 5]);
        return Obj::of(['facts' => $facts, 'policy' => $policy, 'now' => 20]);
    }

    public function testGateNeedsAnObj(): void
    {
        $in = self::input();
        $ok = ProvenanceGate::gate($in);
        $this->assertTrue($ok['ok']);
        $this->assertSame(2, $ok['level']);
        $fake = new class ($in) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }

            public function keys(): array
            {
                return $this->o->keys();
            }
        };
        $this->assertSame(['ok' => false, 'code' => 'malformed_facts'], ProvenanceGate::gate($fake));
    }

    public function testCaveatBuilderIdsAreAList(): void
    {
        $c = ProvenanceGate::caveat(['issuer' => 'iss', 'min_level' => 2, 'builder_ids' => [3 => 'b1', 7 => 'b2']]);
        $req = $c->get('require');
        $this->assertSame('builder_id', $req[1]->get('claim'));
        $this->assertSame(['b1', 'b2'], $req[1]->get('value'));
    }

    public function testInclusionFailsClosedOnAThrow(): void
    {
        $l = str_repeat("\x11", 32);
        $this->assertTrue(ProvenanceGate::verifyRfc9162Inclusion($l, new Num('0'), new Num('1'), [], $l));
        ProvenanceGate::$inclusionHook = static function (): void {
            throw new \RuntimeException('k05');
        };
        try {
            $this->assertFalse(ProvenanceGate::verifyRfc9162Inclusion($l, 0, 1, [], $l));
        } finally {
            ProvenanceGate::$inclusionHook = null;
        }
    }
}
