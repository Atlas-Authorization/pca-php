<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentV2Schema.php: the v2 (schema `v: 2`) parameter / verb / document members (role, format,
 * tags, provenance_min, nested-path parents, effects, traits, traits_digest, trait_defs, pack), the public schemaFloorsError /
 * confirmationShapeError / formatCheck helpers, the v2 string formats and the duration / max_len value bounds.
 */
final class K05KillIntentV2SchemaTest extends TestCase
{
    private const B32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // canonical base64url of 32 zero bytes
    private const P = "verb 'v': action.params.x: ";
    private const ALL_EFFECTS = ['create', 'delete', 'exec', 'export', 'pay', 'privilege', 'provision', 'publish', 'read', 'send', 'sign', 'update'];

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
    }

    private static function floors(array $over = []): array
    {
        return array_merge(['risk' => 0, 'rev' => 'reversible', 'blast_ppm' => 0, 'esc' => 0, 'caveats' => [], 'context' => [], 'prules' => []], $over);
    }

    /** actionSchemaShapeError of a well-formed unsigned v2 schema with one verb `v` (param `action.params.x`), overridden. */
    private static function shape(array $verb = [], array $doc = [], array $param = [], ?array $params = null): ?string
    {
        $p = array_merge(['type' => 'string', 'semantic' => 's', 'sensitivity' => 'free'], $param);
        $v = array_merge(['verb' => 'v', 'kind' => 'write', 'params' => $params ?? ['action.params.x' => $p], 'effects' => ['create'],
            'traits' => [], 'def' => self::B32, 'floors' => self::floors()], $verb);
        $d = array_merge(['v' => 2, 'kind' => 'pca-action-schema', 'site' => 's', 'aud' => 'a', 'version' => '1', 'verbs' => [$v]], $doc);
        return IntentV2::actionSchemaShapeError(self::o($d), false);
    }

    /** @return list<string> n sorted, distinct trait ids */
    private static function traitIds(int $n): array
    {
        return array_map(static fn(int $i): string => sprintf('a.x%02d', $i), range(0, $n - 1));
    }

    public function testBaseV2SchemaIsWellFormed(): void
    {
        $this->assertNull(self::shape());
    }

    public function testRole(): void
    {
        $this->assertNull(self::shape(param: ['role' => str_repeat('r', 128)]));
        $this->assertSame(self::P . 'role must be a non-empty string', self::shape(param: ['role' => str_repeat('r', 129)]));
        $this->assertSame(self::P . 'role must be a non-empty string', self::shape(param: ['role' => 5]));
    }

    public function testFormat(): void
    {
        $f = self::P . 'format must be a known format on a string parameter';
        $this->assertNull(self::shape(param: ['format' => 'email']));
        $this->assertNull(self::shape(param: ['type' => 'object_ref', 'format' => 'uuid']));
        $this->assertSame($f, self::shape(param: ['format' => 'nope']));
        $this->assertSame($f, self::shape(param: ['format' => 5]));
        $this->assertSame($f, self::shape(param: ['type' => 'integer', 'format' => 'email']));
        $this->assertSame($f, self::shape(param: ['type' => 'boolean', 'format' => 'email']));
    }

    public function testTags(): void
    {
        $t = self::P . 'tags must be distinct known tags';
        $this->assertNull(self::shape(param: ['tags' => ['pii', 'sql']]));
        $this->assertNull(self::shape(param: ['tags' => IntentV2::SCHEMA_V2_TAGS])); // all 9: count == the bound
        $this->assertSame($t, self::shape(param: ['tags' => ['nope']]));
        $this->assertSame($t, self::shape(param: ['tags' => ['pii', 'nope']]));
        $this->assertSame($t, self::shape(param: ['tags' => [5]]));
        $this->assertSame($t, self::shape(param: ['tags' => ['pii', 'pii']]));
        $this->assertSame($t, self::shape(param: ['tags' => 'pii']));
        $this->assertSame($t, self::shape(param: ['tags' => [...IntentV2::SCHEMA_V2_TAGS, 'pii']]));
    }

    public function testProvenanceMin(): void
    {
        $this->assertNull(self::shape(param: ['provenance_min' => 'tool']));
        $this->assertSame(self::P . 'unknown provenance_min', self::shape(param: ['provenance_min' => 'x']));
        $this->assertSame(self::P . 'unknown provenance_min', self::shape(param: ['provenance_min' => 5]));
    }

    public function testNestedPathParent(): void
    {
        $d = ['type' => 'string', 'semantic' => 's', 'sensitivity' => 'free'];
        $this->assertSame("verb 'v': parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'",
            self::shape(params: ['action.params.a' => $d, 'action.params.a.b' => $d]));
        $this->assertNull(self::shape(params: ['action.params.a' => $d, 'action.params.ab' => $d]));
        $this->assertNull(self::shape(params: ['action.params.a.b' => $d, 'action.params.a.c' => $d]));
    }

    public function testEffects(): void
    {
        $e = "verb 'v': effects must be 1..12 known effects";
        $s = "verb 'v': effects must be sorted and distinct";
        $this->assertSame($e, self::shape(['effects' => []]));
        $this->assertSame($e, self::shape(['effects' => ['nope']]));
        $this->assertSame($e, self::shape(['effects' => [5]]));
        $this->assertSame($e, self::shape(['effects' => 'create']));
        $this->assertNull(self::shape(['effects' => self::ALL_EFFECTS]));
        $this->assertNull(self::shape(['effects' => ['create', 'update']]));
        $this->assertSame($s, self::shape(['effects' => ['update', 'create']]));
        $this->assertSame($s, self::shape(['effects' => ['create', 'create']]));
        $this->assertNull(self::shape(['kind' => 'read', 'effects' => ['read']]));
    }

    public function testTraits(): void
    {
        $t = "verb 'v': traits must be trait ids";
        $s = "verb 'v': traits must be sorted and distinct";
        $this->assertNull(self::shape(['traits' => ['a.b', 'a.c']]));
        $this->assertNull(self::shape(['traits' => self::traitIds(64)]));
        $this->assertSame($t, self::shape(['traits' => self::traitIds(65)]));
        $this->assertSame($t, self::shape(['traits' => ['BAD']]));
        $this->assertSame($t, self::shape(['traits' => [5]]));
        $this->assertSame($t, self::shape(['traits' => 'a.b']));
        $this->assertSame($s, self::shape(['traits' => ['a.c', 'a.b']]));
        $this->assertSame($s, self::shape(['traits' => ['a.b', 'a.b']]));
    }

    public function testTraitsDigestAndTraitDefs(): void
    {
        $this->assertNull(self::shape(doc: ['traits_digest' => self::B32]));
        $this->assertSame('traits_digest must be a canonical base64url SHA-256 digest', self::shape(doc: ['traits_digest' => 'x']));
        $td = 'trait_defs must be an array of up to 64 objects';
        $this->assertNull(self::shape(doc: ['trait_defs' => [new \stdClass()]]));
        $this->assertNull(self::shape(doc: ['trait_defs' => []]));
        $this->assertNull(self::shape(doc: ['trait_defs' => array_fill(0, 64, new \stdClass())]));
        $this->assertSame($td, self::shape(doc: ['trait_defs' => array_fill(0, 65, new \stdClass())]));
        $this->assertSame($td, self::shape(doc: ['trait_defs' => [5]]));
        $this->assertSame($td, self::shape(doc: ['trait_defs' => [new \stdClass(), 5]]));
        $this->assertSame($td, self::shape(doc: ['trait_defs' => 'x']));
    }

    public function testPack(): void
    {
        $pk = 'pack must be {ns, version, root}';
        $ok = ['ns' => 'n', 'version' => '1', 'root' => self::B32];
        $this->assertNull(self::shape(doc: ['pack' => $ok]));
        $this->assertNull(self::shape(doc: ['pack' => array_merge($ok, ['ns' => str_repeat('n', 64), 'version' => str_repeat('v', 128)])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => 5]));
        $this->assertSame($pk, self::shape(doc: ['pack' => array_merge($ok, ['ns' => str_repeat('n', 65)])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => array_merge($ok, ['ns' => ''])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => array_merge($ok, ['version' => str_repeat('v', 129)])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => array_merge($ok, ['root' => 'x'])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => array_merge($ok, ['x' => 1])]));
        $this->assertSame($pk, self::shape(doc: ['pack' => ['version' => '1', 'root' => self::B32]]));
    }

    public function testSchemaFloorsError(): void
    {
        $f = fn(array $over) => IntentV2::schemaFloorsError(self::o(self::floors($over)));
        $this->assertNull($f([]));
        $this->assertSame('floors must be an object', IntentV2::schemaFloorsError(5));
        $this->assertSame("floors: unknown member 'x'", $f(['x' => 1]));
        $r = 'floors.risk and floors.esc must be integers in 0..3';
        foreach ([0, 3] as $ok) {
            $this->assertNull($f(['risk' => $ok]));
            $this->assertNull($f(['esc' => $ok]));
        }
        foreach ([-1, 4, 1.5] as $bad) {
            $this->assertSame($r, $f(['risk' => $bad]));
            $this->assertSame($r, $f(['esc' => $bad]));
        }
        $b = 'floors.blast_ppm must be an integer in 0..1000000';
        $this->assertNull($f(['blast_ppm' => 1000000]));
        $this->assertSame($b, $f(['blast_ppm' => -1]));
        $this->assertSame($b, $f(['blast_ppm' => 1000001]));
        $k = fn(string $n) => "floors.$n must be an array of known entries";
        $s = fn(string $n) => "floors.$n must be sorted and distinct";
        $this->assertSame($k('caveats'), $f(['caveats' => ['nope']]));
        $this->assertSame($k('caveats'), $f(['caveats' => [5]]));
        $this->assertSame($k('caveats'), $f(['caveats' => 'x']));
        $this->assertSame($k('caveats'), $f(['caveats' => ['session_taint_max:pii']])); // the taint form is a context entry only
        $this->assertSame($k('prules'), $f(['prules' => ['nope']]));
        $this->assertSame($k('context'), $f(['context' => ['bogus']]));
        $this->assertNull($f(['context' => ['session_taint_max:pii']]));
        $this->assertNull($f(['context' => ['approval_ref', 'session_taint_max:pii']]));
        $this->assertNull($f(['caveats' => ['amount_cap', 'window']]));
        $this->assertSame($s('caveats'), $f(['caveats' => ['window', 'amount_cap']]));
        $this->assertSame($s('caveats'), $f(['caveats' => ['amount_cap', 'amount_cap']]));
        $this->assertSame($s('caveats'), $f(['caveats' => array_fill(0, 64, 'amount_cap')])); // 64 is in bounds, then not distinct
        $this->assertSame($k('caveats'), $f(['caveats' => array_fill(0, 65, 'amount_cap')]));
    }

    public function testConfirmationShapeError(): void
    {
        $base = ['def_digest' => self::B32, 'traits_digest' => self::B32, 'facts_digest' => self::B32, 'final_traits' => [],
            'dismissed' => [], 'reviewer_kid' => 'k', 'ts' => 0, 'sig' => str_repeat('A', 86)];
        $c = fn(array $over) => IntentV2::confirmationShapeError(self::o(array_merge($base, $over)));
        $this->assertNull($c([]));
        $this->assertSame('confirmation must be an object', IntentV2::confirmationShapeError(5));
        $ft = 'confirmation: final_traits must be trait ids';
        $this->assertNull($c(['final_traits' => ['a.b', 'a.c']]));
        $this->assertNull($c(['final_traits' => self::traitIds(64)]));
        $this->assertSame($ft, $c(['final_traits' => self::traitIds(65)]));
        $this->assertSame($ft, $c(['final_traits' => ['Z', 'a.b']]));
        $this->assertSame($ft, $c(['final_traits' => ['a.b', 'Z']]));
        $this->assertSame($ft, $c(['final_traits' => [5]]));
        $this->assertSame($ft, $c(['final_traits' => 'x']));
        $this->assertSame('confirmation: final_traits must be sorted and distinct', $c(['final_traits' => ['a.c', 'a.b']]));
        $dm = 'confirmation: dismissed must be an array';
        $one = ['trait' => 'a.b', 'reason' => 'r'];
        $this->assertNull($c(['dismissed' => array_fill(0, 64, $one)]));
        $this->assertSame($dm, $c(['dismissed' => array_fill(0, 65, $one)]));
        $this->assertSame($dm, $c(['dismissed' => 'x']));
        $de = 'confirmation: dismissed entries must be {trait, reason}';
        $this->assertSame($de, $c(['dismissed' => [5]]));
        $this->assertNull($c(['dismissed' => [['trait' => 'a.b', 'reason' => str_repeat('r', 256)]]]));
        $this->assertSame($de, $c(['dismissed' => [['trait' => 'a.b', 'reason' => str_repeat('r', 257)]]]));
        $this->assertNull($c(['reviewer_kid' => str_repeat('k', 128)]));
        $this->assertSame('confirmation: reviewer_kid must be a non-empty string', $c(['reviewer_kid' => str_repeat('k', 129)]));
    }

    public function testFormatCheck(): void
    {
        $this->assertNull(IntentV2::formatCheck('nope'));
        $url = IntentV2::formatCheck('url');
        $this->assertTrue($url('https://x.example/a'));
        $email = IntentV2::formatCheck('email');
        $dom = str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.';
        $at254 = str_repeat('a', 64) . '@' . $dom . str_repeat('d', 61);
        $this->assertSame(254, strlen($at254));
        $this->assertTrue($email($at254));
        $this->assertFalse($email(str_repeat('a', 64) . '@' . $dom . str_repeat('d', 62)));
        $iban = IntentV2::formatCheck('iban');
        $this->assertTrue($iban('AD1200012030200359100100')); // an 'A' digit (10): '>=' not '>'
        $this->assertFalse($iban('AD1200012030200359100101'));
        $cidr = IntentV2::formatCheck('cidr');
        $this->assertTrue($cidr('255.255.255.255/32'));
        $this->assertTrue($cidr('0.0.0.0/0'));
        foreach (['256.1.1.1/8', '1.256.1.1/8', '1.1.256.1/8', '1.1.1.256/8', '1.1.1.1/33', '01.1.1.1/8', '1.01.1.1/8', '1.1.01.1/8', '1.1.1.01/8'] as $bad) {
            $this->assertFalse($cidr($bad), $bad);
        }
        $this->assertTrue($cidr('::1/128'));
        $this->assertFalse($cidr('::1/129'));
        $this->assertFalse($cidr(':1/64'));
        $this->assertFalse($cidr('1:::1/64'));
    }

    public function testParamValueBounds(): void
    {
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'not a valid email'],
            IntentV2::paramValueViolation(self::o(['type' => 'string', 'format' => 'email']), 'bad'));
        $s = self::o(['type' => 'string', 'max_len' => 3]);
        $this->assertNull(IntentV2::paramValueViolation($s, 'abc'));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'longer than 3 UTF-8 bytes'], IntentV2::paramValueViolation($s, 'abcd'));
        $d = self::o(['type' => 'duration', 'min' => 5, 'max' => 10]);
        $this->assertNull(IntentV2::paramValueViolation($d, 5));
        $this->assertNull(IntentV2::paramValueViolation($d, 10));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'below min 5'], IntentV2::paramValueViolation($d, 4));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'above max 10'], IntentV2::paramValueViolation($d, 11));
        $d0 = self::o(['type' => 'duration']);
        $this->assertNull(IntentV2::paramValueViolation($d0, 0));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'a duration is not negative'], IntentV2::paramValueViolation($d0, -1));
    }

    protected function tearDown(): void
    {
        IntentV2::$faultHook = null;
    }

    public function testVerifyActionSchemaErrorCarriesItsMessage(): void
    {
        IntentV2::$faultHook = static function (string $step): void {
            throw new \RuntimeException("boom:$step");
        };
        $this->assertSame(['ok' => false, 'reason' => 'schema verification error: boom:verifyActionSchema'], IntentV2::verifyActionSchema(null, []));
    }
}
