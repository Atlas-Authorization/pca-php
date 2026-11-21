<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentV2Schema.php (second batch): v2 duration min/max, the v2 `harm` object check,
 * formatCheck arms, formatViolation on a non-object declaration, object_ref max_len, schemaVerb's string-verb guard.
 */
final class K05KillIntentV2Schema2Test extends TestCase
{
    private const B32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    private const P = "verb 'v': action.params.x: ";

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
    }

    /** actionSchemaShapeError of a well-formed unsigned v2 schema with one verb `v` (param `action.params.x`), overridden. */
    private static function shape(array $verb = [], array $param = []): ?string
    {
        $p = array_merge(['type' => 'string', 'semantic' => 's', 'sensitivity' => 'free'], $param);
        $v = array_merge(['verb' => 'v', 'kind' => 'write', 'params' => ['action.params.x' => $p], 'effects' => ['create'],
            'traits' => [], 'def' => self::B32, 'floors' => ['risk' => 0, 'rev' => 'reversible', 'blast_ppm' => 0, 'esc' => 0,
                'caveats' => [], 'context' => [], 'prules' => []]], $verb);
        return IntentV2::actionSchemaShapeError(self::o(['v' => 2, 'kind' => 'pca-action-schema', 'site' => 's', 'aud' => 'a',
            'version' => '1', 'verbs' => [$v]]), false);
    }

    public function testV2DurationTakesMinMaxOtherTypesDoNot(): void
    {
        $this->assertNull(self::shape(param: ['type' => 'duration', 'min' => 5]));
        $this->assertNull(self::shape(param: ['type' => 'duration', 'max' => 10]));
        $this->assertSame(self::P . 'min must be a safe integer on an integer parameter', self::shape(param: ['min' => 5]));
        $this->assertSame(self::P . 'max must be a safe integer on an integer parameter', self::shape(param: ['type' => 'boolean', 'max' => 5]));
    }

    public function testV2HarmMustBeAnObject(): void
    {
        $this->assertNull(self::shape(['harm' => new \stdClass()]));
        $this->assertSame("verb 'v': harm must be an object", self::shape(['harm' => 5]));
        $this->assertSame("verb 'v': returns must be an object", self::shape(['returns' => 5]));
    }

    public function testFormatCheckArms(): void
    {
        $this->assertNull(IntentV2::formatCheck('nope'));
        $cases = [
            'email' => ['a@b.co', 'https://b.co'],
            'url' => ['https://b.co', 'a@b.co'],
            'uri_https' => ['https://b.co', 'http://b.co'],
            'uuid' => [implode('-', [str_repeat('0', 8), '0000', '0000', '0000', str_repeat('0', 12)]), 'x'], // built, so the scrub sees no GUID
            'phone_e164' => ['+14155550100', '14155550100'],
            'iso_country' => ['GB', 'GBR'],
            'iso_currency' => ['GBP', 'GB'],
            'semver' => ['1.2.3', '1.2'],
            'sha256' => [str_repeat('a', 64), str_repeat('a', 63)],
            'id:x' => ['A.b:c-1', 'a b'],
        ];
        foreach ($cases as $f => [$ok, $bad]) {
            $ck = IntentV2::formatCheck($f);
            $this->assertNotNull($ck, $f);
            $this->assertTrue($ck($ok), "$f accepts $ok");
            $this->assertFalse($ck($bad), "$f refuses $bad");
        }
    }

    public function testFormatViolationOfANonObjectDeclarationIsNull(): void
    {
        $fv = new \ReflectionMethod(IntentV2::class, 'formatViolation');
        $this->assertNull($fv->invoke(null, 5, 'x'));
        $this->assertNull($fv->invoke(null, self::o(['type' => 'string']), 'x'));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'not a valid email'], $fv->invoke(null, self::o(['format' => 'email']), 'x'));
    }

    public function testObjectRefMaxLenBoundary(): void
    {
        $d = self::o(['type' => 'object_ref', 'max_len' => 3]);
        $this->assertNull(IntentV2::paramValueViolation($d, 'abc'));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'longer than 3 UTF-8 bytes'], IntentV2::paramValueViolation($d, 'abcd'));
        $dflt = self::o(['type' => 'object_ref']);
        $this->assertNull(IntentV2::paramValueViolation($dflt, str_repeat('a', IntentV2::DEFAULT_MAX_LEN)));
        $this->assertSame(['code' => 'out_of_domain', 'reason' => 'longer than 1024 UTF-8 bytes'],
            IntentV2::paramValueViolation($dflt, str_repeat('a', IntentV2::DEFAULT_MAX_LEN + 1)));
    }

    public function testSchemaVerbNeedsAStringVerb(): void
    {
        $doc = self::o(['verbs' => [5, ['verb' => null], ['verb' => 'a']]]);
        $this->assertSame(IntentV2::undef(), IntentV2::schemaVerb($doc, null));
        $this->assertSame('a', IntentV2::schemaVerb($doc, 'a')->get('verb'));
        $this->assertSame(IntentV2::undef(), IntentV2::schemaVerb($doc, 'b'));
    }
}
