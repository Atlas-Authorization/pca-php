<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/PolicyLink.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PolicyLink;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for PolicyLink (the policy-link vectors alone left these): exact refusal arrays, the length / count
 * boundaries (version 64 UTF-16 units, 32 slots, 64 set values, 256-unit strings, 128-byte digests, integer min / max),
 * host objects that only look like Obj, the splice / matcher guards in fill, and the fail-closed catches.
 */
final class K05KillPolicyLinkTest extends TestCase
{
    private static function o(array $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** A host object that answers keys / has / get like an Obj but is not one. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    /** where conditions using each named slot as a value */
    private static function body(array $names, array $extra = []): array
    {
        return ['predicates' => [['verb' => 'x', 'resource' => 'r', 'where' => array_map(
            static fn ($n) => ['field' => 'f', 'op' => 'eq', 'value' => ['$slot' => $n] + $extra],
            $names
        )]]];
    }

    private static function def(array $slots = ['a' => ['type' => 'string']], ?array $body = null, array $over = []): Obj
    {
        return self::o($over + ['v' => 1, 'kind' => 'pca-policy-template', 'id' => 't', 'version' => '1',
            'slots' => $slots === [] ? new \stdClass() : $slots, 'body' => $body ?? self::body(array_keys($slots))]);
    }

    private static function kp(): KeyPair
    {
        return new KeyPair(str_repeat("\x09", 32));
    }

    private static function signTemplate(Obj $def): Obj
    {
        $msg = PolicyLink::SIG_DOMAIN_TEMPLATE . hash('sha256', PolicyLink::templateDigest($def), true);
        return Obj::of(['def' => $def, 'signer' => self::kp()->public, 'sig' => Pca::b64u(self::kp()->sign($msg))]);
    }

    private static function signOverlay(Obj $ov): Obj
    {
        $msg = PolicyLink::SIG_DOMAIN_TIGHTEN . hash('sha256', Pca::hashCanonical($ov), true);
        return Obj::of(['overlay' => $ov, 'signer' => self::kp()->public, 'sig' => Pca::b64u(self::kp()->sign($msg))]);
    }

    private static function overlay(array $over = []): Obj
    {
        return self::o($over + ['v' => 1, 'kind' => 'pca-template-tighten', 'template_id' => 't', 'version_digest' => 'D']);
    }

    // ---- templateDefError ------------------------------------------------------------------------------------------

    public function testVersionAndKindNeedNumOne(): void
    {
        $this->assertNull(PolicyLink::templateDefError(self::def()));
        $this->assertSame('template v / kind mismatch', PolicyLink::templateDefError(self::def(over: ['v' => 2])));
        $fake = new \stdClass();
        $fake->lexeme = '1'; // a lexeme without being a Num
        $d = self::def();
        $d->set('v', $fake);
        $this->assertSame('template v / kind mismatch', PolicyLink::templateDefError($d));
        $this->assertSame('template v / kind mismatch', PolicyLink::templateDefError(self::def(over: ['kind' => 'other'])));
    }

    public function testVersionIsOneTo64Utf16Units(): void
    {
        $msg = 'template version must be a string of 1..64 characters';
        $this->assertNull(PolicyLink::templateDefError(self::def(over: ['version' => str_repeat('a', 64)])));
        $this->assertSame($msg, PolicyLink::templateDefError(self::def(over: ['version' => str_repeat('a', 65)])));
        $this->assertSame($msg, PolicyLink::templateDefError(self::def(over: ['version' => ''])));
        $this->assertNull(PolicyLink::templateDefError(self::def(over: ['version' => str_repeat('é', 64)])));
        $this->assertSame($msg, PolicyLink::templateDefError(self::def(over: ['version' => str_repeat('é', 65)])));
    }

    public function testSlotsMustBeAnObj(): void
    {
        $d = self::def();
        $d->set('slots', self::lookalike([]));
        $this->assertSame('slots must be an object', PolicyLink::templateDefError($d));
    }

    public function testAtMost32Slots(): void
    {
        $slots = static fn (int $n): array => array_combine(array_map(static fn ($i) => "s$i", range(0, $n - 1)), array_fill(0, $n, ['type' => 'string']));
        $this->assertNull(PolicyLink::templateDefError(self::def($slots(32))));
        $this->assertSame('more than 32 slots', PolicyLink::templateDefError(self::def($slots(33))));
    }

    public function testEachSlotMustBeAnObj(): void
    {
        $d = self::def();
        $d->get('slots')->set('a', self::lookalike(['type' => 'string']));
        $this->assertSame("slot 'a' must be an object", PolicyLink::templateDefError($d));
    }

    public function testAtMost64Values(): void
    {
        $vals = static fn (int $n): array => array_map(static fn ($i) => "v$i", range(0, $n - 1));
        $this->assertNull(PolicyLink::templateDefError(self::def(['a' => ['type' => 'string', 'values' => $vals(64)]])));
        $this->assertSame("slot 'a'.values must be a list of strings", PolicyLink::templateDefError(self::def(['a' => ['type' => 'string', 'values' => $vals(65)]])));
    }

    public function testIntegerBoundsMustBeSafeIntegers(): void
    {
        $this->assertNull(PolicyLink::templateDefError(self::def(['a' => ['type' => 'integer', 'min' => 1, 'max' => 9]])));
        $this->assertSame("slot 'a'.min must be a safe integer", PolicyLink::templateDefError(self::def(['a' => ['type' => 'integer', 'min' => 1.5]])));
        $this->assertSame("slot 'a'.min must be a safe integer", PolicyLink::templateDefError(self::def(['a' => ['type' => 'integer', 'min' => 'x']])));
        $this->assertSame("slot 'a'.max must be a safe integer", PolicyLink::templateDefError(self::def(['a' => ['type' => 'integer', 'max' => 1.5]])));
        // bounds are only read on integer slots
        $this->assertNull(PolicyLink::templateDefError(self::def(['a' => ['type' => 'string', 'min' => 'x']])));
    }

    public function testBodyShape(): void
    {
        $this->assertNull(PolicyLink::templateDefError(self::def([], ['predicates' => []])));
        $d = self::def([], ['predicates' => []]);
        $d->set('body', self::lookalike(['predicates' => []]));
        $this->assertSame('body.predicates must be an array', PolicyLink::templateDefError($d));
        $this->assertSame('body.predicates must be an array', PolicyLink::templateDefError(self::def([], ['caveats' => []])));
        $this->assertSame('body.caveats must be an array', PolicyLink::templateDefError(self::def([], ['predicates' => [], 'caveats' => 'x'])));
    }

    public function testPlaceholderPreAndPostMustBeStrings(): void
    {
        $this->assertSame('placeholder pre must be a string', PolicyLink::templateDefError(self::def(body: self::body(['a'], ['pre' => 1]))));
        $this->assertSame('placeholder post must be a string', PolicyLink::templateDefError(self::def(body: self::body(['a'], ['post' => 1]))));
    }

    public function testUndeclaredSlotNameIsRenderedLikeJavaScript(): void
    {
        $body = static fn ($name): array => ['predicates' => [['verb' => ['$slot' => $name]]]];
        $this->assertSame("placeholder names undeclared slot '5'", PolicyLink::templateDefError(self::def([], $body(5))));
        $this->assertSame("placeholder names undeclared slot 'true'", PolicyLink::templateDefError(self::def([], $body(true))));
        $this->assertSame("placeholder names undeclared slot 'false'", PolicyLink::templateDefError(self::def([], $body(false))));
    }

    // ---- verifyTemplate / tightenOverlayError / verifyTighten -----------------------------------------------------

    public function testVerifyTemplateRefusalsAreExact(): void
    {
        $this->assertSame(['ok' => true], PolicyLink::verifyTemplate(self::signTemplate(self::def()), [self::kp()->public]));
        $this->assertSame(['ok' => false, 'reason' => 'template must be an object'], PolicyLink::verifyTemplate(null, []));
        // a non-canonical number makes the digest throw: fail closed
        $d = self::def();
        $d->get('body')->set('caveats', [Obj::of(['type' => 'rate', 'max' => new Num('1.50')])]);
        $this->assertSame(
            ['ok' => false, 'reason' => 'template verification error (fail closed)'],
            PolicyLink::verifyTemplate(Obj::of(['def' => $d, 'signer' => 'K', 'sig' => 'x']), ['K'])
        );
    }

    public function testTightenOverlayError(): void
    {
        $this->assertNull(PolicyLink::tightenOverlayError(self::overlay()));
        $this->assertNull(PolicyLink::tightenOverlayError(self::overlay(['add_where' => [['field' => 'f']], 'add_caveats' => [['type' => 'rate']]])));
        $this->assertSame('overlay must be an object', PolicyLink::tightenOverlayError(self::lookalike(
            ['v' => new Num('1'), 'kind' => 'pca-template-tighten', 'template_id' => 't', 'version_digest' => 'D']
        )));
        $this->assertSame('overlay v / kind mismatch', PolicyLink::tightenOverlayError(self::overlay(['kind' => 'x'])));
        $this->assertSame(
            "overlay has unknown member 'zz' (an overlay can only add where conditions and caveats)",
            PolicyLink::tightenOverlayError(self::overlay(['zz' => 1]))
        );
        $this->assertSame('overlay template_id invalid', PolicyLink::tightenOverlayError(self::overlay(['template_id' => 'Bad'])));
        $this->assertSame('overlay version_digest invalid', PolicyLink::tightenOverlayError(self::overlay(['version_digest' => ''])));
        $this->assertSame('overlay add_where must be a list of conditions', PolicyLink::tightenOverlayError(self::overlay(['add_where' => ['x']])));
        $this->assertSame('overlay add_caveats must be a list of caveats', PolicyLink::tightenOverlayError(self::overlay(['add_caveats' => [['type' => 5]]])));
        $o = self::overlay();
        $o->set('add_caveats', [self::lookalike(['type' => 'rate'])]);
        $this->assertSame('overlay add_caveats must be a list of caveats', PolicyLink::tightenOverlayError($o));
    }

    public function testVerifyTightenRefusalsAreExact(): void
    {
        $this->assertSame(['ok' => true], PolicyLink::verifyTighten(self::signOverlay(self::overlay()), [self::kp()->public]));
        $this->assertSame(['ok' => false, 'reason' => 'overlay must be an object'], PolicyLink::verifyTighten(null, []));
        $this->assertSame(
            ['ok' => false, 'reason' => 'overlay signer is not trusted'],
            PolicyLink::verifyTighten(Obj::of(['overlay' => self::overlay(), 'signer' => 'S', 'sig' => 'x']), ['T'])
        );
        $ov = self::overlay();
        $ov->set('add_caveats', [Obj::of(['type' => 'rate', 'max' => new Num('1.50')])]);
        $this->assertSame(
            ['ok' => false, 'reason' => 'overlay verification error (fail closed)'],
            PolicyLink::verifyTighten(Obj::of(['overlay' => $ov, 'signer' => 'K', 'sig' => 'x']), ['K'])
        );
    }

    // ---- instantiateTemplate ---------------------------------------------------------------------------------------

    public function testInstantiateRefusalsAreExact(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'template must be an object'], PolicyLink::instantiateTemplate(null, new Obj()));
        $this->assertSame(['ok' => false, 'reason' => 'slots must be an object'], PolicyLink::instantiateTemplate(self::def(), null));
    }

    public function testInstantiateCatchesFailClosed(): void
    {
        $slots = self::o(['a' => 'v']);
        $this->assertTrue(PolicyLink::instantiateTemplate(self::def(), $slots)['ok'], 'control');
        try {
            PolicyLink::$instantiateHook = static function (): void {
                throw new \RuntimeException('boom');
            };
            $this->assertSame(['ok' => false, 'reason' => 'instantiation error (fail closed)'], PolicyLink::instantiateTemplate(self::def(), $slots));
            PolicyLink::$instantiateHook = static function (): void {
                throw new \DomainException('refused here');
            };
            $this->assertSame(['ok' => false, 'reason' => 'refused here'], PolicyLink::instantiateTemplate(self::def(), $slots));
        } finally {
            PolicyLink::$instantiateHook = null;
        }
    }

    public function testStringSlotUpTo256Units(): void
    {
        $r = PolicyLink::instantiateTemplate(self::def(), self::o(['a' => str_repeat('q', 256)]));
        $this->assertTrue($r['ok']);
        $this->assertSame(
            ['ok' => false, 'reason' => "slot 'a' must be a string of 1..256 characters"],
            PolicyLink::instantiateTemplate(self::def(), self::o(['a' => str_repeat('q', 257)]))
        );
    }

    public function testIntegerSlotBoundsAreInclusive(): void
    {
        $d = self::def(['n' => ['type' => 'integer', 'min' => 1, 'max' => 1000]]);
        foreach ([1, 1000] as $n) {
            $r = PolicyLink::instantiateTemplate($d, self::o(['n' => $n]));
            $this->assertTrue($r['ok'], "n=$n");
            $this->assertSame((string)$n, $r['policy']->get('predicates')[0]->get('where')[0]->get('value')->lexeme);
        }
        $this->assertSame(['ok' => false, 'reason' => "slot 'n' is below its minimum"], PolicyLink::instantiateTemplate($d, self::o(['n' => 0])));
        $this->assertSame(['ok' => false, 'reason' => "slot 'n' is above its maximum"], PolicyLink::instantiateTemplate($d, self::o(['n' => 1001])));
    }

    public function testSetSlotUpTo64Members(): void
    {
        $vals = array_map(static fn ($i) => "v$i", range(0, 63));
        $d = self::def(['v' => ['type' => 'set', 'values' => $vals]], ['predicates' => [['verb' => ['$slot' => 'v'], 'resource' => 'r']]]);
        $r = PolicyLink::instantiateTemplate($d, self::o(['v' => $vals]));
        $this->assertTrue($r['ok']);
        $this->assertSame($vals, $r['policy']->get('predicates')[0]->get('verb'));
    }

    public function testMatcherGuardOnlyOnVerbAndResource(): void
    {
        $d = self::def(['vb' => ['type' => 'string']], ['predicates' => [['verb' => ['$slot' => 'vb'], 'resource' => 'r']]]);
        $this->assertSame(
            ['ok' => false, 'reason' => "slot 'vb' would inject a wildcard or regex matcher into a verb or resource"],
            PolicyLink::instantiateTemplate($d, self::o(['vb' => 'mail.*']))
        );
        // a where value is not a matcher: a wildcard passes through untouched
        $r = PolicyLink::instantiateTemplate(self::def(), self::o(['a' => 'a*']));
        $this->assertTrue($r['ok']);
        $this->assertSame('a*', $r['policy']->get('predicates')[0]->get('where')[0]->get('value'));
    }

    public function testPreAloneSplices(): void
    {
        $d = self::def(['a' => ['type' => 'string']], ['predicates' => [['verb' => 'x', 'resource' => ['$slot' => 'a', 'pre' => '/x/']]]]);
        $r = PolicyLink::instantiateTemplate($d, self::o(['a' => 'y']));
        $this->assertTrue($r['ok']);
        $this->assertSame('/x/y', $r['policy']->get('predicates')[0]->get('resource'));
    }

    public function testSpliceRefusesAWildcard(): void
    {
        $d = self::def(body: self::body(['a'], ['pre' => 'p-']));
        $this->assertSame(
            ['ok' => false, 'reason' => "slot 'a' cannot be spliced into a string (wildcard or non-string)"],
            PolicyLink::instantiateTemplate($d, self::o(['a' => 'a*']))
        );
        $r = PolicyLink::instantiateTemplate($d, self::o(['a' => 're:x']));
        $this->assertTrue($r['ok']); // a prefix means the result cannot start with re:
        $this->assertSame('p-re:x', $r['policy']->get('predicates')[0]->get('where')[0]->get('value'));
    }

    public function testSpliceWithoutPrefixRefusesARegex(): void
    {
        $d = self::def(body: self::body(['a'], ['post' => '-s']));
        $this->assertSame(
            ['ok' => false, 'reason' => "slot 'a' would inject a regex matcher"],
            PolicyLink::instantiateTemplate($d, self::o(['a' => 're:x']))
        );
        $r = PolicyLink::instantiateTemplate($d, self::o(['a' => 'abc']));
        $this->assertTrue($r['ok']);
        $this->assertSame('abc-s', $r['policy']->get('predicates')[0]->get('where')[0]->get('value'));
    }

    // ---- templateRefError / resolveLink ----------------------------------------------------------------------------

    public function testTemplateRefError(): void
    {
        $ref = static fn (array $over = []) => self::o($over + ['template_id' => 't', 'version_digest' => 'D', 'slots' => ['a' => 'x']]);
        $this->assertNull(PolicyLink::templateRefError($ref()));
        $this->assertSame('template_ref must be an object', PolicyLink::templateRefError(self::lookalike(
            ['template_id' => 't', 'version_digest' => 'D', 'slots' => Obj::of(['a' => 'x'])]
        )));
        $this->assertSame('template_ref.template_id invalid', PolicyLink::templateRefError($ref(['template_id' => 'Bad'])));
        $this->assertNull(PolicyLink::templateRefError($ref(['version_digest' => str_repeat('d', 128)])));
        $this->assertSame('template_ref.version_digest invalid', PolicyLink::templateRefError($ref(['version_digest' => str_repeat('d', 129)])));
        $this->assertSame('template_ref.version_digest invalid', PolicyLink::templateRefError($ref(['version_digest' => ''])));
        $bound = static fn (string $d) => self::o(['template_id' => 't', 'version_digest' => 'D', 'bind_params_digest' => $d]);
        $this->assertNull(PolicyLink::templateRefError($bound(str_repeat('b', 128))));
        $this->assertSame('template_ref.bind_params_digest invalid', PolicyLink::templateRefError($bound(str_repeat('b', 129))));
    }

    /** @return array{0: Obj, 1: Obj, 2: string, 3: Obj} [ref, registry, digest, signed template] */
    private static function link(): array
    {
        $def = self::def();
        $dg = PolicyLink::templateDigest($def);
        $t = self::signTemplate($def);
        $ref = Obj::of(['template_id' => 't', 'version_digest' => $dg, 'slots' => Obj::of(['a' => 'x'])]);
        return [$ref, Obj::of(['templates' => Obj::of([$dg => $t]), 'trusted' => [self::kp()->public]]), $dg, $t];
    }

    public function testResolveRefusalsAreExact(): void
    {
        [$ref, $reg, $dg, $t] = self::link();
        $r = PolicyLink::resolveLink($ref, $reg);
        $this->assertTrue($r['ok']);
        $this->assertSame(0, $r['overlays']);
        $this->assertSame(['ok' => false, 'reason' => 'template_ref must be an object'], PolicyLink::resolveLink(null, $reg));
        $this->assertSame(
            ['ok' => false, 'reason' => 'template version is not in the registry'],
            PolicyLink::resolveLink($ref, Obj::of(['templates' => self::lookalike([$dg => $t]), 'trusted' => [self::kp()->public]]))
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'registry entry does not match its digest'],
            PolicyLink::resolveLink(Obj::of(['template_id' => 't', 'version_digest' => 'X', 'slots' => Obj::of(['a' => 'x'])]),
                Obj::of(['templates' => Obj::of(['X' => $t]), 'trusted' => [self::kp()->public]]))
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'template id does not match the reference'],
            PolicyLink::resolveLink(Obj::of(['template_id' => 'other', 'version_digest' => $dg, 'slots' => Obj::of(['a' => 'x'])]), $reg)
        );
        // no trusted list: verifyTemplate cannot be called (TypeError) and the resolution fails closed
        $this->assertSame(
            ['ok' => false, 'reason' => 'link resolution error (fail closed)'],
            PolicyLink::resolveLink($ref, Obj::of(['templates' => Obj::of([$dg => $t])]))
        );
    }

    public function testOverlaysThatAreNotObjectsAreSkipped(): void
    {
        [$ref, $reg] = self::link();
        $reg->set('overlays', [null, Obj::of(['overlay' => 'x'])]);
        $r = PolicyLink::resolveLink($ref, $reg);
        $this->assertTrue($r['ok']);
        $this->assertSame(0, $r['overlays']);
    }

    public function testAnOverlayForAnotherVersionDoesNotStopTheScan(): void
    {
        [$ref, $reg, $dg] = self::link();
        $other = Obj::of(['overlay' => self::overlay(['version_digest' => 'other'])]);
        $mine = self::signOverlay(self::overlay(['version_digest' => $dg, 'add_where' => [['field' => 'g', 'op' => 'eq', 'value' => '1']]]));
        $reg->set('overlays', [$other, $mine]);
        $r = PolicyLink::resolveLink($ref, $reg);
        $this->assertTrue($r['ok']);
        $this->assertSame(1, $r['overlays']);
        $this->assertCount(2, $r['policy']->get('predicates')[0]->get('where'));
    }
}
