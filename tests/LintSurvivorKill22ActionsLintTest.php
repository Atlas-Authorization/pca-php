<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsLint;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsLint.php';

/** The action lint rules: each finding keeps its rule, param, exact message and sorted position. */
final class LintSurvivorKill22ActionsLintTest extends TestCase
{
    private const BASE = '{"v":1,"kind":"pca-action-def","verb":"a.b.read","title":"Read a file","description":"Reads files.","effects":["read"],'
        . '"resource":{"type":"files.file","id":"*","scope":"set"},"params":{"path":{"type":"string","max_len":4096}},'
        . '"reversibility":"reversible","blast":{"radius":"one","ppm":50000},"review":{"state":"authored"},"since":"0.5.0"}';

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    /** The base def with members replaced (JSON text) or removed (null). @param array<string,?string> $over */
    private static function def(array $over = []): Obj
    {
        $d = self::j(self::BASE);
        foreach ($over as $k => $v) {
            if ($v === null) {
                $d = $d->without($k);
            } else {
                $d->set($k, self::j($v));
            }
        }
        return $d;
    }

    /** A write def (effects update, not reversible) with these members. @param array<string,?string> $over */
    private static function write(array $over = []): Obj
    {
        return self::def($over + ['verb' => '"a.b.update"', 'title' => '"Update a file"', 'effects' => '["update"]', 'reversibility' => '"rate_limited"']);
    }

    /** @param list<mixed> $defs @return list<array<string,mixed>> */
    private static function only(string $rule, array $defs, ?Obj $opts = null, ?\Closure $verifier = null): array
    {
        return array_values(array_filter(ActionsLint::lintDefs($defs, $opts, $verifier), static fn(array $f): bool => $f['rule'] === $rule));
    }

    private static function f(string $rule, string $sev, string $verb, string $msg, ?string $param = null): array
    {
        $f = ['rule' => $rule, 'severity' => $sev, 'verb' => $verb];
        if ($param !== null) {
            $f['param'] = $param;
        }
        $f['message'] = $msg;
        return $f;
    }

    /** The base def is clean, so every finding below comes from the member under test. */
    public function testBaseIsClean(): void
    {
        $this->assertSame([], ActionsLint::lintDefs([self::def()]));
    }

    /** A non-object param does not hide a later param's unknown role; a vocabulary failure does not stop later defs being linted. */
    public function testVocabularyKeepsScanning(): void
    {
        $bad = self::def(['params' => '{"a":5,"b":{"type":"string","role":"Bad Role"}}']);
        $this->assertSame([self::f('LD-007', 'error', 'a.b.read', "b: unknown role 'Bad Role'")], ActionsLint::lintDefs([$bad]));
        $vocab = self::j('{"verb":"zzz","effects":["bogus"]}');
        $this->assertSame([self::f('LW-010', 'warning', 'a.b.read', 'since is missing')], self::only('LW-010', [$vocab, self::def(['since' => null])]));
    }

    /** Findings that compare equal keep their input order (a missing verb sorts as ''), in pairs and triples. */
    public function testEqualFindingsKeepTheirOrder(): void
    {
        $noVerb = ['rule' => 'LD-007', 'severity' => 'error', 'message' => "unknown effect 'bogus'"];
        $empty = ['rule' => 'LD-007', 'severity' => 'error', 'verb' => '', 'message' => "unknown effect 'bogus'"];
        $z = ['rule' => 'LD-007', 'severity' => 'error', 'verb' => 'zzz', 'message' => "unknown effect 'bogus'"];
        $a = self::j('{"verb":5,"effects":["bogus"]}');
        $b = self::j('{"verb":"","effects":["bogus"]}');
        $c = self::j('{"verb":"zzz","effects":["bogus"]}');
        $this->assertSame([$noVerb, $empty], ActionsLint::lintDefs([$a, $b]));
        $this->assertSame([$noVerb, $empty, $z], ActionsLint::lintDefs([$c, $a, $b]));
    }

    /** Findings of one rule sort by param before message, whichever order they were raised in. */
    public function testFindingsSortByParamThenMessage(): void
    {
        $d = self::write(['params' => '{"a":{"type":"integer","max":5},"b":{"type":"integer","min":1}}']);
        $this->assertSame([
            self::f('LD-003', 'error', 'a.b.update', 'a numeric parameter needs both min and max (has no min, max)', 'a'),
            self::f('LD-003', 'error', 'a.b.update', 'a numeric parameter needs both min and max (has min, no max)', 'b'),
        ], self::only('LD-003', [$d]));
        $m = self::write(['params' => '{"z":{"type":"integer","role":"money.amount","min":1,"max":5},"a":{"type":"string","role":"money.currency","max_len":3}}']);
        $this->assertSame([
            self::f('LD-002', 'error', 'a.b.update', 'a currency parameter needs the iso_currency format', 'a'),
            self::f('LD-002', 'error', 'a.b.update', 'a money parameter needs a unit of kind money with a currency', 'z'),
        ], self::only('LD-002', [$m]));
    }

    /** A currency taken from a param passes only with role money.currency and format iso_currency. */
    public function testCurrencyParameterReference(): void
    {
        $p = fn(string $cur) => self::write(['params' => '{"amount":{"type":"integer","role":"money.amount","min":1,"max":5,"unit":{"kind":"money","ccy":{"from":"cur"},"exp":2}},"cur":' . $cur . '}']);
        $this->assertSame([], self::only('LD-002', [$p('{"type":"string","role":"money.currency","format":"iso_currency","max_len":3}')]));
        $this->assertSame([self::f('LD-002', 'error', 'a.b.update', "the currency parameter 'cur' needs role money.currency and format iso_currency", 'amount')],
            self::only('LD-002', [$p('{"type":"string","format":"iso_currency","max_len":3}')]));
    }

    /** id roles and a bounded count.limit skip the min/max rule; later integer params are still checked. */
    public function testNumericBoundsSkips(): void
    {
        $d = self::write(['params' => '{"a":{"type":"integer","role":"id.foo"},"b":{"type":"integer","role":"count.limit","max":5},"c":{"type":"integer"}}']);
        $this->assertSame([self::f('LD-003', 'error', 'a.b.update', 'a numeric parameter needs both min and max (has no min, no max)', 'c')], self::only('LD-003', [$d]));
    }

    /** A money_moving trait alone (no pay effect) still needs idempotency. */
    public function testMoneyMovingTraitNeedsIdempotency(): void
    {
        $this->assertSame([self::f('LD-004', 'error', 'a.b.update', 'a money-moving action needs idempotency key_param or natural')],
            self::only('LD-004', [self::write(['traits' => '["pca.money_moving"]'])]));
    }

    /** Personal data: pii tag, contact.* and person.* roles count; other roles do not; params are listed in name order. */
    public function testPersonalDataMustMatchEffects(): void
    {
        $send = fn(string $params, array $over = []) => self::only('LD-005', [self::write(['verb' => '"a.b.send"', 'params' => $params] + $over)]);
        $sent = fn(string $list, string $verb = 'a.b.send') => [self::f('LD-005', 'error', $verb, "personal data can be sent ($list) but effects do not include send")];
        $this->assertSame([], $send('{"n":{"type":"string","max_len":9},"u":{"type":"string","role":"url.target","format":"url","max_len":9}}'));
        $this->assertSame($sent('t'), $send('{"t":{"type":"string","max_len":9,"tags":["pii"]}}'));
        $this->assertSame($sent('e'), $send('{"e":{"type":"string","role":"contact.email","format":"email","max_len":9}}'));
        $this->assertSame($sent('p'), $send('{"p":{"type":"string","role":"person.name","max_len":9}}'));
        $this->assertSame($sent('a, z'), $send('{"z":{"type":"string","role":"contact.email","format":"email","max_len":9},"a":{"type":"string","max_len":9,"tags":["pii"]}}'));
        $pii = '{"a":{"type":"string","max_len":9,"tags":["pii"]}}';
        $this->assertSame([self::f('LD-005', 'error', 'a.b.export', 'personal data can be exported (a) but effects do not include export')],
            self::only('LD-005', [self::write(['verb' => '"a.b.export"', 'params' => $pii])]));
        $this->assertSame([self::f('LD-005', 'error', 'a.b.update', 'personal data can be exported (a) but effects do not include export')],
            self::only('LD-005', [self::write(['params' => $pii, 'side_effects' => '[{"target":"t","kind":"export"}]'])]));
        $this->assertSame($sent('a', 'a.b.update'), self::only('LD-005', [self::write(['params' => $pii, 'side_effects' => '[{"target":"t","kind":"send"}]'])]));
    }

    /** Resource id '*' is flagged only with scope one. */
    public function testWildcardWithScopeOne(): void
    {
        $this->assertSame([], self::only('LD-008', [self::def(['resource' => '{"type":"files.file","id":{"prefix":"","class":"any_safe","len":[1,128]},"scope":"set"}'])]));
        $this->assertSame([self::f('LD-008', 'error', 'a.b.read', "resource id '*' with scope one names every resource at once")],
            self::only('LD-008', [self::def(['resource' => '{"type":"files.file","id":"*","scope":"one"}'])]));
    }

    /** A reversible write whose compensating action only reads is flagged with the shape's reason; an alias equal to another verb collides. */
    public function testCompensationAndAliasCollision(): void
    {
        $w = self::write(['reversibility' => '"reversible"', 'compensates' => '"a.b.read"']);
        $this->assertSame([self::f('LD-010', 'error', 'a.b.update', "compensates 'a.b.read', which cannot undo it: the compensating action a.b.read only reads")],
            self::only('LD-010', [$w, self::def()]));
        $this->assertSame([self::f('LD-009', 'error', 'c.d.read', "'a.b.read' is also a name of 'a.b.read'")],
            self::only('LD-009', [self::def(), self::def(['verb' => '"c.d.read"', 'aliases' => '["a.b.read"]'])]));
    }

    /** Shared graphql, grpc and asyncapi bindings name the exact binding key. */
    public function testSharedBindingsNameTheKey(): void
    {
        $b = '{"graphql":{"op":"query","field":"users"},"grpc":{"service":"S","method":"M"},"asyncapi":{"channel":"ch","op":"send"}}';
        $this->assertSame([
            self::f('LD-014', 'error', 'c.d.read', "binding asyncapi:send ch is also bound by 'a.b.read'"),
            self::f('LD-014', 'error', 'c.d.read', "binding graphql:query.users is also bound by 'a.b.read'"),
            self::f('LD-014', 'error', 'c.d.read', "binding grpc:S/M is also bound by 'a.b.read'"),
        ], self::only('LD-014', [self::def(['bindings' => $b]), self::def(['verb' => '"c.d.read"', 'bindings' => $b])]));
    }

    /** A confirmed def whose digests match needs a signature (no verifier) or a truthy verifier. */
    public function testConfirmedAttestationSignature(): void
    {
        $confirmed = static function (bool $sig): Obj {
            $d = self::def();
            $att = Obj::of(['def_digest' => Actions::defDigest($d), 'traits_digest' => Actions::traitsDigest(Actions::coreRegistry()), 'facts_digest' => 'F',
                'final_traits' => [], 'dismissed' => [], 'reviewer_kid' => 'k', 'ts' => new \Atlas\Pca\Num('1')]);
            if ($sig) {
                $att->set('sig', 'S');
            }
            $d->set('review', Obj::of(['state' => 'confirmed', 'attestation' => $att]));
            return $d;
        };
        $unsigned = [self::f('LD-011', 'error', 'a.b.read', 'the attestation is not signed by a pinned reviewer')];
        $this->assertSame($unsigned, self::only('LD-011', [$confirmed(false)]));
        $this->assertSame([], self::only('LD-011', [$confirmed(true)]));
        $this->assertSame([], self::only('LD-011', [$confirmed(false)], null, static fn(): bool => true));
        $this->assertSame($unsigned, self::only('LD-011', [$confirmed(true)], null, static fn(): bool => false));
    }

    /** A read-only def may not take code, a query or a credential; sandbox_attested clears only the code/query rule. */
    public function testReadOnlyDefsCannotMutate(): void
    {
        $params = '{"c":{"type":"string","role":"code.command","max_len":9},"k":{"type":"string","max_len":9,"tags":["credential"]},"q":{"type":"string","role":"query.sql","max_len":9}}';
        $code = 'a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)';
        $cred = self::f('LD-013', 'error', 'a.b.read', 'a read-only action handles a credential', 'k');
        $this->assertSame([self::f('LD-013', 'error', 'a.b.read', $code, 'c'), $cred, self::f('LD-013', 'error', 'a.b.read', $code, 'q')],
            self::only('LD-013', [self::def(['params' => $params])]));
        $this->assertSame([$cred], self::only('LD-013', [self::def(['params' => $params, 'context' => '["sandbox_attested"]'])]));
        $this->assertSame([], self::only('LD-013', [self::write(['params' => $params])]));
    }

    /** Description length bound at exactly 400 bytes, and the imperative-title heuristics. */
    public function testDescriptionAndTitle(): void
    {
        $this->assertSame([], self::only('LW-001', [self::def(['description' => '"' . str_repeat('x', 400) . '"'])]));
        $this->assertSame([self::f('LW-001', 'warning', 'a.b.read', 'description is longer than 400 bytes')], self::only('LW-001', [self::def(['description' => '"' . str_repeat('x', 401) . '"'])]));
        foreach (['Sends mail', 'Updated thing', 'A thing', 'An item', 'The item'] as $t) {
            $this->assertSame([self::f('LW-001', 'warning', 'a.b.read', "title '$t' is not imperative")], self::only('LW-001', [self::def(['title' => '"' . $t . '"'])]), $t);
        }
        foreach (['Status report', 'Read a file'] as $t) {
            $this->assertSame([], self::only('LW-001', [self::def(['title' => '"' . $t . '"'])]), $t);
        }
    }

    /** Unreviewed and suggested defs warn only in a stable pack. */
    public function testUnreviewedInStablePack(): void
    {
        $stable = Obj::of(['stability' => 'stable']);
        foreach (['unreviewed', 'suggested'] as $s) {
            $d = self::def(['review' => '{"state":"' . $s . '"}']);
            $this->assertSame([self::f('LW-004', 'warning', 'a.b.read', "a $s def in a stable pack")], self::only('LW-004', [$d], $stable), $s);
            $this->assertSame([], self::only('LW-004', [$d]), $s);
        }
    }

    /** A dismissal reason is trimmed of JavaScript whitespace at both ends before its 5-character minimum is checked. */
    public function testDismissalReasonIsTrimmed(): void
    {
        $mk = static function (string $reason): Obj {
            $a = self::j('{"def_digest":"D","traits_digest":"T","facts_digest":"F","final_traits":[],"reviewer_kid":"k","ts":1}');
            $a->set('dismissed', [Obj::of(['trait' => 'pca.bulk', 'reason' => $reason])]);
            $x = self::def();
            $x->set('review', Obj::of(['state' => 'authored', 'attestation' => $a]));
            return $x;
        };
        $warn = [self::f('LW-005', 'warning', 'a.b.read', 'dismissed trait pca.bulk has no reason')];
        $this->assertSame($warn, self::only('LW-005', [$mk('    abcd')]));
        $this->assertSame($warn, self::only('LW-005', [$mk('abcd    ')]));
        $this->assertSame([], self::only('LW-005', [$mk('abcde')]));
    }

    /** An array without max_items warns; a set with max_items does not. */
    public function testArrayWithoutMaxItems(): void
    {
        $d = self::def(['params' => '{"a":{"type":"array","items":"string"},"s":{"type":"set","values":["x"],"max_items":1}}']);
        $this->assertSame([self::f('LW-006', 'warning', 'a.b.read', 'an array parameter without max_items', 'a')], self::only('LW-006', [$d]));
    }

    /** Warnings fail only under strict, also for plain-array findings; an unknown rule id is refused. */
    public function testFailsTextAndSeverity(): void
    {
        $w = [['rule' => 'LW-001', 'severity' => 'warning', 'message' => 'm']];
        $this->assertFalse(ActionsLint::lintFails($w));
        $this->assertTrue(ActionsLint::lintFails($w, true));
        $note = ['rule' => 'LN-001', 'severity' => 'note', 'message' => 'm'];
        $this->assertSame("note    LN-001  m\n0 errors, 0 warnings, 1 note", ActionsLint::lintText([$note]));
        $this->assertSame("note    LN-001  m\nnote    LN-001  m\n0 errors, 0 warnings, 2 notes", ActionsLint::lintText([$note, $note]));
        try {
            (new \ReflectionMethod(ActionsLint::class, 'severity'))->invoke(null, 'LX-999');
            $this->fail('no refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('unknown lint rule LX-999', $e->getMessage());
        }
    }
}
