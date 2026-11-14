<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Exact results of the forbid-wins clause / condition / trigger checks (reference: forbid-certificate.ts, prohibitions.ts). */
final class ForbidCertificateMutationSurvivorsTest extends TestCase
{
    private const LEAF = '{"field":"f","op":"eq"}';

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function nest(string $kind, int $n): string
    {
        $x = self::LEAF;
        for ($i = 0; $i < $n; $i++) {
            $x = $kind === 'not' ? '{"not":' . $x . '}' : '{"' . $kind . '":[' . $x . ']}';
        }
        return $x;
    }

    private static function ctx(string $verb = 'read', string $resource = 'doc'): Obj
    {
        return self::j(json_encode(['action' => ['verb' => $verb, 'resource' => $resource]], JSON_THROW_ON_ERROR));
    }

    // ---- clausesError ----------------------------------------------------------------------------------------------

    public function testDuplicateIdIsRefused(): void
    {
        $c = self::j('[{"id":"a","kind":"permit","when":{}},{"id":"a","kind":"forbid","when":{}}]');
        $this->assertSame("clauses[1].id 'a' is a duplicate", ForbidCertificate::clausesError($c));
        $ok = self::j('[{"id":"a","kind":"permit","when":{}},{"id":"b","kind":"forbid","when":{}}]');
        $this->assertNull(ForbidCertificate::clausesError($ok));
    }

    // ---- conditionError --------------------------------------------------------------------------------------------

    public function testNonObjectCondition(): void
    {
        $this->assertSame('condition not an object', ForbidCertificate::conditionError('x'));
        $this->assertSame('condition not an object', ForbidCertificate::conditionError([self::j(self::LEAF)]));
        $this->assertSame('condition not an object', ForbidCertificate::conditionError(null));
    }

    public function testNestingDepthBoundaryForEveryGrouping(): void
    {
        foreach (['not', 'all_of', 'any_of'] as $kind) {
            $this->assertNull(ForbidCertificate::conditionError(self::j(self::nest($kind, 32))), "$kind at depth 32");
            $this->assertSame('condition nesting too deep', ForbidCertificate::conditionError(self::j(self::nest($kind, 33))), "$kind at depth 33");
        }
        // an explicit starting depth is honoured
        $this->assertNull(ForbidCertificate::conditionError(self::j(self::LEAF), 32));
        $this->assertSame('condition nesting too deep', ForbidCertificate::conditionError(self::j(self::LEAF), 33));
        // the default starting depth is 0: a lone leaf is fine and 32 wrappers still fit
        $this->assertNull(ForbidCertificate::conditionError(self::j(self::LEAF)));
    }

    public function testGroupingForms(): void
    {
        $this->assertSame('condition.all_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"all_of":[]}')));
        $this->assertSame('condition.any_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"any_of":[]}')));
        $this->assertSame('condition.all_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"all_of":{}}')));
        $this->assertSame('condition.any_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"any_of":"x"}')));
        $this->assertSame('condition.all_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"all_of":null}')));
        // a non-list array (only reachable from PHP) is not an array in the reference
        $assoc = Obj::of(['all_of' => ['x' => self::j(self::LEAF)]]);
        $this->assertSame('condition.all_of must be a non-empty array', ForbidCertificate::conditionError($assoc));
        // all_of wins the key choice when both are present
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"all_of":[' . self::LEAF . '],"any_of":[]}')));
        $this->assertSame('condition.any_of must be a non-empty array', ForbidCertificate::conditionError(self::j('{"any_of":[],"x":1}')));
        // not wins over the lists
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"not":' . self::LEAF . ',"all_of":[]}')));
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"not":' . self::LEAF . '}')));
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"not":{"op":"eq"}}')));
        // a child error is returned, from the first bad child
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"all_of":[' . self::LEAF . ',{"op":"eq"},{"field":"f"}]}')));
        $this->assertSame('unknown condition op bogus', ForbidCertificate::conditionError(self::j('{"any_of":[{"field":"f","op":"bogus"}]}')));
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"all_of":[' . self::LEAF . ',' . self::LEAF . ']}')));
    }

    public function testLeafField(): void
    {
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"op":"eq"}')));
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"field":"","op":"eq"}')));
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"field":5,"op":"eq"}')));
        $this->assertSame('condition.field missing', ForbidCertificate::conditionError(self::j('{"field":null,"op":"eq"}')));
    }

    public function testLeafOpMessages(): void
    {
        $this->assertSame('unknown condition op bogus', ForbidCertificate::conditionError(self::j('{"field":"f","op":"bogus"}')));
        $this->assertSame('unknown condition op undefined', ForbidCertificate::conditionError(self::j('{"field":"f"}')));
        $this->assertSame('unknown condition op null', ForbidCertificate::conditionError(self::j('{"field":"f","op":null}')));
        $this->assertSame('unknown condition op 5', ForbidCertificate::conditionError(self::j('{"field":"f","op":5}')));
        $this->assertSame('unknown condition op true', ForbidCertificate::conditionError(self::j('{"field":"f","op":true}')));
        $this->assertSame('unknown condition op [object Object]', ForbidCertificate::conditionError(self::j('{"field":"f","op":{}}')));
        $this->assertSame('unknown condition op a,b', ForbidCertificate::conditionError(self::j('{"field":"f","op":["a","b"]}')));
        $this->assertSame('unknown condition op ', ForbidCertificate::conditionError(self::j('{"field":"f","op":""}')));
        foreach (['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists', 'like', 'matches', 'is_a', 'member_of'] as $op) {
            $this->assertNull(ForbidCertificate::conditionError(self::j('{"field":"f","op":"' . $op . '"}')), $op);
        }
    }

    public function testLeafRefAndCollection(): void
    {
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"field":"f","op":"eq","ref":"r"}')));
        $this->assertNull(ForbidCertificate::conditionError(self::j(self::LEAF)));
        foreach (['""', '5', 'null', 'true', '{}', '[]'] as $bad) {
            $this->assertSame('bad condition.ref', ForbidCertificate::conditionError(self::j('{"field":"f","op":"eq","ref":' . $bad . '}')), $bad);
        }
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"field":"f","op":"member_of","collection":"c"}')));
        $this->assertNull(ForbidCertificate::conditionError(self::j('{"field":"f","op":"member_of"}')));
        foreach (['""', '5', 'null', 'true', '{}'] as $bad) {
            $this->assertSame('bad condition.collection', ForbidCertificate::conditionError(self::j('{"field":"f","op":"member_of","collection":' . $bad . '}')), $bad);
            $this->assertNull(ForbidCertificate::conditionError(self::j('{"field":"f","op":"eq","collection":' . $bad . '}')), "eq $bad");
        }
    }

    // ---- whenError -------------------------------------------------------------------------------------------------

    public function testWhenErrorNotAnObject(): void
    {
        $this->assertSame('when: not an object', ForbidCertificate::whenError('x'));
        $this->assertSame('when: not an object', ForbidCertificate::whenError(null));
        $this->assertSame('p: not an object', ForbidCertificate::whenError([1], 'p'));
    }

    public function testWhenErrorVerb(): void
    {
        $bad = ['{}', '{"verb":""}', '{"verb":5}', '{"verb":null}', '{"verb":[]}', '{"verb":[""]}', '{"verb":["a",""]}', '{"verb":["a",5]}', '{"verb":{}}', '{"verb":true}'];
        foreach ($bad as $b) {
            $this->assertSame('when: bad verb', ForbidCertificate::whenError(self::j($b)), $b);
        }
        $this->assertSame('q: bad verb', ForbidCertificate::whenError(self::j('{}'), 'q'));
        $this->assertSame('when: bad verb', ForbidCertificate::whenError(Obj::of(['verb' => ['x' => 'a']])));
        foreach (['{"verb":"read"}', '{"verb":["a"]}', '{"verb":["a","b"]}'] as $ok) {
            $this->assertNull(ForbidCertificate::whenError(self::j($ok)), $ok);
        }
    }

    public function testWhenErrorResource(): void
    {
        $this->assertSame('when: bad resource', ForbidCertificate::whenError(self::j('{"verb":"v","resource":5}')));
        $this->assertSame('when: bad resource', ForbidCertificate::whenError(self::j('{"verb":"v","resource":null}')));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"files/x"}')));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"*"}')));
        $this->assertSame('when: unsafe regex resource', ForbidCertificate::whenError(self::j('{"verb":"v","resource":"re:(a+)+"}')));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"re:a"}')));
        // the pattern is the text after "re:" and is at most 200 UTF-16 units
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"re:' . str_repeat('a', 200) . '"}')));
        $this->assertSame('when: unsafe regex resource', ForbidCertificate::whenError(self::j('{"verb":"v","resource":"re:' . str_repeat('a', 201) . '"}')));
        // a plain (non re:) resource is never length-checked as a regex
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"' . str_repeat('a', 300) . '"}')));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","resource":"' . str_repeat('(a+)+', 60) . '"}')));
    }

    public function testWhenErrorWhere(): void
    {
        $this->assertSame('when: where not an array', ForbidCertificate::whenError(self::j('{"verb":"v","where":"x"}')));
        $this->assertSame('when: where not an array', ForbidCertificate::whenError(self::j('{"verb":"v","where":{}}')));
        $this->assertSame('when: where not an array', ForbidCertificate::whenError(self::j('{"verb":"v","where":null}')));
        $this->assertSame('t: where not an array', ForbidCertificate::whenError(self::j('{"verb":"v","where":5}'), 't'));
        $this->assertSame('when: where not an array', ForbidCertificate::whenError(Obj::of(['verb' => 'v', 'where' => ['x' => self::j(self::LEAF)]])));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","where":[]}')));
        $this->assertNull(ForbidCertificate::whenError(self::j('{"verb":"v","where":[' . self::LEAF . ']}')));
        $this->assertSame('when: condition not an object', ForbidCertificate::whenError(self::j('{"verb":"v","where":[' . self::LEAF . ',5]}')));
        $this->assertSame('x: unknown condition op zz', ForbidCertificate::whenError(self::j('{"verb":"v","where":[{"field":"f","op":"zz"}]}'), 'x'));
    }

    // ---- whenMatches -----------------------------------------------------------------------------------------------

    public function testWhenMatchesMalformedIsMatched(): void
    {
        $this->assertTrue(ForbidCertificate::whenMatches(self::j('{"verb":""}'), self::ctx()));
        $this->assertTrue(ForbidCertificate::whenMatches('x', self::ctx()));
        $this->assertTrue(ForbidCertificate::whenMatches(self::j('{"verb":"other","where":5}'), self::ctx()));
    }

    public function testWhenMatchesUnreadableActionIsMatched(): void
    {
        $w = self::j('{"verb":"read"}');
        foreach (['{}', '{"action":5}', '{"action":{"verb":5,"resource":"x"}}', '{"action":{"verb":"read"}}', '{"action":{"verb":"read","resource":5}}', '{"action":{"resource":"x"}}'] as $c) {
            $this->assertTrue(ForbidCertificate::whenMatches($w, self::j($c)), $c);
        }
        $this->assertTrue(ForbidCertificate::whenMatches(self::j('{"verb":"nomatch"}'), self::j('{"action":{"verb":"read","resource":5}}')));
        $this->assertFalse(ForbidCertificate::whenMatches(self::j('{"verb":"nomatch"}'), self::ctx()));
        $this->assertTrue(ForbidCertificate::whenMatches($w, self::ctx()));
    }

    public function testWhenMatchesOversizedRegexSubject(): void
    {
        $w = self::j('{"verb":"read","resource":"re:b"}');
        // 512 units: evaluated normally (no match); 513: undecidable, so the veto applies
        $this->assertFalse(ForbidCertificate::whenMatches($w, self::ctx('read', str_repeat('a', 512))));
        $this->assertTrue(ForbidCertificate::whenMatches($w, self::ctx('read', str_repeat('a', 513))));
        // only a re: resource gets the oversize treatment
        $plain = self::j('{"verb":"read","resource":"abc"}');
        $this->assertFalse(ForbidCertificate::whenMatches($plain, self::ctx('read', str_repeat('a', 600))));
        $this->assertFalse(ForbidCertificate::whenMatches(self::j('{"verb":"read","resource":"abc*"}'), self::ctx('read', 'x' . str_repeat('a', 600))));
        $this->assertTrue(ForbidCertificate::whenMatches(self::j('{"verb":"read"}'), self::ctx('read', str_repeat('a', 600))));
    }

    // ---- decide / certify / check ----------------------------------------------------------------------------------

    public function testRankOfAnUnsignedClauseAmongForbids(): void
    {
        $clauses = self::j('[{"id":"b","kind":"forbid","when":{"verb":"read"}},{"id":"a","kind":"forbid","when":{"verb":"read"}}]');
        $d = ForbidCertificate::decide($clauses, self::ctx());
        $this->assertSame('deny', $d['decision']);
        $this->assertSame(['kind' => 'forbid', 'id' => 'a'], $d['witness']['winner']);
        $this->assertSame(['b'], $d['witness']['shadowed']);
        $mixed = self::j('[{"id":"a","kind":"forbid","when":{"verb":"read"}},{"id":"z","kind":"forbid","signer":"org","when":{"verb":"read"}},{"id":"m","kind":"forbid","signer":"other","when":{"verb":"read"}}]');
        $d = ForbidCertificate::decide($mixed, self::ctx(), ['precedence' => ['org']]);
        $this->assertSame(['kind' => 'forbid', 'id' => 'z'], $d['witness']['winner']);
        $this->assertSame(['a', 'm'], $d['witness']['shadowed']);
    }

    public function testPermitSignersFilter(): void
    {
        $clauses = self::j('[{"id":"pa","kind":"permit","signer":"alice","when":{"verb":"read"}},{"id":"pb","kind":"permit","signer":"bob","when":{"verb":"read"}},{"id":"pn","kind":"permit","when":{"verb":"read"}},{"id":"f","kind":"forbid","signer":"bob","when":{"verb":"nomatch"}}]');
        $d = ForbidCertificate::decide($clauses, self::ctx(), ['permitSigners' => ['alice']]);
        $this->assertSame([['id' => 'pa', 'kind' => 'permit', 'value' => 'true'], ['id' => 'pb', 'kind' => 'permit', 'value' => 'false'], ['id' => 'pn', 'kind' => 'permit', 'value' => 'false'], ['id' => 'f', 'kind' => 'forbid', 'value' => 'false']], $d['values']);
        $this->assertSame('allow', $d['decision']);
        $this->assertSame(['kind' => 'permit', 'id' => 'pa'], $d['witness']['winner']);
        $this->assertSame([], $d['witness']['shadowed']);
        $none = ForbidCertificate::decide($clauses, self::ctx(), ['permitSigners' => ['carol']]);
        $this->assertSame('deny', $none['decision']);
        $this->assertSame(['kind' => 'none', 'id' => null], $none['witness']['winner']);
        $all = ForbidCertificate::decide($clauses, self::ctx());
        $this->assertSame(['pa', 'pb', 'pn'], array_column(array_filter($all['values'], static fn(array $v): bool => $v['value'] === 'true'), 'id'));
    }

    public function testCertifyOfMalformedClausesDoesNotThrow(): void
    {
        foreach (['["x"]', '[{"id":5,"kind":"permit","when":{}}]', '[{"id":null,"kind":"permit","when":{}}]'] as $json) {
            $cert = ForbidCertificate::certify(self::j($json), self::ctx());
            $this->assertSame('deny', $cert->get('decision'), $json);
            $this->assertSame('malformed', $cert->get('winner')->get('kind'), $json);
            $this->assertSame([], $cert->get('clauses'), $json);
            $this->assertSame([], $cert->get('shadowed'), $json);
        }
    }

    public function testCheckHonoursPrecedence(): void
    {
        $clauses = self::j('[{"id":"a","kind":"forbid","signer":"s1","when":{"verb":"read"}},{"id":"b","kind":"forbid","signer":"s2","when":{"verb":"read"}}]');
        $opts = ['precedence' => ['s2', 's1']];
        $cert = ForbidCertificate::certify($clauses, self::ctx(), $opts);
        $this->assertSame('b', $cert->get('winner')->get('id'));
        $this->assertSame(['ok' => true], ForbidCertificate::check($cert, $clauses, self::ctx(), $opts));
        $this->assertTrue(ForbidCertificate::consistent($cert, ['s2', 's1']));
        $this->assertFalse(ForbidCertificate::consistent($cert, []));
        $this->assertSame(['ok' => false, 'reason' => 'certificate table does not entail its decision'], ForbidCertificate::check($cert, $clauses, self::ctx()));
    }

    public function testCheckFailsClosedWhenTheCertificateCannotBeHashed(): void
    {
        $clauses = self::j('[{"id":"a","kind":"permit","when":{"verb":"read"}}]');
        $cert = ForbidCertificate::certify($clauses, self::ctx());
        $this->assertSame(['ok' => true], ForbidCertificate::check($cert, $clauses, self::ctx()));
        $cert->set('extra', new Num('1e5'));
        $this->assertSame(['ok' => false, 'reason' => 'certificate check error (fail closed)'], ForbidCertificate::check($cert, $clauses, self::ctx()));
    }
}
