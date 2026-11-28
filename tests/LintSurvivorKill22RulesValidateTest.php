<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRulesValidate;
use Atlas\Pca\Json;
use Atlas\Pca\JsUndefined;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsRules.php';

/** The rules-block shape check: every refusal keeps its exact reason, every bound holds at exactly its limit. */
final class LintSurvivorKill22RulesValidateTest extends TestCase
{
    private const D = '{"verb":"v","params":{"a":{"type":"string","role":"r"},"b":{"type":"string","role":"r"},"c":{"type":"string","role":"u"},'
        . '"amount":{"type":"integer","role":"money.amount","unit":{"kind":"money","ccy":"USD","exp":2}},'
        . '"cc":{"type":"array","items":"string","max_items":3},"many":{"type":"array","items":"string"},'
        . '"nums":{"type":"array","items":"integer","max_items":3},"cap":{"type":"array","items":"string","max_items":64}}}';

    private const RATE = '"rate":[{"max":1,"per":"day"}]';

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function err(string $def, string $rules): ?string
    {
        return ActionsRulesValidate::error(self::j($def), self::j($rules));
    }

    private static function d(string $rules): ?string
    {
        return self::err(self::D, $rules);
    }

    /** A def whose only param is the money amount with this unit JSON (and type). */
    private static function money(string $unit, string $type = 'integer'): string
    {
        return '{"verb":"v","params":{"amount":{"type":"' . $type . '","role":"money.amount"' . ($unit === '' ? '' : ',"unit":' . $unit) . '}}}';
    }

    /** Amounts: the safe-integer and zero edges pass, -0 and over-range decimals are refused, non-numbers keep their reason. */
    public function testAmountBoundsHoldExactly(): void
    {
        $this->assertNull(self::d('{"amount":{"max":{"USD":9007199254740991}}}'));
        $this->assertNull(self::d('{"amount":{"max":{"USD":0}}}'));
        $this->assertSame('rules.amount.max.USD: an amount is a non-negative integer of minor units, or a decimal string', self::d('{"amount":{"max":{"USD":-0}}}'));
        $this->assertNull(self::d('{"amount":{"max":{"USD":"90071992547409.91"}}}'));
        $this->assertSame("rules.amount.max.USD: '90071992547409.92' is too large", self::d('{"amount":{"max":{"USD":"90071992547409.92"}}}'));
        $this->assertSame('rules.amount.max: a map of 1..32 currencies to amounts', self::d('{"amount":{"max":5}}'));
        $max = new Obj();
        for ($i = 0; $i < 32; $i++) {
            $max->set('A' . chr(65 + intdiv($i, 26)) . chr(65 + $i % 26), new Num('1'));
        }
        $this->assertNull(ActionsRulesValidate::error(self::j(self::D), Obj::of(['amount' => Obj::of(['max' => $max])])));
    }

    /** The money parameter's type, unit, currency source and exponent are each refused with their own reason; 0 and 18 are valid exponents. */
    public function testMoneyParameterAndExponent(): void
    {
        $r = '{"amount":{"max":{"USD":1}}}';
        $this->assertSame("'v': the money.amount parameter 'amount' must be an integer", self::err(self::money('{"kind":"money","ccy":"USD","exp":2}', 'string'), $r));
        $this->assertSame("'v': the amount parameter 'amount' declares no money unit (its currency)", self::err(self::money(''), $r));
        $this->assertSame("'v': the amount parameter 'amount' declares no money unit (its currency)", self::err(self::money('{"kind":"count"}'), $r));
        $this->assertSame("'v': the currency parameter 'nope' does not exist", self::err(self::money('{"kind":"money","ccy":{"from":"nope"},"exp":2}'), $r));
        $this->assertSame('rules.amount.max.USD: the currency exponent is not a small integer', self::err(self::money('{"kind":"money","ccy":"USD"}'), '{"amount":{"max":{"USD":"5"}}}'));
        $this->assertNull(self::err(self::money('{"kind":"money","ccy":"USD","exp":18}'), '{"amount":{"max":{"USD":"0"}}}'));
        $this->assertNull(self::err(self::money('{"kind":"money","ccy":"USD","exp":0}'), '{"amount":{"max":{"USD":"5"}}}'));
        foreach (['19', '-1'] as $exp) {
            $this->assertSame('rules.amount.max.USD: the currency exponent is not a small integer', self::err(self::money('{"kind":"money","ccy":"USD","exp":' . $exp . '}'), '{"amount":{"max":{"USD":"0"}}}'), $exp);
        }
    }

    /** Param and role references: no params, non-object params, missing, none or several holders each keep their reason. */
    public function testReferencesKeepTheirReason(): void
    {
        $this->assertSame("rules.scope[0]: 'v' has several parameters with role r", self::d('{"scope":[{"role":"r","caller":"c"}]}'));
        $this->assertSame("rules.scope[0]: 'v' has no parameter with role q", self::d('{"scope":[{"role":"q","caller":"c"}]}'));
        $this->assertNull(self::d('{"scope":[{"role":"u","caller":"c"}]}'));
        $this->assertSame("rules.scope[0]: 'v' has no parameter 'x'", self::err('{"verb":"v"}', '{"scope":[{"param":"x","caller":"c"}]}'));
        $this->assertSame("rules.scope[0]: 'v' has no parameter with role q", self::err('{"verb":"v"}', '{"scope":[{"role":"q","caller":"c"}]}'));
        $this->assertSame("rules.scope[0]: 'v' has no parameter with role q", self::err('{"verb":"v","params":{"a":1}}', '{"scope":[{"role":"q","caller":"c"}]}'));
        $this->assertSame("rules.scope[0]: unknown member 'x'", self::d('{"scope":[{"param":"a","caller":"c","x":1}]}'));
        $this->assertNull(self::d('{"scope":[' . implode(',', array_fill(0, 64, '{"param":"a","caller":"c"}')) . ']}'));
    }

    /** Anything that is not an ActionKitError (a verb that cannot be printed) still yields the generic refusal, never an exception. */
    public function testUnprintableVerbIsTheGenericRefusal(): void
    {
        $this->assertSame('rules: malformed block', self::err('{"verb":{},"params":{}}', '{"scope":[{"param":"x","caller":"c"}]}'));
    }

    /** Rate limits: shape refusals, the 4-limit and 1000000 ceilings, both `by` values. */
    public function testRateLimits(): void
    {
        $this->assertSame('rules.rate is a list of 1..4 limits', self::d('{"rate":5}'));
        $this->assertSame('rules.rate[0] must be an object', self::d('{"rate":[5]}'));
        $this->assertSame("rules.rate[0]: unknown member 'x'", self::d('{"rate":[{"max":1,"per":"day","x":1}]}'));
        $this->assertNull(self::d('{"rate":[' . implode(',', array_fill(0, 4, '{"max":1,"per":"day"}')) . ']}'));
        $this->assertNull(self::d('{"rate":[{"max":1000000,"per":"hour","by":"principal"}]}'));
        $this->assertNull(self::d('{"rate":[{"max":1,"per":"day","by":"org"}]}'));
    }

    /** Approval: shape, closed members, the 1 and 16 approver edges and a non-number count. */
    public function testApproval(): void
    {
        $this->assertSame('rules.approval must be an object', self::d('{"approval":5}'));
        $this->assertSame("rules.approval: unknown member 'x'", self::d('{"approval":{"always":true,"x":1}}'));
        $this->assertNull(self::d('{"approval":{"always":true,"approvers":16}}'));
        $this->assertNull(self::d('{"approval":{"always":true,"approvers":1}}'));
        $this->assertSame('rules.approval.approvers is 1..16', self::d('{"approval":{"always":true,"approvers":"x"}}'));
    }

    /** Hours: shape, closed members, empty or partly bad day lists, a bad `from`, both `outside` values, the legacy zones. */
    public function testHours(): void
    {
        $h = fn(string $extra, string $days = '["mon"]', string $from = '09:00') => self::d('{"hours":{"days":' . $days . ',"from":"' . $from . '","to":"17:00","tz":"UTC"' . $extra . '}}');
        $this->assertNull($h(''));
        $this->assertSame('rules.hours must be an object', self::d('{"hours":5}'));
        $this->assertSame("rules.hours: unknown member 'x'", $h(',"x":1'));
        $days = 'rules.hours.days is a list of distinct days (sun, mon, tue, wed, thu, fri, sat)';
        $this->assertSame($days, $h('', '[]'));
        $this->assertSame($days, $h('', '["xxx","mon"]'));
        $this->assertSame('rules.hours.from and .to are HH:MM (24 h)', $h('', '["mon"]', '25:00'));
        $this->assertNull($h(',"outside":"escalate"'));
        $this->assertNull($h(',"outside":"deny"'));
        $this->assertSame('EST', ActionsRulesValidate::canonicalZone('est'));
        $this->assertSame('MST', ActionsRulesValidate::canonicalZone('MST'));
        $this->assertSame('HST', ActionsRulesValidate::canonicalZone('hst'));
    }

    /** Recipients: shape, closed members, string items, a bounded list (64 passes), domain list shape and size. */
    public function testRecipients(): void
    {
        $this->assertSame('rules.recipients must be an object', self::d('{"recipients":5}'));
        $this->assertSame("rules.recipients: unknown member 'x'", self::d('{"recipients":{"param":"cc","domains":["a.com"],"x":1}}'));
        $this->assertSame("rules.recipients: 'nums' must hold strings", self::d('{"recipients":{"param":"nums","domains":["a.com"]}}'));
        $this->assertSame("rules.recipients: the list parameter 'many' needs max_items <= 64 so every entry can be checked", self::d('{"recipients":{"param":"many","domains":["a.com"]}}'));
        $this->assertNull(self::d('{"recipients":{"param":"cap","domains":["a.com"]}}'));
        $dom = 'rules.recipients.domains is a list of lowercase domain names';
        $this->assertSame($dom, self::d('{"recipients":{"param":"cc","domains":"x"}}'));
        $this->assertSame($dom, self::d('{"recipients":{"param":"cc","domains":[]}}'));
        $list = implode(',', array_map(static fn(int $i): string => '"d' . $i . '.com"', range(0, 63)));
        $this->assertNull(self::d('{"recipients":{"param":"cc","domains":[' . $list . ']}}'));
    }

    /** Required names: missing params, a string that looks like a number's key, numbers, undefined, and exactly 64 names. */
    public function testRequired(): void
    {
        $this->assertSame("rules.required: 'v' has no parameter 'a'", self::err('{"verb":"v"}', '{"required":["a"]}'));
        $this->assertSame("rules.required: 'v' has no parameter 'o:5'", self::d('{"required":["o:5",5]}'));
        $this->assertSame("rules.required: 'v' has no parameter '1'", self::d('{"required":[1,2]}'));
        $this->assertSame("rules.required: 'v' has no parameter 'undefined'", ActionsRulesValidate::error(self::j(self::D), Obj::of(['required' => [JsUndefined::U]])));
        $params = new Obj();
        $names = [];
        for ($i = 0; $i < 64; $i++) {
            $params->set("p$i", Obj::of(['type' => 'string']));
            $names[] = "p$i";
        }
        $this->assertNull(ActionsRulesValidate::error(Obj::of(['verb' => 'v', 'params' => $params]), Obj::of(['required' => $names])));
    }

    /** Examples: shape, the 32 ceiling, each member's own reason, an object caller passes. */
    public function testExamplesShape(): void
    {
        $ex = fn(string $list) => self::d('{' . self::RATE . ',"examples":' . $list . '}');
        $this->assertSame('rules.examples is a list of at most 32', $ex('5'));
        $this->assertNull($ex('[' . implode(',', array_fill(0, 32, '{"params":{},"expect":"allow"}')) . ']'));
        $this->assertSame('rules.examples[0] must be an object', $ex('[5]'));
        $this->assertSame("rules.examples[0]: unknown member 'x'", $ex('[{"params":{},"expect":"allow","x":1}]'));
        $this->assertSame('rules.examples[0].params must be an object', $ex('[{"expect":"allow"}]'));
        $this->assertNull($ex('[{"params":{},"caller":{},"expect":"allow"}]'));
        $this->assertSame('rules.examples[0].caller must be an object', $ex('[{"params":{},"caller":5,"expect":"allow"}]'));
        $rc = 'rules.examples[0].recent maps rate indexes to counts';
        $this->assertSame($rc, $ex('[{"params":{},"recent":5,"expect":"allow"}]'));
        $this->assertSame($rc, $ex('[{"params":{},"recent":{"0":-1,"1":2},"expect":"allow"}]'));
        $this->assertNull($ex('[{"params":{},"recent":{"0":0},"expect":"allow"}]'));
    }

    /** Example times: every field edge of the RFC 3339 `Z` form (24:00:00 is valid, 24:30:00 is not). */
    public function testExampleTimes(): void
    {
        $at = fn(string $t) => self::d('{' . self::RATE . ',"examples":[{"params":{},"at":"' . $t . '","expect":"allow"}]}');
        foreach (['2026-12-01T00:00:00Z', '2026-01-01T00:59:00Z', '2026-01-01T00:00:59Z', '2026-01-01T23:00:00Z', '2026-01-01T24:00:00Z', '2026-01-31T00:00:00Z'] as $ok) {
            $this->assertNull($at($ok), $ok);
        }
        foreach (['nope', '2026-01-32T00:00:00Z', '2026-01-00T05:00:00Z', '2026-01-01T00:00:60Z', '2026-01-01T00:60:00Z', '2026-01-01T25:00:00Z', '2026-01-01T24:30:00Z'] as $bad) {
            $this->assertSame('rules.examples[0].at is an RFC 3339 UTC time (…Z)', $at($bad), $bad);
        }
    }
}
