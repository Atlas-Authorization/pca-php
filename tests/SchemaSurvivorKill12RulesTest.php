<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsRules;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsRules.php';

/** Business rules: exact refusals, money bounds, the UTC parser, compile/evaluate/lint/diff/review results of ActionsRules. */
final class SchemaSurvivorKill12RulesTest extends TestCase
{
    /** The multi-currency def of the reference corpus (currency from a param: USD, EUR, GBP; amount 1..100000000, exp 2). */
    private const PAY = '{"v":1,"kind":"pca-action-def","verb":"acme.pay.send","aliases":["charge_customer","bill"],"title":"Charge a customer","description":"Charge a customer. Refundable in practice, but a charge is treated as final.","effects":["pay"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":100000000,"unit":{"kind":"money","ccy":{"from":"currency"},"exp":2}},"currency":{"type":"string","role":"money.currency","format":"iso_currency","values":["USD","EUR","GBP"],"max_len":3},"to":{"type":"string","role":"contact.email","format":"email","max_len":254},"cc":{"type":"array","items":"string","max_items":3},"many":{"type":"array","items":"string","max_items":200},"customer":{"type":"string","role":"id.acme.customer","max_len":64},"note":{"type":"string","max_len":100,"required":false},"count":{"type":"integer","min":0,"max":9},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"review":{"state":"authored"},"since":"0.5.0"}';

    /** The single-currency def of the reference corpus (USD literal). */
    private const USD = '{"v":1,"kind":"pca-action-def","verb":"stripe.charge","aliases":["charge_customer","bill"],"title":"Charge a customer","description":"Charge a customer. Refundable in practice, but a charge is treated as final.","effects":["pay"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":10000000000,"unit":{"kind":"money","ccy":"USD","exp":2},"provenance_min":"first_party"},"customer":{"type":"string","max_len":128,"role":"id.stripe.customer"},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"review":{"state":"authored"},"since":"0.5.0"}';

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function pay(): Obj
    {
        return self::j(self::PAY);
    }

    private static function usd(): Obj
    {
        return self::j(self::USD);
    }

    /** The bad_rules message $f throws (fails when it returns or throws anything else). */
    private function refusal(callable $f): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            $this->assertSame('bad_rules', $e->codeName);
            return $e->getMessage();
        }
        $this->fail('no bad_rules refusal');
    }

    /** @return list<array<string,mixed>> */
    private static function lint(Obj $d, string $rules): array
    {
        return ActionsRules::lintBusinessRules($d, self::j($rules));
    }

    private static function entry(string $rule, string $sev, string $verb, string $msg): array
    {
        return ['rule' => $rule, 'severity' => $sev, 'verb' => $verb, 'message' => $msg];
    }

    // ---- references and money parameters ------------------------------------------------------------------------------------

    /** A reference to a missing parameter, to no or several role holders, is refused with its exact reason; one holder resolves. */
    public function testParamReferencesAreRefusedWithTheirExactReason(): void
    {
        $d = self::j('{"verb":"v","params":{"a":{"type":"string","role":"r"},"b":{"type":"string","role":"r"},"c":{"type":"string","role":"u"}}}');
        $this->assertSame("at: 'v' has no parameter 'zz'", $this->refusal(fn() => ActionsRules::resolveParamRef($d, self::j('{"param":"zz"}'), 'at')));
        $this->assertSame("at: 'v' has several parameters with role r", $this->refusal(fn() => ActionsRules::resolveParamRef($d, self::j('{"role":"r"}'), 'at')));
        $this->assertSame("at: 'v' has no parameter with role q", $this->refusal(fn() => ActionsRules::resolveParamRef($d, self::j('{"role":"q"}'), 'at')));
        $one = ActionsRules::resolveParamRef($d, self::j('{"role":"u"}'), 'at');
        $this->assertSame('c', $one['name']);
        $this->assertSame('string', $one['p']->get('type'));
    }

    /** The money parameter must be one integer with a money unit whose currency parameter exists; each refusal keeps its reason. */
    public function testMoneyParameterRefusalsAreExact(): void
    {
        $money = '{"kind":"money","ccy":"USD","exp":2}';
        $this->assertSame("'v' needs exactly one parameter with role money.amount for an amount or approval-above rule (has 2)", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"a":{"type":"integer","role":"money.amount","unit":' . $money . '},"b":{"type":"integer","role":"money.amount","unit":' . $money . '}}}'))));
        $this->assertSame("'v' needs exactly one parameter with role money.amount for an amount or approval-above rule (has 0)", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"a":{"type":"integer"}}}'))));
        $this->assertSame("'v': the money.amount parameter 'amt' must be an integer", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"amt":{"type":"string","role":"money.amount","unit":' . $money . '}}}'))));
        $this->assertSame("'v': the amount parameter 'amt' declares no money unit (its currency)", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"amt":{"type":"integer","role":"money.amount","unit":{"kind":"count","ccy":"USD","exp":2}}}}'))));
        $this->assertSame("'v': the amount parameter 'amt' declares no money unit (its currency)", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"amt":{"type":"integer","role":"money.amount"}}}'))));
        $this->assertSame("'v': the currency parameter 'nope' does not exist", $this->refusal(fn() => ActionsRules::moneyOf(
            self::j('{"verb":"v","params":{"amt":{"type":"integer","role":"money.amount","unit":{"kind":"money","ccy":{"from":"nope"},"exp":2}}}}'))));
        $ok = ActionsRules::moneyOf(self::j('{"verb":"v","params":{"amt":{"type":"integer","role":"money.amount","unit":{"kind":"money","ccy":{"from":"c"},"exp":2}},"c":{"type":"string"}}}'));
        $this->assertSame('amt', $ok['amount']);
        $this->assertSame(['param' => 'c'], $ok['ccy']);
    }

    /** The currency exponent is an integer 0..18; every other exponent is refused with the same reason. */
    public function testTheCurrencyExponentIsBoundedAtExactly18(): void
    {
        $this->assertSame(0, ActionsRules::minorUnits('0', new Num('18'), 'x'));
        $this->assertSame(1, ActionsRules::minorUnits('1', new Num('0'), 'x'));
        foreach ([null, new Num('19'), new Num('-1'), new Num('1.5'), INF, NAN] as $exp) {
            $this->assertSame('x: the currency exponent is not a small integer', $this->refusal(fn() => ActionsRules::minorUnits('1', $exp, 'x')));
        }
    }

    /** A decimal amount converts exactly; 2^53-1 minor units is the largest accepted, one more is too large. */
    public function testDecimalAmountsConvertExactlyUpToTheSafeLimit(): void
    {
        $this->assertSame(1234, ActionsRules::minorUnits('12.34', new Num('2'), 'x'));
        $this->assertSame(1200, ActionsRules::minorUnits('12', new Num('2'), 'x'));
        $this->assertSame(9007199254740991, ActionsRules::minorUnits('90071992547409.91', new Num('2'), 'x'));
        $this->assertSame("x: '90071992547409.92' is too large", $this->refusal(fn() => ActionsRules::minorUnits('90071992547409.92', new Num('2'), 'x')));
        $this->assertSame("x: '999999999999999' is too large", $this->refusal(fn() => ActionsRules::minorUnits('999999999999999', new Num('2'), 'x')));
    }

    // ---- the UTC time parser -------------------------------------------------------------------------------------------------

    /** Date.parse of RFC 3339 UTC seconds: exact milliseconds across eras, leap years, January/February and day rollover. */
    public function testParseUtcMsIsExact(): void
    {
        $cases = [
            '2027-11-23T13:47:52Z' => 1826977672000, '2026-01-01T00:00:00Z' => 1767225600000, '2026-12-31T23:59:59Z' => 1798761599000,
            '2026-01-07T24:00:00Z' => 1767830400000, '2026-02-31T00:00:00Z' => 1772496000000, '0000-01-01T00:00:00Z' => -62167219200000,
            '0000-02-29T12:00:00Z' => -62162078400000, '0000-03-01T00:00:00Z' => -62162035200000, '0001-02-03T00:00:00Z' => -62132745600000,
            '0399-12-31T00:00:00Z' => -49544524800000, '0400-02-29T00:00:00Z' => -49539340800000, '1600-03-01T00:00:00Z' => -11670912000000,
            '1999-06-15T06:07:08Z' => 929426828000, '2000-02-29T00:00:00Z' => 951782400000, '1900-03-01T00:00:00Z' => -2203891200000,
            '2100-01-31T00:00:00Z' => 4105036800000, '9999-12-31T23:59:59Z' => 253402300799000, '1970-01-01T00:00:00Z' => 0,
        ];
        foreach ($cases as $s => $ms) {
            $this->assertSame($ms, ActionsRules::parseUtcMs($s), $s);
        }
    }

    /** Out-of-range fields, 24:00 other than 24:00:00, other shapes and non-strings parse to null. */
    public function testParseUtcMsRefusesOutOfRangeFields(): void
    {
        foreach (['2026-00-10T10:00:00Z', '2026-13-10T10:00:00Z', '2026-01-00T10:00:00Z', '2026-01-32T10:00:00Z', '2026-01-10T10:60:00Z',
            '2026-01-10T10:00:60Z', '2026-01-10T25:00:00Z', '2026-01-10T25:30:00Z', '2026-01-10T24:01:00Z', '2026-01-10T24:00:01Z',
            '2026-01-10T24:30:00Z', '2026-01-10T25:01:01Z', '2026-01-10 10:00:00Z', '2026-01-10T10:00:00+00:00', ''] as $s) {
            $this->assertNull(ActionsRules::parseUtcMs($s), $s);
        }
        $this->assertNull(ActionsRules::parseUtcMs(new Num('5')));
        $this->assertNull(ActionsRules::parseUtcMs(null));
    }

    // ---- clock -----------------------------------------------------------------------------------------------------------------

    /** The clock floors to whole seconds toward zero of the integral millisecond (59999 ms is still minute 0; -0.5 ms is the epoch). */
    public function testClockAtTruncatesToSeconds(): void
    {
        $this->assertSame(['dow' => 4, 'min' => 0], ActionsRules::clockAt(new Num('59999'), 'UTC'));
        $this->assertSame(['dow' => 4, 'min' => 1], ActionsRules::clockAt(new Num('60000'), 'UTC'));
        $this->assertSame(['dow' => 4, 'min' => 0], ActionsRules::clockAt(new Num('-0.5'), 'UTC'));
        $this->assertSame(['dow' => 3, 'min' => 1439], ActionsRules::clockAt(new Num('-1000'), 'UTC'));
    }

    /** A clock 10^15 s after the epoch is still a time (its timestamp text is an integer, never an exponent form). */
    public function testClockAtFarFuture(): void
    {
        $this->assertSame(['dow' => 0, 'min' => 106], ActionsRules::clockAt(new Num('1000000000000000000'), 'UTC'));
    }

    /** The meet of decisions, the rules cap on a base decision and the evaluation context are public and exact. */
    public function testDecisionMeetAndContext(): void
    {
        $this->assertSame('deny', ActionsRules::meetDecision('allow', 'deny'));
        $this->assertSame('escalate', ActionsRules::meetDecision('escalate', 'allow'));
        $this->assertSame('escalate', ActionsRules::withBusinessRules('allow', ['decision' => 'escalate']));
        $this->assertSame('deny', ActionsRules::withBusinessRules('deny', ['decision' => 'allow']));
        $ctx = ActionsRules::rulesContext(self::j('{"verb":"v","accumulators":[]}'), self::j('{"resource":"cus_1","params":{}}'));
        $this->assertSame('cus_1', $ctx->get('action')->get('resource'));
        $this->assertSame('v', $ctx->get('action')->get('verb'));
        $ctx = ActionsRules::rulesContext(self::j('{"verb":"v","accumulators":[]}'), self::j('{"params":{}}'));
        $this->assertSame('', $ctx->get('action')->get('resource'));
    }

    // ---- compile -----------------------------------------------------------------------------------------------------------

    /** The hours reason names the days sorted, as a run only when consecutive; the compiled day list is sorted JSON numbers. */
    public function testHoursCompileSortsDaysAndNamesRuns(): void
    {
        $c = ActionsRules::compileBusinessRules(self::usd(), self::j('{"hours":{"days":["wed","mon","tue"],"from":"09:00","to":"17:00","tz":"UTC"}}'));
        $r = $c->get('tighten')[0];
        $this->assertSame('hours', $r->get('id'));
        $this->assertSame('outside Mon-Wed 09:00-17:00 (UTC)', $r->get('reason'));
        $this->assertSame('UTC', $c->get('clock_tz'));
        $day = $r->get('when')->get('not')->get('all_of')[0];
        $this->assertSame('env.clock.dow', $day->get('field'));
        $this->assertSame(['1', '2', '3'], array_map(static fn(Num $n): string => $n->lexeme, $day->get('value')));
        $c = ActionsRules::compileBusinessRules(self::usd(), self::j('{"hours":{"days":["fri","mon","wed"],"from":"09:00","to":"17:00","tz":"UTC","outside":"deny"}}'));
        $r = $c->get('tighten')[0];
        $this->assertSame('outside Mon, Wed, Fri 09:00-17:00 (UTC)', $r->get('reason'));
        $this->assertSame('deny', $r->get('signal'));
        $this->assertSame(['1', '3', '5'], array_map(static fn(Num $n): string => $n->lexeme, $r->get('when')->get('not')->get('all_of')[0]->get('value')));
    }

    /** @return list<string> */
    private static function addresses(int $n): array
    {
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[] = str_repeat(chr(97 + $i), 16) . sprintf('%02d', $i) . '@x.io';
        }
        return $out;
    }

    private static function recipientsRule(array $addrs): Obj
    {
        $rules = Obj::of(['recipients' => Obj::of(['param' => 'to', 'addresses' => $addrs])]);
        return ActionsRules::compileBusinessRules(self::pay(), $rules)->get('tighten')[0];
    }

    /** A reason of exactly 256 UTF-16 units is kept; a longer one is cut to its first 253 units plus "...". */
    public function testLongReasonsAreCutAt256Units(): void
    {
        $nine = self::addresses(9);
        $full = 'to may only name ' . implode(' or ', $nine);
        $this->assertSame(256, strlen($full));
        $this->assertSame($full, self::recipientsRule($nine)->get('reason'));
        $ten = self::addresses(10);
        $full = 'to may only name ' . implode(' or ', $ten);
        $this->assertGreaterThan(256, strlen($full));
        $cut = self::recipientsRule($ten)->get('reason');
        $this->assertSame(substr($full, 0, 253) . '...', $cut);
        $this->assertSame(256, strlen($cut));
    }

    // ---- examples and evaluation --------------------------------------------------------------------------------------------

    private static function examples(string $rules): array
    {
        return ActionsRules::runRuleExamples(self::usd(), self::j($rules));
    }

    /** A rate example counts 0 calls unless `recent` names the rate's index; at the limit the rule refuses. */
    public function testRateExamplesReadRecentByIndex(): void
    {
        $out = self::examples('{"rate":[{"max":1,"per":"hour"}],"examples":[{"params":{},"expect":"allow"},{"params":{},"recent":{"0":1},"expect":"deny"},{"params":{},"recent":{"1":7},"expect":"allow"}]}');
        $this->assertSame([
            ['index' => 0, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'no rule fired'],
            ['index' => 1, 'expect' => 'deny', 'got' => 'deny', 'ok' => true, 'why' => 'rate_0: at most 1 per hour per principal'],
            ['index' => 2, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'no rule fired'],
        ], $out);
    }

    /** An example without `at` runs at the default time (a Wednesday 15:00 UTC); with `at` it runs then. */
    public function testHoursExamplesUseTheirTimeOrTheDefault(): void
    {
        $out = self::examples('{"hours":{"days":["mon","tue","wed","thu","fri"],"from":"09:00","to":"17:00","tz":"UTC"},"examples":[{"params":{},"expect":"allow"},{"params":{},"at":"2026-01-10T15:00:00Z","expect":"escalate"}]}');
        $this->assertSame([
            ['index' => 0, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'no rule fired'],
            ['index' => 1, 'expect' => 'escalate', 'got' => 'escalate', 'ok' => true, 'why' => 'hours: outside Mon-Fri 09:00-17:00 (UTC)'],
        ], $out);
    }

    /** An example's caller is the subject the scope rule compares with; without one the scope rule refuses. */
    public function testScopeExamplesUseTheCaller(): void
    {
        $out = self::examples('{"scope":[{"param":"customer","caller":"id"}],"examples":[{"params":{"customer":"cus_1"},"caller":{"id":"cus_1"},"expect":"allow"},{"params":{"customer":"cus_1"},"expect":"deny"}]}');
        $this->assertSame([
            ['index' => 0, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'no rule fired'],
            ['index' => 1, 'expect' => 'deny', 'got' => 'deny', 'ok' => true, 'why' => "scope_0: customer must be the caller's own id"],
        ], $out);
    }

    /** A required non-string parameter is missing only when absent: present it allows, absent it refuses. */
    public function testRequiredNonStringParamFiresOnlyWhenAbsent(): void
    {
        $out = self::examples('{"required":["amount"],"examples":[{"params":{"amount":5},"expect":"allow"},{"params":{},"expect":"deny"}]}');
        $this->assertSame([
            ['index' => 0, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'no rule fired'],
            ['index' => 1, 'expect' => 'deny', 'got' => 'deny', 'ok' => true, 'why' => 'required_0: amount is required'],
        ], $out);
    }

    /** One approver is named in the singular. */
    public function testExplainNamesOneApproverInTheSingular(): void
    {
        $this->assertSame(['Always needs approval by 1 approver.'], ActionsRules::explainBusinessRules(self::usd(), self::j('{"approval":{"always":true,"approvers":1}}')));
        $this->assertSame(['Always needs approval by 2 approvers from the ops group.'], ActionsRules::explainBusinessRules(self::usd(), self::j('{"approval":{"always":true,"approvers":2,"group":"ops"}}')));
    }

    // ---- lint ---------------------------------------------------------------------------------------------------------------

    /** A ceiling for no currency the action uses is a contradiction plus a dead rule, with exact wording. */
    public function testLintCeilingOnlyForAnUnusedCurrency(): void
    {
        $this->assertSame([
            self::entry('LR-002', 'error', 'acme.pay.send', "rules.amount: none of the action's currencies (USD, EUR, GBP) has a ceiling, so every call is refused"),
            self::entry('LR-003', 'warning', 'acme.pay.send', 'rules.amount.max.JPY: the action never uses JPY'),
        ], self::lint(self::pay(), '{"amount":{"max":{"JPY":5}}}'));
    }

    /** The ceiling is compared with the parameter's own min (strictly below is a contradiction) and max (at or above is dead). */
    public function testLintCeilingAgainstTheParameterBounds(): void
    {
        $this->assertSame([self::entry('LR-002', 'error', 'acme.pay.send', "rules.amount.max.USD: the ceiling 0.00 USD is below the parameter's minimum, so every USD call is refused")],
            self::lint(self::pay(), '{"amount":{"max":{"USD":0}}}'));
        $this->assertSame([], self::lint(self::pay(), '{"amount":{"max":{"USD":1}}}'));
        $this->assertSame([], self::lint(self::pay(), '{"amount":{"max":{"USD":99999999}}}'));
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', "rules.amount.max.USD: the parameter's own maximum already bounds the amount below this ceiling")],
            self::lint(self::pay(), '{"amount":{"max":{"USD":100000000}}}'));
    }

    /** An approval threshold at the ceiling can never be asked for; one in a currency without a ceiling is always refused first. */
    public function testLintApprovalAgainstTheCeiling(): void
    {
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', 'rules.approval.above.USD: above the amount ceiling, so the approval can never be asked for')],
            self::lint(self::pay(), '{"amount":{"max":{"USD":500}},"approval":{"above":{"USD":500}}}'));
        $this->assertSame([], self::lint(self::pay(), '{"amount":{"max":{"USD":500}},"approval":{"above":{"USD":499}}}'));
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', 'rules.approval.above.EUR: EUR has no ceiling, so it is always refused before an approval')],
            self::lint(self::pay(), '{"amount":{"max":{"USD":500}},"approval":{"above":{"EUR":10}}}'));
    }

    /** Requiring a non-string parameter the definition already requires (explicitly or by default) is a dead rule. */
    public function testLintRequiredAlreadyRequired(): void
    {
        $d = self::pay();
        $d->get('params')->get('count')->set('required', true);
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', "rules.required: 'count' is already required by the definition")], self::lint($d, '{"required":["count"]}'));
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', "rules.required: 'count' is already required by the definition")], self::lint(self::pay(), '{"required":["count"]}'));
        $this->assertSame([], self::lint(self::pay(), '{"required":["note"]}'));
    }

    /** Rate limits are keyed by period and by whom: only a true duplicate is reported, with the lower limit; daily vs hourly uses the lowest hourly. */
    public function testLintRateDuplicatesAndDailyVersusHourly(): void
    {
        $this->assertSame([], self::lint(self::pay(), '{"rate":[{"max":5,"per":"hour","by":"org"},{"max":3,"per":"hour"}]}'));
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', 'rules.rate: two limits per hour per org; only the lower (3) matters')],
            self::lint(self::pay(), '{"rate":[{"max":5,"per":"hour","by":"org"},{"max":3,"per":"hour","by":"org"}]}'));
        $this->assertSame([self::entry('LR-003', 'warning', 'acme.pay.send', 'rules.rate: two limits per hour per principal; only the lower (2) matters')],
            self::lint(self::pay(), '{"rate":[{"max":2,"per":"hour"},{"max":9,"per":"hour"},{"max":5,"per":"day"}]}'));
    }

    // ---- diff ---------------------------------------------------------------------------------------------------------------

    private static function diff(string $a, string $b): array
    {
        return ActionsRules::diffBusinessRules(self::pay(), self::j($a), self::j($b));
    }

    /** Scope bindings compare by (param, role, caller) as separate fields: no two different bindings collide. */
    public function testScopeKeysKeepTheirFieldsApart(): void
    {
        $inc = ['class' => 'incomparable', 'reasons' => ['rules.scope: incomparable']];
        $pairs = [
            ['{"param":"a","role":"x","caller":"c"}', '{"param":"a","role":"y","caller":"c"}'],
            ['{"param":"a","caller":"c"}', '{"param":"b","caller":"c"}'],
            ['{"param":"ab","caller":"c"}', '{"param":"a","role":"b","caller":"c"}'],
            ['{"param":"a","role":"x","caller":"y"}', '{"param":"a","role":"xy","caller":""}'],
        ];
        foreach ($pairs as [$a, $b]) {
            $this->assertSame($inc, self::diff('{"scope":[' . $a . ']}', '{"scope":[' . $b . ']}'), "$a vs $b");
        }
        $this->assertSame(['class' => 'equal', 'reasons' => []], self::diff('{"scope":[{"param":"a","caller":"c"}]}', '{"scope":[{"param":"a","caller":"c"}]}'));
    }

    /** Rate limits compare by (per, by) as separate fields, with the limit's exact value. */
    public function testRateKeysKeepTheirFieldsApart(): void
    {
        $inc = ['class' => 'incomparable', 'reasons' => ['rules.rate: incomparable']];
        $this->assertSame($inc, self::diff('{"rate":[{"max":5,"per":"hour","by":"org"}]}', '{"rate":[{"max":5,"per":"hour"}]}'));
        $this->assertSame($inc, self::diff('{"rate":[{"max":5,"per":"hour","by":"org"}]}', '{"rate":[{"max":5,"per":"day","by":"org"}]}'));
        $this->assertSame($inc, self::diff('{"rate":[{"max":5,"per":"hou","by":"rorg"}]}', '{"rate":[{"max":5,"per":"hour","by":"org"}]}'));
        $this->assertSame(['class' => 'equal', 'reasons' => []], self::diff('{"rate":[{"max":2,"per":"hour"}]}', '{"rate":[{"max":2.5,"per":"hour"}]}'));
        $this->assertSame(['class' => 'widen', 'reasons' => ['rules.rate: widen']], self::diff('{"rate":[{"max":2,"per":"hour"}]}', '{"rate":[{"max":3,"per":"hour"}]}'));
    }

    /** An hours window reads HH from the first two characters and MM from characters 4-5, so these spellings name the same window. */
    public function testHoursWindowReadsFixedPositions(): void
    {
        $eq = ['class' => 'equal', 'reasons' => []];
        $h = static fn(string $from): string => '{"hours":{"days":["mon"],"from":"' . $from . '","to":"13:00","tz":"UTC"}}';
        $this->assertSame($eq, self::diff($h('123:4'), $h('12:00')));
        $this->assertSame($eq, self::diff($h('09:305'), $h('09:30')));
        $this->assertSame($eq, self::diff($h('09:xx'), $h('09:00')));
    }

    /** An address in a domain the previous rule allowed is a narrowing, not an incomparable change. */
    public function testRecipientsAddressCoveredByDomain(): void
    {
        $this->assertSame(['class' => 'narrow', 'reasons' => ['rules.recipients: narrow']],
            self::diff('{"recipients":{"param":"to","domains":["x.io"]}}', '{"recipients":{"param":"to","addresses":["a@x.io"]}}'));
    }

    /** @return list<int> */
    private static function minutes(string $h): array
    {
        $m = new \ReflectionMethod(ActionsRules::class, 'minutesOfWeek');
        $k = array_keys($m->invoke(null, self::j($h)));
        sort($k);
        return $k;
    }

    /** The minutes of the week a window covers: a day window, an overnight window and the Saturday-to-Sunday wrap. */
    public function testMinutesOfWeek(): void
    {
        $this->assertSame([1980, 1981, 1982], self::minutes('{"days":["mon"],"from":"09:00","to":"09:03"}'));
        $this->assertSame([0, 1, 10078, 10079], self::minutes('{"days":["sat"],"from":"23:58","to":"00:02"}'));
        $this->assertSame([2878, 2879, 2880, 2881], self::minutes('{"days":["mon"],"from":"23:58","to":"00:02"}'));
        $this->assertSame([], self::minutes('{"days":["mon"],"from":"10:00","to":"10:00"}'));
    }

    // ---- signed review -----------------------------------------------------------------------------------------------------

    private static function pins(KeyPair $k): Obj
    {
        return Obj::of(['keys' => [Obj::of(['kid' => 'rev', 'pk' => $k->public, 'roles' => ['reviewer'], 'not_before' => new Num('100'), 'not_after' => new Num('200')])]]);
    }

    private static function review(Obj $d, Obj $rules, string $kid, string $ts): Obj
    {
        return Obj::of(['verb' => $d->get('verb'), 'def_digest' => Actions::defDigest($d), 'rules_digest' => ActionsRules::businessRulesDigest($d->get('verb'), $rules),
            'reviewer_kid' => $kid, 'ts' => new Num($ts)]);
    }

    /** A review signed at exactly not_before or not_after is inside the key's validity; a negative time is only a time. */
    public function testReviewValidityBoundsAreInclusive(): void
    {
        $seed = hash('sha256', 'atlas-pca-conformance/kill12-rules-review', true);
        $k = new KeyPair($seed);
        $d = self::usd();
        $rules = self::j('{"required":["customer"]}');
        foreach (['100', '150', '200'] as $ts) {
            $this->assertNull(ActionsRules::rulesReviewError(ActionsRules::signRulesReview(self::review($d, $rules, 'rev', $ts), $seed), $d, $rules, self::pins($k)), $ts);
        }
        $this->assertSame('the review time is outside the key validity', ActionsRules::rulesReviewError(ActionsRules::signRulesReview(self::review($d, $rules, 'rev', '201'), $seed), $d, $rules, self::pins($k)));
        $neg = self::review($d, $rules, 'nobody', '-5');
        $neg->set('sig', 'x');
        $this->assertSame("no pinned key 'nobody'", ActionsRules::rulesReviewError($neg, $d, $rules, self::pins($k)));
    }

    /** An exception inside the check becomes a refusal that keeps the exception's message. */
    public function testReviewErrorKeepsTheExceptionMessage(): void
    {
        $k = new KeyPair(hash('sha256', 'atlas-pca-conformance/kill12-rules-review', true));
        $d = self::j('{"verb":"acme.x","reversibility":"irreversible","blast":{"radius":"tenant"}}');
        $r = self::j('{"verb":"acme.x","def_digest":"d","rules_digest":"r","reviewer_kid":"rev","ts":150,"sig":"x"}');
        $this->assertSame('malformed rules review: Call to a member function keys() on null', ActionsRules::rulesReviewError($r, $d, self::j('{"required":["a"]}'), self::pins($k)));
    }
}
