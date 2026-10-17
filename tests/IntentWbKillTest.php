<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Mutation-kill tests for src/IntentWb.php (Intent Layer v2 W-B, NORMATIVE rules 16, 17, 18 and the decideIntentWb
 * composition). Every boundary is pinned on both sides, every refusal is asserted by its exact first-failure reason, and
 * inputs failing two steps assert that the earlier step wins. Artifacts are signed in-test from fixed seeds (sodium).
 */
final class IntentWbKillTest extends TestCase
{
    private const NOW = 1800000000000;
    private const AUD = 'skyair.example';
    private const GOV = 'gov.example';
    private const MAX_SAFE = 9007199254740991;
    private const MESSAGE = 'We are sorry for the delay.';

    // ---- fixtures ---------------------------------------------------------------------------------------------------

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION));
    }

    private static function d(string $label): string
    {
        return Pca::b64u(hash('sha256', $label, true));
    }

    /** @return array{0:string,1:string} [public b64u, secret key] from a fixed seed */
    private static function kp(string $label): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', "wb-kill/$label", true));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sess(): string
    {
        return self::d('session');
    }

    /** Sign an artifact body: sig = Ed25519(utf8(domain) || strictCanonical(body)). */
    private static function sign(string $domain, array $body, string $sk): array
    {
        $msg = IntentWb::artifactMessage($domain, self::o($body));
        return $body + ['sig' => Pca::b64u(sodium_crypto_sign_detached($msg, $sk))];
    }

    private static function json(Obj $o): string
    {
        return Json::canonicalizeStrict($o);
    }

    private static function action(array $params = []): array
    {
        return ['verb' => 'air.book', 'resource' => 'skyair.example/bookings',
            'params' => array_merge(['offer_id' => 'OF-2', 'total' => 77800, 'quote' => 38900, 'pax' => 2], $params)];
    }

    // rule 16 ---------------------------------------------------------------------------------------------------------

    private static function fact(string $oracle, mixed $value, int $tObs = self::NOW - 1000, string $name = 'fare',
        string $subject = 'OF-2', ?string $signer = null): array
    {
        return self::sign(IntentWb::FACT_DOMAIN, ['v' => 1, 'kind' => 'pca-fact', 'name' => $name, 'subject' => $subject,
            'value' => $value, 't_obs' => $tObs, 'oracle' => $oracle], self::kp($signer ?? $oracle)[1]);
    }

    private static function world(string $name = 'fare', int $min = 3, int $faulty = 1, array $kids = ['o1', 'o2', 'o3'],
        int $fresh = 60000, string $path = 'action.params.offer_id'): array
    {
        return ['name' => $name, 'subject_path' => $path,
            'oracles' => array_map(static fn(string $k): array => ['kid' => $k, 'pk' => self::kp($k)[0]], $kids),
            'freshness_ms' => $fresh, 'min_oracles' => $min, 'max_faulty' => $faulty];
    }

    private static function fref(array $f): string
    {
        return IntentWb::factRef(self::o($f));
    }

    private static function wIn(array $facts, array $policy, array $over = [], ?array $committed = null): Obj
    {
        $in = ['now' => self::NOW, 'aud' => self::AUD, 'session' => self::sess(), 'action' => self::action(),
            'committed' => $committed ?? ['facts' => array_map([self::class, 'fref'], $facts)],
            'facts' => $facts, 'policy' => $policy === [] ? (object)[] : $policy];
        return self::o(array_merge($in, $over));
    }

    private static function wd(array $facts, array $policy, array $over = [], ?array $committed = null): array
    {
        return IntentWb::decideIntentWorld(self::wIn($facts, $policy, $over, $committed));
    }

    /** Three fresh, signed fare facts 10 / 30 / 20 under world `fare` (n = 3, f = 1). */
    private static function three(array $values = [10, 30, 20]): array
    {
        return [self::fact('o1', $values[0]), self::fact('o2', $values[1]), self::fact('o3', $values[2])];
    }

    private function wFail(string $reason, array $r): void
    {
        $this->assertFalse($r['ok']);
        $this->assertSame("facts: $reason", $r['reason']);
        $this->assertArrayNotHasKey('world', $r);
    }

    private function wOk(string $world, array $r, array $single = []): void
    {
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
        $this->assertSame($world, self::json($r['world']));
        $this->assertSame($single, $r['single_source']);
    }

    // offers ------------------------------------------------------------------------------------------------------------

    private static function offerSet(array $over = [], string $kid = 's1', ?string $signer = null): array
    {
        $body = array_merge(['v' => 1, 'kind' => 'pca-offer-set', 'site' => self::AUD, 'session' => self::sess(),
            'query' => ['from' => 'LHR', 'to' => 'JFK'], 'rank' => 'price_asc', 'complete' => true,
            'offers' => [
                ['offer_id' => 'OF-1', 'price' => 39800, 'cabin' => 'economy'],
                ['offer_id' => 'OF-2', 'price' => 41000, 'cabin' => 'economy'],
                ['offer_id' => 'OF-3', 'price' => 30000, 'cabin' => 'basic'],
            ],
            'issued_at' => self::NOW - 1000, 'kid' => $kid], $over);
        return self::sign(IntentWb::OFFER_SET_DOMAIN, $body, self::kp($signer ?? $kid)[1]);
    }

    private static function offersPolicy(array $over = []): array
    {
        return array_merge(['name' => 'excess', 'site_keys' => [['kid' => 's1', 'pk' => self::kp('s1')[0]]], 'max_age_ms' => 300000,
            'offer_param' => 'action.params.offer_id',
            'filter' => ['query' => ['from' => 'LHR', 'to' => 'JFK'], 'offer' => ['cabin' => 'economy']]], $over);
    }

    private static function od(array $os, array $polOver = [], array $over = [], ?string $committed = null): array
    {
        $in = ['committed' => ['offer_set' => $committed ?? IntentWb::offerSetRef(self::o($os))], 'facts' => [],
            'offer_set' => $os];
        return IntentWb::decideIntentWorld(self::o(array_merge(['now' => self::NOW, 'aud' => self::AUD,
            'session' => self::sess(), 'action' => self::action(), 'policy' => ['offers' => self::offersPolicy($polOver)]], $in, $over)));
    }

    // rule 17 ---------------------------------------------------------------------------------------------------------

    private static function labelKeys(): array
    {
        return [['site' => self::AUD, 'kid' => 'k1', 'pk' => self::kp(self::AUD . '/k1')[0]],
            ['site' => self::GOV, 'kid' => 'k1', 'pk' => self::kp(self::GOV . '/k1')[0]]];
    }

    private static function provParams(): array
    {
        return ['offer_id' => 'OF-2', 'passport' => 'X1234567', 'note' => 'hi', 'total' => 77800];
    }

    private static function pIn(array $prov, array $pol = [], array $over = []): Obj
    {
        $in = ['aud' => self::AUD, 'session' => self::sess(), 'action' => ['params' => self::provParams()],
            'prov' => $prov === [] ? (object)[] : $prov, 'committed_labels' => [], 'labels' => [],
            'policy' => array_merge(['params' => ['action.params.offer_id' => 'critical', 'action.params.passport' => 'material'],
                'registry' => ['ref:offer' => 'first_party', 'ref:trusted' => 'trusted', 'ref:web' => 'web', 'ref:tool' => 'tool'],
                'label_keys' => self::labelKeys()], $pol)];
        return self::o(array_merge($in, $over));
    }

    private static function pd(array $prov, array $pol = [], array $over = []): array
    {
        return IntentWb::decideParamProvenance(self::pIn($prov, $pol, $over));
    }

    /** A receipt with fields [path => [class, value]] signed by "<site>/<kid>" (or `$signer`). */
    private static function receipt(string $site, array $fields, array $over = [], string $kid = 'k1', ?string $signer = null): array
    {
        $f = [];
        foreach ($fields as $path => [$class, $value]) {
            $f[$path] = ['class' => $class, 'value_digest' => IntentWb::valueDigest(self::o($value))];
        }
        $body = array_merge(['v' => 1, 'kind' => 'pca-labels', 'site' => $site, 'session' => self::sess(),
            'response_digest' => self::d('resp'), 'fields' => $f, 'issued_at' => self::NOW, 'kid' => $kid], $over);
        return self::sign(IntentWb::LABELS_DOMAIN, $body, self::kp($signer ?? "$site/$kid")[1]);
    }

    private static function rref(array $r): string
    {
        return IntentWb::labelReceiptRef(self::o($r));
    }

    private static function lref(array $r, string $field): string
    {
        return IntentWb::LABEL_REF_PREFIX . self::rref($r) . '#' . $field;
    }

    /** prov = {passport: [refs]}, receipts committed and supplied. */
    private static function ld(array $receipts, array $refs, array $pol = [], array $over = []): array
    {
        return self::pd(['action.params.passport' => $refs], $pol, array_merge([
            'committed_labels' => array_map([self::class, 'rref'], $receipts), 'labels' => $receipts], $over));
    }

    private static function passportReceipt(string $site = self::AUD, string $class = 'pii.passport', mixed $value = 'X1234567', string $field = 'passport'): array
    {
        return self::receipt($site, [$field => [$class, $value]]);
    }

    private function pFail(string $reason, array $r): void
    {
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame("provenance: $reason", $r['reason']);
        $this->assertSame('{}', self::json($r['env']));
    }

    private function pOut(string $outcome, string $labels, array $r, ?string $friction = null, string $classes = '{}'): void
    {
        $this->assertSame($outcome, $r['outcome'], $r['reason'] ?? '');
        $this->assertSame($labels, self::json($r['labels']));
        $this->assertSame($classes, self::json($r['classes']));
        if ($friction === null) {
            $this->assertArrayNotHasKey('friction', $r);
        } else {
            $this->assertSame($friction, $r['friction']);
            $this->assertSame('provenance: a tainted value needs the principal (lazy question)', $r['reason']);
        }
    }

    // rule 18 ---------------------------------------------------------------------------------------------------------

    private static function verdict(string $judge, string $label, array $over = []): array
    {
        $body = array_merge(['v' => 1, 'kind' => 'pca-intent-classification', 'classifier' => 'tone', 'session' => self::sess(),
            'content_digest' => IntentWb::contentDigest(self::MESSAGE), 'label' => $label, 'measurement' => 'm-tone-1',
            'judge' => self::kp($judge)[0]], $over);
        return self::sign(IntentWb::INTENT_CLASSIFIER_DOMAIN, $body, self::kp($judge)[1]);
    }

    private static function clsPolicy(array $over = []): array
    {
        return array_merge(['id' => 'tone', 'param' => 'action.params.message', 'labels' => ['neutral', 'apologetic', 'hostile', 'other'],
            'keys' => [self::kp('j1')[0], self::kp('j2')[0], self::kp('j3')[0]], 'k' => 2, 'measurements' => ['m-tone-1']], $over);
    }

    private static function vref(array $v): string
    {
        return IntentWb::classifierVerdictRef(self::o($v));
    }

    private static function cd(array $verdicts, array $polOver = [], array $over = [], ?array $committed = null, ?array $classifiers = null): array
    {
        return IntentWb::decideClassifierDimensions(self::o(array_merge(['session' => self::sess(),
            'action' => ['params' => ['message' => self::MESSAGE]], 'committed' => $committed ?? array_map([self::class, 'vref'], $verdicts),
            'verdicts' => $verdicts, 'policy' => ['classifiers' => $classifiers ?? [self::clsPolicy($polOver)]]], $over)));
    }

    private function cFail(string $reason, array $r): void
    {
        $this->assertFalse($r['ok']);
        $this->assertSame("classes: $reason", $r['reason']);
    }

    // ==== shared plumbing ==============================================================================================

    public function testConstants(): void
    {
        $this->assertSame("atlas-pca/fact/v1\0", IntentWb::FACT_DOMAIN);
        $this->assertSame('atlas-pca/fact-ref/v1', IntentWb::FACT_REF_DOMAIN);
        $this->assertSame("atlas-pca/offer-set/v1\0", IntentWb::OFFER_SET_DOMAIN);
        $this->assertSame('atlas-pca/offer-set-ref/v1', IntentWb::OFFER_SET_REF_DOMAIN);
        $this->assertSame("atlas-pca/labels/v1\0", IntentWb::LABELS_DOMAIN);
        $this->assertSame('atlas-pca/labels-ref/v1', IntentWb::LABELS_REF_DOMAIN);
        $this->assertSame("atlas-pca/intent-classifier/v1\0", IntentWb::INTENT_CLASSIFIER_DOMAIN);
        $this->assertSame('atlas-pca/intent-classifier-ref/v1', IntentWb::INTENT_CLASSIFIER_REF_DOMAIN);
        $this->assertSame([16, 16, 16, 60000], [IntentWb::MAX_COMMITTED_FACTS, IntentWb::MAX_WORLDS, IntentWb::MAX_RELATIONAL, IntentWb::DEFAULT_WORLD_SKEW_MS]);
        $this->assertSame([256, 32, 32, 64], [IntentWb::MAX_OFFERS, IntentWb::MAX_OFFER_ATTRS, IntentWb::MAX_QUERY_KEYS, IntentWb::MAX_LABEL_FIELDS]);
        $this->assertSame([32, 8, 16, 8, 32], [IntentWb::MAX_PROV_PATHS, IntentWb::MAX_PROV_REFS, IntentWb::MAX_COMMITTED_LABELS,
            IntentWb::MAX_COMMITTED_CLASSES, IntentWb::MAX_CLASSIFIER_LABELS]);
        $this->assertSame(['trusted', 'first_party', 'tool', 'web', 'agent'], IntentWb::TAINT_LEVELS);
    }

    public function testArtifactMessageAndRefsAreLiteral(): void
    {
        $f = ['v' => 1, 'kind' => 'pca-fact', 'name' => 'fare', 'subject' => 'OF-2', 'value' => 5, 't_obs' => 7, 'oracle' => 'o1', 'sig' => 'x'];
        $body = '{"kind":"pca-fact","name":"fare","oracle":"o1","subject":"OF-2","t_obs":7,"v":1,"value":5}';
        $this->assertSame("atlas-pca/fact/v1\0" . $body, IntentWb::artifactMessage(IntentWb::FACT_DOMAIN, self::o($f)));
        $withSig = '{"kind":"pca-fact","name":"fare","oracle":"o1","sig":"x","subject":"OF-2","t_obs":7,"v":1,"value":5}';
        $this->assertSame(Pca::b64u(hash('sha256', '{"d":"atlas-pca/fact-ref/v1","f":' . $withSig . '}', true)), IntentWb::factRef(self::o($f)));
        $this->assertSame(Pca::b64u(hash('sha256', '{"d":"atlas-pca/offer-set-ref/v1","o":1}', true)), IntentWb::offerSetRef(new Num('1')));
        $this->assertSame(Pca::b64u(hash('sha256', '{"d":"atlas-pca/labels-ref/v1","l":1}', true)), IntentWb::labelReceiptRef(new Num('1')));
        $this->assertSame(Pca::b64u(hash('sha256', '{"c":1,"d":"atlas-pca/intent-classifier-ref/v1"}', true)), IntentWb::classifierVerdictRef(new Num('1')));
        $this->assertSame(Pca::b64u(hash('sha256', '"X1234567"', true)), IntentWb::valueDigest('X1234567'));
        $this->assertSame(Pca::b64u(hash('sha256', '{"a":[1,true,null]}', true)), IntentWb::contentDigest(self::o(['a' => [1, true, null]])));
    }

    public function testCanonicalIsByNumericValue(): void
    {
        // JSON.parse yields the VALUE: 1.0, 1e0 and 10e-1 are the number 1; 2.50 is 2.5.
        foreach (['1.0', '1e0', '10e-1', '0.1e1', '1'] as $lex) {
            $this->assertSame(IntentWb::valueDigest(new Num('1')), IntentWb::valueDigest(new Num($lex)), $lex);
        }
        $this->assertSame(Pca::b64u(hash('sha256', '2.5', true)), IntentWb::valueDigest(new Num('2.50')));
        $this->assertSame(Pca::b64u(hash('sha256', '0.000001', true)), IntentWb::valueDigest(new Num('1e-6')));
        $this->assertSame(Pca::b64u(hash('sha256', '9007199254740991', true)), IntentWb::valueDigest(new Num('9007199254740991.0')));
        // Still refused by the strict profile: -0, unsafe integers, tiny / long fractions, a lone surrogate.
        foreach (['-0', '-0.0', '9007199254740992', '1e21', '1e-7', '0.1234567890123456', '1e999'] as $lex) {
            try {
                IntentWb::valueDigest(new Num($lex));
                $this->fail("no throw for $lex");
            } catch (\Atlas\Pca\JsonError) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(\Atlas\Pca\JsonError::class);
        IntentWb::valueDigest(Json::parseLax('"\ud800"'));
    }

    public function testJsNumStrAndJsStr(): void
    {
        $cases = [[1.0, '1'], [0.5, '0.5'], [-2.5, '-2.5'], [1e21, '1e+21'], [1.5e21, '1.5e+21'], [1e-7, '1e-7'],
            [1.25e-7, '1.25e-7'], [0.000001, '0.000001'], [123456789012345680000.0, '123456789012345680000'], [0.1 + 0.2, '0.30000000000000004'],
            [-0.0, '0'], [INF, 'Infinity'], [-INF, '-Infinity'], [NAN, 'NaN'], [100.0, '100']];
        foreach ($cases as [$v, $s]) {
            $this->assertSame($s, IntentWb::jsNumStr($v), (string)$s);
        }
        $this->assertSame('null', IntentWb::jsStr(null));
        $this->assertSame('true', IntentWb::jsStr(true));
        $this->assertSame('5', IntentWb::jsStr(new Num('5.0')));
        $this->assertSame('1,,x,2,3', IntentWb::jsStr(self::o([1, null, 'x', [2, 3]])));
        $this->assertSame('[object Object]', IntentWb::jsStr(new Obj()));
    }

    public function testSafeIntAndScalarEq(): void
    {
        foreach (['0', '5', '5.0', '1e3', '9007199254740991', '-9007199254740991'] as $lex) {
            $this->assertTrue(IntentWb::isSafeInt(new Num($lex)), $lex);
        }
        foreach (['-0', '-0.0', '0.5', '9007199254740992', '-9007199254740992', '1e999'] as $lex) {
            $this->assertFalse(IntentWb::isSafeInt(new Num($lex)), $lex);
        }
        foreach (['5', true, null, [], new Obj()] as $v) {
            $this->assertFalse(IntentWb::isSafeInt($v));
        }
        $this->assertTrue(IntentWb::scalarEq(new Num('2'), new Num('2.0')));
        $this->assertFalse(IntentWb::scalarEq(new Num('2'), '2'));
        $this->assertFalse(IntentWb::scalarEq(true, new Num('1')));
        $this->assertFalse(IntentWb::scalarEq(new Num('1'), true));
        $this->assertTrue(IntentWb::scalarEq('a', 'a'));
        $this->assertFalse(IntentWb::scalarEq('a', 'b'));
        $this->assertTrue(IntentWb::scalarEq(false, false));
        $this->assertFalse(IntentWb::scalarEq([], []));
    }

    public function testJsKeysOrder(): void
    {
        $o = self::o(['b' => 1, '10' => 1, 'a' => 1, '2' => 1, '01' => 1, '4294967295' => 1, '4294967294' => 1]);
        $this->assertSame(['2', '10', '4294967294', 'b', 'a', '01', '4294967295'], IntentWb::jsKeys($o));
    }

    public function testParamPaths(): void
    {
        $this->assertTrue(IntentWb::isParamPath('action.params.a'));
        $this->assertTrue(IntentWb::isParamPath('action.params.a-b_C9'));
        $this->assertTrue(IntentWb::isParamPath('action.params.' . implode('.', array_fill(0, 8, 'x'))));
        $this->assertFalse(IntentWb::isParamPath('action.params.' . implode('.', array_fill(0, 9, 'x'))));
        $this->assertTrue(IntentWb::isParamPath('action.params.' . str_repeat('a', 64)));
        $this->assertFalse(IntentWb::isParamPath('action.params.' . str_repeat('a', 65)));
        foreach (['action.params.', 'action.params.a.', 'action.params.a..b', "action.params.a\n", 'action.params.__proto__',
            'action.params.constructor', 'action.params.x.prototype', 'action.paramsx', 'params.a', 5] as $p) {
            $this->assertFalse(IntentWb::isParamPath($p), (string)json_encode($p));
        }
        $params = self::o(['a' => ['b' => 1, 'c' => null], 'arr' => [1]]);
        $this->assertSame(['found' => true, 'value' => null], IntentWb::resolveParamPath($params, 'action.params.a.c'));
        $this->assertTrue(IntentWb::resolveParamPath($params, 'action.params.a.b')['found']);
        $this->assertFalse(IntentWb::resolveParamPath($params, 'action.params.a.x')['found']);
        $this->assertFalse(IntentWb::resolveParamPath($params, 'action.params.arr.0')['found']); // arrays are not plain objects
        $this->assertFalse(IntentWb::resolveParamPath($params, 'action.params.a.b.c')['found']);
        $this->assertFalse(IntentWb::resolveParamPath($params, 'action.verb')['found']);
        $this->assertFalse(IntentWb::resolveParamPath('str', 'action.params.a')['found']);
    }

    public function testVerifyArtifactSigStrict(): void
    {
        $f = self::fact('o1', 5);
        [$pk] = self::kp('o1');
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o($f), $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::OFFER_SET_DOMAIN, self::o($f), $pk)); // domain separation
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o($f), self::kp('o2')[0]));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o(['value' => 6] + $f), $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o(['sig' => $f['sig'] . 'A'] + $f), $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o(['sig' => 5] + $f), $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, 'x', $pk));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, self::o($f), 'not-a-key'));
        // a value-equal re-encoding (5 -> 5.0) is the same JS value, so the same signed bytes
        $re = self::o($f);
        $re->set('value', new Num('5.0'));
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $re, $pk));
    }

    // ==== rule 16: worlds ==============================================================================================

    public function testEmptyIsOk(): void
    {
        $this->wOk('{}', self::wd([], []));
        $this->wOk('{}', self::wd([], [], [], ['facts' => []]));
    }

    public function testMedians(): void
    {
        $this->wOk('{"fare":20}', self::wd(self::three(), ['worlds' => [self::world()]]));
        $this->wOk('{"fare":20}', self::wd(self::three([30, 20, 10]), ['worlds' => [self::world()]]));
        // liar: one wild value cannot move the median beyond the honest range
        $this->wOk('{"fare":39800}', self::wd(self::three([39800, 1, 39900]), ['worlds' => [self::world()]]));
        // even n: LOWER median (index floor((n-1)/2))
        $facts = [self::fact('o1', 4), self::fact('o2', 1), self::fact('o3', 3), self::fact('o4', 2)];
        $this->wOk('{"fare":2}', self::wd($facts, ['worlds' => [self::world('fare', 4, 1, ['o1', 'o2', 'o3', 'o4'])]]));
        // n = 2 > min 1: lower of two
        $this->wOk('{"fare":5}', self::wd([self::fact('o1', 9), self::fact('o2', 5)], ['worlds' => [self::world('fare', 1, 0, ['o1', 'o2'])]]), ['fare']);
        $this->assertSame(2, IntentWb::lowerMedian([4, 1, 3, 2]));
        $this->assertSame(-5, IntentWb::lowerMedian([-5]));
        $this->expectException(\RuntimeException::class);
        IntentWb::lowerMedian([]);
    }

    public function testSingleSourceAndStrings(): void
    {
        $pol = ['worlds' => [self::world('fare', 1, 0, ['o1']), self::world('tier', 2, 0, ['o1', 'o2'])]];
        $facts = [self::fact('o1', 7), self::fact('o1', 'gold', self::NOW - 1000, 'tier'), self::fact('o2', 'gold', self::NOW - 1000, 'tier')];
        $r = self::wd($facts, $pol);
        $this->wOk('{"fare":7,"tier":"gold"}', $r, ['fare']);
        $this->assertSame(['fare', 'tier'], $r['world']->keys());
        $this->assertSame('7', $r['world']->get('fare')->lexeme);
        $disagree = [self::fact('o1', 'gold', self::NOW - 1000, 'tier'), self::fact('o2', 'silver', self::NOW - 1000, 'tier')];
        $this->wFail("world 'tier': string facts disagree", self::wd($disagree, ['worlds' => [self::world('tier', 2, 0, ['o1', 'o2'])]]));
        $mix = [self::fact('o1', 'gold', self::NOW - 1000, 'tier'), self::fact('o2', 5, self::NOW - 1000, 'tier')];
        $this->wFail("world 'tier': facts mix integer and string values", self::wd($mix, ['worlds' => [self::world('tier', 2, 0, ['o1', 'o2'])]]));
        // "5" and 5 are different JSON types: a string world, then disagreement is by string value
        $str = [self::fact('o1', '5', self::NOW - 1000, 'tier'), self::fact('o2', '5', self::NOW - 1000, 'tier')];
        $this->wOk('{"tier":"5"}', self::wd($str, ['worlds' => [self::world('tier', 2, 0, ['o1', 'o2'])]]));
    }

    public function testFreshnessAndSkewInclusive(): void
    {
        $pol = ['worlds' => [self::world('fare', 1, 0, ['o1'], 5000)]];
        $at = static fn(int $t): array => [self::fact('o1', 3, $t)];
        $this->wOk('{"fare":3}', self::wd($at(self::NOW - 5000), $pol), ['fare']);
        $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", self::wd($at(self::NOW - 5001), $pol));
        $this->wOk('{"fare":3}', self::wd($at(self::NOW + 60000), $pol), ['fare']); // default skew 60000, inclusive
        $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", self::wd($at(self::NOW + 60001), $pol));
        $pol['skew_ms'] = 10;
        $this->wOk('{"fare":3}', self::wd($at(self::NOW + 10), $pol), ['fare']);
        $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", self::wd($at(self::NOW + 11), $pol));
        $pol['skew_ms'] = 0;
        $this->wOk('{"fare":3}', self::wd($at(self::NOW), $pol), ['fare']);
        $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", self::wd($at(self::NOW + 1), $pol));
        // stale facts are not counted, never an error: 2 fresh of 3 with min 3
        $facts = [self::fact('o1', 1), self::fact('o2', 2), self::fact('o3', 3, self::NOW - 60001)];
        $this->wFail("world 'fare' has 2 fresh fact(s), needs 3", self::wd($facts, ['worlds' => [self::world()]]));
    }

    public function testClockMustBeSafeInteger(): void
    {
        $pol = ['worlds' => [self::world('fare', 1, 0, ['o1'])]];
        $facts = [self::fact('o1', 3)];
        foreach (['1800000000000', null, true, [1], 1800000000000.5] as $now) {
            $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", self::wd($facts, $pol, ['now' => $now]));
        }
        $in = self::wIn($facts, $pol);
        foreach (['-0', '1e999', '9007199254740992'] as $lex) {
            $in->set('now', new Num($lex));
            $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", IntentWb::decideIntentWorld($in));
        }
        // the VALUE decides, not the lexeme: 1.8e12 is the safe integer 1800000000000
        $in->set('now', new Num('1.8e12'));
        $this->wOk('{"fare":3}', IntentWb::decideIntentWorld($in), ['fare']);
        $in = self::wIn($facts, $pol);
        $in->set('now', new Num('1800000000000.0'));
        $this->wOk('{"fare":3}', IntentWb::decideIntentWorld($in), ['fare']);
        // absent now: stale too
        $in = self::wIn($facts, $pol);
        $in2 = $in->without('now');
        $this->wFail("world 'fare' has 0 fresh fact(s), needs 1", IntentWb::decideIntentWorld($in2));
        // relational dimensions need no clock
        $rel = ['relational' => [['name' => 'r', 'fn' => 'sub', 'a' => 'action.params.total', 'b' => 'action.params.quote']]];
        $this->wOk('{"r":38900}', self::wd([], $rel, ['now' => 'x']));
    }

    public function testUncommittedIgnoredAndCommitmentChecks(): void
    {
        $pol = ['worlds' => [self::world()]];
        $facts = self::three();
        $extra = self::fact('o1', 999, self::NOW - 5, 'other');
        $this->wOk('{"fare":20}', self::wd(array_merge($facts, [$extra, 'junk', 5, null]), $pol, [],
            ['facts' => array_map([self::class, 'fref'], $facts)]));
        $refs = array_map([self::class, 'fref'], $facts);
        $this->wFail('a committed fact was not supplied (or is malformed)', self::wd(array_slice($facts, 0, 2), $pol, [], ['facts' => $refs]));
        $this->wFail('duplicate committed fact digest', self::wd($facts, $pol, [], ['facts' => [$refs[0], $refs[1], $refs[0]]]));
        $this->wFail('a committed fact digest is not canonical base64url (32 bytes)', self::wd($facts, $pol, [], ['facts' => [$refs[0], 'abc']]));
        // first failure: the malformed digest precedes the duplicate
        $this->wFail('a committed fact digest is not canonical base64url (32 bytes)', self::wd($facts, $pol, [], ['facts' => [$refs[0], 5, $refs[0]]]));
        $this->wFail('duplicate committed fact digest', self::wd($facts, $pol, [], ['facts' => [$refs[0], $refs[0], 5]]));
        $this->wFail('committed facts must be a list of at most 16 digests', self::wd($facts, $pol, [], ['facts' => ['length' => 1]]));
        $this->wFail('committed facts must be a list of at most 16 digests', self::wd($facts, $pol, [], ['facts' => 'abc']));
        $many = [];
        for ($i = 0; $i < 17; $i++) {
            $many[] = self::d("c$i");
        }
        $this->wFail('committed facts must be a list of at most 16 digests', self::wd([], $pol, [], ['facts' => $many]));
        $this->wFail('a committed fact was not supplied (or is malformed)', self::wd([], $pol, [], ['facts' => array_slice($many, 0, 16)]));
        // ABSENT VS NULL: a present null committed list is malformed; absent is []
        $this->wFail('committed facts must be a list of at most 16 digests', self::wd([], [], [], ['facts' => null]));
        $this->wOk('{}', self::wd([], [], [], ['offer_set' => self::d('o')]));
        $this->wFail('the committed offer_set is not canonical base64url (32 bytes)', self::wd([], [], [], ['offer_set' => null]));
        $this->wFail('the committed offer_set is not canonical base64url (32 bytes)', self::wd([], [], [], ['offer_set' => 'abc']));
        // committed facts are judged before the committed offer set
        $this->wFail('duplicate committed fact digest', self::wd($facts, $pol, [], ['facts' => [$refs[0], $refs[0]], 'offer_set' => 'abc']));
        // policy is step 0
        $this->wFail('policy misconfigured (fail closed): skew_ms must be a non-negative safe integer',
            self::wd($facts, $pol + ['skew_ms' => -1], [], ['facts' => [5]]));
        // `committed` absent is {}; present it must be an object (null included)
        foreach (['str', null, [1]] as $c) {
            $this->wFail('committed must be an object', self::wd([], [], ['committed' => $c]));
        }
        $this->wOk('{}', IntentWb::decideIntentWorld(self::wIn([], [])->without('committed')));
        // order: policy, then action / params, then committed
        $this->wFail('policy misconfigured (fail closed): world policy must be an object', self::wd([], [], ['committed' => null, 'policy' => 5]));
        $this->wFail('action must be an object', self::wd([], [], ['committed' => null, 'action' => null]));
        $this->wFail('action.params must be an object', self::wd([], [], ['committed' => null, 'action' => ['params' => null]]));
    }

    public function testFactRefusalsInOrder(): void
    {
        $pol = ['worlds' => [self::world()]];
        $this->wFail("fact for undeclared world 'tier'", self::wd([self::fact('o1', 1, self::NOW - 1, 'tier')], $pol));
        $this->wFail("oracle 'o9' is not pinned for world 'fare'", self::wd([self::fact('o9', 1)], $pol));
        $this->wFail("bad oracle signature on a 'fare' fact", self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'OF-2', 'o2')], $pol));
        $this->wFail("a 'fare' fact names another subject", self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'OF-1')], $pol));
        $this->wFail("two facts from oracle 'o1' for world 'fare'", self::wd([self::fact('o1', 1), self::fact('o1', 2)], $pol));
        // committed order: the first committed fact's error wins
        $this->wFail("oracle 'o9' is not pinned for world 'fare'", self::wd([self::fact('o9', 1), self::fact('o1', 1, self::NOW - 1, 'tier')], $pol));
        $this->wFail("fact for undeclared world 'tier'", self::wd([self::fact('o1', 1, self::NOW - 1, 'tier'), self::fact('o9', 1)], $pol));
        // a bad signature is reported before the subject
        $this->wFail("bad oracle signature on a 'fare' fact", self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'OF-1', 'o2')], $pol));
        // tampering after signing: the reference still matches what was committed, the signature does not
        $t = self::fact('o1', 1);
        $t['value'] = 2;
        $this->wFail("bad oracle signature on a 'fare' fact", self::wd([$t], $pol));
        // subject paths: resource and verb
        $res = ['worlds' => [self::world('fare', 1, 0, ['o1'], 60000, 'action.resource')]];
        $this->wOk('{"fare":1}', self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'skyair.example/bookings')], $res), ['fare']);
        $verb = ['worlds' => [self::world('fare', 1, 0, ['o1'], 60000, 'action.verb')]];
        $this->wOk('{"fare":1}', self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'air.book')], $verb), ['fare']);
        $other = ['worlds' => [self::world('fare', 1, 0, ['o1'], 60000, 'action.other')]];
        $this->wFail("a 'fare' fact names another subject", self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', 'x')], $other));
        // a non-string subject value names no subject
        $this->wFail("a 'fare' fact names another subject", self::wd([self::fact('o1', 1, self::NOW - 1, 'fare', '77800')],
            ['worlds' => [self::world('fare', 1, 0, ['o1'], 60000, 'action.params.total')]]));
        // the action must be an object (absent, null or any other value fails); params absent = {}, present an object
        foreach (['str', [1], null] as $action) {
            $this->wFail('action must be an object', self::wd([self::fact('o1', 1)], $pol, ['action' => $action]));
            $this->wFail('action must be an object', self::wd([], [], ['action' => $action]));
        }
        $this->wFail('action must be an object', IntentWb::decideIntentWorld(self::wIn([], [])->without('action')));
        foreach ([null, 'x', [1]] as $params) {
            $this->wFail('action.params must be an object', self::wd([self::fact('o1', 1)], $pol, ['action' => ['verb' => 'v', 'resource' => 'r', 'params' => $params]]));
        }
        $this->wFail("a 'fare' fact names another subject", self::wd([self::fact('o1', 1)], $pol, ['action' => ['verb' => 'v', 'resource' => 'r']]));
    }

    public function testSuppliedFactsMustBeAnArray(): void
    {
        $pol = ['worlds' => [self::world('fare', 1, 0, ['o1'])]];
        $f = self::fact('o1', 3);
        $committed = ['facts' => [self::fref($f)]];
        // a supplied `facts` that is not a real array (an object, a string, a number, null) fails closed; never iterated
        foreach ([['a' => $f], 'abc', 5, true, null, ['length' => 1]] as $facts) {
            $this->wFail('facts must be an array', self::wd([], $pol, ['facts' => $facts], $committed));
            $this->wFail('facts must be an array', self::wd([], [], ['facts' => $facts], ['facts' => []]));
        }
        // absent: [] (so a commitment is unsupplied)
        $this->wFail('a committed fact was not supplied (or is malformed)', IntentWb::decideIntentWorld(self::wIn([], $pol, [], $committed)->without('facts')));
        // order: the committed digests and the committed offer set are judged before the supplied list
        $this->wFail('duplicate committed fact digest', self::wd([], $pol, ['facts' => 5], ['facts' => [self::fref($f), self::fref($f)]]));
        $this->wFail('the committed offer_set is not canonical base64url (32 bytes)', self::wd([], $pol, ['facts' => 5], ['offer_set' => 'x']));
        // a supplied offer_set must be an object when present (judged even without an offers policy), after the facts list
        foreach ([null, 'x', [1]] as $os) {
            $this->wFail('offer_set must be an object', self::wd([], [], ['offer_set' => $os], ['facts' => []]));
        }
        $this->wFail('facts must be an array', self::wd([], [], ['facts' => 5, 'offer_set' => null], ['facts' => []]));
        // a fact with a lone surrogate has no reference (never matches a commitment) and is skipped, not an error
        $bad = self::o($f);
        $bad->set('subject', Json::parseLax('"\\ud800"'));
        try {
            IntentWb::factRef($bad);
            $this->fail('a lone surrogate must not be canonical');
        } catch (\Atlas\Pca\JsonError) {
            $this->addToAssertionCount(1);
        }
        $in = self::wIn([$f], $pol);
        $in->set('facts', [$bad, self::o($f), 'junk', new Num('5'), null]);
        $this->wOk('{"fare":3}', IntentWb::decideIntentWorld($in), ['fare']);
    }

    public function testFactWire(): void
    {
        $f = self::o(self::fact('o1', 5));
        $this->assertNull(IntentWb::validateFactWire($f));
        $w = static function (array $over) use ($f): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($f));
            foreach ($over as $k => $v) {
                $g->set($k, $v);
            }
            return IntentWb::validateFactWire($g);
        };
        $this->assertSame('fact must be an object', IntentWb::validateFactWire([]));
        $this->assertSame("unknown member 'fact.x'", $w(['x' => 1]));
        $this->assertSame("missing member 'fact.sig'", IntentWb::validateFactWire($f->without('sig')));
        $this->assertNull($w(['v' => new Num('1.0')]));
        foreach ([new Num('2'), true, '1', null] as $v) {
            $this->assertSame('fact must be {v: 1, kind: "pca-fact"}', $w(['v' => $v]));
        }
        $this->assertSame('fact must be {v: 1, kind: "pca-fact"}', $w(['kind' => 'pca-facts']));
        $this->assertNull($w(['name' => 'a' . str_repeat('b', 63)]));
        foreach (['a' . str_repeat('b', 64), "fare\n", 'Fare', '1a', '', 5] as $n) {
            $this->assertSame("'fact.name' must match ^[a-z][a-z0-9_]{0,63}$", $w(['name' => $n]));
        }
        $this->assertNull($w(['subject' => str_repeat('s', 256)]));
        $this->assertSame("'fact.subject' must be a non-empty string (<= 256 bytes)", $w(['subject' => str_repeat('s', 257)]));
        $this->assertSame("'fact.subject' must be a non-empty string (<= 256 bytes)", $w(['subject' => '']));
        $this->assertSame("'fact.subject' must be a non-empty string (<= 256 bytes)", $w(['subject' => str_repeat("\u{e9}", 129)]));
        $this->assertNull($w(['value' => new Num((string)self::MAX_SAFE)]));
        $this->assertNull($w(['value' => new Num('-' . self::MAX_SAFE)]));
        $this->assertNull($w(['value' => str_repeat('v', 256)]));
        foreach ([new Num('9007199254740992'), new Num('0.5'), new Num('-0'), str_repeat('v', 257), '', true, null] as $v) {
            $this->assertSame("'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)", $w(['value' => $v]));
        }
        $this->assertNull($w(['t_obs' => new Num('0')]));
        foreach ([new Num('-1'), new Num('-0'), new Num('0.5'), '5'] as $v) {
            $this->assertSame("'fact.t_obs' must be a non-negative safe integer", $w(['t_obs' => $v]));
        }
        $this->assertNull($w(['oracle' => str_repeat('o', 64)]));
        $this->assertSame("'fact.oracle' must be a non-empty string (<= 64 bytes)", $w(['oracle' => str_repeat('o', 65)]));
        $this->assertSame("'fact.sig' must be a string", $w(['sig' => 5]));
        // order: unknown member before the kind check
        $this->assertSame("unknown member 'fact.x'", $w(['x' => 1, 'kind' => 'no']));
    }

    public function testWorldPolicyRefusals(): void
    {
        $e = static fn(array $p): ?string => IntentWb::validateWorldPolicy(self::o($p === [] ? (object)[] : $p));
        $this->assertNull($e([]));
        $this->assertSame('world policy must be an object', IntentWb::validateWorldPolicy([]));
        $this->assertNull($e(['skew_ms' => 0]));
        foreach ([-1, null, 0.5, '5'] as $v) {
            $this->assertSame('skew_ms must be a non-negative safe integer', $e(['skew_ms' => $v]));
        }
        $this->assertSame('worlds must be a list of at most 16', $e(['worlds' => ['length' => 0]]));
        $ws = [];
        for ($i = 0; $i < 17; $i++) {
            $ws[] = self::world("w$i", 1, 0, ['o1']);
        }
        $this->assertNull($e(['worlds' => array_slice($ws, 0, 16)]));
        $this->assertSame('worlds must be a list of at most 16', $e(['worlds' => $ws]));
        $this->assertSame('worlds must be a list of at most 16', $e(['worlds' => null])); // present null is malformed
        $this->assertSame('relational must be a list of at most 16', $e(['relational' => null]));
        $this->assertSame('world entry must be an object', $e(['worlds' => [5]]));
        $this->assertSame("dimension name 'Fare' must match ^[a-z][a-z0-9_]{0,63}$", $e(['worlds' => [self::world('Fare')]]));
        $this->assertSame("missing member 'world.name'", $e(['worlds' => [array_diff_key(self::world(), ['name' => 1])]]));
        $this->assertSame("dimension name 'null' must match ^[a-z][a-z0-9_]{0,63}$", $e(['worlds' => [['name' => null] + self::world()]]));
        $this->assertSame("dimension name '5' must match ^[a-z][a-z0-9_]{0,63}$", $e(['worlds' => [['name' => 5.0] + self::world()]]));
        $this->assertSame("duplicate dimension name 'fare'", $e(['worlds' => [self::world(), self::world()]]));
        $this->assertSame("world 'fare': subject_path must be rooted at action.", $e(['worlds' => [['subject_path' => 'params.x'] + self::world()]]));
        $this->assertSame("world 'fare': freshness_ms must be a non-negative safe integer", $e(['worlds' => [['freshness_ms' => -1] + self::world()]]));
        $this->assertSame("world 'fare': max_faulty must be a non-negative safe integer", $e(['worlds' => [['max_faulty' => -1] + self::world()]]));
        $this->assertNull($e(['worlds' => [self::world('fare', 3, 1)]]));
        $this->assertSame("world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1", $e(['worlds' => [self::world('fare', 2, 1)]]));
        $this->assertSame("world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1", $e(['worlds' => [self::world('fare', 0, 0)]]));
        $this->assertSame("world 'fare': fewer pinned oracles than min_oracles", $e(['worlds' => [self::world('fare', 3, 1, ['o1', 'o2'])]]));
        $this->assertSame("world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk", $e(['worlds' => [self::world('fare', 1, 0, ['o1', 'o1'])]]));
        $this->assertSame("world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk",
            $e(['worlds' => [['oracles' => [['kid' => 'o1', 'pk' => 'short']]] + self::world('fare', 1, 0)]]));
        $this->assertSame("world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk",
            $e(['worlds' => [['oracles' => [['kid' => str_repeat('k', 65), 'pk' => self::kp('o1')[0]]]] + self::world('fare', 1, 0)]]));
        // relational
        $w = [self::world('fare', 1, 0, ['o1'])];
        $rel = static fn(array $r): array => ['worlds' => $w, 'relational' => [$r]];
        $this->assertNull($e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'env.world.fare', 'b' => 'action.params.total'])));
        $this->assertNull($e($rel(['name' => 'd', 'fn' => 'ratio_ppm', 'a' => 'action.params.a-b', 'b' => 'action.params.x.y'])));
        $this->assertSame('relational must be a list of at most 16', $e(['relational' => 'x']));
        $this->assertSame('relational entry must be an object', $e(['relational' => [[]]]));
        $this->assertSame("duplicate dimension name 'fare'", $e($rel(['name' => 'fare', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => 'action.params.b'])));
        $this->assertSame("relational 'd': fn must be \"sub\" or \"ratio_ppm\"", $e($rel(['name' => 'd', 'fn' => 'add', 'a' => 'action.params.a', 'b' => 'action.params.b'])));
        $this->assertSame("relational 'd': operand 'env.world.d' must be an action.params path or an earlier env.world dimension",
            $e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => 'env.world.d'])));
        $this->assertSame("relational 'd': operand 'env.world.later' must be an action.params path or an earlier env.world dimension",
            $e(['worlds' => $w, 'relational' => [['name' => 'd', 'fn' => 'sub', 'a' => 'env.world.later', 'b' => 'action.params.a'],
                ['name' => 'later', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => 'action.params.b']]]));
        $this->assertSame("relational 'd': operand 'env.world.constructor' must be an action.params path or an earlier env.world dimension",
            $e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => 'env.world.constructor'])));
        $this->assertSame("relational 'd': operand 'action.params.__proto__' must be an action.params path or an earlier env.world dimension",
            $e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.__proto__', 'b' => 'action.params.b'])));
        $this->assertSame("missing member 'relational.b'", $e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.a'])));
        $this->assertSame("relational 'd': operand 'null' must be an action.params path or an earlier env.world dimension",
            $e($rel(['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => null])));
        // offers name claimed after worlds and relational
        $this->assertSame("duplicate dimension name 'fare'", $e(['worlds' => $w, 'offers' => self::offersPolicy(['name' => 'fare'])]));
        $this->assertSame("dimension name 'X' must match ^[a-z][a-z0-9_]{0,63}$", $e(['offers' => self::offersPolicy(['name' => 'X'])]));
        $this->assertSame('offers policy must be an object', $e(['offers' => null]));
        // first failure: a world error precedes a relational one
        $this->assertSame("world 'fare': fewer pinned oracles than min_oracles",
            $e(['worlds' => [self::world('fare', 3, 1, ['o1'])], 'relational' => 5]));
        // in decide: reported as misconfiguration
        $this->wFail("policy misconfigured (fail closed): duplicate dimension name 'fare'", self::wd([], ['worlds' => [self::world(), self::world()]]));
        $this->wFail('policy misconfigured (fail closed): world policy must be an object', self::wd([], [], ['policy' => [1]]));
        $this->wFail('policy misconfigured (fail closed): world policy must be an object', self::wd([], [], ['policy' => null]));
        $this->wOk('{}', IntentWb::decideIntentWorld(self::wIn([], [])->without('policy')));
    }

    public function testOfferPolicyRefusals(): void
    {
        $e = static fn(array $over): ?string => IntentWb::validateOfferPolicy(self::o(self::offersPolicy($over)));
        $this->assertNull($e([]));
        $this->assertSame('offers policy must be an object', IntentWb::validateOfferPolicy([]));
        $this->assertSame('offers policy needs a name', $e(['name' => 5]));
        $this->assertSame('offers policy needs at least one pinned site key', $e(['site_keys' => []]));
        $this->assertSame('offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk', $e(['site_keys' => [['kid' => 's1', 'pk' => 'x']]]));
        $this->assertSame('offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk',
            $e(['site_keys' => [['kid' => 's1', 'pk' => self::kp('a')[0]], ['kid' => 's1', 'pk' => self::kp('b')[0]]]]));
        $this->assertSame('offers policy: max_age_ms must be a non-negative safe integer', $e(['max_age_ms' => -1]));
        $this->assertNull($e(['max_age_ms' => 0]));
        $this->assertSame('offers policy: offer_param must be an action.params.* path', $e(['offer_param' => 'action.offer']));
        $this->assertSame('offers policy: filter must be exactly {query: {}, offer: {}}', $e(['filter' => ['query' => (object)[]]]));
        $this->assertSame('offers policy: filter must be exactly {query: {}, offer: {}}', $e(['filter' => ['query' => [], 'offer' => (object)[]]]));
        $this->assertSame('offers policy: filter values must be scalars', $e(['filter' => ['query' => ['a' => null], 'offer' => (object)[]]]));
        $this->assertSame('offers policy: filter values must be scalars', $e(['filter' => ['query' => (object)[], 'offer' => ['a' => 0.5]]]));
        $this->assertNull($e(['filter' => ['query' => ['a' => true, 'b' => 2.0], 'offer' => (object)[]]]));
    }

    public function testRelational(): void
    {
        $w = [self::world('fare', 3, 1)];
        $rel = static fn(string $fn, string $a, string $b, string $name = 'd'): array => ['name' => $name, 'fn' => $fn, 'a' => $a, 'b' => $b];
        $r = self::wd(self::three(), ['worlds' => $w, 'relational' => [
            $rel('sub', 'action.params.quote', 'env.world.fare', 'margin'),
            $rel('ratio_ppm', 'env.world.margin', 'action.params.total', 'share'),
            $rel('sub', 'action.params.pax', 'action.params.total', 'neg'),
        ]]);
        $this->wOk('{"fare":20,"margin":38880,"neg":-77798,"share":499742}', $r);
        $this->assertSame(['fare', 'margin', 'share', 'neg'], $r['world']->keys());
        $one = static fn(array $p, array $r): array => self::wd([], ['relational' => [$r]], ['action' => self::action($p)]);
        $this->wFail("relational 'd': result undefined or outside the safe integer range", $one(['z' => 0], $rel('ratio_ppm', 'action.params.total', 'action.params.z')));
        $this->wFail("relational 'd': result undefined or outside the safe integer range", $one(['z' => -1], $rel('ratio_ppm', 'action.params.z', 'action.params.total')));
        $this->wFail("relational 'd': result undefined or outside the safe integer range", $one(['z' => -1], $rel('ratio_ppm', 'action.params.total', 'action.params.z')));
        $this->wOk('{"d":0}', $one(['z' => 0], $rel('ratio_ppm', 'action.params.z', 'action.params.total')));
        $this->wFail("relational 'd': result undefined or outside the safe integer range",
            $one(['big' => self::MAX_SAFE, 'b' => 999999], $rel('ratio_ppm', 'action.params.big', 'action.params.b')));
        $this->wOk('{"d":' . self::MAX_SAFE . '}', $one(['big' => self::MAX_SAFE, 'b' => 1000000], $rel('ratio_ppm', 'action.params.big', 'action.params.b')));
        $this->wFail("relational 'd': result undefined or outside the safe integer range",
            $one(['a' => -self::MAX_SAFE, 'b' => 1], $rel('sub', 'action.params.a', 'action.params.b')));
        $this->wOk('{"d":-' . self::MAX_SAFE . '}', $one(['a' => -self::MAX_SAFE + 1, 'b' => 1], $rel('sub', 'action.params.a', 'action.params.b')));
        $this->wFail("relational 'd': result undefined or outside the safe integer range",
            $one(['a' => self::MAX_SAFE, 'b' => -1], $rel('sub', 'action.params.a', 'action.params.b')));
        $this->wFail("relational 'd': an operand is missing or not a safe integer", $one([], $rel('sub', 'action.params.nope', 'action.params.total')));
        $this->wFail("relational 'd': an operand is missing or not a safe integer", $one(['s' => '5'], $rel('sub', 'action.params.total', 'action.params.s')));
        $this->wFail("relational 'd': an operand is missing or not a safe integer", $one(['s' => 0.5], $rel('sub', 'action.params.total', 'action.params.s')));
        $this->wFail("relational 'd': an operand is missing or not a safe integer", $one(['s' => true], $rel('sub', 'action.params.total', 'action.params.s')));
        // numeric value, not lexeme: 2.0 is a safe integer
        $this->wOk('{"d":77798}', $one(['s' => 2.0], $rel('sub', 'action.params.total', 'action.params.s')));
        // a string world is no relational operand
        $tier = [self::fact('o1', 'gold', self::NOW - 1, 'tier')];
        $this->wFail("relational 'd': an operand is missing or not a safe integer", self::wd($tier, ['worlds' => [self::world('tier', 1, 0, ['o1'])],
            'relational' => [$rel('sub', 'env.world.tier', 'action.params.total')]]));
        // a null action is refused up front
        $this->wFail('action must be an object', self::wd([], ['relational' => [$rel('sub', 'action.params.total', 'action.params.quote')]], ['action' => null]));
    }

    public function testRatioPpmExact(): void
    {
        $this->assertNull(IntentWb::ratioPpm(1, 0));
        $this->assertNull(IntentWb::ratioPpm(1, -1));
        $this->assertNull(IntentWb::ratioPpm(-1, 1));
        $this->assertSame(0, IntentWb::ratioPpm(0, 7));
        $this->assertSame(333333, IntentWb::ratioPpm(1, 3));
        $this->assertSame(2000000, IntentWb::ratioPpm(2, 1));
        $this->assertNull(IntentWb::ratioPpm(9000000000000, 7)); // 1.29e18 ppm > 2^53-1: no exact ratio (reference: null)
        foreach ([[1234567, 89], [77800, 38900], [5, 9007199254740991]] as [$a, $b]) {
            $this->assertSame(intdiv($a * 1000000, $b), IntentWb::ratioPpm($a, $b), "$a/$b");
        }
        // beyond float precision: (2^53-2)*10^6 / (2^53-1) = 999999.99999999988... -> 999999
        $this->assertSame(999999, IntentWb::ratioPpm(self::MAX_SAFE - 1, self::MAX_SAFE));
        $this->assertSame(1000000, IntentWb::ratioPpm(self::MAX_SAFE, self::MAX_SAFE));
        $this->assertSame(self::MAX_SAFE, IntentWb::ratioPpm(self::MAX_SAFE, 1000000));
        $this->assertNull(IntentWb::ratioPpm(self::MAX_SAFE, 999999));
        $this->assertSame(9007199254000000, IntentWb::ratioPpm(9007199254, 1));
        $this->assertNull(IntentWb::ratioPpm(9007199255, 1));
    }

    public function testProtoNames(): void
    {
        $pol = ['worlds' => [self::world('constructor', 1, 0, ['o1']), self::world('valueof', 1, 0, ['o1'])],
            'relational' => [['name' => 'tostring', 'fn' => 'sub', 'a' => 'env.world.constructor', 'b' => 'action.params.pax']]];
        $facts = [self::fact('o1', 7, self::NOW - 1, 'constructor'), self::fact('o1', 'gold', self::NOW - 1, 'valueof')];
        $this->wOk('{"constructor":7,"tostring":5,"valueof":"gold"}', self::wd($facts, $pol), ['constructor', 'valueof']);
    }

    // ==== rule 16 step 6: offer sets ===================================================================================

    public function testOffersExcessAndCheapest(): void
    {
        $this->wOk('{"excess":1200}', self::od(self::offerSet()));
        $this->wOk('{"excess":0}', self::od(self::offerSet(), [], ['action' => self::action(['offer_id' => 'OF-1'])]));
        // filter decides the minimum: without the cabin filter OF-3 (30000) is the cheapest
        $this->wOk('{"excess":11000}', self::od(self::offerSet(), ['filter' => ['query' => ['from' => 'LHR', 'to' => 'JFK'], 'offer' => (object)[]]]));
        // broader / empty query: fine
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['query' => ['from' => 'LHR']])));
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['query' => (object)[]])));
        // offers with facts: worlds first, then relational, then the offers name
        $pol = ['worlds' => [self::world('fare', 3, 1)], 'offers' => self::offersPolicy()];
        $facts = self::three();
        $os = self::offerSet();
        $r = IntentWb::decideIntentWorld(self::o(['now' => self::NOW, 'aud' => self::AUD, 'session' => self::sess(), 'action' => self::action(),
            'committed' => ['facts' => array_map([self::class, 'fref'], $facts), 'offer_set' => IntentWb::offerSetRef(self::o($os))],
            'facts' => $facts, 'offer_set' => $os, 'policy' => $pol]));
        $this->wOk('{"excess":1200,"fare":20}', $r);
        $this->assertSame(['fare', 'excess'], $r['world']->keys());
    }

    public function testOffersTypedEquality(): void
    {
        $pol = ['filter' => ['query' => ['stops' => 0, 'flex' => true], 'offer' => ['cabin' => 'economy']]];
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['query' => ['stops' => 0.0, 'flex' => true]]), $pol));
        $this->wFail('offers: the search was narrowed beyond the intent filter (coverage)', self::od(self::offerSet(['query' => ['stops' => '0']]), $pol));
        $this->wFail('offers: the search was narrowed beyond the intent filter (coverage)', self::od(self::offerSet(['query' => ['flex' => 1]]), $pol));
        $this->wFail('offers: the search was narrowed beyond the intent filter (coverage)', self::od(self::offerSet(['query' => ['stops' => 1]]), $pol));
        $this->wFail('offers: the search was narrowed beyond the intent filter (coverage)', self::od(self::offerSet(['query' => ['seller' => 'X']]), $pol));
        // offer filter equality: price is an own member too
        // (the search query must be covered by the filter query, here empty, or coverage refuses first like the reference)
        $this->wFail('offers: the chosen offer does not satisfy the intent filter',
            self::od(self::offerSet(['query' => (object)[]]), ['filter' => ['query' => (object)[], 'offer' => ['price' => '41000']]]));
        $this->wOk('{"excess":0}', self::od(self::offerSet(['query' => (object)[]]), ['filter' => ['query' => (object)[], 'offer' => ['price' => 41000.0]]]));
        $this->wFail('offers: the chosen offer does not satisfy the intent filter',
            self::od(self::offerSet(['query' => (object)[]]), ['filter' => ['query' => (object)[], 'offer' => ['refundable' => true]]]));
    }

    public function testOffersFreshnessInclusive(): void
    {
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['issued_at' => self::NOW - 300000])));
        $this->wFail('offers: the offer set is stale', self::od(self::offerSet(['issued_at' => self::NOW - 300001])));
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['issued_at' => self::NOW + 60000])));
        $this->wFail('offers: the offer set is issued in the future', self::od(self::offerSet(['issued_at' => self::NOW + 60001])));
        $os = self::offerSet(['issued_at' => self::NOW + 5]);
        $in = static fn(int $skew): array => IntentWb::decideIntentWorld(self::o(['now' => self::NOW, 'aud' => self::AUD, 'session' => self::sess(),
            'action' => self::action(), 'committed' => ['offer_set' => IntentWb::offerSetRef(self::o($os))], 'offer_set' => $os,
            'policy' => ['skew_ms' => $skew, 'offers' => self::offersPolicy()]]));
        $this->wOk('{"excess":1200}', $in(5));
        $this->wFail('offers: the offer set is issued in the future', $in(4));
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['issued_at' => self::NOW]), ['max_age_ms' => 0]));
        $this->wFail('offers: the offer set is stale', self::od(self::offerSet(['issued_at' => self::NOW - 1]), ['max_age_ms' => 0]));
        foreach (['1800000000000', null, 1800000000000.5] as $now) {
            $this->wFail('offers: no usable clock (now must be a safe integer): the offer set counts as stale', self::od(self::offerSet(), [], ['now' => $now]));
        }
        // the clock check follows the session check
        $this->wFail('offers: the offer set is bound to another session', self::od(self::offerSet(['session' => self::d('other')]), [], ['now' => 'x']));
    }

    public function testOffersRefusalsInOrder(): void
    {
        $os = self::offerSet();
        $this->wFail('offers: the PCActn commits no offer set but the policy requires one',
            IntentWb::decideIntentWorld(self::o(['now' => self::NOW, 'aud' => self::AUD, 'session' => self::sess(), 'action' => self::action(),
                'committed' => (object)[], 'offer_set' => $os, 'policy' => ['offers' => self::offersPolicy()]])));
        $noSet = self::wIn([], ['offers' => self::offersPolicy()], [], ['offer_set' => IntentWb::offerSetRef(self::o($os))]);
        $this->wFail('offers: the committed offer set was not supplied', IntentWb::decideIntentWorld($noSet));
        $this->wFail('offer_set must be an object', self::od($os, [], ['offer_set' => null], IntentWb::offerSetRef(self::o($os))));
        $this->wFail('offers: the supplied offer set does not match the committed reference', self::od($os, [], [], self::d('x')));
        $this->wFail("offers: signing key 's9' is not pinned", self::od(self::offerSet([], 's9')));
        $this->wFail('offers: bad site signature', self::od(self::offerSet([], 's1', 's2')));
        $this->wFail('offers: the offer set was issued for another audience', self::od(self::offerSet(['site' => self::GOV])));
        $this->wFail('offers: the offer set is bound to another session', self::od(self::offerSet(['session' => self::d('other')])));
        $this->wFail('offers: the offer set is not declared complete', self::od(self::offerSet(['complete' => false])));
        $this->wFail('offers: the action names no offer id at the declared parameter', self::od($os, [], ['action' => self::action(['offer_id' => 2])]));
        $this->wFail('offers: the action names no offer id at the declared parameter', self::od($os, ['offer_param' => 'action.params.nope']));
        $this->wFail('offers: the chosen offer is not in the signed offer set', self::od($os, [], ['action' => self::action(['offer_id' => 'OF-9'])]));
        $this->wFail('offers: the chosen offer does not satisfy the intent filter', self::od($os, [], ['action' => self::action(['offer_id' => 'OF-3'])]));
        // order: the reference is checked before the pin, the pin before the audience
        $this->wFail('offers: the supplied offer set does not match the committed reference', self::od(self::offerSet([], 's9'), [], [], self::d('x')));
        $this->wFail("offers: signing key 's9' is not pinned", self::od(self::offerSet(['site' => self::GOV], 's9')));
        $this->wFail('offers: bad site signature', self::od(self::offerSet(['site' => self::GOV], 's1', 's2')));
        $this->wFail('offers: the offer set was issued for another audience', self::od(self::offerSet(['site' => self::GOV, 'complete' => false])));
        $this->wFail('offers: the offer set is not declared complete', self::od(self::offerSet(['complete' => false, 'query' => ['x' => 1]])));
        $this->wFail('action must be an object', self::od($os, [], ['action' => null]));
        // the offer set is only required when the policy declares offers: a commitment alone is fine
        $this->wOk('{}', self::wd([], [], [], ['offer_set' => IntentWb::offerSetRef(self::o($os))]));
    }

    public function testOfferSetWire(): void
    {
        $base = self::o(self::offerSet());
        $this->assertNull(IntentWb::validateOfferSetWire($base));
        $w = static function (array $over) use ($base): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($base));
            foreach ($over as $k => $v) {
                $g->set($k, self::o($v));
            }
            return IntentWb::validateOfferSetWire($g);
        };
        $offers = static fn(int $n, array $extra = []): array => array_map(static fn(int $i): array => ['offer_id' => "O$i", 'price' => $i] + $extra, range(0, $n - 1));
        $this->assertSame('offer set must be an object', IntentWb::validateOfferSetWire('x'));
        $this->assertSame("unknown member 'offer_set.x'", $w(['x' => 1]));
        $this->assertSame("missing member 'offer_set.kid'", IntentWb::validateOfferSetWire($base->without('kid')));
        $this->assertSame('offer set must be {v: 1, kind: "pca-offer-set"}', $w(['v' => 2]));
        $this->assertSame("'offer_set.site' must be a non-empty string (<= 256 bytes)", $w(['site' => str_repeat('s', 257)]));
        $this->assertNull($w(['site' => str_repeat('s', 256)]));
        $this->assertSame("'offer_set.session' must be canonical base64url (32 bytes)", $w(['session' => 'abc']));
        $q = [];
        for ($i = 0; $i < 33; $i++) {
            $q["k$i"] = $i;
        }
        $this->assertNull($w(['query' => array_slice($q, 0, 32)]));
        $this->assertSame("'offer_set.query' must be an object with <= 32 keys", $w(['query' => $q]));
        $this->assertSame("'offer_set.query' must be an object with <= 32 keys", $w(['query' => [1]]));
        $this->assertSame("'offer_set.query.a' must be a scalar", $w(['query' => ['a' => null]]));
        $this->assertSame("'offer_set.query.' must be a scalar", $w(['query' => ['' => 1]]));
        $this->assertSame("'offer_set.query." . str_repeat('k', 65) . "' must be a scalar", $w(['query' => [str_repeat('k', 65) => 1]]));
        $this->assertSame("'offer_set.rank' must be \"price_asc\"", $w(['rank' => 'price_desc']));
        $this->assertSame("'offer_set.complete' must be a boolean", $w(['complete' => 1]));
        $this->assertSame("'offer_set.offers' must hold 1..256 offers", $w(['offers' => []]));
        $this->assertNull($w(['offers' => $offers(256)]));
        $this->assertSame("'offer_set.offers' must hold 1..256 offers", $w(['offers' => $offers(257)]));
        $this->assertSame('offer 1 must be an object', $w(['offers' => [['offer_id' => 'a', 'price' => 1], 5]]));
        $this->assertSame("offer 0: 'offer_id' must be a non-empty string (<= 128 bytes)", $w(['offers' => [['offer_id' => str_repeat('o', 129), 'price' => 1]]]));
        $this->assertNull($w(['offers' => [['offer_id' => str_repeat('o', 128), 'price' => 0]]]));
        $this->assertSame('offer 1: duplicate offer_id', $w(['offers' => [['offer_id' => 'a', 'price' => 1], ['offer_id' => 'a', 'price' => 2]]]));
        $this->assertSame("offer 0: 'price' must be a non-negative safe integer", $w(['offers' => [['offer_id' => 'a', 'price' => -1]]]));
        $this->assertSame("offer 0: 'price' must be a non-negative safe integer", $w(['offers' => [['offer_id' => 'a']]]));
        $attrs = [];
        for ($i = 0; $i < 33; $i++) {
            $attrs["a$i"] = 'x';
        }
        $this->assertNull($w(['offers' => [['offer_id' => 'a', 'price' => 1] + array_slice($attrs, 0, 32)]]));
        $this->assertSame('offer 0: more than 32 attributes', $w(['offers' => [['offer_id' => 'a', 'price' => 1] + $attrs]]));
        $this->assertSame("offer 0: attribute 'x' must be a scalar", $w(['offers' => [['offer_id' => 'a', 'price' => 1, 'x' => ['y' => 1]]]]));
        $this->assertSame("'offer_set.issued_at' must be a non-negative safe integer", $w(['issued_at' => -1]));
        $this->assertSame("'offer_set.kid' must be a non-empty string (<= 64 bytes)", $w(['kid' => '']));
        $this->assertSame("'offer_set.sig' must be a string", $w(['sig' => null]));
        // first failure: offers before issued_at
        $this->assertSame("'offer_set.offers' must hold 1..256 offers", $w(['offers' => [], 'issued_at' => -1]));
        // in decide: wire refusals are prefixed
        $this->wFail('offers: offer 1: duplicate offer_id', self::od(self::offerSet(['offers' => [['offer_id' => 'OF-2', 'price' => 1], ['offer_id' => 'OF-2', 'price' => 2]]])));
    }

    // ==== rule 17: provenance ==========================================================================================

    public function testRegistryClassificationAndJoin(): void
    {
        $this->pOut('pass', '{"action.params.offer_id":"first_party","action.params.passport":"trusted"}',
            self::pd(['action.params.offer_id' => ['ref:offer'], 'action.params.passport' => ['ref:trusted']]));
        // join = least trusted; any tainted material value is a question (default `question`, tap)
        $this->pOut('question', '{"action.params.offer_id":"first_party","action.params.passport":"web"}',
            self::pd(['action.params.offer_id' => ['ref:offer', 'ref:trusted'], 'action.params.passport' => ['ref:trusted', 'ref:web']]), 'tap');
        // unknown and prototype-named refs are `agent` (own registry keys only); a critical agent value: typed question
        $this->pOut('question', '{"action.params.offer_id":"agent","action.params.passport":"trusted"}',
            self::pd(['action.params.offer_id' => ['__proto__', 'constructor', 'toString'], 'action.params.passport' => ['ref:trusted']]), 'typed');
        // undeclared material / critical parameters the action carries: agent; ones it does not carry: unclassified
        $this->pOut('question', '{"action.params.offer_id":"agent","action.params.passport":"agent"}', self::pd([]), 'typed');
        $this->pOut('pass', '{"action.params.passport":"trusted"}', self::pd(['action.params.passport' => ['ref:trusted']], [],
            ['action' => ['params' => ['passport' => 'X']]]));
        // a free parameter declared in prov is classified (no sensitivity, so no question)
        $this->pOut('question', '{"action.params.note":"agent","action.params.offer_id":"agent","action.params.passport":"agent"}',
            self::pd(['action.params.note' => ['x']]), 'typed');
        // env nests the labels
        $r = self::pd(['action.params.offer_id' => ['ref:offer'], 'action.params.passport' => ['ref:trusted']]);
        $this->assertSame('{"action":{"params":{"offer_id":"first_party","passport":"trusted"}}}', self::json($r['env']));
        $this->assertSame('agent', IntentWb::joinLabels([]));
        $this->assertSame('tool', IntentWb::joinLabels(['trusted', 'tool', 'first_party']));
        $this->assertSame(4, IntentWb::labelRank('constructor'));
        $this->assertSame(0, IntentWb::labelRank('trusted'));
        $this->assertSame('agent', IntentWb::classifyRef('toString', self::o(['ref' => 'trusted'])));
        $this->assertSame('agent', IntentWb::classifyRef('', self::o(['' => 'trusted'])));
        $this->assertSame('agent', IntentWb::classifyRef('x', self::o(['x' => 'bogus'])));
        $this->assertSame('web', IntentWb::classifyRef('x', self::o(['x' => 'web'])));
    }

    public function testTaintedModes(): void
    {
        $prov = ['action.params.offer_id' => ['ref:tool'], 'action.params.passport' => ['ref:web']];
        $this->pOut('question', '{"action.params.offer_id":"tool","action.params.passport":"web"}', self::pd($prov), 'typed');
        $this->pOut('question', '{"action.params.offer_id":"tool","action.params.passport":"web"}', self::pd($prov, ['critical_tainted' => 'question']), 'tap');
        $this->pOut('question', '{"action.params.offer_id":"tool","action.params.passport":"web"}',
            self::pd($prov, ['critical_tainted' => 'question', 'material_tainted' => 'question_typed']), 'typed');
        $this->pOut('question', '{"action.params.offer_id":"tool","action.params.passport":"web"}',
            self::pd($prov, ['critical_tainted' => 'question', 'material_tainted' => 'allow']), 'tap');
        $this->pFail("tainted material parameter 'action.params.passport' (provenance 'web') is denied by policy",
            self::pd($prov, ['material_tainted' => 'deny']));
        $this->pFail("tainted critical parameter 'action.params.offer_id' (provenance 'tool') is denied by policy",
            self::pd($prov, ['critical_tainted' => 'deny', 'material_tainted' => 'deny'])); // ascending order: offer_id first
        // first_party is not tainted (rank 1 < 2)
        $this->pOut('pass', '{"action.params.offer_id":"first_party","action.params.passport":"first_party"}',
            self::pd(['action.params.offer_id' => ['ref:offer'], 'action.params.passport' => ['ref:offer']], ['material_tainted' => 'deny', 'critical_tainted' => 'deny']));
        $this->pOut('pass', '{"action.params.offer_id":"first_party","action.params.passport":"tool"}',
            self::pd(['action.params.offer_id' => ['ref:offer'], 'action.params.passport' => ['ref:tool']], ['material_tainted' => 'allow']));
    }

    public function testCriticalMax(): void
    {
        $this->pOut('pass', '{"action.params.offer_id":"first_party","action.params.passport":"trusted"}',
            self::pd(['action.params.offer_id' => ['ref:offer'], 'action.params.passport' => ['ref:trusted']], ['critical_max' => 'first_party']));
        $this->pFail("critical parameter 'action.params.offer_id' has provenance 'tool', above the policy maximum 'first_party'",
            self::pd(['action.params.offer_id' => ['ref:tool'], 'action.params.passport' => ['ref:trusted']], ['critical_max' => 'first_party', 'critical_tainted' => 'deny']));
        $this->pFail("critical parameter 'action.params.offer_id' has provenance 'agent', above the policy maximum 'web'",
            self::pd(['action.params.passport' => ['ref:trusted']], ['critical_max' => 'web']));
        // a material parameter is never capped
        $this->pOut('question', '{"action.params.offer_id":"trusted","action.params.passport":"agent"}',
            self::pd(['action.params.offer_id' => ['ref:trusted']], ['critical_max' => 'trusted']), 'tap');
    }

    public function testLabelRefs(): void
    {
        $rc = self::passportReceipt();
        $this->pOut('pass', '{"action.params.passport":"first_party"}',
            self::ld([$rc], [self::lref($rc, 'passport')], ['params' => ['action.params.passport' => 'material']]), null, '{"action.params.passport":["pii.passport"]}');
        // value mismatch: agent, class still attached
        $bad = self::passportReceipt(self::AUD, 'pii.passport', 'Y0000000');
        $this->pOut('question', '{"action.params.passport":"agent"}', self::ld([$bad], [self::lref($bad, 'passport')], ['params' => ['action.params.passport' => 'material']]),
            'tap', '{"action.params.passport":["pii.passport"]}');
        // value digest is of the JS value: 2.0 matches a receipt for 2
        $num = self::receipt(self::AUD, ['n' => ['public', 2]]);
        $this->pOut('pass', '{"action.params.passport":"first_party"}', self::ld([$num], [self::lref($num, 'n')], ['params' => (object)[]],
            ['action' => ['params' => ['passport' => 2.0]]]), null, '{"action.params.passport":["public"]}');
        // foreign site: tool, needs a flow rule
        $gov = self::passportReceipt(self::GOV);
        $this->pFail("flow: class 'pii.passport' from 'gov.example' may not reach 'skyair.example' (parameter 'action.params.passport')",
            self::ld([$gov], [self::lref($gov, 'passport')], ['params' => (object)[]]));
        $this->pOut('pass', '{"action.params.passport":"tool"}', self::ld([$gov], [self::lref($gov, 'passport')],
            ['params' => (object)[], 'flows' => ['pii.*' => [self::AUD]]]), null, '{"action.params.passport":["pii.passport"]}');
        $this->pOut('pass', '{"action.params.passport":"tool"}', self::ld([$gov], [self::lref($gov, 'passport')],
            ['params' => (object)[], 'flows' => ['*' => [self::AUD]]]), null, '{"action.params.passport":["pii.passport"]}');
        // public goes anywhere
        $pub = self::passportReceipt(self::GOV, 'public');
        $this->pOut('pass', '{"action.params.passport":"tool"}', self::ld([$pub], [self::lref($pub, 'passport')], ['params' => (object)[]]),
            null, '{"action.params.passport":["public"]}');
        // joined with a registry ref; classes sorted and de-duplicated
        $two = self::receipt(self::AUD, ['a' => ['pii.z', 'X1234567'], 'b' => ['pii.a', 'X1234567'], 'c' => ['pii.z', 'X1234567']]);
        $this->pOut('pass', '{"action.params.passport":"first_party"}', self::ld([$two],
            [self::lref($two, 'a'), self::lref($two, 'b'), self::lref($two, 'c'), 'ref:trusted'], ['params' => (object)[]]),
            null, '{"action.params.passport":["pii.a","pii.z"]}');
        // split at the FIRST '#': the field is "a#b"
        $hash = self::receipt(self::AUD, ['a#b' => ['public', 'X1234567']]);
        $this->pOut('pass', '{"action.params.passport":"first_party"}', self::ld([$hash], [self::lref($hash, 'a#b')], ['params' => (object)[]]),
            null, '{"action.params.passport":["public"]}');
        $this->assertSame(['receipt' => self::d('x'), 'field' => 'a#b'], IntentWb::parseLabelRef('pca-labels:' . self::d('x') . '#a#b'));
        $this->assertNull(IntentWb::parseLabelRef('pca-labels:' . self::d('x') . '#'));
        $this->assertNull(IntentWb::parseLabelRef('pca-labels:' . self::d('x')));
        $this->assertNull(IntentWb::parseLabelRef('pca-labels:abc#f'));
        $this->assertNull(IntentWb::parseLabelRef('pca-label:' . self::d('x') . '#f'));
    }

    public function testFlowRules(): void
    {
        $rules = self::o(['pii.*' => [self::AUD], 'pii.contact' => [], 'pii.contact.*' => ['b'], 'p.*' => ['c'], '*' => ['d']]);
        $this->assertSame('pii.contact', IntentWb::flowRuleFor($rules, 'pii.contact'));
        $this->assertSame('pii.contact.*', IntentWb::flowRuleFor($rules, 'pii.contact.email'));
        $this->assertSame('pii.*', IntentWb::flowRuleFor($rules, 'pii.passport'));
        $this->assertSame('*', IntentWb::flowRuleFor($rules, 'piix'));
        $this->assertSame('*', IntentWb::flowRuleFor($rules, 'pii'));
        $this->assertNull(IntentWb::flowRuleFor(self::o(['pii.*' => []]), 'piix'));
        $this->assertNull(IntentWb::flowRuleFor(self::o(['a' => []]), 'constructor'));
        $this->assertSame('constructor', IntentWb::flowRuleFor(self::o(['constructor' => []]), 'constructor'));
        // most specific decides, even when less specific would allow
        $this->assertFalse(IntentWb::flowAllowed($rules, 'pii.contact', 'gov', self::AUD));
        $this->assertTrue(IntentWb::flowAllowed($rules, 'pii.passport', 'gov', self::AUD));
        $this->assertTrue(IntentWb::flowAllowed($rules, 'pii.contact', self::AUD, self::AUD)); // back to its origin
        $this->assertTrue(IntentWb::flowAllowed(new Obj(), 'public', 'gov', self::AUD));
        $this->assertFalse(IntentWb::flowAllowed(new Obj(), 'pii', 'gov', self::AUD));
        $this->assertFalse(IntentWb::flowAllowed($rules, 'x', 'gov', 'e'));
        $this->assertTrue(IntentWb::flowAllowed($rules, 'x', 'gov', 'd'));
        $this->assertNull(IntentWb::validateFlowRules(self::o(['*' => [], 'a.*' => ['x'], 'a.b_c' => [str_repeat('s', 256)]])));
        $this->assertSame('flows must be an object', IntentWb::validateFlowRules([]));
        $this->assertSame("flow pattern '**' is not a class, a 'prefix.*' or '*'", IntentWb::validateFlowRules(self::o(['**' => []])));
        $this->assertSame("flow pattern '.*' is not a class, a 'prefix.*' or '*'", IntentWb::validateFlowRules(self::o(['.*' => []])));
        $this->assertSame("flow pattern 'A' is not a class, a 'prefix.*' or '*'", IntentWb::validateFlowRules(self::o(['A' => []])));
        $this->assertSame("flow pattern \"a\n\" is not a class, a 'prefix.*' or '*'", str_replace("'a\n'", "\"a\n\"", (string)IntentWb::validateFlowRules(self::o(["a\n" => []]))));
        $this->assertSame("flow pattern 'a' needs a list of audiences", IntentWb::validateFlowRules(self::o(['a' => 'x'])));
        $this->assertSame("flow pattern 'a' needs a list of audiences", IntentWb::validateFlowRules(self::o(['a' => [str_repeat('s', 257)]])));
        $this->assertSame("flow pattern 'a' needs a list of audiences", IntentWb::validateFlowRules(self::o(['a' => ['']])));
        // in decide: most specific pattern denies
        $gov = self::receipt(self::GOV, ['c' => ['pii.contact', 'X1234567']]);
        $this->pFail("flow: class 'pii.contact' from 'gov.example' may not reach 'skyair.example' (parameter 'action.params.passport')",
            self::ld([$gov], [self::lref($gov, 'c')], ['params' => (object)[], 'flows' => ['pii.*' => [self::AUD], 'pii.contact' => ['other']]]));
    }

    public function testLabelRefusalsInOrder(): void
    {
        $rc = self::passportReceipt();
        $ref = self::lref($rc, 'passport');
        $pol = ['params' => (object)[]];
        $this->pFail("malformed label ref on 'action.params.passport'", self::ld([$rc], ['pca-labels:nohash'], $pol));
        $this->pFail("malformed label ref on 'action.params.passport'", self::ld([$rc], [IntentWb::LABEL_REF_PREFIX . self::rref($rc) . '#'], $pol));
        $this->pFail("label ref on 'action.params.passport' names a receipt the PCActn does not commit", self::ld([$rc], [$ref], $pol, ['committed_labels' => []]));
        $this->pFail("label receipt for 'action.params.passport' was not supplied", self::ld([$rc], [$ref], $pol, ['labels' => []]));
        foreach (['abc', null, 5, ['a' => 1]] as $labels) {
            $this->pFail('labels must be an array', self::ld([$rc], [$ref], $pol, ['labels' => $labels]));
        }
        $forged = self::receipt(self::AUD, ['passport' => ['pii.passport', 'X1234567']], [], 'k1', 'evil');
        $this->pFail("label receipt for 'action.params.passport': bad label receipt signature", self::ld([$forged], [self::lref($forged, 'passport')], $pol));
        $k2 = self::receipt(self::AUD, ['passport' => ['pii.passport', 'X1234567']], [], 'k2');
        $this->pFail("label receipt for 'action.params.passport': no pinned label key for site 'skyair.example' kid 'k2'", self::ld([$k2], [self::lref($k2, 'passport')], $pol));
        $this->pFail("label receipt for 'action.params.passport': no pinned label key for site 'skyair.example' kid 'k1'",
            self::ld([$rc], [$ref], $pol + ['label_keys' => [['site' => self::GOV, 'kid' => 'k1', 'pk' => self::kp(self::AUD . '/k1')[0]]]]));
        $this->pFail('policy misconfigured (fail closed): label_keys must be a list', self::ld([$rc], [$ref], ['params' => (object)[], 'label_keys' => (object)[]]));
        $noKeys = self::pIn(['action.params.passport' => [$ref]], ['params' => (object)[]], ['committed_labels' => [self::rref($rc)], 'labels' => [$rc]]);
        $noKeys->get('policy')->set('label_keys', []);
        $this->pFail("label receipt for 'action.params.passport': no pinned label key for site 'skyair.example' kid 'k1'", IntentWb::decideParamProvenance($noKeys));
        $other = self::receipt(self::AUD, ['passport' => ['pii.passport', 'X1234567']], ['session' => self::d('other')]);
        $this->pFail("label receipt for 'action.params.passport' is bound to another session", self::ld([$other], [self::lref($other, 'passport')], $pol));
        $this->pFail("label receipt for 'action.params.passport' has no field 'toString'", self::ld([$rc], [self::lref($rc, 'toString')], $pol));
        $this->pFail("label receipt for 'action.params.passport' has no field 'constructor'", self::ld([$rc], [self::lref($rc, 'constructor')], $pol));
        // a malformed receipt (extra member) has no reference: not supplied
        $extra = $rc + ['extra' => 1];
        $this->pFail("label receipt for 'action.params.passport' was not supplied",
            self::ld([$rc], [$ref], $pol, ['labels' => [$extra]]));
        // first failure within one path: refs in list order
        $this->pFail("malformed label ref on 'action.params.passport'", self::ld([$rc], ['pca-labels:x', self::lref($rc, 'toString')], $pol));
        // a prototype-named field that the receipt owns is an ordinary key
        $proto = self::receipt(self::AUD, ['__proto__' => ['constructor', 'X1234567']]);
        $this->pOut('pass', '{"action.params.passport":"first_party"}', self::ld([$proto], [self::lref($proto, '__proto__')], $pol),
            null, '{"action.params.passport":["constructor"]}');
        $govProto = self::receipt(self::GOV, ['f' => ['constructor', 'X1234567']]);
        $this->pFail("flow: class 'constructor' from 'gov.example' may not reach 'skyair.example' (parameter 'action.params.passport')",
            self::ld([$govProto], [self::lref($govProto, 'f')], $pol));
        $this->pOut('pass', '{"action.params.passport":"tool"}', self::ld([$govProto], [self::lref($govProto, 'f')],
            ['params' => (object)[], 'flows' => ['constructor' => [self::AUD]]]), null, '{"action.params.passport":["constructor"]}');
    }

    public function testLabelsWire(): void
    {
        $base = self::o(self::passportReceipt());
        $this->assertNull(IntentWb::validateLabelsWire($base));
        $w = static function (array $over) use ($base): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($base));
            foreach ($over as $k => $v) {
                $g->set($k, self::o($v));
            }
            return IntentWb::validateLabelsWire($g);
        };
        $vd = self::d('v');
        $this->assertSame('label receipt must be an object', IntentWb::validateLabelsWire(null));
        $this->assertSame("unknown member 'labels.x'", $w(['x' => 1]));
        $this->assertSame('label receipt must be {v: 1, kind: "pca-labels"}', $w(['kind' => 'pca-label']));
        $this->assertSame("'labels.site' must be a non-empty string (<= 256 bytes)", $w(['site' => '']));
        $this->assertSame("'labels.session' must be canonical base64url (32 bytes)", $w(['session' => $vd . 'A']));
        $this->assertSame("'labels.response_digest' must be canonical base64url (32 bytes)", $w(['response_digest' => 5]));
        $this->assertSame("'labels.fields' must be an object", $w(['fields' => []]));
        $this->assertSame("'labels.fields' must hold 1..64 fields", $w(['fields' => (object)[]]));
        $fields = [];
        for ($i = 0; $i < 65; $i++) {
            $fields["f$i"] = ['class' => 'public', 'value_digest' => $vd];
        }
        $this->assertNull($w(['fields' => array_slice($fields, 0, 64)]));
        $this->assertSame("'labels.fields' must hold 1..64 fields", $w(['fields' => $fields]));
        $this->assertSame('label field paths must be non-empty strings (<= 256 bytes)', $w(['fields' => ['' => ['class' => 'public', 'value_digest' => $vd]]]));
        $this->assertNull($w(['fields' => [str_repeat('p', 256) => ['class' => 'public', 'value_digest' => $vd]]]));
        $this->assertSame("label field 'f' must be exactly {class, value_digest}", $w(['fields' => ['f' => ['class' => 'public']]]));
        $this->assertSame("label field 'f' must be exactly {class, value_digest}", $w(['fields' => ['f' => ['class' => 'public', 'value_digest' => $vd, 'x' => 1]]]));
        $this->assertSame("label field 'f' must be exactly {class, value_digest}", $w(['fields' => ['f' => 'public']]));
        $this->assertNull($w(['fields' => ['f' => ['class' => 'a' . str_repeat('.b', 63) . 'c', 'value_digest' => $vd]]])); // 128 bytes
        foreach (['a' . str_repeat('.b', 63) . 'cd', 'A', 'a.', '.a', 'a..b', "a\n", 'a-b', 5] as $c) {
            $this->assertSame("label field 'f': invalid data class", $w(['fields' => ['f' => ['class' => $c, 'value_digest' => $vd]]]), (string)json_encode($c));
        }
        $this->assertSame("label field 'f': value_digest must be canonical base64url (32 bytes)", $w(['fields' => ['f' => ['class' => 'public', 'value_digest' => 'x']]]));
        $this->assertSame("'labels.issued_at' must be a non-negative safe integer", $w(['issued_at' => -1]));
        $this->assertSame("'labels.kid' must be a non-empty string (<= 64 bytes)", $w(['kid' => str_repeat('k', 65)]));
        $this->assertSame("'labels.sig' must be a string", $w(['sig' => 1]));
    }

    public function testProvWireAndCommitments(): void
    {
        $refs = static fn(int $n): array => array_map(static fn(int $i): string => "r$i", range(1, $n));
        $this->pFail("'prov' must be an object", self::pd([], [], ['prov' => [1]]));
        $this->pFail("'prov' must be an object", self::pd([], [], ['prov' => 'x']));
        $this->pFail("'prov' must be an object", self::pd([], [], ['prov' => null])); // present null is malformed
        $this->pOut('question', '{"action.params.offer_id":"agent","action.params.passport":"agent"}',
            IntentWb::decideParamProvenance(self::pIn([])->without('prov')), 'typed');
        $params = [];
        $prov = [];
        for ($i = 0; $i < 33; $i++) {
            $params["p$i"] = 1;
            $prov["action.params.p$i"] = ['r'];
        }
        $wide = ['action' => ['params' => $params], 'policy' => ['params' => (object)[]]];
        $this->assertSame('pass', IntentWb::decideParamProvenance(self::o(['aud' => self::AUD, 'session' => self::sess(), 'prov' => array_slice($prov, 0, 32)] + $wide))['outcome']);
        $this->pFail("'prov' holds more than 32 paths", IntentWb::decideParamProvenance(self::o(['aud' => self::AUD, 'prov' => $prov] + $wide)));
        $this->pFail("'prov' key 'action.params.a-b' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)", self::pd(['action.params.a-b' => ['r']]));
        $this->pFail("'prov' key 'action.params.a.b' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)", self::pd(['action.params.a.b' => ['r']]));
        $this->pFail("'prov' key 'action.params.__proto__' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)", self::pd(['action.params.__proto__' => ['r']]));
        $this->pFail("'prov' key 'action.params.prototype' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)", self::pd(['action.params.prototype' => ['r']]));
        $this->pFail("'prov' key \"action.params.passport\n\" is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)",
            ['outcome' => 'deny', 'env' => new Obj(), 'reason' => str_replace("'action.params.passport\n'", "\"action.params.passport\n\"",
                self::pd(["action.params.passport\n" => ['r']])['reason'])]);
        $this->pFail("'prov' key 'action.params." . str_repeat('a', 65) . "' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)",
            self::pd(['action.params.' . str_repeat('a', 65) => ['r']]));
        $this->pFail("'prov.action.params.passport' must hold 1..8 refs", self::pd(['action.params.passport' => []]));
        $this->pFail("'prov.action.params.passport' must hold 1..8 refs", self::pd(['action.params.passport' => $refs(9)]));
        $this->pFail("'prov.action.params.passport' must hold 1..8 refs", self::pd(['action.params.passport' => 'r']));
        $this->assertNotSame('deny', self::pd(['action.params.passport' => $refs(8)])['outcome']);
        $this->pFail("'prov.action.params.passport' refs must be non-empty strings (<= 256 bytes)", self::pd(['action.params.passport' => ['']]));
        $this->pFail("'prov.action.params.passport' refs must be non-empty strings (<= 256 bytes)", self::pd(['action.params.passport' => [str_repeat('r', 257)]]));
        $this->pFail("'prov.action.params.passport' refs must be non-empty strings (<= 256 bytes)", self::pd(['action.params.passport' => [5]]));
        $this->assertNotSame('deny', self::pd(['action.params.passport' => [str_repeat('r', 256)]])['outcome']);
        // committed labels
        $ds = array_map(static fn(int $i): string => self::d("l$i"), range(1, 17));
        $this->assertNotSame('deny', self::pd([], [], ['committed_labels' => array_slice($ds, 0, 16)])['outcome']);
        $this->pFail('committed labels must be a list of at most 16 digests', self::pd([], [], ['committed_labels' => $ds]));
        $this->pFail('committed labels must be a list of at most 16 digests', self::pd([], [], ['committed_labels' => ['length' => 0]]));
        $this->pFail('committed labels must be distinct canonical 32-byte digests', self::pd([], [], ['committed_labels' => [$ds[0], $ds[0]]]));
        $this->pFail('committed labels must be distinct canonical 32-byte digests', self::pd([], [], ['committed_labels' => ['x']]));
        $this->pFail('committed labels must be a list of at most 16 digests', self::pd([], [], ['committed_labels' => null]));
        $this->assertNotSame('deny', IntentWb::decideParamProvenance(self::pIn([])->without('committed_labels'))['outcome']);
        $this->assertNotSame('deny', IntentWb::decideParamProvenance(self::pIn([])->without('committed_labels'))['outcome']);
        // not carried
        $this->pFail("prov names 'action.params.nope', a parameter the action does not carry", self::pd(['action.params.nope' => ['r']]));
        // the action must be an object; params absent = {}, present an object (null included)
        foreach ([null, 'x', [1]] as $action) {
            $this->pFail('action must be an object', self::pd(['action.params.passport' => ['r']], [], ['action' => $action]));
        }
        $this->pFail('action must be an object', IntentWb::decideParamProvenance(self::pIn([])->without('action')));
        foreach ([null, 'x', [1]] as $params) {
            $this->pFail('action.params must be an object', self::pd([], [], ['action' => ['params' => $params]]));
        }
        $this->pOut('pass', '{}', self::pd([], [], ['action' => (object)[]]));
        // order: committed labels before the action, the action before the supplied labels, those before carried paths
        $this->pFail('committed labels must be a list of at most 16 digests', self::pd([], [], ['committed_labels' => 5, 'action' => null]));
        $this->pFail('action must be an object', self::pd([], [], ['action' => null, 'labels' => 5]));
        $this->pFail('labels must be an array', self::pd(['action.params.nope' => ['r']], [], ['labels' => 5]));
        // order: prov wire before committed labels; committed before carried; carried paths in ascending order
        $this->pFail("'prov.action.params.passport' must hold 1..8 refs", self::pd(['action.params.passport' => []], [], ['committed_labels' => 5]));
        $this->pFail('committed labels must be a list of at most 16 digests', self::pd(['action.params.nope' => ['r']], [], ['committed_labels' => 5]));
        $this->pFail("prov names 'action.params.a', a parameter the action does not carry", self::pd(['action.params.z' => ['r'], 'action.params.a' => ['r']]));
        // policy is step 0
        $this->pFail('policy misconfigured (fail closed): critical_max must be a taint level', self::pd(['action.params.nope' => []], ['critical_max' => 'x']));
    }

    public function testProvenancePolicyRefusals(): void
    {
        $e = static fn(array $p): ?string => IntentWb::validateProvenancePolicy(self::o($p));
        $this->assertNull($e(['params' => (object)[]]));
        $this->assertSame('provenance policy needs a params map', IntentWb::validateProvenancePolicy(null));
        $this->assertSame('provenance policy needs a params map', $e(['params' => []]));
        $this->assertSame('provenance policy needs a params map', $e(['registry' => (object)[]]));
        $this->assertNull($e(['params' => ['action.params.a-b.c' => 'material']]));
        $this->assertSame("policy param 'action.params.__proto__' is not an action.params path", $e(['params' => ['action.params.__proto__' => 'material']]));
        $this->assertSame("policy param 'action.x' is not an action.params path", $e(['params' => ['action.x' => 'material']]));
        $this->assertSame("policy param 'action.params.a': sensitivity must be material or critical", $e(['params' => ['action.params.a' => 'free']]));
        $this->assertSame('registry must be an object', $e(['params' => (object)[], 'registry' => null]));
        $this->assertSame("registry entry 'r' must map to a taint level", $e(['params' => (object)[], 'registry' => ['r' => 'toString']]));
        $this->assertSame("registry entry '' must map to a taint level", $e(['params' => (object)[], 'registry' => ['' => 'trusted']]));
        $this->assertNull($e(['params' => (object)[], 'registry' => [str_repeat('r', 256) => 'web']]));
        $this->assertSame('label_keys must be a list', $e(['params' => (object)[], 'label_keys' => (object)[]]));
        $this->assertSame('every label key needs site, kid, a 32-byte pk and an optional string pq_pk', $e(['params' => (object)[], 'label_keys' => [['site' => 's', 'kid' => 'k']]]));
        $this->assertSame('every label key needs site, kid, a 32-byte pk and an optional string pq_pk', $e(['params' => (object)[], 'label_keys' => [5]]));
        $this->assertSame('critical_max must be a taint level', $e(['params' => (object)[], 'critical_max' => null]));
        $this->assertNull($e(['params' => (object)[], 'critical_max' => 'trusted']));
        $this->assertSame('material_tainted must be allow | question | question_typed | deny', $e(['params' => (object)[], 'material_tainted' => 'Allow']));
        $this->assertNull($e(['params' => (object)[], 'material_tainted' => 'allow']));
        $this->assertSame('critical_tainted must be question | question_typed | deny', $e(['params' => (object)[], 'critical_tainted' => 'allow']));
        $this->assertSame('critical_tainted must be question | question_typed | deny', $e(['params' => (object)[], 'critical_tainted' => null]));
        $this->assertNull($e(['params' => (object)[], 'critical_tainted' => 'deny']));
        $this->assertSame('flows must be an object', $e(['params' => (object)[], 'flows' => null]));
        // a missing policy: the decide input's policy is required
        $this->pFail('policy misconfigured (fail closed): provenance policy needs a params map',
            IntentWb::decideParamProvenance(self::pIn([])->without('policy')));
    }

    public function testEnvOverlap(): void
    {
        // a policy path below a declared prov path: both classified, env nesting collides
        $r = self::pd(['action.params.a' => ['ref:trusted']], ['params' => ['action.params.a.b' => 'material']],
            ['action' => ['params' => ['a' => ['b' => 1]]]]);
        $this->pFail("provenance paths overlap at 'action.params.a.b'", $r);
        $this->assertSame('{"action.params.a":"trusted","action.params.a.b":"agent"}', self::json($r['labels']));
        // an object value is fine to classify
        $this->pOut('pass', '{"action.params.a":"trusted"}', self::pd(['action.params.a' => ['ref:trusted']], ['params' => (object)[]],
            ['action' => ['params' => ['a' => ['b' => 1]]]]));
    }

    // ==== rule 18: classifiers ==========================================================================================

    public function testQuorum(): void
    {
        $r = self::cd([self::verdict('j1', 'apologetic'), self::verdict('j2', 'apologetic'), self::verdict('j3', 'neutral')]);
        $this->assertTrue($r['ok']);
        $this->assertSame('{"tone":"apologetic"}', self::json($r['classes']));
        $this->assertSame('{"tone":{"apologetic":2,"neutral":1}}', self::json($r['votes']));
        $this->assertSame(['apologetic', 'neutral'], $r['votes']->get('tone')->keys());
        $r = self::cd([self::verdict('j3', 'hostile')], ['k' => 1]);
        $this->assertSame('{"tone":"hostile"}', self::json($r['classes']));
        $this->cFail("classifier 'tone': no label reaches the quorum 2", self::cd([self::verdict('j1', 'apologetic'), self::verdict('j2', 'neutral')]));
        $this->cFail("classifier 'tone': no label reaches the quorum 2", self::cd([]));
        $this->cFail("classifier 'tone': ambiguous, 2 labels reach the quorum", self::cd([self::verdict('j1', 'apologetic'), self::verdict('j2', 'neutral')], ['k' => 1]));
        $this->cFail("classifier 'tone': ambiguous, 3 labels reach the quorum",
            self::cd([self::verdict('j1', 'apologetic'), self::verdict('j2', 'neutral'), self::verdict('j3', 'other')], ['k' => 1]));
        // no measurement pin: any measurement
        $r = self::cd([self::verdict('j1', 'other', ['measurement' => 'm-x']), self::verdict('j2', 'other')], [], [], null,
            [array_diff_key(self::clsPolicy(), ['measurements' => 1])]);
        $this->assertSame('{"tone":"other"}', self::json($r['classes']));
        // no classifiers, nothing committed: ok, empty
        $r = IntentWb::decideClassifierDimensions(self::o(['session' => self::sess(), 'action' => ['params' => (object)[]], 'policy' => ['classifiers' => []]]));
        $this->assertTrue($r['ok']);
        $this->assertSame('{}', self::json($r['classes']));
    }

    public function testVerdictRefusalsInOrder(): void
    {
        $v1 = self::verdict('j1', 'apologetic');
        $v2 = self::verdict('j2', 'apologetic');
        $this->cFail("verdict for undeclared classifier 'mood'", self::cd([self::verdict('j1', 'x', ['classifier' => 'mood']), $v2]));
        $this->cFail("classifier 'tone': judge key is not on the allowlist", self::cd([self::verdict('j9', 'apologetic'), $v2]));
        $forged = self::verdict('j1', 'apologetic');
        $forged['label'] = 'neutral';
        $this->cFail("classifier 'tone': bad verdict signature", self::cd([$forged, $v2]));
        $this->cFail("classifier 'tone': verdict bound to another session", self::cd([self::verdict('j1', 'apologetic', ['session' => self::d('o')]), $v2]));
        $this->cFail("classifier 'tone': the action carries no 'action.params.message'", self::cd([$v1, $v2], [], ['action' => ['params' => (object)[]]]));
        $this->cFail('action must be an object', self::cd([$v1, $v2], [], ['action' => null]));
        $this->cFail('action must be an object', self::cd([$v1, $v2], [], ['action' => 'x']));
        $this->cFail('action.params must be an object', self::cd([$v1, $v2], [], ['action' => ['params' => null]]));
        // order: the supplied verdict list before the action
        $this->cFail('verdicts must be an array', self::cd([$v1, $v2], [], ['action' => null, 'verdicts' => 5]));
        $this->cFail("classifier 'tone': the action carries no 'action.params.message'", self::cd([$v1, $v2], [], ['action' => (object)[]]));
        $this->cFail("classifier 'tone': verdict is about other content", self::cd([$v1, $v2], [], ['action' => ['params' => ['message' => 'other']]]));
        $this->cFail("classifier 'tone': label 'sarcastic' is not in its label set", self::cd([self::verdict('j1', 'sarcastic'), $v2]));
        $this->cFail("classifier 'tone': measurement is not pinned", self::cd([self::verdict('j1', 'apologetic', ['measurement' => 'm-x']), $v2]));
        $this->cFail("classifier 'tone': two verdicts from one judge", self::cd([$v1, self::verdict('j1', 'neutral'), $v2]));
        // order inside one verdict: allowlist before signature, session before content, label before measurement
        $this->cFail("classifier 'tone': judge key is not on the allowlist", self::cd([self::verdict('j9', 'apologetic', ['session' => self::d('o')])]));
        $this->cFail("classifier 'tone': verdict bound to another session", self::cd([self::verdict('j1', 'apologetic', ['session' => self::d('o')])], [], ['action' => ['params' => (object)[]]]));
        $this->cFail("classifier 'tone': label 'x' is not in its label set", self::cd([self::verdict('j1', 'x', ['measurement' => 'm-x'])]));
        // committed order: the second verdict's error is never reached
        $this->cFail("classifier 'tone': judge key is not on the allowlist", self::cd([self::verdict('j9', 'a'), self::verdict('j1', 'x', ['classifier' => 'mood'])]));
        // content digest by value: 2.0 is the number 2
        $num = self::verdict('j1', 'other', ['content_digest' => IntentWb::contentDigest(new Num('2'))]);
        $num2 = self::verdict('j2', 'other', ['content_digest' => IntentWb::contentDigest(new Num('2'))]);
        $r = self::cd([$num, $num2], [], ['action' => ['params' => ['message' => 2.0]]]);
        $this->assertSame('{"tone":"other"}', self::json($r['classes']));
        // structured content
        $msg = ['to' => 'c_9', 'body' => ['text' => 'hi', 'n' => [1, 2]]];
        $s1 = self::verdict('j1', 'neutral', ['content_digest' => IntentWb::contentDigest(self::o($msg))]);
        $s2 = self::verdict('j2', 'neutral', ['content_digest' => IntentWb::contentDigest(self::o($msg))]);
        $this->assertTrue(self::cd([$s1, $s2], [], ['action' => ['params' => ['message' => $msg]]])['ok']);
        // non-canonical content (a fraction below 1e-6) throws: fail closed
        $r = self::cd([$v1, $v2], [], ['action' => ['params' => ['message' => 1e-7]]]);
        $this->assertFalse($r['ok']);
        $this->assertStringStartsWith('classes: evaluation error (fail closed): ', $r['reason']);
    }

    public function testVerdictCommitments(): void
    {
        $v1 = self::verdict('j1', 'apologetic');
        $v2 = self::verdict('j2', 'apologetic');
        $refs = [self::vref($v1), self::vref($v2)];
        // uncommitted verdicts are not counted
        $this->cFail("classifier 'tone': no label reaches the quorum 2", self::cd([$v1, $v2], [], [], [$refs[0]]));
        $this->cFail('a committed verdict was not supplied (or is malformed)', self::cd([$v1], [], [], $refs));
        $this->cFail('committed verdicts must be distinct canonical 32-byte digests', self::cd([$v1, $v2], [], [], [$refs[0], $refs[0]]));
        $this->cFail('committed verdicts must be distinct canonical 32-byte digests', self::cd([$v1, $v2], [], [], ['abc']));
        $ds = array_map(static fn(int $i): string => self::d("v$i"), range(1, 9));
        $this->cFail('committed verdicts must be a list of at most 8 digests', self::cd([], [], [], $ds));
        $this->cFail('a committed verdict was not supplied (or is malformed)', self::cd([], [], [], array_slice($ds, 0, 8)));
        $this->cFail('committed verdicts must be a list of at most 8 digests', self::cd([], [], ['committed' => ['length' => 1]]));
        $this->cFail('committed verdicts must be a list of at most 8 digests', self::cd([], [], ['committed' => null]));
        // a malformed verdict has no reference
        $extra = $v1 + ['x' => 1];
        $this->cFail('a committed verdict was not supplied (or is malformed)', self::cd([$extra, $v2], [], [], [self::vref($extra), $refs[1]]));
        // a supplied `verdicts` that is not a real array (null included) fails closed
        foreach ([['a' => $v1], 5, 'abc', null] as $verdicts) {
            $this->cFail('verdicts must be an array', self::cd([], [], ['verdicts' => $verdicts], $refs));
        }
        $this->cFail('committed verdicts must be distinct canonical 32-byte digests', self::cd([], [], ['verdicts' => 5], ['x']));
        // policy first
        $this->cFail("policy misconfigured (fail closed): classifier 'tone': k must be an integer in [1, 3]", self::cd([], ['k' => 4], [], ['x']));
    }

    public function testVerdictWire(): void
    {
        $base = self::o(self::verdict('j1', 'apologetic'));
        $this->assertNull(IntentWb::validateClassifierVerdictWire($base));
        $w = static function (array $over) use ($base): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($base));
            foreach ($over as $k => $v) {
                $g->set($k, self::o($v));
            }
            return IntentWb::validateClassifierVerdictWire($g);
        };
        $this->assertSame('verdict must be an object', IntentWb::validateClassifierVerdictWire([1]));
        $this->assertSame("unknown member 'verdict.x'", $w(['x' => 1]));
        $this->assertSame("missing member 'verdict.judge'", IntentWb::validateClassifierVerdictWire($base->without('judge')));
        $this->assertSame('verdict must be {v: 1, kind: "pca-intent-classification"}', $w(['v' => true]));
        $this->assertSame("'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$", $w(['classifier' => "tone\n"]));
        $this->assertSame("'verdict.session' must be canonical base64url (32 bytes)", $w(['session' => 'x']));
        $this->assertSame("'verdict.content_digest' must be canonical base64url (32 bytes)", $w(['content_digest' => 'x']));
        $this->assertNull($w(['label' => str_repeat('l', 64)]));
        $this->assertSame("'verdict.label' must be a non-empty string (<= 64 bytes)", $w(['label' => str_repeat('l', 65)]));
        $this->assertNull($w(['measurement' => str_repeat('m', 256)]));
        $this->assertSame("'verdict.measurement' must be a non-empty string (<= 256 bytes)", $w(['measurement' => str_repeat('m', 257)]));
        $this->assertSame("'verdict.measurement' must be a non-empty string (<= 256 bytes)", $w(['measurement' => 5]));
        $this->assertSame("'verdict.judge' must be canonical base64url (32 bytes)", $w(['judge' => 'x']));
        $this->assertSame("'verdict.sig' must be a string", $w(['sig' => 5]));
    }

    public function testClassifierPolicyRefusals(): void
    {
        $e = static fn(array $over): ?string => IntentWb::validateClassifierPolicy(self::o(['classifiers' => [self::clsPolicy($over)]]));
        $this->assertNull($e([]));
        $this->assertSame('classifier policy needs a classifiers list', IntentWb::validateClassifierPolicy(self::o(['classifiers' => ['length' => 0]])));
        $this->assertSame('classifier policy needs a classifiers list', IntentWb::validateClassifierPolicy(null));
        $this->assertSame('every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$', $e(['id' => 'Tone']));
        $this->assertSame('every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$',
            IntentWb::validateClassifierPolicy(self::o(['classifiers' => [self::clsPolicy(), self::clsPolicy()]])));
        $this->assertSame('every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}', IntentWb::validateClassifierPolicy(self::o(['classifiers' => [5]])));
        $this->assertSame("classifier 'tone': param must be an action.params path", $e(['param' => 'action.message']));
        $this->assertSame("classifier 'tone': labels must hold 1..32 strings", $e(['labels' => []]));
        $labels = array_map(static fn(int $i): string => "l$i", range(1, 33));
        $this->assertNull($e(['labels' => array_slice($labels, 0, 32)]));
        $this->assertSame("classifier 'tone': labels must hold 1..32 strings", $e(['labels' => $labels]));
        $this->assertSame("classifier 'tone': labels must be distinct non-empty strings", $e(['labels' => ['a', 'a']]));
        $this->assertSame("classifier 'tone': labels must be distinct non-empty strings", $e(['labels' => ['a', '']]));
        $this->assertSame("classifier 'tone': labels must be distinct non-empty strings", $e(['labels' => ['a', 1]]));
        $this->assertSame("classifier 'tone': labels must be distinct non-empty strings", $e(['labels' => [str_repeat('l', 65)]]));
        $this->assertNull($e(['labels' => ['1', '01', '1.0']])); // distinct as strings
        $this->assertSame("classifier 'tone': keys must be distinct 32-byte keys", $e(['keys' => []]));
        $this->assertSame("classifier 'tone': keys must be distinct 32-byte keys", $e(['keys' => [self::kp('j1')[0], self::kp('j1')[0]]]));
        $this->assertSame("classifier 'tone': keys must be distinct 32-byte keys", $e(['keys' => ['x']]));
        $this->assertNull($e(['k' => 3]));
        $this->assertNull($e(['k' => 1]));
        $this->assertSame("classifier 'tone': k must be an integer in [1, 3]", $e(['k' => 4]));
        $this->assertSame("classifier 'tone': k must be an integer in [1, 3]", $e(['k' => 0]));
        $this->assertSame("classifier 'tone': k must be an integer in [1, 3]", $e(['k' => 1.5]));
        $this->assertNull($e(['k' => 2.0]));
        $this->assertSame("classifier 'tone': measurements must be a list of strings", $e(['measurements' => null]));
        $this->assertSame("classifier 'tone': measurements must be a list of strings", $e(['measurements' => ['a', 1]]));
        $this->assertNull($e(['measurements' => []]));
    }

    public function testProtoLabelsAndIds(): void
    {
        foreach (['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty'] as $label) {
            $vs = [self::verdict('j1', $label, ['classifier' => 'constructor']), self::verdict('j2', $label, ['classifier' => 'constructor'])];
            $r = self::cd($vs, ['id' => 'constructor', 'labels' => ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty']]);
            $this->assertTrue($r['ok'], $label);
            $this->assertSame($label, $r['classes']->get('constructor'));
        }
        $split = [self::verdict('j1', '__proto__', ['classifier' => 'constructor']), self::verdict('j2', 'constructor', ['classifier' => 'constructor'])];
        $this->cFail("classifier 'constructor': no label reaches the quorum 2", self::cd($split, ['id' => 'constructor', 'labels' => ['constructor', '__proto__']]));
        // numeric-looking labels are ordinary keys too
        $num = [self::verdict('j1', '1'), self::verdict('j2', '1')];
        $r = self::cd($num, ['labels' => ['01', '1']]);
        $this->assertSame('{"tone":"1"}', self::json($r['classes']));
    }

    // ==== activity and composition =====================================================================================

    public function testActivityTyping(): void
    {
        $d = self::d('x');
        $act = static fn(array $s, array $p = []): array => IntentWb::intentWbActive(self::o(['intent_session' => $s === [] ? (object)[] : $s,
            'policy' => $p === [] ? (object)[] : $p]));
        $none = ['facts' => false, 'provenance' => false, 'classes' => false];
        $this->assertSame($none, $act([]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act(['facts' => [$d]]));
        $this->assertSame($none, $act(['facts' => []]));
        $this->assertSame($none, $act(['facts' => ['0' => $d, 'length' => 1]]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act(['offer_set' => $d]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act(['offer_set' => '']));
        $this->assertSame($none, $act(['offer_set' => ['length' => 43]]));
        $this->assertSame($none, $act(['offer_set' => null]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act([], ['world' => ['worlds' => [['name' => 'x']]]]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act([], ['world' => ['relational' => [1]]]));
        $this->assertSame($none, $act([], ['world' => ['worlds' => ['length' => 2], 'relational' => ['length' => 1]]]));
        $this->assertSame($none, $act([], ['world' => ['worlds' => 'ab', 'relational' => []]]));
        $this->assertSame(array_replace($none, ['facts' => true]), $act([], ['world' => ['offers' => (object)[]]]));
        $this->assertSame($none, $act([], ['world' => ['offers' => []]]));
        $this->assertSame($none, $act([], ['world' => ['offers' => null]]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act(['prov' => (object)[]]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act(['prov' => null]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act(['prov' => 5]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act(['labels' => [$d]]));
        $this->assertSame($none, $act(['labels' => ['length' => 1]]));
        $this->assertSame($none, $act(['labels' => []]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act([], ['provenance' => ['params' => (object)[]]]));
        $this->assertSame(array_replace($none, ['provenance' => true]), $act([], ['provenance' => (object)[]]));
        $this->assertSame($none, $act([], ['provenance' => []]));
        $this->assertSame($none, $act([], ['provenance' => null]));
        $this->assertSame($none, $act([], ['provenance' => 'x']));
        $this->assertSame(array_replace($none, ['classes' => true]), $act(['classes' => [$d]]));
        $this->assertSame($none, $act(['classes' => ['length' => 1]]));
        $this->assertSame(array_replace($none, ['classes' => true]), $act([], ['classifiers' => [['id' => 'tone']]]));
        $this->assertSame($none, $act([], ['classifiers' => ['length' => 3]]));
        $this->assertSame($none, $act([], ['classifiers' => null]));
        $this->assertSame(['facts' => true, 'provenance' => true, 'classes' => true], $act(['facts' => [$d], 'prov' => (object)[], 'classes' => [$d]]));
        // a non-object session / policy: nothing active
        $this->assertSame($none, IntentWb::intentWbActive(self::o(['intent_session' => 'x', 'policy' => [1]])));
        $this->assertSame($none, IntentWb::intentWbActive(new Obj()));
        // the single-rule helpers
        $this->assertTrue(IntentWb::intentWorldActive(self::o(['committed' => ['facts' => [$d]]])));
        $this->assertFalse(IntentWb::intentWorldActive(self::o(['committed' => null, 'policy' => null])));
        $this->assertTrue(IntentWb::intentProvenanceActive(self::o(['prov' => null])));
        $this->assertFalse(IntentWb::intentProvenanceActive(self::o(['labels' => [], 'policy' => null])));
        $this->assertTrue(IntentWb::classifierCheckActive(self::o(['committed' => [1]])));
        $this->assertFalse(IntentWb::classifierCheckActive(self::o(['committed' => 'ab', 'policy' => null])));
    }

    private static function wbIn(array $session, array $artifacts, array $policy, array $over = []): Obj
    {
        return self::o(array_merge(['now' => self::NOW, 'aud' => self::AUD, 'session' => self::sess(),
            'action' => self::action(['passport' => 'X1234567', 'message' => self::MESSAGE]),
            'intent_session' => $session === [] ? (object)[] : $session, 'artifacts' => $artifacts === [] ? (object)[] : $artifacts,
            'policy' => $policy === [] ? (object)[] : $policy], $over));
    }

    /** All three checks active and passing (provenance a typed question unless `$provPol` says otherwise). */
    private static function full(array $provPol = [], array $clsOver = [], array $factsOver = []): Obj
    {
        $facts = [self::fact('o1', 7)];
        $vs = [self::verdict('j1', 'apologetic'), self::verdict('j2', 'apologetic')];
        return self::wbIn(
            ['facts' => array_map([self::class, 'fref'], $facts), 'prov' => ['action.params.offer_id' => ['ref:offer']],
                'classes' => array_map([self::class, 'vref'], $vs)],
            ['facts' => $facts, 'verdicts' => $vs],
            ['world' => array_merge(['worlds' => [self::world('fare', 1, 0, ['o1'])]], $factsOver),
                'provenance' => array_merge(['params' => ['action.params.offer_id' => 'critical', 'action.params.passport' => 'material'],
                    'registry' => ['ref:offer' => 'first_party']], $provPol),
                'classifiers' => [self::clsPolicy($clsOver)]]);
    }

    public function testCompositionAllPass(): void
    {
        $r = IntentWb::decideIntentWb(self::full(['material_tainted' => 'allow']));
        $this->assertSame('admit', $r['outcome'], $r['reason'] ?? '');
        $this->assertSame(['facts' => 'pass', 'provenance' => 'pass', 'classes' => 'pass'], $r['checks']);
        $this->assertSame(['world', 'prov', 'class'], array_keys($r['env']));
        $this->assertSame('{"fare":7}', self::json($r['env']['world']));
        $this->assertSame('{"action":{"params":{"offer_id":"first_party","passport":"agent"}}}', self::json($r['env']['prov']));
        $this->assertSame('{"tone":"apologetic"}', self::json($r['env']['class']));
        $this->assertSame(['fare'], $r['single_source']);
        $this->assertArrayNotHasKey('reason', $r);
        $this->assertArrayNotHasKey('friction', $r);
    }

    public function testCompositionQuestionDoesNotEndTheUnit(): void
    {
        $r = IntentWb::decideIntentWb(self::full());
        $this->assertSame('question', $r['outcome']);
        $this->assertSame(['facts' => 'pass', 'provenance' => 'question', 'classes' => 'pass'], $r['checks']);
        $this->assertSame('tap', $r['friction']);
        $this->assertSame('provenance: a tainted value needs the principal (lazy question)', $r['reason']);
        $this->assertSame(['world', 'prov', 'class'], array_keys($r['env']));
        // a later classes failure after a question: deny, the question's friction stays, the reason is the failure's
        $r = IntentWb::decideIntentWb(self::full([], ['k' => 3]));
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame(['facts' => 'pass', 'provenance' => 'question', 'classes' => 'fail'], $r['checks']);
        $this->assertSame("classes: classifier 'tone': no label reaches the quorum 3", $r['reason']);
        $this->assertSame('tap', $r['friction']);
        $this->assertSame(['world', 'prov'], array_keys($r['env']));
    }

    public function testCompositionFirstFailureEndsTheUnit(): void
    {
        // facts fail: provenance and classes not reported, env empty
        $r = IntentWb::decideIntentWb(self::full([], ['k' => 9], ['skew_ms' => -1]));
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame(['facts' => 'fail'], $r['checks']);
        $this->assertSame('facts: policy misconfigured (fail closed): skew_ms must be a non-negative safe integer', $r['reason']);
        $this->assertSame([], $r['env']);
        $this->assertArrayNotHasKey('single_source', $r);
        // provenance fails: classes not reported, world kept, single_source kept
        $r = IntentWb::decideIntentWb(self::full(['critical_max' => 'trusted'], ['k' => 9]));
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame(['facts' => 'pass', 'provenance' => 'fail'], $r['checks']);
        $this->assertSame("provenance: critical parameter 'action.params.offer_id' has provenance 'first_party', above the policy maximum 'trusted'", $r['reason']);
        $this->assertSame(['world'], array_keys($r['env']));
        $this->assertSame(['fare'], $r['single_source']);
        $this->assertArrayNotHasKey('friction', $r);
    }

    public function testCompositionInactiveChecksAreNotReported(): void
    {
        $r = IntentWb::decideIntentWb(self::wbIn([], [], []));
        $this->assertSame(['outcome' => 'admit', 'checks' => [], 'env' => []], $r);
        // only classes active
        $vs = [self::verdict('j1', 'apologetic'), self::verdict('j2', 'apologetic')];
        $r = IntentWb::decideIntentWb(self::wbIn(['classes' => array_map([self::class, 'vref'], $vs)], ['verdicts' => $vs], ['classifiers' => [self::clsPolicy()]]));
        $this->assertSame(['classes' => 'pass'], $r['checks']);
        $this->assertSame(['class'], array_keys($r['env']));
        // provenance active by an empty prov, with no provenance policy: {params: {}} applies
        $r = IntentWb::decideIntentWb(self::wbIn(['prov' => (object)[]], [], []));
        $this->assertSame('admit', $r['outcome']);
        $this->assertSame(['provenance' => 'pass'], $r['checks']);
        $this->assertSame('{}', self::json($r['env']['prov']));
        // a present null prov makes the check ACTIVE, and rule 17 then refuses it
        $r = IntentWb::decideIntentWb(self::wbIn(['prov' => null], [], []));
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame(['provenance' => 'fail'], $r['checks']);
        $this->assertSame("provenance: 'prov' must be an object", $r['reason']);
        // a present null facts commitment is not active by itself (activity is strict); with a world policy it is refused
        $this->assertSame(['outcome' => 'admit', 'checks' => [], 'env' => []], IntentWb::decideIntentWb(self::wbIn(['facts' => null], [], [])));
        $r = IntentWb::decideIntentWb(self::wbIn(['facts' => null], [], ['world' => ['worlds' => [self::world('fare', 1, 0, ['o1'])]]]));
        $this->assertSame('facts: committed facts must be a list of at most 16 digests', $r['reason']);
        // a null labels commitment with a provenance policy: active, refused
        $r = IntentWb::decideIntentWb(self::wbIn(['labels' => null], [], ['provenance' => ['params' => (object)[]]]));
        $this->assertSame('provenance: committed labels must be a list of at most 16 digests', $r['reason']);
        // provenance active by labels; a malformed prov is refused, not skipped
        $r = IntentWb::decideIntentWb(self::wbIn(['prov' => 5], [], []));
        $this->assertSame(['provenance' => 'fail'], $r['checks']);
        $this->assertSame("provenance: 'prov' must be an object", $r['reason']);
        // world active by a bare offer_set string; the offers policy is absent so the commitment alone passes
        $r = IntentWb::decideIntentWb(self::wbIn(['offer_set' => self::d('o')], [], []));
        $this->assertSame(['facts' => 'pass'], $r['checks']);
        $this->assertArrayNotHasKey('single_source', $r);
        // an object with `length` never activates: not evaluated, so a malformed value is not refused
        $r = IntentWb::decideIntentWb(self::wbIn(['facts' => ['length' => 1], 'classes' => ['length' => 1], 'labels' => ['length' => 1]], [], []));
        $this->assertSame(['outcome' => 'admit', 'checks' => [], 'env' => []], $r);
    }

    public function testContextShape(): void
    {
        $ctx = static fn(array $over): ?string => IntentWb::intentWbContextError(self::o(array_merge(['intent_session' => (object)[]], $over)));
        $this->assertNull($ctx([]));
        $this->assertNull($ctx(['artifacts' => ['facts' => [], 'labels' => [], 'verdicts' => [], 'offer_set' => (object)[]],
            'policy' => ['world' => (object)[], 'provenance' => (object)[], 'classifiers' => []]]));
        $this->assertSame('intent_session must be an object', IntentWb::intentWbContextError(new Obj()));
        foreach ([null, 'x', [1]] as $v) {
            $this->assertSame('intent_session must be an object', $ctx(['intent_session' => $v]));
            $this->assertSame('artifacts must be an object', $ctx(['artifacts' => $v]));
            $this->assertSame('policy must be an object', $ctx(['policy' => $v]));
        }
        // closed member sets
        $this->assertSame("unknown member 'artifacts.receipts'", $ctx(['artifacts' => ['receipts' => []]]));
        $this->assertSame("unknown member 'policy.offers'", $ctx(['policy' => ['offers' => (object)[]]]));
        foreach (['facts', 'labels', 'verdicts'] as $k) {
            foreach ([null, 'x', (object)[]] as $v) {
                $this->assertSame("artifacts.$k must be an array", $ctx(['artifacts' => [$k => $v]]));
            }
        }
        foreach ([null, 'x', [1]] as $v) {
            $this->assertSame('artifacts.offer_set must be an object', $ctx(['artifacts' => ['offer_set' => $v]]));
            $this->assertSame('policy.world must be an object', $ctx(['policy' => ['world' => $v]]));
            $this->assertSame('policy.provenance must be an object', $ctx(['policy' => ['provenance' => $v]]));
        }
        foreach ([null, 'x', (object)[]] as $v) {
            $this->assertSame('policy.classifiers must be an array', $ctx(['policy' => ['classifiers' => $v]]));
        }
        // order: intent_session, artifacts (closed set, lists, offer_set), then policy (closed set, objects, classifiers)
        $this->assertSame('intent_session must be an object', $ctx(['intent_session' => null, 'artifacts' => null]));
        $this->assertSame("unknown member 'artifacts.x'", $ctx(['artifacts' => ['x' => 1, 'facts' => null]]));
        $this->assertSame('artifacts.facts must be an array', $ctx(['artifacts' => ['offer_set' => null, 'facts' => null], 'policy' => null]));
        $this->assertSame('artifacts must be an object', $ctx(['artifacts' => null, 'policy' => null]));
        $this->assertSame("unknown member 'policy.x'", $ctx(['policy' => ['x' => 1, 'world' => null]]));
        $this->assertSame('policy.world must be an object', $ctx(['policy' => ['classifiers' => null, 'world' => null]]));
        // decideIntentWb: a malformed context fails `facts` (the first check), whatever is active
        $r = IntentWb::decideIntentWb(self::wbIn([], [], ['provenance' => null]));
        $this->assertSame(['outcome' => 'deny', 'checks' => ['facts' => 'fail'], 'env' => [],
            'reason' => 'facts: the W-B context is malformed: policy.provenance must be an object'], $r);
        $r = IntentWb::decideIntentWb(self::wbIn([], [], ['classifiers' => 'x']));
        $this->assertSame('facts: the W-B context is malformed: policy.classifiers must be an array', $r['reason']);
        $r = IntentWb::decideIntentWb(self::wbIn([], ['verdicts' => null], []));
        $this->assertSame('facts: the W-B context is malformed: artifacts.verdicts must be an array', $r['reason']);
        $r = IntentWb::decideIntentWb(self::wbIn([], [], [], ['intent_session' => 'x']));
        $this->assertSame('facts: the W-B context is malformed: intent_session must be an object', $r['reason']);
        $r = IntentWb::decideIntentWb(new Obj());
        $this->assertSame(['facts' => 'fail'], $r['checks']);
        // absent artifacts / policy: {}
        $this->assertSame(['outcome' => 'admit', 'checks' => [], 'env' => []],
            IntentWb::decideIntentWb(self::wbIn([], [], [])->without('artifacts')->without('policy')));

    }

    public function testCompositionFactsInputs(): void
    {
        // the world check reads artifacts.facts / artifacts.offer_set and the session's commitments
        $os = self::offerSet();
        $r = IntentWb::decideIntentWb(self::wbIn(['offer_set' => IntentWb::offerSetRef(self::o($os))], ['offer_set' => $os],
            ['world' => ['offers' => self::offersPolicy()]]));
        $this->assertSame('admit', $r['outcome'], $r['reason'] ?? '');
        $this->assertSame('{"excess":1200}', self::json($r['env']['world']));
        // a non-integer clock: the facts check fails (stale), never coerced
        $r = IntentWb::decideIntentWb(self::full(['material_tainted' => 'allow'], [], []))['outcome'];
        $this->assertSame('admit', $r);
        $in = self::full(['material_tainted' => 'allow']);
        $in->set('now', (string)self::NOW);
        $r = IntentWb::decideIntentWb($in);
        $this->assertSame(['facts' => 'fail'], $r['checks']);
        $this->assertSame("facts: world 'fare' has 0 fresh fact(s), needs 1", $r['reason']);
    }

    // ==== closed and typed policies (0cc44911) ========================================================================

    public function testClosedPolicies(): void
    {
        $e = static fn(array $p): ?string => IntentWb::validateWorldPolicy(self::o($p));
        $this->assertSame("unknown member 'policy.x'", $e(['x' => 1]));
        $this->assertSame("unknown member 'policy.x'", $e(['x' => 1, 'skew_ms' => -1])); // before the members
        $this->assertSame("unknown member 'world.x'", $e(['worlds' => [['x' => 1] + self::world('Bad')]]));
        $this->assertSame("missing member 'world.max_faulty'", $e(['worlds' => [array_diff_key(self::world(), ['max_faulty' => 1])]]));
        $msg = "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
        $this->assertSame($msg, $e(['worlds' => [['oracles' => [['kid' => 'o1', 'pk' => self::kp('o1')[0], 'x' => 1]]] + self::world('fare', 1, 0)]]));
        foreach ([null, '', 5] as $pq) {
            $this->assertSame($msg, $e(['worlds' => [['oracles' => [['kid' => 'o1', 'pk' => self::kp('o1')[0], 'pq_pk' => $pq]]] + self::world('fare', 1, 0)]]));
        }
        $this->assertNull($e(['worlds' => [['oracles' => [['kid' => 'o1', 'pk' => self::kp('o1')[0], 'pq_pk' => 'pq']]] + self::world('fare', 1, 0)]]));
        $this->assertSame("unknown member 'relational.c'", $e(['relational' => [['name' => 'd', 'fn' => 'sub', 'a' => 'action.params.a', 'b' => 'action.params.b', 'c' => 1]]]));
        $this->assertSame("unknown member 'offers.x'", $e(['offers' => self::offersPolicy(['x' => 1])]));
        $this->assertSame("missing member 'offers.filter'", IntentWb::validateOfferPolicy(self::o(array_diff_key(self::offersPolicy(), ['filter' => 1]))));
        $sk = 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk';
        $this->assertSame($sk, IntentWb::validateOfferPolicy(self::o(self::offersPolicy(['site_keys' => [['kid' => 's1', 'pk' => self::kp('s1')[0], 'x' => 1]]]))));
        $this->assertSame($sk, IntentWb::validateOfferPolicy(self::o(self::offersPolicy(['site_keys' => [['kid' => 's1', 'pk' => self::kp('s1')[0], 'pq_pk' => null]]]))));
        $this->assertNull(IntentWb::validateOfferPolicy(self::o(self::offersPolicy(['site_keys' => [['kid' => 's1', 'pk' => self::kp('s1')[0], 'pq_pk' => 'pq']]]))));
        $this->assertSame('offers policy: filter must be exactly {query: {}, offer: {}}',
            IntentWb::validateOfferPolicy(self::o(self::offersPolicy(['filter' => ['query' => (object)[], 'offer' => (object)[], 'x' => 1]]))));
        // provenance
        $pe = static fn(array $p): ?string => IntentWb::validateProvenancePolicy(self::o(['params' => (object)[]] + $p));
        $this->assertSame("unknown member 'policy.x'", $pe(['x' => 1]));
        $this->assertSame("unknown member 'policy.x'", $pe(['x' => 1, 'critical_max' => 'nope']));
        $lk = 'every label key needs site, kid, a 32-byte pk and an optional string pq_pk';
        $key = ['site' => self::AUD, 'kid' => 'k1', 'pk' => self::kp('lk')[0]];
        $this->assertNull($pe(['label_keys' => [$key, $key + ['pq_pk' => 'pq']]]));
        $this->assertSame($lk, $pe(['label_keys' => [$key + ['x' => 1]]]));
        $this->assertSame($lk, $pe(['label_keys' => [$key + ['pq_pk' => null]]]));
        $this->assertSame($lk, $pe(['label_keys' => [$key + ['pq_pk' => '']]]));
        $this->assertTrue(IntentWb::isLabelKey(self::o($key)));
        $this->assertFalse(IntentWb::isLabelKey(self::o(array_diff_key($key, ['pk' => 1]))));
        // enums are their strings only
        $this->assertSame('critical_max must be a taint level', $pe(['critical_max' => 4]));
        $this->assertSame('material_tainted must be allow | question | question_typed | deny', $pe(['material_tainted' => true]));
        // classifiers
        $ce = static fn(array $over): ?string => IntentWb::validateClassifierPolicy(self::o(['classifiers' => [self::clsPolicy($over)]]));
        $this->assertSame("unknown member 'policy.x'", IntentWb::validateClassifierPolicy(self::o(['classifiers' => [], 'x' => 1])));
        $this->assertSame('every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}', $ce(['x' => 1]));
        $this->assertSame('every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}', $ce(['x' => 1, 'id' => 'Bad']));
        $this->assertSame('every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}',
            IntentWb::validateClassifierPolicy(self::o(['classifiers' => [array_diff_key(self::clsPolicy(), ['k' => 1])]])));
        $this->assertNull($ce(['pq_keys' => [self::kp('j1')[0] => 'pq1']]));
        $this->assertNull($ce(['pq_keys' => (object)[]]));
        $pk = "classifier 'tone': pq_keys must map allowlisted keys to PQ keys";
        $this->assertSame($pk, $ce(['pq_keys' => [self::kp('j9')[0] => 'pq']]));
        $this->assertSame($pk, $ce(['pq_keys' => [self::kp('j1')[0] => '']]));
        $this->assertSame($pk, $ce(['pq_keys' => [self::kp('j1')[0] => 5]]));
        $this->assertSame($pk, $ce(['pq_keys' => null]));
        $this->assertSame($pk, $ce(['pq_keys' => ['pq']]));
        // in decide: the world closed set is a misconfiguration
        $this->wFail("policy misconfigured (fail closed): unknown member 'policy.x'", self::wd([], ['x' => 1]));
    }

    // ==== suite members (d63b36e6) ======================================================================================

    public function testArtifactSuiteError(): void
    {
        $se = static fn(array $a): ?string => IntentWb::artifactSuiteError(self::o((object)$a)); // (object): [] is a JSON object here
        $this->assertNull($se([]));
        $this->assertNull($se(['alg' => 'ed25519']));
        $this->assertSame('alg must be a string', $se(['alg' => null]));
        $this->assertSame('alg must be a string', $se(['alg' => 5]));
        $this->assertSame("unsupported_suite: 'bogus'", $se(['alg' => 'bogus']));
        $this->assertSame("unsupported_suite: 'bogus'", $se(['alg' => 'bogus', 'pq_pk' => 5])); // alg first
        if (!Pca::suiteImplemented('fn-dsa-512')) {
            $this->assertSame("unsupported_suite: 'fn-dsa-512'", $se(['alg' => 'fn-dsa-512']));
        }
        $this->assertSame('pq_pk must be a string', $se(['pq_pk' => 5]));
        $this->assertSame('pq_sig must be a string', $se(['pq_sig' => null]));
        $this->assertSame('an ed25519 artifact must not carry pq_pk / pq_sig', $se(['pq_pk' => 'x']));
        $this->assertSame('an ed25519 artifact must not carry pq_pk / pq_sig', $se(['alg' => 'ed25519', 'pq_sig' => 'x']));
        $this->assertSame(IntentWb::SUITE_MEMBERS, ['alg', 'pq_pk', 'pq_sig']);
        // the signed body excludes sig AND pq_sig; alg and pq_pk are signed
        $f = self::fact('o1', 1);
        $this->assertSame(IntentWb::artifactMessage(IntentWb::FACT_DOMAIN, self::o($f)),
            IntentWb::artifactMessage(IntentWb::FACT_DOMAIN, self::o($f + ['pq_sig' => 'x'])));
        $this->assertNotSame(IntentWb::artifactMessage(IntentWb::FACT_DOMAIN, self::o($f)),
            IntentWb::artifactMessage(IntentWb::FACT_DOMAIN, self::o($f + ['alg' => 'ed25519'])));
    }

    public function testSuitesPerArtifact(): void
    {
        $pol = ['worlds' => [self::world('fare', 1, 0, ['o1'])]];
        $sig = static fn(string $domain, array $body, string $signer): array => self::sign($domain, $body, self::kp($signer)[1]);
        $factBody = ['v' => 1, 'kind' => 'pca-fact', 'name' => 'fare', 'subject' => 'OF-2', 'value' => 7, 't_obs' => self::NOW - 1, 'oracle' => 'o1'];
        // an explicit, signed alg "ed25519" verifies
        $this->wOk('{"fare":7}', self::wd([$sig(IntentWb::FACT_DOMAIN, $factBody + ['alg' => 'ed25519'], 'o1')], $pol), ['fare']);
        // alg is signed: adding it after signing breaks the signature
        $this->wFail("bad oracle signature on a 'fare' fact", self::wd([$sig(IntentWb::FACT_DOMAIN, $factBody, 'o1') + ['alg' => 'ed25519']], $pol));
        // unsupported suite: before anything else about the fact (even an undeclared world)
        $this->wFail("fact signature suite: unsupported_suite: 'bogus'", self::wd([$sig(IntentWb::FACT_DOMAIN, ['name' => 'tier'] + $factBody + ['alg' => 'bogus'], 'o1')], $pol));
        $this->wFail('fact signature suite: an ed25519 artifact must not carry pq_pk / pq_sig', self::wd([$sig(IntentWb::FACT_DOMAIN, $factBody, 'o1') + ['pq_sig' => 'x']], $pol));
        $this->wFail('fact signature suite: alg must be a string', self::wd([$sig(IntentWb::FACT_DOMAIN, $factBody + ['alg' => null], 'o1')], $pol));
        // a PQ suite without a pinned PQ key never verifies (the artifact's own pq_pk proves nothing)
        $pq = $sig(IntentWb::FACT_DOMAIN, $factBody + ['alg' => 'ml-dsa-65', 'pq_pk' => 'AAAA'], 'o1');
        $want = Pca::suiteImplemented('ml-dsa-65') ? "bad oracle signature on a 'fare' fact" : "fact signature suite: unsupported_suite: 'ml-dsa-65'";
        $this->wFail($want, self::wd([$pq], $pol));
        $pinned = ['worlds' => [['oracles' => [['kid' => 'o1', 'pk' => self::kp('o1')[0], 'pq_pk' => 'BBBB']]] + self::world('fare', 1, 0, ['o1'])]];
        $this->wFail($want, self::wd([$pq], $pinned)); // pinned PQ key differs from the artifact's
        // offer set: the reference is checked before the suite
        $this->wFail("offers: signature suite: unsupported_suite: 'bogus'", self::od(self::offerSet(['alg' => 'bogus'])));
        $this->wFail('offers: the supplied offer set does not match the committed reference', self::od(self::offerSet(['alg' => 'bogus']), [], [], self::d('x')));
        $this->wFail("offers: signature suite: unsupported_suite: 'bogus'", self::od(self::offerSet(['alg' => 'bogus'], 's9')));
        $this->wOk('{"excess":1200}', self::od(self::offerSet(['alg' => 'ed25519'])));
        // label receipt: wire, then suite, then the pin
        $rc = self::receipt(self::AUD, ['passport' => ['pii.passport', 'X1234567']], ['alg' => 'bogus'], 'k9');
        $this->pFail("label receipt for 'action.params.passport': signature suite: unsupported_suite: 'bogus'",
            self::ld([$rc], [self::lref($rc, 'passport')], ['params' => (object)[]]));
        $this->assertSame("signature suite: unsupported_suite: 'bogus'", IntentWb::verifyLabels(self::o($rc), []));
        $ok = self::receipt(self::AUD, ['passport' => ['pii.passport', 'X1234567']], ['alg' => 'ed25519']);
        $this->assertNull(IntentWb::verifyLabels(self::o($ok), array_map([self::class, 'o'], self::labelKeys())));
        // verdict: suite before the classifier lookup
        $bad = self::verdict('j1', 'apologetic', ['alg' => 'bogus', 'classifier' => 'mood']);
        $this->cFail("verdict signature suite: unsupported_suite: 'bogus'", self::cd([$bad, self::verdict('j2', 'apologetic')]));
        $r = self::cd([self::verdict('j1', 'apologetic', ['alg' => 'ed25519']), self::verdict('j2', 'apologetic')]);
        $this->assertSame('{"tone":"apologetic"}', self::json($r['classes']));
        // a PQ verdict under a pq_keys pin that differs from its pq_pk: bad signature (or unsupported)
        $v = self::verdict('j1', 'apologetic', ['alg' => 'ml-dsa-65', 'pq_pk' => 'AAAA']);
        $want = Pca::suiteImplemented('ml-dsa-65') ? "classifier 'tone': bad verdict signature" : "verdict signature suite: unsupported_suite: 'ml-dsa-65'";
        $this->cFail($want, self::cd([$v, self::verdict('j2', 'apologetic')], ['pq_keys' => [self::kp('j1')[0] => 'BBBB']]));
        $this->cFail($want, self::cd([$v, self::verdict('j2', 'apologetic')]));
    }

    public function testVerifyArtifactSigPins(): void
    {
        $f = self::o(self::fact('o1', 1));
        [$pk] = self::kp('o1');
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, self::o(['kid' => 'o1', 'pk' => $pk])));
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, self::o(['kid' => 'o1', 'pk' => $pk, 'pq_pk' => 'x']))); // ed25519 ignores the PQ pin
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, self::o(['kid' => 'o1'])));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, self::o(['pk' => 5])));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, null));
    }

    // ==== read purpose (ab9766e0) ======================================================================================

    private static function rp(array $input): array
    {
        return IntentWb::decideReadPurpose(self::o($input));
    }

    public function testReadPurpose(): void
    {
        $cover = ['booking' => ['pii.identity', 'itinerary'], 'support' => ['pii.*', 'internal'], 'comparison' => []];
        $fields = [
            ['path' => 'passengers[].name', 'class' => 'pii.identity'],
            ['path' => 'passengers[].email', 'class' => 'pii.contact', 'optional' => true],
            ['path' => 'loyalty', 'class' => 'internal', 'optional' => true],
            ['path' => 'fares', 'class' => 'public'],
        ];
        $in = static fn(array $over = []): array => array_merge(['fields' => $fields, 'purpose' => 'booking', 'coverage' => $cover], $over);
        $min = ['loyalty', 'passengers[].email'];
        $this->assertSame(['outcome' => 'allow', 'minimise' => $min, 'uncovered' => []], self::rp($in()));
        $this->assertSame(['outcome' => 'allow', 'minimise' => [], 'uncovered' => []], self::rp($in(['purpose' => 'support'])));
        $q = ['outcome' => 'question', 'minimise' => $min, 'uncovered' => ['passengers[].name']];
        $this->assertSame($q, self::rp($in(['purpose' => 'comparison'])));
        $this->assertSame(['outcome' => 'deny'] + $q, self::rp($in(['purpose' => 'comparison', 'on_uncovered' => 'deny'])));
        $this->assertSame($q, self::rp($in(['purpose' => 'comparison', 'on_uncovered' => 'question'])));
        $this->assertSame($q, self::rp($in(['purpose' => 'nope'])));
        $this->assertSame($q, self::rp($in(['purpose' => 'constructor']))); // own member only
        $this->assertSame($q, self::rp($in(['purpose' => '__proto__'])));
        // patterns: `*`, exact, `p.*` keeps the dot (pii.* does not cover "piix")
        $one = static fn(string $cls, array $pats): array => self::rp(['fields' => [['path' => 'f', 'class' => $cls]], 'purpose' => 'p', 'coverage' => ['p' => $pats]]);
        $this->assertSame('allow', $one('anything', ['*'])['outcome']);
        $this->assertSame('allow', $one('pii.x', ['pii.*'])['outcome']);
        $this->assertSame('question', $one('piix', ['pii.*'])['outcome']);
        $this->assertSame('question', $one('pii', ['pii.*'])['outcome']);
        $this->assertSame('allow', $one('public', [])['outcome']);
        // optional false is required
        $this->assertSame(['outcome' => 'question', 'minimise' => [], 'uncovered' => ['f']],
            self::rp(['fields' => [['path' => 'f', 'class' => 'x', 'optional' => false]], 'purpose' => 'p', 'coverage' => ['p' => []]]));
        // duplicates appear once
        $this->assertSame(['outcome' => 'question', 'minimise' => [], 'uncovered' => ['x']],
            self::rp(['fields' => [['path' => 'x', 'class' => 'secret'], ['path' => 'x', 'class' => 'secret']], 'purpose' => 'booking', 'coverage' => $cover]));
        // UTF-8 BYTE order: U+FFFD (EF BF BD) before U+1F600 (F0 9F 98 80), unlike UTF-16 order
        $mixed = ["z\u{1F600}", "z\u{FFFD}", "z\u{E9}", 'za', "\u{1F600}", "\u{FFFD}", 'a'];
        $mf = [];
        foreach ($mixed as $i => $p) {
            $mf[] = ['path' => $p, 'class' => 'secret', 'optional' => $i % 2 === 0];
            $mf[] = ['path' => $p . '!', 'class' => 'secret'];
        }
        $this->assertSame([
            'outcome' => 'question',
            'minimise' => ['a', "z\u{E9}", "z\u{1F600}", "\u{1F600}"],
            'uncovered' => ['a!', 'za', 'za!', "z\u{E9}!", "z\u{FFFD}", "z\u{FFFD}!", "z\u{1F600}!", "\u{FFFD}", "\u{FFFD}!", "\u{1F600}!"],
        ], self::rp(['fields' => $mf, 'purpose' => 'booking', 'coverage' => $cover]));
        // malformed: deny with empty lists
        $deny = ['outcome' => 'deny', 'minimise' => [], 'uncovered' => []];
        foreach ([
            ['fields' => null], ['fields' => 'x'], ['fields' => (object)[]], ['coverage' => null], ['coverage' => []], ['purpose' => null],
            ['purpose' => 5], ['on_uncovered' => 'allow'], ['on_uncovered' => null], ['coverage' => ['booking' => 'pii.*']],
            ['coverage' => ['booking' => ['pii.*', 5]]], ['coverage' => ['other' => null] + $cover],
            ['fields' => [['path' => 'x', 'class' => 'secret', 'optional' => null]]], ['fields' => [['path' => 'x', 'class' => 'secret', 'optional' => 1]]],
            ['fields' => [['path' => 5, 'class' => 'secret']]], ['fields' => [['path' => 'x']]], ['fields' => [5]],
        ] as $i => $over) {
            $this->assertSame($deny, self::rp($in($over)), "case $i");
        }
        $this->assertSame($deny, IntentWb::decideReadPurpose(new Obj()));
        $this->assertSame($deny, IntentWb::decideReadPurpose(null));
        $this->assertSame($deny, self::rp(['fields' => [], 'coverage' => $cover])); // absent purpose
    }

    public function testCompareUtf8(): void
    {
        $this->assertLessThan(0, IntentWb::compareUtf8("\u{FFFD}", "\u{1F600}"));
        $this->assertGreaterThan(0, IntentWb::compareUtf8("\u{1F600}", "\u{FFFD}"));
        $this->assertLessThan(0, IntentWb::compareUtf8('Z', 'a'));
        $this->assertLessThan(0, IntentWb::compareUtf8('a', 'ab'));
        $this->assertSame(0, IntentWb::compareUtf8('x', 'x'));
        // a lone surrogate encodes as U+FFFD: equal UTF-8 to a real U+FFFD, the tie broken by UTF-16 code units
        $lone = Json::parseLax('"\\ud800"');
        $this->assertLessThan(0, IntentWb::compareUtf8($lone, "\u{FFFD}"));
        $this->assertLessThan(0, IntentWb::compareUtf8($lone . 'a', "\u{FFFD}b"));
        $this->assertGreaterThan(0, IntentWb::compareUtf8($lone, "\u{E9}"));
        // provenance classes use it: sorted UTF-8 byte order
        $rc = self::receipt(self::AUD, ['a' => ['pii.z', 'X1234567'], 'b' => ['pii.a', 'X1234567'], 'c' => ['pii.a', 'X1234567']]);
        $r = self::ld([$rc], [self::lref($rc, 'a'), self::lref($rc, 'b'), self::lref($rc, 'c')], ['params' => (object)[]]);
        $this->assertSame(['pii.a', 'pii.z'], $r['classes']->get('action.params.passport'));
    }

    // ==== 0.4.2 mutation run 38330645854 ==============================================================================

    public function testR042JsNumStrNegatives(): void
    {
        foreach ([[-5.0, '-5'], [-123.0, '-123'], [-0.001, '-0.001'], [-0.000001, '-0.000001'], [-1e-7, '-1e-7'],
                  [-1.5e-7, '-1.5e-7'], [-1e21, '-1e+21'], [-1.25e25, '-1.25e+25']] as [$v, $s]) {
            $this->assertSame($s, IntentWb::jsNumStr($v), $s);
        }
    }

    /** An array-index key is the canonical decimal form only: "5\n" is an ordinary key (insertion order, after indices). */
    public function testR042JsKeysIndexNeedsExactDigits(): void
    {
        $o = new Obj();
        $o->set('b', 1);
        $o->set("5\n", 2);
        $o->set('1', 3);
        $this->assertSame(['1', 'b', "5\n"], IntentWb::jsKeys($o));
    }

    private function jsonError(string $want, callable $f): void
    {
        try {
            $f();
            $this->fail("no JsonError ($want)");
        } catch (\Atlas\Pca\JsonError $e) {
            $this->assertSame($want, $e->getMessage());
        }
    }

    /** Canonical numbers inside arrays are normalised too; non-finite and unsafe values are refused by the strict profile. */
    public function testR042NormNestedAndNonFinite(): void
    {
        $this->assertSame(IntentWb::valueDigest(Json::parseLax('[1]')), IntentWb::valueDigest(Json::parseLax('[1.0]')));
        $this->assertSame(IntentWb::valueDigest(Json::parseLax('[[2,{"a":[3]}]]')), IntentWb::valueDigest(Json::parseLax('[[2.0,{"a":[30e-1]}]]')));
        // a Num lexeme whose value overflows keeps its own lexeme (the strict profile names that lexeme's fault)
        $this->jsonError('integer outside the safe range', fn() => IntentWb::valueDigest(new Num('1' . str_repeat('0', 400))));
        $this->jsonError('exponent form is not allowed', fn() => IntentWb::valueDigest(new Num('1e400')));
        // a native non-finite float is refused like an overflowing lexeme
        $this->jsonError('exponent form is not allowed', fn() => IntentWb::valueDigest(INF));
        $this->jsonError('exponent form is not allowed', fn() => IntentWb::valueDigest([-INF]));
        // an integral value beyond 2^53-1 is its Number::toString form (exponent from 1e21 on)
        $this->jsonError('exponent form is not allowed', fn() => IntentWb::valueDigest(new Num('1e21')));
        $this->jsonError('integer outside the safe range', fn() => IntentWb::valueDigest(new Num('1e20')));
    }

    public function testR042PublicHelpers(): void
    {
        $this->assertTrue(IntentWb::isPathSegment('ab_1'));
        $this->assertFalse(IntentWb::isPathSegment('__proto__'));
        $f = self::o(self::fact('o1', 1));
        $this->assertSame(IntentWb::factRef($f), IntentWb::artifactRef(IntentWb::FACT_REF_DOMAIN, 'f', $f));
        $this->assertTrue(IntentWb::isTaintLevel('web'));
        $this->assertFalse(IntentWb::isTaintLevel('constructor'));
        $this->assertTrue(IntentWb::isProvPath('action.params.a'));
        $this->assertFalse(IntentWb::isProvPath('action.params.a.b'));
        $this->assertNull(IntentWb::validateProvWire(new Obj()));
        $this->assertSame("'prov' must be an object", IntentWb::validateProvWire([]));
    }

    /** The path must start with "action.params." exactly: a same-length look-alike prefix resolves nothing. */
    public function testR042ResolveParamPathPrefix(): void
    {
        $p = self::o(['foo' => 1]);
        // the lax parser keeps every number as its lexeme (a Num), so the resolved value is that very node
        $foo = $p->get('foo');
        $this->assertInstanceOf(\Atlas\Pca\Num::class, $foo);
        $this->assertSame('1', $foo->lexeme);
        $this->assertSame(['found' => true, 'value' => $foo], IntentWb::resolveParamPath($p, 'action.params.foo'));
        $this->assertSame(['found' => false], IntentWb::resolveParamPath($p, 'action.paramX.foo'));
        $this->assertSame(['found' => false], IntentWb::resolveParamPath($p, 'xxxxxxxxxxxxxxfoo'));
        $this->assertSame(['found' => false], IntentWb::resolveParamPath($p, 5));
    }

    /** A body that is not strictly canonical has no signed message: the signature check is false, never an error. */
    public function testR042VerifyArtifactSigNonCanonicalBody(): void
    {
        [$pk] = self::kp('o1');
        $f = self::o(self::fact('o1', 1));
        $this->assertTrue(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, $pk), 'control');
        $f->set('value', new Num('1e400'));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, $pk));
        $f->set('value', Json::parseLax('"\ud800"'));
        $this->assertFalse(IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $f, self::o(['kid' => 'o1', 'pk' => $pk])));
    }

    /** floor(a * 10^6 / b) is refused exactly when it exceeds 2^53-1 (a large fractional part included). */
    public function testR042RatioPpmUpperBoundary(): void
    {
        $this->assertNull(IntentWb::ratioPpm(9007190247800744, 999999)); // 9007199254999998
        $this->assertSame(9007199254740989, IntentWb::ratioPpm(9007190247541735, 999999));
        $this->assertSame(self::MAX_SAFE, IntentWb::ratioPpm(self::MAX_SAFE, 1000000));
    }

    public function testR042OfferPolicyTyping(): void
    {
        $sk = 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk';
        $v = static fn(array $over): ?string => IntentWb::validateOfferPolicy(self::o(self::offersPolicy($over)));
        $this->assertSame($sk, $v(['site_keys' => [5]]));
        $this->assertSame($sk, $v(['site_keys' => [['kid' => 's1', 'pk' => self::kp('s1')[0]], 'x']]));
        $this->assertNull($v(['site_keys' => [['kid' => str_repeat('k', 64), 'pk' => self::kp('s1')[0]]]]));
        $this->assertSame($sk, $v(['site_keys' => [['kid' => str_repeat('k', 65), 'pk' => self::kp('s1')[0]]]]));
        $fm = 'offers policy: filter must be exactly {query: {}, offer: {}}';
        $this->assertSame($fm, $v(['filter' => 5]));
        $this->assertSame($fm, $v(['filter' => ['query' => (object)[], 'offer' => 5]]));
        $this->assertSame($fm, $v(['filter' => ['query' => 5, 'offer' => (object)[]]]));
    }

    public function testR042WorldPolicyBoundaries(): void
    {
        $e = static fn(array $p): ?string => IntentWb::validateWorldPolicy(self::o($p));
        $this->assertNull($e(['worlds' => [self::world('fare', 1, 0, ['o1'], 0)]])); // freshness 0 is allowed
        $this->assertNull($e(['worlds' => [['oracles' => [['kid' => str_repeat('k', 64), 'pk' => self::kp('o1')[0]]]] + self::world('fare', 1, 0)]]));
        $om = "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
        $this->assertSame($om, $e(['worlds' => [['oracles' => [['kid' => str_repeat('k', 65), 'pk' => self::kp('o1')[0]]]] + self::world('fare', 1, 0)]]));
        $this->assertSame($om, $e(['worlds' => [['oracles' => [5]] + self::world('fare', 1, 0)]]));
        $rel = static fn(int $n): array => array_map(static fn(int $i): array => ['name' => "r$i", 'fn' => 'sub', 'a' => 'action.params.total',
            'b' => 'action.params.quote'], range(0, $n - 1));
        $this->assertNull($e(['relational' => $rel(16)]));
        $this->assertSame('relational must be a list of at most 16', $e(['relational' => $rel(17)]));
    }

    /** A malformed supplied fact is skipped, never the end of the scan: a later well-formed one is still found. */
    public function testR042MalformedSuppliedFactSkipped(): void
    {
        $f = self::fact('o1', 7);
        $this->wOk('{"fare":7}', self::wd([['x' => 1], $f], ['worlds' => [self::world('fare', 1, 0, ['o1'])]], [], ['facts' => [self::fref($f)]]), ['fare']);
    }

    /** One fact per (world, oracle) pair, keyed unambiguously: world "a" / oracle "bc" and world "ab" / oracle "c" differ. */
    public function testR042WorldOraclePairsAreDistinct(): void
    {
        $r = self::wd([self::fact('bc', 5, self::NOW - 1000, 'a'), self::fact('c', 6, self::NOW - 1000, 'ab')],
            ['worlds' => [self::world('a', 1, 0, ['bc']), self::world('ab', 1, 0, ['c'])]]);
        $this->wOk('{"a":5,"ab":6}', $r, ['a', 'ab']);
    }

    public function testR042OfferSetWireBoundaries(): void
    {
        $base = self::o(self::offerSet());
        $w = static function (array $over) use ($base): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($base));
            foreach ($over as $k => $v) {
                $g->set($k, self::o($v));
            }
            return IntentWb::validateOfferSetWire($g);
        };
        $this->assertNull($w(['query' => [str_repeat('q', 64) => 'x']]));
        $this->assertNull($w(['offers' => [['offer_id' => 'a', 'price' => 1, str_repeat('a', 64) => 'x']]]));
        $k65 = str_repeat('a', 65);
        $this->assertSame("offer 0: attribute '$k65' must be a scalar", $w(['offers' => [['offer_id' => 'a', 'price' => 1, $k65 => 'x']]]));
        $this->assertNull($w(['issued_at' => 0]));
        $this->assertNull($w(['kid' => str_repeat('k', 64)]));
        $this->assertSame("'offer_set.kid' must be a non-empty string (<= 64 bytes)", $w(['kid' => str_repeat('k', 65)]));
    }

    public function testR042FilterHelpersAreTotal(): void
    {
        $this->assertFalse(IntentWb::offerMatches(new Obj(), 5));
        $this->assertFalse(IntentWb::offerMatches(5, new Obj()));
        $this->assertTrue(IntentWb::offerMatches(new Obj(), new Obj()));
        $this->assertFalse(IntentWb::queryCovers(5, new Obj()));
        $this->assertFalse(IntentWb::queryCovers(new Obj(), 5));
        $this->assertTrue(IntentWb::queryCovers(new Obj(), new Obj()));
    }

    public function testR042LabelsWireBoundaries(): void
    {
        $base = self::o(self::passportReceipt());
        $w = static function (array $over) use ($base): ?string {
            $g = Json::parseLax(Json::canonicalizeStrict($base));
            foreach ($over as $k => $v) {
                $g->set($k, self::o($v));
            }
            return IntentWb::validateLabelsWire($g);
        };
        $vd = self::d('v');
        $this->assertNull($w(['site' => str_repeat('s', 256)]));
        $this->assertSame("'labels.site' must be a non-empty string (<= 256 bytes)", $w(['site' => str_repeat('s', 257)]));
        $this->assertSame('label field paths must be non-empty strings (<= 256 bytes)', $w(['fields' => [str_repeat('p', 257) => ['class' => 'public', 'value_digest' => $vd]]]));
        $this->assertNull($w(['issued_at' => 0]));
        $this->assertNull($w(['kid' => str_repeat('k', 64)]));
    }

    /** Pinned label keys: a list only, and the FIRST entry for (site, kid) is the pin (the reference's find). */
    public function testR042VerifyLabelsPins(): void
    {
        $rc = self::o(self::passportReceipt());
        $keys = array_map([self::class, 'o'], self::labelKeys());
        $this->assertNull(IntentWb::verifyLabels($rc, $keys));
        $this->assertSame('label keys must be an array', IntentWb::verifyLabels($rc, 5));
        $this->assertSame('label keys must be an array', IntentWb::verifyLabels($rc, ['a' => $keys[0]]));
        $wrong = self::o(['site' => self::AUD, 'kid' => 'k1', 'pk' => self::kp('not-the-signer')[0]]);
        $this->assertSame('bad label receipt signature', IntentWb::verifyLabels($rc, [$wrong, $keys[0]]));
        $this->assertNull(IntentWb::verifyLabels($rc, [$keys[0], $wrong]));
    }

    public function testR042FlowSinksMustBeAList(): void
    {
        $this->assertFalse(IntentWb::flowAllowed(self::o(['pii.*' => 'aud.example']), 'pii.a', 'o.example', 'aud.example'));
        $this->assertTrue(IntentWb::flowAllowed(self::o(['pii.*' => ['aud.example']]), 'pii.a', 'o.example', 'aud.example'));
    }

    public function testR042LabelKeyAndRegistryBoundaries(): void
    {
        $k = static fn(string $site, string $kid): bool => IntentWb::isLabelKey(self::o(['site' => $site, 'kid' => $kid, 'pk' => self::kp('x')[0]]));
        $this->assertTrue($k(str_repeat('s', 256), 'k'));
        $this->assertFalse($k(str_repeat('s', 257), 'k'));
        $this->assertTrue($k('s', str_repeat('k', 64)));
        $this->assertFalse($k('s', str_repeat('k', 65)));
        $r257 = str_repeat('r', 257);
        $this->assertSame("registry entry '$r257' must map to a taint level",
            IntentWb::validateProvenancePolicy(self::o(['params' => (object)[], 'registry' => [$r257 => 'web']])));
        $this->assertNull(IntentWb::validateProvenancePolicy(self::o(['params' => (object)[], 'registry' => [str_repeat('r', 256) => 'web']])));
        $this->assertNull(IntentWb::validateClassifierPolicy(self::o(['classifiers' => [self::clsPolicy(['labels' => [str_repeat('l', 64)]])]])));
    }

    /** A parameter value that cannot be hashed strictly never matches its label: provenance `agent`, not the receipt's site. */
    public function testR042UnhashableValueNeverMatchesALabel(): void
    {
        $rc = self::passportReceipt();
        $in = self::pIn(['action.params.passport' => [self::lref($rc, 'passport')]], [], ['committed_labels' => [self::rref($rc)], 'labels' => [$rc]]);
        $this->pOut('question', '{"action.params.offer_id":"agent","action.params.passport":"first_party"}', IntentWb::decideParamProvenance($in),
            'typed', '{"action.params.passport":["pii.passport"]}');
        $in->get('action')->get('params')->set('passport', Json::parseLax('"\ud800"'));
        $this->pOut('question', '{"action.params.offer_id":"agent","action.params.passport":"agent"}', IntentWb::decideParamProvenance($in),
            'typed', '{"action.params.passport":["pii.passport"]}');
    }

    /** Judges are counted per classifier: one judge may vote once on each of two classifiers. */
    public function testR042OneJudgeTwoClassifiers(): void
    {
        $vs = [self::verdict('j1', 'apologetic'), self::verdict('j1', 'apologetic', ['classifier' => 'mood'])];
        $r = self::cd($vs, [], [], null, [self::clsPolicy(['k' => 1]), self::clsPolicy(['id' => 'mood', 'k' => 1])]);
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
        $this->assertSame('{"mood":"apologetic","tone":"apologetic"}', self::json($r['classes']));
    }

    /** A malformed supplied verdict is skipped, never the end of the scan. */
    public function testR042MalformedSuppliedVerdictSkipped(): void
    {
        $vs = [self::verdict('j1', 'apologetic'), self::verdict('j2', 'apologetic')];
        $r = self::cd([['x' => 1], ...$vs], [], [], array_map([self::class, 'vref'], $vs));
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
        $this->assertSame('{"tone":"apologetic"}', self::json($r['classes']));
    }

    /** Content that cannot be hashed strictly: an evaluation error naming the cause (fail closed). */
    public function testR042ClassifierContentNotCanonical(): void
    {
        $vs = [self::verdict('j1', 'apologetic'), self::verdict('j2', 'apologetic')];
        $in = self::o(['session' => self::sess(), 'action' => ['params' => ['message' => self::MESSAGE]], 'committed' => array_map([self::class, 'vref'], $vs),
            'verdicts' => $vs, 'policy' => ['classifiers' => [self::clsPolicy()]]]);
        $this->assertTrue(IntentWb::decideClassifierDimensions($in)['ok'], 'control');
        $in->get('action')->get('params')->set('message', Json::parseLax('"\ud800"'));
        $r = IntentWb::decideClassifierDimensions($in);
        $this->assertFalse($r['ok']);
        $this->assertStringStartsWith('classes: evaluation error (fail closed): ', $r['reason']);
        $this->assertStringContainsString('lone surrogate', $r['reason']);
    }

    /** decideIntentWb hands each rule the members it reads (activity, audience, session, artifacts, policy). */
    public function testR042CompositionWiring(): void
    {
        // provenance active by a labels commitment alone
        $r = IntentWb::decideIntentWb(self::wbIn(['labels' => [self::d('x')]], [], []));
        $this->assertSame('admit', $r['outcome'], $r['reason'] ?? '');
        $this->assertSame(['provenance' => 'pass'], $r['checks']);
        $this->assertSame(['prov'], array_keys($r['env']));
        $this->assertSame('{}', self::json($r['env']['prov']));
        // a first-party label receipt: needs the audience, the session and the supplied receipts
        $rc = self::passportReceipt();
        $r = IntentWb::decideIntentWb(self::wbIn(['prov' => ['action.params.passport' => [self::lref($rc, 'passport')]], 'labels' => [self::rref($rc)]],
            ['labels' => [$rc]], ['provenance' => ['params' => (object)[], 'label_keys' => self::labelKeys()]]));
        $this->assertSame('admit', $r['outcome'], $r['reason'] ?? '');
        $this->assertSame(['provenance' => 'pass'], $r['checks']);
        $this->assertSame('{"action":{"params":{"passport":"first_party"}}}', self::json($r['env']['prov']));
        // classes active by a commitment alone, and by a classifier policy alone
        $r = IntentWb::decideIntentWb(self::wbIn(['classes' => [self::d('x')]], [], []));
        $this->assertSame(['classes' => 'fail'], $r['checks']);
        $this->assertSame('classes: a committed verdict was not supplied (or is malformed)', $r['reason']);
        $r = IntentWb::decideIntentWb(self::wbIn([], [], ['classifiers' => [self::clsPolicy()]]));
        $this->assertSame(['classes' => 'fail'], $r['checks']);
        $this->assertSame("classes: classifier 'tone': no label reaches the quorum 2", $r['reason']);
    }
}
