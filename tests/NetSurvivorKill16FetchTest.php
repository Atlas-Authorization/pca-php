<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Fetch.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Escalation;
use Atlas\Pca\Fetch;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * The Web-Fetch guard end to end: the challenge text, the header reader, the pre-verification refusals with their exact results, the
 * clock, the fresh_at / intent v2 context options, the signature-only verdict mapping, the authorize-path wiring (an escalate, an
 * answered allow, the escalation-answer header, the k1 and risk inputs, the raw text handed to the pipeline) and the deny response.
 */
final class NetSurvivorKill16FetchTest extends TestCase
{
    private const NOW = 1_800_000_000_000;
    private const AUD = 'aud';
    private const PLAN = [['id' => 'a', 'verb' => 'v', 'resource' => 'r']];
    private const FRESH_REQUIRED = 'fresh_at: escalate: a consistency token is required (refresh and retry with the token of your latest write)';
    private const OP_REFUSAL = 'operation: authorize needs the operation to execute (verb, resource, params) (fail closed)';

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/net16-' . $label, true));
    }

    /** @return array{0: Obj, 1: Obj} grant, signed PCActn (iat null = the wall clock, with the default lifetime) */
    private static function signed(array $extra = [], ?int $iat = self::NOW): array
    {
        $k = self::key('holder');
        $grant = Sign::mintRoot(self::key('principal'), $k->public, []);
        $ttl = $iat === null ? Sign::DEFAULT_TTL_MS : 1000;
        return [$grant, Sign::buildPcactn($grant, [$grant], self::PLAN, 'a', 1, $k, self::AUD, null, $iat, null, $ttl, $extra)];
    }

    private static function header(Obj $p): array
    {
        return [Fetch::PCA_HEADER => Pca::b64u(Json::canonicalizeStrict($p))];
    }

    private static function sigGuard(Obj $grant, array $o = []): \Closure
    {
        return Fetch::createPcaFetchGuard($o + ['audience' => self::AUD, 'resolveGrant' => static fn() => $grant, 'now' => self::NOW, 'signatureOnly' => true]);
    }

    public function throwingHook(mixed ...$a): mixed
    {
        throw new \RuntimeException('verifier state down');
    }

    /** Runs $f with every PHP warning / notice turned into a thrown error. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- the challenge and the header reader --------------------------------------------------------------------------

    /** The challenge is built from fixed tokens and quoted-strings that escape backslash and double quote, in a fixed order. */
    public function testTheChallengeQuotesEveryParamInOrder(): void
    {
        $this->assertSame('PCA realm="pca"', Fetch::challenge(null));
        $this->assertSame('PCA realm="pca", audience="a\\\\b\\"c", error="e", error_description="d \\"x\\""', Fetch::challenge('a\\b"c', 'e', 'd "x"'));
        $this->assertSame('PCA realm="pca", audience="x", error_description="d"', Fetch::challenge('x', null, 'd'));
    }

    /** Every spelling of a header is read, the first string of a list counts, and two different values are no value. */
    public function testTheHeaderReaderReadsEverySpellingAndRefusesAmbiguity(): void
    {
        $this->assertSame('x', Fetch::getHeader(['A' => '1', 'PCA-Action' => 'x'], 'pca-action'));
        $this->assertSame('v', Fetch::getHeader(['Pca-Action' => ['v', 'w']], 'PCA-Action'));
        $this->assertSame('v', Fetch::getHeader(['pca-action' => 5, 'PCA-Action' => 'v'], 'pca-action'));
        $this->assertNull(Fetch::getHeader(['a' => '1', 'A' => '2'], 'a'));
        $this->assertSame('1', Fetch::getHeader(['a' => '1', 'A' => '1'], 'a'));
        $this->assertSame('v', Fetch::getHeader(['5' => 'v'], '5'), 'an integer-like header name is still a name');
        $this->assertSame('y', Fetch::getHeader(Obj::of(['X' => 'y']), 'x'));
        $this->assertNull(Fetch::getHeader('PCA-Action: x', 'PCA-Action'), 'a string is no header map');
        $this->assertNull(Fetch::getHeader([['PCA-Action', 'x']], 'PCA-Action'), 'a list is no header map');
    }

    // ---- refusals before verification --------------------------------------------------------------------------------

    /** No proof (a body that is not UTF-8 is no body) and an undecodable proof are 401 with their own challenge. */
    public function testAbsentAndUndecodableProofsAre401(): void
    {
        [$grant] = self::signed();
        $g = self::sigGuard($grant);
        $r = $g([], "\xff\xfe");
        $this->assertSame([false, 401, 'absent', 'deny', null], [$r['ok'], $r['status'], $r['error'], $r['decision'], $r['pcactn']]);
        $this->assertSame('PCA realm="pca", audience="aud", error="missing_pcactn", error_description="no PCActn presented"', $r['wwwAuthenticate']);
        $r = $g([Fetch::PCA_HEADER => '!!']);
        $this->assertSame([false, 401, 'undecodable'], [$r['ok'], $r['status'], $r['error']]);
        $this->assertSame('PCA realm="pca", audience="aud", error="invalid_pcactn", error_description="PCActn could not be decoded"', $r['wwwAuthenticate']);
    }

    /** A decoded header of exactly the artifact limit is read (here: no grant_ref, malformed); one byte more is undecodable. */
    public function testAHeaderAtTheArtifactLimitIsRead(): void
    {
        [$grant] = self::signed();
        $g = self::sigGuard($grant);
        foreach ([Pca::MAX_ARTIFACT_BYTES => 'malformed', Pca::MAX_ARTIFACT_BYTES + 1 => 'undecodable'] as $size => $error) {
            $text = '{"x":"' . str_repeat('a', $size - 8) . '"}';
            $this->assertSame($size, strlen($text));
            $r = $g([Fetch::PCA_HEADER => Pca::b64u($text)]);
            $this->assertSame([false, 401, $error], [$r['ok'], $r['status'], $r['error']], "header of $size bytes");
        }
        $this->assertSame('1', (string)$g([Fetch::PCA_HEADER => Pca::b64u('{"x":"1"}')])['pcactn']->get('x'));
        $this->assertSame('PCA realm="pca", audience="aud", error="invalid_pcactn", error_description="malformed PCActn"', $g([Fetch::PCA_HEADER => Pca::b64u('{}')])['wwwAuthenticate']);
    }

    /** The construction guards: the exact unbound-operation message, authorize alone is enough, signatureOnly excludes authorize. */
    public function testTheConstructionGuards(): void
    {
        try {
            Fetch::createPcaFetchGuard(['audience' => 'a']);
            $this->fail('an unbound guard was built');
        } catch (\TypeError $e) {
            $this->assertSame('pca-fetch: `operation` is required: map each request to the operation it will execute so the proof is bound to it, '
                . 'or use `authorize`; set insecureAllowUnboundOperation only to migrate', $e->getMessage());
        }
        $this->assertInstanceOf(\Closure::class, Fetch::createPcaFetchGuard(['audience' => 'a', 'authorize' => new AuthorizeOptions()]));
        $this->assertInstanceOf(\Closure::class, Fetch::createPcaFetchGuard(['audience' => 'a', 'operation' => static fn() => null]));
        try {
            Fetch::createPcaFetchGuard(['audience' => 'a', 'signatureOnly' => true, 'authorize' => new AuthorizeOptions()]);
            $this->fail('signatureOnly with authorize was accepted');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signatureOnly and authorize are mutually exclusive', $e->getMessage());
        }
    }

    // ---- the clock -----------------------------------------------------------------------------------------------------

    /** `now` may be an int, a float or a callable; without it the wall clock in epoch milliseconds is used. */
    public function testTheClock(): void
    {
        [$grant, $p] = self::signed();
        foreach ([self::NOW, (float)self::NOW, static fn(): int => self::NOW] as $now) {
            $r = self::sigGuard($grant, ['now' => $now])(self::header($p));
            $this->assertSame([true, 200, 'allow'], [$r['ok'], $r['status'], $r['decision']]);
        }
        [$grant, $p] = self::signed([], null);
        $r = Fetch::createPcaFetchGuard(['audience' => self::AUD, 'resolveGrant' => static fn() => $grant, 'signatureOnly' => true])(self::header($p));
        $this->assertSame([true, 200], [$r['ok'], $r['status']], (string)($r['verdict']['reason'] ?? ''));
    }

    // ---- fresh_at and intent v2 context ----------------------------------------------------------------------------------

    /** A fresh_at policy object is applied (and never called); a throwing resolver (closure or array callable) refuses 403. */
    public function testTheFreshAtOption(): void
    {
        [$grant, $p] = self::signed();
        $r = self::sigGuard($grant, ['freshAt' => Obj::of(['require' => true])])(self::header($p));
        $this->assertSame([false, 403, self::FRESH_REQUIRED, false], [$r['ok'], $r['status'], $r['error'], $r['verdict']['checks']['fresh_at']]);
        // a side-carried header is read into a policy that names no token: unparseable, so a null token, never a missing one
        $r = self::sigGuard($grant, ['freshAt' => Obj::of([])])(self::header($p) + [Fetch::FRESH_AT_HEADER => 'not json']);
        $this->assertSame([false, 403, false], [$r['ok'], $r['status'], $r['verdict']['allow']]);
        $this->assertTrue(self::sigGuard($grant, ['freshAt' => Obj::of([])])(self::header($p))['ok'], 'no header, no requirement');
        $this->assertTrue(self::sigGuard($grant, ['freshAt' => 5])(self::header($p))['ok'], 'a value that is neither a policy nor callable is no policy');
        foreach ([[$this, 'throwingHook'], fn(Obj $x): mixed => $this->throwingHook($x)] as $hook) {
            $r = self::sigGuard($grant, ['freshAt' => $hook])(self::header($p));
            $this->assertSame([false, 403, 'fresh_at_context_error', 'deny', null], [$r['ok'], $r['status'], $r['error'], $r['decision'], $r['verdict']]);
            $this->assertInstanceOf(Obj::class, $r['pcactn']);
            $this->assertSame('PCA realm="pca", audience="aud", error="insufficient_authority", error_description="fresh_at verifier state unavailable (fail closed)"',
                $r['wwwAuthenticate']);
        }
    }

    /** An intent v2 state object is applied (and never called); a resolver's state is applied; a throwing resolver refuses 403. */
    public function testTheIntentV2Option(): void
    {
        [$grant, $p] = self::signed();
        $v2 = Obj::of(['policy' => Obj::of(['session' => Obj::of(['require' => true])])]);
        foreach ([$v2, static fn(): Obj => $v2] as $opt) {
            $r = self::sigGuard($grant, ['intentV2' => $opt])(self::header($p));
            $this->assertSame([false, 403], [$r['ok'], $r['status']]);
            $this->assertArrayHasKey('intent_session', $r['verdict']['checks']);
            $this->assertFalse($r['verdict']['checks']['intent_session']);
        }
        $this->assertTrue(self::sigGuard($grant, ['intentV2' => 5])(self::header($p))['ok'], 'a value that is neither state nor callable is none');
        $r = self::sigGuard($grant, ['intentV2' => fn(Obj $x): mixed => $this->throwingHook($x)])(self::header($p));
        $this->assertSame([false, 403, 'intent_v2_context_error', 'deny', null], [$r['ok'], $r['status'], $r['error'], $r['decision'], $r['verdict']]);
        $this->assertInstanceOf(Obj::class, $r['pcactn']);
        $this->assertSame('PCA realm="pca", audience="aud", error="insufficient_authority", error_description="intent v2 verifier state unavailable (fail closed)"',
            $r['wwwAuthenticate']);
    }

    // ---- signature only ---------------------------------------------------------------------------------------------------

    /** The grant-resolution refusals keep the presented PCActn and their own codes and challenges. */
    public function testTheGrantResolutionRefusals(): void
    {
        [$grant, $p] = self::signed();
        $r = self::sigGuard($grant, ['resolveGrant' => fn(string $ref): mixed => $this->throwingHook($ref)])(self::header($p));
        $this->assertSame([false, 403, 'resolve_grant_error'], [$r['ok'], $r['status'], $r['error']]);
        $this->assertSame($grant->get('id'), $r['pcactn']->get('grant_ref'));
        $this->assertSame('PCA realm="pca", audience="aud", error="insufficient_authority", error_description="grant resolution failed (fail closed)"', $r['wwwAuthenticate']);
        $r = self::sigGuard($grant, ['resolveGrant' => static fn(): mixed => null])(self::header($p));
        $this->assertSame([false, 401, 'unknown_grant'], [$r['ok'], $r['status'], $r['error']]);
        $this->assertSame($grant->get('id'), $r['pcactn']->get('grant_ref'));
        $this->assertSame('PCA realm="pca", audience="aud", error="unknown_grant", error_description="grant_ref does not resolve to a known grant"', $r['wwwAuthenticate']);
        $r = self::sigGuard($grant)([Fetch::PCA_HEADER => Pca::b64u('{"grant_ref":""}')]);
        $this->assertSame([false, 401, 'malformed', ''], [$r['ok'], $r['status'], $r['error'], $r['pcactn']->get('grant_ref')]);
    }

    /** A proof in the JSON body is verified as an object, with the plan-root check skipped as for the header. */
    public function testABodyProofAllows(): void
    {
        [$grant, $p] = self::signed();
        $r = self::sigGuard($grant)([], '{"pcactn":' . Json::canonicalizeStrict($p) . '}');
        $this->assertSame([true, 200, 'allow', null], [$r['ok'], $r['status'], $r['decision'], $r['error']]);
        $this->assertTrue($r['verdict']['allow']);
        $this->assertInstanceOf(Obj::class, $r['pcactn']);
    }

    /** A header proof is verified from its raw text (strict profile): an exponent number the lax decode accepts is a wire failure. */
    public function testAHeaderProofIsVerifiedFromItsRawText(): void
    {
        [$grant] = self::signed();
        $r = self::sigGuard($grant)([Fetch::PCA_HEADER => Pca::b64u('{"grant_ref":"g","x":1e2}')]);
        $this->assertSame([false, 403, 'wire: exponent form is not allowed'], [$r['ok'], $r['status'], $r['error']]);
    }

    /** A verified PCActn carrying a bond is still refused: the core never verifies a bond. */
    public function testABondIsRefusedAfterAnAllowingVerdict(): void
    {
        [$grant, $p] = self::signed(['bond_ref' => 'b1']);
        $r = self::sigGuard($grant)(self::header($p));
        $this->assertSame([false, 403, Authorize::BOND_UNSUPPORTED, 'deny'], [$r['ok'], $r['status'], $r['error'], $r['decision']]);
        $this->assertTrue($r['verdict']['allow']);
        $this->assertSame('b1', $r['pcactn']->get('bond_ref'));
        $this->assertSame('PCA realm="pca", audience="aud", error="insufficient_authority"', $r['wwwAuthenticate']);
    }

    /** A refusing verdict's own reason is the error; the challenge never echoes it. */
    public function testARefusingVerdictKeepsItsReason(): void
    {
        [$grant, $p] = self::signed();
        $r = self::sigGuard($grant, ['now' => self::NOW + 3_600_000])(self::header($p));
        $this->assertSame([false, 403, 'validity: the PCActn has expired', false], [$r['ok'], $r['status'], $r['error'], $r['verdict']['allow']]);
        $this->assertSame('PCA realm="pca", audience="aud", error="insufficient_authority"', $r['wwwAuthenticate']);
        $this->assertInstanceOf(Obj::class, $r['pcactn']);
    }

    // ---- the authorize path ------------------------------------------------------------------------------------------------

    private function fixture(): Obj
    {
        return Json::parseLax((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
    }

    private function escCase(Obj $fix): Obj
    {
        foreach ($fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                return $c;
            }
        }
        throw new \RuntimeException('fixture case missing');
    }

    /** @return array{0:string,1:string} [sk, pk b64u] */
    private static function principal(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca/escalation-guard-test', true));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function op(): array
    {
        return ['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])];
    }

    /** The authorize guard over the escalation fixture: the operation comes from the guard's own mapping (the options' one names none). */
    private function azGuard(Obj $fix, array $az = [], array $o = []): \Closure
    {
        $g = $this->escCase($fix)->get('grant');
        $now = $fix->get('now')->int();
        $op = self::op();
        return Fetch::createPcaFetchGuard($o + [
            'audience' => $fix->get('audience'), 'resolveGrant' => static fn(string $ref): ?Obj => $ref === $g->get('id') ? $g : null,
            'now' => static fn(): int => $now, 'operation' => static fn(): array => $op,
            'authorize' => new AuthorizeOptions(...($az + ['stateStore' => new MemoryStateStore(), 'plan' => 'single-step', 'isRevoked' => static fn(): bool => false,
                'operation' => static fn(): mixed => null, 'insecureUnboundApproval' => true])),
        ]);
    }

    private function escHeader(Obj $fix): array
    {
        return self::header($this->escCase($fix)->get('steps')[0]->get('pcactn'));
    }

    private function answerFor(Obj $esc, int $now): Obj
    {
        [$sk, $pk] = self::principal();
        $signed = Escalation::signAnswer(Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-escalation-answer', 'principal' => $pk,
            'policy_digest' => $esc->get('policy_digest'), 'action_digest' => $esc->get('action_digest'),
            'history_head' => $esc->get('history_head'), 'decision' => 'allow',
            'iat' => new Num((string)($now - 1000)), 'expires_at' => new Num((string)($now + 60000)),
            'nonce' => Pca::b64u(str_repeat("\x07", 16)),
        ]), $sk);
        $this->assertNotNull($signed);
        return $signed;
    }

    /**
     * Without a provenance bundle the call escalates (403, the pipeline's reason, verdict and request kept); the principal's answer in
     * the PCA-Escalation-Answer header admits it (200, the verdict and the answered-by record); an answer wrapped in a JSON string is no answer.
     */
    public function testAnEscalationAndItsAnsweredAllow(): void
    {
        $fix = $this->fixture();
        $riskCalls = 0;
        $risk = static function (mixed ...$a) use (&$riskCalls): array {
            $riskCalls++;
            return CalmRisk::inputs();
        };
        $guard = $this->azGuard($fix, ['escalationPrincipals' => [self::principal()[1]], 'risk' => $risk]);
        $h = $this->escHeader($fix);
        $r = $guard($h);
        $this->assertInstanceOf(AuthorizeResult::class, $r['authorization']);
        $this->assertSame([false, 403, 'escalate'], [$r['ok'], $r['status'], $r['decision']], implode('; ', $r['authorization']->reasons));
        $this->assertNotSame(self::OP_REFUSAL, $r['error']);
        $this->assertSame($r['authorization']->reason, $r['error']);
        $this->assertIsArray($r['verdict']);
        $this->assertSame($r['authorization']->verdict, $r['verdict']);
        $this->assertInstanceOf(Obj::class, $r['escalation']);
        $this->assertSame($r['authorization']->escalation, $r['escalation']);
        $this->assertInstanceOf(Obj::class, $r['pcactn']);
        $this->assertSame('PCA realm="pca", audience="payments-rs", error="insufficient_authority"', $r['wwwAuthenticate']);
        $this->assertGreaterThan(0, $riskCalls, 'the host risk source is handed to the pipeline');

        $answer = $this->answerFor($r['escalation'], $fix->get('now')->int());
        $text = Json::canonicalizeStrict($answer);
        // a JSON string holding the answer's text is not an answer object
        $w = $guard($h + ['PCA-Escalation-Answer' => Pca::b64u(Json::canonicalizeStrict($text))]);
        $this->assertSame([false, 403, 'escalate'], [$w['ok'], $w['status'], $w['decision']]);

        $a = $guard($h + ['PCA-Escalation-Answer' => Pca::b64u($text)]);
        $this->assertSame([true, 200, 'allow', null, null], [$a['ok'], $a['status'], $a['decision'], $a['error'], $a['wwwAuthenticate']],
            implode('; ', $a['authorization']->reasons));
        $this->assertIsArray($a['verdict']);
        $this->assertSame($a['authorization']->verdict, $a['verdict']);
        $this->assertInstanceOf(Obj::class, $a['escalation']);
        $this->assertSame(self::principal()[1], $a['escalation']->get('answered_by'));
        $this->assertInstanceOf(AuthorizedOperation::class, $a['authorization']->operation);
    }

    /** With an empty principal list no answer is read: a presented answer changes nothing. */
    public function testNoPrincipalsMeansNoAnswerIsRead(): void
    {
        $fix = $this->fixture();
        $guard = $this->azGuard($fix, ['escalationPrincipals' => []]);
        $h = $this->escHeader($fix);
        $plain = $guard($h);
        $this->assertSame('escalate', $plain['decision']);
        $answered = $this->azGuard($fix, ['escalationPrincipals' => []])($h + ['PCA-Escalation-Answer' => Pca::b64u('{"decision":"allow"}')]);
        $this->assertSame($plain['authorization']->reasons, $answered['authorization']->reasons);
        $this->assertSame('escalate', $answered['decision']);
    }

    /** The host's k1 closure is called with {headers, body} and the raw header text of the proof. */
    public function testTheK1ClosureSeesTheRequestAndTheRawText(): void
    {
        $fix = $this->fixture();
        $seen = [];
        $k1 = static function (mixed ...$a) use (&$seen): mixed {
            $seen = $a;
            return null;
        };
        $h = $this->escHeader($fix);
        $this->azGuard($fix, ['k1' => $k1])($h, 'the body');
        $this->assertCount(2, $seen);
        $this->assertInstanceOf(Obj::class, $seen[0]);
        $this->assertSame(['headers', 'body'], $seen[0]->keys());
        $this->assertSame($h, $seen[0]->get('headers'));
        $this->assertSame('the body', $seen[0]->get('body'));
        $this->assertSame(Json::canonicalizeStrict($this->escCase($fix)->get('steps')[0]->get('pcactn')), $seen[1]);
    }

    /** @var int calls of {@see recordK1} */
    private int $k1Calls = 0;

    public function recordK1(mixed ...$a): mixed
    {
        $this->k1Calls++;
        return null;
    }

    /**
     * Without a k1 option the presented caveat-language headers are never read (a broken PCA-Narrow block changes nothing), and only a
     * closure is called: an array callable is k1 data, not a resolver.
     */
    public function testK1IsOffWithoutTheOptionAndOnlyAClosureIsCalled(): void
    {
        $fix = $this->fixture();
        $h = $this->escHeader($fix);
        $plain = $this->azGuard($fix)($h);
        $narrowed = $this->azGuard($fix)($h + ['PCA-Narrow' => Pca::b64u('{}')]);
        $this->assertSame('escalate', $plain['decision']);
        $this->assertSame([$plain['decision'], $plain['authorization']->reasons], [$narrowed['decision'], $narrowed['authorization']->reasons]);
        $this->k1Calls = 0;
        $this->azGuard($fix, ['k1' => [$this, 'recordK1']])($h);
        $this->assertSame(0, $this->k1Calls);
    }

    /** The pipeline receives the RAW header text: an exponent number the guard's lax decode accepts is undecodable there (401). */
    public function testThePipelineGetsTheRawHeaderText(): void
    {
        $fix = $this->fixture();
        $r = $this->azGuard($fix)([Fetch::PCA_HEADER => Pca::b64u('{"grant_ref":"nope","x":1e2}')]);
        $this->assertSame([false, 401, 'undecodable PCActn: could not be decoded', 'deny'], [$r['ok'], $r['status'], $r['error'], $r['decision']]);
        $this->assertSame('PCA realm="pca", audience="payments-rs", error="invalid_pcactn"', $r['wwwAuthenticate']);
        $this->assertNull($r['escalation']);
    }

    // ---- the deny response ----------------------------------------------------------------------------------------------------

    /** From an authorize result: its checks and reasons, the first reason as the error, the decision and the escalation request. */
    public function testTheDenyResponseFromAnAuthorizeResult(): void
    {
        $az = new AuthorizeResult(false, 403, ['x' => 'fail'], ['r1', 'r2'], 'r1');
        $res = Fetch::denyResponse(['status' => 403, 'authorization' => $az, 'verdict' => null, 'error' => 'E', 'decision' => 'escalate',
            'escalation' => Obj::of(['k' => 'e']), 'wwwAuthenticate' => 'PCA realm="pca"']);
        $this->assertSame(['status' => 403, 'headers' => ['content-type' => 'application/json', 'WWW-Authenticate' => 'PCA realm="pca"'],
            'body' => '{"error":"r1","verdict":{"allow":false,"checks":{"x":"fail"},"reasons":["r1","r2"]},"decision":"escalate","escalation":{"k":"e"}}'], $res);
        $res = self::noWarnings(static fn(): array => Fetch::denyResponse(['status' => 401, 'authorization' => new AuthorizeResult(false, 401), 'verdict' => null,
            'escalation' => null, 'wwwAuthenticate' => null]));
        $this->assertSame(['status' => 401, 'headers' => ['content-type' => 'application/json'],
            'body' => '{"error":"forbidden","verdict":{"allow":false,"checks":{},"reasons":[]},"decision":"deny"}'], $res);
    }

    /** From a verdict array: reasons (or the single reason), allow and checks as given. */
    public function testTheDenyResponseFromAVerdict(): void
    {
        $base = ['status' => 403, 'authorization' => null, 'error' => 'E', 'escalation' => null, 'wwwAuthenticate' => ''];
        $body = static fn(array $v): string => Fetch::denyResponse(['verdict' => $v] + $base)['body'];
        $this->assertSame('{"error":"p","verdict":{"allow":true,"checks":{"a":true},"reasons":["p","q"]},"decision":"deny"}',
            $body(['allow' => true, 'checks' => ['a' => true], 'reasons' => ['p', 'q'], 'reason' => 'p']));
        $this->assertSame('{"error":"only","verdict":{"allow":false,"checks":{},"reasons":["only"]},"decision":"deny"}', $body(['reason' => 'only']));
        $this->assertSame('{"error":"forbidden","verdict":{"allow":false,"checks":{},"reasons":[]},"decision":"deny"}', $body(['reason' => '']));
        $this->assertSame(['content-type' => 'application/json'], Fetch::denyResponse(['verdict' => []] + $base)['headers']);
    }

    /** With neither: the error is the one reason; an empty error is none; a host denyBody replaces the body. */
    public function testTheDenyResponseFromTheErrorAlone(): void
    {
        $base = ['status' => 401, 'authorization' => null, 'verdict' => null, 'escalation' => null, 'wwwAuthenticate' => 'W'];
        $this->assertSame('{"error":"E","verdict":{"allow":false,"checks":{},"reasons":["E"]},"decision":"deny"}', Fetch::denyResponse(['error' => 'E'] + $base)['body']);
        $this->assertSame('{"error":"forbidden","verdict":{"allow":false,"checks":{},"reasons":[]},"decision":"deny"}', Fetch::denyResponse(['error' => ''] + $base)['body']);
        $res = Fetch::denyResponse(['error' => 'E'] + $base, static fn(array $r): Obj => Obj::of(['custom' => 'status ' . $r['status']]));
        $this->assertSame(['status' => 401, 'headers' => ['content-type' => 'application/json', 'WWW-Authenticate' => 'W'], 'body' => '{"custom":"status 401"}'], $res);
    }

    // ---- withPca -------------------------------------------------------------------------------------------------------------

    /** A signature-only allow hands the handler exactly {verdict, pcactn}; a refusal never runs it and answers the deny response. */
    public function testWithPcaSignatureOnly(): void
    {
        [$grant, $p] = self::signed();
        $calls = [];
        $handler = static function (mixed ...$a) use (&$calls): string {
            $calls[] = $a;
            return 'ran';
        };
        $wrapped = Fetch::withPca(['audience' => self::AUD, 'resolveGrant' => static fn() => $grant, 'now' => self::NOW, 'signatureOnly' => true], $handler);
        $req = Obj::of(['headers' => self::header($p)]);
        $this->assertSame('ran', self::noWarnings(static fn(): mixed => $wrapped($req)));
        $this->assertCount(1, $calls);
        $this->assertSame($req, $calls[0][0]);
        $this->assertSame(['pca'], array_keys($calls[0][1]));
        $this->assertSame(['verdict', 'pcactn'], array_keys($calls[0][1]['pca']));
        $this->assertTrue($calls[0][1]['pca']['verdict']['allow']);
        $this->assertSame($grant->get('id'), $calls[0][1]['pca']['pcactn']->get('grant_ref'));
        $res = $wrapped(Obj::of(['headers' => []]));
        $this->assertSame(401, $res['status']);
        $this->assertCount(1, $calls);
    }

    /** An authorize allow hands the handler the authorized operation too. */
    public function testWithPcaAuthorizeAddsTheOperation(): void
    {
        $fix = $this->fixture();
        $g = $this->escCase($fix)->get('grant');
        $now = $fix->get('now')->int();
        $op = self::op();
        $store = new MemoryStateStore();
        $o = ['audience' => $fix->get('audience'), 'resolveGrant' => static fn(string $ref): ?Obj => $ref === $g->get('id') ? $g : null,
            'now' => $now, 'operation' => static fn(): array => $op,
            'authorize' => new AuthorizeOptions(stateStore: $store, plan: 'single-step', isRevoked: static fn(): bool => false,
                escalationPrincipals: [self::principal()[1]], insecureUnboundApproval: true)];
        $h = $this->escHeader($fix);
        $esc = Fetch::createPcaFetchGuard($o)($h);
        $this->assertSame('escalate', $esc['decision']);
        $h['PCA-Escalation-Answer'] = Pca::b64u(Json::canonicalizeStrict($this->answerFor($esc['escalation'], $now)));
        $got = null;
        $wrapped = Fetch::withPca($o, static function (mixed $req, array $ctx) use (&$got): string {
            $got = $ctx;
            return 'ran';
        });
        $this->assertSame('ran', $wrapped(Obj::of(['headers' => $h])));
        $this->assertSame(['verdict', 'pcactn', 'operation'], array_keys($got['pca']));
        $this->assertInstanceOf(AuthorizedOperation::class, $got['pca']['operation']);
        $this->assertSame('payments.send', $got['pca']['operation']->verb);
    }
}
