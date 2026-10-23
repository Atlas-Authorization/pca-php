<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Kills for IntentV2 pipeline-level survivors (non-object inputs, policy checks, primitive result shapes). */
final class IntentV2PipelineKillTest extends TestCase
{
    public function testNonObjectPcactnReportsNothing(): void
    {
        foreach ([null, 5, 'x', [1]] as $p) {
            $this->assertSame(['checks' => [], 'env' => null, 'schema' => null], IntentV2::decideIntentV2($p, null, new Obj(), 1));
            $this->assertFalse(IntentV2::intentV2Active($p, null));
            $this->assertFalse(IntentV2::intentV2Active($p, new Obj()));
        }
        $this->assertTrue(IntentV2::intentV2Active(Obj::of(['intent_session' => new Obj()]), null));
        $this->assertTrue(IntentV2::intentV2Active(new Obj(), Obj::of(['session' => 5])));
    }

    public function testMalformedContextMembersAreNamed(): void
    {
        $e = fn(array $ctx) => IntentV2::intentV2ContextError(Obj::of($ctx));
        $this->assertSame('session must be an object', $e(['session' => 5]));
        $this->assertSame('layers.org must be {predicates: [...]}', $e(['layers' => Obj::of(['org' => 5])]));
        $this->assertSame('layers.org must be {predicates: [...]}', $e(['layers' => Obj::of(['org' => Obj::of(['predicates' => 5])])]));
        // the per-step context checks (defence in depth behind intentV2ContextError)
        $priv = fn(string $n, mixed $ctx) => (new \ReflectionMethod(IntentV2::class, $n))->invoke(null, $ctx);
        $this->assertSame('the session context must be an object', $priv('sessionCtxError', Obj::of(['session' => 5])));
        $this->assertSame('the accumulator context must be an object', $priv('accCtxError', Obj::of(['acc' => 'x'])));
        $this->assertSame('the schema context must be {docs: [...], keys: [...]}', $priv('schemaCtxError', Obj::of(['schema' => 5])));
        $this->assertSame('the schema context must be {docs: [...], keys: [...]}', $priv('schemaCtxError', Obj::of(['schema' => Obj::of(['docs' => [], 'keys' => 5])])));
        $this->assertSame('the schema context must be {docs: [...], keys: [...]}', $priv('schemaCtxError', Obj::of(['schema' => Obj::of(['docs' => 5, 'keys' => []])])));
        $this->assertNull($priv('schemaCtxError', Obj::of(['schema' => Obj::of(['docs' => [], 'keys' => []])])));
    }

    public function testSessionPolicyMaxRevocationAgeIsChecked(): void
    {
        $m = new \ReflectionMethod(IntentV2::class, 'sessionStep');
        $mk = fn($v) => Obj::of(['policy' => Obj::of(['session' => Obj::of(['max_revocation_age_s' => $v])])]);
        $bad = 'session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)';
        foreach ([new Num('-1'), new Num('1.5'), 'x', null, true] as $v) {
            $this->assertSame(['ok' => false, 'reason' => $bad], $m->invoke(null, new Obj(), null, $mk($v), 1));
        }
        foreach ([new Num('0'), new Num('60')] as $v) {
            $this->assertSame('this verifier requires an intent_session but the PCActn carries none', $m->invoke(null, new Obj(), null, $mk($v), 1)['reason']);
        }
        $this->assertSame('this verifier requires an intent_session but the PCActn carries none', $m->invoke(null, new Obj(), null, new Obj(), 1)['reason']);
    }

    public function testSchemaPrimitiveReportsTheSignatureReasonFirst(): void
    {
        $in = Obj::of(['schema' => Obj::of(['v' => new Num('1')]), 'keys' => [], 'verb' => 'x.y', 'params' => 5]);
        [$out, $reason] = IntentV2::primitive('intent_schema', $in);
        $this->assertFalse($out->get('sig'));
        $this->assertFalse($out->get('conform')->get('ok'));
        $this->assertSame('params_not_object', $out->get('conform')->get('code'));
        $this->assertNotSame('params must be a JSON object', $reason);
        $this->assertStringStartsNotWith('params', (string) $reason);
    }

    public function testMapPrimitiveCellIsAListOfNumbers(): void
    {
        $prim = null;
        foreach (Corpus::core()->get('primitives')->get('intent_map') as $p) {
            if ($p->get('expect')->get('ok') === true) {
                $prim = $p;
                break;
            }
        }
        $this->assertNotNull($prim);
        [$out] = IntentV2::primitive('intent_map', $prim->get('input'));
        $this->assertTrue($out->get('ok'));
        foreach ($out->get('cell') as $c) {
            $this->assertInstanceOf(Num::class, $c);
        }
        $this->assertInstanceOf(Num::class, $out->get('p_ppm'));
        $this->assertSame(Json::canonicalizeStrict($prim->get('expect')->get('cell')), Json::canonicalizeStrict($out->get('cell')));
    }

    public function testCanonicalFifteenDigitBoundary(): void
    {
        // 15 significant digits are fine (leading zero and sign are not digits); 16 are refused
        $this->assertSame('0.123456789012345', IntentV2::canonicalize(0.123456789012345));
        $this->assertSame('-0.123456789012345', IntentV2::canonicalize(-0.123456789012345));
        $this->assertSame('-1.23456789012345', IntentV2::canonicalize(-1.23456789012345));
        $this->expectExceptionMessage('canonicalize: non-integer number has more than 15 significant digits');
        IntentV2::canonicalize(-0.1234567890123456);
    }
}
