<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PCA 0.4.1 (reference: packages/pca/src r041-*.test.ts, conformance-r041.test.ts):
 *  - threshold share signatures are validated per suite at the wire stage (`r041-share-*` vectors);
 *  - the policy-layer helpers policyCaveats / evaluateCaveats (root caveats outside the envelope are evaluated like
 *    delegated ones, incl. max_spend), corpus `primitives.caveat_eval`;
 *  - the PCA-Action header is strict unpadded base64url of strict UTF-8 (decodePcaHeader), corpus `primitives.pca_header`.
 */
final class R041Test extends TestCase
{
    private const SUPPORTED = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];

    // ---- caveat_eval ----------------------------------------------------------------------

    public function testCaveatEvalCorpus(): void
    {
        $cases = Corpus::core()->get('primitives')->get('caveat_eval');
        $this->assertGreaterThanOrEqual(40, count($cases));
        $by = [];
        $bad = [];
        foreach ($cases as $c) {
            $name = $c->get('name');
            $by[$name] = $c;
            $exp = $c->get('expect');
            try {
                $r = Pca::evaluateCaveats(Pca::policyCaveats($c->get('grant'), $c->get('chain')), $c->get('context'));
                if ($r['ok'] !== $exp->get('allow') || $r['failed'] !== $exp->get('failed')) {
                    $bad[] = "$name: got " . json_encode($r) . ' want ' . json_encode(['allow' => $exp->get('allow'), 'failed' => $exp->get('failed')]);
                }
            } catch (\Throwable $t) {
                $bad[] = "$name: THREW " . get_class($t) . ': ' . $t->getMessage();
            }
        }
        $this->assertSame(false, $by['r041-root-max-spend-exceeded']->get('expect')->get('allow'));
        $this->assertSame(true, $by['r041-root-max-spend-within']->get('expect')->get('allow'));
        $this->assertSame([], $bad, count($bad) . ' of ' . count($cases) . " caveat_eval cases failed:\n" . implode("\n", $bad));
    }

    private static function ctx(array $action, array $extra = []): Obj
    {
        return Obj::of(['now' => new Num('1800000000000'), 'action' => Obj::of($action)] + $extra);
    }

    public function testEvaluateCaveatsIsTotalAndFailsClosed(): void
    {
        $ctx = self::ctx(['params' => Obj::of(['amount' => new Num('5')])]);
        // a non-list caveat list
        $this->assertSame(['ok' => false, 'failed' => ['<malformed caveats>']], Pca::evaluateCaveats(null, $ctx));
        $this->assertSame(['ok' => false, 'failed' => ['<malformed caveats>']], Pca::evaluateCaveats(Obj::of([]), $ctx));
        $this->assertSame(['ok' => false, 'failed' => ['<malformed caveats>']], Pca::evaluateCaveats('x', $ctx));
        // an empty list is satisfied
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats([], $ctx));
        // non-object caveat, non-string type, unknown types
        $r = Pca::evaluateCaveats(['max_spend', [], Obj::of(['type' => new Num('1')]), Obj::of(['type' => 'note']), Obj::of(['type' => 'predicates'])], $ctx);
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>', '<malformed>', '<malformed>', 'note', 'predicates']], $r);
        // native PHP numbers are accepted as JSON numbers; bools are not numbers
        $ms = fn($usd) => Obj::of(['type' => 'max_spend', 'usd' => $usd]);
        $this->assertTrue(Pca::evaluateCaveats([$ms(5)], $ctx)['ok']);
        $this->assertTrue(Pca::evaluateCaveats([$ms(5.0)], $ctx)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([$ms(4.99)], $ctx)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([$ms(true)], $ctx)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([$ms(INF)], $ctx)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([$ms(new Num('1e999'))], $ctx)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([$ms(5)], self::ctx(['params' => Obj::of(['amount' => true])]))['ok']);
        // max_spend does not need `now`; every time-bound caveat does
        $noNow = Obj::of(['action' => Obj::of(['params' => Obj::of(['amount' => new Num('1')])])]);
        $this->assertTrue(Pca::evaluateCaveats([$ms(5)], $noNow)['ok']);
        $this->assertFalse(Pca::evaluateCaveats([Obj::of(['type' => 'budget_alloc', 'limit' => new Num('1')])], $noNow)['ok']);
        // a non-object context satisfies nothing
        $this->assertSame(['ok' => false, 'failed' => ['max_spend']], Pca::evaluateCaveats([$ms(5)], null));
        // max_spend reads the action's own params, never a top-level ctx.params
        $flat = Obj::of(['now' => new Num('1'), 'params' => Obj::of(['amount' => new Num('1')])]);
        $this->assertFalse(Pca::evaluateCaveats([$ms(5)], $flat)['ok']);
        // reversibility_max reads ctx.reversibility_class, not ctx.action.reversibility_class
        $rv = [Obj::of(['type' => 'reversibility_max', 'class' => 'irreversible'])];
        $this->assertFalse(Pca::evaluateCaveats($rv, self::ctx(['reversibility_class' => 'reversible']))['ok']);
        $this->assertTrue(Pca::evaluateCaveats($rv, self::ctx([], ['reversibility_class' => 'rate_limited']))['ok']);
        $this->assertFalse(Pca::evaluateCaveats($rv, self::ctx([], ['reversibility_class' => 'unknown']))['ok']);
    }

    public function testPolicyCaveatsShapes(): void
    {
        $env = Obj::of(['type' => 'envelope']);
        $a = Obj::of(['type' => 'max_spend', 'usd' => new Num('1')]);
        $b = Obj::of(['type' => 'expires', 'at' => new Num('2')]);
        $grant = Obj::of(['caveats' => [$a, $env, $env]]);
        // only the FIRST envelope is removed, order kept
        $this->assertSame([$a, $env], Pca::policyCaveats($grant, null));
        $this->assertSame([$a, $env], Pca::policyCaveats($grant, 'nope'));
        $this->assertSame([$a, $env], Pca::policyCaveats($grant, []));
        // the leaf's caveats beyond the grant's are appended
        $leaf = Obj::of(['caveats' => [$a, $env, $env, $b]]);
        $this->assertSame([$a, $env, $b], Pca::policyCaveats($grant, [$grant, $leaf]));
        $this->assertSame([$a, $env], Pca::policyCaveats($grant, [$grant, Obj::of(['caveats' => 'x'])]));
        $this->assertSame([$a, $env], Pca::policyCaveats($grant, [$grant, 'leaf']));
        // a grant without a caveat list hands its value through, and evaluateCaveats refuses it
        $this->assertNull(Pca::policyCaveats(Obj::of([]), [$leaf]));
        $this->assertSame('x', Pca::policyCaveats(Obj::of(['caveats' => 'x']), [$leaf]));
        $this->assertNull(Pca::policyCaveats('grant', [$leaf]));
        $this->assertSame(['<malformed caveats>'], Pca::evaluateCaveats(Pca::policyCaveats(Obj::of([]), [$leaf]), self::ctx([]))['failed']);
    }

    // ---- pca_header -----------------------------------------------------------------------

    public function testPcaHeaderCorpus(): void
    {
        $cases = Corpus::core()->get('primitives')->get('pca_header');
        $this->assertGreaterThanOrEqual(27, count($cases));
        $bad = [];
        foreach ($cases as $c) {
            $name = $c->get('name');
            try {
                $got = Pca::decodePcaHeader($c->get('input'));
                if (($got !== null) !== $c->get('valid')) {
                    $bad[] = "$name: valid = " . var_export($got !== null, true);
                } elseif ($got !== null && $got !== $c->get('text')) {
                    $bad[] = "$name: text " . json_encode($got);
                }
            } catch (\Throwable $t) {
                $bad[] = "$name: THREW " . get_class($t) . ': ' . $t->getMessage();
            }
        }
        $this->assertSame([], $bad, count($bad) . ' of ' . count($cases) . " pca_header cases failed:\n" . implode("\n", $bad));
    }

    public function testDecodePcaHeaderRejectsNonStrings(): void
    {
        $this->assertNull(Pca::decodePcaHeader(null));
        $this->assertNull(Pca::decodePcaHeader(123));
        $this->assertNull(Pca::decodePcaHeader(''));
        $this->assertSame('{}', Pca::decodePcaHeader('e30'));
    }

    /** The middleware answers 401 (its existing "not valid base64url" path) for every lenient spelling of a valid header. */
    public function testMiddlewareRefusesLenientHeaderSpellings(): void
    {
        $vector = null;
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') === 'valid-raw-json-format-insensitive') {
                $vector = $v;
            }
        }
        $this->assertNotNull($vector);
        $json = $vector->get('pcactn_json');
        $grant = $vector->get('grant');
        $ctx = $vector->get('context');
        $ref = Json::parseLax($json)->get('grant_ref');
        $canon = Pca::b64u($json);
        $lenient = array_values(array_unique(array_filter([
            $canon . str_repeat('=', (4 - strlen($canon) % 4) % 4),     // padded
            strtr($canon, '-_', '+/'),                                   // standard alphabet
            base64_encode($json),                                        // padded standard base64
        ], fn($h) => $h !== $canon)));
        $this->assertNotEmpty($lenient, 'the vector header has no lenient spelling to test');
        $f = new HttpFactory();
        $mw = new PcaMiddleware($ctx->get('aud'), fn(string $r): mixed => $r === $ref ? $grant : null, fn(): int => $ctx->get('now')->int(), $f, $f);
        $handler = new class implements RequestHandlerInterface {
            public bool $called = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                return new Response(200, [], 'ok');
            }
        };
        // the canonical spelling still verifies
        $this->assertSame(200, $mw->process(new ServerRequest('POST', '/r', [PcaMiddleware::HEADER => $canon]), $handler)->getStatusCode());
        foreach ($lenient as $h) {
            $handler->called = false;
            $resp = $mw->process(new ServerRequest('POST', '/r', [PcaMiddleware::HEADER => $h]), $handler);
            $this->assertSame(401, $resp->getStatusCode(), $h);
            $this->assertFalse($handler->called);
            $this->assertStringContainsString('not valid base64url', (string)$resp->getBody());
        }
    }

    // ---- per-suite share wire -------------------------------------------------------------

    public function testShareWireVectors(): void
    {
        $ran = 0;
        $bad = [];
        foreach (Corpus::core()->get('vectors') as $v) {
            $name = $v->get('name');
            if (!str_starts_with($name, 'r041-share-')) {
                continue;
            }
            $req = $v->has('requires') ? $v->get('requires') : null;
            if (is_string($req) && !in_array($req, self::SUPPORTED, true)) {
                continue; // a suite this verifier does not implement (ml-dsa-87, slh-dsa-sha2-128f)
            }
            $ran++;
            $got = Corpus::verifyCore($v);
            $exp = $v->get('expect');
            if ($got['allow'] !== $exp->get('allow')) {
                $bad[] = "$name: allow " . var_export($got['allow'], true) . " ({$got['reason']})";
            }
            foreach ($exp->get('checks')->keys() as $k) {
                if (($got['checks'][$k] ?? null) !== $exp->get('checks')->get($k)) {
                    $bad[] = "$name: check $k ({$got['reason']})";
                }
            }
        }
        $this->assertSame(18, $ran);
        $this->assertSame([], $bad, count($bad) . " of $ran r041-share vectors failed:\n" . implode("\n", $bad));
    }
}
