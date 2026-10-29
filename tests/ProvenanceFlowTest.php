<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Sign;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Provenance by default in authorize (check `provenance_flow`): on without configuration, escalate for an unlabelled or
 * untrusted sensitive call, deny for a forged or unreadable bundle, the action facts, observation and envelope inputs, the only
 * opt-out (the grant envelope's signed `provenance: {mode: "insecure_off"}`), and the middleware's header / body reader.
 */
final class ProvenanceFlowTest extends TestCase
{
    private Obj $fix;
    private Obj $case;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->case = $c;
            }
        }
    }

    private function op(): Obj
    {
        return $this->case->get('steps')[0]->get('operation');
    }

    /** authorize over the signed fixture (a $50 payments.send under a $100 envelope) with these provenance arguments. */
    private function az(array $prov): AuthorizeResult
    {
        $s = $this->case->get('steps')[0];
        $g = $this->case->get('grant');
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $this->fix->get('audience'),
            fn ($ref) => $ref === $g->get('id') ? $g : null, new MemoryStateStore(), fn () => false, $this->fix->get('now')->int(), 'single-step',
            ...$prov);
    }

    public function testOnByDefaultAnUnlabelledSensitiveCallEscalates(): void
    {
        $r = $this->az([]);
        $this->assertSame([false, 'escalate', 'fail'], [$r->allow, $r->decision, $r->checks['provenance_flow']]);
        $this->assertSame('provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, currency derive '
            . 'from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)', $r->reason);
        $this->assertSame('payments.send', $r->escalation->get('verb'));
        $this->assertArrayNotHasKey('provenance', $r->checks, 'the Intent v2 rule 17 check name is not reused');
    }

    public function testAPrincipalDirectBundleUnderAPinnedMediatorPasses(): void
    {
        $r = $this->az(ProvHarness::args($this->op()));
        $this->assertSame([true, 'pass'], [$r->allow, $r->checks['provenance_flow']]);
        // the explicit bundle may also be its JSON text
        $text = Json::canonicalizeStrict(ProvHarness::bundle($this->op()));
        $this->assertTrue($this->az(['provenance' => $text, 'provenanceMediators' => [ProvHarness::pin()]])->allow);
        // a reader (called only without an explicit bundle)
        $this->assertTrue($this->az(['provenanceMediators' => [ProvHarness::pin()], 'provenanceBundle' => ProvHarness::reader()])->allow);
    }

    public function testAnUnpinnedMediatorVouchesForNothing(): void
    {
        $r = $this->az(['provenance' => ProvHarness::bundle($this->op())]);
        $this->assertSame(['escalate', 'fail'], [$r->decision, $r->checks['provenance_flow']]);
    }

    public function testAForgedBundleIsDenied(): void
    {
        $forged = ProvHarness::pin()->without();
        $forged->set('pk', (new KeyPair(str_repeat("\x0b", 32)))->public);
        $r = $this->az(['provenance' => ProvHarness::bundle($this->op()), 'provenanceMediators' => [$forged]]);
        $this->assertSame(['deny', 'fail'], [$r->decision, $r->checks['provenance_flow']]);
        $this->assertStringStartsWith('provenance_flow: bad_signature: ', (string)$r->reason);
        // a bundle for another operation is not this call's
        $other = ProvHarness::bundle(['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => ['amount' => 99, 'currency' => 'usd']]);
        $r = $this->az(['provenance' => $other, 'provenanceMediators' => [ProvHarness::pin()]]);
        $this->assertStringStartsWith('provenance_flow: unbound_action: ', (string)$r->reason);
        $this->assertSame('deny', $r->decision);
    }

    public function testUnreadableBundleAndFailingSourcesFailClosed(): void
    {
        $r = $this->az(['provenance' => '{not json', 'provenanceMediators' => [ProvHarness::pin()]]);
        $this->assertSame(['deny', 'provenance_flow: the provenance bundle is unreadable (fail closed)'], [$r->decision, $r->reason]);
        $r = $this->az(['provenanceMediators' => [ProvHarness::pin()], 'provenanceBundle' => static function (): never {
            throw new \RuntimeException('x');
        }]);
        $this->assertSame('provenance_flow: the provenance bundle is unreadable (fail closed)', $r->reason);
        $r = $this->az(ProvHarness::args($this->op()) + ['provenanceObserved' => static function (): never {
            throw new \RuntimeException('x');
        }]);
        $this->assertSame(['deny', 'provenance_flow: the observation source failed (fail closed)'], [$r->decision, $r->reason]);
        $r = $this->az(['provenance' => ProvHarness::bundle($this->op()), 'provenanceMediators' => 'not a list']);
        $this->assertStringStartsWith('provenance_flow: malformed_config: ', (string)$r->reason);
    }

    public function testActionFactsAndObservations(): void
    {
        // a read-only action needs no bundle
        $read = ['provenanceActions' => static fn (array $op): array => ['effects' => ['read']]];
        $this->assertSame('pass', $this->az($read)->checks['provenance_flow']);
        // a resolver that fails is an unknown action: sensitive
        $this->assertSame('escalate', $this->az(['provenanceActions' => static function (): never {
            throw new \RuntimeException('x');
        }])->decision);
        // a declared floor admits a tool-labelled parameter, and only that one
        $seen = null;
        $observed = static function (Obj $p, array $op, ?string $session) use (&$seen): array {
            $seen = $session;
            return [['origin' => 'tool', 'source' => 'crm']];
        };
        $bundle = ProvHarness::bundle($this->op());
        $r = $this->az(['provenance' => $bundle, 'provenanceMediators' => [ProvHarness::pin()], 'provenanceObserved' => $observed]);
        $this->assertSame($bundle->get('receipts')[0]->get('session'), $seen, 'the observation source gets the session');
        $this->assertSame('escalate', $r->decision);
        $this->assertStringContainsString('[tool:crm]', (string)$r->reason);
        // malformed facts deny
        $r = $this->az(ProvHarness::args($this->op()) + ['provenanceActions' => static fn (): array => ['effects' => 'read']]);
        $this->assertStringStartsWith('provenance_flow: malformed_action: ', (string)$r->reason);
    }

    public function testAProvenanceEscalationIsEscalateClass(): void
    {
        // `escalate:` is an escalate-class prefix: the existing principal-answer path can admit it; a deny code never is
        $r = $this->az([]);
        $this->assertSame('escalate', \Atlas\Pca\Decision::decisionOf(false, $r->checks, $r->reasons));
        $this->assertNotNull($r->escalation);
        $this->assertContains('provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, currency derive '
            . 'from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)', $r->escalation->get('reasons'));
    }

    // ---- the grant envelope: the only opt-out, and designated mediators ------------------------------------------------

    /** @return array{0: Obj, 1: Obj, 2: int} grant, PCActn, now */
    private static function minted(?array $provenance): array
    {
        $principal = new KeyPair(str_repeat("\x0c", 32));
        $key = new KeyPair(str_repeat("\x0d", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        if ($provenance !== null) {
            $env['provenance'] = $provenance;
        }
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order')['grant'];
        $p = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/1', ['amount_cents' => 500])->pcactn;
        return [$grant, $p, $p->get('iat')->int()];
    }

    private static function azMinted(array $m, array $prov): AuthorizeResult
    {
        [$grant, $p, $now] = $m;
        return Authorize::authorize($p, ['verb' => 'refund', 'resource' => 'orders/1', 'params' => Obj::of(['amount_cents' => 500])], 'rs-test',
            fn ($ref) => $grant, new MemoryStateStore(), fn () => false, $now, 'single-step', ...$prov);
    }

    public function testInsecureOffIsTheOnlyOptOut(): void
    {
        $off = self::azMinted(self::minted(['mode' => 'insecure_off']), []);
        $this->assertSame('not-enforced', $off->checks['provenance_flow']);
        $this->assertSame([], array_values(array_filter($off->reasons, static fn ($r) => str_starts_with((string)$r, 'provenance_flow'))));
        $this->assertSame('fail', self::azMinted(self::minted(null), [])->checks['provenance_flow']);
        $this->assertSame('fail', self::azMinted(self::minted(['mode' => 'enforce']), [])->checks['provenance_flow']);
        $bad = self::azMinted(self::minted(['mode' => 'off']), []);
        $this->assertSame('fail', $bad->checks['provenance_flow']);
        $this->assertContains("provenance_flow: the grant's provenance member is malformed: provenance.mode must be 'enforce' or 'insecure_off'", $bad->reasons);
    }

    public function testTheEnvelopeDesignatesMediators(): void
    {
        $op = ['verb' => 'refund', 'resource' => 'orders/1', 'params' => ['amount_cents' => 500]];
        $bundle = ProvHarness::bundle($op);
        $m = self::minted(['mediators' => [ProvHarness::pin()]]);
        $this->assertSame('pass', self::azMinted($m, ['provenance' => $bundle])->checks['provenance_flow']);
        $this->assertSame('fail', self::azMinted(self::minted(null), ['provenance' => $bundle])->checks['provenance_flow']);
    }

    // ---- the middleware reader: header PCA-Provenance, else body pca_provenance ----------------------------------------

    private function middleware(array $extra = []): PcaMiddleware
    {
        $f = new HttpFactory();
        $g = $this->case->get('grant');
        $opts = new AuthorizeOptions(...([
            'stateStore' => new MemoryStateStore(),
            'isRevoked' => fn () => false,
            'operation' => fn (ServerRequestInterface $r) => ['verb' => 'payments.send', 'resource' => 'payments/acme',
                'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])],
            'provenanceMediators' => [ProvHarness::pin()],
        ] + $extra));
        return new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $ref === $g->get('id') ? $g : null, fn () => $this->fix->get('now')->int(),
            $f, $f, authorize: $opts);
    }

    private function request(): ServerRequestInterface
    {
        $p = $this->case->get('steps')[0]->get('pcactn');
        return new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]);
    }

    private static function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(200, [], 'ok');
            }
        };
    }

    public function testMiddlewareReadsTheHeaderThenTheBody(): void
    {
        $b = Json::canonicalizeStrict(ProvHarness::bundle($this->op()));
        $h = self::handler();
        $res = $this->middleware()->process($this->request()->withHeader('PCA-Provenance', Pca::b64u($b)), $h);
        $this->assertSame([200, 1], [$res->getStatusCode(), $h->calls]);
        $res = $this->middleware()->process($this->request()->withBody(Utils::streamFor('{"amount":50,"currency":"usd","pca_provenance":' . $b . '}')), $h);
        $this->assertSame([200, 2], [$res->getStatusCode(), $h->calls]);
        $res = $this->middleware()->process($this->request(), $h);
        $body = json_decode((string)$res->getBody(), true);
        $this->assertSame([403, 'escalate', 'fail'], [$res->getStatusCode(), $body['decision'], $body['checks']['provenance_flow']]);
        $res = $this->middleware()->process($this->request()->withHeader('PCA-Provenance', '!!'), $h);
        $body = json_decode((string)$res->getBody(), true);
        $this->assertSame([403, 'deny'], [$res->getStatusCode(), $body['decision']]);
        $this->assertSame(2, $h->calls);
        // a configured reader replaces the default one
        $res = $this->middleware(['provenanceBundle' => static fn (ServerRequestInterface $r, Obj $p, array $op): ?Obj => ProvHarness::bundle($op)])
            ->process($this->request(), $h);
        $this->assertSame([200, 3], [$res->getStatusCode(), $h->calls]);
    }
}
