<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Gateway;
use Atlas\Pca\GatewayProvenanceLog;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Full-policy mode end to end: an allow (a read-only action, low server risk, no bundle needed), the session log write after it,
 * the deny codes, the k1 input built from the presented narrow block and the host's own k1, and the worker's narrow header.
 */
final class EdgeSurvivorKill9bGatewayTest extends TestCase
{
    private const AUD = 'https://api.example';
    private const NOW = 1700000000000;
    private const CAP = ['verb' => 'read', 'resource' => 'docs/1'];
    private const ALLOWED = 'proof-carrying action authorized (full policy)';

    private static ?Obj $grant = null;

    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/kill9b-gw-' . $label, true));
    }

    private static function grant(): Obj
    {
        return self::$grant ??= Sign::mintGrant(self::kp('principal'), self::kp('agent')->public,
            ['predicates' => [['verb' => 'read', 'resource' => 'docs/1']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()],
            'read the document', 'c2FsdA')['grant'];
    }

    /** A signed read of docs/1 whose params are the body {"a":1}; `$counter` keeps proofs apart for one state store. */
    private static function proof(int $counter = 1): Obj
    {
        $params = Json::parseStrict('{"a":1}');
        $node = ['id' => 'n1', 'verb' => 'read', 'resource' => 'docs/1', 'params_digest' => Pca::paramsDigest(Sign::n($params))];
        return Sign::buildPcactn(self::grant(), [self::grant()], [$node], 'n1', $counter, self::kp('agent'), self::AUD, $params,
            self::NOW - 1000, self::NOW + 60000);
    }

    /** A narrow block that adds an already expired caveat: presented, it makes the policy refuse. */
    private static function narrow(): Obj
    {
        return Sign::signNarrow(self::kp('agent'), Pca::capHash(self::grant()), [Obj::of(['type' => 'expires', 'at' => self::NOW - 1])],
            self::NOW - 1000, self::NOW + 60000);
    }

    /** Server risk that is low but not zero: a fresh full budget covers it, the deny-metered B = 0 does not. */
    private static function lowRisk(): \Closure
    {
        return static fn(mixed $g, mixed $params, mixed $pc): array => ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0.01,
            'taint' => 0, 'confidence' => 1, 'age' => 0];
    }

    /** Full-policy options that allow: not revoked, low risk, a read-only action (no bundle needed), the log as given. */
    private static function opts(array $policy = [], ?MemoryStateStore $state = null): array
    {
        $g = self::grant();
        return [
            'audience' => self::AUD,
            'routes' => [['method' => 'GET', 'path' => '/docs/*', 'capability' => self::CAP]],
            'resolveGrant' => static fn($ref, $p = null) => $ref === $g->get('id') ? $g : null,
            'insecureSkipPlanRootCheck' => true,
            'now' => static fn() => self::NOW,
            'bindRequest' => false,
            'policy' => array_merge(['mode' => 'full', 'params' => 'body', 'state' => $state ?? new MemoryStateStore(),
                'isRevoked' => static fn($p = null, $g = null) => false, 'risk' => self::lowRisk(), 'provenanceLog' => false,
                'provenance' => ['actions' => static fn($op = null) => ['effects' => ['read']]]], $policy),
        ];
    }

    private static function req(Obj $p, array $extraHeaders = []): array
    {
        return ['method' => 'GET', 'path' => '/docs/1', 'query' => '', 'headers' => array_merge(Sign::headers($p), $extraHeaders), 'body' => '{"a":1}'];
    }

    private static function why(array $d): string
    {
        $pv = $d['policyVerdict'] ?? null;
        return $d['reason'] . ' ' . ($pv instanceof Obj ? Json::canonicalizeNative($pv->get('checks')) : '');
    }

    /** The whole pipeline passes: the decision is an allow carrying an allowing policy verdict with its checks. */
    public function testFullPolicyAllow(): void
    {
        $d = Gateway::authorize(self::req(self::proof()), self::opts());
        $this->assertSame([true, 200, 'allow', self::ALLOWED], [$d['allow'], $d['status'], $d['code'], $d['reason']], self::why($d));
        $pv = $d['policyVerdict'];
        $this->assertSame(['allow', 'checks'], $pv->keys());
        $this->assertTrue($pv->get('allow'));
        $checks = $pv->get('checks');
        foreach (['revocation', 'replay', 'policy', 'operation', 'provenance_flow', 'plan_root_authorized'] as $c) {
            $this->assertSame('pass', $checks->get($c), $c);
        }
        $this->assertFalse($checks->has('principal'), 'a verified principal is not required by default');
    }

    /** After an allow, the session the call ran in has seen the tool's output; a deny writes nothing. */
    public function testAllowRecordsTheToolOutputInTheSessionLog(): void
    {
        $log = new GatewayProvenanceLog();
        $key = self::grant()->get('id') . "\n" . self::kp('agent')->public . "\n-";
        $d = Gateway::authorize(self::req(self::proof()), self::opts(['provenanceLog' => $log]));
        $this->assertTrue($d['allow'], self::why($d));
        $seen = $log->seen($key);
        $this->assertCount(1, $seen);
        $this->assertSame(['origin' => 'tool', 'source' => 'read'], [
            'origin' => $seen[0]->get('origin'), 'source' => $seen[0]->get('source')]);
        $this->assertSame(['origin', 'source'], $seen[0]->keys());

        $log = new GatewayProvenanceLog();
        $d = Gateway::authorize(self::req(self::proof()), self::opts(['provenanceLog' => $log, 'isRevoked' => static fn($p = null, $g = null) => true]));
        $this->assertFalse($d['allow']);
        $this->assertSame([], $log->seen($key));
    }

    /** A deny keeps the pipeline's reason and reports a refusing policy verdict beside the signature verdict. */
    public function testRevokedDenyReport(): void
    {
        $d = Gateway::authorize(self::req(self::proof()), self::opts(['isRevoked' => static fn($p = null, $g = null) => true]));
        $this->assertSame([false, 403, 'proof-rejected', 'revocation: the grant is revoked'], [$d['allow'], $d['status'], $d['code'], $d['reason']]);
        $this->assertTrue($d['verdict']['allow']);
        $this->assertInstanceOf(Obj::class, $d['pcactn']);
        $pv = $d['policyVerdict'];
        $this->assertSame(['allow', 'checks', 'reason'], $pv->keys());
        $this->assertSame([false, 'revocation: the grant is revoked', 'fail'], [$pv->get('allow'), $pv->get('reason'), $pv->get('checks')->get('revocation')]);
    }

    /** The same proof a second time is the pipeline's replay refusal: replayed-proof. */
    public function testReplayedProofCode(): void
    {
        $state = new MemoryStateStore();
        $p = self::proof();
        $first = Gateway::authorize(self::req($p), self::opts([], $state));
        $this->assertTrue($first['allow'], self::why($first));
        $d = Gateway::authorize(self::req($p), self::opts([], $state));
        $this->assertSame([false, 403, 'replayed-proof'], [$d['allow'], $d['status'], $d['code']]);
        $this->assertSame('fail', $d['policyVerdict']->get('checks')->get('replay'));
    }

    /** seedBudget defaults on (a fresh holder starts full); false is the deny-metered budget that cannot pay even a small risk. */
    public function testSeedBudgetOption(): void
    {
        $this->assertTrue(Gateway::authorize(self::req(self::proof()), self::opts(['seedBudget' => true]))['allow']);
        $d = Gateway::authorize(self::req(self::proof()), self::opts(['seedBudget' => false]));
        $this->assertSame([false, 'proof-rejected'], [$d['allow'], $d['code']]);
        $this->assertSame('fail', $d['policyVerdict']->get('checks')->get('threshold'));
    }

    /** The k1 input is the presented narrow block merged with the host's own k1 members; either one alone is enough to refuse. */
    public function testK1InputMergesPresentedArtifactsAndTheHostsOwn(): void
    {
        $n = self::narrow();
        $this->assertTrue(Gateway::authorize(self::req(self::proof()), self::opts(['k1' => new Obj()]))['allow'], 'no narrow block: allowed');
        $viaHeader = Gateway::authorize(self::req(self::proof(), Sign::headers(self::proof(), [], $n)), self::opts(['k1' => new Obj()]));
        $this->assertSame([false, 'proof-rejected'], [$viaHeader['allow'], $viaHeader['code']], 'the presented narrow block reaches the pipeline');
        $viaHost = Gateway::authorize(self::req(self::proof()), self::opts(['k1' => static fn($r, $p) => Obj::of(['narrow' => $n])]));
        $this->assertSame([false, 'proof-rejected'], [$viaHost['allow'], $viaHost['code']], "the host's own k1 members reach the pipeline");
        // without a k1 option the narrow block is not read at all
        $this->assertTrue(Gateway::authorize(self::req(self::proof(), Sign::headers(self::proof(), [], $n)), self::opts())['allow']);
    }

    /** The worker forwards a pca-narrow header to the gateway (and only a present one). */
    public function testCloudflareWorkerForwardsTheNarrowHeader(): void
    {
        $resps = [];
        $respond = static function (string $body, array $init) use (&$resps): string {
            $resps[] = $init['status'];
            return 'respond';
        };
        $next = static fn(mixed $r): string => 'next';
        $w = Gateway::cloudflareWorker(self::opts(['k1' => new Obj()]), $next, $respond);
        $plain = Sign::headers(self::proof());
        $this->assertSame('next', $w(['method' => 'GET', 'url' => '/docs/1', 'headers' => $plain, 'body' => '{"a":1}']));
        $w = Gateway::cloudflareWorker(self::opts(['k1' => new Obj()]), $next, $respond);
        $narrowed = Sign::headers(self::proof(), [], self::narrow());
        $this->assertSame('respond', $w(['method' => 'GET', 'url' => '/docs/1', 'headers' => $narrowed, 'body' => '{"a":1}']));
        $this->assertSame([403], $resps);
    }

    /** The host observer and the session log both feed the gate: a malformed observation from either refuses; a keyed list is read as a list. */
    public function testObservationSources(): void
    {
        $key = self::grant()->get('id') . "\n" . self::kp('agent')->public . "\n-";
        $bad = Obj::of(['origin' => 'nowhere', 'source' => 'x']);
        $good = Obj::of(['origin' => 'tool', 'source' => 'x']);
        $poisoned = static function () use ($key, $bad): GatewayProvenanceLog {
            $l = new GatewayProvenanceLog();
            $l->add($key, $bad);
            return $l;
        };
        $flow = static function (array $policy): ?string {
            $d = Gateway::authorize(self::req(self::proof()), self::opts($policy));
            return $d['policyVerdict']->get('checks')->get('provenance_flow');
        };
        $this->assertSame('pass', $flow(['provenanceLog' => new GatewayProvenanceLog()]));
        $this->assertSame('fail', $flow(['provenanceLog' => $poisoned()]), 'the log is read');
        $this->assertSame('pass', $flow(['provenance' => ['actions' => static fn($op = null) => ['effects' => ['read']], 'observed' => static fn(mixed ...$a) => null]]),
            'an observer with nothing to report');
        $this->assertSame('fail', $flow(['provenance' => ['actions' => static fn($op = null) => ['effects' => ['read']], 'observed' => static fn(mixed ...$a) => [$bad]]]),
            "the host's observer is read");
        $this->assertSame('pass', $flow(['provenance' => ['actions' => static fn($op = null) => ['effects' => ['read']], 'observed' => static fn(mixed ...$a) => ['k' => $good]]]),
            'keyed observations are taken as a list');
        $this->assertSame('fail', $flow(['provenanceLog' => $poisoned(),
            'provenance' => ['actions' => static fn($op = null) => ['effects' => ['read']], 'observed' => static fn(mixed ...$a) => [$good]]]), 'observer and log together');
    }
}
