<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\EvidenceVerify;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\TestCase;

/**
 * The evidence replay's verifier context under a re-signed session root: the `intent_session/ok` case with its session root re-signed
 * by the principal (seed 1) with other accumulators and monitors, G_0 and D_1 re-minted to bind its digest, D_1 delegated to the agent
 * (seed 2) as in the case, and the admitted PCActn P (params total 1000, seq 1) with its trip_budget reservation receipt (seed 7).
 * The replayed history before P is Z (offer OF-1, total 77800, committed). Also: a hybrid-suite root is judged as a grant lifted from the
 * artifact (the reader's PQ pins), never as the verifier's own stored grant.
 */
final class EvidenceVerifySurvivorKill2cTest extends TestCase
{
    private const WALK = 'verifyEvidenceBundle/walkthrough#0';
    private const OK = 'verifyEvidenceBundle/intent_session/ok#197';
    private const SESSION = 'SFWPjbv4MgR4wVQHWz7lyLpC9GDFIszx0MSXacPrlKc';
    private const SCHEMA = 'iKG4bC5fWDTv5K-QjgkQiNtBow7WsdMCUNL7ZhuBR5I';
    private const MAP1 = 'p2WUazMHIgVnfyc3cGsOE3y7N--9gay08gsyldznjRk';
    private const Z = 'zX3GA68C_FnIv17YbdKtLQd_R5btQKPCNc1X2e9_I5I';     // seq-1 PCActn at 1793534405000 (params total 77800)
    private const RMN9 = 'Rmn9oGf4jQzYfUWboIv68REtvgkOvbo6OUQV-tI8G2k';  // G_0 PCActn, no effect record (no params)
    private const IAT = 1793534405500;
    private const HYBRID = 'hybrid-ed25519-ml-dsa-65';

    private const TPL = [
        'shape' => 'The bundle is well formed (pca-intent-evidence v1, closed members)',
        'pcactn.verify' => 'The PCActn verifies (signature, chain, audience, validity at its issue time)',
        'pcactn.session' => "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
    ];

    /** @var array<string,string> */
    private static array $lines = [];

    // ---- shared helpers ------------------------------------------------------------------------------------------------------

    /** @return array{0:Obj,1:Obj} a fresh [bundle, trust]; `trust.verifiers` constants become ports returning them */
    private static function load(string $name): array
    {
        if (!isset(self::$lines[$name])) {
            $h = gzopen(__DIR__ . '/../test-data/ref-evidence-bundle-py.json.gz', 'rb');
            self::assertNotFalse($h);
            while (($l = gzgets($h)) !== false) {
                if (str_contains(substr($l, 0, 200), '"name":"' . $name . '"')) {
                    self::$lines[$name] = rtrim(rtrim($l, "\r\n"), ',');
                    break;
                }
            }
            gzclose($h);
            self::assertArrayHasKey($name, self::$lines, "case $name not found");
        }
        [$b, $t] = (new Parser(self::$lines[$name], PHP_INT_MAX))->run()->get('args');
        $v = $t->get('verifiers');
        if ($v instanceof Obj) {
            $ports = new Obj();
            foreach ($v->keys() as $k) {
                $verdict = $v->get($k);
                $ports->set($k, static fn($artifact, $bundle) => $verdict);
            }
            $t->set('verifiers', $ports);
        }
        return [$b, $t];
    }

    private static function j(string $json): mixed
    {
        return (new Parser($json, 64))->run();
    }

    private static function rt(mixed $v): mixed
    {
        return self::j(Json::canonicalizeNative($v));
    }

    private static function n(int|string $v): Num
    {
        return new Num((string)$v);
    }

    private static function seed(int $n): string
    {
        $s = '';
        for ($i = 0; $i < 32; $i++) {
            $s .= chr(($n * 31 + $i * 7 + 1) & 0xff);
        }
        return $s;
    }

    private static function copy(Obj $o, array $set = [], array $drop = []): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            if (!in_array($k, $drop, true)) {
                $c->set($k, $o->get($k));
            }
        }
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    private static function txt(string $code, string $status, ?string $detail = null): string
    {
        $s = ['pass' => 'verified', 'fail' => 'REFUTED', 'unverified' => 'not verified here'][$status];
        return self::TPL[$code] . ': ' . $s . ($detail !== null ? " ($detail)" : '') . '.';
    }

    /** @return list<array{0:string,1:string,2:array}> */
    private static function fs(Obj $r, string $code): array
    {
        $out = [];
        foreach ($r->get('findings') as $f) {
            if ($f->get('code') === $code) {
                $out[] = [$f->get('status'), $f->get('text'), $f->get('refs')];
            }
        }
        return $out;
    }

    private static function one(Obj $r, string $code, array $refs): string
    {
        $m = array_values(array_filter(self::fs($r, $code), static fn(array $x): bool => $x[2] === $refs));
        self::assertCount(1, $m, "$code " . implode(',', $refs) . ': ' . json_encode(self::fs($r, $code)));
        return $m[0][1];
    }

    private static function completed(Obj $r): void
    {
        self::assertSame([['pass', self::txt('shape', 'pass'), []]], self::fs($r, 'shape'));
    }

    private static function ev(string $acc, int $post, string $d, string $status = 'committed'): Obj
    {
        return Obj::of(['acc' => $acc, 'post' => self::n($post), 'pcactn_digest' => $d, 'status' => $status]);
    }


    // ---- the re-signed session root ------------------------------------------------------------------------------------------

    /** The caveats with the intent_session caveat bound to `$root` (and `$prev`), the envelope extended by `$envelope`. */
    private static function rebind(array $caveats, string $root, ?string $prev, array $envelope = []): array
    {
        return array_map(static fn(Obj $c): Obj => match ($c->get('type')) {
            'intent_session' => self::copy($c, $prev === null ? ['root' => $root] : ['root' => $root, 'prev' => $prev]),
            'envelope' => self::copy($c, $envelope),
            default => $c,
        }, $caveats);
    }

    /** An accumulator declaration like the case's trip_spend (sum of action.params.total over air.book, task window, site-local). */
    private static function acc(string $id, array $set = [], array $drop = []): Obj
    {
        $base = self::j('{"agg":"sum","val":"action.params.total","unit":"usd_cents","sel":{"verbs":["air.book"]},"win":{"kind":"task"},'
            . '"key":null,"holder":{"kind":"site_local"}}');
        return self::copy(self::copy($base, ['id' => $id]), $set, $drop);
    }

    private static function neverRebook(): Obj
    {
        return self::j('{"id":"no_rebook","kind":"never","p":{"verb":"air.book","resource":"*"}}');
    }

    /**
     * The case under a session root re-signed with `$accs` (null = the case's own, from which trip_budget is always taken) and
     * `$mons`; `$claims` are P's site-local claims [id => post] (trip_budget's receipt claim is added); `$envelope` extends D_1's
     * envelope. Events: Rmn9 (no params, skipped), Z's two, then one per claim of P.
     * @return array{0:Obj,1:Obj,2:Obj,3:string}
     */
    private static function resigned(?callable $accs, array $mons, array $claims, array $envelope = []): array
    {
        [$b, $t] = self::load(self::OK);
        $principal = new KeyPair(self::seed(1));
        $agent = new KeyPair(self::seed(2));
        $s = $b->get('session_root');
        $own = $s->get('accumulators');
        $budget = $own[1];
        self::assertSame('trip_budget', $budget->get('id'));
        $sNew = self::rt(SignersMore::signSessionRoot(self::copy($s, ['accumulators' => $accs === null ? $own : $accs($budget, $own[0]),
            'monitors' => $mons], ['signer', 'sig']), $principal));
        $sRef = IntentV2::sessionRootDigest($sNew);
        $g0 = $b->get('root_grant');
        $g0New = self::rt(Sign::mintRoot($principal, (string)$g0->get('holder'), self::rebind($g0->get('caveats'), $sRef, null)));
        $d1 = $b->get('deltas')[0];
        $d1New = self::rt(Sign::mintRoot($principal, (string)$d1->get('holder'), self::rebind($d1->get('caveats'), $sRef, (string)$g0New->get('id'), $envelope)));
        $chain = [$d1New, self::rt(Sign::delegate($d1New, $principal, $agent->public))];
        $b->set('session_root', $sNew);
        $b->set('root_grant', $g0New);
        $b->set('deltas', [$d1New]);

        $zEffect = $b->get('effects')[0];
        self::assertSame(self::Z, $zEffect->get('pcactn_digest'));
        $params = self::copy($zEffect->get('params'), ['total' => self::n(1000)]);
        $r0 = $b->get('accumulator')->get('receipts')[0];
        $intent = Obj::of(['ref' => $sNew->get('intent_ref'), 'map_digest' => self::MAP1, 'goal_salt' => 's',
            'fidelity_ppm' => self::n(900000), 'residual_risk_ppm' => self::n(1000)]);
        $mk = static fn(array $acc): Obj => self::rt(Sign::buildPcactn($d1New, $chain,
            [['id' => 'n1', 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'reversibility_class' => 'irreversible']], 'n1', 4,
            $agent, 'skyair.example', $params, iat: self::IAT, exp: 1793535000000,
            extra: ['intent' => $intent, 'intent_session' => Obj::of(['session' => self::SESSION, 'root' => $sRef, 'seq' => self::n(1),
                'schema' => self::SCHEMA, 'acc' => $acc])]));
        $receipt = self::rt(SignersMore::signAccReceipt(Obj::of(['v' => self::n(1), 'kind' => 'pca-acc-receipt', 'session' => self::SESSION,
            'acc' => 'trip_budget', 'seq' => self::n(2), 'pre' => self::n(77800), 'delta' => self::n(1000), 'post' => self::n(78800),
            'pcactn_digest' => IntentV2::pcactnReservationDigest($mk([])), 'aud' => 'skyair.example', 'issued_at' => self::n(self::IAT - 200),
            'expires_at' => self::n(self::IAT), 'kid' => 'k1',
            'ledger' => Obj::of(['index' => self::n(1), 'head' => $r0->get('ledger')->get('head')])]), new KeyPair(self::seed(7))));
        $acc = [Obj::of(['id' => 'trip_budget', 'post' => self::n(78800), 'receipt' => IntentV2::accReceiptDigest($receipt)])];
        foreach ($claims as $id => $post) {
            $acc[] = Obj::of(['id' => (string)$id, 'post' => self::n($post)]);
        }
        $p = $mk($acc);
        $d = Pca::hashCanonical($p);
        $b->set('pcactns', [...$b->get('pcactns'), $p]);
        $b->set('effects', [$zEffect, Obj::of(['pcactn_digest' => $d, 'params' => $params])]);
        $b->get('accumulator')->set('receipts', [$r0, $receipt]);
        $events = [self::ev('trip_budget', 0, self::RMN9), self::ev('trip_spend', 77800, self::Z), self::ev('trip_budget', 77800, self::Z),
            self::ev('trip_budget', 78800, $d)];
        foreach ($claims as $id => $post) {
            $events[] = self::ev((string)$id, $post, $d);
        }
        $b->get('accumulator')->set('events', $events);
        return [$b, $t, $p, $d];
    }

    private static function session(Obj $r, string $d): string
    {
        return self::one($r, 'pcactn.session', ["pcactn:$d"]);
    }

    /** Control: the case's own accumulators under the re-signed root admit P (the re-signing itself is sound). */
    public function testTheResignedSessionRootAdmitsTheSessionPcactn(): void
    {
        [$b, $t, , $d] = self::resigned(null, [], ['trip_spend' => 78800]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
    }

    /**
     * Sequenced accumulators come first and a keyed site-local one whose key the action lacks is skipped (it feeds air.cancel only),
     * and neither ends the site-local pre-states: trip_spend and the keyed offer_spend (keyed by offer_id, Z's OF-1 = P's) still get
     * theirs (77800 each), and every monitor gets its replayed state.
     */
    public function testEverySiteLocalAccumulatorAndMonitorGetsItsState(): void
    {
        $accs = static fn(Obj $budget, Obj $spend): array => [$budget,
            self::acc('cabin_spend', ['key' => 'action.params.cabin', 'sel' => self::j('{"verbs":["air.cancel"]}')]),
            $spend,
            self::acc('offer_spend', ['key' => 'action.params.offer_id'])];
        [$b, $t, , $d] = self::resigned($accs, [self::neverRebook()], ['trip_spend' => 78800, 'offer_spend' => 78800]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
    }

    /** A sum selected by accumulates_into reads the schema's verbs: Z (air.book total -> spend.usd_cents) is in the pre-state. */
    public function testAnAccumulatesIntoSelectorReadsTheSchemaVerbs(): void
    {
        $accs = static fn(Obj $budget, Obj $spend): array => [
            self::copy($spend, ['sel' => self::j('{"accumulates_into":"spend.usd_cents"}')], ['val']), $budget];
        [$b, $t, , $d] = self::resigned($accs, [], ['trip_spend' => 78800]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
    }

    /**
     * The history keeps each action's resource: the never monitor (air.book on any resource) has seen Z, so D_1's tighten rule on
     * env.mon.no_rebook.state = seen denies P (a v1 check, listed in pcactn.verify), while the accumulators still pass.
     */
    public function testTheMonitorSeesTheHistoryResource(): void
    {
        $tighten = ['tighten' => [self::j('{"id":"no_rebook","when":{"field":"env.mon.no_rebook.state","op":"eq","value":"seen"},"signal":"deny"}')]];
        [$b, $t, , $d] = self::resigned(null, [self::neverRebook()], ['trip_spend' => 78800], $tighten);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
        $this->assertMatchesRegularExpression('/: REFUTED \([^:]*\btighten\b[^:]*: /', self::one($r, 'pcactn.verify', ["pcactn:$d"]));
    }

    // ---- a hybrid-suite root lifted from the artifact ------------------------------------------------------------------------

    /** A PQ-suite root verifies only under the reader's pin for its issuer, never under its own pq_pk (the root is not a stored grant). */
    public function testAHybridRootNeedsTheReadersPin(): void
    {
        [$b, $t] = self::load(self::WALK);
        $g0id = $b->get('root_grant')->get('id');
        $src = null;
        foreach ($b->get('pcactns') as $p) {
            if ($p->get('cap_chain')[0]->get('id') === $g0id) {
                $src = $p;
            }
        }
        self::assertNotNull($src);
        $chain = $src->get('cap_chain');
        $chain[0] = self::copy($chain[0], ['alg' => self::HYBRID, 'pq_pk' => 'AAAA']);
        $x = self::copy($src, ['cap_chain' => $chain]);
        $b->set('pcactns', [...$b->get('pcactns'), $x]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertStringContainsString(sprintf(Pca::ROOT_PQ_PIN_REASON, self::HYBRID),
            self::one($r, 'pcactn.verify', ['pcactn:' . Pca::hashCanonical($x)]));
    }
}
