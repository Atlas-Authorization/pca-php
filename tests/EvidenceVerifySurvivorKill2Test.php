<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\EvidenceVerify;
use Atlas\Pca\IntentStatement;
use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\Wallet;
use PHPUnit\Framework\TestCase;

/**
 * The evidence replay (`verifyEvidenceBundle`) on variants of the reference's chargeback walkthrough (test-data/
 * ref-evidence-bundle-py.json.gz): refusals that must stay refusals with their exact reason, the boundaries of the replayed
 * arithmetic, the anchors, the attribution keys and the port semantics. Re-signed artifacts use the generator's deterministic
 * Ed25519 seeds (byte i of seed n = (31n + 7i + 1) mod 256): 1 the principal, 3 the site, 4 the revocation authority, 9 a stranger.
 */
final class EvidenceVerifySurvivorKill2Test extends TestCase
{
    private const WALK = 'verifyEvidenceBundle/walkthrough#0';
    private const WB = 'verifyEvidenceBundle/wb/pinned#107';
    private const CLAIM = 'verifyEvidenceBundle/intent_session/acc claim#198';
    private const A2 = 'A2Dt8aB8KSXfA_eN9I5UX20S9k52oJV7040ICS4aBP4';  // seed 1, the session principal
    private const V1 = 'v1MLIjjGK18q8Pf9kxUyDygX9wv9Txsp4PXZa2jUIMM';  // seed 2, the agent
    private const K6 = '6zI6i55B9EQsF8Rgy7bzsoszzbdXpFf9wDxFfYUC4As';  // seed 6, the sequencer root
    private const K9 = 'JlCcxk5_0X18r2aHj2MS1Re3g9Kns8l-RQ46E-gnQh0';  // seed 9, not a principal
    private const SUBJ = 'zX3GA68C_FnIv17YbdKtLQd_R5btQKPCNc1X2e9_I5I';
    private const RMN9 = 'Rmn9oGf4jQzYfUWboIv68REtvgkOvbo6OUQV-tI8G2k';  // the walkthrough's PCActn rooted at G_0
    private const D3 = 'u0EnSMmk2zXrpcBN0Yev1nWhnuCq8ApKC1goaCwLJTg';   // the intent_session PCActn of the acc-claim case
    private const SROOT_REF = 'dZjVh14qZ8gmlSEbkGhJtO499UsAd8PUzxOf0ZoDwX8';

    private const TPL = [
        'shape' => 'The bundle is well formed (pca-intent-evidence v1, closed members)',
        'principal.pinned' => 'Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)',
        'trust.acc' => 'The verifier freshness configuration (trust.acc) is well formed',
        'statement.opening' => 'The opened statement is signed by a principal and hashes to the committed ref',
        'session_root.signature' => 'The session root is signed by one of its principal keys',
        'schema.signature' => 'The action schema is signed by a site key',
        'map.replay' => 'The task map replays to its committed digest',
        'root_grant' => 'The root intent grant G_0 is principal-signed and bound to the session',
        'delta.signature' => 'The delta grant is a root capability signed by a principal of the session',
        'delta.chain' => 'The delta grant chains to the session (session, seq, prev, root)',
        'answer.device' => 'The device-tier WebAuthn assertion verifies with user verification',
        'jit.consent' => 'The irreversible subject action carries a principal JIT consent bound to its exact action digest',
        'accumulator.arithmetic' => 'The accumulator posts are the running values of the counted events',
        'accumulator.cap' => "Every accumulator post is within the admitting grant's cap",
        'accumulator.receipts' => 'The sequencer reservation receipt verifies and is consistent',
        'acc.keysets' => "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        'effect.binding' => "The effect record is bound to the PCActn's signed params",
        'effect.charged' => 'The charged amount is within the confirmed value',
        'effect.frame' => 'No monitored state outside the write set changed',
        'effect.signature' => 'The effect record is signed by the site',
        'verdict.signature' => 'The site verdict record verifies',
        'fact.signature' => 'The oracle fact verifies under a pinned oracle key',
        'classifier.signature' => 'The classifier verdict verifies under a pinned judge key',
        'offer_set.signature' => 'The offer set is signed by a site key, for this session',
        'labels.signature' => 'The label receipt is signed by a pinned site key, for this session',
        'settlement.signature' => 'The settlement record verifies',
        'revocation.history' => 'The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)',
        'revocation.epoch' => 'A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time',
        'anchor.inclusion' => 'The anchored artifact is included under a guardian-signed head of the intent log',
    ];

    /** @var array<string,string> */
    private static array $lines = [];

    // ---- fixtures ------------------------------------------------------------------------------------------------------------

    /** @return array{0:Obj,1:Obj} a fresh [bundle, trust] of a corpus case; `trust.verifiers` constants become ports returning them */
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

    /** The parsed-JSON form of a PHP-built value (numbers become Num, as in a bundle read from the wire). */
    private static function rt(mixed $v): mixed
    {
        return self::j(Json::canonicalizeNative($v));
    }

    private static function n(string $lexeme): Num
    {
        return new Num($lexeme);
    }

    private static function seed(int $n): string
    {
        $s = '';
        for ($i = 0; $i < 32; $i++) {
            $s .= chr(($n * 31 + $i * 7 + 1) & 0xff);
        }
        return $s;
    }

    private static function sk(int $n): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed($n)));
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

    private static function answerOf(Obj $b, string $qid): Obj
    {
        foreach ($b->get('answers') as $a) {
            if ($a->get('question_id') === $qid) {
                return $a;
            }
        }
        throw new \RuntimeException("no answer $qid");
    }

    /** A principal-signed (seed 1) answer derived from `$tpl`. */
    private static function answer(Obj $tpl, array $set, array $uxSet = [], array $uxDrop = []): Obj
    {
        $a = self::copy($tpl, $set, ['sig']);
        $a->set('ux', self::copy($tpl->get('ux'), $uxSet, $uxDrop));
        return self::rt(Wallet::signIntentAnswer($a, self::seed(1)));
    }

    /** A device-tier yes answer with a WebAuthn assertion (Ed25519 credential, seed 20) over its device challenge. */
    private static function deviceAnswer(Obj $tpl, string $qid, string $observedAt, bool $uv): Obj
    {
        $ch = Wallet::deviceChallenge($qid, $tpl->get('ux')->get('rendered_digest'), self::n('1'), null);
        $ad = hash('sha256', 'skyair.example', true) . chr($uv ? 0x05 : 0x01) . pack('N', 0);
        $cd = '{"type":"webauthn.get","challenge":"' . $ch . '","origin":"https://skyair.example"}';
        $sig = sodium_crypto_sign_detached($ad . hash('sha256', $cd, true), self::sk(20));
        $wa = Obj::of(['credential_id' => 'c1', 'authenticator_data' => Pca::b64u($ad), 'client_data_json' => Pca::b64u($cd), 'signature' => Pca::b64u($sig)]);
        return self::answer($tpl, ['question_id' => $qid, 'observed_at' => self::n($observedAt)], ['tier' => 'device', 'webauthn' => $wa],
            ['typed_digest', 'action_digest', 'consent_for_action']);
    }

    private static function credentials(): Obj
    {
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed(20)));
        return Obj::of(['c1' => Obj::of(['publicKey' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u($pk)]),
            'rpId' => 'skyair.example', 'origins' => ['https://skyair.example']])]);
    }

    /** A root grant minted by seed `$seed` over the given caveats. */
    private static function grant(int $seed, string $holder, array $caveats): Obj
    {
        return self::rt(Sign::mintRoot(new KeyPair(self::seed($seed)), $holder, $caveats));
    }

    // ---- findings ------------------------------------------------------------------------------------------------------------

    private static function txt(string $code, string $status, ?string $detail = null): string
    {
        $s = ['pass' => 'verified', 'fail' => 'REFUTED', 'unverified' => 'not verified here'][$status];
        return self::TPL[$code] . ': ' . $s . ($detail !== null ? " ($detail)" : '') . '.';
    }

    /** @return list<array{0:string,1:string,2:array}> [status, text, refs] of the findings with this code */
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

    /** @return list<string> */
    private static function texts(Obj $r, string $code): array
    {
        return array_map(static fn(array $x): string => $x[1], self::fs($r, $code));
    }

    /** The text of the single finding with this code and exactly these refs. */
    private static function one(Obj $r, string $code, array $refs): string
    {
        $m = array_values(array_filter(self::fs($r, $code), static fn(array $x): bool => $x[2] === $refs));
        self::assertCount(1, $m, "$code " . implode(',', $refs) . ': ' . json_encode(self::fs($r, $code)));
        return $m[0][1];
    }

    /** The replay ran to its end (no `shape` refutation). */
    private static function completed(Obj $r): void
    {
        self::assertSame([['pass', self::txt('shape', 'pass'), []]], self::fs($r, 'shape'));
    }

    private static function aborted(Obj $r, string $why): void
    {
        self::assertContains(self::txt('shape', 'fail', 'replay aborted: ' . $why), self::texts($r, 'shape'));
    }

    // ---- trust argument and the pre-replay refusals --------------------------------------------------------------------------

    /** A non-object trust is a caller error (TypeError), not a report. */
    public function testANonObjectTrustIsATypeError(): void
    {
        [$b] = self::load(self::WALK);
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('trust must be an object');
        EvidenceVerify::verifyEvidenceBundle($b, 'x');
    }

    /** An associative PHP array is accepted as the trust object (its members are validated like an Obj's). */
    public function testAnAssocArrayTrustIsReadAsAnObject(): void
    {
        [$b] = self::load(self::WALK);
        $r = EvidenceVerify::verifyEvidenceBundle($b, ['acc' => 'x']);
        $this->assertSame([['fail', self::txt('trust.acc', 'fail', 'trust.acc must be an object'), []]], self::fs($r, 'trust.acc'));
        $this->assertCount(1, $r->get('findings'));
    }

    /** A bundle that passes the shape check but cannot be put in normal form is one failed shape finding with the error. */
    public function testANonCanonicalizableBundleIsOneShapeRefutation(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->set('deltas', [new Obj(), new Obj()]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        $this->assertSame([['fail', self::txt('shape', 'fail', 'not canonicalizable: find is not a function'), []]], self::fs($r, 'shape'));
        $this->assertCount(1, $r->get('findings'));
        $this->assertFalse($r->get('ok'));
    }

    // ---- faults inside the replay fail closed with the error -----------------------------------------------------------------

    public function testANonListAccumulatorDeclarationAbortsTheReplay(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->get('session_root')->set('accumulators', 'x');
        self::aborted(EvidenceVerify::verifyEvidenceBundle($b, $t), 'not a list');
    }

    /** A sequencer holder root that is not a string is refused where it is read (no silent key coercion). */
    public function testANumericSequencerRootAbortsTheReplay(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->get('session_root')->get('accumulators')[1]->get('holder')->set('root', self::n('5'));
        self::aborted(EvidenceVerify::verifyEvidenceBundle($b, $t), 'Object of class Atlas\Pca\Num could not be converted to string');
    }

    public function testANumericAccumulatorIdAbortsTheReplay(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->get('session_root')->get('accumulators')[0]->set('id', self::n('5'));
        self::aborted(EvidenceVerify::verifyEvidenceBundle($b, $t), 'Object of class Atlas\Pca\Num could not be converted to string');
    }

    /** An epoch issue time that is not a number aborts the replay where the epoch in force is chosen. */
    public function testANonNumericEpochIssueTimeAbortsTheReplay(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->set('revocation_epochs', [Obj::of(['epoch' => Obj::of(['issued_at' => 'x']), 'revoked' => []])]);
        self::aborted(EvidenceVerify::verifyEvidenceBundle($b, $t), 'not a number');
    }

    /** A signed `intent_session.acc` that is not an array aborts the replay (the reference's not-iterable error). */
    public function testANonArrayIntentSessionClaimListAbortsTheReplay(): void
    {
        [$b, $t] = self::load(self::CLAIM);
        foreach ($b->get('pcactns') as $p) {
            if ($p->has('intent_session')) {
                $p->get('intent_session')->set('acc', new Obj());
            }
        }
        self::aborted(EvidenceVerify::verifyEvidenceBundle($b, $t), 'is_.acc is not iterable');
    }

    // ---- ports ---------------------------------------------------------------------------------------------------------------

    /** The suite's own loop guard ("test deadline of ...") thrown by a port ends the call; it never becomes a finding. */
    public function testATestDeadlineThrownByAPortPropagates(): void
    {
        [$b, $t] = self::load(self::WALK);
        $t->get('verifiers')->set('effect', static fn($a, $x) => throw new \RuntimeException('test deadline of 9 s exceeded'));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('test deadline of 9 s exceeded');
        EvidenceVerify::verifyEvidenceBundle($b, $t);
    }

    /**
     * Any other throw of a port is a refutation carrying the message (a RuntimeException, a LogicException, even one whose text
     * merely contains the guard words); a port of `false` is "no port" (the core default, here none: unverified); a non-callable
     * truthy port is a refutation. Also: a session root without a revocation authority, a G_0 signed by a non-principal, a delta
     * with two intent_session caveats, and key sets ordered by (issued_at, version) with an absent number counted as 0.
     */
    public function testPortsThrowsAndRefusals(): void
    {
        [$b, $t] = self::load(self::WALK);
        $ports = $t->get('verifiers');
        $ports->set('sessionRoot', static fn($a, $x) => throw new \RuntimeException('boom'));
        $ports->set('effect', static fn($a, $x) => throw new \LogicException('bang'));
        $ports->set('receipt', static fn($a, $x) => throw new \LogicException('test deadline of 1 s'));
        $ports->set('schema', static fn($a, $x) => throw new \RuntimeException('xtest deadline of 2'));
        $ports->set('settlement', false);
        $ports->set('verdict', true);
        $b->set('verdicts', [Obj::of(['pcactn_digest' => 'v1'])]);
        $b->set('settlements', [new Obj()]);
        $b->set('session_root', $b->get('session_root')->without('revocation'));
        $g0 = $b->get('root_grant');
        $b->set('root_grant', self::grant(9, self::K9, $g0->get('caveats')));
        $d1 = $b->get('deltas')[0];
        [$env, $is] = $d1->get('caveats');
        $b->set('deltas', [self::grant(1, self::A2, [$env, $is, $is])]);
        $real = $b->get('accumulator')->get('sequencer_keys')[0];
        $b->get('accumulator')->set('sequencer_keys', [
            Obj::of(['sequencer' => 'nope']),
            Obj::of(['sequencer' => 'nope', 'issued_at' => self::n('1'), 'version' => self::n('0')]),
            self::copy($real, ['issued_at' => self::n('1793534399000')]),
            $real,
        ]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('session_root.signature', 'fail', 'verifier threw: boom'), self::one($r, 'session_root.signature', ['session_root']));
        $this->assertSame([self::txt('effect.signature', 'fail', 'verifier threw: bang')], self::texts($r, 'effect.signature'));
        $this->assertSame([self::txt('accumulator.receipts', 'fail', 'verifier threw: test deadline of 1 s')], self::texts($r, 'accumulator.receipts'));
        $this->assertSame(self::txt('schema.signature', 'fail', 'verifier threw: xtest deadline of 2'), self::one($r, 'schema.signature', ['schema']));
        $this->assertSame(self::txt('settlement.signature', 'unverified', 'no verifier for settlement records (no core format yet)'), self::one($r, 'settlement.signature', ['settlement:0']));
        $this->assertSame(self::txt('verdict.signature', 'fail', 'verifier threw: the verifier is not callable'), self::one($r, 'verdict.signature', ['verdict:v1']));
        $this->assertSame([['fail', self::txt('revocation.epoch', 'fail', 'the session root names no revocation authority'), []]], self::fs($r, 'revocation.epoch'));
        $this->assertSame(self::txt('root_grant', 'fail', 'not signed by a principal of the session'), self::one($r, 'root_grant', ['G_0']));
        $this->assertSame(self::txt('delta.chain', 'fail', 'no single intent_session caveat'), self::one($r, 'delta.chain', ['D_1']));
        $unpinned = self::txt('acc.keysets', 'fail', 'not signed by a sequencer root the session root pins');
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#0:undefined']));
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#1:0']));
        $this->assertSame(self::txt('acc.keysets', 'fail', 'the key set does not verify under its pinned root'), self::one($r, 'acc.keysets', ['keyset#2:1']));
        $this->assertSame(self::txt('acc.keysets', 'pass'), self::one($r, 'acc.keysets', ['keyset#3:1']));
    }

    // ---- statement, attribution, revocation freshness, the accumulator value rule --------------------------------------------

    /**
     * A valid opening signed by a non-principal is refuted; attribution names EVERY signing key (the session root's signer and the
     * opening's principal included) and skips non-string signers; the revocation epoch in force is the last one issued AT OR BEFORE
     * the action (an epoch issued at the action time decides, an older stale one does not); a delta bound to another root is refused
     * as such; the accumulator value is read through the schema (accumulates_into) and `count` adds exactly one; an event on an
     * undeclared accumulator does not end the event loop.
     */
    public function testStatementAttributionRevocationAndValueRule(): void
    {
        [$b, $t] = self::load(self::WALK);
        $op = $b->get('statement')->get('opening');
        $opening = self::rt(IntentStatement::signIntent(self::copy($op, [], ['principal', 'sig']), self::seed(9)));
        $b->get('statement')->set('opening', $opening);
        $b->get('statement')->set('commit', IntentStatement::intentRef($opening));
        $sr = $b->get('session_root');
        $sr->set('signer', self::K6);
        $sr->get('revocation')->set('max_age_s', self::n('0.4'));
        $ep0 = $b->get('revocation_epochs')[0];
        $e = self::copy($ep0->get('epoch'), ['issued_at' => self::n('1793534405000'), 'not_after' => self::n('1793534705000')]);
        $body = new Obj();
        foreach (['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'] as $k) {
            $body->set($k, $e->get($k));
        }
        $e->set('sig', Pca::b64u(sodium_crypto_sign_detached(IntentV2::REVEPOCH_DOMAIN . IntentV2::canonicalize($body), self::sk(4))));
        $b->set('revocation_epochs', [$ep0, Obj::of(['epoch' => $e, 'revoked' => $ep0->get('revoked')])]);
        $b->set('answers', [...$b->get('answers'), Obj::of(['question_id' => 'q_bad'])]);
        [$spend, $budget] = $sr->get('accumulators');
        $spend2 = self::copy($spend, ['sel' => self::j('{"verbs": ["air.book"], "accumulates_into": "spend.usd_cents"}')], ['val']);
        $budget2 = self::copy($budget, ['agg' => 'count', 'holder' => self::copy($budget->get('holder'), ['root' => true])]);
        $sr->set('accumulators', [$spend2, $budget2]);
        $b->get('accumulator')->set('events', self::j('[{"acc": "nope", "post": 0, "pcactn_digest": "' . self::SUBJ . '", "status": "committed"},'
            . ' {"acc": "trip_spend", "post": 77800, "pcactn_digest": "' . self::SUBJ . '", "delta": 1, "status": "committed"},'
            . ' {"acc": "trip_budget", "post": 1, "pcactn_digest": "' . self::SUBJ . '", "status": "committed"}]'));
        [$env, $is] = $b->get('deltas')[0]->get('caveats');
        $b->set('deltas', [self::grant(1, self::A2, [$env, $is, $env])]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('statement.opening', 'fail', 'signed by a key that is not a principal of the session'), self::one($r, 'statement.opening', ['statement']));
        $this->assertSame(self::txt('principal.pinned', 'fail', 'signing keys that are not pinned principals'), self::one($r, 'principal.pinned', [self::K6, self::K9]));
        $this->assertSame([self::K6, self::A2, self::K9], $r->get('summary')->get('attribution')->get('keys_to_check'));
        $this->assertSame(self::txt('revocation.history', 'pass'), self::one($r, 'revocation.history', ['epoch#0:1']));
        $this->assertSame(self::txt('revocation.history', 'pass'), self::one($r, 'revocation.history', ['epoch#1:1']));
        $this->assertSame(self::txt('revocation.epoch', 'pass'), self::one($r, 'revocation.epoch', ['epoch:1']));
        $this->assertSame(self::txt('delta.chain', 'fail', 'bound to another session root'), self::one($r, 'delta.chain', ['D_1']));
        $declared = self::fs($r, 'accumulator.declared');
        $this->assertCount(1, $declared);
        $this->assertSame(['fail', ['acc:nope#0']], [$declared[0][0], $declared[0][2]]);
        $this->assertSame(self::txt('accumulator.arithmetic', 'pass'), self::one($r, 'accumulator.arithmetic', ['acc:trip_spend#1']));
        $this->assertSame(self::txt('accumulator.arithmetic', 'pass'), self::one($r, 'accumulator.arithmetic', ['acc:trip_budget#2']));
        $this->assertSame(self::txt('accumulator.receipts', 'fail', 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time'),
            self::one($r, 'accumulator.receipts', ['receipt:trip_budget#1']));
    }

    /**
     * PQ pin agreement is judged against the FIRST session-root principal entry of the key, and only the mismatching keys are named
     * (as a list); a revocation max age that is not a whole number of ms is a misconfiguration (fail closed); without usable
     * credentials a device answer stays unverified; a judge list that is not an array pins nobody.
     */
    public function testPqPinsMaxAgeAndUnknownAuthenticators(): void
    {
        [$b, $t] = self::load(self::WALK);
        $t->set('principals', self::j('[{"key": "' . self::A2 . '", "pq_pk": "AAAA"}, {"key": "' . self::V1 . '", "pq_pk": "AAAA"}]'));
        $t->set('credentials', 'x');
        $t->set('judges', 'x');
        $sr = $b->get('session_root');
        $sr->set('principals', self::j('[{"key": "' . self::A2 . '", "pq_pk": "AAAA"}, {"key": "' . self::A2 . '"}]'));
        $sr->get('revocation')->set('max_age_s', self::n('0.0125'));
        $b->get('statement')->get('opening')->set('principal', self::V1);
        $tpl = self::answerOf($b, 'q_7Hk2');
        $b->set('answers', [...$b->get('answers'), self::deviceAnswer($tpl, 'q_d1', '1793534404100', true), self::deviceAnswer($tpl, 'q_d2', '1793534404200', false)]);
        $b->set('classifier', [Obj::of(['judge' => 'J'])]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $refs = array_values(array_filter(self::fs($r, 'principal.pinned'), static fn(array $x): bool => true));
        $this->assertCount(1, $refs);
        $this->assertSame(['fail', self::txt('principal.pinned', 'fail', 'the session root binds a different PQ key than the pin'), [self::V1]], $refs[0]);
        $this->assertSame(self::txt('revocation.history', 'fail', 'revocation max age misconfigured (fail closed)'), self::one($r, 'revocation.history', ['epoch#0:1']));
        $unknown = self::txt('answer.device', 'unverified', 'unknown authenticator');
        $this->assertSame($unknown, self::one($r, 'answer.device', ['answer:q_d1']));
        $this->assertSame($unknown, self::one($r, 'answer.device', ['answer:q_d2']));
        $this->assertSame(self::txt('classifier.signature', 'unverified', 'no verifier for this classifier verdict (judge not pinned)'), self::one($r, 'classifier.signature', ['classifier:0']));
    }

    // ---- anchors, map replay, key-set order, JIT consent, G_0 without a session caveat ----------------------------------------

    /**
     * Each anchorable kind is recognised by its own digest (statement commit, a bundled map commit, the schema digest, a verified
     * answer's ref) and nothing else is; every anchor is judged (a non-anchorable one or a missing guardian does not end the loop);
     * no `evidence` anchor means the bundle is not anchored. Also: a map whose metrics are all missing reports its first three
     * problems; key sets sort by issued_at first; the first consenting answer is the consent; a G_0 without an intent_session
     * caveat is refused as such.
     */
    public function testAnchorsMapKeysetsConsentAndG0(): void
    {
        [$b, $t] = self::load(self::WALK);
        $t = $t->without('anchorGuardian');
        $q7 = self::answerOf($b, 'q_7Hk2');
        $obs = Wallet::answerRef($q7);
        $schema = $b->get('session_root')->get('schema')->get('digest');
        $anchors = [];
        foreach ([['statement', $b->get('statement')->get('commit')], ['map', $b->get('maps')[0]->get('commit')], ['map', 'nope'], ['schema', $schema],
            ['observation', $obs], ['observation', 'nope'], ['other', 'x']] as [$kind, $digest]) {
            $anchors[] = Obj::of(['kind' => $kind, 'digest' => $digest, 'index' => self::n('1')]);
        }
        $b->set('anchors', $anchors);
        $b->get('accumulator')->set('sequencer_keys', self::j('[{"sequencer": "nope", "issued_at": 20, "version": 1}, {"sequencer": "nope", "issued_at": 10, "version": 2}]'));
        $b->set('answers', [...$b->get('answers'), self::answer($q7, ['question_id' => 'q_z', 'observed_at' => self::n('1793534404100')])]);
        $b->set('root_grant', self::grant(1, self::A2, [$b->get('root_grant')->get('caveats')[0]]));
        $b->get('maps')[0]->get('map')->set('metrics', new Obj());
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $noGuardian = self::txt('anchor.inclusion', 'unverified', 'no anchor-log guardian key supplied');
        $notThis = self::txt('anchor.inclusion', 'fail', 'the anchor names an artifact that is not this one');
        $this->assertSame(self::txt('anchor.inclusion', 'unverified', 'the bundle is not anchored'), self::one($r, 'anchor.inclusion', ['anchor:evidence']));
        $this->assertSame($noGuardian, self::one($r, 'anchor.inclusion', ['anchor:statement:1']));
        $this->assertSame($noGuardian, self::one($r, 'anchor.inclusion', ['anchor:schema:1']));
        $this->assertSame($notThis, self::one($r, 'anchor.inclusion', ['anchor:other:1']));
        foreach (['anchor:map:1', 'anchor:observation:1'] as $ref) {
            $got = array_map(static fn(array $x): string => $x[1], array_values(array_filter(self::fs($r, 'anchor.inclusion'), static fn(array $x): bool => $x[2] === [$ref])));
            sort($got);
            $want = [$notThis, $noGuardian];
            sort($want);
            $this->assertSame($want, $got, $ref);
        }
        $map = self::one($r, 'map.replay', ['map:0']);
        $prefix = self::TPL['map.replay'] . ': REFUTED (';
        $this->assertStringStartsWith($prefix, $map);
        $this->assertStringEndsWith(').', $map);
        $problems = explode('; ', substr($map, strlen($prefix), -2));
        $this->assertCount(3, $problems, $map);
        foreach ($problems as $p) {
            $this->assertMatchesRegularExpression('/^metric [a-z0-9_]+ differs \(undefined claimed, /', $p);
        }
        $unpinned = self::txt('acc.keysets', 'fail', 'not signed by a sequencer root the session root pins');
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#0:2']));
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#1:1']));
        $this->assertSame('q_7Hk2', $r->get('summary')->get('consent')->get('question_id'));
        $this->assertSame(self::txt('root_grant', 'fail', 'no intent_session caveat'), self::one($r, 'root_grant', ['G_0']));
    }

    /**
     * Effects: one naming no bundled PCActn does not end the loop; a charged ref that is not a string, not an `action.params.`
     * path, or a path into non-object params is "no numeric value to compare"; frame violations are reported by their String().
     * Also: key sets tied on issued_at sort by version; a yes answer that carries the action digest WITHOUT consent_for_action is
     * not a JIT consent; an intent_session caveat error of G_0 is reported as is; a non-string revocation pq_pk pin is refused.
     */
    public function testEffectsKeysetTieConsentAndCaveatError(): void
    {
        [$b, $t] = self::load(self::WALK);
        $e = $b->get('effects')[0];
        $plain = self::copy($e, [], ['charged', 'frame_violations']);
        $b->set('effects', [
            Obj::of(['pcactn_digest' => 'AAAA']),
            self::copy($plain, ['charged' => Obj::of(['amount' => self::n('77800'), 'ref' => true])]),
            self::copy($plain, ['charged' => Obj::of(['amount' => self::n('77800'), 'ref' => 'total'])]),
            Obj::of(['pcactn_digest' => self::RMN9, 'params' => [self::n('77800')], 'charged' => Obj::of(['amount' => self::n('77800'), 'ref' => 'action.params.0'])]),
            self::copy($plain, ['frame_violations' => [true]]),
        ]);
        $b->get('accumulator')->set('sequencer_keys', self::j('[{"sequencer": "nope", "issued_at": 10, "version": 1}, {"sequencer": "nope", "issued_at": 10, "version": 2}]'));
        $q7 = self::answerOf($b, 'q_7Hk2');
        $others = array_values(array_filter($b->get('answers'), static fn($a): bool => $a->get('question_id') !== 'q_7Hk2'));
        $b->set('answers', [...$others, self::answer($q7, ['question_id' => 'q_n'], [], ['consent_for_action'])]);
        [$env, $is] = $b->get('root_grant')->get('caveats');
        $b->set('root_grant', self::grant(1, self::A2, [$env, self::copy($is, ['extra' => 'x'])]));
        $b->get('session_root')->get('revocation')->set('pq_pk', self::n('5'));
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('effect.binding', 'fail', 'no such PCActn in the bundle'), self::one($r, 'effect.binding', ['effect:AAAA']));
        $this->assertSame(self::txt('effect.binding', 'fail'), self::one($r, 'effect.binding', ['effect:' . self::RMN9]));
        $charged = self::texts($r, 'effect.charged');
        sort($charged);
        $want = [self::txt('effect.charged', 'unverified', 'no numeric true to compare'), self::txt('effect.charged', 'unverified', 'no numeric total to compare'),
            self::txt('effect.charged', 'unverified', 'no numeric action.params.0 to compare')];
        sort($want);
        $this->assertSame($want, $charged);
        $this->assertSame([self::txt('effect.frame', 'fail', 'true')], self::texts($r, 'effect.frame'));
        $this->assertCount(4, self::fs($r, 'effect.signature'));
        $unpinned = self::txt('acc.keysets', 'fail', 'not signed by a sequencer root the session root pins');
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#0:1']));
        $this->assertSame($unpinned, self::one($r, 'acc.keysets', ['keyset#1:2']));
        $this->assertSame(self::txt('jit.consent', 'fail', 'no principal yes at typed tier or above bound to this action digest'), self::one($r, 'jit.consent', ['pcactn:' . self::SUBJ]));
        $this->assertSame(self::txt('root_grant', 'fail', "intent_session caveat: unknown member 'extra'"), self::one($r, 'root_grant', ['G_0']));
        $this->assertSame('fail', self::fs($r, 'revocation.history')[0][0]);
    }

    // ---- accumulator events, receipts, device answers ------------------------------------------------------------------------

    /**
     * The running value per accumulator (an uncounted event keeps it and does not end the loop), sum adds and never takes the max,
     * an event naming another admitting grant does not end the loop, an event without `delta` is capped by its PCActn's root grant,
     * an accumulator with no stated cap is unverified, an unrecomputable contribution that keeps the post is unverified (not a
     * decrease). Receipts: an age bound of 0 refuses a 200 ms old receipt, a receipt naming a non-string accumulator fails in its
     * verifier, the ref of a receipt without seq is its index. Device answers: a valid assertion with UV passes, one without UV is
     * refused. A subject rooted at G_0 is admitted under G_0.
     */
    public function testEventsReceiptsDeviceAndAdmission(): void
    {
        [$b, $t] = self::load(self::WALK);
        $t->set('acc', self::j('{"max_receipt_age_s": 0}'));
        $t->set('credentials', self::credentials());
        $b->get('subject')->set('pcactn_digest', self::RMN9);
        $s = self::SUBJ;
        $b->get('accumulator')->set('events', self::j('['
            . '{"acc": "trip_spend", "post": 0, "pcactn_digest": "' . $s . '", "status": "released"},'
            . '{"acc": "trip_spend", "post": 77800, "pcactn_digest": "' . $s . '", "delta": 0, "status": "committed"},'
            . '{"acc": "trip_spend", "post": 155600, "pcactn_digest": "' . $s . '", "status": "committed"},'
            . '{"acc": "trip_budget", "post": 77800, "pcactn_digest": "' . $s . '", "status": "committed"},'
            . '{"acc": "trip_spend", "post": 155600, "pcactn_digest": "' . self::RMN9 . '", "status": "committed"}]'));
        $real = $b->get('accumulator')->get('receipts')[0];
        $b->get('accumulator')->set('receipts', [$real, self::copy($real, ['acc' => self::n('5')]), self::copy($real, ['acc' => 'zz'], ['seq'])]);
        $tpl = self::answerOf($b, 'q_7Hk2');
        $b->set('answers', [...$b->get('answers'), self::deviceAnswer($tpl, 'q_d1', '1793534404100', true), self::deviceAnswer($tpl, 'q_d2', '1793534404200', false)]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame('G_0', $r->get('summary')->get('admitted_under'));
        $pass = self::txt('accumulator.arithmetic', 'pass');
        $this->assertSame($pass, self::one($r, 'accumulator.arithmetic', ['acc:trip_spend#0']));
        $this->assertSame($pass, self::one($r, 'accumulator.arithmetic', ['acc:trip_spend#1']));
        $this->assertSame($pass, self::one($r, 'accumulator.arithmetic', ['acc:trip_spend#2']));
        $this->assertSame($pass, self::one($r, 'accumulator.arithmetic', ['acc:trip_budget#3']));
        $this->assertSame(self::txt('accumulator.arithmetic', 'unverified', 'contribution not recomputable'), self::one($r, 'accumulator.arithmetic', ['acc:trip_spend#4']));
        $this->assertSame(self::txt('accumulator.cap', 'fail', 'the event names a different admitting grant from the PCActn root'), self::one($r, 'accumulator.cap', ['acc:trip_spend#1']));
        $this->assertSame(self::txt('accumulator.cap', 'fail', 'post 155600, cap 80000'), self::one($r, 'accumulator.cap', ['acc:trip_spend#2']));
        $this->assertSame(self::txt('accumulator.cap', 'unverified', 'no cap stated for this accumulator'), self::one($r, 'accumulator.cap', ['acc:trip_budget#3']));
        $this->assertSame(self::txt('accumulator.receipts', 'fail', 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time'),
            self::one($r, 'accumulator.receipts', ['receipt:trip_budget#1']));
        $this->assertStringContainsString('verifier threw: Object of class Atlas\Pca\Num could not be converted to string', self::one($r, 'accumulator.receipts', ['receipt:5#1']));
        $zz = array_values(array_filter(self::fs($r, 'accumulator.receipts'), static fn(array $x): bool => str_starts_with($x[2][0], 'receipt:zz#')));
        $this->assertCount(1, $zz);
        $this->assertMatchesRegularExpression('/^receipt:zz#[0-2]$/', $zz[0][2][0]);
        $this->assertSame(self::txt('accumulator.receipts', 'fail', 'the receipt names an accumulator that is not sequenced in the session root'), $zz[0][1]);
        $this->assertSame(self::txt('answer.device', 'pass'), self::one($r, 'answer.device', ['answer:q_d1']));
        $this->assertSame(self::txt('answer.device', 'fail', 'User Verified (UV) flag is required but not set'), self::one($r, 'answer.device', ['answer:q_d2']));
    }

    // ---- delta order and the signed accumulator claims (acc-claim case) ------------------------------------------------------

    /** A delta that fails its signature does not end the delta loop; a signed claim is matched against the FIRST matching event. */
    public function testDeltaLoopContinuesAndClaimsMatchTheFirstEvent(): void
    {
        [$b, $t] = self::load(self::CLAIM);
        $d1 = $b->get('deltas')[0];
        $b->set('deltas', [self::copy($d1, ['sig' => $b->get('root_grant')->get('sig')]), $d1]);
        $ev = $b->get('accumulator')->get('events');
        $b->get('accumulator')->set('events', [...$ev, ...self::j('[{"acc": "trip_spend", "post": 77800, "pcactn_digest": "' . self::D3 . '", "status": "committed"},'
            . ' {"acc": "trip_spend", "post": 1, "pcactn_digest": "' . self::D3 . '", "status": "committed"}]')]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame('fail', self::fs($r, 'delta.signature')[0][0]);
        $this->assertSame(self::txt('delta.signature', 'pass'), self::one($r, 'delta.signature', ['D_2']));
        $session = self::one($r, 'pcactn.session', ['pcactn:' . self::D3]);
        $this->assertStringNotContainsString('has no matching accumulator event', $session);
    }

    // ---- W-B artifacts -------------------------------------------------------------------------------------------------------

    /**
     * Facts, classifier verdicts, offer sets and label receipts: a wire error with a pinned key is a refutation; a non-object
     * artifact is unverified (no key can be looked up); an offer set's key is the FIRST pinned ed25519 site key whose kid equals
     * the set's (containers never compare equal); a correctly signed label receipt for another session is refuted.
     */
    public function testWbArtifacts(): void
    {
        [$b, $t] = self::load(self::WB);
        $f = $b->get('facts')[0];
        $c = $b->get('classifier')[0];
        $o = $b->get('offer_sets')[0];
        $l = $b->get('labels')[0];
        $other = self::copy($l, ['session' => self::SROOT_REF]);
        $other->set('sig', Pca::b64u(sodium_crypto_sign_detached(IntentWb::artifactMessage(IntentWb::LABELS_DOMAIN, $other), self::sk(3))));
        $b->set('facts', [self::copy($f, ['zzz' => '1']), 'str']);
        $b->set('classifier', [self::copy($c, ['zzz' => '1']), 'str']);
        $b->set('offer_sets', [$o, self::copy($o, ['zzz' => '1']), Obj::of(['kid' => 'nomatch']), 'str', Obj::of(['kid' => []])]);
        $b->set('labels', [$l, $other]);
        $site = $t->get('siteKeys')[0];
        $t->set('siteKeys', [$site, self::copy($site, ['pk' => self::K9]), Obj::of(['alg' => 'ed25519', 'pk' => self::K9]),
            Obj::of(['kid' => [], 'alg' => 'ed25519', 'pk' => self::K9])]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $facts = self::texts($r, 'fact.signature');
        $this->assertCount(2, $facts);
        $this->assertContains(self::txt('fact.signature', 'fail', "unknown member 'fact.zzz'"), $facts);
        $this->assertContains(self::txt('fact.signature', 'unverified', 'no verifier for this fact (oracle key not pinned)'), $facts);
        $cls = self::texts($r, 'classifier.signature');
        $this->assertCount(2, $cls);
        $this->assertContains(self::txt('classifier.signature', 'fail', "unknown member 'verdict.zzz'"), $cls);
        $this->assertContains(self::txt('classifier.signature', 'unverified', 'no verifier for this classifier verdict (judge not pinned)'), $cls);
        $offers = self::texts($r, 'offer_set.signature');
        sort($offers);
        $unpinned = self::txt('offer_set.signature', 'unverified', 'no verifier for this offer set (site key not pinned)');
        $want = [self::txt('offer_set.signature', 'pass'), self::txt('offer_set.signature', 'fail', "unknown member 'offer_set.zzz'"), $unpinned, $unpinned, $unpinned];
        sort($want);
        $this->assertSame($want, $offers);
        $labels = self::texts($r, 'labels.signature');
        sort($labels);
        $want = [self::txt('labels.signature', 'pass'), self::txt('labels.signature', 'fail', 'label receipt for another session')];
        sort($want);
        $this->assertSame($want, $labels);
    }
}
