<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/SignersMore.php';
require_once __DIR__ . '/../src/Facade.php';
require_once __DIR__ . '/../src/Undo.php';
require_once __DIR__ . '/../src/Contracts.php';
require_once __DIR__ . '/../src/Prohibitions.php';
require_once __DIR__ . '/../src/ArgProvenance.php';
require_once __DIR__ . '/../src/CaveatLang.php';
require_once __DIR__ . '/../src/Escalation.php';

use Atlas\Pca\CaveatLang;
use Atlas\Pca\Contracts;
use Atlas\Pca\Escalation;
use Atlas\Pca\Facade;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Prohibitions;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore as S;
use Atlas\Pca\Undo;

/** The op names an artifact this SDK does not produce. */
final class NotProduced extends \RuntimeException
{
}

/**
 * Runs one producer vector case (the producer-vectors.json / producer-pq-vectors.json case format) through this SDK's producers.
 * Shared by the producer tests and the cross-language driver: {@see run} returns the produced artifact shaped like the case's
 * `expect` (the reference's member names), or throws what the producer threw. An unknown op throws {@see NotProduced}.
 */
final class ProducerOps
{
    /** The reference names PQ families in lower case. */
    public const FAMILIES = ['ml-dsa-65' => 'ML-DSA-65', 'ml-dsa-87' => 'ML-DSA-87', 'slh-dsa-sha2-128f' => 'SLH-DSA-SHA2-128f',
        'slh-dsa-sha2-256s' => 'SLH-DSA-SHA2-256s', 'fn-dsa-512' => 'FN-DSA-512', 'fn-dsa-1024' => 'FN-DSA-1024'];

    /** @var array<string,KeyPair> */
    private array $keys = [];
    /** @var array<string,PqKeyPair> */
    private array $pqCache = [];

    /** @param Obj|null $keys name -> {seed, ...} (Ed25519) @param Obj|null $pqKeys name -> {family, seed, ...} */
    public function __construct(?Obj $keys, private readonly ?Obj $pqKeys = null)
    {
        foreach ($keys?->keys() ?? [] as $n) {
            $this->keys[$n] = KeyPair::fromSeedB64u($keys->get($n)->get('seed'));
        }
    }

    public function key(string $name): KeyPair
    {
        return $this->keys[$name] ?? throw new \InvalidArgumentException("unknown key $name");
    }

    /** The seeded PQ key pair named `$name` (derived once: seeded keygen is not free). */
    public function pq(mixed $name): ?PqKeyPair
    {
        if (!is_string($name)) {
            return null;
        }
        if (!isset($this->pqCache[$name])) {
            $e = $this->pqKeys?->get($name) ?? throw new \InvalidArgumentException("unknown pq key $name");
            $this->pqCache[$name] = self::pqOf($e->get('family'), $e->get('seed'));
        }
        return $this->pqCache[$name];
    }

    private static function pqOf(string $family, string $seed): PqKeyPair
    {
        return new PqKeyPair(self::FAMILIES[$family] ?? $family, Pca::unb64u($seed) ?? throw new \InvalidArgumentException('bad pq seed'));
    }

    private static function i(mixed $v): int
    {
        return $v instanceof Num ? (int)$v->float() : (int)$v;
    }

    private static function alg(mixed $a): ?string
    {
        return $a === 'ed25519' ? null : $a;
    }

    private static function opt(Obj $a, string $k): mixed
    {
        return $a->has($k) ? $a->get($k) : null;
    }

    public function run(string $op, Obj $a): mixed
    {
        $k = fn(string $n): KeyPair => $this->key($n);
        switch ($op) {
            // ---- producer-vectors.json: Ed25519 ---------------------------------------------------------------------------------
            case 'ed25519_sign':
                $kp = KeyPair::fromSeedB64u($a->get('seed'));
                return Obj::of(['public' => $kp->public, 'sig' => Pca::b64u($kp->sign($a->get('message_utf8')))]);
            case 'goal_commit':
                return Obj::of(['commit' => Sign::goalCommit($a->get('goal'), $a->get('salt'))]);
            case 'params_digest':
                return Obj::of(['digest' => Pca::paramsDigest($a->get('params'))]);
            case 'plan_commit':
                return Sign::commitPlan($a->get('nodes'));
            case 'mint_grant':
                $r = Sign::mintGrant($k($a->get('principal')), $k($a->get('holder'))->public, Sign::plain($a->get('envelope')), $a->get('goal'), $a->get('salt'));
                return Obj::of(['grant' => $r['grant'], 'goal_commit' => $r['goal_commit'], 'goal_salt' => $r['goal_salt']]);
            case 'delegate':
                $to = self::opt($a, 'to_holder');
                return Sign::delegate($a->get('parent'), $k($a->get('signer')), $to === null ? null : $k($to)->public, $a->get('added_caveats'));
            case 'act':
                $extra = [];
                foreach (['nonce', 'caution', 'rationale_commitment', 'tool_binding', 'fresh_at'] as $n) {
                    if ($a->has($n)) {
                        $extra[$n] = $a->get($n);
                    }
                }
                $p = Sign::buildPcactn($a->get('grant'), $a->get('chain'), $a->get('plan'), $a->get('node_id'), self::i($a->get('counter')), $k($a->get('signer')),
                    $a->get('aud'), self::opt($a, 'params'), self::i($a->get('iat')), self::i($a->get('exp')), Sign::DEFAULT_TTL_MS, $extra);
                return Obj::of(['pcactn' => $p, 'header' => Sign::headers($p)['PCA-Action']]);
            case 'fresh_at':
                return Sign::signFreshAt($k($a->get('signer')), $a->get('scope'), $a->get('state'), self::i($a->get('issued_at')));
            case 'escalation_digests':
                $lc = self::opt($a, 'last_counter');
                return Obj::of(['policy_digest' => Escalation::policyDigest($a->get('grant')), 'action_digest' => Escalation::actionDigest($a->get('pcactn')),
                    'history_head' => Escalation::historyHead($lc === null ? null : self::i($lc))]);
            case 'sign_escalation_answer':
                $b = $a->get('body');
                return Sign::signEscalationAnswer($k($a->get('signer')), $b, $b->get('decision'), self::i($b->get('iat')), self::i($b->get('expires_at')), $b->get('nonce'));
            case 'sign_discharge':
                $b = $a->get('body');
                return Sign::signDischarge($k($a->get('signer')), $b->get('caveat_id'), $b->get('issuer'), $b->get('cap_hash'), $b->get('claims'),
                    self::i($b->get('iat')), self::i($b->get('not_after')), $b->get('bind'), self::opt($b, 'action_digest'), $b->get('nonce'));
            case 'discharge_digest':
                return Obj::of(['digest' => CaveatLang::dischargeDigest($a->get('discharge'))]);
            case 'sign_narrow':
                $b = $a->get('body');
                return Sign::signNarrow($k($a->get('signer')), $b->get('cap_hash'), $b->get('caveats'), self::i($b->get('iat')), self::i($b->get('not_after')),
                    self::opt($b, 'action_digest'), $b->get('nonce'));
            case 'sign_passport':
                $pp = Sign::issuePassport($a->get('identity'));
                return Obj::of(['passport' => $pp, 'signed' => Sign::signPassport($pp, $k($a->get('issuer')), $k($a->get('subject'))->public, self::i($a->get('exp')))]);
            case 'sign_workflow':
                return Sign::signWorkflow($k($a->get('signer')), $a->get('body'));
            case 'sign_step_receipt':
                $prev = self::opt($a, 'prev');
                return Sign::signStepReceipt($k($a->get('signer')), $a->get('workflow'), $a->get('step'), $a->get('outcome'), $a->get('params_digest'),
                    $a->get('outputs'), self::i($a->get('issued_at')), $prev instanceof Obj ? $prev : null);
            case 'sign_read_grant':
                return Sign::signReadGrant($k($a->get('signer')), $a->get('body'));
            case 'sign_aggregate_grant':
                return Sign::signAggregateGrant($k($a->get('signer')), $a->get('body'));
            case 'sign_revocation_epoch':
                return S::signRevocationEpoch($k($a->get('signer')), $a->get('body'));
            case 'sign_undo_token':
                return Undo::signToken($a->get('record'), $k($a->get('signer')));
            case 'sign_undo_receipt':
                return Undo::signReceipt($a->get('body'), $k($a->get('signer')));
            case 'sign_contract':
                return Contracts::signContract($a->get('contract'), $k($a->get('signer')));
            case 'sign_contract_reset':
                return Obj::of(['sig' => Contracts::signContractReset($k($a->get('signer')), $a->get('contract_id'), self::i($a->get('seq')))]);
            case 'sign_constitution':
                return Prohibitions::signConstitution($a->get('constitution'), $k($a->get('signer')));
            case 'sign_safety_evidence':
                return Prohibitions::signSafetyEvidence($a->get('evidence'), $k($a->get('signer')));
            case 'sign_threshold_share':
                return S::signThresholdShare($a->get('role'), $k($a->get('signer')), Pca::unb64u($a->get('message')) ?? throw new \InvalidArgumentException('bad message'),
                    $a->get('signer_set'), self::i($a->get('t')));
            case 'sign_prepared_share':
                return S::signPreparedShare($a->get('role'), $k($a->get('signer')), Pca::unb64u($a->get('prepared')) ?? throw new \InvalidArgumentException('bad prepared'));
            case 'sign_pq_binding':
                return S::signPqBinding($k($a->get('signer')), $a->get('pq_pk'), $a->get('epoch'), $a->get('aud'));
            case 'sign_caution':
                return S::signCaution($a->get('body'), $k($a->get('signer')));
            case 'sign_heartbeat':
                return S::signHeartbeat($a->get('body'), $k($a->get('signer')));
            case 'prov_recorder':
                return $this->provRecorder($a);
            case 'sign_mesh_action':
                return Obj::of(['sig' => S::signMeshAction($a->get('chain'), $a->get('action'), $k($a->get('signer')))]);
            case 'sign_session_root':
                return S::signSessionRoot($a->get('body'), $k($a->get('signer')));
            case 'mint_session_grant':
                $cav = self::opt($a, 'caveats');
                $r = S::mintSessionGrant($k($a->get('principal')), $k($a->get('holder'))->public, $a->get('session'), self::i($a->get('seq')), $a->get('root'),
                    $a->get('map_digest'), $a->get('predicates'), self::opt($a, 'prev'), self::opt($a, 'map_form'), is_array($cav) ? $cav : null,
                    salt: self::opt($a, 'salt'));
                return Obj::of(['grant' => $r['grant'], 'goal_salt' => $r['goal_salt']]);
            case 'sign_action_schema':
                return S::signActionSchema($a->get('doc'), $a->get('kid'), $k($a->get('signer')));
            case 'sign_labels':
                return S::signLabels($a->get('body'), $k($a->get('signer')));
            case 'sign_intent_required':
                return S::signIntentRequired($a->get('body'), $a->get('kid'), $k($a->get('signer')));
            case 'sign_progress_step':
                return S::signProgressStep($a->get('step'), $k($a->get('signer')));
            case 'sign_fact':
                return S::signFact($a->get('body'), $k($a->get('signer')));
            case 'sign_offer_set':
                return S::signOfferSet($a->get('body'), $k($a->get('signer')));
            case 'sign_read_receipt':
                $prev = self::opt($a, 'prev');
                return S::signReadReceipt($k($a->get('signer')), $a->get('grant'), $a->get('verb'), $a->get('resource'), $a->get('purpose'), $a->get('fields'),
                    $a->get('labels'), self::i($a->get('issued_at')), $prev instanceof Obj ? $prev : null);
            case 'sign_template':
                return S::signTemplate($a->get('def'), $k($a->get('signer')));
            case 'sign_tighten':
                return S::signTighten($a->get('overlay'), $k($a->get('signer')));
            case 'parse_limit':
                return Sign::n(Facade::parseLimit($a->get('limit')));
            case 'compile_policy':
                $p = Facade::compilePolicy($a->get('permissions'), self::opt($a, 'limits'), null, self::opt($a, 'budget_model'), null, self::i($a->get('now')));
                unset($p['actions'], $p['inputLimits']);
                $out = Sign::n($p);
                if ($p['limits'] === []) {
                    $out->set('limits', new Obj()); // PHP's [] is the empty limits OBJECT
                }
                return $out;
            case 'facade_act':
                return $this->facadeAct($a);
            // ---- producer-pq-vectors.json: every suite ------------------------------------------------------------------------
            case 'pq_keygen':
                return Obj::of(['public' => self::pqOf($a->get('family'), $a->get('seed'))->public]);
            case 'suite_sign':
                $ed = self::opt($a, 'ed');
                return Sign::n(Sign::signWithSuite(self::alg($a->get('alg')), is_string($ed) ? $k($ed) : null, $this->pq(self::opt($a, 'pq')), $a->get('message_utf8')));
            case 'mint_root_suite':
                return Sign::mintRoot($k($a->get('principal')), $k($a->get('holder'))->public, $a->get('caveats'), $this->pq(self::opt($a, 'holder_pq'))?->public,
                    self::alg($a->get('alg')), $this->pq(self::opt($a, 'pq')));
            case 'delegate_suite':
                $to = self::opt($a, 'to_holder');
                return Sign::delegate($a->get('parent'), $k($a->get('signer')), is_string($to) ? $k($to)->public : null, $a->get('added_caveats'),
                    $this->pq(self::opt($a, 'holder_pq'))?->public, self::alg($a->get('alg')), $this->pq(self::opt($a, 'pq')));
            case 'sign_pcactn_suite':
                return Obj::of(['pcactn' => Sign::signPcactn($a->get('body'), $k($a->get('signer')), self::alg($a->get('alg')), $this->pq(self::opt($a, 'pq')))]);
            case 'sign_artifact_suite':
                $b = $a->get('body');
                $alg = self::alg($a->get('alg'));
                $pq = $this->pq(self::opt($a, 'pq'));
                if ($a->get('kind') === 'escalation_answer') {
                    return Sign::signEscalationAnswer($k($a->get('signer')), $b, $b->get('decision'), self::i($b->get('iat')), self::i($b->get('expires_at')),
                        $b->get('nonce'), $alg, $pq);
                }
                return S::signRevocationEpoch($k($a->get('signer')), $b, $alg, $pq);
        }
        throw new NotProduced($op);
    }

    private function provRecorder(Obj $a): Obj
    {
        $clock = array_map(static fn($t) => self::i($t), $a->get('clock'));
        $r = new ProvenanceRecorder($a->get('mediator'), $a->get('kid'), $this->key($a->get('key')), $a->get('session'),
            static function () use (&$clock): int {
                return array_shift($clock) ?? throw new \LogicException('clock exhausted');
            });
        $outs = [];
        foreach ($a->get('steps') as $s) {
            $outs[] = match ($s->get('kind')) {
                'principal' => $r->principal($s->get('text')),
                'tool' => $r->tool($s->get('name'), $s->get('output')),
                'web' => $r->web($s->get('url'), $s->get('content')),
                'retrieval' => $r->retrieval($s->get('source'), $s->get('content')),
                default => $r->forAction($s->get('op')),
            };
        }
        $bundle = array_pop($outs);
        return Obj::of(['pin' => $r->pin, 'receipts' => $outs, 'bundle' => $bundle]);
    }

    private function facadeAct(Obj $a): Obj
    {
        $now = self::i($a->get('now'));
        $h = Facade::createAgent($this->key($a->get('principal')), $a->get('goal'), $a->get('permissions'), self::opt($a, 'limits'),
            holder: $this->key($a->get('holder')), aud: $a->get('aud'), now: $now, goalSalt: $a->get('goal_salt'),
            provenance: ['key' => $this->key($a->get('recorder_key')), 'session' => $a->get('session'), 'now' => static fn(): int => $now]);
        $grant = $h->grant;
        $sub = self::opt($a, 'sub_agent');
        if ($sub instanceof Obj) {
            $h = $h->subAgent($this->key($sub->get('holder')), $sub->get('added_caveats'));
        }
        foreach (self::opt($a, 'principal_messages') ?? [] as $t) {
            $h->provenance->principal($t);
        }
        $act = $a->get('act');
        $nonce = self::opt($act, 'nonce');
        $r = $h->act($act->get('verb'), $act->get('resource'), self::opt($act, 'params'), counter: self::i($act->get('counter')), now: self::i($act->get('now')),
            nonce: is_string($nonce) ? $nonce : null);
        return Obj::of(['grant' => $grant, 'goal_commit' => $grant->get('caveats')[0]->get('goal_commit'), 'chain' => $h->chain, 'pcactn' => $r['pcactn'],
            'encoded' => $r['encoded'], 'provenance' => $r['provenance']]);
    }
}
