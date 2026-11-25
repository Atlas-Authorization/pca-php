<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AdmissionRegistry;
use Atlas\Pca\BlueprintRegistry;
use Atlas\Pca\DecisionLog;
use Atlas\Pca\FreshAtIssuer;
use Atlas\Pca\GrantError;
use Atlas\Pca\GrantHttp;
use Atlas\Pca\GrantService;
use Atlas\Pca\MemoryGrantStore;
use Atlas\Pca\Grants;
use Atlas\Pca\Js;
use Atlas\Pca\K3;
use Atlas\Pca\K3Sig;
use Atlas\Pca\ListAuthorized;
use Atlas\Pca\Shadow;
use Atlas\Pca\ShadowLog;
use Atlas\Pca\WindowReadAccumulator;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryBlueprintStore;
use Atlas\Pca\Lease;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The operational plane's producing side against the TS reference: test-data/ref-grants.json.gz. A secret key is a LABEL whose seed
 * is sha256("atlas-pca-conformance/" + label); in scenario specs "$key:LABEL" is that key's public key and {"$sign": {kind, label,
 * fields}} the signed record. The lease store's per-shard revocation listing has no PHP counterpart (those scenarios are skipped).
 */
final class RefGrantsDifferentialTest extends TestCase
{
    private const FILE = 'ref-grants.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function sk(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    private static function pub(string $label): string
    {
        return self::sk($label)->public;
    }

    private static function resolve(mixed $v): mixed
    {
        if (is_string($v)) {
            return str_starts_with($v, '$key:') ? self::pub(substr($v, 5)) : $v;
        }
        if (is_array($v)) {
            return array_map(self::resolve(...), $v);
        }
        if ($v instanceof Obj) {
            if ($v->has('$sign')) {
                $s = $v->get('$sign');
                $f = ['lease' => 'signLease', 'leaseOver' => 'signLeaseUnsafeOverCap', 'revocation' => 'signLeaseRevocation', 'blueprint' => 'signBlueprint',
                    'breakglass' => 'signBreakGlass', 'review' => 'signBreakGlassReview'][$s->get('kind')];
                return Grants::$f(self::sk($s->get('label')), self::resolve($s->get('fields')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::resolve($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    private static function err(mixed $e): Obj
    {
        return Obj::of(['$err' => property_exists($e, 'errorCode') && is_string($e->errorCode) ? $e->errorCode : 'x']);
    }

    private static function logScenario(Obj $spec): Obj
    {
        $log = new DecisionLog(self::sk($spec->get('label')), $spec->get('mask') ?? []);
        $recs = array_map($log->append(...), $spec->get('records'));
        $signer = self::pub($spec->get('label'));
        $now = $spec->get('now');
        $head = $log->head($now);
        $out = Obj::of(['recs' => $recs, 'head' => $head, 'size' => $log->size()]);
        $proofs = [];
        $incl = [];
        foreach ($spec->get('proofs') ?? [] as $i) {
            try {
                $p = $log->proof($i);
                $proofs[] = $p;
                $incl[] = K3::verifyRecordInclusion($recs[(int)K3Sig::num($i)], $p, $head, $signer);
            } catch (\Throwable) {
                $proofs[] = Obj::of(['$err' => true]);
                $incl[] = Obj::of(['$err' => true]);
            }
        }
        $out->set('proofs', $proofs);
        $out->set('incl', $incl);
        $batches = [];
        foreach ($spec->get('batches') ?? [] as $b) {
            try {
                $bt = $log->nextBatch($b->get('from'), $b->get('max'), $now);
                $from = (int)$b->get('from')->float();
                $st = Obj::of(['next' => $from, 'lastCommit' => $from === 0 ? '' : Grants::recordCommit($recs[$from - 1])]);
                $tampered = $bt;
                $r = $bt->get('records');
                if ($r !== []) {
                    $first = Grants::copy($r[0]);
                    $first->set('at', 1);
                    $tampered = Grants::copy($bt);
                    $tampered->set('records', [$first, ...array_slice($r, 1)]);
                }
                $batches[] = Obj::of(['bt' => $bt, 'verdict' => K3::verifyBatch($bt, $st, $signer), 'tampered' => K3::verifyBatch($tampered, $st, $signer),
                    'wrong' => K3::verifyBatch($bt, $st, self::pub('zz'))]);
            } catch (\Throwable) {
                $batches[] = Obj::of(['$err' => true]);
            }
        }
        $out->set('batches', $batches);
        return $out;
    }

    private static function replayScenario(Obj $spec): Obj
    {
        $dec = static fn(Obj $t): \Closure => static fn($i) => is_string($i) ? $t->get($i) : null;
        $rev = $spec->get('revT');
        return Obj::of([
            'diff' => Grants::semanticDiff($spec->get('cases'), $dec($spec->get('oldT')), $dec($spec->get('newT'))),
            'audit' => Grants::auditReplay($spec->get('records'), $spec->get('cases'), static fn($i, $r) => $rev->get(Js::str($i) . '@' . Js::str($r))),
        ]);
    }

    private static function freshScenario(Obj $spec): array
    {
        $iss = new FreshAtIssuer(self::sk($spec->get('label')), $spec->get('scope'), $spec->get('init'));
        $out = [];
        $last = null;
        foreach ($spec->get('steps') as $s) {
            try {
                switch ($s->get('op')) {
                    case 'advance':
                        $last = $iss->advance($s->get('patch'), $s->get('now'));
                        $out[] = $last;
                        break;
                    case 'check':
                        $out[] = $iss->check($s->get('token') === 'last' ? $last : $s->get('token'), $s->get('now'), $s->get('maxAge'));
                        break;
                    case 'current':
                        $out[] = $iss->current();
                        break;
                    case 'tamper':
                        $t = Grants::copy($last);
                        $t->set('policy_revision', (int)$last->get('policy_revision')->float() + 1);
                        $out[] = $iss->check($t, $s->get('now'));
                        break;
                }
            } catch (\Throwable) {
                $out[] = Obj::of(['$err' => true]);
            }
        }
        return $out;
    }

    private static function blueprintScenario(Obj $spec): array
    {
        $reg = new BlueprintRegistry([self::pub('op')], new MemoryBlueprintStore());
        $adm = new AdmissionRegistry();
        $revoked = [];
        $revoker = new class ($revoked) {
            public function __construct(private array &$log)
            {
            }

            public function revoke(array $i): void
            {
                $this->log[] = $i;
            }
        };
        $fresh = new FreshAtIssuer(self::sk('iss'), 'scope', Obj::of(['revocation_epoch' => 0, 'ledger_tree_size' => 0, 'budget_version' => 0, 'policy_revision' => 0, 'policy_digest' => 'pd']));
        $out = [];
        foreach ($spec->get('steps') as $raw) {
            $s = self::resolve($raw);
            try {
                $out[] = match ($s->get('op')) {
                    'accept' => $reg->accept($s->get('bp')),
                    'epoch' => $reg->epoch(),
                    'kill' => Grants::groupKill(self::sk($s->get('label') ?? 'op'), $reg, $s->get('key'), $s->get('now'),
                        Js::truthy($s->get('reason')) ? $s->get('reason') : null, Js::truthy($s->get('revoker')) ? $revoker : null, Js::truthy($s->get('fresh')) ? $fresh : null),
                    'revoked' => $revoked,
                    'admit' => (function () use ($adm, $reg, $s) {
                        $adm->admit($s->get('instance'), $reg->get($s->get('key')), $s->get('until'));
                        return true;
                    })(),
                    'admitRevoke' => $adm->revoke($s->get('instance'), $s->get('key')),
                    'admitCheck' => $adm->checker($s->get('now'))($s->get('instance'), $reg->get($s->get('key'))),
                    default => throw new \InvalidArgumentException('bad op'),
                };
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    /** The informative text of a refusal is not compared, except the separation-of-duties reason: the reference names it exactly. */
    private static function stripMsg(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            return $x->get('code') === 'sod' ? $x->without('message') : $x->without('reason', 'message');
        }
        if (is_array($x) && !array_is_list($x)) {
            unset($x['message']);
            if (($x['code'] ?? null) !== 'sod') {
                unset($x['reason']);
            }
        }
        return $x;
    }

    private static function leaseScenario(Obj $spec): mixed
    {
        foreach ($spec->get('steps') as $raw) {
            if ($raw->get('op') === 'shardRevs') {
                return [Base::SKIP, 'per-shard revocation listing is not part of the PHP registry'];
            }
        }
        $policy = ['authorities' => [self::pub('auth')]];
        $p = $spec->get('policy');
        foreach ($p instanceof Obj ? $p->keys() : [] as $k) {
            $v = $p->get($k);
            $policy[$k] = $v instanceof \Atlas\Pca\Num ? $v->int() : $v;
        }
        $sh = $spec->get('shards');
        $reg = new LeaseRegistry($policy, new MemoryAtomicKv(), ['shards' => $sh === null ? 4 : $sh->int(), 'clock' => static fn(): int => 1_800_000_000_000]);
        $handler = GrantHttp::leaseResourceHandler($reg, static fn($req) => $req->get('who'), static fn() => 1_800_000_000_000);
        $out = [];
        foreach ($spec->get('steps') as $raw) {
            $s = self::resolve($raw);
            try {
                $out[] = match ($s->get('op')) {
                    'http' => (function () use ($handler, $s) {
                        $res = $handler(self::httpReq($s));
                        return Obj::of(['status' => $res['status'], 'body' => $res['body']]); // an HTTP refusal's message is compared: the reference names it (a new lease starts at seq 1)
                    })(),
                    'accept' => self::stripMsg($reg->accept($s->get('lease'), $s->get('chain') ?? [])),
                    'revoke' => $reg->revoke($s->get('rev')),
                    'get' => $reg->current($s->get('id')),
                    'history' => $reg->history($s->get('id')),
                    'renew' => (function () use ($reg, $s) {
                        $vs = $s->get('vetoSeq');
                        $r = Grants::renewLease(self::sk($s->get('label') ?? 'auth'), $reg, $s->get('id'), $s->get('now'), $s->get('increment'), $s->get('just'),
                            $s->get('approvers'), $vs === null ? null : static fn(Obj $c) => (float)\Atlas\Pca\K3Sig::num($c->get('seq')) >= (float)\Atlas\Pca\K3Sig::num($vs), $s->get('chain'));
                        return $r['ok'] ? $r : ['ok' => false, 'code' => $r['code']];
                    })(),
                    'check' => Lease::check($s->get('lease'), $reg, $s->get('now')),
                    default => throw new \InvalidArgumentException('bad op'),
                };
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    private static function shadowScenario(Obj $spec): Obj
    {
        $log = new ShadowLog(self::sk($spec->get('label')));
        $T = static fn(Obj $t): \Closure => static function ($i) use ($t) {
            $d = is_string($i) ? $t->get($i) : null;
            if ($d === 'throw') {
                throw new \RuntimeException('boom');
            }
            return $d === 'junk' ? 'weird' : $d;
        };
        $cands = $spec->get('cands');
        $runs = [];
        foreach ($spec->get('obs') as $ob) {
            $r = Shadow::runShadow($ob->get('input'), $T($spec->get('enforcedT')),
                array_map(static fn(Obj $c) => ['digest' => $c->get('digest'), 'decide' => $T($c->get('T'))], $cands));
            $runs[] = ['decision' => $r['decision'], 'shadow' => $r['shadow']];
            foreach ($r['shadow'] as $oc) {
                $log->observe($spec->get('enforcedDigest'), $ob->get('action_digest'), $r['decision'], $oc, $ob->get('at'));
            }
        }
        $out = Obj::of(['runs' => $runs, 'diffs' => new Obj()]);
        $stats = new Obj();
        foreach ($cands as $c) {
            $stats->set($c->get('digest'), $log->stats($c->get('digest')));
            $out->get('diffs')->set($c->get('digest'), $log->diffs($c->get('digest')));
        }
        $out->set('stats', $stats);
        $verify = [];
        foreach ($out->get('diffs')->keys() as $dk) {
            foreach ($out->get('diffs')->get($dk) as $d) {
                $bad = Grants::copy($d);
                $bad->set('sig', substr($d->get('sig'), 1) . 'A');
                $late = Grants::copy($d);
                $late->set('at', (int)K3Sig::num($d->get('at')) + 1);
                $verify[] = [Shadow::verifyShadowDiff($d, $log->signer()), Shadow::verifyShadowDiff($d), Shadow::verifyShadowDiff($d, self::pub('zz')),
                    Shadow::verifyShadowDiff($bad, $log->signer()), Shadow::verifyShadowDiff($late)];
            }
        }
        $out->set('verify', $verify);
        $out->set('signer', $log->signer());
        $g = $spec->get('gate');
        if ($g instanceof Obj) {
            $principals = array_map(self::pub(...), $g->get('principals') ?? []);
            $explanations = array_map(static fn(Obj $e) => Shadow::signWideningExplanation(self::sk($e->get('label')),
                Obj::of(['shadow_digest' => $e->get('shadow_digest'), 'action_digest' => $e->get('action_digest'), 'reason_digest' => $e->get('reason_digest')])), $g->get('explain') ?? []);
            $a = $g->get('approval');
            $approval = $a instanceof Obj ? Shadow::signPromotionApproval(self::sk($a->get('label')),
                Obj::of(['shadow_digest' => $a->get('shadow_digest'), 'enforced_digest' => $a->get('enforced_digest'), 'at' => $a->get('at')])) : null;
            $out->set('explanations', $explanations);
            $out->set('approval', $approval);
            $opts = $g->get('options');
            $o = Grants::copy($opts);
            $o->set('principals', $opts->get('principals') ?? $principals);
            $o->set('explanations', $opts->get('explanations') ?? $explanations);
            if ($approval !== null) {
                $o->set('approval', $approval);
            }
            $out->set('gate', Shadow::promotionGate($log, $o));
            $p = $spec->get('promote');
            if ($p instanceof Obj) {
                try {
                    $gate = $p->get('useGate') === false ? ['ok' => false, 'code' => 'bad_input', 'reason' => 'x'] : $out->get('gate');
                    $out->set('promoted', Shadow::promoteShadow($p->get('enforced'), $p->get('candidate'), $gate, $p->get('now')));
                } catch (\Throwable) {
                    $out->set('promoted', Obj::of(['$err' => true]));
                }
            }
        }
        return $out;
    }

    private static function listScenario(Obj $spec): array
    {
        $n = static fn($x): int => (int)K3Sig::num($x);
        $acc = new WindowReadAccumulator($spec->get('cap'), $spec->get('windowMs'));
        $universe = $spec->get('universe');
        $pageOf = static function (array $list, array $q) use ($spec, $n): array {
            $idx = isset($q['cursor']) ? (int)$q['cursor'] : 0;
            $r = ['objects' => array_slice($list, $idx, $q['limit'] + ($spec->get('overfetch') === true ? 3 : 0))];
            if ($idx + $q['limit'] < count($list)) {
                $r['next'] = (string)($idx + $q['limit']);
            } elseif ($spec->get('emptyNext') === true) {
                $r['next'] = '';
            }
            return $r;
        };
        $cand = new class ($pageOf, $universe) {
            public function __construct(private readonly \Closure $f, private readonly array $u)
            {
            }

            public function page(array $q): array
            {
                return ($this->f)($this->u, $q);
            }
        };
        $rs = $spec->get('relation');
        $allowed = $rs instanceof Obj ? ($rs->get('allowed') ?? []) : [];
        $listed = $rs instanceof Obj ? ($rs->get('listed') ?? $universe) : $universe;
        $rel = $rs instanceof Obj && $rs->get('useList') === true
            ? new class ($allowed, $pageOf, $listed) {
                public function __construct(private readonly array $a, private readonly \Closure $f, private readonly array $l)
                {
                }

                public function check(array $q): bool
                {
                    return in_array($q['object'], $this->a, true);
                }

                public function listObjects(array $q): array
                {
                    return ($this->f)($this->l, $q);
                }
            }
            : new class ($allowed) {
                public function __construct(private readonly array $a)
                {
                }

                public function check(array $q): bool
                {
                    return in_array($q['object'], $this->a, true);
                }
            };
        $permitted = $spec->get('permitted');
        $out = [];
        $cursor = null;
        for ($p = 0; $p < $n($spec->get('pages')); $p++) {
            $tp = $spec->get('tamper');
            $t = $tp instanceof Obj && $n($tp->get('page')) === $p ? $tp : null;
            $tg = static fn(string $k, mixed $d): mixed => $t !== null && $t->has($k) ? $t->get($k) : $d;
            try {
                $cands = $rs instanceof Obj && $rs->get('asCandidates') === true ? ListAuthorized::candidatesFromRelation($rel, $spec->get('subject'), $rs->get('name')) : $cand;
                $page = ['limit' => $tg('limit', $spec->get('limit'))];
                if (!($t !== null && $t->get('dropCursor') === true) && $cursor !== null) {
                    $page['cursor'] = $tg('cursor', $cursor);
                }
                $o = ['subject' => $tg('subject', $spec->get('subject')), 'resourceType' => $spec->get('type'),
                    'permits' => static fn($x) => $permitted === null || in_array($x, $permitted, true), 'candidates' => $cands,
                    'filterId' => $tg('filterId', $spec->get('filterId')), 'policyDigest' => $spec->get('policyDigest'), 'freshAtDigest' => $spec->get('freshAt'),
                    'page' => $page, 'reads' => $acc, 'now' => 1_800_000_000_000 + $p * ($spec->get('nowStep') === null ? 1 : $n($spec->get('nowStep'))),
                    'signingSecret' => self::sk($tg('label', $spec->get('label')))];
                if ($spec->get('maxScan') !== null) {
                    $o['maxScan'] = $n($spec->get('maxScan'));
                }
                if ($rs instanceof Obj) {
                    $o['relation'] = ['source' => $rel, 'relation' => $tg('relation', $rs->get('name'))];
                }
                $r = ListAuthorized::listAuthorized($o);
                $out[] = $r;
                $cursor = $r->get('next_cursor');
            } catch (\Throwable $e) {
                $out[] = self::err($e);
                if ($t === null) {
                    break;
                }
            }
        }
        return $out;
    }

    private static function windowAcc(mixed $cap, mixed $win, array $ops): array
    {
        $a = new WindowReadAccumulator($cap, $win);
        return array_map(static fn(Obj $x) => $a->charge($x->get('key'), $x->get('units'), $x->get('now')), $ops);
    }

    private static function httpReq(Obj $s): Obj
    {
        $r = new Obj();
        foreach (['method', 'path', 'query', 'body', 'who'] as $k) {
            if ($s->has($k)) {
                $r->set($k, $s->get($k));
            }
        }
        return $r;
    }

    private static function grantScenario(Obj $spec): Obj
    {
        $store = new MemoryGrantStore();
        $events = [];
        $ctr = ['grant' => 0, 'need' => 0];
        $svc = new GrantService([
            'store' => $store, 'now' => static fn() => 1_800_000_000_000,
            'newId' => static function (string $kind) use (&$ctr): string {
                $ctr[$kind]++;
                return ($kind === 'grant' ? 'g_' : 'n_') . $ctr[$kind];
            },
            'providers' => $spec->get('providers') === true ? [
                'usage' => static fn(Obj $g) => Obj::of(['rev' => $g->get('rev')]), 'remaining_budget' => static fn() => Obj::of(['left' => 5]),
                'residual' => static fn(Obj $g) => Obj::of(['id' => $g->get('id')])] : null,
            'verifyStepUp' => $spec->get('stepUp') === true ? static fn($ref) => $ref === 'ok-step' : null,
            'onRevoke' => static function (array $ids, string $scope, Obj $root) use (&$events): void {
                $events[] = Obj::of(['revoked' => $ids, 'scope' => $scope, 'root' => $root->get('id')]);
            },
            'onChange' => static function (string $kind, Obj $g) use (&$events): void {
                $events[] = Obj::of(['change' => $kind, 'id' => $g->get('id'), 'rev' => $g->get('rev')]);
            },
            'validateNeed' => $spec->get('validateNeed') === true ? static fn(Obj $nd) => $nd->get('verb') === 'forbidden' ? 'verb not allowed' : null : null,
        ]);
        $handler = GrantHttp::grantResourceHandler($svc, static fn($req) => $req->get('who'));
        $sec = static fn(string $by): KeyPair => self::sk(['principal' => '$P', 'holder' => '$A', 'wrongkey' => '$X'][$by]);
        $out = [];
        foreach ($spec->get('steps') as $raw) {
            $s = self::resolve($raw);
            try {
                $by = $s->get('by');
                switch ($s->get('op')) {
                    case 'register':
                        $r = $svc->register($s->get('grant'));
                        break;
                    case 'list':
                        $r = $svc->list($s->get('filter') ?? new Obj());
                        break;
                    case 'inspect':
                        $r = $svc->inspect($s->get('id'));
                        break;
                    case 'amend':
                        $g = $svc->inspect($s->get('id'));
                        $req = Obj::of(['action' => $s->get('action'), 'authority' => $s->get('authority')]);
                        if ($by !== 'none') {
                            $req->set('signed_by', Js::truthy($s->get('signed_by')) ? $s->get('signed_by') : ($by === 'holder' ? 'holder' : 'principal'));
                            $req->set('sig', Grants::signBody(K3::GRANT_AMEND_DOMAIN, K3::amendMessage($g, $s->get('action'), $s->get('authority')), $sec($by)));
                        }
                        if (Js::truthy($s->get('stepUp'))) {
                            $req->set('step_up_ref', $s->get('stepUp'));
                        }
                        $r = $svc->amend($s->get('id'), $req);
                        break;
                    case 'revoke':
                        $g = $svc->inspect($s->get('id'));
                        $auth = $by === 'admin' ? ['admin' => true] : ($by === 'noauth' ? []
                            : ['sig' => Grants::signBody(K3::GRANT_REVOKE_DOMAIN, K3::grantRevokeMessage($g->get('id'), $s->get('scope')), $sec($by))]);
                        $r = $svc->revoke($s->get('id'), $s->get('scope'), $auth);
                        break;
                    case 'needs':
                        $r = $svc->requestNeeds($s->get('id'), $s->get('needs'));
                        break;
                    case 'approve':
                        $nid = $svc->needGrantId($s->get('needId'));
                        $g = $svc->inspect($nid);
                        $sig = Grants::signBody(K3::NEED_APPROVE_DOMAIN, K3::needApproveMessage(Obj::of(['id' => $s->get('needId'), 'grant_id' => $nid]), $g->get('rev'), $s->get('approved')), $sec($by));
                        $r = $svc->approveNeeds($s->get('needId'), $s->get('approved'), $sig, $s->get('stepUp'));
                        break;
                    case 'deny':
                        $svc->denyNeeds($s->get('needId'));
                        $r = null;
                        break;
                    case 'http':
                        $r = $handler(self::httpReq($s));
                        break;
                    default:
                        throw new \InvalidArgumentException('bad op');
                }
                $out[] = $r;
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        $grants = $store->list();
        usort($grants, static fn(Obj $a, Obj $b): int => strcmp((string)mb_convert_encoding($a->get('id'), 'UTF-16BE', 'UTF-8'), (string)mb_convert_encoding($b->get('id'), 'UTF-16BE', 'UTF-8')));
        return Obj::of(['steps' => $out, 'events' => $events, 'grants' => $grants]);
    }

    private static function admit(mixed $bp, mixed $e): array
    {
        return Grants::admitWithEvidence($bp, static function () use ($e) {
            if ($e instanceof Obj && $e->get('$throw') === true) {
                throw new \TypeError('boom');
            }
            return $e;
        });
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'signerOf' => fn(array $a) => Grants::signerOf(self::sk($a[0])),
            'signBody' => fn(array $a) => Grants::signBody($a[0], $a[1], self::sk($a[2])),
            'verifyBody' => fn(array $a) => Grants::verifyBody($a[0], $a[1], $a[2], $a[3]),
            'signLease' => fn(array $a) => Grants::signLease(self::sk($a[0]), $a[1]),
            'signLeaseUnsafeOverCap' => fn(array $a) => Grants::signLeaseUnsafeOverCap(self::sk($a[0]), $a[1]),
            'signLeaseRevocation' => fn(array $a) => Grants::signLeaseRevocation(self::sk($a[0]), $a[1]),
            'signBlueprint' => fn(array $a) => Grants::signBlueprint(self::sk($a[0]), $a[1]),
            'signBreakGlass' => fn(array $a) => Grants::signBreakGlass(self::sk($a[0]), $a[1]),
            'signBreakGlassReview' => fn(array $a) => Grants::signBreakGlassReview(self::sk($a[0]), $a[1]),
            'signBundle' => fn(array $a) => Grants::signBundle($a[0], self::sk($a[1])),
            'assembleBundle' => fn(array $a) => Grants::assembleBundle($a[0], $a[1]),
            'maskRecord' => fn(array $a) => Grants::maskRecord($a[0], $a[1]),
            'mergeFreshAt' => fn(array $a) => Grants::mergeFreshAt($a[0], $a[1]),
            'gateDecision' => fn(array $a) => Grants::gateDecision($a[0], $a[1]),
            'logScenario' => fn(array $a) => self::logScenario($a[0]),
            'replayScenario' => fn(array $a) => self::replayScenario($a[0]),
            'freshScenario' => fn(array $a) => self::freshScenario($a[0]),
            'blueprintScenario' => fn(array $a) => self::blueprintScenario($a[0]),
            'leaseScenario' => fn(array $a) => self::leaseScenario($a[0]),
            'admitWithEvidence' => fn(array $a) => self::admit($a[0], $a[1]),
            'shadowScenario' => fn(array $a) => self::shadowScenario($a[0]),
            'listScenario' => fn(array $a) => self::listScenario($a[0]),
            'windowAcc' => fn(array $a) => self::windowAcc($a[0], $a[1], $a[2]),
            'grantScenario' => fn(array $a) => self::grantScenario($a[0]),
        ]);
    }
}
