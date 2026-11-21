<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/GoalSign.php';
require_once __DIR__ . '/GoalPrecedentLog.php';

/**
 * Progressive authorization. Widening is only by an escalation request answered by a principal-signed escalation answer. A verified
 * answer becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered action's exact
 * quantities as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation.
 * P1 the allow set grows only by cells with a valid principal signature bound to the policy digest; P2 no replay of an answer onto
 * another policy digest, cell or beyond the signed ceiling; P3 a Deny is never turned into Allow (precedents act only on Escalate);
 * P4 Escalate never becomes Allow implicitly. NOT covered by any signature: the relation facts (`rels`) and the log itself (the
 * integrity of the head is the verifier's to anchor).
 */
final class GoalPrecedent
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    private static function unitKey(mixed $q): string
    {
        $u = self::g($q, 'u');
        return self::g($u, 'k') === 'money' ? 'money:' . AnalyzerJs::jsStr(self::g($u, 'ccy')) : AnalyzerJs::jsStr(self::g($u, 'k'));
    }

    /** Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action. */
    public static function ceilingsOf(mixed $params): Obj
    {
        $out = new Obj();
        foreach (GoalJs::okeys($params) as $k) {
            $v = GoalJs::kget($params, $k);
            if (self::g($v, 'k') === 'q') {
                $out->set($k . '|' . self::unitKey(self::g($v, 'q')), self::g(self::g($v, 'q'), 'n'));
            }
        }
        return $out;
    }

    /** The case a precedent answers: the action the principal saw with its plaintext params, and the verifier's own facts. */
    public static function caseOf(mixed $a): Obj
    {
        $act = self::g(self::g($a, 'pcactn'), 'action');
        return Obj::of(['act' => GoalExamples::mkAct(self::g($act, 'verb'), self::g($act, 'resource'), self::g($a, 'params')), 'rels' => self::g($a, 'rels')]);
    }

    public static function signRevocation(mixed $p, mixed $secret): Obj
    {
        return GoalSign::signPayload('precedent-revocation', $p, $secret);
    }

    /** The answer body for a request: bind it to the request's exact (policy, action, history head); sign it as an escalation answer. */
    public static function answerBodyFor(mixed $req, mixed $o): Obj
    {
        return AnalyzerJs::uobj([
            'v' => 1, 'kind' => 'pca-escalation-answer', 'principal' => self::g($o, 'principal'), 'policy_digest' => self::g($req, 'policy_digest'),
            'action_digest' => self::g($req, 'action_digest'), 'history_head' => self::g($req, 'history_head'), 'decision' => self::g($o, 'decision'),
            'iat' => self::g($o, 'iat'), 'expires_at' => self::g($o, 'expires_at'), 'nonce' => self::g($o, 'nonce'),
        ]);
    }

    /** `x ?? null`. */
    public static function nz(mixed $x): mixed
    {
        return $x instanceof Undef ? null : $x;
    }

    /** The digest an entry commits to (every member but `digest`). */
    public static function entryDigest(Obj $e): string
    {
        $answered = self::nz(AnalyzerJs::jget($e, 'answered'));
        if (AnalyzerJs::truthy($answered)) {
            $answered = AnalyzerJs::spread($answered);
            $answered->set('lastCounter', self::nz(AnalyzerJs::jget($answered, 'lastCounter')));
        } else {
            $answered = null;
        }
        return Pca::hashCanonical(Obj::of([
            'd' => 'atlas-pca/goal-precedent-entry/v1', 'seq' => self::nz(AnalyzerJs::jget($e, 'seq')), 'prev' => self::nz(AnalyzerJs::jget($e, 'prev')),
            'kind' => self::nz(AnalyzerJs::jget($e, 'kind')), 'answer' => self::nz(AnalyzerJs::jget($e, 'answer')), 'answered' => $answered,
            'cell' => self::nz(AnalyzerJs::jget($e, 'cell')), 'ceilings' => self::nz(AnalyzerJs::jget($e, 'ceilings')),
            'revocation' => self::nz(AnalyzerJs::jget($e, 'revocation')),
        ]));
    }

    /** Policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a tampered log fails closed. */
    public static function authorizeWithPrecedents(mixed $goal, mixed $ont, mixed $policyDigest, GoalPrecedentLog $log, mixed $c, mixed $now): Obj
    {
        $base = self::g(GoalExamples::decideCase($goal, $ont, $c), 'decision');
        if ($base !== 'escalate') {
            return Obj::of(['decision' => $base, 'via' => 'policy']);
        }
        $space = GoalExamples::buildSpace([$goal]);
        if (!$log->verifyChain($space)) {
            return Obj::of(['decision' => 'escalate', 'via' => 'policy']);
        }
        $hit = $log->lookup($policyDigest, $space, $c, $now);
        if ($hit === null) {
            return Obj::of(['decision' => 'escalate', 'via' => 'policy']);
        }
        return Obj::of(['decision' => $hit->get('decision') === 'allow' ? 'allow' : 'deny', 'via' => 'precedent', 'precedent' => $hit->get('entry')]);
    }
}
