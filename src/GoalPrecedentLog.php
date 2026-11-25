<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Escalation.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/GoalSign.php';
require_once __DIR__ . '/GoalPrecedent.php';

/** The append-only, hash-chained log of principal-answered escalations (see {@see GoalPrecedent}). */
final class GoalPrecedentLog
{
    /** @var list<Obj> */
    public array $entries = [];

    /** `$principals`: the pinned signers allowed to answer and revoke (the verifier's own list). */
    public function __construct(private mixed $principals)
    {
    }

    public function head(): string
    {
        return $this->entries === [] ? GoalPrecedent::GENESIS : (string)AnalyzerJs::jget($this->entries[count($this->entries) - 1], 'digest');
    }

    private function pinFor(mixed $pk): mixed
    {
        foreach (AnalyzerJs::reqList($this->principals) as $p) {
            if (AnalyzerJs::strictEq(is_string($p) ? $p : AnalyzerJs::jget($p, 'pk'), $pk)) {
                return $p;
            }
        }
        return null;
    }

    private static function lastCounter(mixed $answered): ?int
    {
        $lc = GoalPrecedent::nz(AnalyzerJs::jget($answered, 'lastCounter'));
        if ($lc === null) {
            return null;
        }
        $f = Js::num($lc);
        if ($f === null || $f != floor($f) || abs($f) > 9007199254740991) {
            throw new \InvalidArgumentException('lastCounter is not a safe integer');
        }
        return (int)$f;
    }

    /** Everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest. Null = sound. */
    private function answerFault(mixed $answer, mixed $answered): ?string
    {
        if (Escalation::answerShapeError($answer) !== null) {
            return 'malformed answer';
        }
        $pin = $this->pinFor(AnalyzerJs::jget($answer, 'principal'));
        if ($pin === null || !IntentWb::verifyArtifactSig(Escalation::ANSWER_DOMAIN, $answer, $pin)) {
            return 'bad signature';
        }
        $pcactn = AnalyzerJs::jget($answered, 'pcactn');
        if (!AnalyzerJs::strictEq(AnalyzerJs::jget($answer, 'action_digest'), Escalation::actionDigest($pcactn))) {
            return 'answer is bound to another action';
        }
        if (!AnalyzerJs::strictEq(AnalyzerJs::jget($answer, 'history_head'), Escalation::historyHead(self::lastCounter($answered)))) {
            return 'answer is bound to another history state';
        }
        $pd = Pca::paramsDigest(AnalyzerJs::jget($answered, 'params'));
        if (!AnalyzerJs::strictEq($pd, AnalyzerJs::jget(AnalyzerJs::jget($pcactn, 'action'), 'params_digest'))) {
            return 'params do not match the signed action';
        }
        return null;
    }

    /** Recompute the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling under `$space`. */
    public function verifyChain(mixed $space): bool
    {
        try {
            $prev = GoalPrecedent::GENESIS;
            foreach ($this->entries as $i => $e) {
                if (!AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'seq'), $i) || !AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'prev'), $prev)
                    || !AnalyzerJs::strictEq(GoalPrecedent::entryDigest($e), AnalyzerJs::jget($e, 'digest'))) {
                    return false;
                }
                if (AnalyzerJs::jget($e, 'kind') === 'answer') {
                    $answer = AnalyzerJs::jget($e, 'answer');
                    $answered = AnalyzerJs::jget($e, 'answered');
                    if (!AnalyzerJs::truthy($answer) || !AnalyzerJs::truthy($answered) || $this->answerFault($answer, $answered) !== null) {
                        return false;
                    }
                    $ceil = AnalyzerJs::jget($e, 'ceilings');
                    if (!AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'cell'), GoalExamples::cellKey($space, GoalPrecedent::caseOf($answered)))
                        || $ceil instanceof Undef || Js::stringify($ceil) !== Js::stringify(GoalPrecedent::ceilingsOf(AnalyzerJs::jget($answered, 'params')))) {
                        return false;
                    }
                } else {
                    $rev = AnalyzerJs::jget($e, 'revocation');
                    if (!(AnalyzerJs::truthy($rev) && GoalSign::verifyPayload($rev, 'precedent-revocation', $this->principals))) {
                        return false;
                    }
                }
                $prev = AnalyzerJs::jget($e, 'digest');
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function live(mixed $policy, mixed $cell, mixed $now): ?Obj
    {
        $revoked = [];
        foreach ($this->entries as $e) {
            if (AnalyzerJs::jget($e, 'kind') === 'revocation') {
                $revoked[] = AnalyzerJs::jget(AnalyzerJs::jget(AnalyzerJs::jget($e, 'revocation'), 'payload'), 'target_entry');
            }
        }
        for ($i = count($this->entries) - 1; $i >= 0; $i--) {
            $e = $this->entries[$i];
            if (AnalyzerJs::jget($e, 'kind') !== 'answer') {
                continue;
            }
            $a = AnalyzerJs::jget($e, 'answer');
            if (AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'policy_digest'), $policy) && AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'cell'), $cell)
                && AnalyzerJs::jsGt(AnalyzerJs::jget($a, 'expires_at'), $now) && !AnalyzerJs::includes($revoked, AnalyzerJs::jget($e, 'digest'))) {
                return $e;
            }
        }
        return null;
    }

    /**
     * Verify the answer (pinned signer, bound to this grant's policy digest and this exact action and history, unexpired) and record it.
     * Returns `{ok: true, entry}` or `{ok: false, reason}`.
     */
    public function append(mixed $answer, mixed $answered, mixed $grant, mixed $space, mixed $now): Obj
    {
        $pcactn = AnalyzerJs::jget($answered, 'pcactn');
        $v = Escalation::verifyAnswer($answer, $this->principals, [
            'policy_digest' => Escalation::policyDigest($grant), 'action_digest' => Escalation::actionDigest($pcactn),
            'history_head' => Escalation::historyHead(self::lastCounter($answered)),
        ], $now);
        if (!$v['ok']) {
            return Obj::of(['ok' => false, 'reason' => $v['reason']]);
        }
        $fault = $this->answerFault($answer, $answered);
        if ($fault !== null) {
            return Obj::of(['ok' => false, 'reason' => $fault]);
        }
        $cell = GoalExamples::cellKey($space, GoalPrecedent::caseOf($answered));
        $existing = $this->live(AnalyzerJs::jget($answer, 'policy_digest'), $cell, $now);
        if ($existing !== null && !AnalyzerJs::strictEq(AnalyzerJs::jget(AnalyzerJs::jget($existing, 'answer'), 'decision'), AnalyzerJs::jget($answer, 'decision'))) {
            return Obj::of(['ok' => false, 'reason' => 'conflicts with a recorded decision; revoke it first']);
        }
        return Obj::of(['ok' => true, 'entry' => $this->push(['kind' => 'answer', 'answer' => $answer, 'answered' => $answered, 'cell' => $cell,
            'ceilings' => GoalPrecedent::ceilingsOf(AnalyzerJs::jget($answered, 'params'))])]);
    }

    /** Record a principal-signed revocation of a recorded answer. */
    public function revoke(mixed $rev): Obj
    {
        if (!GoalSign::verifyPayload($rev, 'precedent-revocation', $this->principals)) {
            return Obj::of(['ok' => false, 'reason' => 'bad signature']);
        }
        $p = AnalyzerJs::jget($rev, 'payload');
        foreach ($this->entries as $e) {
            if (AnalyzerJs::jget($e, 'kind') === 'answer' && AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'digest'), AnalyzerJs::jget($p, 'target_entry'))
                && AnalyzerJs::strictEq(AnalyzerJs::jget(AnalyzerJs::jget($e, 'answer'), 'policy_digest'), AnalyzerJs::jget($p, 'policy_digest'))
                && AnalyzerJs::strictEq(AnalyzerJs::jget($e, 'cell'), AnalyzerJs::jget($p, 'cell'))) {
                return Obj::of(['ok' => true, 'entry' => $this->push(['kind' => 'revocation', 'revocation' => $rev])]);
            }
        }
        return Obj::of(['ok' => false, 'reason' => 'no such precedent']);
    }

    /** @param array<string,mixed> $e */
    private function push(array $e): Obj
    {
        $base = Obj::of(['seq' => count($this->entries), 'prev' => $this->head()]);
        foreach ($e as $k => $x) {
            if (!($x instanceof Undef)) {
                $base->set($k, $x);
            }
        }
        $entry = AnalyzerJs::copy($base);
        $entry->set('digest', GoalPrecedent::entryDigest($base));
        $this->entries[] = $entry;
        return $entry;
    }

    /** The recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked): `{decision, entry}`. */
    public function lookup(mixed $policyDigest, mixed $space, mixed $c, mixed $now): ?Obj
    {
        $e = $this->live($policyDigest, GoalExamples::cellKey($space, $c), $now);
        if ($e === null) {
            return null;
        }
        $ceil = AnalyzerJs::jget($e, 'ceilings');
        $now2 = GoalPrecedent::ceilingsOf(AnalyzerJs::jget(AnalyzerJs::jget($c, 'act'), 'params'));
        foreach ($now2->keys() as $k) {
            if (AnalyzerJs::jsGt($now2->get($k), AnalyzerJs::nn(AnalyzerJs::jget($ceil, $k), -INF))) { // beyond the signed ceiling
                return null;
            }
        }
        foreach (GoalJs::okeys($ceil) as $k) {
            if (!$now2->has($k)) { // same parameters and units as the signed witness
                return null;
            }
        }
        return Obj::of(['decision' => AnalyzerJs::jget(AnalyzerJs::jget($e, 'answer'), 'decision'), 'entry' => $e]);
    }
}
