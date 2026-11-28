<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalPrecedent.php';
require_once __DIR__ . '/../src/GoalPrecedentLog.php';
require_once __DIR__ . '/../src/GoalExamples.php';

use Atlas\Pca\GoalExamples;
use Atlas\Pca\GoalPrecedent;
use Atlas\Pca\GoalPrecedentLog;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Group 36a mutation kills for src/GoalPrecedentLog.php: every chain check refuses on its own (each tamper re-seals the entry digest so
 * only the targeted check can catch it), the history counter bound, and the live-precedent scan. Built from the reference's flow/3
 * (append an allow answer, revoke it, append a deny answer) in test-data/ref-goal-precedent.json.gz.
 */
final class RestSurvivorKill36aGoalPrecedentLogTest extends TestCase
{
    /** @return list<mixed> [goal, ont, grant, principals, steps] */
    private static function flow3(): array
    {
        for ($k = 0; ; $k++) {
            $cs = Base::cases('ref-goal-precedent.json.gz', 'flow', $k);
            if ($cs === []) {
                break;
            }
            foreach ($cs as $c) {
                if ($c->get('name') === 'flow/3') {
                    return $c->get('args');
                }
            }
        }
        throw new \RuntimeException('flow/3 is missing from ref-goal-precedent.json.gz');
    }

    /**
     * The log after the given flow/3 steps (each must succeed).
     * @param list<int> $steps @return array{0:GoalPrecedentLog,1:Obj,2:list<Obj>}
     */
    private static function logAfter(array $steps): array
    {
        [$goal, , $grant, $principals, $all] = self::flow3();
        $log = new GoalPrecedentLog($principals);
        $space = GoalExamples::buildSpace([$goal]);
        foreach ($steps as $i) {
            $s = $all[$i];
            $r = $s->get('op') === 'append' ? $log->append($s->get('answer'), $s->get('answered'), $grant, $space, $s->get('now')) : $log->revoke($s->get('rev'));
            self::assertTrue($r->get('ok'), "flow/3 step $i");
        }
        return [$log, $space, $all];
    }

    private static function withMember(Obj $o, string $k, mixed $v): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $x) {
            $c->set($x, $o->get($x));
        }
        $c->set($k, $v);
        return $c;
    }

    /** The entry with `$k` replaced and its digest recomputed, so the hash chain itself still holds. */
    private static function resealed(Obj $e, string $k, mixed $v): Obj
    {
        $t = self::withMember($e, $k, $v);
        $t->set('digest', GoalPrecedent::entryDigest($t));
        return $t;
    }

    /** An answer whose signature does not verify under its pinned principal breaks the chain, even with the digest re-sealed. */
    public function testChainRefusesAnAnswerWithABadSignature(): void
    {
        [$log, $space, $all] = self::logAfter([0]);
        self::assertTrue($log->verifyChain($space));
        $e = $log->entries[0];
        $forged = self::withMember($e->get('answer'), 'sig', $all[4]->get('answer')->get('sig')); // a real signature, over the deny answer
        $log->entries = [self::resealed($e, 'answer', $forged)];
        self::assertFalse($log->verifyChain($space));
    }

    /** An entry out of sequence breaks the chain even when its prev link and digest are right. */
    public function testChainRefusesAWrongSequenceNumber(): void
    {
        [$log, $space] = self::logAfter([0]);
        $log->entries = [self::resealed($log->entries[0], 'seq', 5)];
        self::assertFalse($log->verifyChain($space));
    }

    /** An answer filed under a cell other than the one its case derives breaks the chain. */
    public function testChainRefusesAnAnswerUnderAnotherCell(): void
    {
        [$log, $space] = self::logAfter([0]);
        $log->entries = [self::resealed($log->entries[0], 'cell', '{"other":1}')];
        self::assertFalse($log->verifyChain($space));
    }

    /** A revocation whose signature does not verify breaks the chain, even with the digest re-sealed. */
    public function testChainRefusesARevocationWithABadSignature(): void
    {
        [$log, $space] = self::logAfter([0, 1]);
        self::assertTrue($log->verifyChain($space));
        $r = $log->entries[1];
        $forged = self::withMember($r->get('revocation'), 'sig', $log->entries[0]->get('answer')->get('sig'));
        $log->entries[1] = self::resealed($r, 'revocation', $forged);
        self::assertFalse($log->verifyChain($space));
    }

    /** An entry that cannot even be read fails the chain closed (false), never true. */
    public function testChainFailsClosedOnAnUnreadableEntry(): void
    {
        $log = new GoalPrecedentLog([]);
        $log->entries = [null];
        self::assertFalse($log->verifyChain(new Obj()));
    }

    /** The head is the last entry's digest as text (GENESIS for an empty log). */
    public function testHeadIsTheLastDigestAsText(): void
    {
        $log = new GoalPrecedentLog([]);
        self::assertSame(GoalPrecedent::GENESIS, $log->head());
        $log->entries = [Obj::of(['digest' => 5])];
        self::assertSame('5', $log->head());
    }

    /** lastCounter accepts every safe integer up to 2^53 - 1 exactly and refuses a fraction or anything beyond. */
    public function testLastCounterIsASafeInteger(): void
    {
        $m = new \ReflectionMethod(GoalPrecedentLog::class, 'lastCounter');
        self::assertNull($m->invoke(null, new Obj()));
        self::assertSame(9007199254740991, $m->invoke(null, Obj::of(['lastCounter' => 9007199254740991])));
        foreach ([1.5, 9007199254740992] as $bad) {
            try {
                $m->invoke(null, Obj::of(['lastCounter' => $bad]));
                self::fail("lastCounter $bad was accepted");
            } catch (\InvalidArgumentException $e) {
                self::assertSame('lastCounter is not a safe integer', $e->getMessage());
            }
        }
    }

    /** A revocation newer than a live answer does not hide that answer: the scan skips it and finds the answer below. */
    public function testLookupLooksPastANewerRevocation(): void
    {
        [$log, $space, $all] = self::logAfter([0, 1, 4]);
        $q = $all[2];
        $hit = $log->lookup($q->get('policyDigest'), $space, $q->get('case'), $q->get('now'));
        self::assertNotNull($hit);
        self::assertSame('deny', $hit->get('decision'));
        [, $rev, $deny] = $log->entries;
        $log->entries = [$deny, $rev]; // the revocation (of the allow answer) is now the newest entry
        $hit = $log->lookup($q->get('policyDigest'), $space, $q->get('case'), $q->get('now'));
        self::assertNotNull($hit);
        self::assertSame('deny', $hit->get('decision'));
        self::assertSame($deny, $hit->get('entry'));
    }

    /** A precedent signed over a parameter the current case does not carry does not cover that case. */
    public function testLookupRefusesWhenTheCaseLacksASignedParameter(): void
    {
        [$log, $space, $all] = self::logAfter([0, 1, 4]);
        $q = $all[2];
        $deny = $log->entries[2];
        $log->entries = [self::withMember($deny, 'ceilings', self::withMember($deny->get('ceilings'), 'other|count', 1))];
        self::assertNull($log->lookup($q->get('policyDigest'), $space, $q->get('case'), $q->get('now')));
        $log->entries = [$deny];
        $hit = $log->lookup($q->get('policyDigest'), $space, $q->get('case'), $q->get('now'));
        self::assertNotNull($hit);
        self::assertSame('deny', $hit->get('decision'));
    }
}
