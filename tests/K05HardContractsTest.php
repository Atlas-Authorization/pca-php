<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Sign;
use Atlas\Pca\ContractEnforcer;
use Atlas\Pca\Contracts;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\TestCase;

/** contracts-vectors.json: validate, check, advance, verify and the durable enforcer. */
final class K05HardContractsTest extends TestCase
{
    private static function rows(array $evaluated): array
    {
        return array_map(static function (Obj $e): array {
            $o = [];
            foreach ($e->keys() as $k) {
                $o[$k] = $e->get($k);
            }
            return $o;
        }, $evaluated);
    }

    /** @return array<string, float> */
    private static function floats(mixed $o): array
    {
        $out = [];
        if ($o instanceof Obj) {
            $keys = $o->keys();
            sort($keys);
            foreach ($keys as $k) {
                $out[$k] = Prohibitions::fin($o->get($k));
            }
        }
        return $out;
    }

    public function testValidateCheckVerifyVectors(): void
    {
        $f = Vectors::load('contracts-vectors.json');
        $this->assertGreaterThanOrEqual(21, count($f->get('validate')));
        foreach ($f->get('validate') as $v) {
            $this->assertSame($v->get('expect')->get('problems'), Contracts::validateContract($v->get('contract')), $v->get('name'));
        }
        foreach ($f->get('check') as $v) {
            $n = $v->get('name');
            $r = Contracts::check($v->get('action'), $v->get('contract'), $v->get('state'));
            $x = $v->get('expect');
            $this->assertSame($x->get('ok'), $r['ok'], "$n ok");
            $this->assertSame($x->get('violated'), $r['violated'], "$n violated");
            $this->assertSame($x->get('reasons'), $r['reasons'], "$n reasons");
            $this->assertSame(self::rows($x->get('evaluated')), self::rows($r['evaluated']), "$n evaluated");
        }
        foreach ($f->get('verify') as $v) {
            $x = $v->get('expect');
            $r = ($v->has('principal') ? Contracts::verifyContract($v->get('contract'), $v->get('principal')) : Contracts::verifyContract($v->get('contract')));
            $this->assertSame($x->get('ok'), $r['ok'], $v->get('name'));
            if ($x->has('reason')) {
                $this->assertSame($x->get('reason'), $r['reason'], $v->get('name'));
            }
        }
    }

    public function testAdvanceVectors(): void
    {
        $f = Vectors::load('contracts-vectors.json');
        foreach ($f->get('advance') as $v) {
            $n = $v->get('name');
            $st = Prohibitions::emptyState(Prohibitions::fin($v->get('genesis_now')));
            foreach ($v->get('steps') as $i => $step) {
                $o = [];
                $opt = $step->get('options');
                if ($opt instanceof Obj) {
                    if ($opt->has('now')) {
                        $o['now'] = Prohibitions::fin($opt->get('now'));
                    }
                    if ($opt->has('expectedSeq')) {
                        $o['expectedSeq'] = Prohibitions::fin($opt->get('expectedSeq'));
                    }
                    if ($opt->get('stale_digest_of_genesis') === true) {
                        $o['expectedStateDigest'] = Prohibitions::stateDigest(Prohibitions::emptyState(Prohibitions::fin($v->get('genesis_now'))));
                    }
                }
                $r = Contracts::advance($st, $step->get('action'), $v->get('contract'), $o);
                if ($r['ok']) {
                    $st = $r['next'];
                }
                $x = $step->get('expect');
                $m = "$n step $i";
                $this->assertSame($x->get('ok'), $r['ok'], "$m ok");
                $this->assertSame($x->get('decidedBy'), $r['decidedBy'], "$m decidedBy");
                $this->assertSame($x->get('violated'), $r['violated'], "$m violated");
                $this->assertSame($x->get('reasons'), $r['reasons'], "$m reasons");
                $this->assertSame(Prohibitions::fin($x->get('seq')), Prohibitions::fin($r['next']->get('seq')), "$m seq");
                $this->assertSame(self::floats($x->get('deadlines')), self::floats($r['next']->get('deadlines')), "$m deadlines");
                $lk = $r['next']->get('latched')->keys();
                sort($lk);
                $this->assertSame($x->get('latched'), $lk, "$m latched");
                $this->assertSame($x->get('state_digest'), Prohibitions::stateDigest($r['next']), "$m state digest");
            }
        }
    }

    public function testEnforcerVectors(): void
    {
        $rows = Vectors::load('contracts-vectors.json')->get('enforcer');
        $head = $rows[0];
        $contract = $head->get('contract');
        $key = 'contract/' . $contract->get('id');
        $this->assertGreaterThanOrEqual(8, count($rows));
        foreach (array_slice($rows, 1) as $v) {
            $n = $v->get('name');
            $kv = new MemoryAtomicKv();
            $wall = Prohibitions::fin($head->get('clock'));
            $opts = $v->get('options');
            $e = ContractEnforcer::open($kv, $contract, $head->get('principal'), null, static function () use (&$wall): float { return $wall; },
                !($opts instanceof Obj && $opts->get('latchOnViolation') === false));
            if ($v->has('stored_document')) {
                $doc = Json::canonicalizeLenient($v->get('stored_document'));
                $kv->update($key, static fn(?string $p): string => $doc);
            }
            foreach ($v->get('steps') as $i => $s) {
                $m = "$n step $i";
                $x = $s->get('expect');
                switch ($s->get('op')) {
                    case 'check':
                        $wall = $s->has('wall') ? Prohibitions::fin($s->get('wall')) : Prohibitions::fin($head->get('clock'));
                        $r = $e->check($s->get('action'), $s->has('permitted') ? $s->get('permitted') : true);
                        $this->assertSame([$x->get('allow'), $x->get('reason'), $x->get('violated'), $x->get('reasons'), (int)Prohibitions::fin($x->get('seq'))],
                            [$r['allow'], $r['reason'], $r['violated'], $r['reasons'], $r['seq']], $m);
                        break;
                    case 'peek':
                        $r = $e->peek($s->get('action'));
                        $this->assertSame([$x->get('allow'), $x->get('reason'), $x->get('violated'), $x->get('reasons'), (int)Prohibitions::fin($x->get('seq'))],
                            [$r['allow'], $r['reason'], $r['violated'], $r['reasons'], $r['seq']], $m);
                        break;
                    case 'state':
                        $r = $e->state();
                        $this->assertSame([Prohibitions::fin($x->get('seq')), Prohibitions::fin($x->get('now')), $x->get('latched'), $x->get('state_digest')],
                            [Prohibitions::fin($r['state']->get('seq')), Prohibitions::fin($r['state']->get('now')), $r['latched'], Prohibitions::stateDigest($r['state'])], $m);
                        break;
                    default:
                        $this->assertSame($x->get('cleared'), $e->reset($s->get('sig')), $m);
                }
            }
        }
        // a reset signed for another contract id / key does not clear
        $kv = new MemoryAtomicKv();
        $e = ContractEnforcer::open($kv, $contract, $head->get('principal'), null, static fn(): float => Prohibitions::fin($head->get('clock')));
        $e->check(Sign::n(['action' => ['verb' => 'delete', 'resource' => '/r']]));
        $this->assertFalse($e->reset(Contracts::signContractReset(new KeyPair(str_repeat("\x07", 32)), $contract->get('id'), 0)));
    }

    public function testSignContractAndOpenRefusals(): void
    {
        $kp = KeyPair::generate();
        $c = Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [['id' => 'a', 'kind' => 'never', 'p' => ['verb' => 'x']]]]);
        $sc = Contracts::signContract($c, $kp);
        $this->assertSame(['ok' => true], Contracts::verifyContract($sc, $kp->public));
        try {
            ContractEnforcer::open(new MemoryAtomicKv(), $sc, '');
            $this->fail('empty principal');
        } catch (\Atlas\Pca\ContractEnforcerError $e) {
            $this->assertSame('ContractEnforcer: a pinned principal is required', $e->getMessage());
        }
        try {
            ContractEnforcer::open(new MemoryAtomicKv(), $sc, KeyPair::generate()->public);
            $this->fail('wrong principal');
        } catch (\Atlas\Pca\ContractEnforcerError $e) {
            $this->assertSame('ContractEnforcer: contract refused: principal mismatch', $e->getMessage());
        }
        $bad = Sign::n(['version' => 1, 'principal' => $kp->public, 'clauses' => [['id' => 'a', 'kind' => 'bogus']]]);
        $this->expectException(\InvalidArgumentException::class);
        Contracts::signContract($bad, $kp);
    }
}
