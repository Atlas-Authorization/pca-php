<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/ActionVectors.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;

/**
 * Differential / mutation-kill checks for src/Actions.php. Each oracle below is written independently of the implementation
 * (eight rounds of one-step implication, plain max/union joins, a three-line decision table) and compared on seeded random inputs and
 * on the exact boundaries (esc == / > max_esc and preauth_esc, depth 8 vs 9, subset direction, rev rank, ppm). Messages are compared exactly.
 * Used by ActionsOracleTest (PHPUnit) and conformance-actions.php (plain runner); returns the failures.
 */
final class ActionsOracle
{
    private const REV = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];
    /** @var list<string> */
    private static array $fails = [];

    private static function check(bool $ok, string $what): void
    {
        if (!$ok) {
            self::$fails[] = $what;
        }
    }

    private static function eq(mixed $a, mixed $b, string $what): void
    {
        $x = json_encode($a);
        $y = json_encode($b);
        self::check($x === $y, "$what: got $x, want $y");
    }

    /** @param list<string> $implies */
    private static function trait(string $id, array $implies, array $floor): Obj
    {
        return Obj::of(['id' => $id, 'implies' => $implies, 'floor' => Actions::profObj(Actions::profile($floor)), 'card_phrase' => $id]);
    }

    /** Independent join of plain profile arrays. */
    private static function oJoin(array $a, array $b): array
    {
        return ['risk' => max($a['risk'], $b['risk']), 'rev' => self::REV[$a['rev']] >= self::REV[$b['rev']] ? $a['rev'] : $b['rev'],
            'blast_ppm' => max($a['blast_ppm'], $b['blast_ppm']), 'esc' => max($a['esc'], $b['esc']),
            'caveats' => self::us(array_merge($a['caveats'], $b['caveats'])), 'context' => self::us(array_merge($a['context'], $b['context'])),
            'prules' => self::us(array_merge($a['prules'], $b['prules']))];
    }

    private static function us(array $x): array
    {
        $x = array_values(array_unique($x));
        sort($x, SORT_STRING);
        return $x;
    }

    /** Eight rounds of one-step implication over a registry (the model the proofs reason about). */
    private static function oClosure(array $reg, array $ids): array
    {
        $s = $ids;
        for ($r = 0; $r < 8; $r++) {
            foreach ($s as $i) {
                foreach ($reg[$i]['implies'] as $u) {
                    $s[] = $u;
                }
            }
            $s = self::us($s);
        }
        return self::us($s);
    }

    private static function oFloor(array $reg, array $ids): array
    {
        $f = Actions::profile();
        foreach (self::oClosure($reg, $ids) as $i) {
            $f = self::oJoin($f, $reg[$i]['floor']);
        }
        return $f;
    }

    private static function rank(string $d): int
    {
        return ['deny' => 0, 'escalate' => 1, 'allow' => 2][$d];
    }

    private static function oDecision(array $g, array $ctx, array $p): string
    {
        if ($p['esc'] > $g['max_esc']) {
            return 'deny';
        }
        if (array_diff($p['caveats'], $g['caveats']) !== [] || array_diff($p['context'], $ctx) !== [] || $p['esc'] > $g['preauth_esc']) {
            return 'escalate';
        }
        return 'allow';
    }

    private static function vec(string $id): Obj
    {
        foreach (ActionVectors::cases() as $c) {
            if ($c->get('id') === $id) {
                return $c;
            }
        }
        throw new \RuntimeException("vector $id missing");
    }

    private static function copy(mixed $o): mixed
    {
        return Json::parseLax(IntentV2::canonicalize($o));
    }

    /** @return list<string> */
    public static function run(): array
    {
        self::$fails = [];
        mt_srand(0xA7);
        $core = Actions::coreRegistry();
        $coreIds = array_keys($core);
        sort($coreIds, SORT_STRING);

        // ---- closure / floorOf vs the eight-round oracle, with random valid custom chains and DAGs
        for ($n = 0; $n < 120; $n++) {
            $k = mt_rand(0, 8);
            $defs = [];
            $plain = $core;
            for ($j = 0; $j < $k; $j++) {
                $impl = [];
                if ($j > 0 && mt_rand(0, 2) > 0) {
                    $impl[] = "acme.c" . ($j - 1);
                }
                if (mt_rand(0, 2) === 0) {
                    $impl[] = $coreIds[mt_rand(0, count($coreIds) - 1)];
                }
                $impl = self::us($impl);
                $own = ['risk' => mt_rand(0, 3), 'rev' => array_keys(self::REV)[mt_rand(0, 2)], 'blast_ppm' => mt_rand(0, 4) * 250000, 'esc' => mt_rand(0, 3),
                    'caveats' => mt_rand(0, 1) ? ['window'] : [], 'context' => mt_rand(0, 1) ? ['revocable'] : [], 'prules' => []];
                $fl = Actions::profile($own);
                foreach ($impl as $u) {
                    $fl = self::oJoin($fl, $plain[$u]['floor']); // a trait may only extend what it implies
                }
                $defs[] = self::trait("acme.c$j", $impl, $fl);
                $plain["acme.c$j"] = ['implies' => $impl, 'floor' => $fl];
            }
            $reg = Actions::extendRegistry($core, $defs);
            $all = array_keys($plain);
            $pick = [];
            foreach ($all as $id) {
                if (mt_rand(0, 6) === 0) {
                    $pick[] = $id;
                }
            }
            self::eq(Actions::closure($reg, $pick), self::oClosure($plain, self::us($pick)), "closure#$n");
            self::eq(Actions::floorOf($reg, $pick), self::oFloor($plain, self::us($pick)), "floorOf#$n");
        }

        // ---- implies depth: a chain of 8 is accepted, 9 is refused (and only by the depth rule)
        foreach ([8 => true, 9 => false] as $len => $ok) {
            $defs = [];
            for ($i = 0; $i < $len; $i++) {
                $defs[] = self::trait("acme.d$i", $i < $len - 1 ? ['acme.d' . ($i + 1)] : [], []);
            }
            try {
                Actions::extendRegistry($core, $defs);
                self::check($ok, "depth $len must be refused");
            } catch (ActionKitError $e) {
                self::check(!$ok, "depth $len must be accepted: " . $e->getMessage());
                self::check($e->codeName === 'bad_registry' && str_contains($e->getMessage(), 'depth 9 exceeds 8'), 'depth message: ' . $e->getMessage());
            }
        }
        // a trait below the floor it implies, a cycle, an unknown implied trait, a reused core id
        $mm = $core['pca.money_moving']['floor'];
        $weak = self::trait('acme.weak', ['pca.money_moving'], array_merge($mm, ['risk' => 2]));
        $cases = [
            'weak' => [[$weak], "trait 'acme.weak': floor is below the floor of implied 'pca.money_moving'"],
            'cycle' => [[self::trait('acme.a', ['acme.b'], []), self::trait('acme.b', ['acme.a'], [])], "trait 'acme.a': implies cycle"],
            'unknown' => [[self::trait('acme.a', ['acme.zzz'], [])], "trait 'acme.a' implies unknown trait 'acme.zzz'"],
            'dup' => [[self::trait('acme.a', [], []), self::trait('acme.a', [], [])], "trait 'acme.a' is defined twice"],
        ];
        foreach ($cases as $name => [$defs, $msg]) {
            try {
                Actions::extendRegistry($core, $defs);
                self::$fails[] = "registry $name must be refused";
            } catch (ActionKitError $e) {
                self::eq($e->getMessage(), $msg, "registry $name message");
            }
        }
        // T5 boundary: floor exactly equal to the implied floor is fine
        Actions::extendRegistry($core, [self::trait('acme.eq', ['pca.money_moving'], $mm)]);

        // ---- floorDecision: exact boundaries, then random vs the oracle, then antitone
        $G = fn (array $cv, int $mx, int $pre): Obj => Obj::of(['caveats' => $cv, 'max_esc' => new \Atlas\Pca\Num((string)$mx), 'preauth_esc' => new \Atlas\Pca\Num((string)$pre)]);
        $C = fn (array $cx): Obj => Obj::of(['context' => $cx]);
        $P = fn (int $esc, array $cv = [], array $cx = []): array => Actions::profile(['esc' => $esc, 'caveats' => $cv, 'context' => $cx]);
        self::eq(Actions::floorDecision($G([], 2, 2), $C([]), $P(2)), 'allow', 'esc == max == preauth');
        self::eq(Actions::floorDecision($G([], 2, 1), $C([]), $P(2)), 'escalate', 'esc == max > preauth');
        self::eq(Actions::floorDecision($G([], 2, 2), $C([]), $P(3)), 'deny', 'esc > max');
        self::eq(Actions::floorDecision($G([], 0, 0), $C([]), $P(1)), 'deny', 'esc 1 > max 0');
        self::eq(Actions::floorDecision($G(['a'], 3, 3), $C([]), $P(0, [])), 'allow', 'grant has extra caveats');
        self::eq(Actions::floorDecision($G([], 3, 3), $C(['x']), $P(0, [], [])), 'allow', 'call has extra context');
        self::eq(Actions::floorDecision($G([], 3, 3), $C([]), $P(0, ['window'])), 'escalate', 'caveat missing from the grant');
        self::eq(Actions::floorDecision($G(['window'], 3, 3), $C([]), $P(0, ['window'], ['idempotency'])), 'escalate', 'context missing from the call');
        self::eq(Actions::floorDecision($G(['window'], 3, 3), $C(['idempotency']), $P(0, ['window'], ['idempotency'])), 'allow', 'all present');
        $vocabC = ['amount_cap', 'window', 'count_cap'];
        $vocabX = ['idempotency', 'revocable', 'fresh_revocation'];
        $sub = fn (array $v): array => array_values(array_filter($v, fn () => mt_rand(0, 1) === 1));
        for ($n = 0; $n < 400; $n++) {
            $g = ['caveats' => $sub($vocabC), 'max_esc' => mt_rand(0, 3)];
            $g['preauth_esc'] = mt_rand(0, $g['max_esc']);
            $cx = $sub($vocabX);
            $p1 = Actions::profile(['esc' => mt_rand(0, 3), 'caveats' => $sub($vocabC), 'context' => $sub($vocabX)]);
            $d1 = Actions::floorDecision($G($g['caveats'], $g['max_esc'], $g['preauth_esc']), $C($cx), $p1);
            self::eq($d1, self::oDecision($g, $cx, $p1), "decision#$n");
            $p2 = $p1; // p1 <= p2: raise esc and add a caveat / context
            $p2['esc'] = min(3, $p1['esc'] + mt_rand(0, 1));
            $p2['caveats'] = self::us(array_merge($p1['caveats'], $sub($vocabC)));
            $p2['context'] = self::us(array_merge($p1['context'], $sub($vocabX)));
            $d2 = Actions::floorDecision($G($g['caveats'], $g['max_esc'], $g['preauth_esc']), $C($cx), $p2);
            self::check(self::rank($d2) <= self::rank($d1), "antitone#$n: $d1 -> $d2");
        }

        // ---- leq / join: rev rank and ppm boundaries
        $a = Actions::profile(['rev' => 'rate_limited', 'blast_ppm' => 500000]);
        self::check(Actions::leq($a, Actions::profile(['rev' => 'irreversible', 'blast_ppm' => 500000])), 'leq: rev rises');
        self::check(!Actions::leq(Actions::profile(['rev' => 'irreversible']), $a), 'leq: rev must not fall');
        self::check(Actions::leq($a, $a), 'leq reflexive');
        self::check(!Actions::leq($a, Actions::profile(['rev' => 'rate_limited', 'blast_ppm' => 499999])), 'leq: ppm must not fall by one');
        self::check(!Actions::leq(Actions::profile(['caveats' => ['window']]), Actions::profile()), 'leq: subset direction');
        self::eq(Actions::join($a, Actions::profile(['rev' => 'reversible', 'blast_ppm' => 600000]))['rev'], 'rate_limited', 'join keeps the higher rev');
        self::eq(Actions::join(Actions::profile(['rev' => 'reversible']), $a)['rev'], 'rate_limited', 'join keeps the higher rev (right)');
        self::eq(Actions::join($a, Actions::profile(['blast_ppm' => 600000]))['blast_ppm'], 600000, 'join max ppm');

        // ---- digest / normalize invariance
        $base = self::vec('digest-adv-key-order-and-defaults');
        $def = $base->get('input')->get('def');
        $want = $base->get('expect')->get('digest');
        self::eq(Actions::defDigest($def), $want, 'digest of the vector def');
        $rev = new Obj();
        foreach (array_reverse($def->keys()) as $k) {
            $rev->set($k, $def->get($k));
        }
        self::eq(Actions::defDigest($rev), $want, 'digest under key order');
        $d2 = self::copy($def);
        $d2->set('aliases', array_merge(array_reverse($d2->get('aliases')), []));
        self::eq(Actions::defDigest($d2), $want, 'digest under alias order');
        $d3 = self::copy($def);
        $d3->set('review', Obj::of(['state' => 'unreviewed']));
        $d3->set('since', '9.9.9');
        $d3->set('examples', []);
        self::eq(Actions::defDigest($d3), $want, 'digest ignores review, since and examples');
        $d4 = self::copy($def);
        $d4->set('title', $d4->get('title') . 'x');
        self::check(Actions::defDigest($d4) !== $want, 'digest covers the title');
        $d5 = self::copy($def);
        $d5->set('effects', ['pay', 'update']);
        self::check(Actions::defDigest($d5) !== $want, 'digest covers the effects');
        $n1 = Actions::normalize($def);
        self::eq(IntentV2::canonicalize(Actions::normalize($n1)), IntentV2::canonicalize($n1), 'normalize is idempotent');

        // ---- schemaVerbFloorError: forged floors / dropped traits, exact reasons
        $honest = self::vec('schema-verb-adv-honest')->get('input')->get('verb');
        self::eq(Actions::schemaVerbFloorError($honest, $core), null, 'honest verb');
        $mut = function (callable $f) use ($honest): Obj {
            $v = self::copy($honest);
            $f($v);
            return $v;
        };
        $FL = 'schema_floor_forged: floors are below the floor of the carried traits';
        $num = fn (int $n) => new \Atlas\Pca\Num((string)$n);
        $forged = [
            'esc lowered' => [fn ($v) => $v->get('floors')->set('esc', $num(0)), $FL],
            'esc one below' => [fn ($v) => $v->get('floors')->set('esc', $num(1)), $FL],
            'blast lowered' => [fn ($v) => $v->get('floors')->set('blast_ppm', $num(0)), $FL],
            'blast one below' => [fn ($v) => $v->get('floors')->set('blast_ppm', $num(699999)), $FL],
            'risk lowered' => [fn ($v) => $v->get('floors')->set('risk', $num(2)), $FL],
            'rev lowered' => [fn ($v) => $v->get('floors')->set('rev', 'rate_limited'), $FL],
            'caveat dropped' => [fn ($v) => $v->get('floors')->set('caveats', ['amount_cap']), $FL],
            'context dropped' => [fn ($v) => $v->get('floors')->set('context', ['idempotency']), $FL],
            'prule dropped' => [fn ($v) => $v->get('floors')->set('prules', []), $FL],
            'implied trait dropped' => [fn ($v) => $v->set('traits', array_values(array_filter($v->get('traits'), fn ($t) => $t !== 'pca.money_moving'))), 'schema_traits_forged: missing implied trait pca.money_moving'],
            'irreversible dropped' => [fn ($v) => $v->set('traits', array_values(array_filter($v->get('traits'), fn ($t) => $t !== 'pca.irreversible'))), 'schema_traits_forged: missing implied trait pca.irreversible'],
            'unknown trait' => [fn ($v) => $v->set('traits', array_merge($v->get('traits'), ['pca.zzz'])), 'unknown_trait: unknown trait'],
            'v1 verb' => [fn ($v) => $v->set('floors', null), null],
        ];
        foreach ($forged as $name => [$f, $msg]) {
            if ($name === 'v1 verb') {
                $v = self::copy($honest);
                $o = new Obj();
                foreach ($v->keys() as $k) {
                    if ($k !== 'floors' && $k !== 'traits') {
                        $o->set($k, $v->get($k));
                    }
                }
                self::eq(Actions::schemaVerbFloorError($o, $core), 'schema_floor_forged: not a v2 verb', 'v1 verb refused');
                continue;
            }
            self::eq(Actions::schemaVerbFloorError($mut($f), $core), $msg, "forged: $name");
        }
        // a raised floor is fine (floors may exceed the carried traits' floor)
        self::eq(Actions::schemaVerbFloorError($mut(fn ($v) => $v->get('floors')->set('esc', $num(3))), $core), null, 'raised floors are accepted');

        return self::$fails;
    }
}
