<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentJit;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Lazy just-in-time elicitation against the TS reference: test-data/ref-intent-jit.json.gz (visit decisions, cell coordinates, delta
 * cells and predicates, the signed intent_required notice, the wallet check, minted delta grants). The corpus carries "$seed:<label>"
 * placeholders for the site and principal keys: the seed is sha256("atlas-pca-conformance/" + label).
 */
final class RefIntentJitDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-jit.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function key(mixed $s): KeyPair
    {
        return new KeyPair(Base::seedBytes($s));
    }

    private static function mk(mixed $omega, mixed $mapOpts, mixed $observations): IntentLearner
    {
        $l = IntentMapKit::createLearner($omega, $mapOpts);
        foreach ($observations as $x) {
            $l->observe(Obj::of(['verb' => Js::opt($x, 'verb'), 'values' => Js::opt($x, 'values')]), (int)Js::num(Js::opt($x, 'y')), (string)Js::opt($x, 'source'));
        }
        return $l;
    }

    private static function vsOf(mixed $omega, mixed $verb): mixed
    {
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    private static function with(mixed $inp, array $more): Obj
    {
        $o = new Obj();
        foreach ($inp instanceof Obj ? $inp->keys() : [] as $k) {
            $o->set($k, $inp->get($k));
        }
        foreach ($more as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    private static function dig(string $x): string
    {
        return Pca::b64u(hash('sha256', $x, true));
    }

    private static function ceiling(string $name): \Closure
    {
        return match ($name) {
            'all' => static fn() => true,
            'none' => static fn() => false,
            'amountLe60' => static function ($vs, $oc) {
                $a = Js::opt(Js::opt($oc, 'values'), 'action.params.amount');
                return !Js::isNum($a) || Js::num($a) <= 60;
            },
            'notGmail' => static fn($vs, $oc) => Js::opt($oc, 'verb') !== 'gmail.send',
        };
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $P = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'visitScenario' => function (array $a, Obj $c) use ($P) {
                $learner = self::mk($P($a[0]), $P($a[1]), $P($a[2]));
                return RefIntentRound::close(IntentJit::decideVisit(['learner' => $learner, 'lifted' => $P($a[3]), 'conform' => $a[4],
                    'ceilings' => array_map(self::ceiling(...), $a[5]), 'inEffective' => $a[6]]), $c);
            },
            'cellCoords' => fn(array $a) => IntentJit::cellCoords($a[0], $a[1]),
            'cellFromCoords' => fn(array $a) => IntentJit::cellFromCoords($a[0], $a[1]),
            'deltaScenario' => function (array $a) use ($P) {
                $omega = $P($a[0]);
                $prev = self::mk($omega, $P($a[1]), $P($a[2]));
                $next = self::mk($omega, $P($a[1]), array_merge($P($a[2]), $P($a[3])));
                $d = IntentJit::deltaCells($prev, $next);
                $cells = new Obj();
                foreach ($d as $verb => $v) {
                    $cells->set((string)$verb, $v);
                }
                return Obj::of(['cells' => $cells, 'predicates' => IntentJit::deltaPredicates($next->omega, $d)]);
            },
            'requiredScenario' => function (array $a) {
                $vs = self::vsOf($a[0], $a[1]);
                if ($vs === null) {
                    throw new \TypeError('no verb space');
                }
                $inp = self::with($a[3], ['vs' => $vs, 'cell' => $a[2]]);
                return Obj::of(['body' => IntentJit::intentRequiredBody($inp), 'signed' => IntentJit::signedIntentRequired($inp, 'site-1', self::key($a[4]))]);
            },
            'walletScenario' => function (array $a) {
                [$omega, $inp, $mutation, $now, $lifted, $session, $mapDigest, $seedLabel] = $a;
                $site = self::key($seedLabel);
                $vs = self::vsOf($omega, 'stripe.refund');
                $body = IntentJit::signedIntentRequired(self::with($inp, ['vs' => $vs, 'cell' => [1, 0]]), 'site-1', $site);
                if ($mutation === 'coords') {
                    $body->get('cell')->get('coords')->set('action.params.amount', [new Num('2'), new Num('2')]);
                } elseif ($mutation === 'verb') {
                    $body->get('cell')->set('verb', 'gmail.send');
                } elseif ($mutation === 'sig') {
                    $v = $body->get('sig')->get('value');
                    $body->get('sig')->set('value', substr($v, 0, -2) . 'AA');
                } elseif ($mutation === 'kid') {
                    $body->get('sig')->set('kid', 'other');
                } elseif ($mutation === 'session') {
                    $body->set('session', self::dig('other'));
                } elseif ($mutation === 'action') {
                    $body->set('action_digest', self::dig('other'));
                } elseif ($mutation === 'null') {
                    $body = null;
                }
                return IntentJit::walletCheckIntentRequired($body, Obj::of(['keys' => [Obj::of(['kid' => 'site-1', 'alg' => 'ed25519', 'pk' => $site->public])],
                    'now' => $now, 'session' => $session, 'mapDigest' => $mapDigest, 'omegaTilde' => $omega, 'lifted' => $lifted, 'pcactn' => Js::opt($inp, 'pcactn')]));
            },
            'mintScenario' => function (array $a) {
                $P = static fn($x) => WalletOmega::plain($x);
                $omega = $P($a[0]);
                $prev = self::mk($omega, $P($a[1]), $P($a[2]));
                $next = self::mk($omega, $P($a[1]), array_merge($P($a[2]), $P($a[3])));
                $m = $a[4];
                $opts = [];
                foreach (['salt', 'mapForm', 'caveats'] as $key) {
                    if (Js::opt($m, $key) !== null) {
                        $opts[$key] = Js::opt($m, $key);
                    }
                }
                $r = IntentJit::mintDelta($prev, $next, Js::opt($m, 'prevGrant'), self::key($a[5]), Js::opt($m, 'holder'), Js::opt($m, 'session'),
                    (int)Js::num(Js::opt($m, 'seq')), Js::opt($m, 'root'), Js::opt($m, 'mapDigest'), Js::opt($m, 'prev'), $opts);
                return $r === null ? null : ['grant' => $r['grant'], 'goalSalt' => $r['goal_salt'], 'cells' => $r['cells']];
            },
        ]);
    }
}
