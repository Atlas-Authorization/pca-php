<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\SlidingWindowCounter;
use Atlas\Pca\Wallet;
use Atlas\Pca\PopulationAggregator;
use Atlas\Pca\WalletCard;
use Atlas\Pca\WalletChannel;
use Atlas\Pca\WalletDelivery;
use Atlas\Pca\WalletHandlers;
use Atlas\Pca\WalletOmega;
use Atlas\Pca\WalletPopulation;
use Atlas\Pca\WalletPricing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The wallet side of the Intent Layer v2 against the TS reference: test-data/ref-wallet.json.gz (signed answers, friction tiers, cell
 * coordinates, noise numerics, canaries, approval fatigue, risk-priced escalation, the trusted card, clarification, population priors,
 * question delivery and the trusted question channel). Placeholders in args: {"$omega": "A"|"B"} is an outcome space of the `omegas`
 * case, {"$seed": label} the Ed25519 seed sha256("atlas-pca-conformance/" + label). Doubles from transcendental functions are
 * compared to 1e-12 relative.
 */
final class RefWalletDifferentialTest extends TestCase
{
    private const FILE = 'ref-wallet.json.gz';

    /** @var array<string,Obj>|null */
    private static ?array $om = null;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    // ---- placeholders --------------------------------------------------------------------------------------------------------

    public static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    /** The two outcome spaces of the `omegas` case. */
    public static function omegas(): array
    {
        if (self::$om === null) {
            $o = Base::cases(self::FILE, 'omegas', 0)[0]->get('out');
            self::$om = ['A' => WalletOmega::plain($o->get('A')), 'B' => WalletOmega::plain($o->get('B'))];
        }
        return self::$om;
    }

    public static function sub(mixed $x): mixed
    {
        if ($x instanceof Obj) {
            if ($x->keys() === ['$omega']) {
                return self::omegas()[$x->get('$omega')];
            }
            if ($x->keys() === ['$seed']) {
                return self::seed((string)$x->get('$seed'));
            }
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::sub($x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::sub(...), $x) : $x;
    }

    public static function vs(string $i, mixed $verb): Obj
    {
        foreach (self::omegas()[$i]->get('verbs') as $v) {
            if ($v->get('verb') === $verb) {
                return $v;
            }
        }
        throw new \OutOfBoundsException('no such verb');
    }

    public static function dim(string $i, mixed $verb, mixed $k): mixed
    {
        return self::vs($i, $verb)->get('dims')[(int)Js::num($k)];
    }

    // ---- tolerant comparison -------------------------------------------------------------------------------------------------

    public static function isClose(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) && Js::isNum($b)) {
            $x = (float)Js::num($a);
            $y = (float)Js::num($b);
            return $x === $y || abs($x - $y) <= max(1e-12 * max(abs($x), abs($y)), 1e-15);
        }
        if ($a instanceof Obj && $b instanceof Obj) {
            $ka = $a->keys();
            $kb = $b->keys();
            sort($ka);
            sort($kb);
            if ($ka !== $kb) {
                return false;
            }
            foreach ($ka as $k) {
                if (!self::isClose($a->get($k), $b->get($k))) {
                    return false;
                }
            }
            return true;
        }
        if (is_array($a) && is_array($b)) {
            if (array_is_list($a) !== array_is_list($b) && $a !== [] && $b !== []) {
                return Base::canon($a) === Base::canon($b);
            }
            if (count($a) !== count($b)) {
                return false;
            }
            foreach (array_keys($a) as $k) {
                if (!array_key_exists($k, $b) || !self::isClose($a[$k], $b[$k])) {
                    return false;
                }
            }
            return true;
        }
        try {
            return Base::canon($a) === Base::canon($b);
        } catch (\Throwable) {
            return false;
        }
    }

    /** Within the 1e-12 relative tolerance the reference's value stands in for the native one. */
    public static function close(mixed $have, Obj $case): mixed
    {
        $want = $case->get('out');
        if ($want instanceof Obj && $want->has('$throws')) {
            return $have;
        }
        return self::isClose(self::asModel($have), $want) ? $want : $have;
    }

    /** A native result in the model form (assoc arrays -> Obj) for the tolerant walk. */
    private static function asModel(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::asModel($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            if ($v === [] || array_is_list($v)) {
                return array_map(self::asModel(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::asModel($x));
            }
            return $o;
        }
        return $v;
    }

    private static function plain(mixed $v): mixed
    {
        return WalletOmega::plain($v);
    }

    // ---- scenario adapters ---------------------------------------------------------------------------------------------------

    /** A deterministic randomness source: the scripted draws, then a throw. */
    public static function seq(array $xs): \Closure
    {
        $i = 0;
        return static function () use (&$i, $xs): float {
            if ($i >= count($xs)) {
                throw new \RuntimeException('rand exhausted');
            }
            return (float)Js::num($xs[$i++]);
        };
    }

    private static function pick(mixed $ctx): mixed
    {
        $c = self::plain(self::sub($ctx));
        $knownNo = $c->get('knownNo');
        $ctx2 = [
            'omega' => $c->get('omega'), 'confirmed' => $c->get('confirmed'),
            'knownNo' => static fn($verb, $idx) => $knownNo->get(Wallet::cellKey($verb, $idx)),
            'knownYes' => $c->get('knownYes'), 'exclude' => $c->get('exclude'), 'rand' => self::seq($c->get('rands')),
            'lowHarmSession' => $c->get('lowHarmSession'), 'canariesSoFar' => $c->get('canariesSoFar'),
        ];
        if ($c->has('rho')) {
            $ctx2['rho'] = $c->get('rho');
        }
        return Wallet::pickCanary($ctx2);
    }

    private static function sliding(mixed $window, array $ops): array
    {
        $c = $window === null ? new SlidingWindowCounter() : new SlidingWindowCounter($window);
        $out = [];
        foreach ($ops as $op) {
            try {
                $out[] = Obj::of(['v' => $op[0] === 'count' ? $c->count($op[1]) : $c->tryAdd($op[1], $op[2])]);
            } catch (\Throwable) {
                $out[] = Obj::of(['err' => true]);
            }
        }
        return $out;
    }

    private static function resolve(array $a): mixed
    {
        $r = Wallet::resolveCoords(self::plain(self::sub($a[0])), $a[1], $a[2]);
        return $r['ok'] ? ['ok' => true, 'verb' => $r['vs']->get('verb'), 'box' => $r['box']] : $r;
    }

    private static function ofAction(array $a): mixed
    {
        $r = Wallet::cellOfAction(self::omegas()[$a[0]], $a[1]);
        return $r === null ? null : ['verb' => $r['vs']->get('verb'), 'idx' => $r['idx']];
    }

    private static function aggregate(array $a): array
    {
        $opts = ['rand' => self::seq($a[5])];
        if ($a[2]->has('maxCellsPerPrincipal')) {
            $opts['maxCellsPerPrincipal'] = $a[2]->get('maxCellsPerPrincipal');
        }
        $agg = new PopulationAggregator($a[0], $a[1], $opts);
        $votes = array_map(static fn($v) => $agg->contribute($v), $a[3]);
        try {
            $release = $agg->release($a[4]);
        } catch (\Throwable) {
            $release = ['err' => true];
        }
        return ['votes' => $votes, 'release' => $release];
    }

    private static function prior(array $a): array
    {
        $pm = WalletPopulation::populationPrior($a[0], $a[1]);
        $contained = array_map(static fn($c) => (float)Js::num($c), $a[4]);
        return ['beta' => $pm['beta'], 'weight' => ($pm['weight'])(self::vs($a[2], $a[3]), static fn($c): bool => in_array((float)$c, $contained, true))];
    }

    private static function render(array $a): mixed
    {
        $x = $a[0];
        $id = $x->get('omegaId');
        if (!$x->has('omegaId') || !is_string($id) || !array_key_exists($id, self::omegas())) {
            throw new \OutOfBoundsException('unknown outcome space');
        }
        $in = new Obj();
        $in->set('omega', self::omegas()[$id]);
        foreach ($x->keys() as $k) {
            if ($k !== 'omegaId') {
                $in->set($k, $x->get($k));
            }
        }
        return WalletCard::renderCard($in);
    }

    /** The view of a clarification scenario: acceptance by cell key (0 when absent), vetoed and ceiling key lists. */
    private static function viewOf(Obj $v): array
    {
        $p = $v->get('p');
        $veto = $v->get('vetoed');
        $ceil = $v->get('ceiling');
        return [
            'p' => static fn($verb, $i) => $p->has($k = Wallet::cellKey($verb, $i)) ? (float)Js::num($p->get($k)) : 0,
            'vetoed' => static fn($verb, $i) => in_array(Wallet::cellKey($verb, $i), $veto, true),
            'outsideCeiling' => static fn($verb, $i) => in_array(Wallet::cellKey($verb, $i), $ceil, true),
        ];
    }

    private static function plan(array $a): array
    {
        $x = self::sub($a[0]);
        return WalletCard::planClarification([
            'omega' => $x->get('omega'), 'view' => self::viewOf($x->get('view')), 'candidates' => $x->get('candidates'),
            'asked' => array_fill_keys($x->get('asked'), true), 'etaPos' => $x->get('etaPos'), 'etaNeg' => $x->get('etaNeg'),
        ]);
    }

    private static function notice(array $a): mixed
    {
        $ctx = ['keys' => $a[1], 'site' => $a[2], 'now' => $a[3]];
        if (count($a) > 4) {
            $ctx['inboxUrl'] = $a[4];
        }
        return WalletDelivery::siteQuestionNotice($a[0], $ctx);
    }

    private static function hook(array $a): array
    {
        [$cfg, $script, $notices] = $a;
        $calls = [];
        $idx = 0;
        $fetch = static function ($url, $init) use (&$calls, &$idx, $script): array {
            $calls[] = Obj::of(['url' => $url, 'method' => $init->get('method'), 'headers' => $init->get('headers'), 'body' => $init->get('body')]);
            $step = $idx < count($script) ? $script[$idx] : null;
            $idx++;
            if ($step !== null && Js::truthy($step->get('throw'))) {
                throw new \RuntimeException((string)$step->get('throw'));
            }
            return $step === null ? ['ok' => true, 'status' => 200] : ['ok' => $step->get('ok'), 'status' => (int)Js::num($step->get('status'))];
        };
        $conf = ['fetch' => $fetch];
        if ($cfg->has('url')) {
            $conf['url'] = $cfg->get('url');
        }
        if (Js::truthy($cfg->get('headers')) && $cfg->get('headers') instanceof Obj && $cfg->get('headers')->keys() !== []) {
            $conf['headers'] = $cfg->get('headers');
        }
        $ch = WalletDelivery::webhookChannel($conf);
        $deliveries = array_map(static fn($n) => $ch->notify($n), $notices);
        return ['kind' => $ch->kind, 'enabled' => $ch->enabled, 'deliveries' => $deliveries, 'calls' => $calls];
    }

    private static function tchan(array $a): array
    {
        [$kind, $name, $script, $notices] = $a;
        $sent = [];
        $idx = 0;
        $cfg = ['siteName' => $name];
        if ($script !== null) {
            $cfg['send'] = static function ($b) use (&$sent, &$idx, $script): void {
                $sent[] = $b;
                $st = $idx < count($script) ? $script[$idx] : null;
                $idx++;
                if ($st instanceof Obj && Js::truthy($st->get('throw'))) {
                    throw new \RuntimeException((string)$st->get('throw'));
                }
            };
        }
        $ch = WalletDelivery::textChannel($kind, $cfg);
        $deliveries = array_map(static fn($n) => $ch->notify($n), $notices);
        return ['kind' => $ch->kind, 'enabled' => $ch->enabled, 'deliveries' => $deliveries, 'sent' => $sent];
    }

    private static function dispatch(array $a): array
    {
        $chans = [];
        foreach ($a[0] as $c) {
            if ($c->get('type') === 'webhook') {
                $conf = ['fetch' => static fn($u, $i): array => ['ok' => true, 'status' => 200]];
                if ($c->has('url')) {
                    $conf['url'] = $c->get('url');
                }
                $chans[] = WalletDelivery::webhookChannel($conf);
            } else {
                $conf = ['siteName' => 'S'];
                if (Js::truthy($c->get('enabled'))) {
                    $conf['send'] = static function ($b): void {
                    };
                }
                $chans[] = WalletDelivery::textChannel((string)$c->get('type'), $conf);
            }
        }
        $d = WalletDelivery::createQuestionDispatcher($chans);
        return ['n' => count($d->channels), 'deliveries' => $d->notifyAll($a[1])];
    }

    /** Python truthiness of a scenario option (an empty object or list is false). */
    private static function pyTruthy(mixed $v): bool
    {
        if ($v instanceof Obj) {
            return $v->keys() !== [];
        }
        return is_array($v) ? $v !== [] : Js::truthy($v);
    }

    private static function merged(Obj $base, Obj $add): Obj
    {
        $o = new Obj();
        foreach ($base->keys() as $k) {
            $o->set($k, $base->get($k));
        }
        foreach ($add->keys() as $k) {
            $o->set($k, $add->get($k));
        }
        return $o;
    }

    /** One scenario of the trusted question channel: the session options, then the scripted steps (an exception is a step result). */
    private static function channel(array $a): array
    {
        $spec = self::sub($a[0]);
        $state = ['t' => (int)Js::num($spec->get('t0')), 'counts' => $spec->get('noise')];
        $hourly = $spec->has('windowMs') ? new SlidingWindowCounter(WalletOmega::plain($spec->get('windowMs'))) : new SlidingWindowCounter();
        foreach ($spec->get('hourlyPre') as $ts) {
            $hourly->tryAdd(WalletOmega::plain($ts), 9007199254740991);
        }
        $V = $spec->get('view');
        $p = $V->get('p');
        $veto = $V->get('vetoed');
        $ceil = $V->get('ceiling');
        $confirmed = WalletOmega::plain($V->get('confirmed'));
        $view = [
            'p' => static fn($v, $i) => $p->has($k = Wallet::cellKey($v, $i)) ? (float)Js::num($p->get($k)) : 0,
            'vetoed' => static fn($v, $i) => in_array(Wallet::cellKey($v, $i), $veto, true),
            'outsideCeiling' => static fn($v, $i) => in_array(Wallet::cellKey($v, $i), $ceil, true),
            'confirmed' => static fn() => $confirmed,
        ];
        $o = [
            'omega' => $spec->get('omega'), 'session' => $spec->get('session'), 'mapDigest' => static fn() => $spec->get('mapDigest'),
            'principalSecret' => self::seed((string)$spec->get('principal')), 'site' => $spec->get('site'), 'view' => $view, 'hourly' => $hourly,
            'noise' => static function () use (&$state) {
                return $state['counts'];
            },
            'onNoise' => static function ($n) use (&$state): void {
                $state['counts'] = $n;
            },
            'rand' => self::seq($spec->get('rands')),
            'now' => static function () use (&$state) {
                return $state['t'];
            },
        ];
        $always = ['rho', 'maxPerScreen', 'maxBoxCells', 'statementText'];
        foreach (['statementText', 'units', 'sensitivity', 'identityPaths', 'caps', 'rho', 'fatigue', 'maxPerScreen', 'maxBoxCells'] as $k) {
            if ($spec->has($k) && (self::pyTruthy($spec->get($k)) || in_array($k, $always, true))) {
                $o[$k] = in_array($k, ['caps', 'rho', 'fatigue', 'maxPerScreen', 'maxBoxCells'], true) ? WalletOmega::plain($spec->get($k)) : $spec->get($k);
            }
        }
        if (self::pyTruthy($spec->get('device'))) {
            $o['device'] = $spec->get('device');
        }
        if (self::pyTruthy($spec->get('liftCand'))) {
            $add = $spec->get('liftCand');
            $o['liftCandidate'] = static fn($c) => Obj::of(['verb' => Wallet::req($c, 'verb'), 'values' => self::merged(Wallet::req($c, 'values'), $add)]);
        }
        if (self::pyTruthy($spec->get('lift'))) {
            $add = $spec->get('lift')->get('add');
            $o['lift'] = static function ($act) use ($add) {
                $v = Wallet::actionValuesOf($act);
                return Obj::of(['verb' => Wallet::req($v, 'verb'), 'values' => self::merged($v->get('values'), $add)]);
            };
        }
        $ch = new WalletChannel($o);
        $session = $spec->get('session');
        $resolver = static fn($sid) => $sid === $session ? $ch : null;
        $seen = [];
        $steps = [];
        foreach ($spec->get('steps') as $st) {
            try {
                $q = $st->get('q');
                $qid = $q !== null ? (((int)Js::num($q)) < count($seen) ? $seen[(int)Js::num($q)] : null) : $st->get('qid');
                $sid = $st->has('sid') ? $st->get('sid') : $session;
                switch ($st->get('op')) {
                    case 'time':
                        $state['t'] = (int)Js::num($st->get('t'));
                        $r = ['t' => $state['t']];
                        break;
                    case 'receive':
                        $r = $ch->receive($st->get('ir'), Obj::of(['action' => $st->get('action')]));
                        break;
                    case 'next':
                        $r = $ch->nextScreen();
                        foreach (($r['questions'] ?? []) as $x) {
                            $seen[] = $x['questionId'];
                        }
                        break;
                    case 'answer':
                        $r = $ch->answer($qid, $st->get('response'));
                        break;
                    case 'clarify':
                        $r = $ch->clarify($st->get('body'));
                        break;
                    case 'hQuestion':
                        $r = WalletHandlers::questionHandler($resolver)($sid, $st->get('body'));
                        break;
                    case 'hClarify':
                        $r = WalletHandlers::clarifyHandler($resolver)($sid, $st->get('body'));
                        break;
                    case 'summary':
                        $r = $ch->summary();
                        break;
                    case 'state':
                        $r = ['digest' => $ch->stateDigest(), 'asked' => $ch->questionsAsked()];
                        break;
                    case 'noise':
                        $r = ['noise' => $ch->noise(), 'admission' => $ch->admission()];
                        break;
                    case 'challenge':
                        $r = $ch->deviceChallengeFor($qid);
                        break;
                    default:
                        throw new \InvalidArgumentException('bad op');
                }
            } catch (\Throwable) {
                $r = Obj::of(['$err' => true]);
            }
            $steps[] = Obj::of(['op' => $st->get('op'), 'r' => $r]);
        }
        $dev = $o['device'] ?? null;
        return ['steps' => $steps, 'noise' => $state['counts'], 'signCounts' => $dev === null ? null : $dev->get('signCounts')];
    }

    private static function constants(Obj $case): mixed
    {
        $mine = [
            'FRICTION_ORDER' => Wallet::FRICTION_ORDER, 'INTENT_ANSWER_SIG_DOMAIN' => Wallet::INTENT_ANSWER_SIG_DOMAIN,
            'INTENT_ANSWER_REF_DOMAIN' => Wallet::INTENT_ANSWER_REF_DOMAIN, 'INTENT_TYPED_DOMAIN' => Wallet::INTENT_TYPED_DOMAIN,
            'INTENT_DEVICE_CHALLENGE_DOMAIN' => Wallet::INTENT_DEVICE_CHALLENGE_DOMAIN, 'MIN_HOLD_MS' => Wallet::MIN_HOLD_MS,
            'PROVENANCE_ORDER' => Wallet::PROVENANCE_ORDER, 'DEFAULT_FRICTION_THRESHOLDS' => Wallet::DEFAULT_FRICTION_THRESHOLDS,
            'EMPTY_NOISE' => Wallet::EMPTY_NOISE, 'NOISE_PRIOR' => Wallet::NOISE_PRIOR, 'DEFAULT_FATIGUE' => Wallet::DEFAULT_FATIGUE,
        ];
        // only the exported constants of the ported modules are compared
        $want = $case->get('out');
        $keep = new Obj();
        foreach (array_keys($mine) as $k) {
            $keep->set($k, $want->get($k));
        }
        $case->set('out', $keep);
        return $mine;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'omegas' => static fn(array $a) => [Base::SKIP, 'data'],
            'constants' => fn(array $a, Obj $c) => self::constants($c),
            'isFrictionTier' => fn(array $a) => Wallet::isFrictionTier($a[0]),
            'frictionRank' => fn(array $a) => Wallet::frictionRank($a[0]),
            'maxFriction' => fn(array $a) => Wallet::maxFriction(...$a),
            'satisfiesTier' => fn(array $a) => Wallet::satisfiesTier($a[0], $a[1]),
            'isProvenanceLevel' => fn(array $a) => Wallet::isProvenanceLevel($a[0]),
            'worstProvenance' => fn(array $a) => Wallet::worstProvenance($a[0]),
            'frictionFor' => fn(array $a) => Wallet::frictionFor($a[0], $a[1] ?? null),
            'pcaActionDigest' => fn(array $a) => Wallet::pcaActionDigest($a[0]),
            'actionValuesOf' => fn(array $a) => Wallet::actionValuesOf($a[0]),
            'isB64u32' => fn(array $a) => Wallet::isB64u32($a[0]),
            'isObj' => fn(array $a) => Wallet::isObj($a[0]),
            'coordsError' => fn(array $a) => Wallet::coordsError($a[0]),
            'answerShapeError' => fn(array $a) => Wallet::answerShapeError($a[0]),
            'signIntentAnswer' => fn(array $a) => Wallet::signIntentAnswer($a[0], self::seed((string)$a[1]->get('$seed'))),
            'verifyIntentAnswer' => fn(array $a) => Wallet::verifyIntentAnswer($a[0], $a[1] ?? null),
            'answerRef' => fn(array $a) => Wallet::answerRef($a[0]),
            'typedDigest' => fn(array $a) => Wallet::typedDigest($a[0], $a[1]),
            'deviceChallenge' => fn(array $a) => Wallet::deviceChallenge($a[0]->get('questionId'), $a[0]->get('renderedDigest'), $a[0]->get('y'), $a[0]->get('actionDigest')),
            'lnGamma' => fn(array $a, Obj $c) => self::close(Wallet::lnGamma($a[0]), $c),
            'betacf' => fn(array $a, Obj $c) => self::close(Wallet::betacf($a[0], $a[1], $a[2]), $c),
            'betaInc' => fn(array $a, Obj $c) => self::close(Wallet::betaInc($a[0], $a[1], $a[2]), $c),
            'betaQuantile' => fn(array $a, Obj $c) => self::close(Wallet::betaQuantile($a[0], $a[1], $a[2]), $c),
            'clopperPearsonUpper' => fn(array $a) => Wallet::clopperPearsonUpper($a[0], $a[1], $a[2]), // a decision input: exact
            'binEnt' => fn(array $a, Obj $c) => self::close(Wallet::binEnt($a[0]), $c),
            'recordCanary' => fn(array $a) => Wallet::recordCanary($a[0], $a[1], $a[2]),
            'estimateNoise' => fn(array $a) => Wallet::estimateNoise($a[0], $a[1] ?? 0.05), // a decision input: exact
            'cellKey' => fn(array $a) => Wallet::cellKey($a[0], $a[1]),
            'boundaryNeighbours' => fn(array $a) => Wallet::boundaryNeighbours(self::plain(self::sub($a[0])), self::plain($a[1])),
            'pickCanary' => fn(array $a) => self::pick($a[0]),
            'etaUnderLoad' => fn(array $a) => Wallet::etaUnderLoad($a[0], $a[1], $a[2]), // a decision input: exact
            'noiseState' => fn(array $a) => Wallet::noiseState($a[0], $a[1], $a[2] ?? null), // a decision input: exact
            'admissionPolicy' => fn(array $a) => Wallet::admissionPolicy($a[0], $a[1] ?? null), // a decision input: exact
            'doubleConfirmed' => fn(array $a) => Wallet::doubleConfirmed($a[0]),
            'slidingWindow' => fn(array $a) => self::sliding($a[0], $a[1]),
            'omega.verbCellCount' => fn(array $a) => WalletOmega::verbCellCount(self::vs($a[0], $a[1])),
            'omega.cellCount' => fn(array $a) => WalletOmega::cellCount(self::dim($a[0], $a[1], $a[2])),
            'omega.numCells' => fn(array $a) => WalletOmega::numCells(self::dim($a[0], $a[1], $a[2])),
            'omega.labelOf' => fn(array $a) => WalletOmega::labelOf($a[0]),
            'omega.decodeCell' => fn(array $a) => WalletOmega::decodeCell(self::vs($a[0], $a[1]), $a[2]),
            'omega.cellStats' => fn(array $a, Obj $c) => self::close(WalletOmega::cellStats(self::vs($a[0], $a[1]), self::plain($a[2])), $c),
            'omega.cellRep' => fn(array $a) => WalletOmega::cellRep(self::vs($a[0], $a[1]), self::plain($a[2])),
            'omega.cellOf' => fn(array $a) => WalletOmega::cellOf(self::vs($a[0], $a[1]), $a[2]),
            'coordKeyOf' => fn(array $a) => Wallet::coordKeyOf($a[0]),
            'resolveCoords' => fn(array $a) => self::resolve($a),
            'coordsOfBox' => fn(array $a) => Wallet::coordsOfBox(self::vs($a[0], $a[1]), self::plain($a[2])),
            'coordsOfCell' => fn(array $a) => Wallet::coordsOfCell(self::vs($a[0], $a[1]), self::plain($a[2])),
            'cellInBox' => fn(array $a) => Wallet::cellInBox(self::plain($a[0]), self::plain($a[1])),
            'boxCells' => fn(array $a) => Wallet::boxCells(self::plain($a[0])),
            'boxSize' => fn(array $a) => Wallet::boxSize(self::plain($a[0])),
            'cellOfAction' => fn(array $a) => self::ofAction($a),
            'flatIndex' => fn(array $a) => Wallet::flatIndex(self::vs($a[0], $a[1]), self::plain($a[2])),
            'signPricingConfig' => fn(array $a) => WalletPricing::signPricingConfig($a[0], self::seed((string)$a[1]->get('$seed'))),
            'pricingConfigError' => fn(array $a) => WalletPricing::pricingConfigError($a[0]),
            'freshCalibration' => fn(array $a) => WalletPricing::freshCalibration(),
            'decideEscalation' => fn(array $a) => WalletPricing::decideEscalation($a[0], $a[1], $a[2]),
            'signAnswer' => fn(array $a) => WalletPricing::signAnswer($a[0], self::seed((string)$a[1]->get('$seed'))),
            'updateCalibration' => fn(array $a) => WalletPricing::updateCalibration($a[0], $a[1], $a[2], $a[3]),
            'signAutonomyRaise' => fn(array $a) => WalletPricing::signAutonomyRaise($a[0], self::seed((string)$a[1]->get('$seed'))),
            'applyAutonomyRaise' => fn(array $a) => WalletPricing::applyAutonomyRaise($a[0], $a[1], self::seed((string)$a[2]->get('$seed'))),
            'gaussianSigma' => fn(array $a, Obj $c) => self::close(WalletPopulation::gaussianSigma($a[0], $a[1], $a[2]), $c),
            'gaussian' => fn(array $a, Obj $c) => self::close(WalletPopulation::gaussian(self::seq($a[0])), $c),
            'rrKeepProbability' => fn(array $a, Obj $c) => self::close(WalletPopulation::rrKeepProbability($a[0]), $c),
            'randomizedResponse' => fn(array $a) => WalletPopulation::randomizedResponse($a[0], $a[1], static fn(): float => (float)Js::num($a[2])),
            'debiasRandomizedResponse' => fn(array $a, Obj $c) => self::close(WalletPopulation::debiasRandomizedResponse($a[0], $a[1], $a[2]), $c),
            'populationCellKey' => fn(array $a) => WalletPopulation::populationCellKey($a[0], self::vs($a[1], $a[2]), self::plain($a[3])),
            'aggregate' => fn(array $a, Obj $c) => self::close(self::aggregate($a), $c),
            'populationPrior' => fn(array $a, Obj $c) => self::close(self::prior($a), $c),
            // the trusted card, clarification, population priors, delivery and the question channel
            'cleanText' => fn(array $a) => WalletCard::cleanText($a[0], (int)Js::num($a[1])),
            'last4' => fn(array $a) => WalletCard::last4($a[0]),
            'formatNumber' => fn(array $a) => WalletCard::formatNumber($a[0], $a[1] ?? null),
            'renderCard' => fn(array $a) => self::render($a),
            'cardDigest' => fn(array $a) => WalletCard::cardDigest($a[0]),
            'cardDigestMatches' => fn(array $a) => WalletCard::cardDigestMatches($a[0]),
            'cardText' => fn(array $a) => WalletCard::cardText($a[0]),
            'partialError' => fn(array $a) => WalletCard::partialError($a[0], $a[1]),
            'normalizeTyped' => fn(array $a) => WalletCard::normalizeTyped($a[0], $a[1], $a[2] ?? null),
            'expectedTyped' => fn(array $a) => WalletCard::expectedTyped($a[0], $a[1]),
            'parseClarifyRequest' => fn(array $a) => WalletCard::parseClarifyRequest($a[0] ?? null),
            'informationGain' => fn(array $a, Obj $c) => self::close(WalletCard::informationGain($a[0], $a[1], $a[2]), $c),
            'planClarification' => fn(array $a, Obj $c) => self::close(self::plan($a), $c),
            'siteQuestionNotice' => fn(array $a) => self::notice($a),
            'clarificationNotice' => fn(array $a) => WalletDelivery::clarificationNotice($a[0], $a[1], $a[2] ?? null),
            'questionText' => fn(array $a) => WalletDelivery::questionText($a[0], $a[1]),
            'webhookChannel' => fn(array $a) => self::hook($a),
            'textChannel' => fn(array $a) => self::tchan($a),
            'dispatcher' => fn(array $a) => self::dispatch($a),
            'channel' => fn(array $a, Obj $c) => self::close(self::channel($a), $c),
        ]);
    }
}
