<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentObservation.php';

/**
 * Trust ramp and drift: start narrow, widen only through confirmed behaviour, veto on every negative runtime signal, and a one-sided
 * Bernoulli CUSUM that freezes widening on drift. A "learner" is an IntentLearner (cells(), admitsOutcome(), observe()).
 */
final class IntentRamp
{
    public static function signalLabel(mixed $s): int
    {
        return $s === 'jit-approve' || $s === 'principal-confirm' ? 1 : 0;
    }

    /** The narrow starting configuration for a learner that will be ramped: {eta, tau, nullMass}. */
    public static function narrowStart(mixed $omega, mixed $slots, mixed $opts = null): Obj
    {
        $slotMass = Js::opt($opts, 'slotNullMass');
        $otherMass = Js::opt($opts, 'otherNullMass');
        $verbs = Js::opt($slots, 'verbs');
        $nullMass = new Obj();
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $v = Js::opt($vs, 'verb');
            $nullMass->set($v, in_array($v, $verbs, true) ? ($slotMass === null ? 0.5 : $slotMass) : ($otherMass === null ? 0.95 : $otherMass));
        }
        return Obj::of(['eta' => 0, 'tau' => 1, 'nullMass' => $nullMass]);
    }
}

/** A one-sided Bernoulli CUSUM over "diverged" signals about actions that were inside the grant. */
final class IntentDriftDetector
{
    public readonly float $rho0;
    public readonly float $rho1;
    public readonly float $h;
    /** @var array{statistic:int|float,alarm:bool,informative:int,divergences:int} */
    private array $s;

    public function __construct(mixed $o = null)
    {
        $r0 = Js::opt($o, 'rho0');
        $r1 = Js::opt($o, 'rho1');
        $h = Js::opt($o, 'h');
        $this->rho0 = $r0 === null ? 0.02 : (float)Js::num($r0);
        $this->rho1 = $r1 === null ? 0.25 : (float)Js::num($r1);
        $this->h = $h === null ? log(100) : (float)Js::num($h);
        if (!(0 < $this->rho0 && $this->rho0 < $this->rho1 && $this->rho1 < 1)) {
            throw new \InvalidArgumentException('DriftDetector: need 0 < rho0 < rho1 < 1');
        }
        if (!($this->h > 0)) {
            throw new \InvalidArgumentException('DriftDetector: h must be positive');
        }
        $this->s = self::fresh();
    }

    private static function fresh(): array
    {
        return ['statistic' => 0, 'alarm' => false, 'informative' => 0, 'divergences' => 0];
    }

    /** Feed one signal about an action that was inside the grant: diverged = true for a negative signal. */
    public function update(bool $diverged): array
    {
        $inc = $diverged ? log($this->rho1 / $this->rho0) : log((1 - $this->rho1) / (1 - $this->rho0));
        $statistic = IntentOmega::jsMax(0, $this->s['statistic'] + $inc);
        $this->s = ['statistic' => $statistic, 'alarm' => $this->s['alarm'] || $statistic >= $this->h,
            'informative' => $this->s['informative'] + 1, 'divergences' => $this->s['divergences'] + ($diverged ? 1 : 0)];
        return $this->s;
    }

    public function state(): array
    {
        return $this->s;
    }

    public function reset(): void
    {
        $this->s = self::fresh();
    }
}

/** Widening gated by drift: positive signals are held back while an alarm stands; every negative signal is applied at once. */
final class IntentTrustRamp
{
    public readonly IntentDriftDetector $drift;
    /** @var list<array{o:mixed,signal:string}> */
    private array $queued = [];
    /** @var list<array<string,mixed>> */
    public array $log = [];

    public function __construct(private object $l, mixed $drift = null)
    {
        $this->drift = new IntentDriftDetector($drift);
    }

    public function learner(): object
    {
        return $this->l;
    }

    /** Widening is frozen while a drift alarm stands. */
    public function frozen(): bool
    {
        return $this->drift->state()['alarm'];
    }

    /** Positive signals held back by a freeze (released only by rebase). */
    public function pending(): array
    {
        return $this->queued;
    }

    private function grantSize(): int
    {
        $n = 0;
        foreach ($this->l->cells() as $c) {
            if ($c['inGrant']) {
                $n++;
            }
        }
        return $n;
    }

    /** @return array<string,mixed> the log record */
    public function record(mixed $o, string $signal): array
    {
        $y = IntentRamp::signalLabel($signal);
        $wasInGrant = $this->l->admitsOutcome($o);
        $before = $this->grantSize();
        $drift = $this->drift->state();
        if ($wasInGrant) {
            $drift = $this->drift->update($y === 0);
        }
        $applied = true;
        if ($y === 1 && $this->frozen()) {
            $this->queued[] = ['o' => $o, 'signal' => $signal];
            $applied = false;
        } else {
            $this->l->observe($o, $y, 'runtime');
        }
        $rec = ['signal' => $signal, 'y' => $y, 'wasInGrant' => $wasInGrant, 'before' => $before, 'after' => $this->grantSize(), 'applied' => $applied, 'drift' => $drift];
        $this->log[] = $rec;
        return $rec;
    }

    /**
     * Record a SIGNED runtime observation: the signature must verify (IntentObservation::verify with $ctx verify, or a
     * Closure(obs, verifyOpts) in $ctx verifyObservation), the signer must be trusted and the observation must be about this map.
     * @return array{ok:bool,reason?:string,record?:array}
     */
    public function recordObservation(mixed $obs, mixed $ctx): array
    {
        $verify = Js::opt($ctx, 'verifyObservation');
        if (!($verify instanceof \Closure)) {
            $verify = IntentObservation::verify(...);
        }
        $v = $verify($obs, Js::opt($ctx, 'verify') ?? new Obj());
        if (Js::opt($v, 'ok') !== true) {
            return ['ok' => false, 'reason' => Js::opt($v, 'reason')];
        }
        if (!in_array(Js::opt($obs, 'signer'), Js::opt($ctx, 'trustedSigners'), true)) {
            return ['ok' => false, 'reason' => 'untrusted observation signer'];
        }
        if (Js::opt($obs, 'map_digest') !== Js::opt($ctx, 'mapDigest')) {
            return ['ok' => false, 'reason' => 'observation is about a different map'];
        }
        if (Js::opt($obs, 'source') !== 'runtime') {
            return ['ok' => false, 'reason' => 'only runtime observations feed the ramp'];
        }
        $y = Js::opt($obs, 'y');
        $sig = Js::isNum($y) && Js::num($y) === 1.0 ? 'principal-confirm' : 'postcondition-violation';
        return ['ok' => true, 'record' => $this->record(Obj::of(['verb' => Js::opt($obs, 'verb'), 'values' => Js::opt($obs, 'values')]), $sig)];
    }

    /** Re-base on a new, signed intent statement (the only way to clear an alarm); queued positive signals are discarded. */
    public function rebase(object $next): void
    {
        $this->l = $next;
        $this->queued = [];
        $this->drift->reset();
    }
}
