<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Grants.php';

/**
 * Shadow policy rollout: run candidate policy bundles beside the enforced one, record every divergence as a verifier-signed diff,
 * and gate promotion on zero unexplained widenings. The enforced decision is computed first and returned untouched, so a candidate
 * that throws, returns junk or mutates its input cannot change the answer. Nothing here decides an action. `decide` hooks return
 * "allow", "deny" or "escalate"; gate options are an Obj (or assoc array) with the reference's member names. Outcomes are assoc
 * arrays `{digest, decision | "error", diverged, widening}`.
 */
final class Shadow
{
    public const DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\0";
    public const EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\0";
    public const APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\0";
    private const DIFF_KEYS = ['v', 'shadow_digest', 'enforced_digest', 'action_digest', 'enforced', 'shadow', 'widening', 'at', 'signer'];

    private static function isKind(mixed $x): bool
    {
        return is_string($x) && Grants::rank($x) !== null;
    }

    /**
     * The enforced decision plus what each candidate (`['digest' => string, 'decide' => callable]`) would have said:
     * `['decision' => ..., 'shadow' => [outcome]]`. The returned decision is the enforced one, always.
     *
     * @return array{decision:mixed, shadow:list<array<string,mixed>>}
     */
    public static function runShadow(mixed $input, callable $enforced, array $candidates): array
    {
        $decision = $enforced($input);
        $shadow = [];
        foreach ($candidates as $c) {
            try {
                $d = ($c['decide'])(Grants::deepCopy($input));
                if (!self::isKind($d)) {
                    $shadow[] = ['digest' => $c['digest'], 'decision' => 'error', 'diverged' => false, 'widening' => false];
                } else {
                    $shadow[] = ['digest' => $c['digest'], 'decision' => $d, 'diverged' => $d !== $decision, 'widening' => Grants::gt(Grants::rank($d), Grants::rank($decision))];
                }
            } catch (\Throwable) { // a failing candidate is an error outcome, never an answer
                $shadow[] = ['digest' => $c['digest'], 'decision' => 'error', 'diverged' => false, 'widening' => false];
            }
        }
        return ['decision' => $decision, 'shadow' => $shadow];
    }

    /** The `shadow` member of a decision record, from the outcomes. @return list<array<string,mixed>> */
    public static function shadowRecordField(array $outcomes): array
    {
        return array_map(static fn(array $o): array => ['digest' => $o['digest'], 'decision' => $o['decision'], 'diverged' => $o['diverged']], $outcomes);
    }

    private static function pick(Obj $o, array $keys): Obj
    {
        $b = new Obj();
        foreach ($keys as $k) {
            $b->set($k, $o->get($k));
        }
        return $b;
    }

    /** A well formed diff signed by its own `signer` (and by `$signer` when given). Never throws. */
    public static function verifyShadowDiff(mixed $d, ?string $signer = null): bool
    {
        try {
            if (!($d instanceof Obj) || !K3Sig::isNumber($d->get('v'), 1.0)
                || !(K3Sig::isStr($d->get('shadow_digest'), 128) && K3Sig::isStr($d->get('enforced_digest'), 128) && K3Sig::isStr($d->get('action_digest'), 128))
                || !self::isKind($d->get('enforced')) || !self::isKind($d->get('shadow')) || !is_bool($d->get('widening'))
                || !K3Sig::isSafeInt($d->get('at')) || !K3Sig::isStr($d->get('signer'), 128)) {
                return false;
            }
            if ($d->get('enforced') === $d->get('shadow') || $d->get('widening') !== Grants::gt(Grants::rank($d->get('shadow')), Grants::rank($d->get('enforced')))) {
                return false;
            }
            if ($signer !== null && $d->get('signer') !== $signer) {
                return false;
            }
            return K3Sig::verifyBody(self::DIFF_DOMAIN, self::pick($d, self::DIFF_KEYS), $d->get('signer'), $d->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /** A principal states that this widening is intended (`reason_digest` binds the display-only reason text). */
    public static function signWideningExplanation(KeyPair $secret, mixed $e): Obj
    {
        $base = Obj::of(['v' => 1]);
        foreach (Grants::copy($e)->keys() as $k) {
            $base->set($k, $e->get($k));
        }
        $base->set('principal', $secret->public);
        $base->set('sig', Grants::signBody(self::EXPLANATION_DOMAIN, self::pick($base, ['v', 'shadow_digest', 'action_digest', 'reason_digest', 'principal']), $secret));
        return $base;
    }

    private static function verifyExplanation(mixed $e): bool
    {
        try {
            return $e instanceof Obj && K3Sig::isNumber($e->get('v'), 1.0)
                && K3Sig::isStr($e->get('shadow_digest'), 128) && K3Sig::isStr($e->get('action_digest'), 128)
                && K3Sig::isStr($e->get('reason_digest'), 128) && K3Sig::isStr($e->get('principal'), 128)
                && K3Sig::verifyBody(self::EXPLANATION_DOMAIN, self::pick($e, ['v', 'shadow_digest', 'action_digest', 'reason_digest', 'principal']), $e->get('principal'), $e->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    public static function signPromotionApproval(KeyPair $secret, mixed $a): Obj
    {
        $base = Obj::of(['v' => 1]);
        foreach (Grants::copy($a)->keys() as $k) {
            $base->set($k, $a->get($k));
        }
        $base->set('principal', $secret->public);
        $base->set('sig', Grants::signBody(self::APPROVAL_DOMAIN, self::pick($base, ['v', 'shadow_digest', 'enforced_digest', 'at', 'principal']), $secret));
        return $base;
    }

    private static function verifyApproval(mixed $a): bool
    {
        try {
            return $a instanceof Obj && K3Sig::isNumber($a->get('v'), 1.0) && K3Sig::isStr($a->get('shadow_digest'), 128) && K3Sig::isStr($a->get('enforced_digest'), 128)
                && K3Sig::isSafeInt($a->get('at')) && K3Sig::isStr($a->get('principal'), 128)
                && K3Sig::verifyBody(self::APPROVAL_DOMAIN, self::pick($a, ['v', 'shadow_digest', 'enforced_digest', 'at', 'principal']), $a->get('principal'), $a->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return array<string,mixed> */
    private static function no(string $code, string $reason, array $unexplained = []): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason] + ($unexplained !== [] ? ['unexplained' => $unexplained] : []);
    }

    /**
     * May this candidate be promoted? Enough samples, no candidate failures, every diff verifies, zero unexplained widenings, and a
     * principal-signed approval when the static verdict on the declared surfaces is `wider` or `unknown`. Fails closed.
     *
     * @return array<string,mixed>
     */
    public static function promotionGate(ShadowLog $log, mixed $o): array
    {
        try {
            $principals = Js::opt($o, 'principals');
            $minSamples = Js::opt($o, 'minSamples');
            $surface = Js::opt($o, 'surface');
            if (!K3Sig::isStr(Js::opt($o, 'shadow_digest'), 128) || !K3Sig::isStr(Js::opt($o, 'enforced_digest'), 128) || !K3Sig::isSafeInt($minSamples)
                || (float)K3Sig::num($minSamples) < 1 || !K3Sig::isList($principals) || !in_array($surface, ['narrower', 'equal', 'wider', 'unknown'], true)) {
                return self::no('bad_input', 'bad gate options');
            }
            $sd = Js::opt($o, 'shadow_digest');
            $ed = Js::opt($o, 'enforced_digest');
            $s = $log->stats($sd);
            if ($s['total'] < (float)K3Sig::num($minSamples)) {
                return self::no('too_few_samples', $s['total'] . ' observation(s), need ' . Js::str($minSamples));
            }
            if ($s['errors'] > 0) {
                return self::no('shadow_errors', $s['errors'] . ' observation(s) where the candidate failed');
            }
            $diffs = $log->diffs($sd);
            foreach ($diffs as $d) {
                if (!self::verifyShadowDiff($d, $log->signer()) || $d->get('shadow_digest') !== $sd || $d->get('enforced_digest') !== $ed) {
                    return self::no('bad_diff', 'a recorded diff does not verify, belongs to another pair, or is missing');
                }
            }
            if (count($diffs) !== $s['diverged']) {
                return self::no('bad_diff', 'a recorded diff does not verify, belongs to another pair, or is missing');
            }
            $explained = [];
            $exps = Js::opt($o, 'explanations');
            if ($exps === null) {
                $exps = [];
            } elseif (is_string($exps)) {
                $exps = preg_split('//u', $exps, -1, PREG_SPLIT_NO_EMPTY) ?: []; // for..of a string: its characters, none of them an explanation
            } elseif (!K3Sig::isList($exps)) {
                throw new \TypeError('explanations is not iterable');
            }
            foreach ($exps as $e) {
                if (self::verifyExplanation($e) && in_array($e->get('principal'), $principals, true) && $e->get('shadow_digest') === $sd) {
                    $explained[$e->get('action_digest')] = true;
                }
            }
            $un = [];
            foreach ($diffs as $d) {
                if ($d->get('widening') === true && !isset($explained[$d->get('action_digest')])) {
                    $un[$d->get('action_digest')] = true;
                }
            }
            $unexplained = K3Sig::sortedUtf16(array_map('strval', array_keys($un)));
            if ($unexplained !== []) {
                return self::no('unexplained_widening', count($unexplained) . " widening(s) without a principal's explanation", $unexplained);
            }
            if ($surface === 'wider' || $surface === 'unknown') {
                $a = Js::opt($o, 'approval');
                if (!self::verifyApproval($a) || !in_array($a->get('principal'), $principals, true) || $a->get('shadow_digest') !== $sd || $a->get('enforced_digest') !== $ed) {
                    return self::no('advisory_wider', 'the analyzer reports the candidate ' . ($surface === 'wider' ? 'wider' : 'not provably narrower')
                        . ' on the declared surfaces: a principal-signed approval is required');
                }
            }
            $w = 0;
            foreach ($diffs as $d) {
                $w += $d->get('widening') === true ? 1 : 0;
            }
            return ['ok' => true, 'samples' => $s['total'], 'widenings' => $w, 'surface' => $surface];
        } catch (\Throwable) {
            return self::no('bad_input', 'evaluation error (fail closed)');
        }
    }

    /**
     * The body of the bundle revision that makes the candidate the enforced policy: its content at revision + 1, chained to the
     * enforced revision, with the shadow list cleared. Needs a passing gate for this candidate, and the candidate must be listed in
     * the enforced revision's `shadow`. Sign it with {@see Grants::signBundle} / {@see Grants::assembleBundle} like any revision.
     *
     * @param array<string,mixed> $gate
     */
    public static function promoteShadow(Obj $enforced, Obj $candidate, array $gate, mixed $now): Obj
    {
        $digest = K3::bundleDigest($candidate);
        if (($gate['ok'] ?? false) !== true) {
            throw new \InvalidArgumentException('promoteShadow: the gate did not pass (' . ($gate['code'] ?? 'undefined') . ')');
        }
        $sh = $enforced->get('shadow');
        if (!is_array($sh) || !in_array($digest, $sh, true)) {
            throw new \InvalidArgumentException("promoteShadow: the candidate is not listed in the enforced revision's shadow");
        }
        if (!K3Sig::isSafeInt($now)) {
            throw new \InvalidArgumentException('promoteShadow: bad time');
        }
        $o = $candidate->without('sigs', 'shadow', 'prev');
        $o->set('revision', (int)K3Sig::num($enforced->get('revision')) + 1);
        $o->set('prev', K3::bundleDigest($enforced));
        $o->set('issued_at', $now);
        return $o;
    }
}

/** Collects the signed diffs and counters per candidate. In memory: persist `diffs()` to the decision log for the audit trail. */
final class ShadowLog
{
    /** @var array<string,array{total:int,diverged:int,widened:int,tightened:int,errors:int}> */
    private array $stat = [];
    /** @var array<string,list<Obj>> */
    private array $list = [];

    public function __construct(private readonly KeyPair $secret)
    {
    }

    public function signer(): string
    {
        return $this->secret->public;
    }

    /** Count one observation; sign and keep a diff when the candidate diverged. @param array<string,mixed> $outcome */
    public function observe(string $enforcedDigest, string $actionDigest, string $enforced, array $outcome, mixed $at): ?Obj
    {
        $k = 'k' . $outcome['digest'];
        $s = $this->stat[$k] ?? ['total' => 0, 'diverged' => 0, 'widened' => 0, 'tightened' => 0, 'errors' => 0];
        $s['total']++;
        if ($outcome['decision'] === 'error') {
            $s['errors']++;
            $this->stat[$k] = $s;
            return null;
        }
        if (!$outcome['diverged']) {
            $this->stat[$k] = $s;
            return null;
        }
        $s['diverged']++;
        $s[$outcome['widening'] ? 'widened' : 'tightened']++;
        $this->stat[$k] = $s;
        $diff = Obj::of(['v' => 1, 'shadow_digest' => $outcome['digest'], 'enforced_digest' => $enforcedDigest, 'action_digest' => $actionDigest,
            'enforced' => $enforced, 'shadow' => $outcome['decision'], 'widening' => $outcome['widening'], 'at' => $at, 'signer' => $this->signer()]);
        $diff->set('sig', Grants::signBody(Shadow::DIFF_DOMAIN, $diff, $this->secret));
        $this->list[$k][] = $diff;
        return $diff;
    }

    /** @return array{total:int,diverged:int,widened:int,tightened:int,errors:int} */
    public function stats(string $digest): array
    {
        return $this->stat['k' . $digest] ?? ['total' => 0, 'diverged' => 0, 'widened' => 0, 'tightened' => 0, 'errors' => 0];
    }

    /** @return list<Obj> */
    public function diffs(string $digest): array
    {
        return $this->list['k' . $digest] ?? [];
    }
}
