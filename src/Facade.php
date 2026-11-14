<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/ArgProvenance.php';

/**
 * The high-level agent facade: compile a principal's human-level inputs (permissions, limits) into a signed grant, and act.
 *
 *     $a = Agent::fromPrincipal(principal: $principalKey, goal: 'reconcile refunds for October',
 *         permissions: ['stripe' => ['refund'], 'gmail' => ['send']], limits: ['refund' => '$500/day'], aud: 'https://api.example.com');
 *     $r = $a->act('stripe.refund', 'charge:ch_123', ['amount' => 42, 'currency' => 'usd']);
 *     // send $r['headers'] (PCA-Action, and PCA-Provenance when the bundle fits a header) with the request
 *
 * {@see createAgent} compiles the permissions into predicates, caveats and a risk policy ({@see compilePolicy}), creates the
 * provenance recorder whose key the grant's signed envelope names, and mints the root grant. `act` builds a signed PCActn per tool
 * call with its provenance bundle; `dryRun` is a local, NON-authoritative pre-check. Nothing here authorizes anything: the resource
 * server's verifier decides. Same compile and wire as the TypeScript reference's `agent()`. Keep the provenance recorder in the
 * harness, out of the model's reach.
 */
final class Facade
{
    /** Longest limit string accepted (the grammar needs about 20 characters); bounds the work and the error text. */
    public const MAX_LIMIT_LENGTH = 64;
    private const PERIODS = [
        's' => 1000, 'sec' => 1000, 'second' => 1000, 'seconds' => 1000,
        'm' => 60000, 'min' => 60000, 'minute' => 60000, 'minutes' => 60000,
        'h' => 3600000, 'hr' => 3600000, 'hour' => 3600000, 'hours' => 3600000,
        'd' => 86400000, 'day' => 86400000, 'days' => 86400000,
        'w' => 604800000, 'week' => 604800000, 'weeks' => 604800000,
        'mo' => 2592000000, 'month' => 2592000000, 'months' => 2592000000,
    ];
    /** ECMAScript WhiteSpace and LineTerminator: what the reference's trim() and \s cover. */
    private const WS = '[\t\n\x{0B}\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]';
    private const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];

    /**
     * Parse "$500/day", "$500", "10/hour", "10" into ['amount', 'unit' => 'usd' | 'count', 'periodMs'?]. Throws on anything
     * malformed or longer than {@see MAX_LIMIT_LENGTH} characters, with the reference's messages.
     * @return array{amount:int|float, unit:string, periodMs?:int}
     */
    public static function parseLimit(mixed $s): array
    {
        $t = is_string($s) ? preg_replace('/\A' . self::WS . '+|' . self::WS . '+\z/u', '', $s) : null;
        if ($t === null || $t === '') {
            throw new \InvalidArgumentException('parseLimit: empty limit');
        }
        if (intdiv(strlen(mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2) > self::MAX_LIMIT_LENGTH) {
            throw new \InvalidArgumentException('parseLimit: limit is longer than ' . self::MAX_LIMIT_LENGTH . ' characters');
        }
        $w = self::WS . '*';
        if (preg_match('/\A(\$)?' . $w . '([0-9]+(?:\.[0-9]+)?)' . $w . '(?:\/' . $w . '([a-zA-Z]+))?\z/u', $t, $m) !== 1) {
            throw new \InvalidArgumentException("parseLimit: cannot parse limit '$s'");
        }
        $f = (float)$m[2];
        $out = ['amount' => $f === floor($f) && $f <= 9007199254740991 ? (int)$f : $f, 'unit' => $m[1] === '$' ? 'usd' : 'count'];
        if (isset($m[3])) {
            $out['periodMs'] = self::PERIODS[strtolower($m[3])] ?? throw new \InvalidArgumentException("parseLimit: unknown period '{$m[3]}' in '$s'");
        }
        return $out;
    }

    /** An associative array of an Obj (shallow), or the array itself. */
    private static function map(mixed $v): array
    {
        if ($v instanceof Obj) {
            $a = [];
            foreach ($v->keys() as $k) {
                $a[$k] = $v->get($k);
            }
            return $a;
        }
        return is_array($v) ? $v : [];
    }

    /**
     * The catalog spec of `$verb`: the exact verb, else the one action of its connector that has the verb's action as an alias,
     * else an uncatalogued spec that counts as irreversible with blast radius 0.8.
     * @return array<string,mixed>
     */
    public static function specFor(Catalog $catalog, string $verb): array
    {
        $dot = strpos($verb, '.');
        $s = $catalog->get($verb) ?? ($dot > 0 ? $catalog->resolve(substr($verb, 0, $dot), substr($verb, $dot + 1)) : null);
        if ($s !== null) {
            return $s;
        }
        $parts = explode('.', $verb);
        $action = implode('.', array_slice($parts, 1));
        return ['connector' => $parts[0], 'action' => $action === '' ? $verb : $action, 'verb' => $verb, 'reversibility' => 'irreversible',
            'blastRadius' => 0.8, 'description' => "(uncatalogued) $verb"];
    }

    private static function sev(mixed $cls): int
    {
        $i = array_search($cls, self::REVERSIBILITY_ORDER, true);
        return $i === false ? -1 : $i;
    }

    /**
     * Compile permissions (`[connector => [action, ...]]`) and limits (`[action | connector.action | alias => '$N[/period]' |
     * 'N[/period]']`) into ['predicates', 'caveats', 'riskPolicy', 'actions', 'budgetModel', 'limits', 'inputLimits',
     * 'approximations'] (the reference's member names). Pure: no keys. A money limit becomes a per-call ceiling on the action's
     * amount field; a period becomes the grant lifetime (`expires`); each count limit with a period becomes one `rate` caveat;
     * `reversibility_max` is the strictest granted class. A money limit on a verb without an amount field is refused (it could not
     * be enforced). Arrays and the verifier's Obj are both accepted.
     * @return array<string,mixed>
     */
    public static function compilePolicy(array|Obj $permissions, array|Obj|null $limits = null, ?Catalog $catalog = null, ?string $budgetModel = null,
                                         ?array $riskPolicy = null, ?int $now = null): array
    {
        $catalog ??= new Catalog();
        $now ??= (int)(microtime(true) * 1000);
        $raw = self::map($limits);
        $actions = [];
        foreach (self::map($permissions) as $connector => $acts) {
            if (!is_array($acts) || !array_is_list($acts)) {
                throw new \InvalidArgumentException("compilePolicy: permissions.$connector must be an array");
            }
            foreach ($acts as $a) {
                $actions[] = self::specFor($catalog, "$connector." . (is_string($a) ? $a : json_encode(Sign::plain($a))));
            }
        }
        if ($actions === []) {
            throw new \InvalidArgumentException('compilePolicy: no permissions granted');
        }
        $parsed = [];
        // the reference's `own(verb) ?? own(action) ?? own(alias)...`: a JSON null falls through, and a null at the end is parsed (and refused)
        $limitFor = static function (array $s) use ($raw, &$parsed): ?array {
            $lim = null; // $found is set on the first key: $lim starts null
            foreach ([$s['verb'], $s['action'], ...($s['aliases'] ?? [])] as $k) {
                if ($lim === null) {
                    $found = array_key_exists($k, $raw);
                    $lim = $raw[$k] ?? null;
                }
            }
            return $found ? $parsed[$s['verb']] = self::parseLimit($lim) : null;
        };
        $predicates = [];
        foreach ($actions as $s) {
            $lim = $limitFor($s);
            $p = ['verb' => $s['verb'], 'resource' => $s['resource'] ?? '*'];
            if ($lim !== null && $lim['unit'] === 'usd') {
                $field = $s['amountField'] ?? throw new \InvalidArgumentException("compilePolicy: '\$' limit on '{$s['verb']}' but the catalog gives that verb no amount field, so the limit could not be enforced");
                $p['where'] = [['field' => "action.params.$field", 'op' => 'lte', 'value' => $lim['amount']],
                    ['field' => "action.params.$field", 'op' => 'gte', 'value' => 0]];
            }
            $predicates[] = $p;
        }
        $strictest = 'reversible';
        foreach ($actions as $s) {
            if (self::sev($s['reversibility']) > self::sev($strictest)) {
                $strictest = $s['reversibility'];
            }
        }
        $caveats = [['type' => 'reversibility_max', 'class' => $strictest]];
        $periods = array_filter(array_map(static fn(array $l): ?int => $l['periodMs'] ?? null, $parsed), 'is_int');
        if ($periods !== []) {
            $caveats[] = ['type' => 'expires', 'at' => $now + min($periods)];
        }
        foreach ($parsed as $l) { // one rate caveat per count limit: a second limit can only narrow
            if ($l['unit'] === 'count' && isset($l['periodMs'])) {
                $caveats[] = ['type' => 'rate', 'max' => $l['amount'], 'per_secs' => max(1, (int)floor($l['periodMs'] / 1000 + 0.5))];
            }
        }
        $dollars = array_filter($parsed, static fn(array $l): bool => $l['unit'] === 'usd');
        $model = $budgetModel === 'dollars' || $budgetModel === 'risk' ? $budgetModel : ($dollars !== [] ? 'dollars' : 'risk');
        $def = Sign::defaultRiskPolicy();
        $rp = $def;
        if ($model === 'dollars' && $dollars !== []) {
            $irreversible = in_array('irreversible', array_column($actions, 'reversibility'), true);
            $kappa = max(array_column($dollars, 'amount'));
            $bMax = array_sum(array_column($dollars, 'amount'));
            // within-cap actions auto-approve only when nothing granted is irreversible
            $rp = ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0],
                'theta1' => $irreversible ? $def['theta1'] : 1, 'theta2' => $irreversible ? $def['theta2'] : 1, 'kappa' => $kappa > 0 ? $kappa : 1,
                'lambda' => 0, 'rho' => $def['rho'], 'bMax' => $bMax > 0 ? $bMax : 1];
        }
        if ($riskPolicy !== null) {
            $w = array_replace($rp['weights'], $riskPolicy['weights'] ?? []);
            $rp = array_replace($rp, $riskPolicy);
            $rp['weights'] = $w;
        }
        $bad = Sign::riskPolicyError($rp);
        if ($bad !== null) {
            throw new \InvalidArgumentException("compilePolicy: derived risk policy invalid: $bad");
        }
        $approx = [];
        foreach ($parsed as $v => $l) {
            if ($l['unit'] === 'usd' && isset($l['periodMs'])) {
                $approx[] = "$v: \$" . IntentV2::jsNumStr($l['amount']) . '/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap';
            }
        }
        return ['predicates' => $predicates, 'caveats' => $caveats, 'riskPolicy' => $rp, 'actions' => $actions, 'budgetModel' => $model,
            'limits' => $parsed, 'inputLimits' => $raw, 'approximations' => $approx];
    }

    /** ECMAScript Number() of a parameter value (NaN when it is not a number; an array reads as its String(), like the reference). */
    private static function toNumber(mixed $v): float
    {
        return match (true) {
            $v === null => 0.0,
            is_bool($v) => $v ? 1.0 : 0.0,
            is_int($v), is_float($v) => (float)$v,
            $v instanceof Num => $v->float(),
            is_string($v) => IntentWb::jsNumber($v),
            is_array($v) && array_is_list($v) => IntentWb::jsNumber(IntentWb::jsStr($v)),
            default => NAN,
        };
    }

    /** The risk the action claims: the override, else amount / kappa under the dollars model, else the blast radius; in [0, 1]. */
    public static function riskFor(array $policy, array $spec, mixed $params, int|float|null $override = null): int|float
    {
        $clamp = static fn(int|float $x): int|float => max(0, min(1, $x));
        if ($override !== null) {
            return $clamp($override);
        }
        $field = $spec['amountField'] ?? null;
        if ($policy['budgetModel'] === 'dollars' && $field !== null) {
            $p = self::map($params);
            $amt = array_key_exists($field, $p) ? self::toNumber($p[$field]) : NAN;
            if (is_finite($amt) && $policy['riskPolicy']['kappa'] > 0) {
                return $clamp($amt / $policy['riskPolicy']['kappa']);
            }
        }
        return $clamp($spec['blastRadius']);
    }

    /**
     * Compile the principal's inputs into a signed root grant for `$holder` (generated when null) and return the handle.
     *
     * `$limits` keys are a bare action ("refund"), a full verb ("stripe.refund") or an alias. `$budgetModel` 'dollars' makes
     * spend = risk exact when limits are monetary (null picks it iff a '$' limit is present). `$provenance` overrides the recorder's
     * {@see ProvenanceRecorder} arguments (mediator 'agent-harness', kid 'k1', key, session, now, alg, pq); its key is named in the
     * grant's signed envelope (`provenance.mediators`). `$goalSalt` fixes the goal commitment's salt.
     */
    public static function createAgent(KeyPair $principal, string $goal, array|Obj $permissions, array|Obj|null $limits = null, ?KeyPair $holder = null,
                                       mixed $agentBinding = null, ?array $riskPolicy = null, ?string $budgetModel = null, ?Catalog $catalog = null,
                                       ?string $aud = null, ?int $now = null, ?string $goalSalt = null, array $provenance = []): AgentHandle
    {
        $catalog ??= new Catalog();
        $now ??= (int)(microtime(true) * 1000);
        $holder ??= KeyPair::generate();
        $policy = self::compilePolicy($permissions, $limits, $catalog, $budgetModel, $riskPolicy, $now);
        $recorder = new ProvenanceRecorder(...($provenance + ['mediator' => 'agent-harness', 'kid' => 'k1']));
        $minted = Sign::mintGrant($principal, $holder->public, ['predicates' => $policy['predicates'], 'caveats' => $policy['caveats'],
            'agent_binding' => $agentBinding ?? new Obj(), 'risk_policy' => $policy['riskPolicy'],
            // the principal designates the harness's mediator key: a verifier trusts its labels with no extra configuration
            'provenance' => ['mediators' => [$recorder->pin]]], $goal, $goalSalt);
        return new AgentHandle($minted['grant'], [$minted['grant']], $minted['goal_salt'], $policy, $holder, $principal->public, $catalog, $aud, $now, $recorder);
    }
}

/**
 * What {@see Facade::createAgent} returns: the signed grant and chain, the compiled policy, the holder key, the starting trust budget,
 * and `act` / `dryRun` / `subAgent` / `encodeGrant`. `provenance` is the session's recorder: record the principal's message and every
 * tool, retrieval or web result entering the model's context; `act` appends the action.
 */
final class AgentHandle
{
    /** The last counter used (auto-incremented by `act`). */
    public int $counter = 0;
    /** The starting trust budget (B = bMax), metered by the server; for planning. */
    public readonly array $budget;
    /** The most this agent can do between human co-signs: bMax / kappa * kappa. */
    public readonly int|float $autonomyBound;

    /** @param Obj[] $chain */
    public function __construct(public readonly Obj $grant, public readonly array $chain, public readonly string $goalSalt, public readonly array $policy,
                                public readonly KeyPair $holder, public readonly string $principalPublic, private readonly Catalog $catalog,
                                private readonly ?string $aud, private readonly int $startNow, public readonly ?ProvenanceRecorder $provenance)
    {
        $rp = $policy['riskPolicy'];
        $this->budget = ['B' => $rp['bMax'], 'tau' => $startNow, 'asOf' => $startNow];
        $this->autonomyBound = ($rp['kappa'] > 0 ? max(0, $rp['bMax']) / $rp['kappa'] : 0) * $rp['kappa'];
    }

    /**
     * Local, NON-authoritative pre-check of the grant's own predicates and caveats: ['allowed', 'reason'?, 't'?] where `t` is the
     * risk tier the compiled policy would assign (1 automatic, 2, 3 human co-sign).
     */
    public function dryRun(string $verb, string $resource, mixed $params = null, ?int $now = null): array
    {
        $spec = Facade::specFor($this->catalog, $verb);
        $action = Sign::n(['verb' => $verb, 'resource' => $resource, 'params' => $params ?? new Obj(), 'reversibility_class' => $spec['reversibility']]);
        $pred = Predicates::evaluatePredicates(Sign::n($this->policy['predicates']), Obj::of(['action' => $action]));
        if ($pred['allowed'] !== true) {
            return ['allowed' => false, 'reason' => $pred['reason'] ?? 'no predicate matched'];
        }
        $cav = Pca::evaluateCaveats(Sign::n($this->policy['caveats']), Sign::n(['now' => $now ?? (int)(microtime(true) * 1000),
            'blast_radius' => $spec['blastRadius'], 'reversibility_class' => $spec['reversibility'], 'delegation_depth' => count($this->chain) - 1,
            // the local handle has no admitted-action history (the server meters it)
            'recent_action_times' => []]));
        if (!$cav['ok']) {
            return ['allowed' => false, 'reason' => 'caveat(s) failed: ' . implode(', ', $cav['failed'])];
        }
        $rp = $this->policy['riskPolicy'];
        $r = (float)Facade::riskFor($this->policy, $spec, $params);
        $t = Risk::requiredThreshold($r, (float)$rp['theta1'], (float)$rp['theta2'])['t'];
        return ['allowed' => true, 't' => Risk::admission($t, $this->budget['B'] >= Risk::cost($r, (float)$rp['kappa']))['t']];
    }

    /**
     * Build a proof-carrying action (it does NOT authorize): ['pcactn', 'encoded', 'headers', 'dryRun', 'provenance']. Send `headers`
     * (PCA-Action, and PCA-Provenance when the bundle fits a header; else send `provenance` as the body member `pca_provenance`).
     * The one-node plan is `n0` with the catalog's reversibility and the params digest. The counter auto-increments unless given;
     * no nonce unless given.
     */
    public function act(string $verb, string $resource, mixed $params = null, ?int $counter = null, ?string $aud = null, ?int $now = null,
                        ?int $ttlMs = null, ?string $nonce = null, int|float|null $caution = null, int|float|null $risk = null): array
    {
        $a = $aud ?? $this->aud;
        if ($a === null || $a === '') {
            throw new \InvalidArgumentException('act: aud (resource-server / instance id) is required (pass aud here or to createAgent)');
        }
        $params = $params === [] ? new Obj() : $params; // PHP's [] is the empty params object here
        $spec = Facade::specFor($this->catalog, $verb);
        // the node commits the SAME params digest the action carries, else plan inclusion fails
        $node = ['id' => 'n0', 'verb' => $verb, 'resource' => $resource, 'reversibility_class' => $spec['reversibility'],
            'params_digest' => Pca::paramsDigest($params === null ? null : Sign::n($params))];
        $r = Facade::riskFor($this->policy, $spec, $params, $risk);
        $use = $counter ?? $this->counter + 1;
        $this->counter = max($this->counter, $use);
        $pcactn = Sign::buildPcactn($this->grant, $this->chain, [$node], 'n0', $use, $this->holder, $a, $params, $now, null, $ttlMs ?? Sign::DEFAULT_TTL_MS,
            ['nonce' => $nonce, 'caution' => $caution, 'risk_claim' => ['r' => $r, 'inputs' => ['blastRadius' => $r]]]);
        $bundle = $this->provenance?->forAction(['verb' => $verb, 'resource' => $resource, 'params' => $params ?? new Obj()]);
        return ['pcactn' => $pcactn, 'encoded' => Json::canonicalizeLenient($pcactn), 'headers' => Sign::headers($pcactn, [], null, null, $bundle),
            'dryRun' => $this->dryRun($verb, $resource, $params, $now), 'provenance' => $bundle];
    }

    /**
     * A handle for a sub-agent (a fresh Ed25519 holder unless given) whose chain has one more, narrower hop signed by this holder.
     * It shares the policy, catalog and provenance recorder. A post-quantum sub-agent goes through {@see Agent::delegate}.
     */
    public function subAgent(?KeyPair $holder = null, array $addedCaveats = []): self
    {
        $sub = $holder ?? KeyPair::generate();
        $child = Sign::delegate($this->chain[count($this->chain) - 1], $this->holder, $sub->public, $addedCaveats);
        return new self($this->grant, [...$this->chain, $child], $this->goalSalt, $this->policy, $sub, $this->principalPublic, $this->catalog,
            $this->aud, $this->startNow, $this->provenance);
    }

    /** The grant as canonical JSON text, for transport or inspection. */
    public function encodeGrant(): string
    {
        return Json::canonicalizeLenient($this->grant);
    }
}
