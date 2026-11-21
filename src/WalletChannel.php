<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/IntentOmega.php';

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/Webauthn.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletOmega.php';
require_once __DIR__ . '/WalletCard.php';

/**
 * The trusted question channel of the wallet (PCA Intent Layer v2): one instance per session. SELECTION belongs to the verifier
 * (questions enter only as a site-signed `intent_required`, re-derived by the wallet, or as a structured agent clarification whose cell
 * the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with harm; canaries are inserted with
 * probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate bound the questions; a cell is
 * asked at most once per session; under estimated noise an irreversible cell needs two confirmations.
 *
 * Options (assoc array or Obj): omega, session, mapDigest (Closure -> string), principalSecret (32-byte Ed25519 seed), site (Obj origin,
 * name, keys), view (assoc of Closures p, vetoed, outsideCeiling, confirmed over (verb, idx)), hourly (SlidingWindowCounter), noise
 * (Closure -> counts), onNoise (Closure(counts)), rand (Closure -> float in [0,1)), now (Closure -> int ms); optional statementText,
 * units, sensitivity, identityPaths, caps {perSession, perHour}, rho, fatigue, friction (thresholds), maxPerScreen, maxBoxCells, harm
 * (HarmModel), reversibility (Closure(vs, box)), lift (Closure(action)), liftCandidate (Closure(candidate)), device {credentials,
 * rpId, origins, signCounts (an Obj, updated in place)}. Results are assoc arrays with the reference's member names.
 */
final class WalletChannel
{
    private const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    /**
     * A grant view over an intent learner, with an optional ceiling predicate `insideCeiling(verb, idx)` (true = inside every ceiling):
     * the `view` option of a channel. An unknown verb is refused.
     * @return array{p:\Closure,vetoed:\Closure,outsideCeiling:\Closure,confirmed:\Closure}
     */
    public static function learnerView(IntentLearner $l, mixed $opts = null): array
    {
        $vsOf = static function (mixed $verb) use ($l): mixed {
            foreach (Js::opt($l->omega, 'verbs') as $v) {
                if (Js::opt($v, 'verb') === $verb) {
                    return $v;
                }
            }
            throw new \InvalidArgumentException('learnerView: unknown verb ' . (is_string($verb) ? $verb : gettype($verb)));
        };
        $inside = Js::opt($opts, 'insideCeiling');
        return [
            'p' => static fn(mixed $verb, mixed $idx) => $l->acceptance(IntentOmega::cellRep($vsOf($verb), $idx)),
            'vetoed' => static fn(mixed $verb, mixed $idx) => $l->isVetoed(IntentOmega::cellRep($vsOf($verb), $idx)),
            'outsideCeiling' => static fn(mixed $verb, mixed $idx): bool => $inside instanceof \Closure ? !$inside($verb, $idx) : false,
            'confirmed' => static function () use ($l): array {
                $out = [];
                foreach ($l->cells() as $c) {
                    if ($c['inGrant']) {
                        $out[] = ['verb' => $c['verb'], 'idx' => $c['cell']];
                    }
                }
                return $out;
            },
        ];
    }

    private const MAX_SAFE = 9007199254740991;

    /** @var array<string,array<string,mixed>> */
    private array $pending = [];
    /** @var array<string,true> */
    private array $asked = [];
    /** @var array<string,true> */
    private array $canaryUsed = [];
    /** @var list<array{verb:mixed,idx:list<int>}> */
    private array $knownYes = [];
    /** @var array<string,list<array<string,mixed>>> */
    private array $confirmations = [];
    /** @var list<array<string,mixed>> */
    private array $refusedWhileFrozen = [];
    private int $sessionQuestions = 0;
    private int $canaries = 0;
    private int $screenNo = 0;

    public function __construct(private readonly mixed $o)
    {
    }

    // ---- options ------------------------------------------------------------------------------------------------------------

    private function opt(string $k): mixed
    {
        return Js::opt($this->o, $k);
    }

    private function req(string $k): mixed
    {
        $v = $this->opt($k);
        if ($v === null) {
            throw new \InvalidArgumentException("missing option $k");
        }
        return $v;
    }

    private function perSession(): mixed
    {
        $v = Js::opt($this->opt('caps'), 'perSession');
        return $v === null ? 6 : $v;
    }

    private function perHour(): mixed
    {
        $v = Js::opt($this->opt('caps'), 'perHour');
        return $v === null ? 12 : $v;
    }

    private function fatigue(): mixed
    {
        $f = $this->opt('fatigue');
        return Jsx::truthy($f) ? $f : Wallet::DEFAULT_FATIGUE;
    }

    private function now(): int|float
    {
        return ($this->req('now'))();
    }

    private function harm(): HarmModel
    {
        $h = $this->opt('harm');
        return $h instanceof HarmModel ? $h : WalletOmega::defaultHarm();
    }

    private function hourlyCount(): int
    {
        return $this->req('hourly')->count($this->now());
    }

    /** The current noise state (eta+ under load, frozen?). @return array<string,mixed> */
    public function noise(): array
    {
        return Wallet::noiseState(($this->req('noise'))(), $this->hourlyCount(), $this->fatigue());
    }

    /** The admission policy the learner should use now (tau, eta+, eta-; double confirmation). @return array<string,mixed> */
    public function admission(): array
    {
        return Wallet::admissionPolicy($this->noise(), $this->fatigue());
    }

    public function questionsAsked(): int
    {
        return $this->sessionQuestions;
    }

    private function newId(): string
    {
        $s = 'q_';
        for ($i = 0; $i < 10; $i++) {
            $s .= self::B64U[((int)floor((float)(($this->req('rand'))()) * 64)) % 64];
        }
        return isset($this->pending[$s]) ? $this->newId() : $s;
    }

    private static function u16(string $s): string
    {
        return (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    private function vsOf(mixed $verb): mixed
    {
        foreach (Js::opt($this->opt('omega'), 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                return $v;
            }
        }
        throw new \InvalidArgumentException('unknown verb');
    }

    private function reversibilityOf(mixed $vs, array $box): mixed
    {
        $fn = $this->opt('reversibility');
        return $fn instanceof \Closure ? $fn($vs, $box) : Js::opt($vs, 'reversibility');
    }

    /** @param list<list<int>> $box @return array{weight:float,meanHarm:float|int}|null */
    private function boxStats(mixed $vs, array $box): ?array
    {
        $cells = Wallet::boxCells($box);
        $mx = $this->opt('maxBoxCells');
        if (count($cells) > ($mx === null ? 4096 : (float)Js::num($mx))) {
            return null;
        }
        $m = 0.0;
        $mh = 0.0;
        $harm = $this->harm();
        foreach ($cells as $idx) {
            $s = WalletOmega::cellStats($vs, $idx, $harm);
            $m += $s['mass'];
            $mh += $s['mass'] * $s['harm'];
        }
        return ['weight' => $mh, 'meanHarm' => $m > 0 ? $mh / $m : 0];
    }

    /** @param list<list<int>> $box */
    private function frictionOf(mixed $vs, array $box, mixed $meanHarm, mixed $siteMin, bool $irreversible): string
    {
        $provenance = [];
        $widensIdentity = false;
        $sens = $this->opt('sensitivity');
        $identityPaths = $this->opt('identityPaths');
        $identityPaths = is_array($identityPaths) && array_is_list($identityPaths) ? $identityPaths : [];
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            $path = (string)Js::opt($d, 'path');
            if (str_starts_with($path, 'env.prov.') && Js::opt($d, 'kind') === 'cat') {
                $param = substr($path, strlen('env.prov.'));
                $levels = [];
                foreach ($box[$k] as $i) {
                    $v = Js::opt($d, 'values')[$i];
                    $val = (string)Js::opt($v, 'value');
                    foreach (preg_split('/[|,]/', Js::opt($v, 'kind') === 'prefix' ? $val . '*' : $val) ?: [] as $l) {
                        $levels[] = $l;
                    }
                }
                $sv = Js::opt($sens, $param);
                $provenance[] = ['path' => $param, 'sensitivity' => Jsx::truthy($sv) ? $sv : 'material', 'levels' => $levels];
            }
            if (Js::opt($d, 'kind') === 'cat' && in_array($path, $identityPaths, true)) {
                // widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones
                foreach ($box[$k] as $i) {
                    if (Js::opt(Js::opt($d, 'values')[$i], 'kind') !== 'exact') {
                        $widensIdentity = true;
                        break;
                    }
                }
            }
        }
        $inp = ['reversibility' => $this->reversibilityOf($vs, $box), 'expectedHarm' => $meanHarm, 'provenance' => $provenance,
            'widensCriticalIdentity' => $widensIdentity];
        if (Jsx::truthy($siteMin)) {
            $inp['siteMin'] = $siteMin;
        }
        $th = $this->opt('friction');
        $tier = Wallet::frictionFor($inp, Jsx::truthy($th) ? $th : Wallet::DEFAULT_FRICTION_THRESHOLDS)['tier'];
        if ($irreversible && $this->admission()['doubleConfirmIrreversible']) {
            $tier = Wallet::maxFriction($tier, 'typed');
        }
        return $tier;
    }

    /** @param list<list<int>> $box @return array{card:Obj,friction:mixed}|null */
    private function render(string $kind, mixed $verb, mixed $coords, string $friction, mixed $action, mixed $vs, array $box, mixed $reason = null): ?array
    {
        $site = $this->opt('site');
        $base = new Obj();
        $base->set('omega', $this->opt('omega'));
        $base->set('verb', $verb);
        $base->set('coords', $coords);
        $base->set('site', Obj::of(['origin' => Wallet::req($site, 'origin'), 'name' => Wallet::req($site, 'name')]));
        if ($this->opt('statementText') !== null) {
            $base->set('statementText', $this->opt('statementText'));
        }
        $base->set('reversibility', $this->reversibilityOf($vs, $box));
        if (Jsx::truthy($this->opt('units'))) {
            $base->set('units', $this->opt('units'));
        }
        if (Jsx::truthy($action)) {
            $base->set('action', $action);
        }
        $base->set('kind', $kind);
        if (Jsx::truthy($reason)) {
            $base->set('reason', $reason);
        }
        $with = static function (string $f) use ($base): Obj {
            $o = new Obj();
            foreach ($base->keys() as $k) {
                $o->set($k, $base->get($k));
            }
            $o->set('friction', $f);
            return $o;
        };
        $r = WalletCard::renderCard($with($friction));
        // a typed question needs a value to type; with none on the card, the only stronger tier is the device
        if ($r['ok'] && Wallet::frictionRank($friction) === Wallet::frictionRank('typed') && !Jsx::truthy(Js::opt($r['card'], 'typed'))) {
            $r = WalletCard::renderCard($with('device'));
        }
        return $r['ok'] ? ['card' => $r['card'], 'friction' => Js::opt($r['card'], 'friction')] : null;
    }

    /** @return array<string,mixed> */
    private function gate(): array
    {
        if ($this->noise()['frozen']) {
            return ['ok' => false, 'code' => 'frozen', 'reason' => 'the estimated false-yes rate is above η_stop: no more questions this session'];
        }
        if (!($this->sessionQuestions < (float)Js::num($this->perSession()))) {
            return ['ok' => false, 'code' => 'cap_session', 'reason' => 'at most ' . Jsx::str($this->perSession()) . ' questions per session'];
        }
        if (!(is_finite((float)$this->now()) && $this->hourlyCount() < (float)Js::num($this->perHour()))) {
            return ['ok' => false, 'code' => 'cap_hour', 'reason' => 'at most ' . Jsx::str($this->perHour()) . ' questions per hour'];
        }
        return ['ok' => true];
    }

    /** @param array<string,mixed> $it (with `vs`) */
    private function enqueue(array $it): void
    {
        $vs = $it['vs'];
        unset($it['vs']);
        $it['flat'] = min(array_map(static fn(array $idx): int => Wallet::flatIndex($vs, $idx), Wallet::boxCells($it['box'])));
        $this->pending[$it['id']] = $it;
    }

    private function count(): void
    {
        $this->sessionQuestions++;
        if (!$this->req('hourly')->tryAdd($this->now(), self::MAX_SAFE)) {
            throw new \RuntimeException('unreachable');
        }
    }

    /** Insert a canary with probability rho (rendered and ordered like a real question). */
    private function maybeCanary(): void
    {
        $exclude = array_keys($this->canaryUsed);
        $lowHarm = true;
        foreach ($this->pending as $p) {
            foreach (Wallet::boxCells($p['box']) as $idx) {
                $exclude[] = Wallet::cellKey($p['verb'], $idx);
            }
            if ($p['kind'] === 'real' && Wallet::frictionRank(Js::opt($p['card'], 'friction')) > Wallet::frictionRank('hold')) {
                $lowHarm = false;
            }
        }
        $view = $this->req('view');
        $ctx = [
            'omega' => $this->opt('omega'), 'confirmed' => ($view['confirmed'])(),
            'knownNo' => static fn($verb, $idx) => ($view['outsideCeiling'])($verb, $idx) ? 'ceiling' : (($view['vetoed'])($verb, $idx) ? 'veto' : null),
            'knownYes' => $this->knownYes, 'exclude' => $exclude, 'rand' => $this->req('rand'), 'lowHarmSession' => $lowHarm, 'canariesSoFar' => $this->canaries,
        ];
        if ($this->opt('rho') !== null) {
            $ctx['rho'] = $this->opt('rho');
        }
        $c = Wallet::pickCanary($ctx);
        if ($c === null) {
            return;
        }
        $vs = $this->vsOf($c['verb']);
        $box = array_map(static fn(int $i): array => [$i], $c['idx']);
        $st = $this->boxStats($vs, $box);
        if ($st === null) {
            return;
        }
        $coords = Wallet::coordsOfCell($vs, $c['idx']);
        $action = Obj::of(['verb' => $c['verb'], 'values' => Js::opt(WalletOmega::cellRep($vs, $c['idx']), 'values')]);
        $friction = $this->frictionOf($vs, $box, $st['meanHarm'], null, false);
        $r = $this->render('question', $c['verb'], $coords, $friction, $action, $vs, $box);
        if ($r === null) {
            return;
        }
        $this->canaries++;
        $this->canaryUsed[Wallet::cellKey($c['verb'], $c['idx'])] = true;
        $this->enqueue(['id' => $this->newId(), 'kind' => 'canary', 'source' => 'elicitation', 'verb' => $c['verb'], 'box' => $box, 'coords' => $coords,
            'card' => $r['card'], 'action' => $action, 'irreversible' => false, 'expected' => $c['expected'], 'weight' => $st['weight'], 'jit' => false, 'vs' => $vs]);
    }

    /**
     * Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the agent
     * attempted (`$ctx` = {action}). Every check fails closed.
     * @return array<string,mixed>
     */
    public function receive(mixed $ir, mixed $ctx): array
    {
        $now = $this->now();
        $site = $this->req('site');
        $v = IntentV2::verifyIntentRequired($ir, Js::opt($site, 'keys'), $now);
        if (!$v['ok']) {
            return ['ok' => false, 'code' => 'bad_site_signature', 'reason' => $v['reason'] ?? ''];
        }
        if (Wallet::req($ir, 'session') !== $this->opt('session')) {
            return ['ok' => false, 'code' => 'wrong_session', 'reason' => 'the question is for another session'];
        }
        if (Wallet::req($ir, 'map_digest') !== ($this->req('mapDigest'))()) {
            return ['ok' => false, 'code' => 'stale_map', 'reason' => 'the question names another map version'];
        }
        $action = Wallet::req($ctx, 'action');
        $cell = Wallet::req($ir, 'cell');
        if (Wallet::req($action, 'verb') !== Wallet::req($cell, 'verb') || Wallet::pcaActionDigest($action) !== Wallet::req($ir, 'action_digest')) {
            return ['ok' => false, 'code' => 'action_mismatch', 'reason' => 'the action does not match the signed action digest'];
        }
        $liftFn = $this->opt('lift');
        $lifted = $liftFn instanceof \Closure ? $liftFn($action) : Wallet::actionValuesOf($action);
        $omega = $this->opt('omega');
        $r = Wallet::resolveCoords($omega, Wallet::req($cell, 'verb'), Wallet::req($cell, 'coords'));
        if (!$r['ok']) {
            return ['ok' => false, 'code' => 'cell_mismatch', 'reason' => $r['reason']];
        }
        $at = Wallet::cellOfAction($omega, $lifted);
        if ($at === null || !Wallet::cellInBox($r['box'], $at['idx'])) {
            return ['ok' => false, 'code' => 'cell_mismatch', 'reason' => "the action's cell (re-derived by the wallet) is not the cell the site names"];
        }
        $st = $this->boxStats($r['vs'], $r['box']);
        if ($st === null) {
            return ['ok' => false, 'code' => 'cell_too_large', 'reason' => 'the question covers too many cells'];
        }
        $cells = Wallet::boxCells($r['box']);
        $view = $this->req('view');
        $verb = Js::opt($r['vs'], 'verb');
        foreach ($cells as $idx) {
            if (($view['outsideCeiling'])($verb, $idx)) {
                return ['ok' => false, 'code' => 'not_uncertain', 'reason' => 'the cell is outside a ceiling: the principal cannot widen it'];
            }
            if (($view['vetoed'])($verb, $idx)) {
                return ['ok' => false, 'code' => 'not_uncertain', 'reason' => 'the cell was vetoed'];
            }
        }
        $pa = ($view['p'])($verb, $at['idx']);
        if (!($pa > 0 && $pa < 1)) {
            return ['ok' => false, 'code' => 'not_uncertain', 'reason' => $pa <= 0 ? 'the cell is denied' : 'the cell is already in the grant'];
        }
        foreach ($cells as $idx) {
            if (isset($this->asked[Wallet::cellKey($verb, $idx)])) {
                return ['ok' => false, 'code' => 'already_asked', 'reason' => 'a cell is asked at most once per session'];
            }
        }
        $g = $this->gate();
        if (!$g['ok']) {
            if ($g['code'] === 'frozen') {
                $this->refusedWhileFrozen[] = ['verb' => $verb, 'coords' => Wallet::req($cell, 'coords')];
            }
            return $g;
        }
        $irreversible = $this->reversibilityOf($r['vs'], $r['box']) === 'irreversible';
        $friction = $this->frictionOf($r['vs'], $r['box'], $st['meanHarm'], Wallet::req($ir, 'friction'), $irreversible);
        $rendered = $this->render('question', Wallet::req($cell, 'verb'), Wallet::req($cell, 'coords'), $friction, $lifted, $r['vs'], $r['box']);
        if ($rendered === null) {
            return ['ok' => false, 'code' => 'render_failed', 'reason' => 'the card could not be rendered'];
        }
        $qid = Wallet::req($ir, 'question_id');
        if (isset($this->pending[(string)$qid])) {
            return ['ok' => false, 'code' => 'already_asked', 'reason' => 'duplicate question id'];
        }
        foreach ($cells as $idx) {
            $this->asked[Wallet::cellKey($verb, $idx)] = true;
        }
        $this->count();
        $this->enqueue(['id' => (string)$qid, 'kind' => 'real', 'source' => 'elicitation', 'verb' => Wallet::req($cell, 'verb'), 'box' => $r['box'],
            'coords' => Wallet::req($cell, 'coords'), 'card' => $rendered['card'], 'action' => $lifted, 'actionDigest' => Wallet::req($ir, 'action_digest'),
            'irreversible' => $irreversible, 'weight' => $st['weight'], 'expiresAt' => (float)Js::num(Wallet::req($ir, 'expires_at')), 'jit' => true, 'vs' => $r['vs']]);
        $this->maybeCanary();
        return ['ok' => true, 'questionId' => $qid, 'friction' => $rendered['friction']];
    }

    /**
     * An agent clarification: {candidates: [<= 8 structured actions], reason}, no text. Certain cells are answered at once (dry run);
     * among the uncertain ones the wallet picks the most informative and asks it.
     * @return array<string,mixed>
     */
    public function clarify(mixed $body): array
    {
        $parsed = WalletCard::parseClarifyRequest($body);
        if (!$parsed['ok']) {
            return ['status' => 400, 'verdicts' => [], 'error' => $parsed['error']];
        }
        $request = $parsed['request'];
        $st = $this->noise();
        $liftCand = $this->opt('liftCandidate');
        $pin = [
            'omega' => $this->opt('omega'), 'view' => $this->req('view'), 'candidates' => Js::opt($request, 'candidates'), 'asked' => $this->asked,
            'etaPos' => min(0.5 - 1e-9, $st['etaPosBar']), 'etaNeg' => min(0.5 - 1e-9, $st['etaNegBar']), 'harm' => $this->harm(),
        ];
        if ($liftCand instanceof \Closure) {
            $pin['lift'] = $liftCand;
        }
        $plan = WalletCard::planClarification($pin);
        if ($plan['ask'] === null) {
            return ['status' => 200, 'verdicts' => $plan['verdicts']];
        }
        $g = $this->gate();
        if (!$g['ok']) {
            return ['status' => $g['code'] === 'frozen' ? 200 : 429, 'verdicts' => $plan['verdicts'], 'refused' => $g['code']];
        }
        $ask = $plan['ask'];
        $vs = $this->vsOf($ask['verb']);
        $box = array_map(static fn(int $i): array => [$i], $ask['idx']);
        $stats = $this->boxStats($vs, $box);
        if ($stats === null) {
            throw new \RuntimeException('a single cell exceeds the box limit');
        }
        $coords = Wallet::coordsOfCell($vs, $ask['idx']);
        $raw = Js::opt($request, 'candidates')[$ask['index']];
        $action = $liftCand instanceof \Closure ? $liftCand($raw) : $raw;
        $irreversible = $this->reversibilityOf($vs, $box) === 'irreversible';
        $friction = $this->frictionOf($vs, $box, $stats['meanHarm'], null, $irreversible);
        $rendered = $this->render('clarification', Js::opt($vs, 'verb'), $coords, $friction, $action, $vs, $box, Js::opt($request, 'reason'));
        if ($rendered === null) {
            return ['status' => 200, 'verdicts' => $plan['verdicts'], 'refused' => 'render_failed'];
        }
        $qid = $this->newId();
        $this->asked[Wallet::cellKey(Js::opt($vs, 'verb'), $ask['idx'])] = true;
        $this->count();
        $this->enqueue(['id' => $qid, 'kind' => 'real', 'source' => 'clarification', 'verb' => Js::opt($vs, 'verb'), 'box' => $box, 'coords' => $coords,
            'card' => $rendered['card'], 'action' => $action, 'irreversible' => $irreversible, 'weight' => $stats['weight'], 'jit' => false, 'vs' => $vs]);
        $this->maybeCanary();
        return ['status' => 200, 'verdicts' => $plan['verdicts'], 'questionId' => $qid];
    }

    /** Pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc. @return list<array<string,mixed>> */
    private function ordered(): array
    {
        $items = array_values($this->pending);
        usort($items, static function (array $a, array $b): int {
            $ra = Wallet::frictionRank(Js::opt($a['card'], 'friction'));
            $rb = Wallet::frictionRank(Js::opt($b['card'], 'friction'));
            return [$rb, $b['weight'], $a['flat'], self::u16((string)$a['id'])] <=> [$ra, $a['weight'], $b['flat'], self::u16((string)$b['id'])];
        });
        return $items;
    }

    /**
     * The next screen (null: nothing to show). A typed or device question is always alone; tap/hold questions share up to maxPerScreen.
     * @return array<string,mixed>|null
     */
    public function nextScreen(): ?array
    {
        $now = $this->now();
        foreach ($this->pending as $qid => $it) {
            if (isset($it['expiresAt']) && !(is_finite($now) && $now <= $it['expiresAt'])) {
                unset($this->pending[$qid]);
            }
        }
        $items = array_values(array_filter($this->ordered(), static fn(array $it): bool => !isset($it['shownOn'])));
        if (count($items) === 0) {
            return null;
        }
        $nxt = $this->screenNo + 1;
        $eligible = array_values(array_filter($items, static fn(array $it): bool => !isset($it['notBefore']) || $nxt >= $it['notBefore']));
        $this->screenNo = $nxt;
        if (count($eligible) === 0) {
            return ['screen' => $nxt, 'kind' => 'interstitial', 'questions' => []];
        }
        $first = $eligible[0];
        $picked = [$first];
        $hold = Wallet::frictionRank('hold');
        if (Wallet::frictionRank(Js::opt($first['card'], 'friction')) <= $hold) {
            $mx = $this->opt('maxPerScreen');
            $mx = $mx === null ? 3 : (float)Js::num($mx);
            foreach (array_slice($eligible, 1) as $it) {
                if (count($picked) >= $mx) {
                    break;
                }
                if (Wallet::frictionRank(Js::opt($it['card'], 'friction')) <= $hold) {
                    $picked[] = $it;
                }
            }
        }
        $qs = [];
        foreach ($picked as $it) {
            $this->pending[$it['id']]['shownOn'] = $nxt;
            $qs[] = ['questionId' => $it['id'], 'card' => $it['card']];
        }
        return ['screen' => $nxt, 'kind' => 'questions', 'questions' => $qs];
    }

    /** The principal's response to a shown question. @return array<string,mixed> */
    public function answer(mixed $questionId, mixed $response): array
    {
        $it = is_string($questionId) ? ($this->pending[$questionId] ?? null) : null;
        if ($it === null) {
            return ['ok' => false, 'code' => 'unknown_question', 'reason' => 'no such pending question'];
        }
        if (!isset($it['shownOn'])) {
            return ['ok' => false, 'code' => 'not_shown', 'reason' => 'the question was never shown'];
        }
        $now = $this->now();
        if (isset($it['expiresAt']) && !(is_finite($now) && $now <= $it['expiresAt'])) {
            unset($this->pending[$questionId]);
            return ['ok' => false, 'code' => 'expired', 'reason' => 'the question expired'];
        }
        if (!Wallet::isDict($response)) {
            throw new \TypeError('response is not an object');
        }
        $partial = null;
        $ans = Js::opt($response, 'answer');
        if ($ans === 'no') {
            $y = 0;
        } elseif ($ans === 'partly') {
            $e = WalletCard::partialError($it['card'], Js::opt($response, 'partial'));
            if ($e !== null && $e !== '') {
                return ['ok' => false, 'code' => 'bad_response', 'reason' => $e];
            }
            $y = 1;
            $partial = Js::opt($response, 'partial');
        } else {
            $y = 1;
        }
        $card = $it['card'];
        $friction = Js::opt($card, 'friction');
        $ux = Obj::of(['tier' => $friction, 'rendered_digest' => Js::opt($card, 'rendered_digest'), 'canary' => $it['kind'] === 'canary']);
        if ($y === 1) {
            $ev = $this->tierEvidence($it, $response, $questionId);
            if (!$ev['ok']) {
                return $ev;
            }
            foreach ($ev['ux']->keys() as $k) {
                $ux->set($k, $ev['ux']->get($k));
            }
        }
        $plainYes = $y === 1 && $partial === null;
        if ($it['kind'] !== 'canary' && $it['jit'] && $it['irreversible'] && $plainYes && Jsx::truthy($it['actionDigest'] ?? null)
            && Wallet::frictionRank($friction) >= Wallet::frictionRank('typed')) {
            $ux->set('action_digest', $it['actionDigest']);
            $ux->set('consent_for_action', true);
        }
        $body = Obj::of(['map_digest' => ($this->req('mapDigest'))(), 'session' => $this->opt('session'), 'question_id' => $questionId, 'verb' => $it['verb'],
            'cell' => $it['coords'], 'y' => $y]);
        if (Jsx::truthy($partial) && !($partial instanceof Obj && $partial->keys() === [])) {
            $body->set('partial', $partial);
        }
        $body->set('source', $it['source']);
        $body->set('observed_at', $now);
        $body->set('ux', $ux);
        $answer = Wallet::signIntentAnswer($body, $this->req('principalSecret'));
        unset($this->pending[$questionId]);
        if ($it['kind'] === 'canary') {
            ($this->req('onNoise'))(Wallet::recordCanary(($this->req('noise'))(), $it['expected'], $y));
            return ['ok' => true, 'kind' => 'canary', 'answer' => $answer];
        }
        if ($y === 0) {
            return ['ok' => true, 'kind' => 'veto', 'answer' => $answer];
        }
        $strong = Wallet::frictionRank($friction) >= Wallet::frictionRank('typed');
        $single = true;
        foreach ($it['box'] as $ids) {
            $single = $single && count($ids) === 1;
        }
        if ($plainYes && $strong && $single) {
            // a verified high-friction yes: a source of known-yes canaries
            $this->knownYes[] = ['verb' => $it['verb'], 'idx' => array_map(static fn(array $ids): int => $ids[0], $it['box'])];
        }
        if ($plainYes && $it['irreversible'] && $this->admission()['doubleConfirmIrreversible']) {
            $key = Jsx::str($it['verb']) . '|' . Js::stringify($it['coords']);
            $recs = [...($this->confirmations[$key] ?? []), ['screen' => $it['shownOn'], 'tier' => $friction]];
            $this->confirmations[$key] = $recs;
            if ($it['kind'] === 'confirmation' && Jsx::truthy($it['first'] ?? null) && Wallet::doubleConfirmed($recs)) {
                return ['ok' => true, 'kind' => 'confirmed', 'answers' => [$it['first'], $answer]];
            }
            if ($it['kind'] === 'confirmation') {
                return ['ok' => true, 'kind' => 'pending_confirmation', 'answer' => $answer];
            }
            // schedule the second, independent confirmation: at least one other screen in between
            $second = $it;
            $second['id'] = $this->newId();
            $second['kind'] = 'confirmation';
            $second['first'] = $answer;
            $second['notBefore'] = $it['shownOn'] + 2;
            unset($second['shownOn']);
            $this->pending[$second['id']] = $second;
            return ['ok' => true, 'kind' => 'pending_confirmation', 'answer' => $answer];
        }
        return ['ok' => true, 'kind' => 'answer', 'answer' => $answer];
    }

    /** @param array<string,mixed> $it @return array<string,mixed> */
    private function tierEvidence(array $it, mixed $response, string $questionId): array
    {
        $r = Js::opt($response, 'answer') === 'no' ? new Obj() : $response;
        $card = $it['card'];
        $tier = Js::opt($card, 'friction');
        if ($tier === 'tap') {
            return ['ok' => true, 'ux' => new Obj()];
        }
        if ($tier === 'hold') {
            $hm = Js::opt($r, 'holdMs');
            $f = Js::num($hm);
            if (!(Js::isNum($hm) && is_finite($f) && $f == floor($f) && $f >= Wallet::MIN_HOLD_MS)) {
                return ['ok' => false, 'code' => 'tier_evidence', 'reason' => 'hold for at least ' . Wallet::MIN_HOLD_MS . ' ms'];
            }
            return ['ok' => true, 'ux' => Obj::of(['hold_ms' => $hm])];
        }
        if ($tier === 'typed') {
            $t = Js::opt($card, 'typed');
            if (!Jsx::truthy($t) || !Jsx::truthy($it['action'] ?? null) || !is_string(Js::opt($r, 'typed'))) {
                return ['ok' => false, 'code' => 'tier_evidence', 'reason' => 'type the value shown on the card'];
            }
            $want = WalletCard::expectedTyped($card, $it['action']);
            $units = $this->opt('units');
            $got = WalletCard::normalizeTyped(Js::opt($r, 'typed'), Js::opt($t, 'mode'), Jsx::truthy($units) ? Js::opt($units, (string)Js::opt($t, 'path')) : null);
            if ($want === null || $got === null || $got !== $want) {
                return ['ok' => false, 'code' => 'typed_mismatch', 'reason' => 'the typed value does not match the card'];
            }
            return ['ok' => true, 'ux' => Obj::of(['typed_digest' => Wallet::typedDigest($questionId, $got)])];
        }
        if ($tier === 'device') {
            $wa = Js::opt($r, 'webauthn');
            $dev = $this->opt('device');
            if (!Jsx::truthy($wa) || !Jsx::truthy($dev)) {
                return ['ok' => false, 'code' => 'tier_evidence', 'reason' => 'a security-key assertion is required'];
            }
            $cred = Js::opt($wa, 'credential_id');
            $pk = is_string($cred) ? Js::opt(Js::opt($dev, 'credentials'), $cred) : null;
            $ad = Pca::unb64u(Js::opt($wa, 'authenticator_data'));
            $cd = Pca::unb64u(Js::opt($wa, 'client_data_json'));
            $sg = Pca::unb64u(Js::opt($wa, 'signature'));
            if (!Jsx::truthy($pk) || $ad === null || $cd === null || $sg === null) {
                return ['ok' => false, 'code' => 'tier_evidence', 'reason' => 'unknown credential or malformed assertion'];
            }
            $challenge = $this->deviceChallengeOf($it, $questionId);
            $counts = Js::opt($dev, 'signCounts');
            $stored = $counts instanceof Obj && $counts->has($cred) ? (int)Js::num($counts->get($cred)) : 0;
            $res = Webauthn::verifyAssertion(
                ['authenticatorData' => $ad, 'clientDataJSON' => $cd, 'signature' => $sg, 'publicKey' => $pk],
                ['expectedChallenge' => $challenge, 'rpId' => Js::opt($dev, 'rpId'), 'origins' => Js::opt($dev, 'origins'), 'requireUV' => true, 'storedSignCount' => $stored]
            );
            if (!$res['ok']) {
                return ['ok' => false, 'code' => 'tier_evidence', 'reason' => 'security key: ' . $res['reason']];
            }
            if ($counts instanceof Obj) {
                $counts->set($cred, $res['signCount']);
            }
            return ['ok' => true, 'ux' => Obj::of(['webauthn' => $wa])];
        }
        throw new \InvalidArgumentException('unknown friction tier');
    }

    /** @param array<string,mixed> $it */
    private function deviceChallengeOf(array $it, string $questionId): string
    {
        $bound = $it['jit'] && $it['irreversible'] && Jsx::truthy($it['actionDigest'] ?? null);
        return Wallet::deviceChallenge($questionId, Js::opt($it['card'], 'rendered_digest'), new Num('1'), $bound ? $it['actionDigest'] : null);
    }

    /** The WebAuthn challenge the wallet UI passes to navigator.credentials.get for a shown device-tier question. */
    public function deviceChallengeFor(mixed $questionId): ?string
    {
        $it = is_string($questionId) ? ($this->pending[$questionId] ?? null) : null;
        if ($it === null || !isset($it['shownOn']) || Js::opt($it['card'], 'friction') !== 'device') {
            return null;
        }
        return $this->deviceChallengeOf($it, $questionId);
    }

    /** The end-of-session summary shown instead of questions once the session froze. @return array<string,mixed> */
    public function summary(): array
    {
        return ['frozen' => $this->noise()['frozen'], 'refused' => $this->refusedWhileFrozen, 'asked' => $this->sessionQuestions, 'canaries' => $this->canaries];
    }

    /** A stable digest of the channel's pending state (for tests and audit logs). */
    public function stateDigest(): string
    {
        $p = [];
        foreach ($this->ordered() as $i) {
            $p[] = Obj::of(['id' => $i['id'], 'k' => $i['kind'], 'd' => Js::opt($i['card'], 'rendered_digest')]);
        }
        $asked = array_map('strval', array_keys($this->asked));
        usort($asked, static fn(string $a, string $b): int => strcmp(self::u16($a), self::u16($b)));
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/wallet-channel-state/v1', 'p' => $p, 'a' => $asked, 'n' => new Num((string)$this->sessionQuestions)]));
    }
}
