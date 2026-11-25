<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/SignersMore.php';

/**
 * Lazy just-in-time elicitation: the ordered per-visit decision, the cell coordinates carried by a signed `pca-intent-required`, its
 * wallet-side body, and the delta cells between two answers. A "learner" is an IntentLearner; signing / verifying the required notice
 * and minting the signed delta grant go through the core signers.
 */
final class IntentJit
{
    public const INTENT_ACTION_DOMAIN = 'atlas-pca/intent-action/v1';

    private static function plain(mixed $x): mixed
    {
        return WalletOmega::plain($x);
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

    /**
     * The ordered lazy-elicitation decision: schema violation, ceiling, denied, admit, or intent_required. Input: learner, lifted, conform
     * ({ok, code?, reason?}), ceilings (list of Closure(verbSpace, outcome): bool), inEffective.
     * @return array<string,mixed>
     */
    public static function decideVisit(mixed $i): array
    {
        $conform = Js::opt($i, 'conform');
        if (!Js::truthy(Js::opt($conform, 'ok'))) {
            $reason = Js::opt($conform, 'reason');
            return ['kind' => 'schema_violation', 'reason' => Js::str(Js::opt($conform, 'code')) . ': ' . ($reason === null && !Js::has($conform, 'reason') ? 'undefined' : Js::str($reason))];
        }
        $learner = Js::opt($i, 'learner');
        $lifted = Js::opt($i, 'lifted');
        $vs = self::vsOf($learner->omega, Js::opt($lifted, 'verb'));
        $cell = $vs !== null ? IntentOmega::cellOf($vs, $lifted) : null;
        if ($vs === null || $cell === null) {
            return ['kind' => 'schema_violation', 'reason' => "the lifted action lies outside \u{03A9}\u{0303}"];
        }
        foreach (Js::opt($i, 'ceilings') ?? [] as $ceiling) {
            if (!$ceiling($vs, $lifted)) {
                return ['kind' => 'ceiling'];
            }
        }
        $vetoed = $learner->isVetoed($lifted);
        $p = $learner->acceptance($lifted);
        if ($vetoed || $p <= 0) {
            return ['kind' => 'intent_denied', 'vetoed' => $vetoed];
        }
        if (Js::truthy(Js::opt($i, 'inEffective'))) {
            return ['kind' => 'admit', 'cell' => $cell];
        }
        return ['kind' => 'intent_required', 'cell' => $cell, 'p' => $p];
    }

    /** The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). Never text about the value. */
    public static function cellCoords(mixed $vs, mixed $cell): Obj
    {
        if (!Js::isObj($vs)) {
            throw new \TypeError('cellCoords: no verb space');
        }
        $vs = self::plain($vs);
        $cell = self::plain($cell);
        $out = new Obj();
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            if (Js::opt($d, 'kind') === 'num') {
                $out->set(Js::opt($d, 'path'), [$cell[$k], $cell[$k]]);
            } else {
                $v = Js::opt($d, 'values')[$cell[$k]] ?? throw new \OutOfRangeException('cell index out of range');
                $out->set(Js::opt($d, 'path'), [Js::opt($v, 'value')]);
            }
        }
        return $out;
    }

    /** Coordinates -> per-dimension cell indices (the inverse of cellCoords for one cell), or null. @return list<int|float>|null */
    public static function cellFromCoords(mixed $vs, mixed $coords): ?array
    {
        $vs = self::plain($vs);
        $coords = self::plain($coords);
        $dims = Js::opt($vs, 'dims');
        if (!($coords instanceof Obj) || count($coords->keys()) !== count($dims)) {
            return null;
        }
        $out = [];
        foreach ($dims as $d) {
            $c = $coords->get(Js::opt($d, 'path'));
            if (!is_array($c) || !array_is_list($c)) {
                return null;
            }
            if (Js::opt($d, 'kind') === 'num') {
                if (count($c) < 2 || !Js::isNum($c[0]) || !Js::isNum($c[1]) || Js::num($c[0]) != Js::num($c[1])) {
                    return null;
                }
                $out[] = $c[0];
            } else {
                if (count($c) !== 1 || !is_string($c[0])) {
                    return null;
                }
                $i = -1;
                foreach (Js::opt($d, 'values') as $k => $v) {
                    if (Js::opt($v, 'value') === $c[0]) {
                        $i = $k;
                        break;
                    }
                }
                if ($i < 0) {
                    return null;
                }
                $out[] = $i;
            }
        }
        return $out;
    }

    /** The action digest a JIT consent is bound to. */
    public static function intentActionDigest(mixed $action): string
    {
        if ($action === null) {
            throw new \TypeError("Cannot read properties of null (reading 'verb')");
        }
        foreach (['verb', 'resource', 'params_digest', 'reversibility_class'] as $k) {
            if (!Js::has($action, $k)) { // an undefined member does not canonicalize
                throw new JsonError('canonicalize: unsupported type undefined');
            }
        }
        return IntentV2::hashCanonical(Obj::of(['d' => self::INTENT_ACTION_DOMAIN, 'action' => Obj::of([
            'verb' => Js::opt($action, 'verb'), 'resource' => Js::opt($action, 'resource'), 'params_digest' => Js::opt($action, 'params_digest'),
            'reversibility_class' => Js::opt($action, 'reversibility_class')])]));
    }

    /**
     * The site's `pca-intent-required` body for a visited uncertain cell (sign it with the core). Input: session, mapDigest, schemaDigest,
     * pcactn, vs, cell, questionId, friction, deliveredTo, expiresAt.
     */
    public static function intentRequiredBody(mixed $i): Obj
    {
        $pcactn = Js::opt($i, 'pcactn');
        $vs = Js::opt($i, 'vs');
        return Obj::of(['v' => 1, 'kind' => 'pca-intent-required', 'session' => Js::opt($i, 'session'), 'map_digest' => Js::opt($i, 'mapDigest'),
            'schema' => Js::opt($i, 'schemaDigest'), 'pcactn_digest' => IntentV2::hashCanonical($pcactn),
            'action_digest' => self::intentActionDigest(Js::opt($pcactn, 'action')),
            'cell' => Obj::of(['verb' => Js::opt($vs, 'verb'), 'coords' => self::cellCoords($vs, Js::opt($i, 'cell'))]), 'reason' => 'uncertain',
            'question_id' => Js::opt($i, 'questionId'), 'friction' => Js::opt($i, 'friction'), 'delivered_to' => Js::opt($i, 'deliveredTo'),
            'expires_at' => Js::opt($i, 'expiresAt')]);
    }

    /** intentRequiredBody signed by the site key (Ed25519 under the kid; a malformed body refuses). */
    public static function signedIntentRequired(mixed $i, string $kid, KeyPair $site): Obj
    {
        return SignersMore::signIntentRequired(self::intentRequiredBody($i), $kid, $site);
    }

    /**
     * The wallet's check of an intent_required: the verifier (default IntentV2::verifyIntentRequired(body, keys, now) -> {ok, reason?})
     * checks the site signature under its keys and the expiry; the session, map, action and the cell are then re-derived from the
     * wallet's own space. Any disagreement refuses the question. Input $w: keys, now, session, mapDigest, omegaTilde, lifted, pcactn.
     * @param (\Closure(mixed,mixed,mixed):array)|null $verify
     * @return array<string,mixed>
     */
    public static function walletCheckIntentRequired(mixed $body, mixed $w, ?\Closure $verify = null): array
    {
        $verify ??= static fn($b, $keys, $now): array => IntentV2::verifyIntentRequired($b, $keys, $now);
        $v = $verify($body, Js::opt($w, 'keys'), Js::opt($w, 'now'));
        if (!($v['ok'] ?? false)) {
            return $v;
        }
        if (Js::opt($body, 'session') !== Js::opt($w, 'session') || Js::opt($body, 'map_digest') !== Js::opt($w, 'mapDigest')) {
            return ['ok' => false, 'reason' => 'the question is for another session or map'];
        }
        $pcactn = Js::opt($w, 'pcactn');
        if (Js::opt($body, 'pcactn_digest') !== IntentV2::hashCanonical($pcactn) || Js::opt($body, 'action_digest') !== self::intentActionDigest(Js::opt($pcactn, 'action'))) {
            return ['ok' => false, 'reason' => 'the question is about another action'];
        }
        $lifted = Js::opt($w, 'lifted');
        $vs = self::vsOf(Js::opt($w, 'omegaTilde'), Js::opt($lifted, 'verb'));
        $mine = $vs !== null ? IntentOmega::cellOf($vs, $lifted) : null;
        $cell = Js::opt($body, 'cell');
        if ($vs === null || $mine === null || Js::opt($cell, 'verb') !== Js::opt($vs, 'verb')) {
            return ['ok' => false, 'reason' => "the wallet cannot place the action in \u{03A9}\u{0303}"];
        }
        $theirs = self::cellFromCoords($vs, Js::opt($cell, 'coords'));
        if ($theirs !== null) {
            foreach ($theirs as $k => $x) {
                if (Js::num($x) != $mine[$k]) {
                    $theirs = null;
                    break;
                }
            }
        }
        if ($theirs === null) {
            return ['ok' => false, 'reason' => 'the site cell differs from the cell the wallet derives'];
        }
        return ['ok' => true, 'vs' => $vs, 'cell' => $mine];
    }

    private static function cellKey(array $c): string
    {
        return $c['verb'] . '|' . implode(',', $c['cell']);
    }

    /**
     * Per verb, the cells the next learner's grant adds over the previous one's (as 0/1 lists over the flat cell index).
     * @return array<string,list<int>>
     */
    public static function deltaCells(IntentLearner $prev, IntentLearner $next): array
    {
        $out = [];
        $prevIn = [];
        foreach ($prev->cells() as $c) {
            if ($c['inGrant']) {
                $prevIn[self::cellKey($c)] = true;
            }
        }
        $nextCells = $next->cells();
        foreach (Js::opt($next->omega, 'verbs') as $vs) {
            $a = array_fill(0, IntentOmega::verbCellCount($vs), 0);
            $any = false;
            foreach ($nextCells as $c) {
                if ($c['verb'] !== Js::opt($vs, 'verb') || !$c['inGrant'] || isset($prevIn[self::cellKey($c)])) {
                    continue;
                }
                $a[IntentOmega::encodeCell($vs, $c['cell'])] = 1;
                $any = true;
            }
            if ($any) {
                $out[Js::opt($vs, 'verb')] = $a;
            }
        }
        return $out;
    }

    /** The predicates of a delta (one maximal box per covered region, per verb). @param array<string,list<int>> $delta */
    public static function deltaPredicates(mixed $omegaTilde, array $delta): array
    {
        $out = [];
        foreach (Js::opt($omegaTilde, 'verbs') as $vs) {
            if (isset($delta[Js::opt($vs, 'verb')])) {
                array_push($out, ...IntentLearner::boxesToPredicates($vs, $delta[Js::opt($vs, 'verb')]));
            }
        }
        return $out;
    }

    /**
     * Mint D_k from the k-th answer: null when the answer added no cell. `$principal` is the PRINCIPAL key (the wallet holds it; the agent's
     * key never signs a grant); `$opts` are the remaining SignersMore::mintSessionGrant arguments (mapForm, caveats, salt, ...).
     * @param array<string,mixed> $opts
     * @return array{grant:Obj,goal_salt:string,cells:int}|null
     */
    public static function mintDelta(IntentLearner $prev, IntentLearner $next, mixed $prevGrant, KeyPair $principal, string $holder, string $session, int $seq,
                                     string $root, string $mapDigest, ?string $prevId = null, array $opts = []): ?array
    {
        $delta = self::deltaCells($prev, $next);
        $cells = 0;
        foreach ($delta as $v) {
            $cells += array_sum($v);
        }
        if ($cells === 0) {
            return null;
        }
        if ($prevId !== null && $prevId !== Js::opt($prevGrant, 'id')) {
            throw new \InvalidArgumentException('mintDelta: prev must be the id of the previous session grant');
        }
        $r = SignersMore::mintSessionGrant($principal, $holder, $session, $seq, $root, $mapDigest, self::deltaPredicates($next->omega, $delta),
            ...['prev' => Js::opt($prevGrant, 'id')] + $opts);
        return $r + ['cells' => $cells];
    }
}
