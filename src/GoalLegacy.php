<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Facade.php';

/**
 * `liftLegacy`: the total, conservative lift of the facade's {permissions, limits} input to a Goal + Ontology. Corrected semantics
 * of the four facade bugs: `$200/day` is a SLIDING 86 400 000 ms sum bound (explicit window), not a per-call ceiling plus a one-day
 * grant lifetime; a `$` limit on a verb with no amount field is an error; every limit is its own bound, so adding a limit only
 * narrows (co-sign tiers are not part of the goal); money parameters are integers in MINOR units of USD (cents), the explicit unit
 * the old facade left implicit.
 */
final class GoalLegacy
{
    public const MAX_SAFE = 9007199254740991;

    private static function usd(): Obj
    {
        return Obj::of(['k' => 'money', 'ccy' => 'USD']);
    }

    /** `o[k]`: undefined when absent. */
    private static function opt(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : AnalyzerJs::undef();
        }
        return is_array($o) && !array_is_list($o) && array_key_exists($k, $o) ? $o[$k] : AnalyzerJs::undef();
    }

    private static function jsRound(float $x): float
    {
        $r = floor($x);
        return $x - $r >= 0.5 ? $r + 1 : $r;
    }

    private static function safe(int|float $n): bool
    {
        return is_int($n) ? abs($n) <= self::MAX_SAFE : (is_finite($n) && $n == floor($n) && abs($n) <= self::MAX_SAFE);
    }

    /** @param list<Obj> $xs @return list<Obj> */
    private static function byKey(array $xs, string $k): array
    {
        usort($xs, static fn(Obj $a, Obj $b): int => AnalyzerJs::u16cmp((string)$a->get($k), (string)$b->get($k)));
        return $xs;
    }

    /**
     * `$o`: {permissions, limits?, catalog?, principal, notAfter?, notBefore?, nlDigest?} as an Obj or an assoc array (the money epoch
     * `notAfter` defaults to the largest safe integer); `catalog` is a {@see Catalog} or a list of action specs. Returns `{goal, ontology}`.
     */
    public static function liftLegacy(mixed $o): Obj
    {
        $raw = AnalyzerJs::nn(self::opt($o, 'limits'), new Obj());
        // the reference's hasOwnProperty over any object: an assoc-array limits map counts like an Obj (it was silently ignored)
        $own = static fn(mixed $k): mixed => is_string($k) ? self::opt($raw, $k) : AnalyzerJs::undef();
        $cat = AnalyzerJs::nn(self::opt($o, 'catalog'), null);
        $catalog = $cat instanceof Catalog ? $cat : (is_array($cat) ? new Catalog($cat) : null);
        // the facade resolves every granted verb (uncatalogued verbs become irreversible); it also validates the permission map shape
        $specs = Facade::compilePolicy(self::opt($o, 'permissions'), null, $catalog)['actions'];
        $grants = [];
        $bounds = [];
        $verbs = [];
        foreach ($specs as $s) {
            $verb = $s['verb'];
            $gid = "g:$verb";
            $amountPath = AnalyzerJs::truthy($s['amountField'] ?? null) ? $s['amountField'] : null;
            $verbs[] = Obj::of(['verb' => $verb, 'cls' => $s['reversibility'], 'params' => $amountPath === null ? []
                : [Obj::of(['path' => $amountPath, 'ty' => Obj::of(['k' => 'q', 'u' => self::usd()])])]]);
            $resource = $s['resource'] ?? '*';
            if (preg_match('/[*?]|\Are:/', $resource) === 1 && $resource !== '*') {
                throw new \InvalidArgumentException("liftLegacy: resource pattern '$resource' of $verb is not expressible; name exact resources or acknowledge a wildcard");
            }
            $rawLimit = $own($verb);
            if ($rawLimit instanceof Undef || $rawLimit === null) {
                $rawLimit = $own($s['action']);
            }
            $cond = Obj::of(['k' => 'true']);
            if (!($rawLimit instanceof Undef)) {
                $lim = Facade::parseLimit($rawLimit);
                $gids = [$gid];
                if ($lim['unit'] === 'usd') {
                    if ($amountPath === null) {
                        throw new \InvalidArgumentException("liftLegacy: '\$' limit on '$verb' but the catalog gives that verb no amount field, so the limit could not be enforced");
                    }
                    $minorF = self::jsRound((float)$lim['amount'] * 100);
                    if (!self::safe($minorF)) {
                        throw new \InvalidArgumentException("liftLegacy: limit for $verb is out of range");
                    }
                    $minor = (int)$minorF;
                    $amt = static fn(): Obj => Obj::of(['k' => 'param', 'path' => $amountPath, 'ty' => Obj::of(['k' => 'q', 'u' => self::usd()])]);
                    $lit = static fn(int $n): Obj => Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => self::usd(), 'n' => $n])])]);
                    $cond = Obj::of(['k' => 'and', 'a' => Obj::of(['k' => 'cmp', 'op' => 'gte', 'l' => $amt(), 'r' => $lit(0)]),
                        'b' => Obj::of(['k' => 'cmp', 'op' => 'lte', 'l' => $amt(), 'r' => $lit($minor)])]);
                    if (isset($lim['periodMs'])) {
                        $bounds[] = Obj::of(['bid' => "b:$verb", 'sel' => Obj::of(['k' => 'gids', 'gids' => $gids]), 'agg' => 'sum', 'value' => $amt(), 'key' => '',
                            'window' => Obj::of(['k' => 'sliding', 'ms' => $lim['periodMs']]), 'scope' => Obj::of(['k' => 'session']),
                            'cap' => Obj::of(['u' => self::usd(), 'n' => $minor]), 'onExceed' => 'deny']);
                    }
                } else {
                    if (!self::safe($lim['amount'])) {
                        throw new \InvalidArgumentException("liftLegacy: count limit for $verb must be a whole number");
                    }
                    $count = static fn(): Obj => Obj::of(['k' => 'count']);
                    $bounds[] = Obj::of(['bid' => "b:$verb", 'sel' => Obj::of(['k' => 'gids', 'gids' => $gids]), 'agg' => 'count',
                        'value' => Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => $count(), 'n' => 1])])]), 'key' => '',
                        'window' => isset($lim['periodMs']) ? Obj::of(['k' => 'sliding', 'ms' => $lim['periodMs']]) : Obj::of(['k' => 'lifetime']),
                        'scope' => Obj::of(['k' => 'session']), 'cap' => Obj::of(['u' => $count(), 'n' => (int)$lim['amount']]), 'onExceed' => 'deny']);
                }
            }
            $grants[] = Obj::of(['gid' => $gid, 'verb' => $verb,
                'res' => $resource === '*' ? Obj::of(['k' => 'any', 'reason' => 'legacy default: no resource scope given']) : Obj::of(['k' => 'exact', 'id' => $resource]),
                'cond' => $cond]);
        }
        $grants = self::byKey($grants, 'gid');
        $bounds = self::byKey($bounds, 'bid');
        for ($i = 1; $i < count($grants); $i++) {
            if ($grants[$i]->get('gid') === $grants[$i - 1]->get('gid')) {
                throw new \InvalidArgumentException('liftLegacy: duplicate grant ' . $grants[$i]->get('gid'));
            }
        }
        $gidsAll = array_map(static fn(Obj $g): mixed => $g->get('gid'), $grants);
        $goal = AnalyzerJs::uobj([
            'v' => 1, 'principal' => self::opt($o, 'principal'), 'ontDigest' => 'legacy-catalog', 'nlDigest' => AnalyzerJs::nn(self::opt($o, 'nlDigest'), ''), 'sources' => [],
            'grants' => $grants, 'prohibits' => [], 'bounds' => $bounds,
            'validity' => Obj::of(['notBefore' => AnalyzerJs::nn(self::opt($o, 'notBefore'), 0), 'notAfter' => AnalyzerJs::nn(self::opt($o, 'notAfter'), self::MAX_SAFE), 'maxIdle' => 0]),
            'deleg' => Obj::of(['maxDepth' => 16, 'narrowOnly' => true, 'mayTouch' => $gidsAll]),
            'escalateOn' => [],
            'wildcardAck' => array_values(array_map(static fn(Obj $g): mixed => $g->get('gid'), array_filter($grants, static fn(Obj $g): bool => $g->get('res')->get('k') === 'any'))),
            'holes' => [],
        ]);
        $sorted = self::byKey($verbs, 'verb');
        $uniq = [];
        foreach ($sorted as $i => $v) {
            if ($i === 0 || $sorted[$i - 1]->get('verb') !== $v->get('verb')) {
                $uniq[] = $v;
            }
        }
        return Obj::of(['goal' => $goal, 'ontology' => Obj::of(['verbs' => $uniq, 'rels' => []])]);
    }
}
