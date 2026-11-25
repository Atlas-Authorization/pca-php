<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Ha.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/Pca.php';

/** A refusal of the embedding step (a vector that is not `dims` safe integers in range, a param-stuffed action, a bad model). */
final class EmbeddingError extends \RuntimeException
{
}

/** Maps the CANONICAL action to an integer vector; never sees agent-supplied features. `config` is the committed descriptor behind `modelId`. */
interface ObjEmbedder
{
    public function modelId(): mixed;

    public function config(): mixed;

    public function dims(): mixed;

    /** @return mixed `dims` safe integers (any value for a custom embedder); may throw */
    public function embed(Obj $action): mixed;
}

/** The committed registry of verified inverses (verbs to inverse entries) with its trusted verifier set. */
final class InMemoryInverseRegistry
{
    /** @var array<string,array{0:string,1:Obj}> */
    private array $m = [];
    /** @var list<string> */
    private array $trusted;

    /** @param list<string> $trustedVerifiers */
    public function __construct(array $trustedVerifiers = [])
    {
        $t = array_values(array_unique($trustedVerifiers));
        usort($t, static fn(string $a, string $b): int => ObjectiveRisk::cmp($a, $b));
        $this->trusted = $t;
    }

    public function register(string $verb, Obj $e): self
    {
        $c = Jsx::spread($e);
        if ($e->get('verification') instanceof Obj) {
            $c->set('verification', Jsx::spread($e->get('verification')));
        }
        $this->m['k' . $verb] = [$verb, $c];
        return $this;
    }

    public function lookup(mixed $verb): ?Obj
    {
        return is_string($verb) && isset($this->m['k' . $verb]) ? Jsx::spread($this->m['k' . $verb][1]) : null;
    }

    /** @return list<string> */
    public function trustedVerifiers(): array
    {
        return $this->trusted;
    }

    public function digest(): string
    {
        $es = array_values($this->m);
        usort($es, static fn(array $a, array $b): int => ObjectiveRisk::cmp($a[0], $b[0]));
        $entries = array_map(static fn(array $p): Obj => Obj::of(['verb' => $p[0], 'inverseKind' => Jsx::get($p[1], 'inverseKind'), 'fidelity' => Jsx::get($p[1], 'fidelity'),
            'verification' => $p[1]->has('verification') ? $p[1]->get('verification') : null]), $es);
        return ObjectiveRisk::hash(Obj::of(['v' => 1, 'trusted' => $this->trusted, 'entries' => $entries]));
    }
}

/** The committed resource graph: nodes `{id, harm?}`, edges `{from, to, kind}`, with a content digest the grant commits. */
final class ResourceGraph
{
    /** @var array<string,Obj> */
    private array $nodes = [];
    /** @var array<string,list<Obj>> */
    private array $out = [];

    public function addNode(Obj $n): self
    {
        $id = (string)$n->get('id');
        $this->nodes['k' . $id] = $n;
        $this->out['k' . $id] ??= [];
        return $this;
    }

    public function addEdge(Obj $e): self
    {
        if (!isset($this->nodes['k' . $e->get('from')]) || !isset($this->nodes['k' . $e->get('to')])) {
            throw new \RuntimeException('edge endpoints must exist');
        }
        $this->out['k' . $e->get('from')][] = $e;
        return $this;
    }

    public function size(): int
    {
        return count($this->nodes);
    }

    public function node(mixed $id): ?Obj
    {
        return is_string($id) ? ($this->nodes['k' . $id] ?? null) : null;
    }

    /**
     * BFS reachable set (including `$start`), restricted to the scope's edge kinds and depth, sorted.
     * @param ?Obj $scope `{edgeKinds?, maxDepth?}` @return list<string>
     */
    public function reachable(mixed $start, ?Obj $scope = null): array
    {
        if (!is_string($start) || !isset($this->nodes['k' . $start])) {
            return [];
        }
        $ek = $scope?->get('edgeKinds');
        $kinds = is_array($ek) ? $ek : null;
        $md = $scope?->get('maxDepth');
        $maxDepth = $md === null ? INF : (float)Js::num($md);
        $seen = ['k' . $start => $start];
        $frontier = [$start];
        for ($d = 0; $d < $maxDepth && $frontier !== []; $d++) {
            $next = [];
            foreach ($frontier as $u) {
                foreach ($this->out['k' . $u] ?? [] as $e) {
                    $to = $e->get('to');
                    if (($kinds === null || in_array($e->get('kind'), $kinds, true)) && !isset($seen['k' . $to])) {
                        $seen['k' . $to] = $to;
                        $next[] = $to;
                    }
                }
            }
            $frontier = $next;
        }
        $ids = array_values($seen);
        usort($ids, static fn(string $a, string $b): int => ObjectiveRisk::cmp($a, $b));
        return $ids;
    }

    public function digest(): string
    {
        $n = array_map(static fn(Obj $x): Obj => Obj::of(['id' => $x->get('id'), 'harm' => $x->get('harm') ?? new Obj()]), array_values($this->nodes));
        usort($n, static fn(Obj $a, Obj $b): int => ObjectiveRisk::cmp($a->get('id'), $b->get('id')));
        $es = [];
        foreach ($this->out as $list) {
            foreach ($list as $x) {
                $es[] = Obj::of(['from' => $x->get('from'), 'to' => $x->get('to'), 'kind' => $x->get('kind')]);
            }
        }
        $key = static fn(Obj $x): string => $x->get('from') . "\0" . $x->get('to') . "\0" . $x->get('kind');
        usort($es, static fn(Obj $a, Obj $b): int => ObjectiveRisk::cmp($key($a), $key($b)));
        return ObjectiveRisk::hash(Obj::of(['v' => 1, 'n' => $n, 'e' => $es]));
    }
}

/** The native embedder: integer feature hashing over code-point n-grams and word tokens of the canonical action. */
final class NativeHashEmbedder implements ObjEmbedder
{
    private readonly Obj $committed;
    private readonly string $id;
    private readonly int $dimsN;
    private readonly int $nmin;
    private readonly int $nmax;
    private readonly string $seed;
    /** @var array{verb:int,resource:int,param:int} */
    private readonly array $w;
    private readonly ?int $maxLeaves;
    private readonly ?string $paramMode;

    public function __construct(mixed $config)
    {
        $okInt = static function (mixed $x, float $lo, float $hi): bool {
            $f = Js::num($x);
            return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0 && $f >= $lo && $f <= $hi;
        };
        $c = static fn(string $k): mixed => Jsx::rd($config, $k);
        if (!$okInt($c('dims'), 8, 65536)) {
            throw new \RangeException('native config: dims must be an integer in [8, 65536]');
        }
        if (!$okInt($c('ngramMin'), 1, 8) || !$okInt(Jsx::get($config, 'ngramMax'), (float)Js::num($c('ngramMin')), 8)) {
            throw new \RangeException('native config: need 1 <= ngramMin <= ngramMax <= 8');
        }
        $seed = Jsx::get($config, 'seed');
        if (!is_string($seed) || $seed === '') {
            throw new \RangeException('native config: seed required');
        }
        $fw = Jsx::rd($config, 'fieldWeights');
        foreach (['verb', 'resource', 'param'] as $k) {
            if (!$okInt(Jsx::rd($fw, $k), 0, 1000)) {
                throw new \RangeException("native config: fieldWeights.$k must be an integer in [0, 1000]");
            }
        }
        $ml = Jsx::get($config, 'maxParamLeaves');
        if (!($ml instanceof Undef) && !$okInt($ml, 1, 1000000)) {
            throw new \RangeException('native config: maxParamLeaves must be an integer in [1, 1000000]');
        }
        $pm = Jsx::get($config, 'paramMode');
        if (!($pm instanceof Undef) && $pm !== 'leaves' && $pm !== 'digest') {
            throw new \RangeException("native config: paramMode must be 'leaves' or 'digest'");
        }
        $cfg = Jsx::spread($config);
        $cfg->set('fieldWeights', Jsx::spread($fw));
        $committed = Obj::of(['scheme' => ObjectiveRisk::NATIVE_SCHEME]);
        foreach ($cfg->keys() as $k) {
            $committed->set($k, $cfg->get($k));
        }
        $this->committed = $committed;
        $this->id = 'native:' . ObjectiveRisk::hash($committed);
        $this->dimsN = (int)Js::num($config->get('dims'));
        $this->nmin = (int)Js::num($config->get('ngramMin'));
        $this->nmax = (int)Js::num($config->get('ngramMax'));
        $this->seed = $seed;
        $this->w = ['verb' => (int)Js::num($fw->get('verb')), 'resource' => (int)Js::num($fw->get('resource')), 'param' => (int)Js::num($fw->get('param'))];
        $this->maxLeaves = $ml instanceof Undef ? null : (int)Js::num($ml);
        $this->paramMode = $pm instanceof Undef ? null : $pm;
    }

    public function modelId(): string
    {
        return $this->id;
    }

    public function config(): Obj
    {
        return $this->committed;
    }

    public function dims(): int
    {
        return $this->dimsN;
    }

    /** @return list<string> */
    private function textFeatures(string $prefix, string $text): array
    {
        $out = [];
        $cps = preg_split('//u', "\x02" . $text . "\x03", -1, PREG_SPLIT_NO_EMPTY) ?: [];
        for ($n = $this->nmin; $n <= $this->nmax; $n++) {
            for ($i = 0; $i + $n <= count($cps); $i++) {
                $out[] = $prefix . 'c' . $n . ':' . implode('', array_slice($cps, $i, $n));
            }
        }
        foreach (preg_split('/[^\p{L}\p{N}]+/u', $text) ?: [] as $word) {
            if ($word !== '') {
                $out[] = $prefix . 'w:' . mb_strtolower($word, 'UTF-8');
            }
        }
        return $out;
    }

    /** @param list<string> $out */
    private static function leaves(mixed $v, string $path, array &$out): void
    {
        if (is_array($v)) {
            foreach (array_values($v) as $i => $x) {
                self::leaves($x, $path . '[' . $i . ']', $out);
            }
        } elseif ($v instanceof Obj) {
            $ks = $v->keys();
            usort($ks, static fn(string $a, string $b): int => IntentWb::compareUtf8($a, $b));
            foreach ($ks as $k) {
                self::leaves($v->get($k), $path !== '' ? $path . '.' . $k : $k, $out);
            }
        } else {
            $out[] = $path . '=' . Json::canonicalizeLenient($v);
        }
    }

    /** @return list<int> */
    public function embed(Obj $a): array
    {
        $v = array_fill(0, $this->dimsN, 0);
        $prefix = $this->seed . "\x1f";
        $add = function (string $feat, int $w) use (&$v, $prefix): void {
            if ($w === 0) {
                return;
            }
            $h = hash('sha256', $prefix . $feat, true);
            $bucket = (ord($h[0]) * 16777216 + ord($h[1]) * 65536 + ord($h[2]) * 256 + ord($h[3])) % $this->dimsN;
            $v[$bucket] += (ord($h[4]) & 1) === 0 ? $w : -$w;
        };
        foreach ($this->textFeatures('v:', Jsx::rd($a, 'verb')) as $f) {
            $add($f, $this->w['verb']);
        }
        foreach ($this->textFeatures('r:', Jsx::get($a, 'resource')) as $f) {
            $add($f, $this->w['resource']);
        }
        $leaves = [];
        self::leaves(Jsx::get($a, 'params'), '', $leaves);
        $cap = $this->maxLeaves ?? ObjectiveRisk::DEFAULT_MAX_PARAM_LEAVES;
        if (count($leaves) > $cap) {
            throw new EmbeddingError('param leaf count ' . count($leaves) . " exceeds cap $cap");
        }
        if ($this->paramMode === 'digest') {
            $add('p#:' . ObjectiveRisk::hash(Obj::of(['t' => 'pca-objrisk-params-v1', 'params' => Jsx::get($a, 'params')])), $this->w['param']);
        } else {
            foreach ($leaves as $leaf) {
                foreach ($this->textFeatures('p:', $leaf) as $f) {
                    $add($f, $this->w['param']);
                }
            }
        }
        return $v;
    }
}

/** A customer-supplied model that meets the determinism contract: `modelId` is the hash of its committed descriptor. */
final class ByoEmbedder implements ObjEmbedder
{
    private readonly string $id;
    private readonly int $qmax;

    /** @param callable(string):mixed $infer receives the canonical action JSON and returns the integer vector */
    public function __construct(private readonly mixed $descriptor, private readonly mixed $infer, ?string $claimedModelId = null)
    {
        if (!Ha::safeInt(Jsx::get($descriptor, 'dims')) || Js::num(Jsx::get($descriptor, 'dims')) < 1) {
            throw new \RangeException('byo: dims must be a positive integer');
        }
        $q = Jsx::rd($descriptor, 'quantization');
        $bits = Jsx::rd($q, 'bits');
        $scale = Jsx::toNum(Jsx::get($q, 'scale'));
        if (!Ha::safeInt($bits) || Js::num($bits) < 2 || Js::num($bits) > 31 || !($scale > 0)) {
            throw new \RangeException('byo: invalid quantization');
        }
        if (Jsx::get($descriptor, 'inputEncoding') !== 'pca-canonical-action-json-v1') {
            throw new \RangeException('byo: unsupported inputEncoding');
        }
        $this->id = ObjectiveRisk::byoModelId($descriptor);
        if ($claimedModelId !== null && $claimedModelId !== $this->id) {
            throw new \RuntimeException('byo: modelId does not match the committed descriptor');
        }
        $this->qmax = (2 ** ((int)Js::num($bits) - 1)) - 1;
    }

    public function modelId(): string
    {
        return $this->id;
    }

    public function config(): mixed
    {
        return $this->descriptor;
    }

    public function dims(): int
    {
        return (int)Js::num(Jsx::get($this->descriptor, 'dims'));
    }

    /** @return list<int> */
    public function embed(Obj $a): array
    {
        $v = ObjectiveRisk::validateVector(($this->infer)(ObjectiveRisk::canonicalActionJson($a)), $this->dims());
        foreach ($v as $x) {
            if (abs($x) > $this->qmax) {
                throw new EmbeddingError('byo: component exceeds declared quantization range');
            }
        }
        return $v;
    }
}

/** What `objectiveRisk` is computed from: the committed registry, graph, embedder and goal, and the verifier's own numbers. */
final class ObjectiveRiskContext
{
    /**
     * @param list<string> $authorizedKinds @param list<mixed> $denominations @param ?list<mixed> $calibration
     * @param mixed $attestedUncertainty null = none
     */
    public function __construct(public readonly InMemoryInverseRegistry $registry, public readonly array $authorizedKinds, public readonly ResourceGraph $graph,
                                public readonly ?Obj $scope, public readonly ObjEmbedder $embedder, public readonly mixed $goal, public readonly mixed $commitments,
                                public readonly array $denominations, public readonly mixed $weights, public readonly mixed $taint, public readonly mixed $age,
                                public readonly mixed $attestedUncertainty = null, public readonly ?array $calibration = null)
    {
    }
}

/**
 * The objective risk functional: every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL action;
 * nothing the agent merely asserts is read. Any commitment mismatch fails closed (r = 1, valid false). Digests are the LENIENT
 * canonical hash (any finite double, printed as ECMAScript prints it).
 */
final class ObjectiveRisk
{
    public const METRIC = 'half-chord-v1';
    public const DEFAULT_EPSILON = 1 / 4096;
    public const NATIVE_SCHEME = 'pca-native-hash-ngram-v1';
    public const DEFAULT_MAX_PARAM_LEAVES = 256;

    public static function defaultNativeConfig(): Obj
    {
        return Obj::of(['dims' => 256, 'ngramMin' => 2, 'ngramMax' => 4, 'seed' => 'pca-native-v1',
            'fieldWeights' => Obj::of(['verb' => 4, 'resource' => 2, 'param' => 1])]);
    }

    /** The lenient canonical hash (base64url SHA-256) of a JSON value. */
    public static function hash(mixed $v): string
    {
        return Pca::b64u(hash('sha256', Json::canonicalizeLenient($v), true));
    }

    /** JavaScript string order (UTF-16 code units). */
    public static function cmp(mixed $a, mixed $b): int
    {
        return Jsx::cmp($a, $b);
    }

    private static function clamp01(float $x): float
    {
        return is_finite($x) ? ($x < 0 ? 0.0 : ($x > 1 ? 1.0 : $x)) : 1.0;
    }

    private static function jsMin(float $a, float $b): float
    {
        return is_nan($a) || is_nan($b) ? NAN : min($a, $b);
    }

    private static function jsMax(float $a, float $b): float
    {
        return is_nan($a) || is_nan($b) ? NAN : max($a, $b);
    }

    // ---- canonical action --------------------------------------------------------------------------------------------------

    private const WS = '\x{9}\x{A}\x{B}\x{C}\x{D}\x{20}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}';

    private static function nfc(string $s): string
    {
        $n = \Normalizer::normalize($s, \Normalizer::FORM_C);
        return $n === false ? $s : $n;
    }

    private static function jsTrim(string $s): string
    {
        return (string)preg_replace('/^[' . self::WS . ']+|[' . self::WS . ']+$/u', '', $s);
    }

    private static function normValue(mixed $v): mixed
    {
        if (is_string($v)) {
            return self::nfc($v);
        }
        if (is_array($v)) {
            return array_map(self::normValue(...), $v);
        }
        if ($v instanceof Obj) {
            $out = new Obj();
            foreach ($v->keys() as $k) {
                $nk = self::nfc($k);
                if ($out->has($nk)) {
                    throw new \TypeError('canonicalAction: duplicate key after NFC normalization');
                }
                $out->set($nk, self::normValue($v->get($k)));
            }
            return $out;
        }
        return $v;
    }

    /** The canonical form: verb trimmed and lowercased, every string and key NFC, params an object with a stable encoding; throws on anything else. */
    public static function canonicalAction(mixed $a): Obj
    {
        $verb = Jsx::get($a, 'verb');
        $res = Jsx::get($a, 'resource');
        if (!is_string($verb) || !is_string($res)) {
            throw new \TypeError('canonicalAction: verb/resource must be strings');
        }
        $verb = mb_strtolower(self::jsTrim(self::nfc($verb)), 'UTF-8');
        $res = self::jsTrim(self::nfc($res));
        if ($verb === '' || $res === '') {
            throw new \TypeError('canonicalAction: empty verb/resource');
        }
        $p = Jsx::get($a, 'params');
        $params = self::normValue($p === null || $p instanceof Undef ? new Obj() : $p);
        if (!($params instanceof Obj)) {
            throw new \TypeError('canonicalAction: params must be an object');
        }
        $c = Obj::of(['verb' => $verb, 'resource' => $res, 'params' => $params]);
        Json::canonicalizeLenient($c); // validates
        return $c;
    }

    public static function canonicalActionJson(mixed $c): string
    {
        return Json::canonicalizeLenient($c);
    }

    public static function canonicalActionDigest(mixed $c): string
    {
        return self::hash($c);
    }

    // ---- reversibility and blast radius ---------------------------------------------------------------------------------------

    /**
     * Reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND the inverse verb is itself
     * authorized; anything else is irreversible. @param list<string> $authorizedKinds
     */
    public static function reversibility(mixed $action, InMemoryInverseRegistry $registry, array $authorizedKinds): Obj
    {
        $e = $registry->lookup(Jsx::get($action, 'verb'));
        $ver = $e === null ? null : $e->get('verification');
        $trusted = Jsx::truthy($ver) ? in_array(Jsx::get($ver, 'verifierId'), $registry->trustedVerifiers(), true) : false;
        $kind = $e === null ? null : Jsx::get($e, 'inverseKind');
        if ($e === null || !$trusted || !in_array($kind, $authorizedKinds, true)) {
            return Obj::of(['class' => 'irreversible', 'value' => 0]);
        }
        return $e->get('fidelity') === 'exact' ? Obj::of(['class' => 'reversible', 'value' => 1, 'inverseKind' => $kind])
            : Obj::of(['class' => 'compensable', 'value' => 0.5, 'inverseKind' => $kind]);
    }

    /** The reachable set, its size relative to the graph, and the summed harm per denomination; an unknown resource is normalized 1. */
    public static function blastRadius(mixed $action, ResourceGraph $graph, ?Obj $scope = null): Obj
    {
        $reachable = $graph->reachable(Jsx::get($action, 'resource'), $scope);
        if ($reachable === [] || $graph->size() === 0) {
            return Obj::of(['count' => 0, 'reachable' => $reachable, 'normalized' => 1, 'harm' => new Obj()]);
        }
        $harm = new Obj();
        foreach ($reachable as $id) {
            $h = $graph->node($id)?->get('harm');
            foreach (Jsx::keys($h) as $d) {
                $v = Js::num(Jsx::get($h, $d));
                if ($v !== null && is_finite($v) && $v > 0) {
                    $harm->set($d, ($harm->has($d) ? $harm->get($d) : 0) + $v);
                }
            }
        }
        return Obj::of(['count' => count($reachable), 'reachable' => $reachable, 'normalized' => count($reachable) / $graph->size(), 'harm' => $harm]);
    }

    // ---- embeddings -----------------------------------------------------------------------------------------------------------

    /** @return list<int> `dims` safe integers within the dot-product-exact range (negative zero becomes 0) */
    public static function validateVector(mixed $v, mixed $dims): array
    {
        $d = (float)Js::num($dims);
        if (!is_array($v) || !array_is_list($v) || (float)count($v) !== $d) {
            throw new EmbeddingError('vector must have exactly ' . Js::str($dims) . ' components');
        }
        $lim = floor(sqrt(9007199254740991.0 / (2 * max(1.0, $d))));
        $out = [];
        foreach ($v as $x) {
            $f = Js::num($x);
            if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0) {
                throw new EmbeddingError('vector components must be safe integers');
            }
            if (abs($f) > $lim) {
                throw new EmbeddingError('vector component out of range');
            }
            $out[] = (int)$f;
        }
        return $out;
    }

    public static function byoModelId(mixed $d): string
    {
        return 'byo:' . self::hash($d);
    }

    /** True iff every conformance case `{action, vector}` reproduces exactly; any failure is false. */
    public static function conformanceCheck(ObjEmbedder $e, mixed $cases): bool
    {
        try {
            foreach (Jsx::iter($cases) as $c) {
                $v = $e->embed(self::canonicalAction(Jsx::rd($c, 'action')));
                $want = Jsx::get($c, 'vector');
                if (!is_array($v) || !is_array($want) || count($v) !== count($want)) {
                    return false;
                }
                foreach (array_values($v) as $i => $x) {
                    $w = array_values($want)[$i];
                    if (Js::num($w) === null || (float)$x !== (float)Js::num($w)) {
                        return false;
                    }
                }
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- goal commitment and distance -------------------------------------------------------------------------------------------

    private static function goalInput(mixed $g): Obj
    {
        return Obj::of(['embedderModelId' => Jsx::get($g, 'embedderModelId'), 'config' => Jsx::get($g, 'config'), 'goalVector' => Jsx::get($g, 'goalVector'),
            'metric' => Jsx::get($g, 'metric'), 'epsilon' => Jsx::get($g, 'epsilon')]);
    }

    /** Embed the goal's CANONICAL action and bind it to this embedder; `$epsilon` in (0, 1]. Throws on invalid input. */
    public static function commitGoal(ObjEmbedder $embedder, mixed $goalAction, mixed $epsilon = self::DEFAULT_EPSILON): Obj
    {
        $e = Js::num($epsilon);
        if ($e === null || !($e > 0 && $e <= 1)) {
            throw new \RangeException('epsilon must be in (0, 1]');
        }
        $vec = self::validateVector($embedder->embed(self::canonicalAction($goalAction)), $embedder->dims());
        $g = Obj::of(['embedderModelId' => $embedder->modelId(), 'config' => $embedder->config(), 'goalVector' => $vec, 'metric' => self::METRIC, 'epsilon' => $epsilon]);
        $g->set('commit', self::hash(self::goalInput($g)));
        return $g;
    }

    /** The first failing reason (metric, epsilon, commit hash, model id, config hash, vector) or null; a thrown error's message is the reason. */
    public static function verifyGoalCommitment(mixed $g, ObjEmbedder $embedder): ?string
    {
        try {
            if (Jsx::rd($g, 'metric') !== self::METRIC) {
                return 'unknown metric';
            }
            $eps = Jsx::toNum(Jsx::get($g, 'epsilon'));
            if (!($eps > 0 && $eps <= 1)) {
                return 'bad epsilon';
            }
            if (Jsx::get($g, 'commit') !== self::hash(self::goalInput($g))) {
                return 'goal commitment hash mismatch';
            }
            if (Jsx::get($g, 'embedderModelId') !== $embedder->modelId()) {
                return 'embedder modelId mismatch';
            }
            if (self::hash(Jsx::get($g, 'config')) !== self::hash($embedder->config())) {
                return 'embedder config mismatch';
            }
            self::validateVector(Jsx::get($g, 'goalVector'), $embedder->dims());
            return null;
        } catch (\Throwable $e) {
            return $e->getMessage() === '' ? 'invalid goal commitment' : $e->getMessage();
        }
    }

    /** Integer vectors to sin(theta/2) = sqrt((1-cos)/2), rounded UP to the epsilon grid; only IEEE `/` and `sqrt`, summed left to right. */
    public static function vectorDistance(mixed $a, mixed $b, mixed $epsilon = self::DEFAULT_EPSILON): float
    {
        $a = Jsx::iter($a);
        $b = Jsx::iter($b);
        if (count($a) !== count($b)) {
            return 1.0;
        }
        $dot = $na = $nb = 0.0;
        $same = true;
        foreach ($a as $i => $x) {
            $x = Jsx::toNum($x);
            $y = Jsx::toNum($b[$i]);
            $dot += $x * $y;
            $na += $x * $x;
            $nb += $y * $y;
            if ($x != $y) {
                $same = false;
            }
        }
        if ($na == 0.0 || $nb == 0.0) {
            return 1.0;
        }
        if ($same) {
            return 0.0;
        }
        $cos = self::jsMax(-1.0, self::jsMin(1.0, fdiv($dot, sqrt($na * $nb))));
        $d = sqrt((1 - $cos) / 2);
        if ($d < 1e-9) {
            return 0.0;
        }
        $eps = Jsx::toNum($epsilon);
        return self::clamp01(ceil(fdiv($d, $eps)) * $eps);
    }

    /** @return array{ok:true,value:float}|array{ok:false,reason:string} the distance to the committed goal; ok false on any failure */
    public static function committedDistanceChecked(mixed $action, mixed $goal, ObjEmbedder $embedder): array
    {
        $bad = self::verifyGoalCommitment($goal, $embedder);
        if ($bad !== null && $bad !== '') {
            return ['ok' => false, 'reason' => $bad];
        }
        try {
            $v = self::validateVector($embedder->embed($action), $embedder->dims());
            return ['ok' => true, 'value' => self::vectorDistance($v, Jsx::get($goal, 'goalVector'), Jsx::get($goal, 'epsilon'))];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => $e->getMessage() === '' ? 'embedding failed' : $e->getMessage()];
        }
    }

    /** An agent submission canonicalized and measured against the goal; 1 on any failure. */
    public static function committedDistance(mixed $action, mixed $goal, ObjEmbedder $embedder): float
    {
        try {
            $r = self::committedDistanceChecked(self::canonicalAction($action), $goal, $embedder);
            return $r['ok'] ? $r['value'] : 1.0;
        } catch (\Throwable) {
            return 1.0;
        }
    }

    // ---- split-conformal calibration ----------------------------------------------------------------------------------------------

    /** The calibrated risk 1 - (1 + #{s >= raw}) / (n + 1); an empty set or a non-finite raw score is 1. @param list<mixed> $scores */
    public static function calibrate(mixed $raw, array $scores): float
    {
        $r = Js::num($raw);
        if ($scores === [] || $r === null || !is_finite($r)) {
            return 1.0;
        }
        $ge = 0;
        foreach ($scores as $s) {
            $ge += Jsx::toNum($s) >= $r ? 1 : 0;
        }
        return 1 - (1 + $ge) / (count($scores) + 1);
    }

    /** The split-conformal quantile (+Infinity when n is too small; null when alpha puts the rank outside the set). @param list<mixed> $scores */
    public static function conformalThreshold(array $scores, mixed $alpha): int|float|null
    {
        $n = count($scores);
        $k = ceil(($n + 1) * (1 - Jsx::toNum($alpha)));
        if ($n === 0 || $k > $n) {
            return INF;
        }
        $s = array_map(static fn($x) => Jsx::toNum($x), $scores);
        usort($s, static fn(float $a, float $b): int => self::subCmp($a, $b));
        return is_nan($k) || $k < 1 ? null : $s[(int)$k - 1];
    }

    /** JS `(a, b) => a - b` as a sort comparator: a NaN difference counts as equal (the sort is stable). */
    private static function subCmp(float $a, float $b): int
    {
        $d = $a - $b;
        return is_nan($d) || $d == 0 ? 0 : ($d < 0 ? -1 : 1);
    }

    /** @param list<mixed> $scores the digest of a calibration set (sorted numerically), committed by the grant */
    public static function calibrationDigest(array $scores): string
    {
        $s = array_map(static fn($x) => Js::num($x) ?? $x, $scores);
        usort($s, static fn($a, $b): int => self::subCmp(Jsx::toNum($a), Jsx::toNum($b)));
        return self::hash(Obj::of(['v' => 1, 'scores' => $s]));
    }

    // ---- harm currency ----------------------------------------------------------------------------------------------------------------

    /** The weighted saturating normalization of the harm units over the denominations. @param list<mixed> $denoms */
    public static function harmReport(mixed $units, array $denoms): Obj
    {
        $num = $den = 0.0;
        foreach ($denoms as $d) {
            $w = Jsx::toNum(Jsx::rd($d, 'weight'));
            $c = Jsx::toNum(Jsx::get($d, 'ceiling'));
            if (!($w > 0) || !($c > 0)) {
                continue;
            }
            $id = Jsx::get($d, 'id');
            $u = $units instanceof Obj && !($id instanceof Undef) && $units->has(Js::str($id)) ? Jsx::toNum($units->get(Js::str($id))) : 0.0;
            $num += $w * self::jsMin(1.0, fdiv(self::jsMax(0.0, $u), $c));
            $den += $w;
        }
        return Obj::of(['units' => $units, 'normalized' => $den == 0.0 ? 1 : self::clamp01(fdiv($num, $den))]);
    }

    // ---- composition ----------------------------------------------------------------------------------------------------------------

    private static function reject(array $reasons): Obj
    {
        return Obj::of(['r' => 1, 'valid' => false, 'reasons' => $reasons, 'raw' => 1,
            'inputs' => Obj::of(['semanticDistance' => 1, 'reversibility' => 0, 'blastRadius' => 1, 'taint' => 1, 'confidence' => 0, 'age' => 1]),
            'reversibility' => Obj::of(['class' => 'irreversible', 'value' => 0]),
            'blast' => Obj::of(['count' => 0, 'reachable' => [], 'normalized' => 1, 'harm' => new Obj()]),
            'harm' => Obj::of(['units' => new Obj(), 'normalized' => 1]), 'evidenceDigest' => '']);
    }

    private static function finiteOr(mixed $x, float|int $d): mixed
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) ? $x : $d;
    }

    /**
     * A pure function of (canonical action, committed context). A commitment mismatch (registry, graph, goal and embedder binding,
     * calibration set) or an action with no stable encoding is the fail-closed r = 1 with `valid` false. A graph or calibration set
     * that cannot be hashed (non-finite) throws.
     */
    public static function objectiveRisk(mixed $submitted, ObjectiveRiskContext $ctx): Obj
    {
        try {
            $action = self::canonicalAction($submitted);
        } catch (\Throwable $e) {
            return self::reject(['action: ' . ($e->getMessage() === '' ? 'not canonicalizable' : $e->getMessage())]);
        }
        $reasons = [];
        $cm = $ctx->commitments;
        if ($ctx->registry->digest() !== Jsx::get($cm, 'registryDigest')) {
            $reasons[] = 'registry digest does not match the committed digest';
        }
        if ($ctx->graph->digest() !== Jsx::get($cm, 'graphDigest')) {
            $reasons[] = 'graph digest does not match the committed digest';
        }
        if ($ctx->calibration !== null) {
            $cd = Jsx::get($cm, 'calibrationDigest');
            if ($cd instanceof Undef) {
                $reasons[] = 'calibration set used without a committed digest';
            } elseif (self::calibrationDigest($ctx->calibration) !== $cd) {
                $reasons[] = 'calibration digest does not match the committed digest';
            }
        }
        $dist = self::committedDistanceChecked($action, $ctx->goal, $ctx->embedder);
        if (!$dist['ok']) {
            $reasons[] = 'goal/embedder: ' . $dist['reason'];
        }
        if ($reasons !== []) {
            return self::reject($reasons);
        }
        $rev = self::reversibility($action, $ctx->registry, $ctx->authorizedKinds);
        $blast = self::blastRadius($action, $ctx->graph, $ctx->scope);
        $harm = self::harmReport($blast->get('harm'), $ctx->denominations);
        $au = $ctx->attestedUncertainty;
        $unc = self::clamp01(Js::num($au === null ? 0 : $au) ?? NAN); // a non-number is not finite: the worst case
        $useHarm = $ctx->denominations !== [] && $blast->get('harm')->keys() !== [];
        $blastIn = self::jsMax((float)$blast->get('normalized'), $useHarm ? (float)$harm->get('normalized') : 0.0);
        $inputs = Obj::of(['semanticDistance' => $dist['value'], 'reversibility' => $rev->get('value'), 'blastRadius' => $blastIn,
            'taint' => self::finiteOr($ctx->taint, 1), 'confidence' => 1 - $unc, 'age' => self::finiteOr($ctx->age, 1)]);
        $f = static fn(string $k): float => (float)Js::num($inputs->get($k));
        $w = static fn(string $k): float => (float)Jsx::toNum(Jsx::get($ctx->weights, $k));
        $raw = Risk::score(['semanticDistance' => $f('semanticDistance'), 'reversibility' => $f('reversibility'), 'blastRadius' => $f('blastRadius'),
            'taint' => $f('taint'), 'confidence' => $f('confidence'), 'age' => $f('age')],
            ['alpha' => $w('alpha'), 'beta' => $w('beta'), 'gamma' => $w('gamma'), 'delta' => $w('delta'), 'epsilon' => $w('epsilon'), 'zeta' => $w('zeta')]);
        $r = $ctx->calibration !== null ? self::calibrate($raw, $ctx->calibration) : $raw;
        $ek = $ctx->scope?->get('edgeKinds');
        $kinds = is_array($ek) ? $ek : null;
        if ($kinds !== null) {
            usort($kinds, static fn($a, $b): int => self::cmp($a, $b));
        }
        $auth = $ctx->authorizedKinds;
        usort($auth, static fn($a, $b): int => self::cmp($a, $b));
        $md = $ctx->scope?->get('maxDepth');
        $evidence = self::hash(Obj::of(['action' => self::canonicalActionDigest($action),
            'scope' => Obj::of(['edgeKinds' => $kinds, 'maxDepth' => $md]), 'authorized' => $auth, 'registry' => Jsx::get($cm, 'registryDigest'),
            'graph' => Jsx::get($cm, 'graphDigest'), 'goal' => Jsx::get($ctx->goal, 'commit'),
            'calibration' => ($c = Jsx::get($cm, 'calibrationDigest')) instanceof Undef ? null : $c, 'inputs' => $inputs]));
        return Obj::of(['r' => $r, 'valid' => true, 'reasons' => [], 'raw' => $raw, 'inputs' => $inputs, 'reversibility' => $rev, 'blast' => $blast, 'harm' => $harm,
            'evidenceDigest' => $evidence]);
    }

    /**
     * The dispute-game oracle: recompute one disputed input (`reversibility_class`, `reversibility`, `blastRadius`, `semanticDistance`)
     * from the committed facts over the frozen snapshot's canonical action. Fails closed (`valid` false, never a fabricated worst case).
     */
    public static function objectiveRiskOracle(ObjectiveRiskContext $ctx, mixed $input, mixed $snapshot): Obj
    {
        try {
            $a = Jsx::get(Jsx::get($snapshot, 'action'), 'action');
            if (!Jsx::truthy($a) || !is_string(Jsx::get($a, 'verb')) || !is_string(Jsx::get($a, 'resource'))) {
                return Obj::of(['input' => $input, 'valid' => false, 'reason' => 'snapshot action is missing a canonical verb/resource']);
            }
            $p = Jsx::get($a, 'params');
            $res = self::objectiveRisk(Obj::of(['verb' => $a->get('verb'), 'resource' => $a->get('resource'), 'params' => $p instanceof Obj ? $p : new Obj()]), $ctx);
            if ($res->get('valid') !== true) {
                $why = implode('; ', $res->get('reasons'));
                return Obj::of(['input' => $input, 'valid' => false, 'reason' => $why === '' ? 'objective risk could not be reproduced' : $why]);
            }
            return match ($input) {
                'reversibility_class' => Obj::of(['input' => $input, 'class' => $res->get('reversibility')->get('class'), 'valid' => true]),
                'reversibility', 'blastRadius', 'semanticDistance' => Obj::of(['input' => $input, 'value' => $res->get('inputs')->get($input), 'valid' => true]),
                default => Obj::of(['input' => $input, 'valid' => false, 'reason' => 'unknown disputed input: ' . Jsx::str($input)]),
            };
        } catch (\Throwable $e) {
            return Obj::of(['input' => $input, 'valid' => false, 'reason' => 'objective oracle error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())]);
        }
    }
}
