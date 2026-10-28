<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/ReadSide.php';

/** Where {@see ReadVault::redactReadWithVault} records the tokens it mints. An entry is `['cls' => string, 'value' => mixed, 'grant' => string, 'exp' => int]`. */
interface VaultStore
{
    public function put(string $token, array $entry): void;

    public function get(string $token): ?array;
}

final class MemoryVault implements VaultStore
{
    /** @var array<string,array> */
    private array $m = [];

    public function put(string $token, array $entry): void
    {
        $this->m['k' . $token] = $entry;
    }

    public function get(string $token): ?array
    {
        return $this->m['k' . $token] ?? null;
    }
}

/**
 * The integer-exact draw source of the discrete Laplace sampler: block i is SHA-256 of the canonical {d, seed, i}, each block
 * yields five 48-bit big-endian values (bytes 0-5, 6-11, ... 24-29). PHP ints are signed 64-bit, so every value is exact.
 */
final class Draws
{
    private const STREAM = 'atlas-pca/dp-stream/v1';
    private const TWO48 = 281474976710656;
    private const MAX_STEPS = 100000;

    private int $block = 0;
    /** @var list<int> */
    private array $buf = [];
    private int $pos = 0;

    public function __construct(private readonly string $seed)
    {
    }

    private function next48(): int
    {
        if ($this->pos >= count($this->buf)) {
            $raw = Pca::unb64u(IntentV2::hashCanonical(Obj::of(['d' => self::STREAM, 'seed' => $this->seed, 'i' => $this->block++])), 32);
            if ($raw === null) {
                throw new \RangeException('draws: bad block');
            }
            $this->buf = [];
            for ($k = 0; $k < 5; $k++) {
                $v = 0;
                for ($j = 0; $j < 6; $j++) {
                    $v = $v * 256 + ord($raw[$k * 6 + $j]);
                }
                $this->buf[] = $v;
            }
            $this->pos = 0;
        }
        return $this->buf[$this->pos++];
    }

    /** Uniform on [0, n) for 1 <= n <= 2^47, by rejection sampling of 48-bit values. */
    public function uniform(int $n): int
    {
        if ($n < 1 || $n > 140737488355328) {
            throw new \RangeException('uniform: bad bound');
        }
        $limit = self::TWO48 - (self::TWO48 % $n);
        for ($i = 0; $i < self::MAX_STEPS; $i++) {
            $r = $this->next48();
            if ($r < $limit) {
                return $r % $n;
            }
        }
        throw new \RangeException('uniform: no draw');
    }
}

/**
 * TOKENISATION VAULT and AGGREGATE READ LIMITS (K5, C-315..C-319), the port of packages/pca/src/read-vault.ts. A `token` mask
 * replaces a value with `tok_...`; {@see redactReadWithVault} records every token it minted and {@see detokenize} returns the
 * value only for a sink the same signed, unexpired, pinned-principal grant lets that token's class reach. {@see aggregateRead}
 * answers one count / sum under a signed AggregateGrant (group size k, clamp, query cap, integer micro-epsilon budget), a repeated
 * identical query is answered from the state without a charge. Verification only (no signing here). Total: a thrown error is a
 * denial (`bad_request`). Integers only. Replays packages/pca/conformance/vault-aggregate-vectors.json.
 */
final class ReadVault
{
    public const AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\0";
    private const AG_REF = 'atlas-pca/aggregate-grant-ref/v1';
    private const AG_Q = 'atlas-pca/aggregate-query/v1';
    private const AG_N = 'atlas-pca/aggregate-noise/v1';
    private const MAX_STEPS = 100000;

    // ---- vault ----------------------------------------------------------------------------------------------------------

    /** {@see ReadSide::redactRead} that also records every token it minted in `$store`. */
    public static function redactReadWithVault(mixed $inp, VaultStore $store): array
    {
        try {
            $r = ReadSide::redactRead($inp);
            if ($r['decision'] !== 'allow') {
                return $r;
            }
            $g = $inp->get('grant')->get('body');
            $digest = ReadSide::readGrantDigest($g);
            foreach ($r['fields']->keys() as $path) {
                $f = $r['fields']->get($path);
                if ($f->get('action') === 'masked' && $f->get('kind') === 'token') {
                    $store->put($r['view']->get($path), ['cls' => $f->get('class'), 'value' => $inp->get('record')->get($path), 'grant' => $digest, 'exp' => Workflow::iv($g->get('expires_at'))]);
                }
            }
            return $r;
        } catch (\Throwable) {
            return ReadSide::redactRead(null); // the total deny result of the redaction
        }
    }

    /** @return array{decision: string, code: ?string, value: mixed} */
    private static function no(string $code): array
    {
        return ['decision' => 'deny', 'code' => $code, 'value' => null];
    }

    /**
     * Turn a token back into its value, only for a sink the grant allows that token's class to reach. `$inp` is an Obj with `grant`,
     * `principal`, `now`, `sink`, `token` and `store` (a {@see VaultStore}).
     *
     * @return array{decision: string, code: ?string, value: mixed}
     */
    public static function detokenize(mixed $inp): array
    {
        try {
            if (!($inp instanceof Obj)) {
                return self::no('bad_request');
            }
            $store = $inp->get('store');
            $principal = $inp->get('principal');
            $now = $inp->get('now');
            $token = $inp->get('token');
            $sink = $inp->get('sink');
            if (!($store instanceof VaultStore) || !Workflow::isB32($principal) || !Workflow::isUint($now) || !is_string($token) || !is_string($sink)) {
                return self::no('bad_request');
            }
            $sg = $inp->get('grant');
            if (!($sg instanceof Obj) || !Workflow::onlyKeys($sg, ['body', 'sig']) || !ReadSide::validReadGrantBody($sg->get('body'))) {
                return self::no('bad_grant');
            }
            $b = $sg->get('body');
            if ($b->get('principal') !== $principal || !Workflow::verifyBody(ReadSide::READ_GRANT_DOMAIN, $b, $principal, $sg->get('sig'))) {
                return self::no('bad_signature');
            }
            $n = Workflow::iv($now);
            if ($n < Workflow::iv($b->get('issued_at'))) {
                return self::no('not_yet');
            }
            if ($n >= Workflow::iv($b->get('expires_at'))) {
                return self::no('expired');
            }
            $e = $store->get($token);
            if ($e === null || $e['grant'] !== ReadSide::readGrantDigest($b)) {
                return self::no('unknown_token');
            }
            if ($n >= $e['exp']) {
                return self::no('expired');
            }
            $sinks = $b->get('sinks');
            if (!$sinks->has($sink)) {
                return self::no('unknown_sink');
            }
            $rule = $sinks->get($sink);
            if (in_array($e['cls'], $rule->get('allow'), true)) {
                return ['decision' => 'allow', 'code' => null, 'value' => $e['value']];
            }
            if (in_array($e['cls'], $rule->get('escalate'), true)) {
                return ['decision' => 'escalate', 'code' => 'label_escalate', 'value' => null];
            }
            return self::no('label_flow');
        } catch (\Throwable) {
            return self::no('bad_request');
        }
    }

    // ---- aggregates -----------------------------------------------------------------------------------------------------

    private static function validRule(mixed $r): bool
    {
        if (!($r instanceof Obj) || !Workflow::onlyKeys($r, ['verb', 'resource_prefix', 'purposes', 'fns', 'min_group', 'clamp', 'epsilon_micro', 'dp'])
            || !Workflow::isStr($r->get('verb'), 128) || !Workflow::isStr($r->get('resource_prefix'), 512)
            || !Workflow::sortedUnique($r->get('purposes'), Workflow::ID_RE, 16) || count($r->get('purposes')) === 0
            || !Workflow::sortedUnique($r->get('fns'), '/\A(?:count|sum)\z/D', 2) || count($r->get('fns')) === 0
            || !Workflow::isUint($r->get('min_group')) || Workflow::iv($r->get('min_group')) < 1
            || !Workflow::isUint($r->get('clamp')) || Workflow::iv($r->get('clamp')) > 1000000
            || !Workflow::isUint($r->get('epsilon_micro')) || Workflow::iv($r->get('epsilon_micro')) > 1073741824 || !is_bool($r->get('dp'))) {
            return false;
        }
        return $r->get('dp') ? Workflow::iv($r->get('epsilon_micro')) >= 1 : true;
    }

    /** Shape of an aggregate grant body (no signature). */
    public static function validAggregateGrantBody(mixed $b): bool
    {
        if (!($b instanceof Obj) || !Workflow::onlyKeys($b, ['v', 'id', 'principal', 'issued_at', 'expires_at', 'rules', 'epsilon_budget_micro', 'max_queries'])
            || !Workflow::isUint($b->get('v')) || Workflow::iv($b->get('v')) !== 1 || !Workflow::matches(Workflow::ID_RE, $b->get('id'))
            || !Workflow::isB32($b->get('principal')) || !Workflow::isUint($b->get('issued_at')) || !Workflow::isUint($b->get('expires_at'))
            || !Workflow::isUint($b->get('epsilon_budget_micro')) || !Workflow::isUint($b->get('max_queries'))) {
            return false;
        }
        $rules = $b->get('rules');
        if (!Workflow::isList($rules) || count($rules) < 1 || count($rules) > 16) {
            return false;
        }
        foreach ($rules as $r) {
            if (!self::validRule($r)) {
                return false;
            }
        }
        return true;
    }

    public static function aggregateGrantDigest(Obj $b): string
    {
        return Workflow::hash(self::AG_REF, 'g', $b);
    }

    public static function emptyAggregateState(): Obj
    {
        return Obj::of(['spent_micro' => 0, 'queries' => 0, 'answered' => new Obj()]);
    }

    /** @return array{decision: string, code: ?string, value: ?int, state: Obj, charged_micro: int} */
    private static function fail(string $code, ?Obj $s = null): array
    {
        return ['decision' => 'deny', 'code' => $code, 'value' => null, 'state' => $s ?? self::emptyAggregateState(), 'charged_micro' => 0];
    }

    private static function clampSum(array $values, int $clamp): int
    {
        $s = 0;
        foreach ($values as $v) {
            $s += max(-$clamp, min($clamp, Workflow::iv($v)));
        }
        return $s;
    }

    /**
     * Answer one aggregate under the grant, or refuse. The input state is never mutated. `$inp` is an Obj with `grant`,
     * `principal`, `now`, `verb`, `resource`, `purpose`, `fn` ('count' | 'sum'), `values` (a list of integers), `salt` (>= 16
     * characters), `noise` ('seeded' | 'secure') and `state` ({spent_micro, queries, answered}). `secure` draws a fresh CSPRNG seed per
     * answer and is the PRODUCTION setting (the answer is then not reproducible); `seeded` is deterministic from the salt and the
     * query (vectors, tests, reproducible audits).
     *
     * @return array{decision: string, code: ?string, value: ?int, state: Obj, charged_micro: int}
     */
    public static function aggregateRead(mixed $inp): array
    {
        try {
            if (!($inp instanceof Obj)) {
                return self::fail('bad_request');
            }
            $st = $inp->get('state');
            if (!($st instanceof Obj) || !Workflow::isUint($st->get('spent_micro'))
                || !Workflow::isUint($st->get('queries')) || !($st->get('answered') instanceof Obj)) {
                return self::fail('bad_request');
            }
            $answered = $st->get('answered');
            foreach ($answered->keys() as $k) {
                if (!Workflow::isSafeInt($answered->get($k))) {
                    return self::fail('bad_request');
                }
            }
            $principal = $inp->get('principal');
            $now = $inp->get('now');
            if (!Workflow::isB32($principal) || !Workflow::isUint($now)) {
                return self::fail('bad_request', $st);
            }
            $sg = $inp->get('grant');
            if (!($sg instanceof Obj) || !Workflow::onlyKeys($sg, ['body', 'sig']) || !self::validAggregateGrantBody($sg->get('body'))) {
                return self::fail('bad_grant', $st);
            }
            $g = $sg->get('body');
            if ($g->get('principal') !== $principal || !Workflow::verifyBody(self::AGGREGATE_DOMAIN, $g, $principal, $sg->get('sig'))) {
                return self::fail('bad_signature', $st);
            }
            $n = Workflow::iv($now);
            if ($n < Workflow::iv($g->get('issued_at'))) {
                return self::fail('not_yet', $st);
            }
            if ($n >= Workflow::iv($g->get('expires_at'))) {
                return self::fail('expired', $st);
            }
            $verb = $inp->get('verb');
            $resource = $inp->get('resource');
            $purpose = $inp->get('purpose');
            $fn = $inp->get('fn');
            $noise = $inp->get('noise');
            $salt = $inp->get('salt');
            $values = $inp->get('values');
            if (!Workflow::isStr($verb, 128) || !Workflow::isStr($resource, 512) || !Workflow::matches(Workflow::ID_RE, $purpose) || ($fn !== 'count' && $fn !== 'sum')
                || ($noise !== 'seeded' && $noise !== 'secure') || !is_string($salt) || K3Sig::utf16Len($salt) < 16 || !Workflow::isList($values) || count($values) > 1000000) {
                return self::fail('bad_request', $st);
            }
            foreach ($values as $v) {
                if (!Workflow::isSafeInt($v)) {
                    return self::fail('bad_request', $st);
                }
            }
            $rule = null;
            foreach ($g->get('rules') as $r) {
                if ($r->get('verb') === $verb && str_starts_with($resource, $r->get('resource_prefix')) && in_array($purpose, $r->get('purposes'), true)) {
                    $rule = $r;
                    break;
                }
            }
            if ($rule === null || !in_array($fn, $rule->get('fns'), true)) {
                return self::fail('no_read_scope', $st);
            }
            if (count($values) < Workflow::iv($rule->get('min_group'))) {
                return self::fail('group_too_small', $st);
            }
            $clamp = Workflow::iv($rule->get('clamp'));
            $qd = IntentV2::hashCanonical(Obj::of(['d' => self::AG_Q, 'g' => self::aggregateGrantDigest($g), 'verb' => $verb, 'resource' => $resource,
                'purpose' => $purpose, 'fn' => $fn, 'n' => count($values), 's' => self::clampSum($values, $clamp)]));
            if ($answered->has($qd)) {
                return ['decision' => 'allow', 'code' => null, 'value' => Workflow::iv($answered->get($qd)), 'state' => $st, 'charged_micro' => 0];
            }
            $spent = Workflow::iv($st->get('spent_micro'));
            $queries = Workflow::iv($st->get('queries'));
            if ($queries + 1 > Workflow::iv($g->get('max_queries'))) {
                return self::fail('query_cap', $st);
            }
            $eps = Workflow::iv($rule->get('epsilon_micro'));
            $cost = $rule->get('dp') ? $eps : 0;
            if ($spent + $cost > Workflow::iv($g->get('epsilon_budget_micro'))) {
                return self::fail('epsilon_exhausted', $st);
            }
            $exact = $fn === 'count' ? count($values) : self::clampSum($values, $clamp);
            if ($rule->get('dp')) {
                $sens = $fn === 'count' ? 1 : $clamp;
                // 'secure' (PRODUCTION): a fresh seed from the OS CSPRNG; 'seeded': deterministic from the salt and the query digest
                $draws = $noise === 'secure' ? self::secureDraws() : self::seededDraws(IntentV2::hashCanonical(Obj::of(['d' => self::AG_N, 'salt' => $salt, 'q' => $qd])));
                $exact += self::discreteLaplace($draws, $eps, $sens * 1000000);
            }
            $next = new Obj();
            foreach ($answered->keys() as $k) {
                $next->set($k, $answered->get($k));
            }
            $next->set($qd, $exact);
            return ['decision' => 'allow', 'code' => null, 'value' => $exact,
                'state' => Obj::of(['spent_micro' => $spent + $cost, 'queries' => $queries + 1, 'answered' => $next]), 'charged_micro' => $cost];
        } catch (\Throwable) { // includes the sampler's RangeException (bad bound, no termination)
            return self::fail('bad_request');
        }
    }

    // ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) ------------------------------------

    public static function seededDraws(string $seed): Draws
    {
        return new Draws($seed);
    }

    /** The PRODUCTION mode: a seed from the operating system's CSPRNG. */
    public static function secureDraws(): Draws
    {
        return new Draws(Pca::b64u(random_bytes(32)));
    }

    private static function bern(Draws $d, int $num, int $den): bool
    {
        return $d->uniform($den) < $num; // Bernoulli(num/den)
    }

    /** Bernoulli(exp(-num/den)) for 0 <= num/den <= 1. */
    private static function bernExpSmall(Draws $d, int $num, int $den): bool
    {
        for ($k = 1; $k <= self::MAX_STEPS; $k++) {
            if (!self::bern($d, $num, $den * $k)) {
                return $k % 2 === 1;
            }
        }
        throw new \RangeException('bernoulli: no termination');
    }

    /** Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s the rate numerator, t the scale denominator). */
    public static function discreteLaplace(Draws $d, int $s, int $t): int
    {
        if ($s < 1) {
            throw new \RangeException('laplace: bad rate');
        }
        for ($outer = 0; $outer < self::MAX_STEPS; $outer++) {
            $u = $d->uniform($t);
            if (!self::bernExpSmall($d, $u, $t)) {
                continue;
            }
            $v = 0;
            while (self::bernExpSmall($d, 1, 1)) {
                if (++$v > self::MAX_STEPS) {
                    throw new \RangeException('laplace: no termination');
                }
            }
            $y = intdiv($u + $t * $v, $s);
            $negative = $d->uniform(2) === 1;
            if ($negative && $y === 0) {
                continue;
            }
            return $negative ? -$y : $y;
        }
        throw new \RangeException('laplace: no sample');
    }
}
