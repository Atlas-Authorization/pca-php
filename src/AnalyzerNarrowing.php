<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/AnalyzerCore.php';
require_once __DIR__ . '/AnalyzerExposure.php';
require_once __DIR__ . '/AnalyzerResidual.php';

/**
 * Least privilege from observed behaviour: proposes a narrower grant from what its holder really did (proven subsumed by the
 * original, never applied), unused-permission findings, and signed access requests.
 */
final class AnalyzerNarrowing
{
    public const ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\0";

    private const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];

    private static function revWeight(mixed $r): int
    {
        if (is_string($r)) {
            $i = array_search($r, self::REVERSIBILITY_ORDER, true);
            if ($i !== false) {
                return $i + 1;
            }
        }
        return 0;
    }

    /** @param list<string> $rs */
    private static function commonPrefix(array $rs): string
    {
        $p = $rs[0] ?? '';
        foreach ($rs as $r) {
            $i = 0;
            $n = min(strlen($p), strlen($r));
            while ($i < $n && $p[$i] === $r[$i]) {
                $i++;
            }
            $p = substr($p, 0, $i);
        }
        $cut = strrpos($p, '/');
        return $cut !== false ? substr($p, 0, $cut + 1) : '';
    }

    private static function isInteger(mixed $v): bool
    {
        if (!AnalyzerJs::isNum($v)) {
            return false;
        }
        $f = AnalyzerJs::jsnum($v);
        return is_finite($f) && floor($f) === $f;
    }

    private static function upperBoundOf(mixed $where, string $path): float
    {
        $ub = INF;
        foreach (AnalyzerJs::reqList(AnalyzerJs::nn($where, [])) as $c) {
            if ($c instanceof Obj && $c->has('field') && AnalyzerJs::strictEq($c->get('field'), $path)
                && ($c->get('op') === 'lte' || $c->get('op') === 'lt') && AnalyzerJs::isNum(AnalyzerJs::own($c, 'value'))) {
                $ub = min($ub, AnalyzerJs::jsnum($c->get('value')));
            }
        }
        return $ub;
    }

    private static function paramsOf(mixed $a): mixed
    {
        return AnalyzerJs::nn(AnalyzerJs::jget($a, 'params'), new Obj());
    }

    private static function matches(mixed $p, mixed $a): bool
    {
        $params = AnalyzerJs::jget($a, 'params');
        $action = AnalyzerJs::uobj([
            'verb' => AnalyzerJs::jget($a, 'verb'),
            'resource' => AnalyzerJs::jget($a, 'resource'),
            'params' => ($params instanceof Undef || $params === null) ? new Obj() : $params,
        ]);
        return Predicates::predicateMatches($p, Obj::of(['action' => $action]));
    }

    /** @param list<mixed> $verbs */
    private static function joinVerbs(array $verbs): string
    {
        return implode(', ', array_map(static fn($v) => $v === null ? '' : AnalyzerJs::jsStr($v), $verbs));
    }

    /** A JSON number option: a number, else TypeError (the reference would compute with a non-number). */
    private static function numOpt(mixed $v): float
    {
        if (!AnalyzerJs::isNum($v)) {
            throw new \TypeError('option must be a number');
        }
        return AnalyzerJs::jsnum($v);
    }

    /** @param list<float> $xs */
    private static function maxOf(array $xs): float
    {
        if ($xs === []) {
            throw new \ValueError('max() of an empty list');
        }
        $m = $xs[0];
        foreach ($xs as $x) {
            if ($x > $m) {
                $m = $x;
            }
        }
        return $m;
    }

    private static function specOf(mixed $catalog, mixed $verb): Obj
    {
        $s = AnalyzerExposure::resolveAction($catalog, $verb);
        $spec = AnalyzerJs::jget($s, 'spec');
        if (!($spec instanceof Obj)) {
            throw new \TypeError('resolveAction returned no spec');
        }
        return $spec;
    }

    private static function finding(Obj $f, Obj $s): Obj
    {
        $f->set('blastRadius', AnalyzerJs::jget($s, 'blastRadius'));
        $f->set('reversibility', AnalyzerJs::jget($s, 'reversibility'));
        $f->set('rank', AnalyzerJs::toNumber(AnalyzerJs::jget($s, 'blastRadius')) * self::revWeight(AnalyzerJs::jget($s, 'reversibility')));
        return $f;
    }

    /**
     * Propose a narrower replacement for `$policy` from the ledger-sourced `$observed` actions, plus unused-permission findings
     * and access requests for refused attempts. Result: {used, rejected, denied, proposal?, reason?, coversObserved, diff?,
     * findings, accessRequests, taskBinding?}. Never applies anything.
     */
    public static function suggestNarrowing(mixed $policy, mixed $observed, mixed $o = null): Obj
    {
        if ($o === null || $o === []) {
            $o = new Obj();
        } elseif (is_array($o) && !array_is_list($o)) {
            $o = Obj::of($o);
        }
        $margin = self::numOpt(AnalyzerJs::nn(AnalyzerJs::jget($o, 'margin'), 0.1));
        $minSamples = self::numOpt(AnalyzerJs::nn(AnalyzerJs::jget($o, 'minSamples'), 5));
        $enumLimit = self::numOpt(AnalyzerJs::nn(AnalyzerJs::jget($o, 'enumLimit'), 8));
        $catalog = AnalyzerJs::jget($o, 'catalog');
        $model = AnalyzerCore::toModel($policy);
        $digest = AnalyzerResidual::policyDigestOf($model);
        $observed = AnalyzerJs::reqList($observed);

        $trusted = [];
        $refused = [];
        $rejected = 0;
        foreach ($observed as $x) {
            $ledger = AnalyzerJs::jget($x, 'source') === 'ledger';
            $outcome = AnalyzerJs::jget($x, 'outcome');
            if ($ledger && $outcome !== 'denied') {
                $trusted[] = $x;
            }
            if (!$ledger) {
                $rejected++;
            }
            if ($ledger && $outcome === 'denied') {
                $refused[] = $x;
            }
        }

        $findings = [];
        $pp = AnalyzerJs::jget($policy, 'predicates');
        $base = AnalyzerJs::isArr($pp) ? $pp : [];

        $build = function (bool $narrowResources) use ($base, $trusted, $minSamples, $enumLimit, $margin): array {
            $out = [];
            foreach ($base as $p) {
                $hits = [];
                foreach ($trusted as $a) {
                    if (self::matches($p, $a)) {
                        $hits[] = $a;
                    }
                }
                if (!$hits) {
                    continue;
                }
                $verbs = self::sortedStrings(array_map(static fn($h) => AnalyzerJs::jget($h, 'verb'), $hits));
                $resources = self::sortedStrings(array_map(static fn($h) => AnalyzerJs::jget($h, 'resource'), $hits));
                $nxt = new Obj();
                $nxt->set('verb', count($verbs) === 1 ? $verbs[0] : $verbs);
                $pres = AnalyzerJs::jget($p, 'resource');
                if ($narrowResources) {
                    if (count($resources) === 1) {
                        $nxt->set('resource', $resources[0]);
                    } else {
                        $pre = self::commonPrefix($resources);
                        if (strlen($pre) > 1) {
                            $nxt->set('resource', $pre . '*');
                        } elseif (!($pres instanceof Undef)) {
                            $nxt->set('resource', $pres);
                        }
                    }
                } elseif (!($pres instanceof Undef)) {
                    $nxt->set('resource', $pres);
                }
                $where = AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), []));
                $names = [];
                foreach ($hits as $h) {
                    foreach (AnalyzerJs::spread(self::paramsOf($h))->keys() as $k) {
                        $names['k' . $k] = $k;
                    }
                }
                $names = array_values($names);
                usort($names, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b));
                foreach ($names as $name) {
                    $path = 'action.params.' . $name;
                    $vals = array_map(static fn($h) => AnalyzerJs::own(self::paramsOf($h), $name), $hits);
                    if (count($vals) < $minSamples) {
                        continue;
                    }
                    foreach ($vals as $v) {
                        if ($v instanceof Undef) {
                            continue 2;
                        }
                    }
                    $allNum = true;
                    $allStr = true;
                    foreach ($vals as $v) {
                        $allNum = $allNum && AnalyzerJs::isFin($v);
                        $allStr = $allStr && is_string($v);
                    }
                    if ($allNum) {
                        $mx = self::maxOf(array_map(static fn($v) => AnalyzerJs::jsnum($v), $vals));
                        $v = $mx * (1 + $margin);
                        $allInt = true;
                        foreach ($vals as $x) {
                            $allInt = $allInt && self::isInteger($x);
                        }
                        if ($allInt) {
                            if (!is_finite($v)) {
                                throw new \OverflowException('cannot convert to integer');
                            }
                            $ceil = ceil($v);
                        } else {
                            $ceil = $v;
                        }
                        if ($ceil < self::upperBoundOf(AnalyzerJs::jget($p, 'where'), $path)) {
                            $where[] = Obj::of(['field' => $path, 'op' => 'lte', 'value' => $ceil]);
                        }
                    } elseif ($allStr) {
                        $st = self::sortedStrings($vals);
                        if (count($st) <= $enumLimit) {
                            $where[] = Obj::of(['field' => $path, 'op' => 'in', 'value' => $st]);
                        }
                    }
                }
                if ($where) {
                    $nxt->set('where', $where);
                }
                $out[] = $nxt;
            }
            return $out;
        };

        foreach ($base as $i => $p) {
            $hit = false;
            foreach ($trusted as $a) {
                if (self::matches($p, $a)) {
                    $hit = true;
                    break;
                }
            }
            $pv = AnalyzerJs::jget($p, 'verb');
            $verbs = is_string($pv) ? [$pv] : (AnalyzerJs::isArr($pv) ? $pv : []);
            if (!$hit) {
                $v = ($verbs && $verbs[0] !== null) ? $verbs[0] : '*';
                $s = self::specOf($catalog, $v === '*' ? 'unknown.any' : $v);
                $joined = self::joinVerbs($verbs);
                $findings[] = self::finding(Obj::of([
                    'kind' => 'unused-predicate', 'predicate' => $i, 'verb' => $v,
                    'detail' => sprintf('no observed action used predicate %d (%s)', $i, $joined === '' ? '*' : $joined),
                ]), $s);
                continue;
            }
            foreach ($verbs as $v) {
                if ($v === '*') {
                    continue;
                }
                $used = false;
                foreach ($trusted as $a) {
                    if (AnalyzerJs::strictEq(AnalyzerJs::jget($a, 'verb'), $v) && self::matches($p, $a)) {
                        $used = true;
                        break;
                    }
                }
                if (!$used) {
                    $s = self::specOf($catalog, $v);
                    $findings[] = self::finding(Obj::of([
                        'kind' => 'unused-verb', 'predicate' => $i, 'verb' => $v,
                        'detail' => sprintf('verb %s is granted by predicate %d but never used', AnalyzerJs::jsStr($v), $i),
                    ]), $s);
                }
            }
            foreach (AnalyzerJs::reqList(AnalyzerJs::nn(AnalyzerJs::jget($p, 'where'), [])) as $c) {
                if ($c instanceof Obj && is_string($c->get('field')) && ($c->get('op') === 'lte' || $c->get('op') === 'lt')
                    && AnalyzerJs::isNum(AnalyzerJs::own($c, 'value')) && str_starts_with($c->get('field'), 'action.params.')) {
                    $name = substr($c->get('field'), strlen('action.params.'));
                    $vals = [];
                    foreach ($trusted as $a) {
                        if (self::matches($p, $a)) {
                            $x = AnalyzerJs::own(self::paramsOf($a), $name);
                            if (AnalyzerJs::isNum($x)) {
                                $vals[] = AnalyzerJs::jsnum($x);
                            }
                        }
                    }
                    if (count($vals) >= $minSamples && self::maxOf($vals) < AnalyzerJs::jsnum($c->get('value')) / 2) {
                        $v0 = $verbs ? $verbs[0] : AnalyzerJs::undef();
                        $s = self::specOf($catalog, (!($v0 instanceof Undef) && $v0 !== null) ? $v0 : 'unknown.any');
                        $f = Obj::of(['kind' => 'unreached-cap', 'predicate' => $i]);
                        if (AnalyzerJs::truthy($v0)) {
                            $f->set('verb', $v0);
                        }
                        $f->set('detail', sprintf('%s <= %s but the largest observed value is %s', $name,
                            AnalyzerJs::numStr(AnalyzerJs::jsnum($c->get('value'))), AnalyzerJs::numStr(self::maxOf($vals))));
                        $findings[] = self::finding($f, $s);
                    }
                }
            }
        }
        usort($findings, static function (Obj $a, Obj $b): int {
            return ($b->get('rank') <=> $a->get('rank')) ?: ($a->get('predicate') <=> $b->get('predicate'));
        });

        $groups = [];
        $taskBinding = AnalyzerJs::jget($o, 'taskBinding');
        foreach ($refused as $a) {
            $k = AnalyzerJs::jsStr(AnalyzerJs::jget($a, 'verb')) . "\0" . AnalyzerJs::jsStr(AnalyzerJs::jget($a, 'resource'));
            if (isset($groups['k' . $k])) {
                $g = $groups['k' . $k];
                $g->set('denied_count', $g->get('denied_count') + 1);
            } else {
                $r = AnalyzerJs::uobj([
                    'v' => 1, 'kind' => 'pca-access-request', 'verb' => AnalyzerJs::jget($a, 'verb'), 'resource' => AnalyzerJs::jget($a, 'resource'),
                    'example_params' => AnalyzerJs::spread(self::paramsOf($a)), 'denied_count' => 1, 'policy_digest' => $digest,
                ]);
                if (AnalyzerJs::truthy($taskBinding)) {
                    $r->set('task_binding', $taskBinding);
                }
                $groups['k' . $k] = $r;
            }
        }
        $accessRequests = array_values($groups);
        foreach ($accessRequests as $g) {
            if (!is_string($g->get('verb'))) {
                throw new \TypeError('access request verb must be a string');
            }
        }
        usort($accessRequests, static fn(Obj $a, Obj $b): int => ($b->get('denied_count') <=> $a->get('denied_count'))
            ?: AnalyzerJs::u16cmp($a->get('verb'), $b->get('verb')));

        $res = Obj::of([
            'used' => count($trusted), 'rejected' => $rejected, 'denied' => count($refused), 'coversObserved' => false,
            'findings' => $findings, 'accessRequests' => $accessRequests,
        ]);
        if (AnalyzerJs::truthy($taskBinding)) {
            $res->set('taskBinding', $taskBinding);
        }

        $caveats = AnalyzerJs::reqList(AnalyzerJs::nn($model->get('caveats'), []));
        $decay = AnalyzerJs::jget($o, 'decay');
        if (AnalyzerJs::truthy($decay)) {
            $nowSec = AnalyzerJs::jget($decay, 'nowSec');
            $exp = AnalyzerJs::jget($decay, 'expiresInSecs');
            if (!AnalyzerJs::isNum($nowSec) || !AnalyzerJs::isNum($exp)) {
                throw new \TypeError('decay needs numeric nowSec and expiresInSecs');
            }
            $caveats[] = Obj::of(['type' => 'expires', 'at' => AnalyzerJs::jsnum($nowSec) + AnalyzerJs::jsnum($exp)]);
        }
        $original = $policy;
        foreach ([true, false] as $narrow) {
            $proposal = Obj::of(['predicates' => $build($narrow), 'caveats' => $caveats, 'vetoes' => $model->get('vetoes'), 'tighten' => $model->get('tighten')]);
            if (count($proposal->get('predicates')) === 0) {
                $res->set('reason', 'no ledger observation matches any predicate');
                return $res;
            }
            $proof = AnalyzerCore::subsumes($original, $proposal);
            if ($proof->get('subsumes') !== true || $proof->get('approximate') === true) {
                $res->set('reason', $proof->has('reason') ? $proof->get('reason') : 'the proposal could not be proven narrower than the original');
                continue;
            }
            if ($res->has('reason')) {
                $res = $res->without('reason');
            }
            $res->set('proposal', $proposal);
            $covers = true;
            foreach ($trusted as $a) {
                $act = Obj::of(['verb' => AnalyzerJs::jget($a, 'verb'), 'resource' => AnalyzerJs::jget($a, 'resource'), 'params' => self::paramsOf($a)]);
                if (!AnalyzerCore::admitsConcrete($proposal, $act)) {
                    $covers = false;
                    break;
                }
            }
            $res->set('coversObserved', $covers);
            $res->set('diff', AnalyzerExposure::diffPolicies($original, $proposal));
            return $res;
        }
        return $res;
    }

    /**
     * Unique strings of `$xs` in JavaScript default string order; a non-string throws (the reference sorts by UTF-16 key).
     * @param list<mixed> $xs @return list<string>
     */
    private static function sortedStrings(array $xs): array
    {
        $u = [];
        foreach ($xs as $x) {
            if (!is_string($x)) {
                throw new \TypeError('expected a string');
            }
            $u['k' . $x] = $x;
        }
        $u = array_values($u);
        usort($u, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b));
        return $u;
    }

    // ---- access requests ---------------------------------------------------------------------------------------------------------

    /**
     * Parsed-JSON form of a built tree: PHP ints / floats become Num (the canonical hash takes only that model); a non-finite
     * number or an undefined value throws.
     */
    public static function modelOf(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::modelOf($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::modelOf(...), array_values($v));
        }
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            if (!is_finite($v)) {
                throw new \InvalidArgumentException('non-finite number');
            }
            return new Num($v == 0.0 ? '0' : IntentWb::jsStr($v));
        }
        if ($v instanceof Undef) {
            throw new \TypeError('undefined is not JSON');
        }
        return $v;
    }

    private static function requestMessage(mixed $r): string
    {
        return self::ACCESS_REQUEST_SIG_DOMAIN . hash('sha256', Pca::hashCanonical(self::modelOf($r)), true);
    }

    /** The holder's signed ask (a request for a human to read; nothing here turns it into authority). `$secret` is the Ed25519 seed. */
    public static function signAccessRequest(mixed $r, string $secret, string $signerPublic): Obj
    {
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($secret));
        return Obj::of(['request' => $r, 'signer' => $signerPublic, 'sig' => Pca::b64u(sodium_crypto_sign_detached(self::requestMessage($r), $sk))]);
    }

    /** Verify a signed access request (optionally against an expected signer public key); any failure is false. */
    public static function verifyAccessRequest(mixed $s, mixed $expectedSigner = null): bool
    {
        try {
            if (!($s instanceof Obj)) {
                return false;
            }
            $req = $s->get('request');
            if (!($req instanceof Obj) || $req->get('kind') !== 'pca-access-request' || !AnalyzerJs::strictEq(AnalyzerJs::own($req, 'v'), 1)) {
                return false;
            }
            if ($expectedSigner !== null && !AnalyzerJs::strictEq(AnalyzerJs::own($s, 'signer'), $expectedSigner)) {
                return false;
            }
            $sig = $s->get('sig');
            if (!is_string($sig)) {
                return false;
            }
            $pk = Pca::unb64u($s->get('signer'), 32);
            $sg = Pca::unb64u($sig, 64);
            if ($pk === null || $sg === null) {
                return false;
            }
            return sodium_crypto_sign_verify_detached($sg, self::requestMessage($req), $pk);
        } catch (\Throwable) {
            return false;
        }
    }
}
