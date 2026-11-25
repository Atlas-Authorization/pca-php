<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Grants.php';

/** A list-authorized refusal; `errorCode` is `read_budget_exhausted`, `bad_cursor` or `bad_limit`. */
final class ListError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * Reference read accumulator: `$cap` units per `$windowMs` fixed window per key. `charge` is false when the charge would exceed the cap.
 */
final class WindowReadAccumulator
{
    /** @var array<string,array{start:float,n:float}> */
    private array $used = [];

    public function __construct(private readonly mixed $cap, private readonly mixed $windowMs)
    {
    }

    public function charge(string $key, mixed $units, mixed $now): bool
    {
        if (K3Sig::num($units) === null || K3Sig::num($now) === null) {
            return false; // a non-finite charge or clock never counts as within budget
        }
        $now = (float)K3Sig::num($now);
        $e = $this->used['k' . $key] ?? null;
        // the window and cap read raw: +INF is a legitimate unbounded window or cap, NaN or a non-number never roll the window or admit
        $window = Js::num($this->windowMs) ?? NAN;
        $cap = Js::num($this->cap) ?? NAN;
        $cur = $e === null || $now - $e['start'] >= $window ? ['start' => $now, 'n' => 0.0] : $e;
        if (!($cur['n'] + (float)K3Sig::num($units) <= $cap)) {
            return false;
        }
        $cur['n'] += (float)K3Sig::num($units);
        $this->used['k' . $key] = $cur;
        return true;
    }
}

/**
 * List-authorized: "which objects of this type may this agent touch?". Authority is capability AND relationship: `permits` (the
 * grant's own predicates) decides, a relation source can only NARROW. Every page is charged to a read accumulator (scanned AND
 * returned objects), pages are bound by a signed cursor (changing subject, type, filter, policy, relation or limit between pages is
 * refused) and the result carries a signed receipt.
 *
 * A candidate source is an object with `page(array{type, cursor?, limit}): array{objects, next?}`; a relation source an object with
 * `check(array{subject, relation, object}): bool` and optionally `listObjects(array): array`; a read accumulator an object with
 * `charge(key, units, now): bool` ({@see WindowReadAccumulator}).
 */
final class ListAuthorized
{
    public const MAX_PAGE_LIMIT = 500;

    /** Adapt a relation source's `listObjects` into a candidate source for one subject and relation. */
    public static function candidatesFromRelation(object $rel, string $subject, string $relation): object
    {
        if (!method_exists($rel, 'listObjects')) {
            throw new \TypeError('candidatesFromRelation: the relation source has no listObjects');
        }
        return new class ($rel, $subject, $relation) {
            public function __construct(private readonly object $rel, private readonly string $subject, private readonly string $relation)
            {
            }

            public function page(array $q): array
            {
                return $this->rel->listObjects(['subject' => $this->subject, 'relation' => $this->relation] + $q);
            }
        };
    }

    private static function encCursor(Obj $c, KeyPair $secret): string
    {
        return Pca::b64u(Js::stringify($c)) . '.' . Grants::signBody(K3::LIST_CURSOR_DOMAIN, $c, $secret);
    }

    /**
     * One page of authorized objects: `{objects, next_cursor?, receipt}`. Options (assoc array, the reference's names): subject,
     * resourceType, permits (callable), candidates, filterId, policyDigest, freshAtDigest, page (`['limit' => .., 'cursor' => ..]`),
     * reads, now, signingSecret (KeyPair), relation (`['source' => object, 'relation' => string]`), maxScan. Throws {@see ListError}.
     */
    public static function listAuthorized(array $o): Obj
    {
        $page = $o['page'];
        $limit = $page['limit'] ?? null;
        if (!K3Sig::anySafeInt($limit) || (float)K3Sig::num($limit) < 1 || (float)K3Sig::num($limit) > self::MAX_PAGE_LIMIT) {
            throw new ListError('bad_limit', 'limit must be 1..' . self::MAX_PAGE_LIMIT);
        }
        $limit = (int)K3Sig::num($limit);
        $secret = $o['signingSecret'];
        $signer = $secret->public;
        $relation = $o['relation'] ?? null;
        $bindInputs = Obj::of(['subject' => $o['subject'], 'resourceType' => $o['resourceType'], 'filterId' => $o['filterId'], 'policyDigest' => $o['policyDigest'], 'limit' => $limit]);
        if ($relation !== null) {
            $bindInputs->set('relation', Obj::of(['relation' => $relation['relation']]));
        }
        $bind = K3::listBind($bindInputs);
        $inner = null;
        $skipIn = 0;
        if (($page['cursor'] ?? null) !== null) {
            $c = K3::verifyListCursor($page['cursor'], $signer, $bindInputs);
            if (!$c['ok']) {
                throw new ListError('bad_cursor', $c['reason'] === 'bind' ? 'subject, type, filter, policy or limit changed between pages'
                    : 'the page cursor is malformed, forged or from another signer');
            }
            $inner = $c['inner'] ?? null;
            $skipIn = $c['skip'];
        }
        $maxScan = min($o['maxScan'] ?? $limit * 4, 1000);
        $key = Pca::hashCanonical(Obj::of(['s' => $o['subject'], 't' => $o['resourceType']]));
        $out = [];
        $scanned = 0;
        $pageStart = $inner;
        $skip = $skipIn;
        $resume = null;
        while (true) {
            $q = ['type' => $o['resourceType'], 'limit' => $limit];
            if ($pageStart !== null) {
                $q['cursor'] = $pageStart;
            }
            $pg = $o['candidates']->page($q);
            $objs = array_slice(array_values($pg['objects']), 0, $limit);
            // charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack
            if (!$o['reads']->charge($key, max(count($objs) - $skip, 1), $o['now'])) {
                throw new ListError('read_budget_exhausted', 'the read budget for this subject and type is exhausted');
            }
            $i = $skip;
            while ($i < count($objs) && count($out) < $limit) {
                $scanned++;
                $obj = $objs[$i];
                $i++;
                if (!($o['permits'])($obj)) {
                    continue;
                }
                if ($relation !== null && !$relation['source']->check(['subject' => $o['subject'], 'relation' => $relation['relation'], 'object' => $obj])) {
                    continue;
                }
                $out[] = $obj;
            }
            if ($i < count($objs)) {
                $resume = ['skip' => $i] + ($pageStart !== null ? ['inner' => $pageStart] : []);
                break;
            }
            $nxt = $pg['next'] ?? null;
            if ($nxt === null || $nxt === '' || count($objs) === 0) {
                break;
            }
            $pageStart = $nxt;
            $skip = 0;
            if (count($out) >= $limit || $scanned >= $maxScan) {
                $resume = ['inner' => $nxt, 'skip' => 0];
                break;
            }
        }
        $receipt = Obj::of(['v' => 1, 'subject' => $o['subject'], 'resource_type' => $o['resourceType'], 'policy_digest' => $o['policyDigest'], 'fresh_at' => $o['freshAtDigest'],
            'filter_digest' => $o['filterId'], 'count' => count($out), 'objects_digest' => K3::objectsDigest($out), 'issued_at' => $o['now'], 'signer' => $signer]);
        $result = Obj::of(['objects' => $out]);
        if ($resume !== null) {
            $cur = Obj::of(['v' => 1]);
            if (array_key_exists('inner', $resume)) {
                $cur->set('inner', $resume['inner']);
            }
            $cur->set('skip', $resume['skip']);
            $cur->set('bind', $bind);
            $cur->set('signer', $signer);
            $result->set('next_cursor', self::encCursor($cur, $secret));
        }
        $receipt->set('sig', Grants::signBody(K3::LIST_RECEIPT_DOMAIN, $receipt->without('sig'), $secret));
        $result->set('receipt', $receipt);
        return $result;
    }
}
