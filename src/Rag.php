<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/ArgProvenance.php';

/**
 * FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the reference's
 * pca-rag: aclsFromMetadata, compilePolicy, principalFromPCActn, filterDocuments).
 *
 * FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation, resource =
 * object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy translation, an evaluator
 * error) drops the document. Every decision is recorded, with a content digest of the whole decision set.
 *
 * Values are the library's JSON (Obj, list, string, ...). A principal is a string id or an Obj {id, attributes?, env?}. A policy is a list of
 * predicates, an Obj {openfga: {model, tuples}}, an Obj {predicates, denies?, report?} or an already compiled policy.
 */
final class Rag
{
    private static function nonEmpty(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function docAcl(mixed $v): bool
    {
        return $v instanceof Obj && self::nonEmpty($v->get('relation')) && self::nonEmpty($v->get('object'));
    }

    /** @return list<mixed> */
    private static function aclArray(mixed $acl): array
    {
        if (self::isList($acl)) {
            return array_values(array_filter($acl, self::docAcl(...)));
        }
        return self::docAcl($acl) ? [$acl] : [];
    }

    /** A `relation:object` tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons. */
    private static function tagToAcl(mixed $tag): ?Obj
    {
        if (!is_string($tag)) {
            return null;
        }
        $i = strpos($tag, ':');
        if ($i === false || $i <= 0 || $i >= strlen($tag) - 1) {
            return null;
        }
        return Obj::of(['relation' => substr($tag, 0, $i), 'object' => substr($tag, $i + 1)]);
    }

    /** ACL entries from free-form `acl` (one entry or a list) and `tags` (`relation:object` strings) metadata. @return list<mixed> */
    public static function aclsFromMetadata(mixed $acl, mixed $tags): array
    {
        $out = self::aclArray($acl);
        if (self::isList($tags)) {
            foreach ($tags as $t) {
                $a = self::tagToAcl($t);
                if ($a !== null) {
                    $out[] = $a;
                }
            }
        }
        return $out;
    }

    /**
     * The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with `opts.id`).
     * Throws on a PCActn with no capability chain, rather than producing an empty principal.
     */
    public static function principalFromPCActn(mixed $pcactn, mixed $opts = null): Obj
    {
        $chain = $pcactn instanceof Obj ? $pcactn->get('cap_chain') : null;
        $leaf = self::isList($chain) && $chain !== [] ? $chain[array_key_last($chain)] : null;
        $holder = $leaf instanceof Obj ? $leaf->get('holder') : null;
        if (!self::nonEmpty($holder)) {
            throw new \TypeError('principalFromPCActn: PCActn has no leaf capability holder');
        }
        $o = $opts instanceof Obj ? $opts : new Obj();
        $out = Obj::of(['id' => $o->get('id') ?? $holder]);
        foreach (['attributes', 'env'] as $k) {
            if ($o->has($k)) {
                $out->set($k, $o->get($k));
            }
        }
        return $out;
    }

    private static function toPrincipal(mixed $p): ?Obj
    {
        if (is_string($p)) {
            return Obj::of(['id' => $p]);
        }
        if ($p instanceof Obj) {
            return $p;
        }
        return self::isList($p) ? new Obj() : null; // a JavaScript array is an object with no id
    }

    private static function incomplete(string $reason): Obj
    {
        return Obj::of(['predicates' => [], 'denies' => [], 'incomplete' => true, 'incompleteReason' => $reason]);
    }

    /** JavaScript `x.length > 0` for a JSON value that is not null. */
    private static function lengthPositive(mixed $x): bool
    {
        if (is_array($x) || is_string($x)) {
            return $x !== [] && $x !== '';
        }
        if ($x instanceof Obj) {
            $n = Js::num($x->get('length'));
            return $n !== null && $n > 0;
        }
        return false;
    }

    /**
     * Compile any policy into {predicates, denies, incomplete, incompleteReason?, report?} (an already compiled policy passes through). A
     * value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.
     */
    public static function compilePolicy(mixed $policy): Obj
    {
        if (!($policy instanceof Obj) && !self::isList($policy)) {
            return self::incomplete('no usable policy was supplied (fail closed)');
        }
        if (self::isList($policy)) {
            return Obj::of(['predicates' => $policy, 'denies' => [], 'incomplete' => false]);
        }
        if (is_bool($policy->get('incomplete'))) {
            return $policy;
        }
        if (!$policy->has('openfga') && !self::isList($policy->get('predicates'))) {
            return self::incomplete('the policy has no predicates and is not an OpenFGA policy (fail closed)');
        }
        if ($policy->has('openfga')) {
            $fga = $policy->get('openfga');
            if (!($fga instanceof Obj) && !self::isList($fga)) {
                return self::incomplete('the OpenFGA policy has no model (fail closed)');
            }
            $f = $fga instanceof Obj ? $fga : new Obj(); // an array has no model or tuples
            $br = $f->has('tuples') ? PolicyBridge::openfgaToPca($f->get('model'), $f->get('tuples')) : PolicyBridge::openfgaToPca($f->get('model'));
            $report = $br->get('report');
            $errors = $report instanceof Obj ? $report->get('errors') : null;
            return Obj::of(['predicates' => $br->get('predicates'), 'denies' => $br->get('denies'), 'report' => $report,
                'incomplete' => self::isList($errors) && $errors !== []]);
        }
        $denies = $policy->get('denies');
        $out = Obj::of(['predicates' => $policy->get('predicates'), 'denies' => self::isList($denies) ? $denies : []]);
        if ($policy->has('report')) {
            $report = $policy->get('report');
            // the reference reads report.errors.length: a report without errors is a TypeError there
            if (!($report instanceof Obj) || $report->get('errors') === null) {
                throw new \TypeError('compilePolicy: report.errors is required');
            }
            $out->set('report', $report);
            $out->set('incomplete', self::lengthPositive($report->get('errors')));
        } else {
            $out->set('incomplete', false);
        }
        return $out;
    }

    /** The evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id. */
    private static function context(Obj $principal, Obj $acl): Obj
    {
        $attrs = $principal->get('attributes');
        $subject = new Obj();
        if ($attrs instanceof Obj) {
            foreach ($attrs->keys() as $k) {
                $subject->set($k, $attrs->get($k));
            }
        } elseif (self::isList($attrs)) {
            foreach ($attrs as $i => $v) { // object spread of an array
                $subject->set((string)$i, $v);
            }
        } elseif (is_string($attrs)) {
            foreach (mb_str_split($attrs, 1, 'UTF-8') as $i => $c) {
                $subject->set((string)$i, $c);
            }
        }
        $subject->set('id', $principal->get('id'));
        $ctx = Obj::of(['action' => Obj::of(['verb' => $acl->get('relation'), 'resource' => $acl->get('object')]), 'subject' => $subject]);
        if ($principal->has('env')) {
            $ctx->set('env', $principal->get('env'));
        }
        return $ctx;
    }

    /** @param list<mixed> $acls */
    private static function decideDocument(string $id, array $acls, Obj $principal, Obj $compiled): Obj
    {
        if ($compiled->get('incomplete') === true) {
            $why = $compiled->get('incompleteReason');
            return Obj::of(['id' => $id, 'allowed' => false, 'reason' => is_string($why) ? $why : 'policy translation incomplete (fail closed)']);
        }
        $pid = $principal->get('id');
        if (!self::nonEmpty($pid)) {
            return Obj::of(['id' => $id, 'allowed' => false, 'reason' => 'no principal identity (fail closed)']);
        }
        if ($acls === []) {
            return Obj::of(['id' => $id, 'allowed' => false, 'reason' => 'no decidable ACL metadata (fail closed)']);
        }
        $last = 'no relation grants access (fail closed)';
        $pol = Obj::of(['predicates' => $compiled->get('predicates'), 'denies' => $compiled->get('denies')]);
        foreach ($acls as $acl) {
            try {
                $res = PolicyBridge::decide($pol, self::context($principal, $acl));
            } catch (\Throwable) {
                $last = 'evaluator error (fail closed)';
                continue;
            }
            if (($res['allowed'] ?? null) === true) {
                $d = Obj::of(['id' => $id, 'allowed' => true, 'via' => $acl,
                    'reason' => "granted: $pid has " . $acl->get('relation') . ' on ' . $acl->get('object')]);
                if (($res['matched'] ?? null) !== null) {
                    $d->set('matched', $res['matched']);
                }
                return $d;
            }
            if (is_string($res['reason'] ?? null)) {
                $last = $res['reason'];
            }
        }
        return Obj::of(['id' => $id, 'allowed' => false, 'reason' => $last]);
    }

    /**
     * The generic filter. `$getId($doc, $i)` reads a candidate's id (null or empty: positional `doc#i`) and `$getAcls($doc)` its ACL
     * entries (anything that is not a list or entry yields none); either throwing marks the document unreadable and drops it.
     *
     * @param \Closure(mixed, int): mixed $getId
     * @param \Closure(mixed): mixed $getAcls
     * @return array{documents: list<mixed>, decision: Obj}
     */
    public static function filter(mixed $principalInput, mixed $candidates, mixed $policy, \Closure $getId, \Closure $getAcls): array
    {
        $principal = self::toPrincipal($principalInput) ?? Obj::of(['id' => '']);
        $compiled = self::compilePolicy($policy);
        $list = self::isList($candidates) ? $candidates : [];
        $documents = $decisions = $allowedIds = $droppedIds = $allowedIndexes = [];
        $seen = [];
        foreach ($list as $i => $doc) {
            try {
                $rawId = $getId($doc, $i);
                $docAcls = self::aclArray($getAcls($doc));
            } catch (\Throwable) {
                $fid = "doc#$i"; // metadata that cannot even be read is unknown: fail closed
                $decisions[] = Obj::of(['id' => $fid, 'allowed' => false, 'reason' => 'unreadable document metadata (fail closed)']);
                $droppedIds[] = $fid;
                continue;
            }
            $docId = self::nonEmpty($rawId) ? $rawId : "doc#$i";
            if (isset($seen['k' . $docId])) {
                $docId = "$docId#dup$i"; // two candidates with one id must stay distinguishable
            }
            $seen['k' . $docId] = true;
            $d = self::decideDocument($docId, $docAcls, $principal, $compiled);
            $decisions[] = $d;
            if ($d->get('allowed') === true) {
                $documents[] = $doc;
                $allowedIds[] = $docId;
                $allowedIndexes[] = $i;
            } else {
                $droppedIds[] = $docId;
            }
        }
        $pid = $principal->get('id');
        $base = ['principal' => is_string($pid) ? $pid : '', 'considered' => count($list), 'allowedIds' => $allowedIds, 'allowedIndexes' => $allowedIndexes,
            'droppedIds' => $droppedIds, 'policyIncomplete' => $compiled->get('incomplete') === true];
        $decision = Obj::of($base);
        $decision->set('decisions', $decisions);
        $decision->set('digest', Pca::hashCanonical(Obj::of(['v' => new Num('1'), 'kind' => 'pca-rag/filter',
            'considered' => new Num((string) $base['considered']), 'allowedIndexes' => array_map(static fn(int $n): Num => new Num((string) $n), $allowedIndexes)] + $base)));
        if ($compiled->get('report') !== null) {
            $decision->set('report', $compiled->get('report'));
        }
        return ['documents' => $documents, 'decision' => $decision];
    }

    private static function member(mixed $doc, string $key): mixed
    {
        if ($doc === null) {
            throw new \TypeError('null document');
        }
        return $doc instanceof Obj ? $doc->get($key) : null;
    }

    /** Filter JSON documents ({id, acl?, tags?} Objs) with the default readers. A null document is unreadable (dropped). @return array{documents: list<mixed>, decision: Obj} */
    public static function filterDocuments(mixed $principal, mixed $candidates, mixed $policy): array
    {
        return self::filter($principal, $candidates, $policy, static fn(mixed $d, int $i): mixed => self::member($d, 'id'),
            static fn(mixed $d): mixed => self::aclsFromMetadata(self::member($d, 'acl'), self::member($d, 'tags')));
    }

    /**
     * Wrap a generic retriever (`callable(string $query, ?int $k): list<doc>`) so every result set is filtered to what `$principal` may see BEFORE it reaches
     * the model (withPcaFilter). Returns a {@see FilteredRetriever}: `retrieve($query, $k)` and `lastDecision()` for audit. With a
     * {@see ProvenanceRecorder} in `$recorder`, every admitted document is recorded as untrusted retrieval content (a document's text can carry an injected
     * instruction); `$getId`/`$getAcls` override the document readers ({id, acl?, tags?} by default).
     */
    public static function withPcaFilter(callable $retriever, mixed $principal, mixed $policy, ?ProvenanceRecorder $recorder = null,
                                         ?\Closure $getId = null, ?\Closure $getAcls = null): FilteredRetriever
    {
        $compiled = self::compilePolicy($policy);
        return new FilteredRetriever($retriever, $principal, $compiled, $recorder,
            $getId ?? static fn(mixed $d, int $i): mixed => self::member($d, 'id'),
            $getAcls ?? static fn(mixed $d): mixed => self::aclsFromMetadata(self::member($d, 'acl'), self::member($d, 'tags')));
    }
}

/** See {@see Rag::withPcaFilter}. */
final class FilteredRetriever
{
    private ?Obj $last = null;

    /** @param \Closure(mixed,int):mixed $getId @param \Closure(mixed):mixed $getAcls */
    public function __construct(private readonly mixed $retriever, private readonly mixed $principal, private readonly mixed $policy, private readonly ?ProvenanceRecorder $recorder,
                                private readonly \Closure $getId, private readonly \Closure $getAcls)
    {
    }

    /** @return list<mixed> */
    public function retrieve(string $query, ?int $k = null): array
    {
        $docs = ($this->retriever)($query, $k);
        $res = Rag::filter($this->principal, is_array($docs) ? $docs : [], $this->policy, $this->getId, $this->getAcls);
        $this->last = $res['decision'];
        if ($this->recorder !== null) {
            foreach (array_values($res['documents']) as $i => $doc) {
                try {
                    $src = ($this->getId)($doc, $i);
                    $src = is_string($src) && $src !== '' ? $src : "doc#$i";
                } catch (\Throwable) {
                    $src = "doc#$i";
                }
                $this->recorder->retrieval($src, $doc);
            }
        }
        return $res['documents'];
    }

    public function lastDecision(): ?Obj
    {
        return $this->last;
    }
}
