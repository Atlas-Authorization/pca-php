<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Revoke.php';

/**
 * Key rotation and subtree revocation for capability chains. A chain binds authority to keys, so rotating or losing a key means
 * re-issuing what it carried under a fresh key and naming the old one in a revocation record a registry can act on. Re-issue uses
 * the real builders ({@see Sign::mintRoot} / {@see Sign::delegate}) and carries exactly the caveats each replaced hop carried, so a
 * re-issue can never widen authority.
 *
 * Chains are lists of capability Obj; keys are {@see KeyPair}; options are an Obj or an assoc array with the reference's names
 * (a present-but-null `now` is refused, as in the reference). Revocation records are assoc arrays. Every refusal throws.
 */
final class Rotate
{
    private static function pub(mixed $secret): string
    {
        if (!($secret instanceof KeyPair)) {
            throw new \TypeError('expected a KeyPair secret key');
        }
        return $secret->public;
    }

    /** A hop of the supported shape (stricter than the reference, which would pass odd shapes through). */
    private static function hop(mixed $c, string $ctx): Obj
    {
        if (!($c instanceof Obj)) {
            throw new \TypeError("$ctx: a chain hop is not an object");
        }
        $id = $c->get('id');
        if (!is_string($id) || $id === '' || !is_string($c->get('issuer')) || !is_string($c->get('holder'))
            || !is_array($c->get('caveats')) || !array_is_list($c->get('caveats'))) {
            throw new \TypeError("$ctx: malformed capability");
        }
        return $c;
    }

    /** @return list<Obj> the validated chain */
    private static function chain(mixed $chain, string $ctx): array
    {
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            throw new \InvalidArgumentException("$ctx: empty chain");
        }
        return array_map(static fn($c) => self::hop($c, $ctx), $chain);
    }

    /** The caveats a child appended beyond its parent (append-only, so re-delegating with this slice reproduces it). */
    private static function appended(Obj $parent, Obj $child): array
    {
        $pc = $parent->get('caveats');
        $cc = $child->get('caveats');
        if (count($cc) < count($pc)) {
            throw new \InvalidArgumentException('malformed chain: a child carries fewer caveats than its parent (not an attenuation)');
        }
        return array_slice($cc, count($pc));
    }

    /** The clock: absent = now; present must be a finite number (null is refused). */
    private static function now(mixed $o, string $ctx): mixed
    {
        if (!Js::has($o, 'now')) {
            return Revoke::nowMs();
        }
        $n = Js::opt($o, 'now');
        $f = Js::num($n);
        if ($f === null || !is_finite($f)) {
            throw new \TypeError("$ctx: now must be a finite number");
        }
        return $f == 0.0 ? 0 : $n; // -0 prints as 0
    }

    private static function reason(mixed $o, string $dflt): string
    {
        $r = Js::opt($o, 'reason');
        if ($r !== null && !is_string($r)) {
            throw new \TypeError('reason must be a string');
        }
        return $r ?? $dflt;
    }

    /**
     * Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf, re-binding it to `newKeyPair` with the leaf's exact
     * caveats. Options: oldHolderSecret (the leaf's issuer KeyPair), newKeyPair, reason?, now?.
     *
     * @return array{chain:list<Obj>,revocation:array}
     */
    public static function rotateAgentKey(mixed $chain, mixed $opts): array
    {
        $c = self::chain($chain, 'rotateAgentKey');
        if (count($c) < 2) {
            throw new \InvalidArgumentException('rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey');
        }
        $parent = $c[count($c) - 2];
        $leaf = $c[count($c) - 1];
        $secret = Js::opt($opts, 'oldHolderSecret');
        if (self::pub($secret) !== $leaf->get('issuer')) {
            throw new \InvalidArgumentException("rotateAgentKey: oldHolderSecret is not the leaf's issuer; the leaf is re-signed by its parent holder (the leaf issuer)");
        }
        $new = Js::opt($opts, 'newKeyPair');
        $newHolder = self::pub($new);
        if ($newHolder === $leaf->get('holder')) {
            throw new \InvalidArgumentException('rotateAgentKey: newKeyPair is the key being rotated out');
        }
        $at = self::now($opts, 'rotateAgentKey');
        $why = self::reason($opts, 'agent key rotated');
        $newLeaf = Sign::delegate($parent, $secret, $newHolder, self::appended($parent, $leaf));
        return [
            'chain' => [...array_slice($c, 0, -1), $newLeaf],
            'revocation' => ['capId' => $leaf->get('id'), 'holder' => $leaf->get('holder'), 'issuer' => $leaf->get('issuer'),
                'capIds' => [$leaf->get('id')], 'reason' => $why, 'revokedAt' => $at],
        ];
    }

    /**
     * Rotate the PRINCIPAL (root) key by re-rooting: a fresh root under `newPrincipalKeyPair` bound to the same holder and caveats,
     * then every downstream hop re-issued (`holderSecrets`: each non-root hop's issuer KeyPair, in chain order). Options: chain (or
     * oldRoot for a root-only chain), oldPrincipalSecret, newPrincipalKeyPair, holderSecrets?, reason?, now?.
     *
     * @return array{chain:list<Obj>,revocation:array}
     */
    public static function rotatePrincipalKey(mixed $args): array
    {
        $given = Js::opt($args, 'chain');
        $oldRootArg = Js::opt($args, 'oldRoot');
        $chain = $given ?? (Js::truthy($oldRootArg) ? [$oldRootArg] : []);
        $c = self::chain($chain, 'rotatePrincipalKey');
        $oldRoot = $c[0];
        if (Js::has($oldRoot, 'parent')) {
            throw new \InvalidArgumentException('rotatePrincipalKey: chain[0] is not a root (it has a parent)');
        }
        if (self::pub(Js::opt($args, 'oldPrincipalSecret')) !== $oldRoot->get('issuer')) {
            throw new \InvalidArgumentException("rotatePrincipalKey: oldPrincipalSecret is not the root's issuer");
        }
        $secrets = Js::opt($args, 'holderSecrets') ?? [];
        if (!is_array($secrets) || !array_is_list($secrets) || count($secrets) !== count($c) - 1) {
            throw new \InvalidArgumentException('rotatePrincipalKey: expected one holderSecret per non-root hop');
        }
        $newKey = Js::opt($args, 'newPrincipalKeyPair');
        if (self::pub($newKey) === $oldRoot->get('issuer')) {
            throw new \InvalidArgumentException('rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out');
        }
        $at = self::now($args, 'rotatePrincipalKey');
        $why = self::reason($args, 'principal key rotated (re-root)');
        $new = [Sign::mintRoot($newKey, $oldRoot->get('holder'), $oldRoot->get('caveats'))];
        for ($i = 1; $i < count($c); $i++) {
            $signer = $secrets[$i - 1];
            if (self::pub($signer) !== $c[$i]->get('issuer')) {
                throw new \InvalidArgumentException("rotatePrincipalKey: holderSecret for hop $i is not that hop's issuer");
            }
            $new[] = Sign::delegate($new[$i - 1], $signer, $c[$i]->get('holder'), self::appended($c[$i - 1], $c[$i]));
        }
        return [
            'chain' => $new,
            'revocation' => ['capId' => $oldRoot->get('id'), 'issuer' => $oldRoot->get('issuer'), 'holder' => $oldRoot->get('holder'),
                'subtreeRoot' => $oldRoot->get('id'), 'capIds' => array_map(static fn(Obj $x) => $x->get('id'), $c),
                'reason' => $why, 'revokedAt' => $at],
        ];
    }

    /** First index whose holder is `$holder`, or -1 (where the compromise enters). */
    private static function indexOfHolder(array $c, mixed $holder): int
    {
        foreach ($c as $i => $x) {
            if ($x->get('holder') === $holder) {
                return $i;
            }
        }
        return -1;
    }

    /**
     * Treat `$compromisedHolder` as COMPROMISED: revoke the hop it first holds and every descendant, and re-issue one delegation from
     * the nearest safe ancestor to `newKeyPair` carrying the deepest leaf's caveats (never wider). Options: newKeyPair, ancestorSecret
     * (the safe ancestor's holder KeyPair), reason?, now?. Throws when the holder is not in the chain or is the root holder.
     *
     * @return array{chain:list<Obj>,revocation:array}
     */
    public static function revokeAndReissueSubtree(mixed $chain, mixed $compromisedHolder, mixed $opts): array
    {
        $c = self::chain($chain, 'revokeAndReissueSubtree');
        $idx = self::indexOfHolder($c, $compromisedHolder);
        if ($idx < 0) {
            throw new \InvalidArgumentException('revokeAndReissueSubtree: the holder is not in the chain');
        }
        if ($idx === 0) {
            throw new \InvalidArgumentException('revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey');
        }
        $ancestor = $c[$idx - 1];
        $subtreeRoot = $c[$idx];
        $leaf = $c[count($c) - 1];
        $secret = Js::opt($opts, 'ancestorSecret');
        if (self::pub($secret) !== $ancestor->get('holder')) {
            throw new \InvalidArgumentException("revokeAndReissueSubtree: ancestorSecret is not the safe ancestor's holder");
        }
        $newHolder = self::pub(Js::opt($opts, 'newKeyPair'));
        foreach (array_slice($c, $idx) as $x) {
            if ($x->get('holder') === $newHolder) {
                throw new \InvalidArgumentException('revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree');
            }
        }
        $at = self::now($opts, 'revokeAndReissueSubtree');
        $why = self::reason($opts, 'delegation subtree compromised');
        $newHop = Sign::delegate($ancestor, $secret, $newHolder, self::appended($ancestor, $leaf));
        return [
            'chain' => [...array_slice($c, 0, $idx), $newHop],
            'revocation' => ['capId' => $subtreeRoot->get('id'), 'holder' => $compromisedHolder, 'issuer' => $subtreeRoot->get('issuer'),
                'subtreeRoot' => $subtreeRoot->get('id'), 'capIds' => array_map(static fn(Obj $x) => $x->get('id'), array_slice($c, $idx)),
                'reason' => $why, 'revokedAt' => $at],
        ];
    }

    /**
     * {@see revokeAndReissueSubtree} end to end: one revocation record PER capability in the compromised subtree (root to leaf) plus
     * the re-issued chain.
     *
     * @return array{revocations:list<array>,reissued:list<Obj>}
     */
    public static function compromisedKeyFlow(mixed $chain, mixed $compromisedHolder, mixed $opts): array
    {
        $c = self::chain($chain, 'compromisedKeyFlow');
        $idx = self::indexOfHolder($c, $compromisedHolder);
        if ($idx < 0) {
            throw new \InvalidArgumentException('compromisedKeyFlow: the holder is not in the chain');
        }
        $r = self::revokeAndReissueSubtree($c, $compromisedHolder, $opts);
        $at = $r['revocation']['revokedAt'];
        $why = $r['revocation']['reason'];
        $root = $c[$idx]->get('id');
        return [
            'revocations' => array_map(static fn(Obj $x) => ['capId' => $x->get('id'), 'holder' => $x->get('holder'), 'issuer' => $x->get('issuer'),
                'subtreeRoot' => $root, 'capIds' => [$x->get('id')], 'reason' => $why, 'revokedAt' => $at], array_slice($c, $idx)),
            'reissued' => $r['chain'],
        ];
    }

    /**
     * Revoke what a rotation replaced, all or nothing. `$sink` has revoke($input), unrevoke($key) and lookup($kind, $value) (a
     * {@see RevocationRegistry} fits). Every capability id the record(s) cover is revoked; if any revoke throws, the ones this call
     * added are removed again and the error is rethrown. Only capability ids are revoked (revoking the old holder key would deny the
     * re-issued chain). Refuses, before touching the sink, a record naming no capability id and a re-issued chain sharing an id with
     * what is being revoked. Returns the revoked ids.
     *
     * @return list<string>
     */
    public static function applyRotation(object $sink, mixed $records, mixed $reissued = null): array
    {
        $list = is_array($records) && array_is_list($records) ? $records : [$records];
        $todo = []; // 'k'.id => [id, record]; a PHP key would coerce a numeric id
        foreach ($list as $r) {
            if (!Js::isObj($r)) {
                throw new \TypeError('applyRotation: a record is not an object');
            }
            $ids = Js::opt($r, 'capIds');
            if ($ids === null) {
                $ids = Js::has($r, 'capId') ? [Js::opt($r, 'capId')] : [];
            } elseif (!is_array($ids) || !array_is_list($ids)) {
                throw new \TypeError('applyRotation: capIds must be a list');
            }
            foreach ($ids as $id) {
                if (!is_string($id) || $id === '') {
                    throw new \TypeError('applyRotation: a record names an invalid capability id');
                }
                $todo['k' . $id] ??= [$id, $r];
            }
        }
        if ($todo === []) {
            throw new \InvalidArgumentException('applyRotation: the record names no capability to revoke');
        }
        if ($reissued !== null && (!is_array($reissued) || !array_is_list($reissued))) {
            throw new \TypeError('applyRotation: reissued must be a chain');
        }
        foreach ($reissued ?? [] as $x) {
            if (!($x instanceof Obj)) {
                throw new \TypeError('applyRotation: a re-issued hop is not an object');
            }
            $kept = $x->get('id');
            if (is_string($kept) && isset($todo['k' . $kept])) {
                throw new \InvalidArgumentException('applyRotation: the re-issued chain contains a capability that is being revoked');
            }
        }
        $added = [];
        try {
            foreach ($todo as [$id, $r]) {
                if ($sink->lookup('cap', $id) === null) {
                    $added[] = $id;
                }
                $sink->revoke(['kind' => 'cap', 'value' => $id, 'reason' => Js::opt($r, 'reason'), 'revokedAt' => Js::opt($r, 'revokedAt')]);
            }
        } catch (\Throwable $e) {
            foreach ($added as $id) {
                try {
                    $sink->unrevoke(['kind' => 'cap', 'value' => $id]);
                } catch (\Throwable) {
                    // best effort: the original failure is the one to report
                }
            }
            throw $e;
        }
        return array_map(static fn(array $t) => $t[0], array_values($todo));
    }
}
