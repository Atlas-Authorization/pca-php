<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsEvolve.php';
require_once __DIR__ . '/ActionsRegistry.php';
require_once __DIR__ . '/Agent.php';

/**
 * Signed action packs, the producer side: shardDefs, buildPack (sort, chain to the previous version, derive and sign the evolution, shard, sign
 * the pack) and verifyUpgrade (a pack is the successor of the previous one and its signed evolution is EXACTLY the computed change). The
 * verifier half is {@see ActionsRegistry::verifyPack}. Signing is Ed25519 (the registry key suite of this SDK).
 */
final class ActionsPack
{
    public const DEFAULT_SHARD_DEFS = 512; // largest shard the builder writes by default
    public const MAX_PACK_DEFS = 4096;

    /**
     * Shard names are the resource family (`resource.type` first segment) of the defs, split in order into chunks of $max.
     *
     * @param list<Obj> $defs
     * @return list<array{name:string,defs:list<Obj>}>
     */
    public static function shardDefs(array $defs, mixed $max = null): array
    {
        $max ??= self::DEFAULT_SHARD_DEFS;
        $m = Js::num($max);
        if (is_bool($max) || $m === null || fmod($m, 1.0) != 0.0 || $m < 1) {
            throw new ActionKitError('bad_shard_size', 'the shard size must be a positive integer');
        }
        $max = (int)$m;
        $fam = [];
        foreach ($defs as $d) {
            $fam[explode('.', $d->get('resource')->get('type'))[0]][] = $d;
        }
        $names = array_map('strval', array_keys($fam));
        usort($names, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        $out = [];
        foreach ($names as $f) {
            $lst = $fam[$f] ?? $fam[(int)$f];
            $n = 1;
            for ($i = 0; $i < count($lst); $i += $max) {
                $out[] = ['name' => count($lst) > $max ? "$f-$n" : $f, 'defs' => array_slice($lst, $i, $max)];
                $n++;
            }
        }
        return $out;
    }

    /**
     * Build, chain and sign a pack: {pack, shards}. $prev is {pack, shards?} (the previous signed pack and its shard documents): it chains `prev` and
     * derives the signed evolution. $shard (true, or {max?, uri?}) shards the pack (always above MAX_PACK_DEFS defs). Throws ActionKitError on any
     * inconsistency.
     *
     * @param list<Obj> $defs
     * @return array{pack:Obj,shards:Obj}
     */
    public static function buildPack(string $ns, string $version, string $stability, array $defs, Obj $source, string $kid, string $secret,
        ?array $reg = null, ?Obj $prev = null, mixed $shard = null, ?\Closure $verifier = null): array
    {
        $reg ??= Actions::coreRegistry();
        $ds = $defs;
        usort($ds, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        $de = ActionsRegistry::defsError($ds);
        if ($de !== null) {
            throw new ActionKitError('bad_pack', $de);
        }
        if (count($ds) === 0) {
            throw new ActionKitError('empty_pack', 'a pack has at least one def');
        }
        $prevDefs = $prev !== null ? ActionsRegistry::packDefs($prev->get('pack'), $prev->get('shards')) : [];
        if ($prev !== null) {
            if ($prev->get('pack')->get('ns') !== $ns) {
                throw new ActionKitError('bad_chain', 'the previous pack is of another namespace');
            }
            if (ActionsRegistry::compareVersions($version, $prev->get('pack')->get('version')) <= 0) {
                throw new ActionKitError('bad_chain', 'the version must increase');
            }
        }
        $evolution = ActionsEvolve::signEvolution(ActionsEvolve::evolutionRecords($ns, $prevDefs, $ds, $reg, $verifier), $kid, $secret);
        $root = Actions::packRoot(array_map([Actions::class, 'defDigest'], $ds));
        $wantShards = ($shard !== null && $shard !== false) || count($ds) > self::MAX_PACK_DEFS;
        $shards = new Obj();
        $body = $ds;
        if ($wantShards) {
            $opts = $shard instanceof Obj ? $shard : new Obj();
            $refs = [];
            foreach (self::shardDefs($ds, $opts->get('max')) as $s) {
                $doc = Obj::of(['v' => new Num('1'), 'kind' => ActionsRegistry::PACK_SHARD_KIND, 'ns' => $ns, 'version' => $version, 'name' => $s['name'], 'defs' => $s['defs']]);
                $shards->set($s['name'], $doc);
                $uri = $opts->get('uri') instanceof \Closure ? ($opts->get('uri'))($s['name']) : 'shards/' . $s['name'] . '.json';
                $refs[] = Obj::of(['name' => $s['name'], 'digest' => ActionsRegistry::shardDigest($doc), 'uri' => $uri]);
            }
            $body = Obj::of(['shards' => $refs]);
        }
        $unsigned = Obj::of(['v' => new Num('1'), 'kind' => Actions::ACTION_PACK_KIND, 'ns' => $ns, 'version' => $version, 'stability' => $stability,
            'traits_digest' => Actions::traitsDigest($reg), 'roles_digest' => Actions::tablesDigest(), 'rules_digest' => ActionsRegistry::rulesDigest(), 'root' => $root,
            'defs' => $body, 'source' => $source, 'prev' => $prev !== null ? ActionsRegistry::packDigest($prev->get('pack')) : null, 'evolution' => $evolution]);
        $pe = ActionsRegistry::packShapeError($unsigned, false);
        if ($pe !== null) {
            throw new ActionKitError('bad_pack', $pe);
        }
        $sig = Obj::of(['alg' => 'ed25519', 'kid' => $kid, 'value' => Pca::b64u((new KeyPair($secret))->sign(ActionsRegistry::PACK_SIG_DOMAIN . Json::canonicalizeNative($unsigned)))]);
        $pack = $unsigned->without();
        $pack->set('sig', $sig);
        return ['pack' => $pack, 'shards' => $shards];
    }

    /**
     * Verify $next as the successor of $prev: both verify, same namespace, `next.prev` is `prev`'s digest, the version increases and the signed
     * evolution is EXACTLY the computed change (a registry cannot sign `narrow` for a widening def).
     *
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyUpgrade(mixed $prev, mixed $next, mixed $keys, mixed $prevShards = null, mixed $shards = null, ?array $reg = null, ?\Closure $verifier = null): array
    {
        $a = ActionsRegistry::verifyPack($prev, $keys, $prevShards);
        if (!$a['ok']) {
            return ['ok' => false, 'reason' => 'previous pack: ' . $a['reason']];
        }
        $b = ActionsRegistry::verifyPack($next, $keys, $shards);
        if (!$b['ok']) {
            return ['ok' => false, 'reason' => 'pack: ' . $b['reason']];
        }
        if ($next->get('ns') !== $prev->get('ns')) {
            return ['ok' => false, 'reason' => 'the packs are of different namespaces'];
        }
        if ($next->get('prev') !== $a['digest']) {
            return ['ok' => false, 'reason' => 'chain gap: prev does not name the previous pack'];
        }
        if (ActionsRegistry::compareVersions($next->get('version'), $prev->get('version')) <= 0) {
            return ['ok' => false, 'reason' => 'the version does not increase'];
        }
        $ee = ActionsEvolve::evolutionError($next->get('ns'), $a['defs'], $b['defs'], $next->get('evolution'), $keys, $reg ?? Actions::coreRegistry(), $verifier);
        return $ee === null ? ['ok' => true] : ['ok' => false, 'reason' => $ee];
    }
}
