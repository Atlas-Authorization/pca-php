<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsDerive.php';
require_once __DIR__ . '/ActionsLint.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';

/**
 * `pca actions build|sign` as pure functions (native port of build.ts of the reference actions package): from defs to the unsigned schema, the
 * pack, policy cards, ontology fragment, MCP tool map and generated TypeScript declarations, plus pack signing and the consistency check.
 */
final class ActionsBuild
{
    public const MAX_PACK_DEFS = 4096;
    public const PACK_SIGN_DOMAIN = Actions::PACK_DIGEST_DOMAIN . "\0";
    private const IDENT_RE = '/\A[A-Za-z_][A-Za-z0-9_]*\z/';

    /**
     * Every output of a build. Throws on a pack above the unsharded limit, a duplicate verb or a unit conflict (never a partial build).
     * $cfg: {ns, version, stability, site, aud}.
     *
     * @param list<Obj> $defsIn
     */
    public static function buildArtifacts(array $defsIn, Obj $cfg, array $reg, ?\Closure $verifier = null): Obj
    {
        $defs = $defsIn;
        usort($defs, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        if (count($defs) > self::MAX_PACK_DEFS) {
            throw new \InvalidArgumentException('a pack above ' . self::MAX_PACK_DEFS . ' defs must be sharded (' . count($defs) . ' given)');
        }
        for ($i = 1; $i < count($defs); $i++) {
            if ($defs[$i]->get('verb') === $defs[$i - 1]->get('verb')) {
                throw new \InvalidArgumentException("verb '" . $defs[$i]->get('verb') . "' appears twice");
            }
        }
        if (!$defs) {
            throw new ActionKitError('empty_pack', 'a pack has at least one def');
        }
        $root = Actions::packRoot(array_map([Actions::class, 'defDigest'], $defs));
        $schema = ActionsDerive::toSchemaDoc($defs, $reg, Obj::of(['site' => $cfg->get('site'), 'aud' => $cfg->get('aud'), 'version' => $cfg->get('version'),
            'pack' => Obj::of(['ns' => $cfg->get('ns'), 'version' => $cfg->get('version'), 'root' => $root])]), $verifier);
        $pack = Obj::of(['v' => new Num('1'), 'kind' => 'pca-action-pack', 'ns' => $cfg->get('ns'), 'version' => $cfg->get('version'), 'stability' => $cfg->get('stability'),
            'traits_digest' => Actions::traitsDigest($reg), 'roles_digest' => Actions::tablesDigest(), 'rules_digest' => ActionsLint::lintRulesDigest(), 'root' => $root,
            'defs' => $defs, 'prev' => null, 'evolution' => []]);
        $cards = array_map(static fn(Obj $d): Obj => ActionsDerive::cardOf($d, ActionsDerive::effectiveWith($d, $reg, $verifier), $reg), $defs);
        $tools = new Obj();
        foreach ($defs as $d) {
            $b = $d->get('bindings');
            $mcp = $b instanceof Obj ? $b->get('mcp') : null;
            if ($mcp !== null) {
                $tools->set($mcp->get('tool'), Obj::of(['verb' => $d->get('verb'), 'annotations' => ActionsDerive::mcpAnnotationsOf($d, ActionsDerive::effectiveWith($d, $reg, $verifier))]));
            }
        }
        return Obj::of(['schema' => $schema, 'pack' => $pack, 'cards' => $cards, 'ontology' => ActionsDerive::toOntology($defs, $reg, $verifier),
            'mcp' => Obj::of(['tools' => $tools]), 'types' => self::generateTypes($defs)]);
    }

    /**
     * The ToolActionMap of the defs' MCP bindings: tool name and arguments to {verb, resource}, or null.
     *
     * @param list<Obj> $defs
     * @return \Closure(string,mixed):?array
     */
    public static function toolActionMapOf(array $defs): \Closure
    {
        $m = [];
        foreach ($defs as $d) {
            $b = $d->get('bindings');
            $mcp = $b instanceof Obj ? $b->get('mcp') : null;
            if ($mcp !== null) {
                $m[$mcp->get('tool')] = $d;
            }
        }
        return static function (string $tool, mixed $args) use ($m): ?array {
            $d = $m[$tool] ?? null;
            if ($d === null) {
                return null;
            }
            $r = ActionsDerive::operationOf($d, Obj::of(['params' => $args]));
            return $r['ok'] ? ['verb' => $r['op']->get('verb'), 'resource' => $r['op']->get('resource')] : null;
        };
    }

    // ---- generated types ---------------------------------------------------------------------------------------------------

    private static function pascal(string $s): string
    {
        return implode('', array_map(static fn(string $x): string => ucfirst($x), preg_split('/[._]/', $s)));
    }

    private static function key(string $k): string
    {
        return preg_match(self::IDENT_RE, $k) === 1 ? $k : Json::lenientStr($k);
    }

    private static function tsType(Obj $p): string
    {
        $t = $p->get('type');
        if ($t === 'integer' || $t === 'duration') {
            return 'number';
        }
        if ($t === 'boolean') {
            return 'boolean';
        }
        if ($t === 'set') {
            return 'Array<' . (implode(' | ', array_map([Json::class, 'lenientStr'], $p->get('values') ?? [])) ?: 'string') . '>';
        }
        if ($t === 'array') {
            return $p->get('items') === 'integer' ? 'number[]' : 'string[]';
        }
        return $p->get('values') !== null ? implode(' | ', array_map([Json::class, 'lenientStr'], $p->get('values'))) : 'string';
    }

    /** @param array{kids:array<string,array>,leaf?:Obj} $n */
    private static function render(array $n, string $indent): string
    {
        $lines = [];
        $ks = array_map('strval', array_keys($n['kids']));
        usort($ks, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
        foreach ($ks as $k) {
            $c = $n['kids'][$k];
            if (isset($c['leaf'])) {
                $lines[] = $indent . self::key($k) . ($c['leaf']->get('required') === false ? '?' : '') . ': ' . self::tsType($c['leaf']) . ';';
            } else {
                $lines[] = $indent . self::key($k) . ": {\n" . self::render($c, $indent . '  ') . "\n$indent};";
            }
        }
        return implode("\n", $lines);
    }

    /**
     * TypeScript declarations for typed call sites: one params interface per verb, ActionParams and ActionVerb.
     *
     * @param list<Obj> $defs
     */
    public static function generateTypes(array $defs): string
    {
        $out = ['// Generated by `pca actions build`. Do not edit.', ''];
        $names = [];
        usort($defs, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        foreach ($defs as $d) {
            $root = ['kids' => []];
            $pn = $d->get('params')->keys();
            usort($pn, static fn(string $a, string $b): int => Actions::u16Order($a, $b));
            foreach ($pn as $name) {
                $segs = explode('.', $name);
                $n = &$root;
                foreach ($segs as $i => $s) {
                    if (!isset($n['kids'][$s])) {
                        $n['kids'][$s] = ['kids' => []];
                    }
                    $n = &$n['kids'][$s];
                    if ($i === count($segs) - 1) {
                        $n['leaf'] = $d->get('params')->get($name);
                    }
                }
                unset($n);
            }
            $iface = self::pascal($d->get('verb')) . 'Params';
            $names[] = '  ' . Json::lenientStr($d->get('verb')) . ": $iface;";
            array_push($out, "export interface $iface {", self::render($root, '  '), '}', '');
        }
        $out = array_merge($out, ['export interface ActionParams {'], $names, ['}', '', 'export type ActionVerb = keyof ActionParams;', '']);
        return implode("\n", $out);
    }

    // ---- pack signing and consistency --------------------------------------------------------------------------------------

    private static function packMessage(Obj $p): string
    {
        return self::PACK_SIGN_DOMAIN . Json::canonicalizeNative($p);
    }

    /** Null when the pack is internally consistent: every def valid and unique, the Merkle root and digests recomputed. */
    public static function packConsistencyError(mixed $p, array $reg): ?string
    {
        try {
            if (!($p instanceof Obj)) {
                return 'the pack must be an object';
            }
            if ($p->get('kind') !== 'pca-action-pack' || !Js::isNum($p->get('v')) || Js::num($p->get('v')) != 1) {
                return 'not a pca-action-pack v1';
            }
            $defs = $p->get('defs');
            if (!is_array($defs) || !array_is_list($defs) || count($defs) > self::MAX_PACK_DEFS) {
                return 'defs must be a list within the unsharded limit';
            }
            $seen = [];
            foreach ($defs as $d) {
                $e = Actions::validateDef($d);
                if ($e !== null) {
                    return 'def ' . ($d instanceof Obj && $d->has('verb') ? IntentWb::jsStr($d->get('verb')) : '?') . ": $e";
                }
                if (isset($seen[$d->get('verb')])) {
                    return "verb '" . $d->get('verb') . "' is defined twice";
                }
                $seen[$d->get('verb')] = true;
            }
            if ($p->get('root') !== Actions::packRoot(array_map([Actions::class, 'defDigest'], $defs))) {
                return 'the pack root does not match its defs';
            }
            if ($p->get('traits_digest') !== Actions::traitsDigest($reg)) {
                return 'traits_digest does not match the trait registry';
            }
            return null;
        } catch (\Throwable $e) {
            return 'malformed pack: ' . $e->getMessage();
        }
    }

    /** Sign a pack as the registry (Ed25519, 32-byte secret). Refuses an inconsistent pack. */
    public static function signPack(Obj $pack, string $kid, string $secret, array $reg): Obj
    {
        $bad = self::packConsistencyError($pack, $reg);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signPack: $bad");
        }
        $body = $pack->without('sig');
        $out = $body->without();
        $out->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => $kid, 'value' => Pca::b64u((new KeyPair($secret))->sign(self::packMessage($body)))]));
        return $out;
    }

    /** The registry key entry of a signing secret. */
    public static function packKeyOf(string $kid, string $secret): Obj
    {
        return Obj::of(['kid' => $kid, 'alg' => 'ed25519', 'pk' => (new KeyPair($secret))->public]);
    }

    /**
     * Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never throws.
     *
     * @return array{ok:bool,reason?:string}
     */
    public static function verifySignedPack(mixed $pack, mixed $keys, array $reg): array
    {
        try {
            $bad = self::packConsistencyError($pack, $reg);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => $bad];
            }
            $sig = $pack->get('sig');
            $body = $pack->without('sig');
            if (!($sig instanceof Obj) || $sig->get('alg') !== 'ed25519' || !is_string($sig->get('kid')) || !is_string($sig->get('value'))) {
                return ['ok' => false, 'reason' => 'missing or malformed signature'];
            }
            $k = null;
            foreach ($keys as $x) {
                if ($x->get('kid') === $sig->get('kid')) {
                    $k = $x;
                    break;
                }
            }
            if ($k === null) {
                return ['ok' => false, 'reason' => "no registry key with kid '" . $sig->get('kid') . "'"];
            }
            if ($k->get('alg') !== 'ed25519' || !is_string($k->get('pk')) || Pca::unb64u($k->get('pk'), 32) === null) {
                return ['ok' => false, 'reason' => 'the registry key entry is malformed'];
            }
            return Pca::verifyEd25519B64u($k->get('pk'), self::packMessage($body), $sig->get('value')) ? ['ok' => true] : ['ok' => false, 'reason' => 'pack signature invalid'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'pack verification error: ' . $e->getMessage()];
        }
    }
}
