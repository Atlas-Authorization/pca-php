<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * Cross-domain mesh proofs (the agent mesh, `verifyMeshProof` of the reference). A mesh proof carries a capability chain, one
 * witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action.
 * {@see Mesh::verify} checks all of it offline and returns the reference's reason and failing hop (`hop` is -1 when none is
 * named). Total: any malformed input is a verdict, never an exception. Scope: everything the reference verifier does, including
 * RFC 9162 consistency proofs from a pinned head; the witness side (cosigning, head publication) is not here.
 * Inputs are the library's JSON values (Obj, lists, strings, Num).
 */
final class Mesh
{
    public const HEAD_DOMAIN = "atlas-pca/mesh-head/v1\0";
    public const COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\0";
    public const BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\0";
    public const ACTION_DOMAIN = "atlas-pca/mesh-action/v1\0";
    private const DEFAULT_MAX_HEAD_AGE_MS = 300_000;
    private const DEFAULT_MAX_SKEW_MS = 60_000;
    private const DEFAULT_MAX_CHAIN = 64;
    private const MAX_COSIGS = 256;
    private const MAX_PATH = 128;
    private const MAX_SAFE = 9007199254740991;

    // ---- value helpers ---------------------------------------------------------------------------------------------

    private static function f(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    private static function num(mixed $x): bool
    {
        return self::f($x) !== null;
    }

    /** A non-negative safe integer. */
    private static function nat(mixed $x): bool
    {
        $v = self::f($x);
        return $v !== null && floor($v) === $v && $v >= 0 && $v <= self::MAX_SAFE;
    }

    private static function natV(mixed $x): int
    {
        return (int)self::f($x);
    }

    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    private static function list(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** @return list<string>|null */
    private static function strings(mixed $v): ?array
    {
        if (!self::list($v)) {
            return null;
        }
        foreach ($v as $x) {
            if (!is_string($x)) {
                return null;
            }
        }
        return $v;
    }

    private static function msg(string $domain, mixed $body): ?string
    {
        try {
            return $domain . Json::canonicalizeStrict($body);
        } catch (\Throwable) {
            return null;
        }
    }

    private static function verifySig(mixed $pub, string $msg, mixed $sig): bool
    {
        return is_string($pub) && is_string($sig) && Pca::verifyEd25519B64u($pub, $msg, $sig);
    }

    private static function fail(string $reason, int $hop = -1): array
    {
        return ['ok' => false, 'reason' => $reason, 'hop' => $hop];
    }

    private static function validHead(mixed $h): bool
    {
        if (!($h instanceof Obj) || !is_string($h->get('domain')) || !is_string($h->get('root')) || !is_string($h->get('rev_root'))) {
            return false;
        }
        if (!self::nat($h->get('size')) || !self::nat($h->get('rev_size')) || !self::num($h->get('timestamp'))) {
            return false;
        }
        return (self::natV($h->get('size')) === 0) === ($h->get('root') === '');
    }

    private static function validConsistency(mixed $c): bool
    {
        if (!($c instanceof Obj) || !self::nat($c->get('oldSize')) || !self::nat($c->get('newSize'))) {
            return false;
        }
        $path = $c->get('path');
        if (!self::list($path) || count($path) > self::MAX_PATH) {
            return false;
        }
        foreach ($path as $p) {
            if (!is_string($p)) {
                return false;
            }
        }
        return true;
    }

    private static function validInclusion(mixed $i): bool
    {
        if (!($i instanceof Obj) || !self::nat($i->get('index')) || !self::nat($i->get('size'))) {
            return false;
        }
        $path = $i->get('path');
        return self::list($path) && count($path) <= self::MAX_PATH;
    }

    private static function validAction(mixed $a): bool
    {
        if (!($a instanceof Obj)) {
            return false;
        }
        foreach (['type', 'resource', 'service_domain', 'nonce'] as $k) {
            if (!is_string($a->get($k))) {
                return false;
            }
        }
        if (!self::num($a->get('at'))) {
            return false;
        }
        return !$a->has('amount') || self::num($a->get('amount'));
    }

    // ---- effective authority -----------------------------------------------------------------------------------------

    /** @return list<string> */
    private static function intersect(bool $have, array $a, array $b): array
    {
        if (!$have) {
            $out = array_values(array_unique($b));
            usort($out, 'strcmp');
            return $out;
        }
        $out = [];
        foreach ($a as $x) {
            if (in_array($x, $b, true)) {
                $out[] = $x;
            }
        }
        return $out;
    }

    private static function min(bool $have, float $cur, float $v): float
    {
        return $have ? min($cur, $v) : $v;
    }

    /** The conjunction of the caveats (effectiveAuthority); an unknown or malformed caveat is an error. @return array{0: array, 1: string} */
    private static function effective(mixed $caveats): array
    {
        $e = ['actions' => [], 'hasAct' => false, 'prefixes' => [], 'maxAmount' => 0.0, 'hasAmount' => false, 'expiresAt' => 0.0,
            'hasExp' => false, 'audience' => [], 'hasAud' => false, 'maxHops' => 0.0, 'hasHops' => false];
        if (!self::list($caveats)) {
            return [$e, 'malformed proof'];
        }
        foreach ($caveats as $c) {
            if (!($c instanceof Obj)) {
                return [$e, 'malformed proof'];
            }
            $t = is_string($c->get('type')) ? $c->get('type') : '';
            switch ($t) {
                case 'scope':
                    $a = self::strings($c->get('actions'));
                    if ($a === null) {
                        return [$e, 'malformed scope caveat'];
                    }
                    $e['actions'] = self::intersect($e['hasAct'], $e['actions'], $a);
                    $e['hasAct'] = true;
                    break;
                case 'resource':
                    if (!is_string($c->get('prefix'))) {
                        return [$e, 'malformed resource caveat'];
                    }
                    $e['prefixes'][] = $c->get('prefix');
                    break;
                case 'max_amount':
                    if (!self::num($c->get('max'))) {
                        return [$e, 'malformed max_amount caveat'];
                    }
                    $e['maxAmount'] = self::min($e['hasAmount'], $e['maxAmount'], (float)self::f($c->get('max')));
                    $e['hasAmount'] = true;
                    break;
                case 'expires':
                    if (!self::num($c->get('at'))) {
                        return [$e, 'malformed expires caveat'];
                    }
                    $e['expiresAt'] = self::min($e['hasExp'], $e['expiresAt'], (float)self::f($c->get('at')));
                    $e['hasExp'] = true;
                    break;
                case 'audience':
                    $d = self::strings($c->get('domains'));
                    if ($d === null) {
                        return [$e, 'malformed audience caveat'];
                    }
                    $e['audience'] = self::intersect($e['hasAud'], $e['audience'], $d);
                    $e['hasAud'] = true;
                    break;
                case 'max_hops':
                    if (!self::num($c->get('n'))) {
                        return [$e, 'malformed max_hops caveat'];
                    }
                    $e['maxHops'] = self::min($e['hasHops'], $e['maxHops'], (float)self::f($c->get('n')));
                    $e['hasHops'] = true;
                    break;
                default:
                    return [$e, 'unknown caveat type "' . ($c->has('type') ? IntentWb::jsStr($c->get('type')) : 'undefined') . '" (fail closed)'];
            }
        }
        return [$e, ''];
    }

    private static function subset(array $child, array $parent): bool
    {
        foreach ($child as $c) {
            if (!in_array($c, $parent, true)) {
                return false;
            }
        }
        return true;
    }

    private static function narrows(array $child, array $parent): bool
    {
        if ($parent['hasAct'] && (!$child['hasAct'] || !self::subset($child['actions'], $parent['actions']))) {
            return false;
        }
        if ($parent['hasAud'] && (!$child['hasAud'] || !self::subset($child['audience'], $parent['audience']))) {
            return false;
        }
        if ($parent['hasAmount'] && (!$child['hasAmount'] || $child['maxAmount'] > $parent['maxAmount'])) {
            return false;
        }
        if ($parent['hasExp'] && (!$child['hasExp'] || $child['expiresAt'] > $parent['expiresAt'])) {
            return false;
        }
        if ($parent['hasHops'] && (!$child['hasHops'] || $child['maxHops'] > $parent['maxHops'])) {
            return false;
        }
        return self::subset($parent['prefixes'], $child['prefixes']);
    }

    /** '' when the effective authority admits the action, else why not. */
    private static function admits(array $e, Obj $a, float $now, int $chainLen): string
    {
        $typ = is_string($a->get('type')) ? $a->get('type') : '';
        $res = is_string($a->get('resource')) ? $a->get('resource') : '';
        $svc = is_string($a->get('service_domain')) ? $a->get('service_domain') : '';
        if ($e['hasAct'] && !self::subset([$typ], $e['actions'])) {
            return "action \"$typ\" not in scope";
        }
        foreach ($e['prefixes'] as $p) {
            if (!str_starts_with($res, $p)) {
                return "resource \"$res\" outside prefix \"$p\"";
            }
        }
        if ($e['hasAmount']) {
            $amt = $a->get('amount');
            if (!$a->has('amount') || (float)self::f($amt) > $e['maxAmount']) {
                return 'amount exceeds ceiling ' . IntentWb::jsNumStr($e['maxAmount']);
            }
        }
        if ($e['hasExp'] && $now > $e['expiresAt']) {
            return 'capability expired';
        }
        if ($e['hasAud'] && !self::subset([$svc], $e['audience'])) {
            return 'service domain not in audience';
        }
        if ($e['hasHops'] && (float)$chainLen > $e['maxHops']) {
            return 'chain exceeds max_hops ' . IntentWb::jsNumStr($e['maxHops']);
        }
        return '';
    }

    // ---- revocation sets and Merkle proofs ----------------------------------------------------------------------------

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    private static function revNodeHash(string $l, string $r): string
    {
        return self::sha("\x01" . $l . $r);
    }

    private static function bindRevRoot(int $size, string $tree): ?string
    {
        $tail = self::msg('', Obj::of(['size' => new Num((string)$size), 'tree' => $tree]));
        return $tail === null ? null : Pca::b64u(self::sha(IntentV2::REVSET_DOMAIN . $tail));
    }

    private static function emptyRevTree(): string
    {
        return Pca::b64u(self::sha(''));
    }

    private static function leafOk(string $root, int $size, string $id, mixed $proof): bool
    {
        if (!($proof instanceof Obj) || !self::nat($proof->get('size')) || !self::nat($proof->get('index'))) {
            return false;
        }
        $psize = self::natV($proof->get('size'));
        $index = self::natV($proof->get('index'));
        if ($psize !== $size || $index >= $size) {
            return false;
        }
        $sides = Pca::pathShape($index, $size);
        $path = $proof->get('path');
        if (!self::list($path) || count($path) !== count($sides)) {
            return false;
        }
        try {
            $h = self::sha("\x00" . Json::canonicalizeStrict($id));
        } catch (\Throwable) {
            return false;
        }
        foreach ($path as $i => $step) {
            if (!($step instanceof Obj)) {
                return false;
            }
            $side = $step->get('side');
            if ($side !== $sides[$i]) {
                return false;
            }
            $sib = Pca::unb64u($step->get('hash'), 32);
            if ($sib === null) {
                return false;
            }
            $h = $side === 'L' ? self::revNodeHash($sib, $h) : self::revNodeHash($h, $sib);
        }
        return self::bindRevRoot($size, Pca::b64u($h)) === $root;
    }

    /** verifyNonMembership over an expanded proof `{size, lo?, hi?}`. */
    public static function nonMembership(string $root, Obj $nm, string $id): bool
    {
        if (!self::nat($nm->get('size'))) {
            return false;
        }
        $size = self::natV($nm->get('size'));
        $lo = $nm->get('lo') instanceof Obj ? $nm->get('lo') : null;
        $hi = $nm->get('hi') instanceof Obj ? $nm->get('hi') : null;
        if ($size === 0) {
            return $lo === null && $hi === null && self::bindRevRoot(0, self::emptyRevTree()) === $root;
        }
        if ($lo === null && $hi === null) {
            return false;
        }
        $loIdx = 0;
        $hiIdx = 0;
        if ($lo !== null) {
            $loId = is_string($lo->get('id')) ? $lo->get('id') : '';
            $lp = $lo->get('proof');
            if (!($lp instanceof Obj) || !(strcmp($loId, $id) < 0) || !self::leafOk($root, $size, $loId, $lp)) {
                return false;
            }
            $loIdx = self::natV($lp->get('index'));
            if ($hi === null && $loIdx !== $size - 1) {
                return false;
            }
        }
        if ($hi !== null) {
            $hiId = is_string($hi->get('id')) ? $hi->get('id') : '';
            $hp = $hi->get('proof');
            if (!($hp instanceof Obj) || !(strcmp($id, $hiId) < 0) || !self::leafOk($root, $size, $hiId, $hp)) {
                return false;
            }
            $hiIdx = self::natV($hp->get('index'));
            if ($lo === null && $hiIdx !== 0) {
                return false;
            }
        }
        return !($lo !== null && $hi !== null && $hiIdx !== $loIdx + 1);
    }

    /** verifyLedgerConsistency (RFC 9162 section 2.1.4.2) with strict 32-byte base64url hashes. */
    private static function consistency(string $oldRoot, string $newRoot, Obj $proof): bool
    {
        if (!self::nat($proof->get('oldSize')) || !self::nat($proof->get('newSize'))) {
            return false;
        }
        $first = self::natV($proof->get('oldSize'));
        $second = self::natV($proof->get('newSize'));
        if ($first > $second) {
            return false;
        }
        $raw = self::list($proof->get('path')) ? $proof->get('path') : [];
        if (count($raw) > self::MAX_PATH) {
            return false;
        }
        $empty = self::emptyRevTree();
        if ($first === 0) {
            if ($raw !== [] || $oldRoot !== $empty) {
                return false;
            }
            return $second === 0 ? $newRoot === $empty : true;
        }
        if ($first === $second) {
            return $raw === [] && $oldRoot === $newRoot;
        }
        $path = [];
        if (($first & ($first - 1)) === 0) {
            $o = Pca::unb64u($oldRoot, 32);
            if ($o === null) {
                return false;
            }
            $path[] = $o;
        }
        foreach ($raw as $p) {
            $b = Pca::unb64u($p, 32);
            if ($b === null) {
                return false;
            }
            $path[] = $b;
        }
        if ($path === []) {
            return false;
        }
        $fn = $first - 1;
        $sn = $second - 1;
        while (($fn & 1) === 1) {
            $fn >>= 1;
            $sn >>= 1;
        }
        $fr = $sr = $path[0];
        for ($i = 1; $i < count($path); $i++) {
            $c = $path[$i];
            if ($sn === 0) {
                return false;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $fr = self::revNodeHash($c, $fr);
                $sr = self::revNodeHash($c, $sr);
                while (($fn & 1) === 0 && $fn !== 0) {
                    $fn >>= 1;
                    $sn >>= 1;
                }
            } else {
                $sr = self::revNodeHash($sr, $c);
            }
            $fn >>= 1;
            $sn >>= 1;
        }
        return $sn === 0 && Pca::b64u($fr) === $oldRoot && Pca::b64u($sr) === $newRoot;
    }

    // ---- heads -----------------------------------------------------------------------------------------------------------

    /** '' when `$next` is a legitimate successor of the pinned `$prev`, else why not. */
    private static function checkHeadAdvance(mixed $prev, mixed $next, mixed $proof): string
    {
        if (!self::validHead($prev) || !self::validHead($next)) {
            return 'malformed head';
        }
        if ($prev->get('domain') !== $next->get('domain')) {
            return 'head is for a different domain';
        }
        if (self::natV($next->get('size')) < self::natV($prev->get('size')) || self::natV($next->get('rev_size')) < self::natV($prev->get('rev_size'))) {
            return 'head rolls back';
        }
        if (self::natV($next->get('size')) === self::natV($prev->get('size'))) {
            if ($next->get('root') !== $prev->get('root')) {
                return 'equivocation (same size, different log)';
            }
        } else {
            if (!self::validConsistency($proof) || self::natV($proof->get('oldSize')) !== self::natV($prev->get('size'))
                || self::natV($proof->get('newSize')) !== self::natV($next->get('size'))) {
                return 'consistency proof required for a larger head';
            }
            if (!self::consistency($prev->get('root'), $next->get('root'), $proof)) {
                return 'head is not consistent with the previous head (fork or rewrite)';
            }
        }
        if (self::natV($next->get('rev_size')) === self::natV($prev->get('rev_size')) && $next->get('rev_root') !== $prev->get('rev_root')) {
            return 'equivocation (revocation set)';
        }
        return '';
    }

    private static function opt(Obj $t, string $k, float $def): ?float
    {
        if (!$t->has($k)) {
            return $def;
        }
        $v = self::f($t->get($k));
        return $v === null || $v < 0 ? null : $v;
    }

    /** @return array{0: ?array, 1: string} the validated trust configuration, or the refusal */
    private static function validTrust(mixed $traw): array
    {
        if (!($traw instanceof Obj)) {
            return [null, 'invalid trust configuration'];
        }
        $t = $traw;
        $human = $t->get('humanPrincipal');
        $ws = self::strings($t->get('witnesses'));
        if (!is_string($human) || $ws === null) {
            return [null, 'invalid trust configuration'];
        }
        $c = ['human' => $human, 'witnesses' => array_flip($ws)];
        $th = $t->get('threshold');
        if (!self::nat($th) || self::natV($th) < 1 || self::natV($th) > count($c['witnesses'])) {
            return [null, 'invalid trust configuration: threshold'];
        }
        $c['threshold'] = self::natV($th);
        if (!self::num($t->get('now'))) {
            return [null, 'invalid trust configuration: now'];
        }
        $c['now'] = (float)self::f($t->get('now'));
        if (($c['maxHeadAge'] = self::opt($t, 'maxHeadAgeMs', self::DEFAULT_MAX_HEAD_AGE_MS)) === null) {
            return [null, 'invalid trust configuration: maxHeadAgeMs'];
        }
        if (($c['maxSkew'] = self::opt($t, 'maxClockSkewMs', self::DEFAULT_MAX_SKEW_MS)) === null) {
            return [null, 'invalid trust configuration: maxClockSkewMs'];
        }
        $c['hasActionAge'] = false;
        $c['maxActionAge'] = 0.0;
        if ($t->has('maxActionAgeMs')) {
            if (($c['maxActionAge'] = self::opt($t, 'maxActionAgeMs', 0.0)) === null) {
                return [null, 'invalid trust configuration: maxActionAgeMs'];
            }
            $c['hasActionAge'] = true;
        }
        $c['maxChain'] = self::DEFAULT_MAX_CHAIN;
        if ($t->has('maxChainLength')) {
            $v = $t->get('maxChainLength');
            if (!self::nat($v) || self::natV($v) < 1) {
                return [null, 'invalid trust configuration: maxChainLength'];
            }
            $c['maxChain'] = self::natV($v);
        }
        $ad = self::strings($t->get('allowedDomains'));
        if ($ad === null || $ad === []) {
            return [null, 'invalid trust configuration: allowedDomains is required'];
        }
        $c['allowed'] = $ad;
        $rd = $t->get('rootDomain');
        if (!is_string($rd) || !self::subset([$rd], $ad)) {
            return [null, 'invalid trust configuration: rootDomain is required and must be in allowedDomains'];
        }
        $c['rootDomain'] = $rd;
        $c['issuerDoms'] = null;
        if ($t->has('issuerDomains')) {
            $m = $t->get('issuerDomains');
            if (!($m instanceof Obj)) {
                return [null, 'invalid trust configuration: issuerDomains'];
            }
            foreach ($m->keys() as $k) {
                if (!is_string($m->get($k))) {
                    return [null, 'invalid trust configuration: issuerDomains'];
                }
            }
            $c['issuerDoms'] = $m;
        }
        $c['pinned'] = null;
        if ($t->has('pinnedHeads')) {
            $m = $t->get('pinnedHeads');
            if (!($m instanceof Obj)) {
                return [null, 'invalid trust configuration: pinnedHeads'];
            }
            $c['pinned'] = $m;
        }
        $c['pqPins'] = [];
        if ($t->has('pqPins') && $t->get('pqPins') instanceof Obj) {
            $m = $t->get('pqPins');
            foreach ($m->keys() as $k) {
                if (is_string($m->get($k))) {
                    $c['pqPins'][$k] = $m->get($k);
                }
            }
        }
        return [$c, ''];
    }

    /** JavaScript truthiness of a decoded JSON value. */
    private static function truthy(mixed $v): bool
    {
        if ($v === null || $v === false || $v === '') {
            return false;
        }
        if ($v instanceof Num) {
            $f = $v->float();
            return $f != 0.0 && !is_nan($f);
        }
        return true;
    }

    private static function checkCosignedHead(mixed $ch, string $expectedDomain, array $t, mixed $pinProof): string
    {
        $h = self::g($ch, 'head');
        if (!($h instanceof Obj) || $h->get('domain') !== $expectedDomain) {
            return 'head is for a different domain';
        }
        if (!self::validHead($h)) {
            return 'malformed head';
        }
        $sig = $ch->get('sig');
        if (!is_string($sig)) {
            return 'malformed head';
        }
        $domain = $h->get('domain');
        $m = self::msg(self::HEAD_DOMAIN, $h);
        if ($m === null || !self::verifySig($domain, $m, $sig)) {
            return 'head not signed by its domain key';
        }
        $cosigs = $ch->get('cosigs');
        if (!self::list($cosigs) || count($cosigs) > self::MAX_COSIGS) {
            return 'malformed head';
        }
        $good = [];
        $cm = self::msg(self::COSIG_DOMAIN, $h);
        foreach ($cosigs as $c) {
            if (!($c instanceof Obj)) {
                continue;
            }
            $w = $c->get('witness');
            $s = $c->get('sig');
            if (is_string($w) && is_string($s) && isset($t['witnesses'][$w]) && !isset($good[$w]) && $cm !== null && self::verifySig($w, $cm, $s)) {
                $good[$w] = true;
            }
        }
        if (count($good) < $t['threshold']) {
            return 'head has ' . count($good) . '/' . $t['threshold'] . ' trusted witness cosignatures';
        }
        $ts = (float)self::f($h->get('timestamp'));
        if ($ts > $t['now'] + $t['maxSkew']) {
            return 'head timestamp is in the future';
        }
        if ($t['now'] - $ts > $t['maxHeadAge']) {
            return 'head is stale';
        }
        if ($t['pinned'] !== null && $t['pinned']->has($domain) && self::truthy($t['pinned']->get($domain))) {
            $why = self::checkHeadAdvance($t['pinned']->get($domain), $h, $pinProof);
            if ($why !== '') {
                return $why . ' (vs pinned head)';
            }
        }
        return '';
    }

    /** Expand a revocation non-membership reference `{size, lo?, hi?}` against the shared leaf table. */
    private static function expandNm(mixed $c, array $leaves): ?Obj
    {
        if (!($c instanceof Obj) || !self::nat($c->get('size'))) {
            return null;
        }
        $out = Obj::of(['size' => $c->get('size')]);
        foreach (['lo', 'hi'] as $side) {
            if (!$c->has($side)) {
                continue;
            }
            $ix = $c->get($side);
            if (!self::nat($ix) || self::natV($ix) >= count($leaves)) {
                return null;
            }
            $out->set($side, $leaves[self::natV($ix)]);
        }
        return $out;
    }

    // ---- the verifier -------------------------------------------------------------------------------------------------------

    /**
     * Verify a mesh proof end to end, offline. Both arguments are parsed JSON (Json::parseLax values).
     * @return array{ok: bool, reason?: string, hop: int}
     */
    public static function verify(mixed $proof, mixed $trust): array
    {
        try {
            return self::verifyInner($proof, $trust);
        } catch (\Throwable) {
            return self::fail('malformed proof');
        }
    }

    private static function verifyInner(mixed $proof, mixed $trust): array
    {
        [$t, $bad] = self::validTrust($trust);
        if ($t === null) {
            return self::fail($bad);
        }
        if (!($proof instanceof Obj)) {
            return self::fail('malformed proof');
        }
        $p = $proof;
        $chain = $p->get('chain');
        $hops = $p->get('hops');
        $heads = $p->get('heads');
        $revLeaves = $p->get('rev_leaves');
        if (!self::list($chain) || !self::list($hops) || !self::list($heads) || !self::list($revLeaves)) {
            return self::fail('malformed proof');
        }
        $actionSig = $p->get('action_sig');
        $action = $p->get('action');
        if (!is_string($actionSig) || !self::validAction($action)) {
            return self::fail('malformed action');
        }
        $pinProofs = null;
        if ($p->has('pin_proofs')) {
            $pinProofs = $p->get('pin_proofs');
            if (!self::list($pinProofs) || count($pinProofs) > self::MAX_COSIGS) {
                return self::fail('malformed pin proofs');
            }
            foreach ($pinProofs as $x) {
                if (!($x instanceof Obj) || !is_string($x->get('domain')) || !self::validConsistency($x->get('proof'))) {
                    return self::fail('malformed pin proofs');
                }
            }
        }
        if (count($chain) < 1 || count($chain) > $t['maxChain']) {
            return self::fail('chain length out of bounds');
        }
        if (count($heads) > count($chain) || count($revLeaves) > 2 * count($chain)) {
            return self::fail('evidence tables exceed chain size');
        }
        [$why, $ok] = Pca::verifyChain($chain, $t['human'], true, null, $t['pqPins']);
        if (!$ok) {
            return self::fail('chain: ' . $why);
        }
        if (count($hops) !== count($chain)) {
            return self::fail('hop evidence count does not match chain length');
        }
        foreach ($revLeaves as $l) {
            if (!($l instanceof Obj) || !is_string($l->get('id')) || !self::validInclusion($l->get('proof'))) {
                return self::fail('malformed revocation leaves');
            }
        }
        $used = [];
        foreach ($hops as $h) {
            if ($h instanceof Obj && self::nat($h->get('head'))) {
                $used[self::natV($h->get('head'))] = true;
            }
        }
        if (count($used) !== count($heads)) {
            return self::fail('unreferenced or missing head in evidence table');
        }

        $headErrs = [];
        $prev = null;
        foreach ($chain as $i => $cap) {
            $ev = $hops[$i];
            if (!($ev instanceof Obj)) {
                return self::fail('malformed hop evidence', $i);
            }
            $domain = $ev->get('domain');
            if (!is_string($domain) || !self::nat($ev->get('head')) || self::natV($ev->get('head')) >= count($heads)
                || !($ev->get('revocation') instanceof Obj)) {
                return self::fail('malformed hop evidence', $i);
            }
            if (!self::subset([$domain], $t['allowed'])) {
                return self::fail('issuing domain not allowed by policy', $i);
            }
            if ($i === 0 && $domain !== $t['rootDomain']) {
                return self::fail('root capability must be anchored in the pinned root domain', $i);
            }
            $issuer = $cap->get('issuer');
            if ($i > 0 && $t['issuerDoms'] !== null && $t['issuerDoms']->has((string)$issuer) && $t['issuerDoms']->get((string)$issuer) !== $domain) {
                return self::fail('issuer key is pinned to a different domain', $i);
            }
            $hi = self::natV($ev->get('head'));
            $ch = $heads[$hi];
            if (!isset($headErrs[$hi])) {
                $headM = self::g($ch, 'head');
                $dom = $headM instanceof Obj && is_string($headM->get('domain')) ? $headM->get('domain') : '';
                $pinProof = null;
                foreach ($pinProofs ?? [] as $x) {
                    if ($x->get('domain') === $dom) {
                        $pinProof = $x->get('proof');
                        break;
                    }
                }
                $headErrs[$hi] = self::checkCosignedHead($ch, $dom, $t, $pinProof);
            }
            $headM = self::g($ch, 'head');
            if (!($ch instanceof Obj) || $headM === null) {
                return self::fail('malformed proof'); // `ch.head.domain` throws in the reference
            }
            if (!($headM instanceof Obj) || $headM->get('domain') !== $domain) {
                return self::fail('source-domain anchor: head is for a different domain', $i);
            }
            if ($headErrs[$hi] !== '') {
                return self::fail('source-domain anchor: ' . $headErrs[$hi], $i);
            }

            $incl = $ev->get('inclusion');
            if (!self::validInclusion($incl) || self::natV($incl->get('size')) !== self::natV($headM->get('size'))) {
                return self::fail('hop not included in the issuing domain log', $i);
            }
            try {
                $capDigest = Pca::capHash($cap);
            } catch (\Throwable) {
                return self::fail('hop not included in the issuing domain log', $i);
            }
            $root = is_string($headM->get('root')) ? $headM->get('root') : '';
            if (!Pca::verifyInclusion($root, $incl, $capDigest)) {
                return self::fail('hop not included in the issuing domain log', $i);
            }

            if ($i > 0) {
                $b = $ev->get('binding');
                if (!($b instanceof Obj) || !is_string($b->get('role')) || !is_string($b->get('sig'))
                    || $b->get('agent') !== $cap->get('issuer') || $b->get('domain') !== $ev->get('domain')) {
                    return self::fail('missing or mismatched domain binding for issuer', $i);
                }
                $m = self::msg(self::BINDING_DOMAIN, Obj::of(['agent' => $b->get('agent'), 'domain' => $b->get('domain'), 'role' => $b->get('role')]));
                if ($m === null || !self::verifySig($domain, $m, $b->get('sig'))) {
                    return self::fail('domain binding signature invalid', $i);
                }
            }

            $rev = $ev->get('revocation');
            $revRoot = is_string($headM->get('rev_root')) ? $headM->get('rev_root') : '';
            $id = is_string($cap->get('id')) ? $cap->get('id') : '';
            $nmCap = self::expandNm($rev->get('cap'), $revLeaves);
            if ($nmCap === null || !self::nonMembership($revRoot, $nmCap, $id)) {
                return self::fail('capability revoked (or revocation proof invalid)', $i);
            }
            $nmKey = self::expandNm($rev->get('issuer_key'), $revLeaves);
            if ($nmKey === null || !self::nonMembership($revRoot, $nmKey, 'key:' . (is_string($issuer) ? $issuer : ''))) {
                return self::fail('issuer key revoked (or revocation proof invalid)', $i);
            }

            [$eff, $why] = self::effective($cap->get('caveats'));
            if ($why !== '') {
                return self::fail($why, $i);
            }
            if ($prev !== null && !self::narrows($eff, $prev)) {
                return self::fail('hop widens authority', $i);
            }
            $prev = $eff;
        }

        $at = (float)self::f($action->get('at'));
        if ($at > $t['now'] + $t['maxSkew']) {
            return self::fail('action timestamp is in the future');
        }
        if ($t['hasActionAge'] && $t['now'] - $at > $t['maxActionAge']) {
            return self::fail('action is stale');
        }
        $tip = $chain[count($chain) - 1];
        $holder = $tip->get('holder');
        try {
            $tipHash = Pca::capHash($tip);
            $am = self::msg(self::ACTION_DOMAIN, Obj::of(['action' => $action, 'tip' => $tipHash]));
        } catch (\Throwable) {
            $am = null;
        }
        if ($am === null || !self::verifySig($holder, $am, $actionSig)) {
            return self::fail('action not signed by the chain tip holder');
        }
        $denied = self::admits($prev, $action, $t['now'], count($chain));
        if ($denied !== '') {
            return self::fail('action not admitted: ' . $denied);
        }
        return ['ok' => true, 'hop' => -1];
    }
}
