<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * Linked policy templates (security contract C-242, C-243): a port of packages/pca/src/policy-link.ts (the TypeScript is
 * authoritative). Template definitions, instantiation with closed slot domains, signed templates and tighten overlays, and
 * resolution of a grant's `template_ref`. Total: nothing throws; anything malformed fails closed. Inputs are the library's JSON
 * values (Obj, lists, strings, Num, bool, null). Results are ['ok' => bool, 'reason' => string] / ['ok' => true, ...].
 */
final class PolicyLink
{
    public const SIG_DOMAIN_TEMPLATE = "atlas-pca/policy-template/v1\0";
    public const SIG_DOMAIN_TIGHTEN = "atlas-pca/template-tighten/v1\0";
    private const NAME_RE = '/\A[a-z][a-z0-9_]{0,63}\z/D';
    private const NAME_SOURCE = '^[a-z][a-z0-9_]{0,63}$';
    private const MAX_SLOTS = 32;
    private const MAX_SLOT_STRING = 256;
    private const MAX_SLOT_SET = 64;

    private static function isOne(mixed $v): bool
    {
        return $v instanceof Num && $v->lexeme === '1';
    }

    private static function safeInt(mixed $v): bool
    {
        return $v instanceof Num && $v->isInt() && $v->strictError() === null;
    }

    private static function u16len(string $s): int
    {
        return intdiv(strlen(mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2);
    }

    private static function message(string $domain, string $digest): string
    {
        return $domain . hash('sha256', $digest, true);
    }

    private static function jsString(mixed $x): string
    {
        return $x === null ? 'null' : (is_bool($x) ? ($x ? 'true' : 'false') : ($x instanceof Num ? $x->lexeme : (is_string($x) ? $x : 'object')));
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** @param array<string,true> $used */
    private static function scan(mixed $v, Obj $decl, array &$used): ?string
    {
        if (self::isList($v)) {
            foreach ($v as $x) {
                if (($e = self::scan($x, $decl, $used)) !== null) {
                    return $e;
                }
            }
            return null;
        }
        if (!($v instanceof Obj)) {
            return null;
        }
        foreach ($v->keys() as $k) {
            if ($k === '__proto__' || $k === 'constructor' || $k === 'prototype') {
                return "body has the forbidden key '$k'";
            }
        }
        if ($v->has('$slot')) {
            foreach ($v->keys() as $k) {
                if ($k !== '$slot' && $k !== 'pre' && $k !== 'post') {
                    return "placeholder has unknown member '$k'";
                }
            }
            $name = $v->get('$slot');
            if (!is_string($name) || !$decl->has($name)) {
                return "placeholder names undeclared slot '" . self::jsString($name) . "'";
            }
            foreach (['pre', 'post'] as $k) {
                if ($v->has($k) && !is_string($v->get($k))) {
                    return "placeholder $k must be a string";
                }
            }
            $used[$name] = true;
            return null;
        }
        foreach ($v->keys() as $k) {
            if (($e = self::scan($v->get($k), $decl, $used)) !== null) {
                return $e;
            }
        }
        return null;
    }

    public static function templateDefError(mixed $d): ?string
    {
        if (!($d instanceof Obj)) {
            return 'template must be an object';
        }
        if (!self::isOne($d->get('v')) || $d->get('kind') !== 'pca-policy-template') {
            return 'template v / kind mismatch';
        }
        if (!is_string($d->get('id')) || preg_match(self::NAME_RE, $d->get('id')) !== 1) {
            return 'template id must match ' . self::NAME_SOURCE;
        }
        $ver = $d->get('version');
        if (!is_string($ver) || $ver === '' || self::u16len($ver) > 64) {
            return 'template version must be a string of 1..64 characters';
        }
        $slots = $d->get('slots');
        if (!($slots instanceof Obj)) {
            return 'slots must be an object';
        }
        $names = $slots->keys();
        if (count($names) > self::MAX_SLOTS) {
            return 'more than ' . self::MAX_SLOTS . ' slots';
        }
        foreach ($names as $n) {
            $s = $slots->get($n);
            if (preg_match(self::NAME_RE, $n) !== 1) {
                return "slot name '$n' must match " . self::NAME_SOURCE;
            }
            if (!($s instanceof Obj)) {
                return "slot '$n' must be an object";
            }
            $type = $s->get('type');
            if (!in_array($type, ['string', 'integer', 'set'], true)) {
                return "slot '$n'.type must be string, integer or set";
            }
            if ($type === 'set' && !self::isList($s->get('values'))) {
                return "set slot '$n' needs a closed values list";
            }
            if ($s->has('values')) {
                $vals = $s->get('values');
                if (!self::isList($vals) || count($vals) > self::MAX_SLOT_SET || count(array_filter($vals, static fn ($x) => !is_string($x))) > 0) {
                    return "slot '$n'.values must be a list of strings";
                }
            }
            if ($type === 'integer') {
                foreach (['min', 'max'] as $k) {
                    if ($s->has($k) && !self::safeInt($s->get($k))) {
                        return "slot '$n'.$k must be a safe integer";
                    }
                }
            }
        }
        $body = $d->get('body');
        if (!($body instanceof Obj) || !self::isList($body->get('predicates'))) {
            return 'body.predicates must be an array';
        }
        if ($body->has('caveats') && !self::isList($body->get('caveats'))) {
            return 'body.caveats must be an array';
        }
        $used = [];
        if (($e = self::scan($body, $slots, $used)) !== null) {
            return $e;
        }
        foreach ($names as $n) {
            if (!isset($used[$n])) {
                return "slot '$n' is declared but never used";
            }
        }
        return null;
    }

    public static function templateDigest(mixed $d): string
    {
        return Pca::hashCanonical($d);
    }

    /** @param list<string> $trusted */
    private static function signedOk(mixed $signer, string $domain, string $digest, mixed $sig): bool
    {
        return is_string($signer) && is_string($sig) && Pca::verifyEd25519B64u($signer, self::message($domain, $digest), $sig);
    }

    /** @param list<string> $trusted */
    public static function verifyTemplate(mixed $t, array $trusted): array
    {
        try {
            $e = self::templateDefError($t instanceof Obj ? $t->get('def') : null);
            if ($e !== null) {
                return ['ok' => false, 'reason' => $e];
            }
            $signer = $t->get('signer');
            if (!is_string($signer) || !in_array($signer, $trusted, true)) {
                return ['ok' => false, 'reason' => 'template signer is not trusted'];
            }
            if (!self::signedOk($signer, self::SIG_DOMAIN_TEMPLATE, self::templateDigest($t->get('def')), $t->get('sig'))) {
                return ['ok' => false, 'reason' => 'bad template signature'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'template verification error (fail closed)'];
        }
    }

    public static function tightenOverlayError(mixed $o): ?string
    {
        if (!($o instanceof Obj)) {
            return 'overlay must be an object';
        }
        if (!self::isOne($o->get('v')) || $o->get('kind') !== 'pca-template-tighten') {
            return 'overlay v / kind mismatch';
        }
        foreach ($o->keys() as $k) {
            if (!in_array($k, ['v', 'kind', 'template_id', 'version_digest', 'add_where', 'add_caveats'], true)) {
                return "overlay has unknown member '$k' (an overlay can only add where conditions and caveats)";
            }
        }
        if (!is_string($o->get('template_id')) || preg_match(self::NAME_RE, $o->get('template_id')) !== 1) {
            return 'overlay template_id invalid';
        }
        if (!is_string($o->get('version_digest')) || $o->get('version_digest') === '') {
            return 'overlay version_digest invalid';
        }
        if ($o->has('add_where') && (!self::isList($o->get('add_where')) || count(array_filter($o->get('add_where'), static fn ($c) => !($c instanceof Obj))) > 0)) {
            return 'overlay add_where must be a list of conditions';
        }
        if ($o->has('add_caveats') && (!self::isList($o->get('add_caveats')) || count(array_filter($o->get('add_caveats'), static fn ($c) => !($c instanceof Obj) || !is_string($c->get('type')))) > 0)) {
            return 'overlay add_caveats must be a list of caveats';
        }
        return null;
    }

    /** @param list<string> $trusted */
    public static function verifyTighten(mixed $t, array $trusted): array
    {
        try {
            $e = self::tightenOverlayError($t instanceof Obj ? $t->get('overlay') : null);
            if ($e !== null) {
                return ['ok' => false, 'reason' => $e];
            }
            $signer = $t->get('signer');
            if (!is_string($signer) || !in_array($signer, $trusted, true)) {
                return ['ok' => false, 'reason' => 'overlay signer is not trusted'];
            }
            if (!self::signedOk($signer, self::SIG_DOMAIN_TIGHTEN, Pca::hashCanonical($t->get('overlay')), $t->get('sig'))) {
                return ['ok' => false, 'reason' => 'bad overlay signature'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'overlay verification error (fail closed)'];
        }
    }

    private static function slotValueError(string $name, Obj $d, mixed $v): ?string
    {
        $type = $d->get('type');
        $values = $d->has('values') ? $d->get('values') : null;
        if ($type === 'string') {
            if (!is_string($v) || $v === '' || self::u16len($v) > self::MAX_SLOT_STRING) {
                return "slot '$name' must be a string of 1.." . self::MAX_SLOT_STRING . ' characters';
            }
            if ($values !== null && !in_array($v, $values, true)) {
                return "slot '$name' is outside its closed value set";
            }
            return null;
        }
        if ($type === 'integer') {
            if (!self::safeInt($v)) {
                return "slot '$name' must be a safe integer";
            }
            if ($d->has('min') && $v->int() < $d->get('min')->int()) {
                return "slot '$name' is below its minimum";
            }
            if ($d->has('max') && $v->int() > $d->get('max')->int()) {
                return "slot '$name' is above its maximum";
            }
            return null;
        }
        if (!self::isList($v) || $v === [] || count($v) > self::MAX_SLOT_SET || count(array_filter($v, static fn ($x) => !is_string($x))) > 0) {
            return "slot '$name' must be a non-empty list of strings";
        }
        if (count(array_unique($v)) !== count($v)) {
            return "slot '$name' has duplicate members";
        }
        if ($values !== null && count(array_filter($v, static fn ($x) => !in_array($x, $values, true))) > 0) {
            return "slot '$name' has a member outside its closed set";
        }
        return null;
    }

    private static function matcherSafe(string $name, mixed $val): void
    {
        foreach (self::isList($val) ? $val : [$val] as $x) {
            if (is_string($x) && (str_contains($x, '*') || str_starts_with($x, 're:'))) {
                throw new \DomainException("slot '$name' would inject a wildcard or regex matcher into a verb or resource");
            }
        }
    }

    private static function fill(mixed $v, Obj $slots, ?string $key = null): mixed
    {
        if (self::isList($v)) {
            return array_map(static fn ($x) => self::fill($x, $slots, $key), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->has('$slot')) {
            $name = $v->get('$slot');
            $val = $slots->get($name);
            if ($key === 'verb' || $key === 'resource') {
                self::matcherSafe($name, $val);
            }
            $pre = is_string($v->get('pre')) ? $v->get('pre') : '';
            $post = is_string($v->get('post')) ? $v->get('post') : '';
            if ($pre === '' && $post === '') {
                return $val;
            }
            if (!is_string($val) || str_contains($val, '*') || str_contains($val, "\0")) {
                throw new \DomainException("slot '$name' cannot be spliced into a string (wildcard or non-string)");
            }
            $out = $pre . $val . $post;
            if ($pre === '' && str_starts_with($out, 're:')) {
                throw new \DomainException("slot '$name' would inject a regex matcher");
            }
            return $out;
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::fill($v->get($k), $slots, $k));
        }
        return $o;
    }

    public static function instantiateTemplate(mixed $d, mixed $slots): array
    {
        try {
            if (($e = self::templateDefError($d)) !== null) {
                return ['ok' => false, 'reason' => $e];
            }
            if (!($slots instanceof Obj)) {
                return ['ok' => false, 'reason' => 'slots must be an object'];
            }
            $decl = $d->get('slots');
            foreach ($slots->keys() as $k) {
                if (!$decl->has($k)) {
                    return ['ok' => false, 'reason' => "slot '$k' is not declared by the template"];
                }
            }
            foreach ($decl->keys() as $n) {
                if (!$slots->has($n)) {
                    return ['ok' => false, 'reason' => "slot '$n' is not filled"];
                }
                if (($se = self::slotValueError($n, $decl->get($n), $slots->get($n))) !== null) {
                    return ['ok' => false, 'reason' => $se];
                }
            }
            $body = self::fill($d->get('body'), $slots);
            return ['ok' => true, 'policy' => Obj::of(['predicates' => $body->get('predicates'), 'caveats' => $body->has('caveats') ? $body->get('caveats') : []])];
        } catch (\DomainException $e) {
            return ['ok' => false, 'reason' => $e->getMessage()];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'instantiation error (fail closed)'];
        }
    }

    public static function templateRefError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'template_ref must be an object';
        }
        foreach ($r->keys() as $k) {
            if (!in_array($k, ['template_id', 'version_digest', 'slots', 'bind_params_digest'], true)) {
                return "template_ref has unknown member '$k'";
            }
        }
        if (!is_string($r->get('template_id')) || preg_match(self::NAME_RE, $r->get('template_id')) !== 1) {
            return 'template_ref.template_id invalid';
        }
        $vd = $r->get('version_digest');
        if (!is_string($vd) || $vd === '' || strlen($vd) > 128) {
            return 'template_ref.version_digest invalid';
        }
        if ($r->has('slots') && $r->has('bind_params_digest')) {
            return 'template_ref has both slots and bind_params_digest';
        }
        if ($r->has('bind_params_digest')) {
            $d = $r->get('bind_params_digest');
            return is_string($d) && $d !== '' && strlen($d) <= 128 ? null : 'template_ref.bind_params_digest invalid';
        }
        if (!($r->get('slots') instanceof Obj)) {
            return 'template_ref.slots must be an object';
        }
        return null;
    }

    /** @param Obj $reg {templates: Obj, overlays?: list, trusted: list<string>} */
    public static function resolveLink(mixed $ref, Obj $reg): array
    {
        try {
            if (($e = self::templateRefError($ref)) !== null) {
                return ['ok' => false, 'reason' => $e];
            }
            $trusted = $reg->get('trusted');
            $templates = $reg->get('templates');
            $t = $templates instanceof Obj && $templates->has($ref->get('version_digest')) ? $templates->get($ref->get('version_digest')) : null;
            if ($t === null) {
                return ['ok' => false, 'reason' => 'template version is not in the registry'];
            }
            $v = self::verifyTemplate($t, $trusted);
            if (!$v['ok']) {
                return ['ok' => false, 'reason' => $v['reason']];
            }
            if (self::templateDigest($t->get('def')) !== $ref->get('version_digest')) {
                return ['ok' => false, 'reason' => 'registry entry does not match its digest'];
            }
            if ($t->get('def')->get('id') !== $ref->get('template_id')) {
                return ['ok' => false, 'reason' => 'template id does not match the reference'];
            }
            $slots = $ref->get('slots');
            if ($ref->has('bind_params_digest')) {
                $params = $reg->get('params');
                $bound = $params instanceof Obj && $params->has($ref->get('bind_params_digest')) ? $params->get($ref->get('bind_params_digest')) : null;
                if (!($bound instanceof Obj)) {
                    return ['ok' => false, 'reason' => 'parameter object is not available'];
                }
                if (Pca::hashCanonical($bound) !== $ref->get('bind_params_digest')) {
                    return ['ok' => false, 'reason' => 'parameter object does not match bind_params_digest'];
                }
                $slots = $bound;
            }
            $inst = self::instantiateTemplate($t->get('def'), $slots);
            if (!$inst['ok']) {
                return $inst;
            }
            $predicates = $inst['policy']->get('predicates');
            $caveats = $inst['policy']->get('caveats');
            $applied = 0;
            foreach ($reg->has('overlays') ? $reg->get('overlays') : [] as $o) {
                $ov = $o instanceof Obj ? $o->get('overlay') : null;
                if (!($ov instanceof Obj) || $ov->get('version_digest') !== $ref->get('version_digest') || $ov->get('template_id') !== $ref->get('template_id')) {
                    continue;
                }
                $vv = self::verifyTighten($o, $trusted);
                if (!$vv['ok']) {
                    return ['ok' => false, 'reason' => $vv['reason']];
                }
                $add = $ov->has('add_where') ? $ov->get('add_where') : [];
                $predicates = array_map(static function ($p) use ($add) {
                    $c = new Obj();
                    foreach ($p->keys() as $k) {
                        $c->set($k, $p->get($k));
                    }
                    $c->set('where', array_merge($p->has('where') ? $p->get('where') : [], $add));
                    return $c;
                }, $predicates);
                $caveats = array_merge($caveats, $ov->has('add_caveats') ? $ov->get('add_caveats') : []);
                $applied++;
            }
            return ['ok' => true, 'policy' => Obj::of(['predicates' => $predicates, 'caveats' => $caveats]), 'overlays' => $applied];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'link resolution error (fail closed)'];
        }
    }
}
