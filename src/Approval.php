<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
 * challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render
 * of an action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely throws
 * {@see ActionKitError} rather than returning something partial.
 */
final class Approval
{
    public const RENDER_DOMAIN = 'atlas-pca/approval-render/v1';
    public const CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\0";
    public const BATCH_DOMAIN = 'atlas-pca/approval-batch/v1';
    private const ITEM_DOMAIN = 'atlas-pca/approval-batch-item/v1';
    private const PAYEE_DOMAIN = 'atlas-pca/approval-payee/v1';
    private const MAX_FIELDS = 64;
    private const MAX_DEPTH = 3;
    private const MAX_SAFE = 9007199254740991;

    public const WORDS = [
        'able', 'acid', 'aged', 'also', 'area', 'army', 'atom', 'aunt',
        'away', 'baby', 'back', 'ball', 'band', 'bank', 'base', 'bath',
        'bear', 'beat', 'beef', 'bell', 'belt', 'bend', 'bird', 'blue',
        'boat', 'body', 'bold', 'bone', 'book', 'boot', 'born', 'both',
        'bowl', 'bulb', 'burn', 'bush', 'busy', 'cafe', 'cake', 'calm',
        'camp', 'card', 'care', 'cart', 'case', 'cash', 'cast', 'cave',
        'cell', 'chat', 'chef', 'chip', 'city', 'clay', 'clip', 'club',
        'coal', 'coat', 'code', 'coin', 'cold', 'cook', 'cool', 'cope',
        'copy', 'cord', 'core', 'cost', 'crew', 'crop', 'dark', 'data',
        'date', 'dawn', 'deal', 'dear', 'deck', 'deep', 'deer', 'desk',
        'dial', 'dice', 'diet', 'dish', 'dive', 'door', 'dose', 'down',
        'draw', 'drop', 'drum', 'duck', 'dust', 'duty', 'each', 'earn',
        'east', 'easy', 'edge', 'echo', 'else', 'even', 'ever', 'exit',
        'face', 'fact', 'fair', 'fall', 'farm', 'fast', 'fate', 'fern',
        'file', 'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish',
        'five', 'flag', 'flat', 'flow', 'foam', 'fold', 'folk', 'food',
        'foot', 'fork', 'form', 'fort', 'four', 'free', 'frog', 'fuel',
        'full', 'fund', 'gain', 'game', 'gate', 'gear', 'gift', 'girl',
        'glad', 'glow', 'goat', 'gold', 'golf', 'good', 'grab', 'gray',
        'grid', 'grip', 'grow', 'gulf', 'hair', 'half', 'hall', 'hand',
        'hard', 'harp', 'hawk', 'head', 'heat', 'help', 'herb', 'hill',
        'hint', 'hold', 'hole', 'home', 'hood', 'hook', 'hope', 'horn',
        'host', 'hour', 'huge', 'hunt', 'idea', 'inch', 'iron', 'isle',
        'item', 'jade', 'jazz', 'join', 'joke', 'jump', 'jury', 'just',
        'keen', 'keep', 'kind', 'king', 'kite', 'knee', 'knot', 'lake',
        'lamp', 'land', 'lane', 'last', 'late', 'lawn', 'lead', 'leaf',
        'lean', 'left', 'lens', 'less', 'lift', 'lime', 'line', 'link',
        'lion', 'list', 'live', 'load', 'loan', 'lock', 'logo', 'long',
        'loop', 'lord', 'loud', 'love', 'luck', 'lung', 'made', 'mail',
        'main', 'mask', 'mass', 'mate', 'meal', 'melt', 'menu', 'mild',
        'milk', 'mind', 'mint', 'mole', 'moon', 'more', 'moss', 'move',
        'much', 'nail', 'navy', 'neat', 'neck', 'nest', 'news', 'nice',
    ];

    private static function digestOk(mixed $v): bool
    {
        return is_string($v) && Pca::unb64u($v, 32) !== null;
    }

    private static function safeInt(mixed $v): bool
    {
        return !is_bool($v) && IntentWb::isSafeInt($v);
    }

    private static function num(mixed $v): float
    {
        return $v instanceof Num ? $v->float() : (float)$v;
    }

    private static function bounded(mixed $v, int $n): bool
    {
        return is_string($v) && $v !== '' && strlen($v) <= $n;
    }

    private static function lone(string $s): bool
    {
        return preg_match('/\xED[\xA0-\xBF]/', $s) === 1;
    }

    private static function u16(string $s): string
    {
        return mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    /** @param list<string> $required @param list<string> $optional */
    private static function closed(Obj $o, array $required, array $optional = []): ?string
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $required, true) && !in_array($k, $optional, true)) {
                return "unknown member '$k'";
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return "missing member '$k'";
            }
        }
        return null;
    }

    /** Null if `$r` is a well-formed render (closed members, sorted unique ids, bounded), else the reason. */
    public static function renderShapeError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'render must be an object';
        }
        $e = self::closed($r, ['v', 'kind', 'verb', 'def_digest', 'unreviewed', 'fields']);
        if ($e !== null) {
            return $e;
        }
        if (!self::safeInt($r->get('v')) || self::num($r->get('v')) !== 1.0 || $r->get('kind') !== 'pca-approval-render') {
            return 'not a pca-approval-render v1';
        }
        if (!self::bounded($r->get('verb'), 128)) {
            return 'verb must be a bounded string';
        }
        if (!self::digestOk($r->get('def_digest'))) {
            return 'def_digest must be canonical base64url (32 bytes)';
        }
        if (!is_bool($r->get('unreviewed'))) {
            return 'unreviewed must be a boolean';
        }
        $fs = $r->get('fields');
        if (!is_array($fs) || !array_is_list($fs) || count($fs) > self::MAX_FIELDS) {
            return 'fields must be an array of at most ' . self::MAX_FIELDS;
        }
        $prev = null;
        foreach ($fs as $f) {
            if (!($f instanceof Obj)) {
                return 'a field must be an object';
            }
            $e = self::closed($f, ['id', 'class', 'value'], ['unit']);
            if ($e !== null) {
                return $e;
            }
            if (!self::bounded($f->get('id'), 192) || !self::bounded($f->get('class'), 128)) {
                return 'field id and class must be bounded strings';
            }
            if ($prev !== null && strcmp(self::u16($prev), self::u16($f->get('id'))) >= 0) {
                return 'fields must be sorted by id and unique';
            }
            $prev = $f->get('id');
            if ($f->has('unit')) {
                $u = $f->get('unit');
                if (!($u instanceof Obj)) {
                    return 'unit must be an object';
                }
                if ($u->get('kind') === 'money') {
                    if (self::closed($u, ['kind', 'ccy', 'exp']) !== null || !self::bounded($u->get('ccy'), 16) || !self::safeInt($u->get('exp'))
                        || self::num($u->get('exp')) < 0 || self::num($u->get('exp')) > 18) {
                        return 'a money unit needs ccy and exp';
                    }
                } elseif (!in_array($u->get('kind'), ['count', 'bytes', 'duration', 'ratio'], true) || self::closed($u, ['kind']) !== null) {
                    return 'unknown unit';
                }
            }
        }
        return null;
    }

    /** H(R). A malformed render throws (a digest is never made over a shapeless value). */
    public static function renderDigest(mixed $render): string
    {
        $e = self::renderShapeError($render);
        if ($e !== null) {
            throw new \InvalidArgumentException("approvalRenderDigest: $e");
        }
        return IntentV2::hashCanonical(Obj::of(['d' => self::RENDER_DOMAIN, 'render' => $render]));
    }

    /** b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values. */
    public static function challenge(mixed $actionDigest, mixed $renderDigest): string
    {
        $a = is_string($actionDigest) ? Pca::unb64u($actionDigest, 32) : null;
        $r = is_string($renderDigest) ? Pca::unb64u($renderDigest, 32) : null;
        if ($a === null || $r === null) {
            throw new \InvalidArgumentException('approvalChallenge: both digests must be canonical 32-byte values');
        }
        return Pca::b64u(hash('sha256', self::CHALLENGE_DOMAIN . $a . $r, true));
    }

    public static function bindingWords(mixed $renderDigest): string
    {
        $r = is_string($renderDigest) ? Pca::unb64u($renderDigest, 32) : null;
        if ($r === null) {
            throw new \InvalidArgumentException('bindingWords: render digest must be a canonical 32-byte value');
        }
        $w = [];
        for ($i = 0; $i < 6; $i++) {
            $w[] = self::WORDS[ord($r[$i])];
        }
        return implode('-', $w);
    }

    // ---- the render ------------------------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private static function flatten(Obj $params): array
    {
        $out = [];
        $walk = null;
        $walk = static function (string $prefix, int $depth, mixed $v) use (&$out, &$walk): void {
            if ($v instanceof Obj && $depth < self::MAX_DEPTH && $v->keys() !== []) {
                foreach ($v->keys() as $k) {
                    if (str_contains($k, '.')) {
                        throw new ActionKitError('render_bad_params', "the parameter key '$k' contains a dot");
                    }
                    $walk($prefix === '' ? $k : "$prefix.$k", $depth + 1, $v->get($k));
                }
            } else {
                $out[$prefix] = $v;
            }
        };
        foreach ($params->keys() as $k) {
            if (str_contains($k, '.')) {
                throw new ActionKitError('render_bad_params', "the parameter key '$k' contains a dot");
            }
            $walk($k, 1, $params->get($k));
        }
        return $out;
    }

    private static function leafOk(mixed $v): bool
    {
        if (is_string($v)) {
            return !self::lone($v);
        }
        if (is_bool($v)) {
            return true;
        }
        if (is_array($v)) {
            foreach ($v as $x) {
                if (!self::leafOk($x)) {
                    return false;
                }
            }
            return array_is_list($v);
        }
        return self::safeInt($v);
    }

    private static function valueOk(string $type, mixed $v): bool
    {
        return match ($type) {
            'integer', 'duration' => self::safeInt($v),
            'boolean' => is_bool($v),
            'string', 'date', 'datetime', 'object_ref' => is_string($v) && !self::lone($v),
            'set', 'array' => is_array($v) && array_is_list($v) && self::leafOk($v),
            default => false,
        };
    }

    /**
     * The canonical approval render of `$d` for `$params`. `$confirmed`: whether the definition carries a valid signed confirmation
     * (the caller decides, as for `effective`); an unconfirmed render carries `unreviewed: true`.
     */
    public static function render(Obj $d, mixed $params, bool $confirmed = false): Obj
    {
        if (!($params instanceof Obj)) {
            throw new ActionKitError('render_bad_params', 'params must be an object');
        }
        $n = Actions::normalize($d);
        $np = $n->get('params');
        $flat = self::flatten($params);
        foreach (array_keys($flat) as $k) {
            if (!$np->has((string)$k)) {
                throw new ActionKitError('render_undeclared_param', "'$k' is not a parameter of " . $n->get('verb'));
            }
        }
        foreach ($np->keys() as $k) {
            if ($np->get($k)->get('required') === true && !array_key_exists($k, $flat)) {
                throw new ActionKitError('render_missing_param', "required parameter '$k' of " . $n->get('verb') . ' is missing');
            }
        }
        $ids = array_map('strval', array_keys($flat));
        usort($ids, static fn(string $a, string $b): int => strcmp(self::u16($a), self::u16($b)));
        $fields = [];
        foreach ($ids as $id) {
            $p = $np->get($id);
            if (!self::valueOk($p->get('type'), $flat[$id])) {
                throw new ActionKitError('render_bad_value', "'$id' is not a " . $p->get('type') . ' in the canonical domain');
            }
            $f = Obj::of(['id' => $id, 'class' => $p->has('role') ? $p->get('role') : 'param', 'value' => $flat[$id]]);
            $u = $p->get('unit');
            if ($u instanceof Obj) {
                if ($u->get('kind') === 'money') {
                    $c = $u->get('ccy');
                    $ccy = is_string($c) ? $c : ($c instanceof Obj ? ($flat[(string)$c->get('from')] ?? null) : null);
                    if (!is_string($ccy) || $ccy === '') {
                        throw new ActionKitError('render_unresolved_currency', "the currency of '$id' is not a string");
                    }
                    $f->set('unit', Obj::of(['kind' => 'money', 'ccy' => $ccy, 'exp' => $u->get('exp')]));
                } else {
                    $f->set('unit', Obj::of(['kind' => $u->get('kind')]));
                }
            }
            $fields[] = $f;
        }
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-approval-render', 'verb' => $n->get('verb'), 'def_digest' => Actions::defDigest($d),
            'unreviewed' => !$confirmed, 'fields' => $fields]);
    }

    // ---- PSD2 RTS Art. 5 -------------------------------------------------------------------------------------------------

    private static function unlinkable(string $m): never
    {
        throw new ActionKitError('psd2_unlinkable', $m);
    }

    public static function psd2Linking(Obj $r): Obj
    {
        if ($r->get('unreviewed') === true) {
            self::unlinkable('an unreviewed definition cannot be a payment approval');
        }
        $amts = [];
        $payees = [];
        foreach ($r->get('fields') as $f) {
            if ($f->get('class') === 'money.amount') {
                $amts[] = $f;
            } elseif ($f->get('class') === 'party.payee') {
                $payees[] = $f;
            }
        }
        if (count($amts) !== 1) {
            self::unlinkable('a payment approval needs exactly one money.amount parameter');
        }
        $a = $amts[0];
        $u = $a->get('unit');
        if (!($u instanceof Obj) || $u->get('kind') !== 'money') {
            self::unlinkable('the money.amount parameter has no money unit');
        }
        if (!self::safeInt($a->get('value')) || self::num($a->get('value')) < 0) {
            self::unlinkable('the amount must be a non-negative integer in minor units');
        }
        if (count($payees) !== 1 || !is_string($payees[0]->get('value')) || $payees[0]->get('value') === '') {
            self::unlinkable('a payment approval needs exactly one non-empty party.payee parameter');
        }
        return Obj::of(['amount_minor' => $a->get('value'), 'currency' => $u->get('ccy'), 'exp' => $u->get('exp'), 'payee' => $payees[0]->get('value')]);
    }

    public static function minorToDecimal(int $minor, int $exp): string
    {
        if ($minor < 0 || $exp < 0 || $exp > 18) {
            self::unlinkable('minor units must be a non-negative safe integer');
        }
        if ($exp === 0) {
            return (string)$minor;
        }
        $s = str_pad((string)$minor, $exp + 1, '0', STR_PAD_LEFT);
        return substr($s, 0, -$exp) . '.' . substr($s, -$exp);
    }

    /** @param list<Obj> $items each `{action_digest, render}` */
    public static function batch(array $items): Obj
    {
        if ($items === []) {
            self::unlinkable('a batch needs at least one payment');
        }
        $totals = [];
        $payees = [];
        $leaves = [];
        foreach ($items as $it) {
            $link = self::psd2Linking($it->get('render'));
            $ccy = $link->get('currency');
            $exp = (int)$link->get('exp')->lexeme;
            if (isset($totals[$ccy]) && $totals[$ccy][0] !== $exp) {
                self::unlinkable("currency $ccy appears with two exponents");
            }
            $minor = ($totals[$ccy][1] ?? 0) + (int)$link->get('amount_minor')->lexeme;
            if ($minor > self::MAX_SAFE) {
                self::unlinkable('the batch total exceeds the safe integer range');
            }
            $totals[$ccy] = [$exp, $minor];
            $payees[$link->get('payee')] = true;
            $leaves[] = Obj::of(['d' => self::ITEM_DOMAIN, 'a' => $it->get('action_digest'), 'r' => self::renderDigest($it->get('render'))]);
        }
        $ccys = array_map('strval', array_keys($totals));
        usort($ccys, static fn(string $a, string $b): int => strcmp(self::u16($a), self::u16($b)));
        $tl = [];
        foreach ($ccys as $c) {
            $tl[] = Obj::of(['ccy' => $c, 'exp' => new Num((string)$totals[$c][0]), 'minor' => new Num((string)$totals[$c][1])]);
        }
        $pl = array_map('strval', array_keys($payees));
        usort($pl, static fn(string $a, string $b): int => strcmp(self::u16($a), self::u16($b)));
        $batch = Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-approval-batch', 'n' => new Num((string)count($items)), 'totals' => $tl,
            'payees_root' => Pca::merkleRoot(array_map(static fn(string $p): Obj => Obj::of(['d' => self::PAYEE_DOMAIN, 'payee' => $p]), $pl)),
            'items_root' => Pca::merkleRoot($leaves),
        ]);
        $rd = IntentV2::hashCanonical(Obj::of(['d' => self::BATCH_DOMAIN, 'batch' => $batch]));
        return Obj::of(['batch' => $batch, 'action_digest' => $batch->get('items_root'), 'render_digest' => $rd,
            'challenge' => self::challenge($batch->get('items_root'), $rd), 'words' => self::bindingWords($rd)]);
    }
}
