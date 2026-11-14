<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Workflow.php';

/**
 * Read-side authorization (K5, C-310..C-319): what an agent may SEE, proven, and where it may go next. `redactRead` applies a
 * principal-signed read grant to one flat response (every field shown, masked or dropped, tighten-only), `readChainLabels` and
 * `checkSink` carry the labels of what was read into the decision about where it may go. Pure and total: anything malformed,
 * unsigned, unknown or out of scope DENIES (a thrown error is `bad_request`). Integers only. Values are parsed JSON (Obj,
 * lists, Num, strings, bools, null). Replays packages/pca/conformance/readside-vectors.json.
 */
final class ReadSide
{
    public const READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\0";
    public const READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\0";
    private const RG_REF = 'atlas-pca/read-grant-ref/v1';
    private const RR_REF = 'atlas-pca/read-receipt-ref/v1';

    private const RANK = ['show' => 0, 'last4' => 1, 'bucket' => 2, 'token' => 3, 'hash' => 4, 'drop' => 5];
    private const MODE_RE = '/\A(?:show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})\z/D';
    private const SALT_MIN = 16;

    private static function isMode(mixed $x): bool
    {
        return Workflow::matches(self::MODE_RE, $x);
    }

    private static function rank(string $m): int
    {
        return self::RANK[str_starts_with($m, 'bucket:') ? 'bucket' : $m];
    }

    private static function validEntry(mixed $e): bool
    {
        if (!($e instanceof Obj) || !Workflow::onlyKeys($e, ['verb', 'resource_prefix', 'purposes', 'modes', 'default_mode'])
            || !Workflow::isStr($e->get('verb'), 128) || !Workflow::isStr($e->get('resource_prefix'), 512)
            || !Workflow::sortedUnique($e->get('purposes'), Workflow::ID_RE, 16) || count($e->get('purposes')) === 0) {
            return false;
        }
        $m = $e->get('modes');
        if (!($m instanceof Obj) || count($m->keys()) > 32) {
            return false;
        }
        foreach ($m->keys() as $k) {
            if (!Workflow::matches(Workflow::LABEL_RE, $k) || !self::isMode($m->get($k))) {
                return false;
            }
        }
        return self::isMode($e->get('default_mode'));
    }

    /** Shape of a read grant body (no signature). */
    public static function validReadGrantBody(mixed $b): bool
    {
        if (!($b instanceof Obj) || !Workflow::onlyKeys($b, ['v', 'id', 'principal', 'issued_at', 'expires_at', 'reads', 'caps', 'sinks'])
            || !Workflow::isUint($b->get('v')) || Workflow::iv($b->get('v')) !== 1) {
            return false;
        }
        if (!Workflow::matches(Workflow::ID_RE, $b->get('id')) || !Workflow::isB32($b->get('principal')) || !Workflow::isUint($b->get('issued_at')) || !Workflow::isUint($b->get('expires_at'))) {
            return false;
        }
        $reads = $b->get('reads');
        if (!Workflow::isList($reads) || count($reads) === 0 || count($reads) > 32) {
            return false;
        }
        foreach ($reads as $e) {
            if (!self::validEntry($e)) {
                return false;
            }
        }
        $caps = $b->get('caps');
        if (!($caps instanceof Obj) || count($caps->keys()) > 32) {
            return false;
        }
        foreach ($caps->keys() as $k) {
            if (!Workflow::matches(Workflow::LABEL_RE, $k) || !Workflow::isUint($caps->get($k))) {
                return false;
            }
        }
        $s = $b->get('sinks');
        if (!($s instanceof Obj) || count($s->keys()) > 16) {
            return false;
        }
        foreach ($s->keys() as $k) {
            $v = $s->get($k);
            if (!Workflow::matches(Workflow::ID_RE, $k) || !($v instanceof Obj) || !Workflow::onlyKeys($v, ['allow', 'escalate'])
                || !Workflow::sortedUnique($v->get('allow'), Workflow::LABEL_RE, 16) || !Workflow::sortedUnique($v->get('escalate'), Workflow::LABEL_RE, 16)
                || array_intersect($v->get('allow'), $v->get('escalate')) !== []) {
                return false;
            }
        }
        return true;
    }

    public static function readGrantDigest(Obj $b): string
    {
        return Workflow::hash(self::RG_REF, 'g', $b);
    }

    public static function readReceiptRef(mixed $r): string
    {
        return Workflow::hash(self::RR_REF, 'r', $r);
    }

    /** @return array<string,mixed> the redaction result */
    private static function out(string $decision, ?string $code, ?Obj $counts = null): array
    {
        return ['decision' => $decision, 'code' => $code, 'view' => new Obj(), 'fields' => new Obj(), 'labels' => [], 'counts' => $counts ?? new Obj()];
    }

    /** @return list<string> */
    private static function sorted(array $xs): array
    {
        $xs = array_values(array_unique($xs));
        usort($xs, 'strcmp'); // every member is ASCII (LABEL_RE / NAME_RE)
        return $xs;
    }

    /** @return array{body: Obj}|array{code: string} */
    private static function gradeGrant(mixed $g, mixed $principal, mixed $now): array
    {
        if (!Workflow::isB32($principal) || !Workflow::isUint($now)) {
            return ['code' => 'bad_request'];
        }
        if (!($g instanceof Obj) || !Workflow::onlyKeys($g, ['body', 'sig']) || !self::validReadGrantBody($g->get('body'))) {
            return ['code' => 'bad_grant'];
        }
        $b = $g->get('body');
        if ($b->get('principal') !== $principal || !Workflow::verifyBody(self::READ_GRANT_DOMAIN, $b, $principal, $g->get('sig'))) {
            return ['code' => 'bad_signature'];
        }
        if (Workflow::iv($now) < Workflow::iv($b->get('issued_at'))) {
            return ['code' => 'not_yet'];
        }
        if (Workflow::iv($now) >= Workflow::iv($b->get('expires_at'))) {
            return ['code' => 'expired'];
        }
        return ['body' => $b];
    }

    /** The code points of a string as a list (byte-walk: total on any bytes). @return list<string> */
    private static function codePoints(string $s): array
    {
        preg_match_all('/[\x00-\x7F\xC2-\xF4][\x80-\xBF]*/', $s, $m);
        return $m[0];
    }

    /**
     * Apply a read grant to one response. `$inp` is an Obj with `grant` (the signed {body, sig}), `principal`, `now`, `verb`,
     * `resource`, `purpose`, `schema` ({fields, required}), `record` (flat scalars), `tighten`, `salt` and `counts`.
     *
     * @return array{decision: string, code: ?string, view: Obj, fields: Obj, labels: list<string>, counts: Obj}
     */
    public static function redactRead(mixed $inp): array
    {
        try {
            if (!($inp instanceof Obj)) {
                return self::out('deny', 'bad_request');
            }
            $g = self::gradeGrant($inp->get('grant'), $inp->get('principal'), $inp->get('now'));
            if (isset($g['code'])) {
                return self::out('deny', $g['code']);
            }
            $sc = $inp->get('schema');
            $verb = $inp->get('verb');
            $resource = $inp->get('resource');
            $purpose = $inp->get('purpose');
            $salt = $inp->get('salt');
            $record = $inp->get('record');
            $tighten = $inp->get('tighten');
            $counts = $inp->get('counts');
            if (!Workflow::isB32($inp->get('principal')) || !Workflow::isUint($inp->get('now')) || !Workflow::isStr($verb, 128) || !Workflow::isStr($resource, 512)
                || !Workflow::matches(Workflow::ID_RE, $purpose) || !is_string($salt) || K3Sig::utf16Len($salt) < self::SALT_MIN) {
                return self::out('deny', 'bad_request');
            }
            if (!($sc instanceof Obj) || !($sc->get('fields') instanceof Obj) || !Workflow::isList($sc->get('required'))) {
                return self::out('deny', 'bad_request');
            }
            $sf = $sc->get('fields');
            foreach ($sf->keys() as $k) {
                if (!Workflow::matches(Workflow::NAME_RE, $k) || !Workflow::matches(Workflow::LABEL_RE, $sf->get($k))) {
                    return self::out('deny', 'bad_request');
                }
            }
            foreach ($sc->get('required') as $p) {
                if (!is_string($p) || !$sf->has($p)) {
                    return self::out('deny', 'bad_request');
                }
            }
            if (!Workflow::isScalarMap($record) || !($tighten instanceof Obj)) {
                return self::out('deny', 'bad_request');
            }
            foreach ($tighten->keys() as $k) {
                if (!Workflow::matches(Workflow::LABEL_RE, $k) || !self::isMode($tighten->get($k))) {
                    return self::out('deny', 'bad_request');
                }
            }
            if (!($counts instanceof Obj)) {
                return self::out('deny', 'bad_request');
            }
            foreach ($counts->keys() as $k) {
                if (!Workflow::matches(Workflow::LABEL_RE, $k) || !Workflow::isUint($counts->get($k))) {
                    return self::out('deny', 'bad_request');
                }
            }
            $body = $g['body'];
            $entry = null;
            foreach ($body->get('reads') as $e) {
                if ($e->get('verb') === $verb && str_starts_with($resource, $e->get('resource_prefix')) && in_array($purpose, $e->get('purposes'), true)) {
                    $entry = $e;
                    break;
                }
            }
            if ($entry === null) {
                return self::out('deny', 'no_read_scope', $counts);
            }
            $fields = new Obj();
            $view = new Obj();
            $used = new Obj();
            $paths = $record->keys();
            usort($paths, 'strcmp');
            foreach ($paths as $path) {
                $v = $record->get($path);
                // a field the schema does not classify is never shown
                $vd = IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/read-value/v1', 'salt' => $salt, 'p' => $path, 'v' => $v]));
                if (!$sf->has($path)) {
                    $fields->set($path, Obj::of(['class' => 'unclassified', 'action' => 'dropped', 'kind' => null, 'vd' => $vd]));
                    continue;
                }
                $cls = $sf->get($path);
                $modes = $entry->get('modes');
                $mode = $modes->has($cls) ? $modes->get($cls) : $entry->get('default_mode');
                if ($tighten->has($cls) && self::rank($tighten->get($cls)) > self::rank($mode)) {
                    $mode = $tighten->get($cls);
                }
                $shown = null;
                $action = 'masked';
                $kind = str_starts_with($mode, 'bucket:') ? 'bucket' : $mode;
                if ($mode === 'show') {
                    $shown = $v;
                    $action = 'shown';
                    $kind = null;
                } elseif ($mode === 'last4') {
                    if (is_string($v) && preg_match('/[\xF0-\xF4]/', $v) !== 1) { // BMP only: a code point above U+FFFF is never masked
                        $cps = self::codePoints($v);
                        if (count($cps) > 4) {
                            $shown = '****' . implode('', array_slice($cps, -4));
                        }
                    }
                } elseif (str_starts_with($mode, 'bucket:')) {
                    $n = (int)substr($mode, 7);
                    if ($v instanceof Num && Workflow::iv($v) >= 0) {
                        $shown = new Num((string)(Workflow::iv($v) - Workflow::iv($v) % $n));
                    }
                } elseif ($mode === 'hash') {
                    $shown = IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/read-hash/v1', 'salt' => $salt, 'c' => $cls, 'v' => $v]));
                } elseif ($mode === 'token') {
                    $shown = 'tok_' . substr(IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/read-token/v1', 'salt' => $salt, 'c' => $cls, 'v' => $v])), 0, 22);
                }
                if ($shown === null) {
                    $fields->set($path, Obj::of(['class' => $cls, 'action' => 'dropped', 'kind' => null, 'vd' => $vd]));
                    continue;
                }
                $fields->set($path, Obj::of(['class' => $cls, 'action' => $action, 'kind' => $kind, 'vd' => $vd]));
                $view->set($path, $shown);
                $used->set($cls, ($used->has($cls) ? $used->get($cls) : 0) + 1);
            }
            $outCounts = $counts->without();
            foreach ($used->keys() as $c) {
                $outCounts->set($c, ($outCounts->has($c) ? Workflow::iv($outCounts->get($c)) : 0) + $used->get($c));
                if ($body->get('caps')->has($c) && $outCounts->get($c) > Workflow::iv($body->get('caps')->get($c))) {
                    return self::out('deny', 'read_cap', $counts);
                }
            }
            foreach ($sc->get('required') as $p) {
                if (!$view->has($p)) {
                    return self::out('escalate', 'required_dropped', $counts);
                }
            }
            $classes = [];
            foreach ($fields->keys() as $k) {
                if ($fields->get($k)->get('action') !== 'dropped') {
                    $classes[] = $fields->get($k)->get('class');
                }
            }
            return ['decision' => 'allow', 'code' => null, 'view' => $view, 'fields' => $fields, 'labels' => self::sorted($classes), 'counts' => $outCounts];
        } catch (\Throwable) {
            return self::out('deny', 'bad_request');
        }
    }

    private static function validReadReceipt(mixed $r): bool
    {
        if (!($r instanceof Obj) || !Workflow::onlyKeys($r, ['v', 'grant', 'verb', 'resource', 'purpose', 'seq', 'prev', 'fields', 'labels', 'issued_at', 'signer', 'sig'])
            || !Workflow::isUint($r->get('v')) || Workflow::iv($r->get('v')) !== 1) {
            return false;
        }
        $prev = $r->get('prev');
        if (!Workflow::isB32($r->get('grant')) || !Workflow::isStr($r->get('verb'), 128) || !Workflow::isStr($r->get('resource'), 512) || !Workflow::matches(Workflow::ID_RE, $r->get('purpose'))
            || !Workflow::isUint($r->get('seq')) || !($prev === null || Workflow::isB32($prev)) || (Workflow::iv($r->get('seq')) === 0) !== ($prev === null)) {
            return false;
        }
        $fs = $r->get('fields');
        if (!Workflow::isUint($r->get('issued_at')) || !Workflow::isB32($r->get('signer')) || !is_string($r->get('sig')) || !Workflow::sortedUnique($r->get('labels'), Workflow::LABEL_RE, 32)
            || !($fs instanceof Obj) || count($fs->keys()) > 64) {
            return false;
        }
        foreach ($fs->keys() as $k) {
            $f = $fs->get($k);
            if (!Workflow::matches(Workflow::NAME_RE, $k) || !($f instanceof Obj) || !Workflow::onlyKeys($f, ['class', 'action', 'kind', 'vd']) || !is_string($f->get('class'))
                || !($f->get('class') === 'unclassified' || Workflow::matches(Workflow::LABEL_RE, $f->get('class')))
                || !in_array($f->get('action'), ['shown', 'masked', 'dropped'], true) || !($f->get('kind') === null || is_string($f->get('kind'))) || !Workflow::isB32($f->get('vd'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * The labels carried by a verified, unbroken chain of read receipts, or an error code.
     *
     * @return array{labels: list<string>}|array{code: string, at: int}
     */
    public static function readChainLabels(mixed $receipts, mixed $rsSigner, mixed $grantDigest, mixed $now): array
    {
        if (!Workflow::isList($receipts)) {
            return ['code' => 'bad_receipt', 'at' => 0];
        }
        $all = [];
        $prev = null;
        foreach ($receipts as $i => $r) {
            if (!self::validReadReceipt($r) || $r->get('signer') !== $rsSigner || $r->get('grant') !== $grantDigest || Workflow::iv($r->get('seq')) !== $i
                || !Workflow::isUint($now) || Workflow::iv($r->get('issued_at')) > Workflow::iv($now)) {
                return ['code' => 'bad_receipt', 'at' => $i];
            }
            if (($prev === null ? $r->get('prev') !== null : $r->get('prev') !== self::readReceiptRef($prev)) || !Workflow::verifyBody(self::READ_RECEIPT_DOMAIN, $r->without('sig'), $rsSigner, $r->get('sig'))) {
                return ['code' => 'bad_receipt', 'at' => $i];
            }
            // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
            $classes = [];
            foreach ($r->get('fields')->keys() as $k) {
                if ($r->get('fields')->get($k)->get('action') !== 'dropped') {
                    $classes[] = $r->get('fields')->get($k)->get('class');
                }
            }
            if (self::sorted($classes) !== $r->get('labels')) {
                return ['code' => 'bad_receipt', 'at' => $i];
            }
            foreach ($r->get('labels') as $l) {
                $all[] = $l;
            }
            $prev = $r;
        }
        return ['labels' => self::sorted($all)];
    }

    /**
     * May data read under these receipts reach `sink`? Deny on any label the grant does not allow; escalate on an "ask" label.
     * `$inp` is an Obj with `grant`, `principal`, `rsSigner`, `now`, `sink` and `receipts`.
     *
     * @return array{decision: string, code: ?string, labels: list<string>}
     */
    public static function checkSink(mixed $inp): array
    {
        $no = static fn (string $code): array => ['decision' => 'deny', 'code' => $code, 'labels' => []];
        try {
            if (!($inp instanceof Obj)) {
                return $no('bad_request');
            }
            $g = self::gradeGrant($inp->get('grant'), $inp->get('principal'), $inp->get('now'));
            if (isset($g['code'])) {
                return $no($g['code']);
            }
            if (!Workflow::isB32($inp->get('rsSigner')) || !is_string($inp->get('sink'))) {
                return $no('bad_request');
            }
            $sinks = $g['body']->get('sinks');
            if (!$sinks->has($inp->get('sink'))) {
                return $no('unknown_sink');
            }
            $rule = $sinks->get($inp->get('sink'));
            $c = self::readChainLabels($inp->get('receipts'), $inp->get('rsSigner'), self::readGrantDigest($g['body']), $inp->get('now'));
            if (isset($c['code'])) {
                return $no($c['code']);
            }
            foreach ($c['labels'] as $l) {
                if (!in_array($l, $rule->get('allow'), true) && !in_array($l, $rule->get('escalate'), true)) {
                    return ['decision' => 'deny', 'code' => 'label_flow', 'labels' => $c['labels']];
                }
            }
            foreach ($c['labels'] as $l) {
                if (in_array($l, $rule->get('escalate'), true)) {
                    return ['decision' => 'escalate', 'code' => 'label_escalate', 'labels' => $c['labels']];
                }
            }
            return ['decision' => 'allow', 'code' => null, 'labels' => $c['labels']];
        } catch (\Throwable) {
            return $no('bad_request');
        }
    }
}
