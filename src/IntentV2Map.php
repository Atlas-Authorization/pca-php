<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Part of {@see IntentV2} (a trait so the 3800-line class is split into mutation-testable files): rule 19 (the committed map and Z0 disclosure).
 * Members are used through IntentV2 only; constants and shared helpers stay in IntentV2.
 */
trait IntentV2Map
{
    // ==== rule 19: the committed map and Z0 disclosure (intent-map-commit.ts) =========================================


    /** A string without lone surrogates of at most `max` UTF-8 bytes (empty allowed). */
    private static function mapStr(mixed $v, int $max = self::MAX_MAP_STRING_BYTES): bool
    {
        return is_string($v) && !self::lone($v) && strlen($v) <= $max;
    }

    /** Keys within `allowed` and every `required` member own. */
    private static function closedObj(Obj $o, array $allowed, array $required): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return false;
            }
        }
        return true;
    }

    /** SHA-256(TAG_kind || salt || strictCanonical(leaf)). Throws on a 32-byte-less salt or a leaf with no canonical form. */
    public static function mapLeafHash(string $kind, string $salt, mixed $leaf): string
    {
        if (!isset(self::MAP_TAGS[$kind])) {
            throw new \InvalidArgumentException('mapLeafHash: unknown leaf kind');
        }
        if (strlen($salt) !== 32) {
            throw new \InvalidArgumentException('mapLeafHash: the salt is 32 bytes');
        }
        return self::sha(self::MAP_TAGS[$kind] . $salt . self::canonicalize($leaf));
    }

    public static function mapNodeHash(string $l, string $r): string
    {
        return self::sha(self::MAP_TAG_NODE . $l . $r);
    }

    /** map_commit of a tree of `size` leaves with root `root`: b64u(SHA-256(TAG_COMMIT || u64be(size) || root)). */
    public static function mapCommitOf(int $size, string $root): string
    {
        return Pca::b64u(self::sha(self::MAP_TAG_COMMIT . pack('J', $size) . $root));
    }

    /** The RFC 6962 / 9162-shaped root over leaf hashes (split at the largest power of two < n). */
    public static function mapTreeRoot(array $hs): string
    {
        $n = count($hs);
        if ($n === 0) {
            throw new \InvalidArgumentException('mapTree: empty');
        }
        if ($n === 1) {
            return $hs[0];
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return self::mapNodeHash(self::mapTreeRoot(array_slice($hs, 0, $k)), self::mapTreeRoot(array_slice($hs, $k)));
    }

    /**
     * RFC 9162 §2.1.3.2 inclusion verification with the map node hash: the root the audit path of leaf `index` in a tree of
     * `size` leaves recomputes, or null when the path has the wrong length for (index, size).
     */
    public static function mapRootFromPath(int $index, int $size, string $leafHash, array $path): ?string
    {
        if (!($index >= 0 && $index < $size)) {
            return null;
        }
        $fn = $index;
        $sn = $size - 1;
        $r = $leafHash;
        foreach ($path as $p) {
            if ($sn === 0) {
                return null;
            }
            if ($fn % 2 === 1 || $fn === $sn) {
                $r = self::mapNodeHash($p, $r);
                if ($fn % 2 === 0) {
                    while ($fn % 2 === 0 && $fn !== 0) {
                        $fn = intdiv($fn, 2);
                        $sn = intdiv($sn, 2);
                    }
                }
            } else {
                $r = self::mapNodeHash($r, $p);
            }
            $fn = intdiv($fn, 2);
            $sn = intdiv($sn, 2);
        }
        return $sn === 0 ? $r : null;
    }

    /** The commitment of a full leaf list [{kind, salt, leaf}] (primitives.intent_map_commit). Throws on malformed input. */
    public static function mapCommitOfLeaves(mixed $leaves): string
    {
        if (!self::isList($leaves) || count($leaves) === 0) {
            throw new \InvalidArgumentException('leaves must be a non-empty array');
        }
        $hs = [];
        foreach ($leaves as $e) {
            $salt = Pca::unb64u(self::m($e, 'salt'), 32);
            $kind = self::m($e, 'kind');
            if ($salt === null || !is_string($kind) || !($e instanceof Obj) || !$e->has('leaf')) {
                throw new \InvalidArgumentException('a leaf entry is {kind, salt, leaf}');
            }
            $hs[] = self::mapLeafHash($kind, $salt, $e->get('leaf'));
        }
        return self::mapCommitOf(count($hs), self::mapTreeRoot($hs));
    }

    private static function isDimPath(mixed $p): bool
    {
        return $p === 'action.resource' || (is_string($p) && preg_match(self::PARAM_PATH_RE, $p) === 1);
    }

    /** The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped). @return list<array{0:int,1:int}> */
    public static function mapNumCells(Obj $d): array
    {
        $out = [];
        $cur = self::iv($d->get('lo'));
        foreach ($d->get('cuts') as $cv) {
            $c = self::iv($cv);
            if ($cur <= $c - 1) {
                $out[] = [$cur, $c - 1];
            }
            $out[] = [$c, $c];
            $cur = $c + 1;
        }
        if ($cur <= self::iv($d->get('hi'))) {
            $out[] = [$cur, self::iv($d->get('hi'))];
        }
        return $out;
    }

    private static function dimCells(Obj $d): int
    {
        return $d->get('kind') === 'num' ? count(self::mapNumCells($d)) : count($d->get('values'));
    }

    private static function dimError(mixed $d, int $j): ?string
    {
        if (!($d instanceof Obj)) {
            return "dims[$j] must be an object";
        }
        $kind = self::m($d, 'kind');
        if ($kind === 'num') {
            $all = ['kind', 'path', 'lo', 'hi', 'cuts'];
            if (!self::closedObj($d, $all, $all)) {
                return "dims[$j] must be exactly {kind, path, lo, hi, cuts}";
            }
            if (!self::isDimPath($d->get('path')) || $d->get('path') === 'action.resource') {
                return "dims[$j].path must be action.params.<name>";
            }
            $lo = $d->get('lo');
            $hi = $d->get('hi');
            if (!self::isInt($lo) || !self::isInt($hi) || self::f($lo) > self::f($hi)) {
                return "dims[$j] lo / hi must be safe integers with lo <= hi";
            }
            $cuts = $d->get('cuts');
            if (!self::isList($cuts) || count($cuts) > self::MAX_MAP_CUTS) {
                return "dims[$j].cuts must be an array of at most " . self::MAX_MAP_CUTS;
            }
            $prev = -INF;
            foreach ($cuts as $c) {
                if (!self::isInt($c) || self::f($c) <= $prev || self::f($c) < self::f($lo) || self::f($c) > self::f($hi)) {
                    return "dims[$j].cuts must be strictly increasing safe integers in [lo, hi]";
                }
                $prev = self::f($c);
            }
            return null;
        }
        if ($kind === 'cat') {
            $all = ['kind', 'path', 'values'];
            if (!self::closedObj($d, $all, $all)) {
                return "dims[$j] must be exactly {kind, path, values}";
            }
            if (!self::isDimPath($d->get('path'))) {
                return "dims[$j].path must be action.resource or action.params.<name>";
            }
            $vals = $d->get('values');
            if (!self::isList($vals) || count($vals) === 0 || count($vals) > self::MAX_MAP_VALUES) {
                return "dims[$j].values must be an array of 1.." . self::MAX_MAP_VALUES;
            }
            $seen = [];
            $last = count($vals) - 1;
            foreach ($vals as $i => $v) {
                if (!($v instanceof Obj) || !self::closedObj($v, ['kind', 'value'], ['kind', 'value'])) {
                    return "dims[$j].values[$i] must be exactly {kind, value}";
                }
                $vk = $v->get('kind');
                if ($vk !== 'exact' && $vk !== 'prefix' && $vk !== 'other') {
                    return "dims[$j].values[$i].kind must be exact, prefix or other";
                }
                $vv = $v->get('value');
                if (!self::mapStr($vv)) {
                    return "dims[$j].values[$i].value must be a string of at most " . self::MAX_MAP_STRING_BYTES . ' UTF-8 bytes';
                }
                if ($vk === 'other' ? ($i !== $last || $vv !== self::MAP_OTHER) : ($vk === 'prefix' && $vv === '')) {
                    return "dims[$j].values: exactly one other ('" . self::MAP_OTHER . "'), last; prefixes non-empty";
                }
                $key = "$vk:$vv";
                if (isset($seen['k' . $key])) {
                    return "dims[$j].values must be distinct";
                }
                $seen['k' . $key] = true;
            }
            if ($vals[$last]->get('kind') !== 'other') {
                return "dims[$j].values must end with the other value";
            }
            return null;
        }
        return "dims[$j].kind must be num or cat";
    }

    /** Shape of a header leaf (closed, typed; `cells` equals the product of the dimensions' cell counts). Null = well-formed. */
    public static function mapHeaderError(mixed $h): ?string
    {
        $all = ['verb', 'first', 'cells', 'dims'];
        if (!($h instanceof Obj) || !self::closedObj($h, $all, $all)) {
            return 'the header leaf must be exactly {verb, first, cells, dims}';
        }
        if (!self::mapStr($h->get('verb'), 128) || $h->get('verb') === '') {
            return 'header.verb must be a non-empty string of at most 128 UTF-8 bytes';
        }
        if (!self::isNonNeg($h->get('first')) || self::f($h->get('first')) >= self::MAX_MAP_LEAVES) {
            return 'header.first must be a leaf index';
        }
        $cells = $h->get('cells');
        if (!self::isInt($cells) || self::f($cells) < 1 || self::f($cells) > self::MAX_VERB_CELLS) {
            return 'header.cells must be a safe integer in [1, ' . self::MAX_VERB_CELLS . ']';
        }
        $dims = $h->get('dims');
        if (!self::isList($dims) || count($dims) > self::MAX_MAP_DIMS) {
            return 'header.dims must be an array of at most ' . self::MAX_MAP_DIMS;
        }
        $paths = [];
        $n = 1;
        foreach ($dims as $j => $d) {
            if (($e = self::dimError($d, $j)) !== null) {
                return "header.$e";
            }
            if (isset($paths['k' . $d->get('path')])) {
                return 'header.dims paths must be distinct';
            }
            $paths['k' . $d->get('path')] = true;
            $n *= self::dimCells($d);
            if ($n > self::MAX_VERB_CELLS) {
                return 'header: too many cells';
            }
        }
        if ($n !== self::iv($cells)) {
            return "header.cells is not the product of the dimensions' cell counts";
        }
        return null;
    }

    public static function mapCellError(mixed $c): ?string
    {
        $all = ['verb', 'cell', 'p_ppm', 'in_grant'];
        if (!($c instanceof Obj) || !self::closedObj($c, $all, $all)) {
            return 'the cell leaf must be exactly {verb, cell, p_ppm, in_grant}';
        }
        if (!self::mapStr($c->get('verb'), 128) || $c->get('verb') === '') {
            return 'cell.verb must be a non-empty string of at most 128 UTF-8 bytes';
        }
        $cell = $c->get('cell');
        $ok = self::isList($cell) && count($cell) <= self::MAX_MAP_DIMS;
        foreach ($ok ? $cell : [] as $x) {
            if (!self::isNonNeg($x)) {
                $ok = false;
                break;
            }
        }
        if (!$ok) {
            return 'cell.cell must be an array of non-negative safe integers';
        }
        if (!self::isNonNeg($c->get('p_ppm')) || self::f($c->get('p_ppm')) > 1000000) {
            return 'cell.p_ppm must be a safe integer in [0, 1000000]';
        }
        if (!is_bool($c->get('in_grant'))) {
            return 'cell.in_grant must be a boolean';
        }
        return null;
    }

    public static function mapMetricsError(mixed $m): ?string
    {
        $all = [...self::MAP_METRIC_FIELDS, 'log2_vs_mbits'];
        if (!($m instanceof Obj) || !self::closedObj($m, $all, self::MAP_METRIC_FIELDS)) {
            return 'the metrics leaf must be exactly {' . implode(', ', self::MAP_METRIC_FIELDS) . ', log2_vs_mbits?}';
        }
        foreach ($all as $k) {
            if ($k === 'log2_vs_mbits' && !$m->has($k)) {
                continue;
            }
            if (!self::isNonNeg($m->get($k))) {
                return "metrics.$k must be a non-negative safe integer";
            }
        }
        return null;
    }

    public static function mapLearnerError(mixed $l): ?string
    {
        if (!($l instanceof Obj) || !self::closedObj($l, ['learner_digest'], ['learner_digest'])) {
            return 'the learner leaf must be exactly {learner_digest}';
        }
        return self::b32($l->get('learner_digest')) ? null : 'learner.learner_digest must be canonical base64url (32 bytes)';
    }

    /**
     * Cell of ω under a well-formed header: per-dimension indices and the flat index, or ['error' => ...]. `resource` is
     * `action.resource`, `params` the plaintext params (own members). num: a safe integer in its cell; cat: exact, else the
     * longest prefix, else other. @return array{cell?: list<int>, flat?: int, error?: string}
     */
    public static function mapCellOf(Obj $header, mixed $resource, mixed $params): array
    {
        $cell = [];
        $flat = 0;
        foreach ($header->get('dims') as $d) {
            $path = $d->get('path');
            $x = $path === 'action.resource' ? $resource : self::m($params, self::paramName($path));
            $i = -1;
            if ($d->get('kind') === 'num') {
                if (self::isInt($x)) {
                    foreach (self::mapNumCells($d) as $k => [$lo, $hi]) {
                        if (self::f($x) >= $lo && self::f($x) <= $hi) {
                            $i = $k;
                            break;
                        }
                    }
                }
            } elseif (is_string($x) && !self::lone($x)) {
                $best = -1;
                $bestLen = -1;
                foreach ($d->get('values') as $k => $v) {
                    $vv = $v->get('value');
                    if ($v->get('kind') === 'exact' && $vv === $x) {
                        $best = $k;
                        break;
                    }
                    // prefixes of one string: the longer one is longer in UTF-16 units and in UTF-8 bytes alike
                    if ($v->get('kind') === 'prefix' && str_starts_with($x, $vv) && strlen($vv) > $bestLen) {
                        $best = $k;
                        $bestLen = strlen($vv);
                    }
                }
                $i = $best >= 0 ? $best : count($d->get('values')) - 1;
            }
            if ($i < 0) {
                return ['error' => "the action's $path lies outside the committed map's dimension"];
            }
            $cell[] = $i;
            $flat = $flat * self::dimCells($d) + $i;
        }
        return ['cell' => $cell, 'flat' => $flat];
    }

    private static function mapEntryShape(mixed $e, string $what): ?string
    {
        $all = ['index', 'salt', 'leaf', 'path'];
        if (!($e instanceof Obj) || !self::closedObj($e, $all, $all)) {
            return "disclosure.$what must be exactly {index, salt, leaf, path}";
        }
        if (!self::isNonNeg($e->get('index'))) {
            return "disclosure.$what.index must be a non-negative safe integer";
        }
        if (!self::b32($e->get('salt'))) {
            return "disclosure.$what.salt must be canonical base64url (32 bytes)";
        }
        $path = $e->get('path');
        $ok = self::isList($path) && count($path) <= 64;
        foreach ($ok ? $path : [] as $h) {
            if (!self::b32($h)) {
                $ok = false;
                break;
            }
        }
        return $ok ? null : "disclosure.$what.path must be an array of 32-byte digests";
    }

    /** Shape of a Z0 disclosure (closed, typed). Null = well-formed. */
    public static function mapDisclosureError(mixed $d): ?string
    {
        $all = ['size', 'header', 'cell', 'metrics'];
        if (!($d instanceof Obj) || !self::closedObj($d, $all, $all)) {
            return 'the disclosure must be exactly {size, header, cell, metrics}';
        }
        $size = $d->get('size');
        if (!self::isInt($size) || self::f($size) < 4 || self::f($size) > self::MAX_MAP_LEAVES) {
            return 'disclosure.size must be a safe integer in [4, ' . self::MAX_MAP_LEAVES . ']';
        }
        foreach (['header', 'cell', 'metrics'] as $k) {
            if (($e = self::mapEntryShape($d->get($k), $k)) !== null) {
                return $e;
            }
        }
        return self::mapHeaderError($d->get('header')->get('leaf')) ?? self::mapCellError($d->get('cell')->get('leaf'))
            ?? self::mapMetricsError($d->get('metrics')->get('leaf'));
    }

    /** Does the disclosed entry (kind `$kind`) open `$mapCommit` in a tree of `$size` leaves? */
    private static function mapOpens(string $kind, Obj $e, int $size, string $mapCommit): bool
    {
        try {
            $h = self::mapLeafHash($kind, Pca::unb64u($e->get('salt'), 32), $e->get('leaf'));
            $path = array_map(fn($x) => Pca::unb64u($x, 32), $e->get('path'));
            $root = self::mapRootFromPath(self::iv($e->get('index')), $size, $h, $path);
            return $root !== null && self::mapCommitOf($size, $root) === $mapCommit;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Z0, the `map` check (rule 19; intent-map-commit.ts decideMapDisclosure). First failure wins: the disclosure is
     * well-formed; the commitment is a 32-byte digest; params (absent = {}) hash to `action.params_digest`; the header is the
     * action's verb and fits the layout; header, cell and metrics open the commitment; the cell is the action's cell;
     * `in_grant`; metrics at index size - 2 and, with ε (`$maxResidualRiskPpm`), residual_risk_ppm <= ε. Never throws.
     * `$params` absent = undefined. @return array{ok:bool, cell?: list<int>, p_ppm?: int, residual_risk_ppm?: int, reason?: string}
     */
    public static function decideMapDisclosure(mixed $mapCommit, mixed $action, mixed $params, mixed $disclosure, mixed $maxResidualRiskPpm = null): array
    {
        try {
            if (($de = self::mapDisclosureError($disclosure)) !== null) {
                return self::bad("map disclosure malformed: $de");
            }
            if (!self::b32($mapCommit)) {
                return self::bad('the PCActn carries no map commitment');
            }
            /** @var Obj $disclosure */
            if (!self::isU($params) && !($params instanceof Obj)) {
                return self::bad('params must be an object');
            }
            $pobj = self::isU($params) ? new Obj() : $params;
            if (self::hashCanonical($pobj) !== self::m($action, 'params_digest')) {
                return self::bad('the params do not hash to action.params_digest');
            }
            $size = self::iv($disclosure->get('size'));
            $he = $disclosure->get('header');
            $h = $he->get('leaf');
            if ($h->get('verb') !== self::m($action, 'verb')) {
                return self::bad("the disclosed header is not the action's verb");
            }
            $first = self::iv($h->get('first'));
            if (!(self::iv($he->get('index')) < $first) || !($first + self::iv($h->get('cells')) <= $size - 2)) {
                return self::bad('the disclosed header does not fit the committed layout');
            }
            foreach (['header' => 'the header leaf', 'cell' => 'the cell leaf', 'metrics' => 'the metrics leaf'] as $k => $what) {
                if (!self::mapOpens($k, $disclosure->get($k), $size, $mapCommit)) {
                    return self::bad("$what does not open the map commitment");
                }
            }
            $w = self::mapCellOf($h, self::m($action, 'resource'), $pobj);
            if (isset($w['error'])) {
                return self::bad($w['error']);
            }
            $ce = $disclosure->get('cell');
            $c = $ce->get('leaf');
            $cc = $c->get('cell');
            $same = self::iv($ce->get('index')) === $first + $w['flat'] && $c->get('verb') === $h->get('verb') && count($cc) === count($w['cell']);
            foreach ($same ? $cc : [] as $i => $x) {
                if (self::iv($x) !== $w['cell'][$i]) {
                    $same = false;
                    break;
                }
            }
            if (!$same) {
                return self::bad("the disclosed cell is not the action's cell");
            }
            if ($c->get('in_grant') !== true) {
                return self::bad("the action's cell is outside the committed grant");
            }
            $me = $disclosure->get('metrics');
            if (self::iv($me->get('index')) !== $size - 2) {
                return self::bad('the disclosed metrics leaf is not at its committed position');
            }
            $risk = self::iv($me->get('leaf')->get('residual_risk_ppm'));
            if ($maxResidualRiskPpm !== null && !self::isU($maxResidualRiskPpm)) {
                $eps = self::f($maxResidualRiskPpm);
                if (!($eps !== null && $risk <= $eps)) {
                    return self::bad("the committed residual risk $risk ppm exceeds \u{03B5} = " . self::txt($maxResidualRiskPpm));
                }
            }
            return ['ok' => true, 'cell' => array_map(fn($x) => self::iv($x), $cc), 'p_ppm' => self::iv($c->get('p_ppm')), 'residual_risk_ppm' => $risk];
        } catch (\Throwable $e) {
            return self::bad('map error (fail closed): ' . $e->getMessage());
        }
    }
}
