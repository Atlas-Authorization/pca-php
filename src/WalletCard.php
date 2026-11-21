<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Wallet.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render from the
 * wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a closed-enum
 * reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured clarification request
 * with max-information cell selection. Input is an Obj or an assoc array with the reference's member names (omega, verb, coords, site,
 * statementText, reversibility, units, action, friction, kind, reason, locale, catalog). Strings are WTF-8: every JavaScript string
 * operation here is spelled over UTF-8 bytes or UTF-16 units so lone surrogates behave as in the reference.
 */
final class WalletCard
{
    public const CARD_DOMAIN = 'atlas-pca/intent-card/v2';
    public const CLARIFY_REASONS = ['ambiguous_parameter', 'multiple_options', 'price_changed', 'constraint_conflict', 'missing_value', 'other'];
    public const REASON_LABELS = [
        'ambiguous_parameter' => 'Your agent found a detail your request did not settle.',
        'multiple_options' => 'Your agent found several options that match.',
        'price_changed' => 'Your agent found that a price changed.',
        'constraint_conflict' => 'Your agent found that two parts of your request conflict.',
        'missing_value' => 'Your agent needs a value your request did not give.',
        'other' => 'Your agent needs a decision before it continues.',
    ];
    public const MAX_CANDIDATES = 8;
    private const MAX_VALUES = 64;
    private const MAX_STRING = 256;
    private const CURRENCY_SYMBOL = ['USD' => '$', 'EUR' => "\u{20AC}", 'GBP' => "\u{00A3}", 'JPY' => "\u{00A5}"];
    private const REV_TEXT = ['reversible' => 'that can be undone', 'rate_limited' => 'that is rate-limited', 'irreversible' => 'that cannot be undone'];
    /** The JavaScript \s class over UTF-8 bytes. */
    private const WS = '(?:[\t\n\x0b\x0c\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';

    private static ?Catalog $defaultCatalog = null;

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static function str(mixed $v): string
    {
        if (!is_string($v)) {
            throw new \TypeError('a string is required');
        }
        return $v;
    }

    private static function f(mixed $x): float
    {
        $f = Js::num($x);
        if ($f === null) {
            throw new \TypeError('a number is required');
        }
        return $f;
    }

    private static function negZero(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    private static function d(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    /** Strip control characters, collapse whitespace, cap length (for the principal's own words and the site's name). */
    public static function cleanText(mixed $s, int $mx): string
    {
        $s = self::str($s);
        $t = preg_replace('/[\x00-\x1f\x7f]|\xC2[\x80-\x9F]|\xE2\x80[\x8B-\x8F\xA8-\xAE]|\xE2\x81[\xA6-\xA9]/', ' ', $s) ?? $s;
        $t = preg_replace('/' . self::WS . '+/', ' ', $t) ?? $t;
        $t = preg_replace('/\A' . self::WS . '+|' . self::WS . '+\z/', '', $t) ?? $t;
        return WalletOmega::u16len($t) <= $mx ? $t : WalletOmega::u16slice($t, 0, $mx - 1) . "\u{2026}";
    }

    /** The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name). */
    public static function last4(mixed $s): string
    {
        $t = preg_replace('/[^A-Za-z0-9]/', '', self::str($s)) ?? '';
        return strtoupper(strlen($t) > 4 ? substr($t, -4) : $t);
    }

    private static function group(int $n): string
    {
        return preg_replace('/\B(?=(\d{3})+(?!\d))/', ',', (string)$n) ?? (string)$n;
    }

    private static function isMoney(mixed $unit): bool
    {
        return Wallet::isDict($unit) && Js::opt($unit, 'kind') === 'money';
    }

    /** The money exponent, clamped to [0, 6]; a NaN exponent throws (the reference computes with NaN, which cannot be a BigInt). */
    private static function exponent(mixed $unit): int
    {
        $e = Jsx::toNum(Wallet::g($unit, 'exponent'));
        if (is_nan($e)) {
            throw new \InvalidArgumentException('NaN exponent');
        }
        if (is_infinite($e)) {
            return $e > 0 ? 6 : 0;
        }
        return (int)max(0.0, min(6.0, floor($e)));
    }

    private static function symbol(mixed $unit): string
    {
        $cur = Wallet::g($unit, 'currency');
        return is_string($cur) && isset(self::CURRENCY_SYMBOL[$cur]) ? self::CURRENCY_SYMBOL[$cur] : Jsx::str($cur) . ' ';
    }

    /** Thousands grouping with commas, independent of any locale data (cards render identically anywhere). */
    public static function formatNumber(mixed $x, mixed $unit = null): string
    {
        $f = self::f($x);
        $neg = $f < 0;
        $a = abs((int)$f); // trunc
        if (self::isMoney($unit)) {
            try {
                $e = self::exponent($unit);
            } catch (\InvalidArgumentException) {
                // an exponent that is not a number: the reference renders "NaN" for the whole part and no fraction
                return ($neg ? '-' : '') . self::symbol($unit) . 'NaN';
            }
            $div = 10 ** $e;
            $whole = self::group(intdiv($a, $div));
            $frac = $e > 0 ? '.' . str_pad((string)($a % $div), $e, '0', STR_PAD_LEFT) : '';
            return ($neg ? '-' : '') . self::symbol($unit) . $whole . $frac;
        }
        return ($neg ? '-' : '') . self::group($a);
    }

    private static function dimLabel(string $path): string
    {
        if (preg_match('/\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z/', $path, $m) === 1) {
            return strtr($m[1], '_.', '  ') . ' (running total for this task)';
        }
        if (preg_match('/\Aenv\.world\.([A-Za-z0-9_.-]+)\z/', $path, $m) === 1) {
            return strtr($m[1], '_.', '  ') . ' (from a signed fact)';
        }
        if (preg_match('/\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z/', $path, $m) === 1) {
            return 'state of ' . strtr($m[1], '_.', '  ');
        }
        return WalletOmega::labelOf($path);
    }

    private static function isProvPath(string $p): bool
    {
        return str_starts_with($p, 'env.prov.');
    }

    private static function numFact(mixed $d, array $ids, mixed $unit, mixed $actionValue): string
    {
        $cells = WalletOmega::numCells($d);
        $lo = $cells[$ids[0]]['lo'];
        $hi = $cells[$ids[count($ids) - 1]]['hi'];
        $dlo = self::d($d, 'lo');
        $dhi = self::d($d, 'hi');
        if ($lo == $hi) {
            $rng = 'exactly ' . self::formatNumber($lo, $unit);
        } elseif ($lo == $dlo && $hi == $dhi) {
            $rng = 'any value';
        } elseif ($hi == $dhi) {
            $rng = self::formatNumber($lo, $unit) . ' or more';
        } elseif ($lo == $dlo) {
            $rng = 'up to ' . self::formatNumber($hi, $unit);
        } else {
            $rng = self::formatNumber($lo, $unit) . " \u{2013} " . self::formatNumber($hi, $unit);
        }
        $ex = Js::isNum($actionValue) && is_finite((float)Js::num($actionValue)) ? ' (this action: ' . self::formatNumber($actionValue, $unit) . ')' : '';
        return $rng . $ex;
    }

    private static function catValueText(mixed $d, int $i): string
    {
        $v = self::d($d, 'values')[$i];
        $kind = self::d($v, 'kind');
        if ($kind === 'exact') {
            return '"' . self::cleanText(self::d($v, 'value'), 64) . '"';
        }
        if ($kind === 'prefix') {
            return 'anything starting with "' . self::cleanText(self::d($v, 'value'), 64) . '"';
        }
        return 'a value not named in your request';
    }

    private static function catFact(mixed $d, array $ids, mixed $actionValue): string
    {
        $parts = array_map(fn($i) => self::catValueText($d, $i), $ids);
        if (count($parts) === 1) {
            $st = $parts[0];
        } else {
            $st = implode(', ', array_slice($parts, 0, -1)) . ' or ' . ($parts ? $parts[count($parts) - 1] : 'undefined');
        }
        if (!is_string($actionValue)) {
            return $st;
        }
        $named = false;
        foreach (self::d($d, 'values') as $v) {
            if (self::d($v, 'kind') === 'exact' && self::d($v, 'value') === $actionValue) {
                $named = true;
                break;
            }
        }
        return $st . ' (this action: ' . ($named ? '"' . self::cleanText($actionValue, 64) . '"' : 'a value ending in "' . self::last4($actionValue) . '"') . ')';
    }

    private static function bannerFor(string $path, array $levels): ?string
    {
        $w = Wallet::worstProvenance($levels);
        $label = self::dimLabel($path);
        if ($w === 'web') {
            return "This $label was suggested by content on a web page, not by you.";
        }
        if ($w === 'tool') {
            return "This $label came from a tool result, not from you.";
        }
        if ($w === 'agent') {
            return "This $label was chosen by your agent, not taken from your request or from the site.";
        }
        return null;
    }

    /** @return list<string> */
    private static function provLevels(mixed $d, array $ids): array
    {
        $out = [];
        foreach ($ids as $i) {
            foreach (preg_split('/[|,]/', Wallet::catLabel($d, $i)) ?: [] as $p) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /** `action.values[path]` for a value that may be any JSON: a missing or null `values` throws, a non-object has no members. */
    private static function vget(mixed $values, string $path): mixed
    {
        if ($values === null || $values instanceof Undef) {
            throw new \TypeError('Cannot read properties of undefined');
        }
        return Js::has($values, $path) ? Js::opt($values, $path) : null;
    }

    private static function typedTarget(mixed $vs, mixed $action, mixed $units): ?Obj
    {
        if (!Jsx::truthy($action)) {
            return null;
        }
        $values = Wallet::g($action, 'values');
        $dims = [];
        foreach (self::d($vs, 'dims') as $d) {
            if (!self::isProvPath((string)self::d($d, 'path'))) {
                $dims[] = $d;
            }
        }
        $nums = [];
        foreach ($dims as $d) {
            if (self::d($d, 'kind') === 'num' && Js::isNum(self::vget($values, (string)self::d($d, 'path')))) {
                $nums[] = $d;
            }
        }
        $pick = null;
        foreach ($nums as $d) {
            if (self::isMoney(Wallet::isDict($units) ? Wallet::g($units, (string)self::d($d, 'path')) : null)) {
                $pick = $d;
                break;
            }
        }
        $pick ??= $nums[0] ?? null;
        if ($pick !== null) {
            $p = (string)self::d($pick, 'path');
            return Obj::of(['path' => $p, 'mode' => 'number', 'prompt' => 'To allow it, type the ' . self::dimLabel($p) . ' of this action shown above.']);
        }
        foreach ($dims as $d) {
            if (self::d($d, 'kind') === 'cat') {
                $v = self::vget($values, (string)self::d($d, 'path'));
                if (is_string($v) && strlen(self::last4($v)) === 4) {
                    $p = (string)self::d($d, 'path');
                    return Obj::of(['path' => $p, 'mode' => 'last4', 'prompt' => 'To allow it, type the last 4 letters or digits of the ' . self::dimLabel($p) . '.']);
                }
            }
        }
        return null;
    }

    private const NO = ['id' => 'no', 'label' => 'No'];
    private const PARTLY = ['id' => 'partly', 'label' => "Partly\u{2026}"];

    /** @return list<Obj>|null */
    private static function answersOf(mixed $friction): ?array
    {
        // ANSWERS[friction]: a property key, so a one-element array of a tier name selects that tier too
        $key = is_string($friction) ? $friction : (is_array($friction) && array_is_list($friction) && count($friction) === 1 && is_string($friction[0]) ? $friction[0] : null);
        $yes = ['tap' => 'Yes', 'hold' => 'Press and hold to allow', 'typed' => 'Yes, type the value to confirm', 'device' => 'Yes, confirm with your security key'];
        if ($key === null || !isset($yes[$key])) {
            return null;
        }
        return [Obj::of(self::NO), Obj::of(self::PARTLY), Obj::of(['id' => 'yes', 'label' => $yes[$key]])];
    }

    private static function lowerFirst(string $s): string
    {
        if ($s === '') {
            return $s;
        }
        $c = mb_substr($s, 0, 1, 'UTF-8');
        if ($c === "\n" || $c === "\r" || $c === "\u{2028}" || $c === "\u{2029}") {
            return $s;
        }
        return mb_strtolower($c, 'UTF-8') . substr($s, strlen($c));
    }

    /** Render the trusted question card: ['ok' => true, 'card' => Obj] or ['ok' => false, 'reason' => ...]. */
    public static function renderCard(mixed $inp): array
    {
        $loc = Wallet::g($inp, 'locale');
        if ($loc instanceof Undef || $loc === null) {
            $loc = 'en';
        }
        if ($loc !== 'en') {
            return ['ok' => false, 'reason' => 'unsupported locale ' . Jsx::str(Wallet::g($inp, 'locale'))];
        }
        $kind = Wallet::g($inp, 'kind');
        $reason = Wallet::g($inp, 'reason');
        if ($kind === 'clarification' && $reason instanceof Undef) {
            return ['ok' => false, 'reason' => 'a clarification card needs a reason'];
        }
        if (!($reason instanceof Undef) && !(is_string($reason) && in_array($reason, self::CLARIFY_REASONS, true))) {
            return ['ok' => false, 'reason' => 'unknown clarification reason'];
        }
        $verb = Wallet::g($inp, 'verb');
        $r = Wallet::resolveCoords(Wallet::req($inp, 'omega'), $verb, Wallet::g($inp, 'coords'));
        if (!$r['ok']) {
            return $r;
        }
        $vs = $r['vs'];
        $box = $r['box'];
        $action = Wallet::g($inp, 'action');
        if (Jsx::truthy($action) && Wallet::g($action, 'verb') !== $verb) {
            return ['ok' => false, 'reason' => 'the action is for another verb'];
        }
        $cat = Js::opt($inp, 'catalog');
        $catalog = $cat instanceof Catalog ? $cat : (self::$defaultCatalog ??= new Catalog());
        $site = Wallet::req($inp, 'site');
        $siteName = self::cleanText(Wallet::req($site, 'name'), 64);
        if ($siteName === '') {
            $siteName = self::cleanText(Wallet::req($site, 'origin'), 64);
        }
        $said = Js::has($inp, 'statementText') ? self::cleanText(Js::opt($inp, 'statementText'), 280) : '';
        if ($kind === 'clarification') {
            $header = $said !== '' ? "Your agent needs a decision for your request \"$said\"" : 'Your agent needs a decision';
        } else {
            $header = $said !== '' ? "$siteName asks on behalf of your request \"$said\"" : "$siteName asks for your confirmation";
        }
        $verbS = self::str($verb);
        $spec = $catalog->get($verbS);
        if ($spec) {
            $what = self::lowerFirst(preg_replace('/\.\z/', '', (string)$spec['description']) ?? '');
        } else {
            $what = 'the action "' . self::cleanText($verbS, 64) . "\" on $siteName";
        }
        $rev = Js::opt($inp, 'reversibility');
        if ($rev === null) {
            $rev = Js::opt($vs, 'reversibility');
        }
        $sentence = "Allow $what, " . (is_string($rev) && isset(self::REV_TEXT[$rev]) ? self::REV_TEXT[$rev] : 'undefined') . ', with:';
        $units = Js::opt($inp, 'units');
        $facts = [];
        $banners = [];
        $partial = [];
        foreach (self::d($vs, 'dims') as $k => $d) {
            $ids = $box[$k];
            $path = (string)self::d($d, 'path');
            if (self::isProvPath($path)) {
                if (self::d($d, 'kind') !== 'cat') {
                    continue;
                }
                $b = self::bannerFor(substr($path, strlen('env.prov.')), self::provLevels($d, $ids));
                if ($b !== null && $b !== '') {
                    $banners[] = $b;
                }
                continue;
            }
            $av = null;
            if ($action !== null && !($action instanceof Undef)) {
                $av = self::vget(Wallet::g($action, 'values'), $path);
            }
            $unit = Wallet::isDict($units) ? Wallet::g($units, $path) : null;
            $unit = $unit instanceof Undef ? null : $unit;
            if (self::d($d, 'kind') === 'num') {
                $facts[] = Obj::of(['key' => $path, 'label' => self::dimLabel($path), 'text' => self::numFact($d, $ids, $unit, $av)]);
                $cells = WalletOmega::numCells($d);
                $partial[] = Obj::of(['path' => $path, 'kind' => 'num', 'lo' => $cells[$ids[0]]['lo'], 'hi' => $cells[$ids[count($ids) - 1]]['hi']]);
            } else {
                $facts[] = Obj::of(['key' => $path, 'label' => self::dimLabel($path), 'text' => self::catFact($d, $ids, $av)]);
                $options = [];
                foreach ($ids as $i) {
                    $v = self::d($d, 'values')[$i];
                    if (self::d($v, 'kind') === 'exact') {
                        $options[] = self::d($v, 'value');
                    }
                }
                if (count($options) > 1) {
                    $partial[] = Obj::of(['path' => $path, 'kind' => 'cat', 'options' => $options]);
                }
            }
        }
        $friction = Wallet::g($inp, 'friction');
        $typed = Wallet::frictionRank($friction) >= Wallet::frictionRank('typed') ? self::typedTarget($vs, $action, $units) : null;
        $site2 = Obj::of(['origin' => self::cleanText(Wallet::req($site, 'origin'), 256), 'name' => $siteName]);
        $body = Obj::of(['v' => 2, 'verb' => $verb, 'coords' => Wallet::jsPlain(Wallet::req($inp, 'coords')), 'locale' => 'en', 'site' => $site2, 'header' => $header]);
        if (!($kind instanceof Undef)) {
            $body->set('kind', $kind);
        }
        if (!($reason instanceof Undef)) {
            $body->set('reason_label', self::REASON_LABELS[$reason]);
        }
        $body->set('sentence', $sentence);
        $body->set('facts', $facts);
        $body->set('banners', $banners);
        if (!($friction instanceof Undef)) {
            $body->set('friction', $friction);
        }
        $answers = self::answersOf($friction);
        if ($answers !== null) {
            $body->set('answers', $answers);
        }
        if ($typed !== null) {
            $body->set('typed', $typed);
        }
        $body->set('partial', $partial);
        $out = new Obj();
        foreach ($body->keys() as $k) {
            $out->set($k, $body->get($k));
        }
        $out->set('rendered_digest', self::cardDigest($body));
        return ['ok' => true, 'card' => $out];
    }

    /** The content address of a card body (everything but `rendered_digest`). */
    public static function cardDigest(mixed $body): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::CARD_DOMAIN, 'c' => Wallet::jsPlain($body)]));
    }

    /** Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed. */
    public static function cardDigestMatches(mixed $card): bool
    {
        if (!($card instanceof Obj)) {
            throw new \TypeError('card is not an object');
        }
        $body = new Obj();
        foreach ($card->keys() as $k) {
            if ($k !== 'rendered_digest') {
                $body->set($k, $card->get($k));
            }
        }
        $want = Wallet::g($card, 'rendered_digest');
        return is_string($want) && self::cardDigest($body) === $want;
    }

    private static function line(mixed $v): string
    {
        return is_string($v) ? $v : (is_array($v) || $v instanceof Obj ? throw new \TypeError('a string is required') : Jsx::str($v));
    }

    /** The plain text of a card, line by line (what a screen reader or a text channel shows). */
    public static function cardText(mixed $card): string
    {
        $lines = [self::str(Wallet::req($card, 'header'))];
        if (Jsx::truthy(Js::opt($card, 'reason_label'))) {
            $lines[] = self::str($card instanceof Obj ? $card->get('reason_label') : Js::opt($card, 'reason_label'));
        }
        $lines[] = self::str(Wallet::req($card, 'sentence'));
        foreach (self::arr(Wallet::req($card, 'facts')) as $f) {
            $lines[] = '- ' . self::line(Wallet::req($f, 'label')) . ': ' . self::line(Wallet::req($f, 'text'));
        }
        foreach (self::arr(Wallet::req($card, 'banners')) as $b) {
            $lines[] = self::str($b);
        }
        if (Jsx::truthy(Js::opt($card, 'typed'))) {
            $lines[] = self::str(Wallet::req(Js::opt($card, 'typed'), 'prompt'));
        }
        $labels = [];
        foreach (self::arr(Wallet::req($card, 'answers')) as $a) {
            $labels[] = '[' . self::line(Wallet::req($a, 'label')) . ']';
        }
        $lines[] = implode(' ', $labels);
        return implode("\n", $lines);
    }

    /** @return list<mixed> */
    private static function arr(mixed $v): array
    {
        if (!is_array($v) || !array_is_list($v)) {
            throw new \TypeError('not iterable');
        }
        return $v;
    }

    private static function inRange(mixed $slot, mixed $x): bool
    {
        if (!Js::isNum($x)) {
            return false;
        }
        $f = (float)Js::num($x);
        return is_finite($f) && $f == floor($f) && !self::negZero($x) && $f >= self::f(Js::opt($slot, 'lo')) && $f <= self::f(Js::opt($slot, 'hi'));
    }

    /** Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only. */
    public static function partialError(mixed $card, mixed $p): ?string
    {
        if (!Wallet::isDict($p)) {
            throw new \TypeError('p is not an object');
        }
        $path = Wallet::g($p, 'path');
        $slot = null;
        foreach (self::arr(Wallet::req($card, 'partial')) as $s) {
            if (Wallet::req($s, 'path') === $path) {
                $slot = $s;
                break;
            }
        }
        if ($slot === null) {
            return 'the card has no field ' . Jsx::str($path);
        }
        if (Wallet::req($slot, 'kind') === 'num') {
            $lo = (int)self::f(Wallet::req($slot, 'lo'));
            $hi = (int)self::f(Wallet::req($slot, 'hi'));
            if (Js::has($p, 'upTo')) {
                $x = Js::opt($p, 'upTo');
                return self::inRange($slot, $x) && self::f($x) < $hi ? null : sprintf('upTo must be an integer in [%d, %d]', $lo, $hi - 1);
            }
            if (Js::has($p, 'from')) {
                $x = Js::opt($p, 'from');
                return self::inRange($slot, $x) && self::f($x) > $lo ? null : sprintf('from must be an integer in [%d, %d]', $lo + 1, $hi);
            }
            if (Js::has($p, 'except')) {
                $ex = Js::opt($p, 'except');
                $okAll = false;
                if (is_array($ex) && array_is_list($ex)) {
                    $okAll = count($ex) > 0;
                    foreach ($ex as $x) {
                        $okAll = $okAll && self::inRange($slot, $x);
                    }
                } elseif (!is_string($ex)) {
                    throw new \TypeError('object of this type has no len()');
                }
                return $okAll ? null : sprintf('except values must be integers in [%d, %d]', $lo, $hi);
            }
            return 'a numeric partly answer needs upTo, from or except';
        }
        if (!Js::has($p, 'notFor')) {
            return 'a categorical partly answer needs notFor';
        }
        $vals = [];
        foreach (self::arr(Js::opt($p, 'notFor')) as $v) {
            if (!in_array($v, $vals, true)) {
                $vals[] = $v;
            }
        }
        $options = self::arr(Wallet::req($slot, 'options'));
        $all = count($vals) > 0;
        foreach ($vals as $v) {
            $all = $all && in_array($v, $options, true);
        }
        if (!$all) {
            return 'notFor must name values shown on the card';
        }
        if (count($vals) === count($options)) {
            return 'excluding every value is a "No"';
        }
        return null;
    }

    /** Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money). */
    public static function normalizeTyped(mixed $inp, mixed $mode, mixed $unit = null): ?string
    {
        $s = self::str($inp);
        if ($mode === 'last4') {
            $t = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $s) ?? '');
            return strlen($t) === 4 ? $t : null;
        }
        $strip = '(?:' . substr(self::WS, 3, -1) . '|,|\$|\xE2\x82\xAC|\xC2\xA3|\xC2\xA5)';
        $t = preg_replace('/' . $strip . '/', '', $s) ?? $s;
        $t = preg_replace('/\A[A-Za-z]{3}/', '', $t) ?? $t;
        if (preg_match('/\A(-?)([0-9]+)(?:\.([0-9]+))?\z/', $t, $m) !== 1) {
            return null;
        }
        $e = self::isMoney($unit) ? self::exponent($unit) : 0;
        $frac = $m[3] ?? '';
        if (strlen($frac) > $e) {
            return null;
        }
        $minor = gmp_add(gmp_mul(gmp_init($m[2], 10), gmp_pow(10, $e)), $frac !== '' ? gmp_init(str_pad($frac, $e, '0', STR_PAD_RIGHT), 10) : gmp_init(0));
        return ($m[1] === '-' && gmp_cmp($minor, 0) !== 0 ? '-' : '') . gmp_strval($minor);
    }

    /** The normalized value the human must type for this card and action (what a site or auditor recomputes). */
    public static function expectedTyped(mixed $card, mixed $action): ?string
    {
        if (!Wallet::isDict($card)) {
            throw new \TypeError('card is not an object');
        }
        $typed = Js::opt($card, 'typed');
        if (!Jsx::truthy($typed)) {
            return null;
        }
        $v = self::vget(Js::has($action, 'values') ? Js::opt($action, 'values') : Jsx::$U, (string)Wallet::req($typed, 'path'));
        if (Wallet::req($typed, 'mode') === 'last4') {
            return is_string($v) && strlen(self::last4($v)) === 4 ? self::last4($v) : null;
        }
        return Js::isNum($v) && WalletOmega::isSafeInt($v) && !self::negZero($v) ? (string)(int)self::f($v) : null;
    }

    // ---- agent-initiated clarification --------------------------------------------------------------------------------------

    /** Strict parse of a clarification body: ['ok' => true, 'request' => ...] or ['ok' => false, 'error' => ...]. Never throws. */
    public static function parseClarifyRequest(mixed $body): array
    {
        if (!Wallet::isObj($body)) {
            return ['ok' => false, 'error' => 'body must be an object'];
        }
        foreach (Wallet::dictKeys($body) as $k) {
            if ($k !== 'candidates' && $k !== 'reason') {
                return ['ok' => false, 'error' => "unknown member \"$k\" (clarifications carry no text)"];
            }
        }
        $reason = Js::opt($body, 'reason');
        if (!is_string($reason) || !in_array($reason, self::CLARIFY_REASONS, true)) {
            return ['ok' => false, 'error' => 'reason must be one of ' . implode(', ', self::CLARIFY_REASONS)];
        }
        $cands = Js::opt($body, 'candidates');
        if (!is_array($cands) || !array_is_list($cands) || count($cands) === 0 || count($cands) > self::MAX_CANDIDATES) {
            return ['ok' => false, 'error' => 'candidates must be 1..' . self::MAX_CANDIDATES . ' structured actions'];
        }
        $out = [];
        foreach ($cands as $i => $c) {
            if (!Wallet::isObj($c)) {
                return ['ok' => false, 'error' => "candidates[$i] must be an object"];
            }
            foreach (Wallet::dictKeys($c) as $k) {
                if ($k !== 'verb' && $k !== 'values') {
                    return ['ok' => false, 'error' => "candidates[$i] has an unknown member \"$k\""];
                }
            }
            $verb = Js::opt($c, 'verb');
            if (!is_string($verb) || WalletOmega::u16len($verb) === 0 || WalletOmega::u16len($verb) > 128) {
                return ['ok' => false, 'error' => "candidates[$i].verb must be a non-empty string"];
            }
            if (!Wallet::isObj(Js::opt($c, 'values'))) {
                return ['ok' => false, 'error' => "candidates[$i].values must be an object"];
            }
            $entries = Wallet::entries(Js::opt($c, 'values'));
            if (count($entries) > self::MAX_VALUES) {
                return ['ok' => false, 'error' => "candidates[$i] has too many values"];
            }
            $values = new Obj();
            foreach ($entries as [$p, $v]) {
                if (preg_match('/\A[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\z/i', $p) !== 1) {
                    return ['ok' => false, 'error' => "candidates[$i] has a malformed path"];
                }
                if (!($p === 'action.resource' || str_starts_with($p, 'action.params.'))) {
                    return ['ok' => false, 'error' => "candidates[$i].values may only name action.params.* or action.resource"];
                }
                if (Js::isNum($v)) {
                    if (!WalletOmega::isSafeInt($v) || self::negZero($v)) {
                        return ['ok' => false, 'error' => "candidates[$i].values.$p must be a safe integer"];
                    }
                } elseif (!is_string($v) || WalletOmega::u16len($v) > self::MAX_STRING) {
                    return ['ok' => false, 'error' => "candidates[$i].values.$p must be a string (\u{2264} " . self::MAX_STRING . ') or an integer'];
                }
                $values->set($p, $v);
            }
            $out[] = Obj::of(['verb' => $verb, 'values' => $values]);
        }
        return ['ok' => true, 'request' => Obj::of(['candidates' => $out, 'reason' => $reason])];
    }

    /** Expected information gain of asking a cell with acceptance p under asymmetric noise (bits). */
    public static function informationGain(mixed $p, mixed $etaPos, mixed $etaNeg): float
    {
        $p = self::f($p);
        $ep = self::f($etaPos);
        $en = self::f($etaNeg);
        $py = $p * (1 - $en) + (1 - $p) * $ep;
        return Wallet::binEnt($py) - ($p * Wallet::binEnt($en) + (1 - $p) * Wallet::binEnt($ep));
    }

    /**
     * Dry-run verdicts for each candidate and the one cell worth asking, if any. `$inp` (assoc array): omega, view (['p', 'vetoed',
     * 'outsideCeiling'] Closures over (verb, idx)), candidates, optional lift Closure, asked (array<string,true> of `verb|i,j,..`), etaPos,
     * etaNeg and an optional HarmModel under `harm`.
     * @return array{verdicts:list<array<string,mixed>>,ask:?array<string,mixed>}
     */
    public static function planClarification(array $inp): array
    {
        $omega = $inp['omega'];
        $view = $inp['view'];
        $lift = $inp['lift'] ?? null;
        $harm = $inp['harm'] ?? WalletOmega::defaultHarm();
        $verdicts = [];
        $best = null;
        $seen = [];
        foreach ($inp['candidates'] as $index => $cand) {
            $at = Wallet::cellOfAction($omega, $lift ? $lift($cand) : $cand);
            if ($at === null) {
                $verdicts[] = ['index' => $index, 'verdict' => 'outside'];
                continue;
            }
            $vs = $at['vs'];
            $idx = $at['idx'];
            $verb = Js::opt($vs, 'verb');
            if ($view['outsideCeiling']($verb, $idx) || $view['vetoed']($verb, $idx)) {
                $verdicts[] = ['index' => $index, 'verdict' => 'denied'];
                continue;
            }
            $p = $view['p']($verb, $idx);
            if ($p <= 0) {
                $verdicts[] = ['index' => $index, 'verdict' => 'denied'];
                continue;
            }
            if ($p >= 1) {
                $verdicts[] = ['index' => $index, 'verdict' => 'admitted'];
                continue;
            }
            $key = Wallet::cellKey($verb, $idx);
            if (isset($inp['asked'][$key])) {
                $verdicts[] = ['index' => $index, 'verdict' => 'asked'];
                continue;
            }
            $verdicts[] = ['index' => $index, 'verdict' => 'uncertain'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $ig = self::informationGain($p, $inp['etaPos'], $inp['etaNeg']);
            $s = WalletOmega::cellStats($vs, $idx, $harm);
            $c2 = ['index' => $index, 'verb' => $verb, 'idx' => $idx, 'p' => $p, 'ig' => $ig, 'weight' => $s['mass'] * $s['harm'], 'flat' => Wallet::flatIndex($vs, $idx)];
            if ($best === null || $c2['ig'] > $best['ig'] + 1e-12
                || (abs($c2['ig'] - $best['ig']) <= 1e-12 && ($c2['weight'] > $best['weight'] || ($c2['weight'] == $best['weight'] && $c2['flat'] < $best['flat'])))) {
                $best = $c2;
            }
        }
        $ask = $best === null ? null : ['index' => $best['index'], 'verb' => $best['verb'], 'idx' => $best['idx'], 'p' => $best['p'], 'ig' => $best['ig']];
        return ['verdicts' => $verdicts, 'ask' => $ask];
    }
}
