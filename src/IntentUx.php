<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Question cards for human studies: a deterministic, structured form of a cell question, and the parser that turns card input into the
 * learner's answer. Rendering goes through IntentRender (labelOf, renderQuestion).
 */
final class IntentUx
{
    private static function js(mixed $v): string
    {
        return IntentWb::jsStr($v);
    }

    private static function plain(mixed $x): mixed
    {
        return WalletOmega::plain($x);
    }

    private static function cellIdx(mixed $q, int $k): int
    {
        $c = Js::opt($q, 'cell');
        $v = is_array($c) ? ($c[$k] ?? null) : null;
        $f = Js::num($v);
        if ($f === null || !is_finite($f) || $f != floor($f)) {
            throw new \OutOfRangeException('cell index out of range');
        }
        return (int)$f;
    }

    private static function factOf(mixed $d, int $i): Obj
    {
        require_once __DIR__ . '/IntentRender.php';
        $label = IntentRender::labelOf(Js::opt($d, 'path'));
        if (Js::opt($d, 'kind') === 'num') {
            $cells = IntentOmega::numCells($d);
            if ($i < 0 || $i >= count($cells)) {
                throw new \OutOfRangeException('cell index out of range');
            }
            $lo = $cells[$i]->get('lo');
            $hi = $cells[$i]->get('hi');
            $text = $lo == $hi ? 'exactly ' . self::js($lo)
                : 'any value from ' . self::js($lo) . ' to ' . self::js($hi) . ' (for example ' . self::js(IntentOmega::repValue($d, $i)) . ')';
            return Obj::of(['path' => Js::opt($d, 'path'), 'label' => $label, 'text' => $text]);
        }
        $values = Js::opt($d, 'values');
        if ($i < 0 || $i >= count($values)) {
            throw new \OutOfRangeException('cell index out of range');
        }
        $v = $values[$i];
        $kind = Js::opt($v, 'kind');
        $text = $kind === 'exact' ? '"' . Js::opt($v, 'value') . '"'
            : ($kind === 'prefix' ? 'anything under "' . Js::opt($v, 'value') . '" not named elsewhere'
                : 'any value not named anywhere in the grant or your request');
        return Obj::of(['path' => Js::opt($d, 'path'), 'label' => $label, 'text' => $text]);
    }

    /** The structured question card for a cell question {verb, cell}, with its digest. */
    public static function questionCard(mixed $omega, mixed $q, mixed $catalog = null): Obj
    {
        require_once __DIR__ . '/IntentRender.php';
        $omega = self::plain($omega);
        $q = self::plain($q);
        $vs = null;
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === Js::opt($q, 'verb')) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            throw new \InvalidArgumentException('questionCard: no verb ' . Js::opt($q, 'verb'));
        }
        $facts = [];
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            $facts[] = self::factOf($d, self::cellIdx($q, $k));
        }
        $partial = [];
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            if (Js::opt($d, 'kind') === 'num') {
                $c = IntentOmega::numCells($d);
                $i = self::cellIdx($q, $k);
                if ($i < 0 || $i >= count($c)) {
                    throw new \OutOfRangeException('cell index out of range');
                }
                $partial[] = Obj::of(['path' => Js::opt($d, 'path'), 'kind' => 'num', 'lo' => $c[$i]->get('lo'), 'hi' => $c[$i]->get('hi')]);
            } else {
                $opts = [];
                foreach (Js::opt($d, 'values') as $v) {
                    if (Js::opt($v, 'kind') === 'exact') {
                        $opts[] = Js::opt($v, 'value');
                    }
                }
                $partial[] = Obj::of(['path' => Js::opt($d, 'path'), 'kind' => 'cat', 'options' => $opts]);
            }
        }
        $body = Obj::of(['v' => 1, 'verb' => Js::opt($q, 'verb'), 'cell' => array_values(Js::opt($q, 'cell')),
            'sentence' => IntentRender::renderQuestion($vs, Js::opt($q, 'cell'), $catalog), 'facts' => $facts,
            'reversibility' => Js::opt($vs, 'reversibility'), 'answers' => ['yes', 'no', 'partly'], 'partial' => $partial]);
        $card = new Obj();
        foreach ($body->keys() as $k) {
            $card->set($k, $body->get($k));
        }
        $card->set('digest', IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/intent-card/v1', 'c' => $body])));
        return $card;
    }

    /** [...new Set(x.filter(nonempty string))]: x must be an array (the reference throws on anything else). @return list<string> */
    private static function strings(mixed $x): array
    {
        if (!is_array($x) || !array_is_list($x)) {
            throw new \TypeError('input.notFor.filter is not a function');
        }
        $out = [];
        foreach ($x as $v) {
            if (is_string($v) && $v !== '' && !in_array($v, $out, true)) {
                $out[] = $v;
            }
        }
        return $out;
    }

    private static function isIntNotNeg0(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && !($f == 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function sameValueZero(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) && Js::isNum($b)) {
            $x = Js::num($a);
            $y = Js::num($b);
            return $x == $y || (is_nan($x) && is_nan($y));
        }
        return $a === $b || ($a instanceof Obj && $a === $b);
    }

    /** [...new Set(x)]: null / undefined give the empty set, a string its characters, an array its items; anything else throws. @return list<mixed> */
    private static function setOf(mixed $x): array
    {
        if ($x === null) {
            return [];
        }
        if (is_string($x)) {
            $x = preg_split('//u', $x, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        if (!is_array($x) || !array_is_list($x)) {
            throw new \TypeError('object is not iterable');
        }
        $out = [];
        foreach ($x as $v) {
            $seen = false;
            foreach ($out as $w) {
                if (self::sameValueZero($v, $w)) {
                    $seen = true;
                    break;
                }
            }
            if (!$seen) {
                $out[] = $v;
            }
        }
        return $out;
    }

    private static function partial(string $path, array $rest): Obj
    {
        $o = Obj::of(['kind' => 'partial', 'path' => $path]);
        foreach ($rest as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    private static function part(array $a): Obj
    {
        return Obj::of($a);
    }

    /**
     * Turn card input into the learner's answer: yes -> 1, anything else without "partly" -> 0, "partly" -> a structured partial answer.
     * @return array{ok:bool,answer?:mixed,error?:string}
     */
    public static function parseCardAnswer(mixed $card, mixed $inp): array
    {
        $card = self::plain($card);
        $inp = self::plain($inp);
        $ans = Js::opt($inp, 'answer');
        if ($ans !== 'partly') {
            return ['ok' => true, 'answer' => $ans === 'yes' ? 1 : 0];
        }
        $has = static fn(string $k): bool => $inp instanceof Obj && $inp->has($k);
        if ($has('newField')) {
            $nf = Js::opt($inp, 'newField');
            if (!(is_string($nf) && preg_match('/\A(?:action\.params\.[a-z_][a-z0-9_]*|action\.resource)\z/', $nf) === 1)) {
                return ['ok' => false, 'error' => 'unknown field ' . self::js($nf)];
            }
            foreach (Js::opt($card, 'partial') as $s) {
                if (Js::opt($s, 'path') === $nf) {
                    return ['ok' => false, 'error' => "$nf is already on the card; answer partly for it directly"];
                }
            }
            $vals = self::strings($has('notFor') ? Js::opt($inp, 'notFor') : Jsx::$U);
            if (count($vals) === 0) {
                return ['ok' => false, 'error' => 'name at least one value'];
            }
            $newVals = array_map(static fn(string $v) => Obj::of(['kind' => 'exact', 'value' => $v]), $vals);
            $newVals[] = Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER]);
            return ['ok' => true, 'answer' => self::partial($nf, ['newDim' => Obj::of(['kind' => 'cat', 'path' => $nf, 'values' => $newVals]),
                'parts' => [self::part(['values' => $vals, 'y' => 0]), self::part(['other' => true, 'y' => 1])]])];
        }
        $path = $has('path') ? Js::opt($inp, 'path') : Jsx::$U;
        $slot = null;
        foreach (Js::opt($card, 'partial') as $s) {
            if ($path === Js::opt($s, 'path')) {
                $slot = $s;
                break;
            }
        }
        if ($slot === null) {
            return ['ok' => false, 'error' => 'the card has no field ' . ($path instanceof Undef ? 'undefined' : self::js($path))];
        }
        $sp = Js::opt($slot, 'path');
        if (Js::opt($slot, 'kind') === 'num') {
            $lo = Js::opt($slot, 'lo');
            $hi = Js::opt($slot, 'hi');
            $inRange = static fn(mixed $x): bool => self::isIntNotNeg0($x) && $x >= $lo && $x <= $hi;
            if ($has('upTo')) {
                $x = Js::opt($inp, 'upTo');
                if (!$inRange($x) || $x == $hi) {
                    return ['ok' => false, 'error' => 'upTo must be an integer in [' . self::js($lo) . ', ' . self::js($hi - 1) . ']'];
                }
                return ['ok' => true, 'answer' => self::partial($sp, ['cuts' => [$x], 'parts' => [self::part(['lo' => $lo, 'hi' => $x, 'y' => 1]), self::part(['lo' => $x + 1, 'hi' => $hi, 'y' => 0])]])];
            }
            if ($has('from')) {
                $x = Js::opt($inp, 'from');
                if (!$inRange($x) || $x == $lo) {
                    return ['ok' => false, 'error' => 'from must be an integer in [' . self::js($lo + 1) . ', ' . self::js($hi) . ']'];
                }
                return ['ok' => true, 'answer' => self::partial($sp, ['cuts' => [$x], 'parts' => [self::part(['lo' => $lo, 'hi' => $x - 1, 'y' => 0]), self::part(['lo' => $x, 'hi' => $hi, 'y' => 1])]])];
            }
            if ($has('except')) {
                $ex = self::setOf(Js::opt($inp, 'except'));
                if (count(array_filter($ex, static fn($v) => !self::isIntNotNeg0($v))) === 0) {
                    sort($ex);
                }
                if (count($ex) === 0 || count(array_filter($ex, static fn($v) => !$inRange($v))) > 0) {
                    return ['ok' => false, 'error' => 'except values must be integers in [' . self::js($lo) . ', ' . self::js($hi) . ']'];
                }
                $parts = array_map(static fn($x) => self::part(['lo' => $x, 'hi' => $x, 'y' => 0]), $ex);
                $parts[] = self::part(['lo' => $lo, 'hi' => $hi, 'y' => 1]);
                return ['ok' => true, 'answer' => self::partial($sp, ['cuts' => $ex, 'parts' => $parts])];
            }
            return ['ok' => false, 'error' => 'a numeric partly answer needs upTo, from or except'];
        }
        if (!$has('notFor')) {
            return ['ok' => false, 'error' => 'a categorical partly answer needs notFor'];
        }
        $vals = self::strings(Js::opt($inp, 'notFor'));
        if (count($vals) === 0) {
            return ['ok' => false, 'error' => 'name at least one value'];
        }
        return ['ok' => true, 'answer' => self::partial($sp, ['values' => $vals, 'parts' => [self::part(['values' => $vals, 'y' => 0]), self::part(['other' => true, 'y' => 1])]])];
    }
}
