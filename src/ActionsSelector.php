<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Approval.php';
require_once __DIR__ . '/Js.php';

/**
 * Trait selectors and the registry-growth semantics (selector.ts of pca-actions). A selector is an Obj: `{k: trait, id}`, `{k: all_of | any_of, ids}`,
 * `{k: not, s}` or `{k: and, a, b}`. A closure is the list of trait ids an action carries.
 */
final class ActionsSelector
{
    /** @param list<string> $closure */
    public static function selectorMatches(mixed $s, array $closure): ?bool
    {
        $cl = array_flip($closure);
        $k = Js::opt($s, 'k');
        switch ($k) {
            case 'trait':
                return isset($cl[Js::opt($s, 'id')]);
            case 'all_of':
            case 'any_of':
                $ids = Js::opt($s, 'ids');
                $ids = is_array($ids) ? $ids : [];
                foreach ($ids as $i) {
                    $has = is_string($i) && isset($cl[$i]);
                    if ($k === 'all_of' && !$has) {
                        return false;
                    }
                    if ($k === 'any_of' && $has) {
                        return true;
                    }
                }
                return $k === 'all_of';
            case 'not':
                return !self::selectorMatches(Js::opt($s, 's'), $closure);
            case 'and':
                return (bool)self::selectorMatches(Js::opt($s, 'a'), $closure) && (bool)self::selectorMatches(Js::opt($s, 'b'), $closure);
            default:
                return null; // an unknown selector kind never matches, as the reference
        }
    }

    /**
     * Unconfirmed = maximally dangerous: every `prohibit` selector matches it, no `allow` selector ever does; the closure is not consulted.
     * @param list<string> $closure
     */
    public static function selectorMatchesFor(mixed $s, string $mode, array $closure, bool $confirmed): ?bool
    {
        return $confirmed ? self::selectorMatches($s, $closure) : $mode === 'prohibit';
    }

    public static function selectorHasNot(mixed $s): bool
    {
        $k = Js::opt($s, 'k');
        if ($k === 'not') {
            return true;
        }
        return $k === 'and' && (self::selectorHasNot(Js::opt($s, 'a')) || self::selectorHasNot(Js::opt($s, 'b')));
    }

    private static function hasAnyOf(mixed $x): bool
    {
        $k = Js::opt($x, 'k');
        return $k === 'any_of' || ($k === 'and' && (self::hasAnyOf(Js::opt($x, 'a')) || self::hasAnyOf(Js::opt($x, 'b'))));
    }

    /** T7 typing rule for an ALLOW selector: no negation, and any_of only in a pinned allow. null = allowed. */
    public static function allowSelectorError(mixed $s, bool $pinned): ?string
    {
        if (self::selectorHasNot($s)) {
            return 'an allow selector must not use negation: the absence of a trait is never a safety claim';
        }
        if (!$pinned && self::hasAnyOf($s)) {
            return 'any_of in an allow selector requires the grant to be pinned to a pack digest';
        }
        return null;
    }

    /**
     * A matching prohibit denies; a pinned verb with a matching allow is allowed; an unpinned verb is deny / escalate (`on_new_action`); else deny.
     * @param list<string> $closure
     */
    public static function policyDecision(mixed $p, string $verb, array $closure, bool $confirmed): string
    {
        foreach (Js::opt($p, 'prohibit') ?? [] as $s) {
            if (self::selectorMatchesFor($s, 'prohibit', $closure, $confirmed)) {
                return 'deny';
            }
        }
        if (!in_array($verb, Js::opt($p, 'pinned') ?? [], true)) {
            return Js::opt($p, 'on_new_action') === 'escalate' ? 'escalate' : 'deny';
        }
        foreach (Js::opt($p, 'allow') ?? [] as $s) {
            if (self::selectorMatchesFor($s, 'allow', $closure, $confirmed)) {
                return 'allow';
            }
        }
        return 'deny';
    }
}

/** Resource id patterns (idpattern.ts): matching and decidable containment. A pattern is `'*'`, `{exact}` or `{prefix, class, len: [min, max]}`. */
final class ActionsIdPattern
{
    public const MAX_ID_LEN = 128;
    private const DIGITS = '0123456789';
    private const LOWER = 'abcdefghijklmnopqrstuvwxyz';

    /** The characters of each id class (ID_CLASS_CHARS). @return array<string,string> */
    public static function idClassChars(): array
    {
        $u = strtoupper(self::LOWER);
        return ['digits' => self::DIGITS, 'hex' => self::DIGITS . 'abcdef', 'alnum' => self::DIGITS . self::LOWER . $u, 'slug' => self::DIGITS . self::LOWER . '-_',
            'uuid' => self::DIGITS . 'abcdef-', 'any_safe' => self::DIGITS . self::LOWER . $u . '._-:/'];
    }

    public static function inClass(string $s, string $c): bool
    {
        $chars = self::idClassChars()[$c] ?? null;
        return $chars !== null && ($s === '' || strspn($s, $chars) === strlen($s));
    }

    /** Does `$id` (the id part of a resource, without the type) match the pattern? A non-string id never matches. */
    public static function idMatches(mixed $p, mixed $id): bool
    {
        if (!is_string($id)) {
            return false;
        }
        if ($p === '*') {
            return $id !== '' && strlen($id) <= self::MAX_ID_LEN && self::inClass($id, 'any_safe');
        }
        if (!($p instanceof Obj)) {
            return false;
        }
        if ($p->has('exact')) {
            return $id === $p->get('exact');
        }
        $prefix = $p->get('prefix');
        if (!is_string($prefix) || !str_starts_with($id, $prefix)) {
            return false;
        }
        $rest = substr($id, strlen($prefix));
        $len = $p->get('len');
        if (!is_array($len) || strlen($rest) < (int)Js::num($len[0]) || strlen($rest) > (int)Js::num($len[1])) {
            return false;
        }
        if ($p->get('class') === 'uuid') {
            return preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/D', $rest) === 1;
        }
        return self::inClass($rest, (string)$p->get('class'));
    }

    private static function classSubset(string $a, string $b): bool
    {
        $c = self::idClassChars();
        return count(array_diff(str_split($c[$a]), str_split($c[$b]))) === 0;
    }

    /** Is every id matched by `$inner` also matched by `$outer`? Sound; an exact id never contains a pattern. */
    public static function idPatternContains(mixed $outer, mixed $inner): bool
    {
        if ($outer === '*') {
            return true;
        }
        if ($inner === '*') {
            return false;
        }
        if ($outer->has('exact')) {
            return $inner->has('exact') && $inner->get('exact') === $outer->get('exact');
        }
        if ($inner->has('exact')) {
            return self::idMatches($outer, $inner->get('exact'));
        }
        $op = (string)$outer->get('prefix');
        $ip = (string)$inner->get('prefix');
        if (!str_starts_with($ip, $op)) {
            return false;
        }
        $r = substr($ip, strlen($op));
        if (!self::inClass($r, (string)$outer->get('class'))) {
            return false;
        }
        if ($outer->get('class') === 'uuid') {
            return $inner->get('class') === 'uuid' && $r === '';
        }
        if (!self::classSubset((string)$inner->get('class'), (string)$outer->get('class'))) {
            return false;
        }
        [$ol0, $ol1] = array_map(static fn($x): int => (int)Js::num($x), $outer->get('len'));
        [$il0, $il1] = array_map(static fn($x): int => (int)Js::num($x), $inner->get('len'));
        return strlen($r) + $il0 >= $ol0 && strlen($r) + $il1 <= $ol1;
    }
}

/**
 * The remaining approval profiles of approval-profiles.ts: the Secure Payment Confirmation expectation and the CIBA / RAR authorization_details entry.
 * PSD2 linking, minor units and batches are in {@see Approval}.
 */
final class ActionsApprovalProfiles
{
    public const APPROVAL_BATCH_DOMAIN = Approval::BATCH_DOMAIN;

    /**
     * What a WebAuthn assertion verifier must find in the signed `clientData.payment`. The payee value is the name (`payeeAs` = name) or the origin the browser shows.
     * @return array<string,mixed>
     */
    public static function spcExpectation(Obj $r, string $topOrigin, string $payeeAs = 'name'): array
    {
        $link = Approval::psd2Linking($r);
        $out = ['topOrigin' => $topOrigin, 'total' => ['currency' => $link->get('currency'), 'value' => Approval::minorToDecimal((int)Js::num($link->get('amount_minor')), (int)Js::num($link->get('exp')))]];
        $out[$payeeAs === 'name' ? 'payeeName' : 'payeeOrigin'] = $link->get('payee');
        return $out;
    }

    /**
     * The RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code.
     * @return array{authorization_details:list<Obj>,match_code:string}
     */
    public static function cibaApprovalDetails(Obj $r): array
    {
        $digest = Approval::renderDigest($r);
        return ['authorization_details' => [Obj::of(['type' => 'pca_approval', 'render' => $r, 'render_digest' => $digest])], 'match_code' => Approval::bindingWords($digest)];
    }
}
