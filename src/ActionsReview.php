<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Actions.php';

/**
 * The confirmation flow and signed review attestations (native port of the review flow of the reference actions package): the attestation
 * verdict with its reasons, the review status, the review queue and view, and the producer side (confirmDef). A def WITHOUT a valid attestation
 * has the top of the registry as its effective traits; one counts only when a key pinned with the reviewer role signed this exact def digest.
 */
final class ActionsReview
{
    private const MAX_SAFE = 9007199254740991;
    private const SUSPECT = ['pca.money_moving', 'pca.privilege_change', 'pca.code_execution', 'pca.destructive', 'pca.external_communication'];
    private const NEXT = ['pca.credential_access', 'pca.data_export', 'pca.regulated_data', 'pca.public_exposure', 'pca.infra_mutation', 'pca.legal_binding',
        'pca.impersonation', 'pca.persistence'];
    private const TRAIT_ID_RE = '/\A[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}\z/';
    private const WS_ONLY_RE = '/\A[\x{0009}-\x{000D}\x{0020}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]*\z/u';

    private static function fail(string $reason, string $detail): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason, 'detail' => $detail]);
    }

    private static function f(mixed $x): ?float
    {
        if ($x instanceof Num) {
            return (float)$x->lexeme;
        }
        return is_int($x) || is_float($x) ? (float)$x : null;
    }

    /** Number.isSafeInteger and not -0 (any sign: a negative ts is judged later by the key validity). */
    private static function isSafeInt(mixed $x): bool
    {
        $f = self::f($x);
        return $f !== null && is_finite($f) && fmod($f, 1.0) === 0.0 && abs($f) <= self::MAX_SAFE && !($f == 0.0 && fdiv(1.0, $f) === -INF);
    }

    private static function isStrList(mixed $x): bool
    {
        if (!is_array($x) || !array_is_list($x)) {
            return false;
        }
        foreach ($x as $s) {
            if (!is_string($s)) {
                return false;
            }
        }
        return true;
    }

    /** {ok: true, kid} iff the confirmation is valid, else {ok: false, reason, detail}. Never throws. */
    public static function verifyAttestationVerdict(mixed $d, array $reg, mixed $pins): Obj
    {
        try {
            $pe = Actions::reviewerPinsError($pins);
            if ($pe !== null) {
                return self::fail('bad_pins', $pe);
            }
            $review = $d instanceof Obj ? $d->get('review') : null;
            if (!($review instanceof Obj) || $review->get('state') !== 'confirmed') {
                return self::fail('not_confirmed', 'review.state is not confirmed');
            }
            if (!$review->has('attestation')) {
                return self::fail('no_attestation', 'a confirmed def carries an attestation');
            }
            $a = $review->get('attestation');
            if ($a === null) {
                return self::fail('malformed', 'the attestation is null');
            }
            if (!($a instanceof Obj)) {
                $a = new Obj();   // a scalar or array has no members: unsigned
            }
            if (!is_string($a->get('sig'))) {
                return self::fail('no_signature', 'the attestation is unsigned');
            }
            if (!is_string($a->get('facts_digest'))) {
                return self::fail('malformed', 'the attestation facts_digest must be a string');
            }
            $ft = $a->get('final_traits');
            $dis = $a->get('dismissed');
            $disOk = is_array($dis) && array_is_list($dis);
            foreach ($disOk ? $dis : [] as $x) {
                $disOk = $disOk && $x instanceof Obj && is_string($x->get('trait')) && is_string($x->get('reason'));
            }
            if (!self::isStrList($ft) || !$disOk || !self::isSafeInt($a->get('ts')) || !is_string($a->get('reviewer_kid'))) {
                return self::fail('malformed', 'the attestation final_traits, dismissed, ts or reviewer_kid is malformed');
            }
            if ($a->get('def_digest') !== Actions::defDigest($d)) {
                return self::fail('digest_mismatch', 'the def changed after it was reviewed');
            }
            $accepted = [Actions::traitsDigest($reg)];
            $extra = $pins->get('traits_digests');
            foreach (is_array($extra) ? $extra : [] as $x) {
                $accepted[] = $x;
            }
            if (!in_array($a->get('traits_digest'), $accepted, true)) {
                return self::fail('traits_digest_mismatch', 'the trait registry changed since the review');
            }
            $declared = $d->get('traits');
            if (Actions::sortUniq($ft) !== Actions::sortUniq(is_array($declared) ? $declared : [])) {
                return self::fail('final_traits_mismatch', 'the attested final traits are not the def\'s declared traits');
            }
            foreach ($dis as $x) {
                if (in_array($x->get('trait'), $ft, true) || Actions::blankReason($x->get('reason'))) {
                    return self::fail('dismissed_conflict', 'a dismissed trait is also final, or has no reason');
                }
            }
            $key = null;
            foreach ($pins->get('keys') as $k) {
                if ($k->get('kid') === $a->get('reviewer_kid')) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null) {
                return self::fail('unknown_reviewer', "no pinned key '" . $a->get('reviewer_kid') . "'");
            }
            if (!in_array('reviewer', $key->get('roles'), true)) {
                return self::fail('not_a_reviewer', "key '" . $key->get('kid') . "' does not hold the reviewer role");
            }
            $ts = self::f($a->get('ts'));
            if (($key->has('not_before') && $ts < self::f($key->get('not_before'))) || ($key->has('not_after') && $ts > self::f($key->get('not_after')))) {
                return self::fail('outside_validity', 'the attestation time is outside the key validity');
            }
            if (Pca::verifyEd25519B64u($key->get('pk'), Actions::reviewMessage($a->without('sig')), $a->get('sig'))) {
                return Obj::of(['ok' => true, 'kid' => $key->get('kid')]);
            }
            return self::fail('bad_signature', 'the attestation signature is invalid');
        } catch (\Throwable $e) {
            return self::fail('malformed', $e->getMessage());
        }
    }

    /** The callback the algebra takes: a confirmed def counts only if the attestation verdict is ok. */
    public static function attestationVerifier(array $reg, mixed $pins): \Closure
    {
        return fn($d) => self::verifyAttestationVerdict($d, $reg, $pins)->get('ok') === true;
    }

    /** The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed). */
    public static function reviewStatus(Obj $d, array $reg, mixed $pins): string
    {
        $state = $d->get('review')->get('state');
        if ($state !== 'confirmed') {
            return $state;
        }
        return self::verifyAttestationVerdict($d, $reg, $pins)->get('ok') === true ? 'confirmed' : 'stale';
    }

    /** Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped). */
    public static function revertStale(Obj $d, array $reg, mixed $pins): Obj
    {
        if (self::reviewStatus($d, $reg, $pins) !== 'stale') {
            return $d;
        }
        $review = $d->get('review')->without('attestation');
        $review->set('state', 'unreviewed');
        $out = new Obj();
        foreach ($d->keys() as $k) {
            $out->set($k, $d->get($k));
        }
        $out->set('review', $review);
        return $out;
    }

    private static function intrinsic(Obj $d, array $reg): array
    {
        return ActionsDerive::effectiveWith($d, $reg)['hint'];
    }

    /** 0 = a core suspect trait (money, privilege, code, destructive, outbound communication), 1 = other risky, 2 = the rest. */
    public static function reviewPriority(Obj $d, array $reg): int
    {
        $cl = self::intrinsic($d, $reg)['closure'];
        if (array_intersect(self::SUSPECT, $cl)) {
            return 0;
        }
        return array_intersect(self::NEXT, $cl) ? 1 : 2;
    }

    /** Defs in review order: suspect traits first, then by risk (highest first), then by verb. @param list<Obj> $defs @return list<Obj> */
    public static function reviewQueueOrder(array $defs, array $reg): array
    {
        $rows = array_map(fn($d) => [self::reviewPriority($d, $reg), self::intrinsic($d, $reg)['eff']['risk'], $d], $defs);
        usort($rows, fn($x, $y) => ($x[0] <=> $y[0]) ?: ($y[1] <=> $x[1]) ?: strcmp(AnalyzerJs::u16key($x[2]->get('verb')), AnalyzerJs::u16key($y[2]->get('verb'))));
        return array_map(fn($r) => $r[2], $rows);
    }

    private static function sj(Obj $o, string $k): string
    {
        return $o->has($k) ? Js::stringify($o->get($k)) : 'undefined';
    }

    /** What the reviewer is shown: the def's facts, the traits it would carry once signed, the policy card and (with `previous`) what changed. */
    public static function prepareReview(Obj $d, array $reg, ?Obj $previous = null): Obj
    {
        $eff = ActionsDerive::effectiveWith($d, $reg);
        $shown = $eff['hint'] + $eff;   // the hint's own members win; confirmed is shown as true
        $shown['confirmed'] = true;
        $sb = $d->get('review')->get('suggested_by');
        $added = $sb instanceof Obj ? $sb->get('added') : null;
        $changes = [];
        if ($previous !== null) {
            $skip = ['review', 'examples', 'source', 'since'];
            $a = $previous->without(...$skip);
            $b = $d->without(...$skip);
            $keys = array_values(array_unique(array_merge($a->keys(), $b->keys())));
            foreach ($keys as $k) {
                if (self::sj($a, $k) !== self::sj($b, $k)) {
                    $changes[] = $k;
                }
            }
            usort($changes, fn($x, $y) => strcmp(AnalyzerJs::u16key($x), AnalyzerJs::u16key($y)));
        }
        $effective = $eff;
        return Obj::of([
            'verb' => $d->get('verb'), 'def_digest' => Actions::defDigest($d), 'state' => $d->get('review')->get('state'),
            'declared_traits' => Actions::sortUniq($d->get('traits') ?? []), 'implied_traits' => ActionsDerive::impliedTraits(Actions::normalize($d)),
            'suggested' => $added ?? Obj::of(['traits' => [], 'roles' => new Obj(), 'tags' => new Obj()]),
            'effective' => $effective, 'card' => ActionsDerive::cardOf($d, $shown, $reg), 'changes' => $changes, 'priority' => new Num((string)self::reviewPriority($d, $reg)),
        ]);
    }

    private static function bad(string $why): ActionKitError
    {
        return new ActionKitError('bad_confirm', $why);
    }

    /**
     * The ReviewRef for the body `$b` (`def_digest`, `traits_digest`, `facts_digest`, `final_traits`, `dismissed`, `reviewer_kid`, `ts`): `final_traits` sorted and
     * distinct, `dismissed` sorted by trait, signed with a 32-byte Ed25519 seed (signReview). Throws \InvalidArgumentException on a key of another length.
     */
    public static function signReview(Obj $b, string $secret): Obj
    {
        if (strlen($secret) !== 32) {
            throw new \InvalidArgumentException('the reviewer key must be a 32-byte Ed25519 secret');
        }
        $norm = $b->without();
        $norm->set('final_traits', Actions::sortUniq($b->get('final_traits')));
        $dm = $b->get('dismissed');
        usort($dm, static fn(Obj $x, Obj $y): int => strcmp((string)$x->get('trait'), (string)$y->get('trait')));
        $norm->set('dismissed', $dm);
        $norm->set('sig', Pca::b64u((new KeyPair($secret))->sign(Actions::reviewMessage($norm))));
        return $norm;
    }

    /**
     * Review one def: validate the decision, write the final traits, sign an attestation over the resulting digest, return the confirmed def.
     * $o: registry, reviewer {kid, secret (32-byte seed)}, pins?, finalTraits, dismissed? (list of {trait, reason}), ts. Throws ActionKitError
     * bad_confirm / undismissed_suggestion / not_reviewer.
     *
     * @param array<string,mixed> $o
     */
    public static function confirmDef(Obj $d, array $o): Obj
    {
        $reg = $o['registry'];
        $ts = $o['ts'] ?? null;
        if (!self::isSafeInt($ts) || self::f($ts) < 0) {
            throw self::bad('ts must be a non-negative integer');
        }
        $tsNum = new Num((string)(int)self::f($ts));   // the reference's number: a Num 1e3 or 1000.0 is the integer 1000
        $final = Actions::sortUniq($o['finalTraits']);
        if (count($final) !== count($o['finalTraits'])) {
            throw self::bad('final traits must be distinct');
        }
        foreach ($final as $t) {
            if (preg_match(self::TRAIT_ID_RE, $t) !== 1 || !isset($reg[$t])) {
                throw self::bad("unknown trait '$t'");
            }
            if ($t === 'pca.unreviewed') {
                throw self::bad("'pca.unreviewed' is the review marker, not a final trait");
            }
        }
        $dismissed = [];
        $dset = [];
        foreach ($o['dismissed'] ?? [] as $x) {
            $x = $x instanceof Obj ? $x : Obj::of($x);
            $dismissed[] = Obj::of(['trait' => $x->get('trait'), 'reason' => $x->get('reason')]);
        }
        foreach ($dismissed as $x) {
            $reason = $x->get('reason');
            if (!is_string($reason) || preg_match(self::WS_ONLY_RE, $reason) === 1 || Js::len($reason) > 256) {
                throw self::bad("dismissed trait '" . $x->get('trait') . "' needs a reason (1..256 characters)");
            }
            if (isset($dset[$x->get('trait')])) {
                throw self::bad("trait '" . $x->get('trait') . "' is dismissed twice");
            }
            $dset[$x->get('trait')] = true;
            if (in_array($x->get('trait'), $final, true)) {
                throw self::bad("trait '" . $x->get('trait') . "' is both final and dismissed");
            }
        }
        $sb = $d->get('review')->get('suggested_by');
        $addedTraits = $sb instanceof Obj && $sb->get('added') instanceof Obj ? ($sb->get('added')->get('traits') ?? []) : [];
        $shown = Actions::sortUniq(array_merge($d->get('traits') ?? [], $addedTraits));
        $covered = Actions::closure($reg, Actions::sortUniq(array_merge($final, ActionsDerive::impliedTraits(Actions::normalize($d)))));
        foreach ($shown as $t) {
            if (in_array($t, $final, true) || in_array($t, $covered, true)) {
                continue;
            }
            if (!isset($dset[$t])) {
                throw new ActionKitError('undismissed_suggestion', "trait '$t' was suggested and is not in the final set: record it as dismissed with a reason");
            }
        }
        foreach (array_keys($dset) as $t) {
            if (!in_array((string)$t, $shown, true)) {
                throw self::bad("trait '$t' was never suggested; nothing to dismiss");
            }
        }
        $rv = $o['reviewer'];
        $secret = $rv['secret'];
        if (!is_string($secret) || strlen($secret) !== 32) {
            throw new \InvalidArgumentException('the reviewer key must be a 32-byte Ed25519 secret');
        }
        $pins = $o['pins'] ?? null;
        if ($pins !== null) {
            $pe = Actions::reviewerPinsError($pins);
            if ($pe !== null) {
                throw self::bad($pe);
            }
            $key = null;
            foreach ($pins->get('keys') as $k) {
                if ($k->get('kid') === $rv['kid']) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null || !in_array('reviewer', $key->get('roles'), true)) {
                throw new ActionKitError('not_reviewer', "key '" . $rv['kid'] . "' is not pinned with the reviewer role");
            }
            if ($key->get('pk') !== (new KeyPair($secret))->public) {
                throw new ActionKitError('not_reviewer', "the secret does not belong to the pinned key '" . $rv['kid'] . "'");
            }
        }
        $body = new Obj();
        foreach ($d->keys() as $k) {
            $body->set($k, $d->get($k));
        }
        if ($final) {
            $body->set('traits', $final);
        } else {
            $body = $body->without('traits');
        }
        usort($dismissed, fn($x, $y) => strcmp(AnalyzerJs::u16key($x->get('trait')), AnalyzerJs::u16key($y->get('trait'))));
        $att = Obj::of([
            'def_digest' => Actions::defDigest($body), 'traits_digest' => Actions::traitsDigest($reg),
            'facts_digest' => Actions::factsDigest(ActionsDerive::toSchemaVerb($body, $reg)->get('verb')), 'final_traits' => $final,
            'dismissed' => $dismissed, 'reviewer_kid' => $rv['kid'], 'ts' => $tsNum,
        ]);
        $att->set('sig', Pca::b64u((new KeyPair($secret))->sign(Actions::reviewMessage($att))));
        $review = new Obj();
        foreach ($d->get('review')->keys() as $k) {
            $review->set($k, $d->get('review')->get($k));
        }
        $review->set('state', 'confirmed');
        $review->set('attestation', $att);
        $out = new Obj();
        foreach ($body->keys() as $k) {
            $out->set($k, $body->get($k));
        }
        $out->set('review', $review);
        $err = Actions::validateDef($out);
        if ($err !== null) {
            throw self::bad("the confirmed def is invalid: $err");
        }
        return $out;
    }
}
