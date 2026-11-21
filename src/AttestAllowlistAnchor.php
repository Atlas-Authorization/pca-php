<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Ledger.php';
require_once __DIR__ . '/LedgerLog.php';
require_once __DIR__ . '/Pca.php';

/**
 * The operator's append-only anchor log of `{issuer, version, digest}` entries: a {@see TransparencyLedger} of anchor commitments, the
 * plaintext entries behind them and the latest signed tree head.
 */
final class AllowlistAnchorLog
{
    public TransparencyLedger $ledger;
    /** @var list<Obj> */
    public array $entries = [];
    public ?Obj $latest = null;

    public function __construct(public readonly string $instanceId, public readonly string $principal)
    {
        $this->ledger = new TransparencyLedger($principal);
    }

    /** @return list<Obj> copies */
    public function entries(): array
    {
        return array_map(static fn(Obj $e): Obj => Jsx::spread($e), $this->entries);
    }

    public function latest(): ?Obj
    {
        return $this->latest;
    }
}

/**
 * Transparency-anchored rollback detection for signed allowlist manifests: the operator anchors `{issuer, version, manifest digest}` in an
 * append-only Merkle log and re-signs the tree head; the verifier requires, with NO local state, a head signed by the pinned log key (and
 * the witnesses when configured), a fresh head, a consistent extension of its cached head, a feed that reproduces the signed root, an
 * inclusion proof of the manifest's own anchor and that its version is the highest anchored for the issuer. Evidence is
 * `{head, entries, proof, consistency?}`.
 */
final class AttestAllowlistAnchor
{
    public const DOMAIN = 'pca-attest-allowlist-anchor/v1';
    private const MAX_FEED = 100000;
    private const DAY = 86400000;

    /** The leaf the log stores for an entry. */
    public static function commit(mixed $e): string
    {
        return Pca::hashCanonical(Sign::n(Obj::of(['domain' => self::DOMAIN, 'issuer' => Jsx::get($e, 'issuer'), 'version' => Jsx::get($e, 'version'), 'digest' => Jsx::get($e, 'digest')])));
    }

    private static function safeInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0;
    }

    private static function validEntry(mixed $e): bool
    {
        if (!($e instanceof Obj) || count($e->keys()) !== 3) {
            return false;
        }
        $i = Jsx::get($e, 'issuer');
        $v = Jsx::get($e, 'version');
        $d = Jsx::get($e, 'digest');
        return is_string($i) && $i !== '' && Js::len($i) <= 200 && self::safeInt($v) && Js::num($v) >= 1 && is_string($d) && preg_match('/\A[A-Za-z0-9_-]{43}\z/', $d) === 1;
    }

    /** `{issuer, version, digest}` of an `ok` verification result. */
    public static function entryOf(mixed $v): Obj
    {
        return Obj::of(['issuer' => Jsx::get($v, 'issuer'), 'version' => Jsx::get($v, 'version'), 'digest' => Jsx::get($v, 'digest')]);
    }

    public static function createLog(string $instanceId, string $principal): AllowlistAnchorLog
    {
        return new AllowlistAnchorLog($instanceId, $principal);
    }

    private static function signHead(AllowlistAnchorLog $log, string $guardianSecret, mixed $nowMs, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $h = $log->ledger->head();
        $sth = TransparencyLedger::signTreeHead(new KeyPair($guardianSecret), Obj::of(['instance_id' => $log->instanceId, 'principal' => $log->principal,
            'size' => $h['size'], 'root' => $h['root'], 'prev_root' => $log->latest === null ? '' : $log->latest->get('root'), 'timestamp' => $nowMs]), $alg, $pq);
        $log->latest = $sth;
        return $sth;
    }

    /**
     * Evidence for the leaf at `$index` under the latest head, with a consistency proof from `$cachedSize` when it is smaller. Throws when the
     * log has no signed head or the index is out of range.
     */
    public static function evidenceFor(AllowlistAnchorLog $log, mixed $index, mixed $cached = null): Obj
    {
        if ($log->latest === null) {
            throw new \LogicException('evidenceFor: log has no signed head');
        }
        $out = Obj::of(['head' => $log->latest, 'entries' => $log->entries(), 'proof' => $log->ledger->inclusionProof($index)]);
        $cs = Jsx::get($cached, 'size');
        $latestSize = Js::num($log->latest->get('size'));
        if ($cached !== null && !($cs instanceof Undef) && Js::num($cs) > 0 && Js::num($cs) < $latestSize) {
            $out->set('consistency', $log->ledger->consistencyProof($cs, $log->latest->get('size')));
        }
        return $out;
    }

    /**
     * Anchor a manifest's entry (an `{issuer, version, digest}` or an `ok` verification result) and re-sign the head. Throws if it would lower
     * the issuer's highest anchored version or give an anchored version a second digest; re-anchoring the identical entry is idempotent.
     * @param string $guardianSecret the 32-byte Ed25519 seed of the log guardian
     */
    public static function anchorHead(AllowlistAnchorLog $log, mixed $what, string $guardianSecret, mixed $nowMs, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $entry = $what instanceof Obj && $what->has('body') ? self::entryOf($what) : Jsx::spread($what);
        if (!self::validEntry($entry)) {
            throw new \TypeError('anchorAllowlistHead: malformed entry');
        }
        $entry = Obj::of(['issuer' => $entry->get('issuer'), 'version' => (int)Js::num($entry->get('version')), 'digest' => $entry->get('digest')]);
        $same = -1;
        foreach ($log->entries as $i => $e) {
            if ($e->get('issuer') === $entry->get('issuer') && $e->get('version') === $entry->get('version')) {
                $same = $i;
                break;
            }
        }
        if ($same >= 0) {
            if ($log->entries[$same]->get('digest') !== $entry->get('digest')) {
                throw new \RuntimeException('anchorAllowlistHead: this version is already anchored with a different digest');
            }
            $index = $same;
        } else {
            $max = 0;
            foreach ($log->entries as $e) {
                if ($e->get('issuer') === $entry->get('issuer')) {
                    $max = max($max, $e->get('version'));
                }
            }
            if ($entry->get('version') < $max) {
                throw new \RuntimeException('anchorAllowlistHead: version ' . $entry->get('version') . " is lower than the anchored $max");
            }
            $index = $log->ledger->appendCommitment(self::commit($entry))['index'];
            $log->entries[] = $entry;
            self::signHead($log, $guardianSecret, $nowMs, $alg, $pq);
        }
        if ($log->latest === null) {
            self::signHead($log, $guardianSecret, $nowMs, $alg, $pq);
        }
        return self::evidenceFor($log, $index);
    }

    /** Re-sign the current head with a fresh timestamp (a liveness heartbeat). Throws on an empty log. */
    public static function refreshHead(AllowlistAnchorLog $log, string $guardianSecret, mixed $nowMs, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        if ($log->ledger->size() === 0) {
            throw new \LogicException('refreshAnchorHead: nothing anchored yet');
        }
        return self::signHead($log, $guardianSecret, $nowMs, $alg, $pq);
    }

    /** @return array<string,mixed> */
    private static function no(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /**
     * Check a signature-verified manifest (`$verified`: `{issuer, version, digest}`) against log evidence. `$opts`: `{trust: {logKey,
     * instanceId, principal, witnesses?, pqPins?}, nowMs, maxHeadAgeMs? (24 h), clockSkewMs? (60 s), cachedHead?}`. Never throws.
     * @return array<string,mixed> `{ok: true, issuer, version, digest, highestAnchoredVersion, head}` or `{ok: false, code, reason}`
     */
    public static function verify(mixed $verified, mixed $evidence, mixed $opts): array
    {
        try {
            $proof = Jsx::get($evidence, 'proof');
            $head = Jsx::get($evidence, 'head');
            $entries = Jsx::get($evidence, 'entries');
            if (!($evidence instanceof Obj) || $proof instanceof Undef || $head instanceof Undef || !is_array($entries) || !array_is_list($entries)) {
                return self::no('missing-proof', 'no anchor evidence (head + entries + inclusion proof) supplied');
            }
            $trust = Jsx::get($opts, 'trust');
            $nowV = Jsx::get($opts, 'nowMs');
            if (!self::safeInt($nowV)) {
                return self::no('bad-head', 'nowMs must be an integer');
            }
            $now = Js::num($nowV);
            $logKey = Jsx::rd($trust, 'logKey');
            $witnesses = Jsx::get($trust, 'witnesses');
            $witnesses = $witnesses instanceof Undef ? null : $witnesses;
            $pins = Jsx::get($trust, 'pqPins');
            $pins = $pins instanceof Undef ? null : $pins;
            if (!Ledger::verifyTreeHead($head, $logKey, $witnesses, $pins)) {
                return self::no('bad-head', 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)');
            }
            if (Jsx::get($head, 'instance_id') !== Jsx::get($trust, 'instanceId') || Jsx::get($head, 'principal') !== Jsx::get($trust, 'principal')) {
                return self::no('bad-head', 'tree head is for a different log');
            }
            $skewV = Jsx::get($opts, 'clockSkewMs');
            $ageV = Jsx::get($opts, 'maxHeadAgeMs');
            $skewOk = $skewV instanceof Undef || (Js::isNum($skewV) && is_finite(Js::num($skewV)));
            $ageOk = $ageV instanceof Undef || (Js::isNum($ageV) && is_finite(Js::num($ageV)));
            if (!$skewOk || !$ageOk) {
                return self::no('bad-head', $skewOk ? 'maxHeadAgeMs must be a finite number' : 'clockSkewMs must be a finite number');
            }
            $skew = max(0.0, $skewV instanceof Undef ? 60000.0 : Js::num($skewV));
            $maxAge = $ageV instanceof Undef ? (float)self::DAY : Js::num($ageV);
            $ts = Jsx::get($head, 'timestamp');
            if (!self::safeInt($ts)) {
                return self::no('stale-head', 'tree head is timestamped in the future');
            }
            $t = Js::num($ts);
            $integral = abs($maxAge) < 4503599627370496.0;
            $sk = $integral ? floor($skew) : $skew;
            $ma = $integral ? floor($maxAge) : $maxAge;
            if ($t > $now + $sk) {
                return self::no('stale-head', 'tree head is timestamped in the future');
            }
            if ($now - $t > $ma) {
                return self::no('stale-head', 'tree head is older than maxHeadAgeMs (' . Jsx::str($ageV instanceof Undef ? (float)self::DAY : $ageV) . ')');
            }
            $cached = Jsx::get($opts, 'cachedHead');
            if (!($cached instanceof Undef)) {
                if (!Ledger::verifyTreeHead($cached, $logKey, $witnesses, $pins) || Jsx::get($cached, 'instance_id') !== Jsx::get($trust, 'instanceId')
                    || Jsx::get($cached, 'principal') !== Jsx::get($trust, 'principal')) {
                    return self::no('bad-cache', 'the cached head does not verify under the pinned log key');
                }
                $hs = Js::num(Jsx::get($head, 'size'));
                $cs = Js::num(Jsx::get($cached, 'size'));
                if ($hs < $cs) {
                    return self::no('log-rollback', "head size $hs < cached $cs: the log shrank");
                }
                if ($hs == $cs) {
                    if (Jsx::get($head, 'root') !== Jsx::get($cached, 'root')) {
                        return self::no('split-view', 'two different roots at the same size: split view / fork');
                    }
                } else {
                    $c = Jsx::get($evidence, 'consistency');
                    if ($c instanceof Undef || !Ledger::verifyHeadConsistency($cached, $head, $c, $logKey, $witnesses, $pins)) {
                        return self::no('inconsistent-with-cache', 'no valid consistency proof from the cached head: forked or truncated log');
                    }
                }
            }
            $size = Js::num(Jsx::get($head, 'size'));
            if (count($entries) > self::MAX_FEED || (float)count($entries) !== $size) {
                return self::no('feed-mismatch', 'entries do not match the signed tree size');
            }
            foreach ($entries as $e) {
                if (!self::validEntry($e)) {
                    return self::no('feed-mismatch', 'entries do not match the signed tree size');
                }
            }
            if (TransparencyLedger::rootOf(array_map([self::class, 'commit'], $entries)) !== Jsx::get($head, 'root')) {
                return self::no('feed-mismatch', 'entries do not reproduce the signed root');
            }
            $issuer = Jsx::rd($verified, 'issuer');
            $version = Js::num(Jsx::rd($verified, 'version'));
            $digest = Jsx::rd($verified, 'digest');
            $byVersion = [];
            $highest = 0.0;
            foreach ($entries as $e) {
                if ($e->get('issuer') !== $issuer) {
                    continue;
                }
                $v = Js::num($e->get('version'));
                $k = (string)(int)$v;
                if (isset($byVersion[$k]) && $byVersion[$k] !== $e->get('digest')) {
                    return self::no('log-conflict', "log anchors two different digests for version $k");
                }
                $byVersion[$k] = $e->get('digest');
                $highest = max($highest, $v);
            }
            if (Js::num(Jsx::rd($proof, 'size')) !== $size) {
                return self::no('bad-proof', 'inclusion proof size does not match the signed head size');
            }
            if (!Ledger::verifyInclusion(Jsx::get($head, 'root'), $proof, self::commit($verified))) {
                return self::no('bad-proof', 'inclusion proof does not place this manifest under the signed root');
            }
            if ($version < $highest) {
                return self::no('anchored-rollback', "manifest version $version < highest anchored $highest for '" . Jsx::str($issuer) . "'");
            }
            if (($byVersion[(string)(int)$version] ?? null) !== $digest) {
                return self::no('not-anchored', 'this manifest digest is not the one anchored for its version');
            }
            return ['ok' => true, 'issuer' => $issuer, 'version' => Jsx::get($verified, 'version'), 'digest' => $digest, 'highestAnchoredVersion' => (int)$highest, 'head' => $head];
        } catch (\Throwable $e) {
            return self::no('bad-head', $e->getMessage() === '' ? 'anchor verification error' : $e->getMessage());
        }
    }
}
