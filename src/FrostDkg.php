<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Frost.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';

/** One participant's secret state between the DKG rounds (the polynomial coefficients stay inside it). */
final class DkgState
{
    /** @param list<string> $coefficients 32-byte scalars @param Obj $package the broadcast round-1 package */
    public function __construct(public readonly mixed $identifier, public readonly int $t, public readonly int $n, public readonly string $sessionId,
        public readonly array $coefficients, public readonly Obj $package)
    {
    }
}

/**
 * FROST distributed key generation (Pedersen DKG with a proof of knowledge per participant, RFC 9591 FROST(Ed25519, SHA-512)): round 1 commit with a PoP,
 * round 2 signed shares, per-share verification against the sender's commitments, non-repudiable complaints, rebuttals and blame resolution, the qualified
 * set, echo broadcast agreement on the transcript, and finalize. All group and scalar arithmetic is libsodium's through {@see Frost}. Every verifier is total
 * (a verdict, never a throw); a constructor of a message (round1, round2, file a complaint, rebut, finalize) throws on a malformed input.
 * Packages, complaints, rebuttals and echoes are JSON objects (Obj); shares, keys and session ids are raw byte strings. `$opts['random']` is a closure
 * returning 32 bytes (the randomness seam of the differential tests; random_bytes when absent).
 */
final class FrostDkg
{
    public const CONTEXT = 'FROST-ED25519-SHA512-v1';

    private static function zero(): string
    {
        return str_repeat("\0", 32);
    }

    /** JS Set / Map key of a value: numbers by value, strings by content. */
    private static function kid(mixed $x): string
    {
        return Js::isNum($x) ? 'n' . (string)Js::num($x) : (is_string($x) ? 's' . $x : 'o' . serialize($x instanceof Obj || $x instanceof Undef ? get_class($x) : $x));
    }

    /** A whole JS number as a PHP int; anything else (a non-integer, a string, null, a huge value) throws, as BigInt(x) would. */
    private static function intOf(mixed $x): int
    {
        $f = Js::num($x);
        if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0) {
            throw new \RangeException('dkg: not an integer');
        }
        return (int)$f;
    }

    private static function isInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    private static function sc(int $id): string
    {
        if ($id < 0) { // scalarToBytes(BigInt(id)) reduces mod L: -n is L - n
            return Ed25519Core::scalarSub(str_repeat("\0", 32), Frost::scalarOfId(-$id));
        }
        return Frost::scalarOfId($id);
    }

    /** `o.k` with JS null/undefined semantics: a member of null or undefined throws. */
    private static function m(mixed $o, string $k): mixed
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError("Cannot read properties of undefined (reading '$k')");
        }
        return Jsx::get($o, $k);
    }

    private static function ub(mixed $s): string
    {
        $raw = is_string($s) ? Pca::unb64u($s) : null;
        if ($raw === null) {
            throw new \InvalidArgumentException('dkg: bad base64url');
        }
        return $raw;
    }

    private static function canonicalScalar(string $b): string
    {
        if (!Frost::isCanonicalScalar($b)) {
            throw new \InvalidArgumentException('dkg: scalar must be 32 bytes and < the group order');
        }
        return Frost::bytesToScalar($b);
    }

    private static function hashToScalar(string $m): string
    {
        return Frost::bytesToScalar(hash('sha512', $m, true));
    }

    /** @return array{0:string,1:string} the first point and `u32be(count) || points` */
    private static function commitVec(mixed $commitments): array
    {
        if (!is_array($commitments) || !array_is_list($commitments) || $commitments === []) {
            throw new \InvalidArgumentException('dkg: empty commitment vector');
        }
        $pts = array_map(static fn(mixed $c): string => Frost::decodeSafePoint(self::ub($c)), $commitments);
        return [$pts[0], pack('N', count($pts)) . implode('', $pts)];
    }

    /** @param list<string> $coeffs 32-byte scalars */
    private static function evalPoly(array $coeffs, int $x): string
    {
        $xs = self::sc($x);
        $acc = self::zero();
        for ($j = count($coeffs) - 1; $j >= 0; $j--) {
            $acc = Frost::sAdd(Frost::sMul($acc, $xs), $coeffs[$j]);
        }
        return $acc;
    }

    private static function vssCheck(string $share, mixed $commitments, int $atId): bool
    {
        if (!is_array($commitments) || $commitments === []) {
            return false;
        }
        $lhs = Frost::mulBase($share);
        $rhs = Frost::mulBase(self::zero());
        $x = self::sc($atId);
        $xk = Frost::scalarOfId(1);
        foreach ($commitments as $cB) {
            $rhs = Frost::add($rhs, Frost::mulPoint(Frost::decodeSafePoint(self::ub($cB)), $xk));
            $xk = Frost::sMul($xk, $x);
        }
        return hash_equals($lhs, $rhs);
    }

    private static function popChallenge(string $sid, int $id, string $cvBytes, string $r): string
    {
        return self::hashToScalar(self::CONTEXT . 'dkg-pop' . $sid . self::sc($id) . $cvBytes . $r);
    }

    private static function shareChallenge(string $sid, int $from, int $to, string $share, string $cvBytes, string $rs): string
    {
        return self::hashToScalar(self::CONTEXT . 'dkg-share' . $sid . self::sc($from) . self::sc($to) . $share . $cvBytes . $rs);
    }

    private static function signShareScalar(string $a0, string $cvBytes, string $sid, int $from, int $to, string $share): string
    {
        $k = self::hashToScalar(self::CONTEXT . 'dkg-share-nonce' . $a0 . $sid . self::sc($from) . self::sc($to) . $share . $cvBytes);
        $rs = Frost::mulBase($k);
        $e = self::shareChallenge($sid, $from, $to, $share, $cvBytes, $rs);
        return Pca::b64u($rs . Frost::sAdd($k, Frost::sMul($a0, $e)));
    }

    private static function verifyShareSig(mixed $sig, string $sid, mixed $from, mixed $to, string $share, string $c0, string $cvBytes): bool
    {
        try {
            $raw = self::ub($sig);
            if (strlen($raw) !== 64) {
                return false;
            }
            $rs = Frost::decodeSafePoint(substr($raw, 0, 32));
            $s = self::canonicalScalar(substr($raw, 32, 32));
            $e = self::shareChallenge($sid, self::intOf($from), self::intOf($to), $share, $cvBytes, $rs);
            return hash_equals(Frost::mulBase($s), Frost::add($rs, Frost::mulPoint($c0, $e)));
        } catch (\Throwable) {
            return false;
        }
    }

    private static function verifyShareSigAgainstPackage(mixed $sig, string $sid, mixed $from, mixed $to, string $share, mixed $senderPackage): bool
    {
        try {
            $cc = self::m($senderPackage, 'coefficientCommitments');
            if (!is_string($sig) || !is_array($cc) || $cc === []) {
                return false;
            }
            [$c0, $bytes] = self::commitVec($cc);
            return self::verifyShareSig($sig, $sid, $from, $to, $share, $c0, $bytes);
        } catch (\Throwable) {
            return false;
        }
    }

    /** The signature `b64u(R || s)` of a share from this participant to `$to`: a Schnorr signature under the constant commitment, any share bytes. */
    public static function signShare(DkgState $state, mixed $to, string $shareBytes): string
    {
        [, $bytes] = self::commitVec(Jsx::get($state->package, 'coefficientCommitments'));
        return self::signShareScalar(Frost::bytesToScalar($state->coefficients[0]), $bytes, $state->sessionId, self::intOf($state->identifier), self::intOf($to), $shareBytes);
    }

    private static function rand(array $opts): string
    {
        $r = $opts['random'] ?? null;
        return $r !== null ? $r() : random_bytes(32);
    }

    /**
     * Round 1: a random degree t-1 polynomial, its coefficient commitments and a Schnorr proof of knowledge of the constant term bound to the session and
     * identifier. `$opts`: `coefficients?` (t raw scalars), `popNonce?`, `random?`. @return array{package:Obj,state:DkgState}
     */
    public static function round1(mixed $identifier, mixed $t, mixed $n, mixed $sessionId, array $opts = []): array
    {
        if (!self::isInt($identifier) || Js::num($identifier) <= 0) {
            throw new \RuntimeException('dkgRound1: identifier must be a positive integer');
        }
        if (!self::isInt($t) || !self::isInt($n) || Js::num($t) < 1 || Js::num($n) < Js::num($t)) {
            throw new \RuntimeException('dkgRound1: need 1 <= t <= n');
        }
        if (!is_string($sessionId) || $sessionId === '') {
            throw new \RuntimeException('dkgRound1: sessionId must be a non-empty byte string');
        }
        $id = self::intOf($identifier);
        $tt = self::intOf($t);
        $coeffs = [];
        $given = $opts['coefficients'] ?? null;
        if ($given !== null) {
            if (count($given) !== $tt) {
                throw new \RuntimeException("dkgRound1: coefficients.length must equal t ($tt)");
            }
            foreach ($given as $c) {
                $coeffs[] = Frost::bytesToScalar($c);
            }
        } else {
            for ($j = 0; $j < $tt; $j++) {
                $coeffs[] = Frost::bytesToScalar(self::rand($opts));
            }
        }
        $points = array_map(Frost::mulBase(...), $coeffs);
        $commitments = array_map(static fn(string $p): string => Pca::b64u($p), $points);
        [, $bytes] = self::commitVec($commitments);
        $pn = $opts['popNonce'] ?? null;
        $k = $pn !== null ? Frost::bytesToScalar($pn) : Frost::bytesToScalar(self::rand($opts));
        $r = Frost::mulBase($k);
        $c = self::popChallenge($sessionId, $id, $bytes, $r);
        $mu = Frost::sAdd($k, Frost::sMul($coeffs[0], $c));
        $pkg = Obj::of(['identifier' => $identifier, 'sessionId' => Pca::b64u($sessionId), 'coefficientCommitments' => $commitments,
            'proofOfKnowledge' => Obj::of(['R' => Pca::b64u($r), 'mu' => Pca::b64u($mu)])]);
        return ['package' => $pkg, 'state' => new DkgState($identifier, $tt, self::intOf($n), $sessionId, $coeffs, $pkg)];
    }

    /** Verify a round-1 package's proof of knowledge for the claimed sender. Never throws. */
    public static function verifyRound1(mixed $fromIdentifier, mixed $pkg, mixed $sessionId): bool
    {
        try {
            if (!is_string($sessionId) || self::m($pkg, 'sessionId') !== Pca::b64u($sessionId)) {
                return false;
            }
            $cc = self::m($pkg, 'coefficientCommitments');
            if (!is_array($cc) || $cc === []) {
                return false;
            }
            [$c0, $bytes] = self::commitVec($cc);
            $pok = self::m($pkg, 'proofOfKnowledge');
            $r = Frost::decodeSafePoint(self::ub(self::m($pok, 'R')));
            $mu = self::canonicalScalar(self::ub(self::m($pok, 'mu')));
            $c = self::popChallenge($sessionId, self::intOf($fromIdentifier), $bytes, $r);
            return hash_equals(Frost::mulBase($mu), Frost::add($r, Frost::mulPoint($c0, $c)));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Round 2: one signed share f_i(j) per OTHER participant, in package order. Throws on duplicate identifiers, a missing own package or a package from
     * another session. @param list<Obj> $allRound1Packages @return list<Obj> `{from, to, sessionId, share (raw), sig}`
     */
    public static function round2(DkgState $state, mixed $allRound1Packages): array
    {
        if (!is_array($allRound1Packages)) {
            throw new \TypeError('dkgRound2: packages must be a list');
        }
        $ids = array_map(static fn(mixed $p): mixed => self::m($p, 'identifier'), $allRound1Packages);
        if (count(array_unique(array_map(self::kid(...), $ids))) !== count($ids)) {
            throw new \RuntimeException('dkgRound2: duplicate identifiers in round-1 packages');
        }
        $mine = self::kid($state->identifier);
        if (!in_array($mine, array_map(self::kid(...), $ids), true)) {
            throw new \RuntimeException('dkgRound2: my own round-1 package is missing');
        }
        $sidB64 = Pca::b64u($state->sessionId);
        foreach ($allRound1Packages as $p) {
            if (self::m($p, 'sessionId') !== $sidB64) {
                throw new \RuntimeException('dkgRound2: a round-1 package is from a different session');
            }
        }
        $a0 = Frost::bytesToScalar($state->coefficients[0]);
        [, $bytes] = self::commitVec(Jsx::get($state->package, 'coefficientCommitments'));
        $out = [];
        foreach ($ids as $j) {
            if (self::kid($j) === $mine) {
                continue;
            }
            $ji = self::intOf($j);
            $share = self::evalPoly(array_map(Frost::bytesToScalar(...), $state->coefficients), $ji);
            $sig = self::signShareScalar($a0, $bytes, $state->sessionId, self::intOf($state->identifier), $ji, $share);
            $out[] = Obj::of(['from' => $state->identifier, 'to' => $j, 'sessionId' => $sidB64, 'share' => $share, 'sig' => $sig]);
        }
        return $out;
    }

    /** Check a received share: the sender's round-1 PoP, the sender's signature over (session, from, to, share) and the VSS equation at my identifier. Never throws. */
    public static function verifyShare(mixed $received, mixed $senderPackage, mixed $myIdentifier, mixed $sessionId): bool
    {
        try {
            $share = Jsx::truthy($received) ? self::m($received, 'share') : null;
            if (!is_string($share) || !is_string($sessionId)) {
                return false;
            }
            if (!self::verifyRound1(self::m($senderPackage, 'identifier'), $senderPackage, $sessionId)) {
                return false;
            }
            if (!self::verifyShareSigAgainstPackage(self::m($received, 'sig'), $sessionId, self::m($received, 'from'), $myIdentifier, $share, $senderPackage)) {
                return false;
            }
            return self::vssCheck(self::canonicalScalar($share), self::m($senderPackage, 'coefficientCommitments'), self::intOf($myIdentifier));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * File a complaint carrying the accused-signed share as evidence. `$p`: accused, accuser, receivedShare (raw), shareSig, senderCommitments, sessionId (raw).
     * @param Obj|array $p
     */
    public static function fileComplaint(mixed $p): Obj
    {
        $accused = Jsx::get($p, 'accused');
        $accuser = Jsx::get($p, 'accuser');
        $shareSig = Jsx::get($p, 'shareSig');
        $sid = Jsx::get($p, 'sessionId');
        if (!self::isInt($accused) || Js::num($accused) <= 0) {
            throw new \RuntimeException('dkgFileComplaint: accused must be a positive integer');
        }
        if (!self::isInt($accuser) || Js::num($accuser) <= 0) {
            throw new \RuntimeException('dkgFileComplaint: accuser must be a positive integer');
        }
        if (Js::num($accused) === Js::num($accuser)) {
            throw new \RuntimeException('dkgFileComplaint: cannot file a complaint against yourself');
        }
        if (!is_string($shareSig) || $shareSig === '') {
            throw new \RuntimeException('dkgFileComplaint: shareSig (the accused-signed share) is required');
        }
        if (!is_string($sid) || $sid === '') {
            throw new \RuntimeException('dkgFileComplaint: sessionId must be a non-empty byte string');
        }
        return Obj::of(['accused' => $accused, 'accuser' => $accuser, 'sessionId' => Pca::b64u($sid),
            'revealedShare' => Pca::b64u(Frost::bytesToScalar(Jsx::get($p, 'receivedShare'))), 'shareSig' => $shareSig]);
    }

    private static function find(mixed $pkgs, mixed $id): mixed
    {
        if (!is_array($pkgs)) {
            throw new \TypeError('round1Packages.find is not a function');
        }
        foreach ($pkgs as $p) {
            if (self::same(self::m($p, 'identifier'), $id)) {
                return $p;
            }
        }
        return null;
    }

    private static function same(mixed $a, mixed $b): bool
    {
        return Js::isNum($a) && Js::isNum($b) ? Js::num($a) === Js::num($b) : (is_string($a) && $a === $b);
    }

    /** Adjudicate a complaint against the accused's broadcast commitments: justified only when the accused signed a share that fails VSS. */
    public static function verifyComplaint(mixed $complaint, mixed $round1Packages): Obj
    {
        try {
            $accused = self::m($complaint, 'accused');
            $accuser = self::m($complaint, 'accuser');
            $pkg = self::find($round1Packages, $accused);
            if ($pkg === null) {
                return Obj::of(['justified' => false, 'reason' => 'accused ' . Jsx::str($accused) . ' has no round-1 package to adjudicate against']);
            }
            if (self::m($pkg, 'sessionId') !== self::m($complaint, 'sessionId')) {
                return Obj::of(['justified' => false, 'reason' => 'complaint sessionId does not match the accused round-1 package session']);
            }
            $sid = self::ub(self::m($complaint, 'sessionId'));
            $share = self::ub(self::m($complaint, 'revealedShare'));
            if (!self::verifyShareSigAgainstPackage(self::m($complaint, 'shareSig'), $sid, $accused, $accuser, $share, $pkg)) {
                return Obj::of(['justified' => false, 'atFault' => $accuser,
                    'reason' => 'revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)']);
            }
            if (self::vssCheck(self::canonicalScalar($share), self::m($pkg, 'coefficientCommitments'), self::intOf($accuser))) {
                return Obj::of(['justified' => false, 'atFault' => $accuser, 'reason' => 'accused-signed share is VALID against the accused commitments — false accusation']);
            }
            return Obj::of(['justified' => true, 'disqualify' => $accused, 'reason' => 'accused non-repudiably signed a share that FAILS VSS against its broadcast commitments']);
        } catch (\Throwable) {
            return Obj::of(['justified' => false, 'reason' => 'malformed complaint']);
        }
    }

    /** The accused's answer to a complaint: a fresh validly-signed, VSS-correct share for the accuser. Throws unless the state is the accused's, in this session. */
    public static function rebut(mixed $accused, mixed $complaint, DkgState $state): Obj
    {
        if (!self::same($state->identifier, $accused)) {
            throw new \RuntimeException('dkgRebut: myRound2State is not the accused');
        }
        if (!self::same(self::m($complaint, 'accused'), $accused)) {
            throw new \RuntimeException('dkgRebut: complaint does not name this accused');
        }
        if (Pca::b64u($state->sessionId) !== self::m($complaint, 'sessionId')) {
            throw new \RuntimeException('dkgRebut: complaint is scoped to a different session than my state');
        }
        $accuser = self::m($complaint, 'accuser');
        $share = self::evalPoly(array_map(Frost::bytesToScalar(...), $state->coefficients), self::intOf($accuser));
        return Obj::of(['accused' => $accused, 'accuser' => $accuser, 'sessionId' => self::m($complaint, 'sessionId'), 'presentedShare' => Pca::b64u($share),
            'shareSig' => self::signShare($state, $accuser, $share)]);
    }

    /** Resolve who is at fault in a complaint, given the accused's rebuttal (or null). @return Obj `{guilty, reason}` */
    public static function resolveBlame(mixed $complaint, mixed $rebuttal, mixed $round1Packages): Obj
    {
        $accuserOf = static fn(): mixed => Jsx::get($complaint, 'accuser');
        try {
            $accused = self::m($complaint, 'accused');
            $accuser = self::m($complaint, 'accuser');
            $pkg = self::find($round1Packages, $accused);
            if ($pkg === null) {
                return Obj::of(['guilty' => $accused, 'reason' => 'accused ' . Jsx::str($accused) . ' has no round-1 package to defend with']);
            }
            $csid = self::m($complaint, 'sessionId');
            if (self::m($pkg, 'sessionId') !== $csid) {
                return Obj::of(['guilty' => $accuser, 'reason' => 'complaint names a session the accused did not run — inadmissible']);
            }
            $sid = self::ub($csid);
            $share = self::ub(self::m($complaint, 'revealedShare'));
            if (self::verifyShareSigAgainstPackage(self::m($complaint, 'shareSig'), $sid, $accused, $accuser, $share, $pkg)) {
                if (!self::vssCheck(self::canonicalScalar($share), self::m($pkg, 'coefficientCommitments'), self::intOf($accuser))) {
                    return Obj::of(['guilty' => $accused, 'reason' => 'accused non-repudiably signed a share that fails VSS']);
                }
                return Obj::of(['guilty' => $accuser, 'reason' => 'accused-signed share is valid against its commitments — false accusation']);
            }
            if (Jsx::truthy($rebuttal) && self::same(self::m($rebuttal, 'accused'), $accused) && self::same(self::m($rebuttal, 'accuser'), $accuser)
                && self::m($rebuttal, 'sessionId') === $csid) {
                $rShare = self::ub(self::m($rebuttal, 'presentedShare'));
                $ok = self::verifyShareSigAgainstPackage(self::m($rebuttal, 'shareSig'), $sid, $accused, $accuser, $rShare, $pkg)
                    && self::vssCheck(self::canonicalScalar($rShare), self::m($pkg, 'coefficientCommitments'), self::intOf($accuser));
                if ($ok) {
                    return Obj::of(['guilty' => $accuser,
                        'reason' => 'accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted']);
                }
                return Obj::of(['guilty' => $accused, 'reason' => 'accused could not present a validly-signed, VSS-correct share on rebuttal']);
            }
            return Obj::of(['guilty' => $accuser,
                'reason' => 'complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused']);
        } catch (\Throwable) {
            return Obj::of(['guilty' => $accuserOf(), 'reason' => 'malformed complaint — inadmissible']);
        }
    }

    /**
     * The participants that survive: a valid round-1 package in the run's (majority) session and no complaint resolved against them. Ascending.
     * @return list<mixed>
     */
    public static function qualifiedSet(mixed $participants, mixed $complaints, mixed $round1Packages, mixed $rebuttals = []): array
    {
        $byId = [];
        $counts = [];
        foreach ($round1Packages as $p) {
            $byId[self::kid(self::m($p, 'identifier'))] = $p;
            $s = self::m($p, 'sessionId');
            $counts[self::kid($s)] = [$s, ($counts[self::kid($s)][1] ?? 0) + 1];
        }
        $run = '';
        $best = -1;
        foreach ($counts as [$s, $c]) {
            if ($c > $best) {
                $best = $c;
                $run = $s;
            }
        }
        $q = [];
        foreach ($participants as $p) {
            $pkg = $byId[self::kid($p)] ?? null;
            if ($pkg === null || self::m($pkg, 'sessionId') !== $run) {
                continue;
            }
            try {
                $sid = self::ub(self::m($pkg, 'sessionId'));
            } catch (\Throwable) {
                continue;
            }
            if (self::verifyRound1($p, $pkg, $sid)) {
                $q[self::kid($p)] = $p;
            }
        }
        foreach ($complaints as $c) {
            $reb = null;
            foreach ($rebuttals as $r) {
                if (self::same(self::m($r, 'accused'), self::m($c, 'accused')) && self::same(self::m($r, 'accuser'), self::m($c, 'accuser'))
                    && self::m($r, 'sessionId') === self::m($c, 'sessionId')) {
                    $reb = $r;
                    break;
                }
            }
            $res = self::resolveBlame($c, $reb, $round1Packages);
            if (self::same(Jsx::get($res, 'guilty'), self::m($c, 'accused'))) {
                unset($q[self::kid(Jsx::get($res, 'guilty'))]);
            }
        }
        $out = array_values($q);
        usort($out, static fn(mixed $a, mixed $b): int => Js::num($a) <=> Js::num($b));
        return $out;
    }

    private static function digestOf(Obj $o): string
    {
        return Pca::hashCanonical(Sign::n($o));
    }

    private static function round1PackageDigest(mixed $p): string
    {
        $pok = self::m($p, 'proofOfKnowledge');
        return self::digestOf(Obj::of(['identifier' => self::m($p, 'identifier'), 'sessionId' => self::m($p, 'sessionId'),
            'coefficientCommitments' => self::m($p, 'coefficientCommitments'), 'proofOfKnowledge' => Obj::of(['R' => self::m($pok, 'R'), 'mu' => self::m($pok, 'mu')])]));
    }

    private static function complaintDigest(mixed $c): string
    {
        return self::digestOf(Obj::of(['accused' => self::m($c, 'accused'), 'accuser' => self::m($c, 'accuser'), 'sessionId' => self::m($c, 'sessionId'),
            'revealedShare' => self::m($c, 'revealedShare'), 'shareSig' => self::m($c, 'shareSig')]));
    }

    /** The digest of the whole transcript: sorted round-1 package digests, sorted complaint digests, the qualified set and the session. */
    public static function transcriptDigest(mixed $round1Packages, mixed $complaints, mixed $qualified, string $sessionId): string
    {
        $r1 = array_map(self::round1PackageDigest(...), $round1Packages);
        sort($r1, SORT_STRING);
        $cs = array_map(self::complaintDigest(...), $complaints);
        sort($cs, SORT_STRING);
        $q = array_values($qualified);
        usort($q, static fn(mixed $a, mixed $b): int => Jsx::toNum($a) <=> Jsx::toNum($b));
        return self::digestOf(Obj::of(['sessionId' => Pca::b64u($sessionId), 'round1' => $r1, 'complaints' => $cs, 'qualified' => $q]));
    }

    /** This participant's echo of the transcript it saw. */
    public static function echo(mixed $identifier, mixed $round1Packages, mixed $complaints, mixed $qualified, string $sessionId): Obj
    {
        return Obj::of(['identifier' => $identifier, 'sessionId' => Pca::b64u($sessionId), 'transcriptDigest' => self::transcriptDigest($round1Packages, $complaints, $qualified, $sessionId)]);
    }

    /** Do all qualified participants echo the same transcript? @return Obj `{agreed, digest?, reason?}` */
    public static function checkEchoes(mixed $qualified, mixed $echoes, mixed $sessionId): Obj
    {
        try {
            $sid = Pca::b64u($sessionId);
            if (!is_array($echoes) || !is_array($qualified)) {
                throw new \TypeError('echoes is not iterable'); // for...of over a non-iterable throws in the reference: reported as malformed
            }
            $qs = [];
            foreach ($qualified as $q) {
                $qs[self::kid($q)] = $q;
            }
            $by = [];
            foreach ($echoes as $e) {
                $id = self::m($e, 'identifier');
                if (!isset($qs[self::kid($id)])) {
                    continue;
                }
                if (self::m($e, 'sessionId') !== $sid) {
                    return Obj::of(['agreed' => false, 'reason' => 'echo from ' . Jsx::str($id) . ' is bound to a different session']);
                }
                if (isset($by[self::kid($id)])) {
                    return Obj::of(['agreed' => false, 'reason' => 'duplicate echo from qualified participant ' . Jsx::str($id)]);
                }
                $by[self::kid($id)] = $e;
            }
            $agreed = null;
            foreach ($qs as $k => $j) {
                $e = $by[$k] ?? null;
                if ($e === null) {
                    return Obj::of(['agreed' => false, 'reason' => 'missing echo from qualified participant ' . Jsx::str($j)]);
                }
                $d = Jsx::get($e, 'transcriptDigest');
                if ($agreed === null) {
                    $agreed = $d;
                } elseif ($d !== $agreed) {
                    return Obj::of(['agreed' => false, 'reason' => 'qualified participant ' . Jsx::str($j) . ' echoed a DIFFERENT transcript (equivocation detected)']);
                }
            }
            if ($agreed === null) {
                return Obj::of(['agreed' => false, 'reason' => 'no qualified echoes to agree on']);
            }
            return Obj::of(['agreed' => true, 'digest' => $agreed]);
        } catch (\Throwable) {
            return Obj::of(['agreed' => false, 'reason' => 'malformed echoes']);
        }
    }

    /**
     * Finalize: the signing share (own f_i(i) plus every qualified sender's share), the group key and commitment, every qualified verifying share and a
     * self-consistency check. Refuses without the qualified set at threshold, with a different session, a missing or duplicate share, a wrong-degree
     * commitment vector or (with `$agreement`) an echo disagreement. @param ?array $qualified @param mixed $agreement `{echoes, complaints?}` or null
     */
    public static function finalize(mixed $myIdentifier, DkgState $state, mixed $receivedShares, mixed $allCommitments, mixed $qualified = null, mixed $agreement = null): Obj
    {
        if (!self::same($state->identifier, $myIdentifier)) {
            throw new \RuntimeException('dkgFinalize: myState.identifier != myIdentifier');
        }
        $ids = array_map(static fn(mixed $p): mixed => self::m($p, 'identifier'), $allCommitments);
        $idKeys = array_map(self::kid(...), $ids);
        if (count(array_unique($idKeys)) !== count($ids)) {
            throw new \RuntimeException('dkgFinalize: duplicate identifiers in commitments');
        }
        $me = self::kid($myIdentifier);
        if (!in_array($me, $idKeys, true)) {
            throw new \RuntimeException('dkgFinalize: my own package is missing from allCommitments');
        }
        $sidB64 = Pca::b64u($state->sessionId);
        foreach ($allCommitments as $p) {
            if (self::m($p, 'sessionId') !== $sidB64) {
                throw new \RuntimeException('dkgFinalize: a round-1 package is from a different session');
            }
        }
        $qset = array_values(array_filter($qualified ?? $ids, static fn(mixed $id): bool => in_array(self::kid($id), $idKeys, true)));
        $qSet = [];
        foreach ($qset as $id) {
            $qSet[self::kid($id)] = $id;
        }
        if (!isset($qSet[$me])) {
            throw new \RuntimeException('dkgFinalize: myIdentifier is not in the qualified set');
        }
        $t = $state->t;
        if (count($qSet) < $t) {
            throw new \RuntimeException('dkgFinalize: qualified set (' . count($qSet) . ") is smaller than the threshold t=$t");
        }
        foreach ($allCommitments as $p) {
            if (!isset($qSet[self::kid(self::m($p, 'identifier'))])) {
                continue;
            }
            $cc = self::m($p, 'coefficientCommitments');
            if (!is_array($cc) || count($cc) !== $t) {
                throw new \RuntimeException('dkgFinalize: a participant committed to the wrong number of coefficients, expected t=' . $t);
            }
        }
        $echoes = $agreement === null ? null : Jsx::get($agreement, 'echoes');
        if ($echoes !== null && !($echoes instanceof Undef)) {
            $qsorted = array_values($qSet);
            usort($qsorted, static fn(mixed $a, mixed $b): int => Js::num($a) <=> Js::num($b));
            $check = self::checkEchoes($qsorted, $echoes, $state->sessionId);
            if ($check->get('agreed') !== true) {
                throw new \RuntimeException('dkgFinalize: echo-broadcast agreement failed — ' . Jsx::str($check->get('reason')));
            }
            $cmp = Jsx::get($agreement, 'complaints');
            $myDigest = self::transcriptDigest($allCommitments, $cmp instanceof Undef || $cmp === null ? [] : $cmp, $qsorted, $state->sessionId);
            if ($check->get('digest') !== $myDigest) {
                throw new \RuntimeException('dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)');
            }
        }
        $recv = [];
        foreach ($receivedShares as $r) {
            $from = self::m($r, 'from');
            if (self::kid($from) === $me || !isset($qSet[self::kid($from)])) {
                continue;
            }
            if (self::m($r, 'sessionId') !== $sidB64) {
                throw new \RuntimeException('dkgFinalize: a received share is from a different session');
            }
            if (isset($recv[self::kid($from)])) {
                throw new \RuntimeException('dkgFinalize: duplicate received share');
            }
            $recv[self::kid($from)] = self::m($r, 'share');
        }
        foreach ($qset as $j) {
            if (self::kid($j) !== $me && !isset($recv[self::kid($j)])) {
                throw new \RuntimeException('dkgFinalize: missing received share from a qualified participant');
            }
        }
        $s = self::evalPoly(array_map(Frost::bytesToScalar(...), $state->coefficients), self::intOf($myIdentifier));
        foreach ($recv as $share) {
            $s = Frost::sAdd($s, Frost::bytesToScalar($share));
        }
        $group = [];
        for ($k = 0; $k < $t; $k++) {
            $acc = Frost::mulBase(self::zero());
            foreach ($allCommitments as $p) {
                if (isset($qSet[self::kid(self::m($p, 'identifier'))])) {
                    $acc = Frost::add($acc, Frost::decodeSafePoint(self::ub(self::m($p, 'coefficientCommitments')[$k])));
                }
            }
            $group[] = $acc;
        }
        $verifying = [];
        foreach ($qset as $j) {
            $x = self::sc(self::intOf($j));
            $acc = Frost::mulBase(self::zero());
            $xk = Frost::scalarOfId(1);
            foreach ($group as $phi) {
                $acc = Frost::add($acc, Frost::mulPoint($phi, $xk));
                $xk = Frost::sMul($xk, $x);
            }
            $verifying[] = Obj::of(['identifier' => $j, 'publicKey' => $acc]);
        }
        $vs = Frost::mulBase($s);
        $mine = null;
        foreach ($verifying as $v) {
            if (self::same($v->get('identifier'), $myIdentifier)) {
                $mine = $v;
                break;
            }
        }
        if ($mine === null || !hash_equals($vs, Frost::decodeSafePoint($mine->get('publicKey')))) {
            throw new \RuntimeException('dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)');
        }
        return Obj::of(['identifier' => $myIdentifier, 'signingShare' => $s, 'groupPublicKey' => $group[0], 'verifyingShare' => $vs,
            'publicKeyPackage' => Obj::of(['groupPublicKey' => $group[0], 'groupCommitment' => $group, 'verifyingShares' => $verifying])]);
    }

    /**
     * A whole honest-majority ceremony in one process (for tests and bootstrapping): rounds, signed shares, complaints against `cheaters` (whose shares are
     * corrupted), rebuttals, the qualified set, echoes (`equivocateEchoFor` echoes a different view) and finalize for every qualified participant.
     * `$opts`: identifiers?, coefficientsByParticipant?, sessionId?, cheaters?, equivocateEchoFor?, random?. @return Obj raw bytes for keys and the session id
     */
    public static function simulate(mixed $t, mixed $n, array $opts = []): Obj
    {
        if (!self::isInt($t) || !self::isInt($n) || Js::num($t) < 1 || Js::num($n) < Js::num($t)) {
            throw new \RuntimeException('frostDkgSimulate: need 1 <= t <= n');
        }
        $nn = self::intOf($n);
        $ids = $opts['identifiers'] ?? range(1, $nn);
        if (count($ids) !== $nn) {
            throw new \RuntimeException('frostDkgSimulate: identifiers.length must equal n');
        }
        if (count(array_unique(array_map(self::kid(...), $ids))) !== $nn) {
            throw new \RuntimeException('frostDkgSimulate: identifiers must be distinct');
        }
        foreach ($ids as $x) {
            if (!self::isInt($x) || Js::num($x) <= 0) {
                throw new \RuntimeException('frostDkgSimulate: identifiers must be positive integers');
            }
        }
        $sid = $opts['sessionId'] ?? self::rand($opts);
        $cheaters = array_map(self::kid(...), $opts['cheaters'] ?? []);
        $states = [];
        foreach ($ids as $idx => $id) {
            $o = ['random' => $opts['random'] ?? null];
            $cb = $opts['coefficientsByParticipant'][$idx] ?? null;
            if ($cb !== null) {
                $o['coefficients'] = $cb;
            }
            $states[] = self::round1($id, $t, $n, $sid, $o)['state'];
        }
        $r1 = array_map(static fn(DkgState $s): Obj => $s->package, $states);
        foreach ($r1 as $pkg) {
            if (!self::verifyRound1($pkg->get('identifier'), $pkg, $sid)) {
                throw new \RuntimeException('frostDkgSimulate: PoP verification failed');
            }
        }
        $inbox = [];
        foreach ($ids as $id) {
            $inbox[self::kid($id)] = [];
        }
        $complaints = [];
        $byId = [];
        foreach ($states as $st) {
            $byId[self::kid($st->identifier)] = $st;
        }
        foreach ($states as $st) {
            foreach (self::round2($st, $r1) as $out) {
                $share = $out->get('share');
                $sig = $out->get('sig');
                if (in_array(self::kid($out->get('from')), $cheaters, true)) {
                    $share[0] = chr(ord($share[0]) ^ 1);
                    $sig = self::signShare($st, $out->get('to'), $share);
                }
                $senderPkg = $byId[self::kid($out->get('from'))]->package;
                if (self::verifyShare(Obj::of(['from' => $out->get('from'), 'share' => $share, 'sig' => $sig]), $senderPkg, $out->get('to'), $sid)) {
                    $inbox[self::kid($out->get('to'))][] = Obj::of(['from' => $out->get('from'), 'sessionId' => $out->get('sessionId'), 'share' => $share, 'sig' => $sig]);
                } else {
                    $complaints[] = self::fileComplaint(Obj::of(['accused' => $out->get('from'), 'accuser' => $out->get('to'), 'receivedShare' => $share, 'shareSig' => $sig,
                        'senderCommitments' => $senderPkg->get('coefficientCommitments'), 'sessionId' => $sid]));
                }
            }
        }
        $rebuttals = array_map(static fn(Obj $c): Obj => self::rebut($c->get('accused'), $c, $byId[self::kid($c->get('accused'))]), $complaints);
        $q = self::qualifiedSet($ids, $complaints, $r1, $rebuttals);
        if (count($q) < self::intOf($t)) {
            throw new \RuntimeException('frostDkgSimulate: only ' . count($q) . ' qualified participants after the blame round');
        }
        $lastQ = $q[count($q) - 1];
        $echoes = [];
        foreach ($q as $id) {
            $view = self::kid($id) === self::kid($opts['equivocateEchoFor'] ?? null) ? array_values(array_filter($q, static fn(mixed $x): bool => self::kid($x) !== self::kid($lastQ))) : $q;
            $echoes[] = self::echo($id, $r1, $complaints, $view, $sid);
        }
        $qk = array_map(self::kid(...), $q);
        $kps = [];
        foreach ($states as $st) {
            if (in_array(self::kid($st->identifier), $qk, true)) {
                $kps[] = self::finalize($st->identifier, $st, $inbox[self::kid($st->identifier)], $r1, $q, Obj::of(['echoes' => $echoes, 'complaints' => $complaints]));
            }
        }
        $gpk = $kps[0]->get('groupPublicKey');
        foreach ($kps as $kp) {
            if ($kp->get('groupPublicKey') !== $gpk) {
                throw new \RuntimeException('frostDkgSimulate: participants disagree on the group public key');
            }
        }
        return Obj::of(['groupPublicKey' => $gpk,
            'participantShares' => array_map(static fn(Obj $kp): Obj => Obj::of(['identifier' => $kp->get('identifier'), 'share' => $kp->get('signingShare'), 'publicKey' => $kp->get('verifyingShare')]), $kps),
            'groupCommitment' => $kps[0]->get('publicKeyPackage')->get('groupCommitment'), 'keyPackages' => $kps, 'round1Packages' => $r1, 'qualified' => $q,
            'complaints' => $complaints, 'rebuttals' => $rebuttals, 'echoes' => $echoes, 'sessionId' => $sid]);
    }
}
