<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostNet.php';
require_once __DIR__ . '/../src/FrostNonceStore.php';

use Atlas\Pca\EquivocationError;
use Atlas\Pca\EquivocationGuard;
use Atlas\Pca\FrostNet;
use Atlas\Pca\FrostPq;
use Atlas\Pca\Frost;
use Atlas\Pca\Js;
use Atlas\Pca\MemoryFrostNonceStore;
use Atlas\Pca\NonceRecord;
use Atlas\Pca\NonceStore;
use Atlas\Pca\NonceStoreContract;
use Atlas\Pca\PoPError;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The stateless half of networked FROST against the TS reference: the constants, the action digest, the allow token (issue and verify), the equivocation
 * guard and the wire decoders (test-data/ref-frost-net.json.gz). A refusal flagged `reasonOpen` is compared without its text. Signer proof of possession, the
 * signer service, the coordinator and the nonce store are replayed by their own tests.
 */
final class RefFrostNetDifferentialTest extends TestCase
{
    private const FILE = 'ref-frost-net.json.gz';
    private const FNS = ['constants' => 1, 'frostActionDigest' => 7, 'issueAllowToken' => 25, 'verifyAllowToken' => 58, 'equivocationGuard' => 27,
        'decodeCommitment' => 22, 'decodeCommitments' => 10, 'decodeVerificationShares' => 16,
        'createSignerPoP' => 24, 'verifySignerPoP' => 36, 'enrollVerificationShares' => 23, 'nonceStore' => 16, 'assertNonceStoreContract' => 11];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    /** `{"$bytes": b64u}` to raw bytes and `{"$num": ...}` to the double, throughout. */
    private static function conv(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return self::b($v);
            }
            if ($v->keys() === ['$share']) {
                return self::share($v->get('$share'));
            }
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::conv($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::conv(...), $v) : $v;
    }

    /** `{"$bytes": b64u}` or `{"$bytes": {"$seed": label}}` to raw bytes. */
    private static function b(Obj $v): string
    {
        return $v->get('$bytes') instanceof Obj ? self::seed($v) : Base::bytes($v);
    }

    private static function seed(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    /** The dealer share of participant `id` for a `{"$share": descriptor}`. */
    private static function share(Obj $d): string
    {
        $coeffs = $d->get('coefficients');
        $kg = Frost::trustedDealerKeygen((int)Js::num($d->get('t')), (int)Js::num($d->get('n')), self::seed($d->get('secret')),
            $coeffs === null ? null : array_map(self::seed(...), $coeffs), $d->get('identifiers') === null ? null : array_map(static fn($x) => (int)Js::num($x), $d->get('identifiers')));
        foreach ($kg['participantShares'] as $p) {
            if ($p['identifier'] === (int)Js::num($d->get('id'))) {
                return $p['share'];
            }
        }
        throw new \LogicException('no such share');
    }

    private static function rec(Obj $r): NonceRecord
    {
        return new NonceRecord(Base::bytes($r->get('hiding')), Base::bytes($r->get('binding')), Base::bytes($r->get('hidingCommitment')), Base::bytes($r->get('bindingCommitment')), $r->get('createdAt'));
    }

    private static function recOut(NonceRecord $r): Obj
    {
        return Obj::of(['hiding' => Base::outBytes($r->hiding), 'binding' => Base::outBytes($r->binding), 'hidingCommitment' => Base::outBytes($r->hidingCommitment),
            'bindingCommitment' => Base::outBytes($r->bindingCommitment), 'createdAt' => $r->createdAt]);
    }

    private static function store(array $ops): array
    {
        $s = new MemoryFrostNonceStore();
        $out = [];
        foreach ($ops as $op) {
            try {
                switch ($op->get('op')) {
                    case 'create':
                        $r = self::rec($op->get('rec'));
                        $s->create($op->get('sid'), $r);
                        if ($op->get('mutateInputAfter')) {
                            $r->hiding = str_repeat("\xee", 32);
                        }
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'load':
                        $r = $s->load($op->get('sid'));
                        $j = $r === null ? null : self::recOut($r);
                        if ($r !== null && $op->get('mutate')) {
                            $r->hiding = str_repeat("\xee", 32);
                        }
                        $out[] = Obj::of(['value' => $j]);
                        break;
                    case 'spend':
                        $s->spend($op->get('sid'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'drop':
                        $s->drop($op->get('sid'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    default:
                        $out[] = Obj::of(['value' => $s->isSpent($op->get('sid'))]);
                }
            } catch (\Throwable $e) {
                $out[] = Obj::of(['$throws' => $e->getMessage()]);
            }
        }
        return $out;
    }

    /** The store with exactly one defect, and the restart that goes with it. */
    private static function broken(string $kind): array
    {
        $st = new class($kind) implements NonceStore {
            /** @var array<string,NonceRecord> */
            public array $live = [];
            /** @var array<string,true> */
            public array $spent = [];

            public function __construct(private string $kind)
            {
            }

            public function create(string $sessionId, NonceRecord $record): void
            {
                if ($this->kind !== 'create-overwrites' && isset($this->live[$sessionId])) {
                    throw new \RuntimeException('exists');
                }
                if ($this->kind !== 'create-over-spent' && isset($this->spent[$sessionId])) {
                    throw new \RuntimeException('spent');
                }
                $this->live[$sessionId] = $this->kind === 'create-aliases-input' ? $record : $record->copy();
            }

            public function load(string $sessionId): ?NonceRecord
            {
                $r = $this->live[$sessionId] ?? null;
                return $r === null ? null : ($this->kind === 'load-aliases' ? $r : $r->copy());
            }

            public function spend(string $sessionId): void
            {
                if (!isset($this->live[$sessionId])) {
                    if ($this->kind === 'spend-unknown-ok' || ($this->kind === 'spend-twice-ok' && isset($this->spent[$sessionId]))) {
                        return;
                    }
                    throw new \RuntimeException('not live');
                }
                unset($this->live[$sessionId]);
                $this->spent[$sessionId] = true;
            }

            public function drop(string $sessionId): void
            {
                unset($this->live[$sessionId]);
                if ($this->kind === 'drop-marks-spent') {
                    $this->spent[$sessionId] = true;
                }
            }

            public function isSpent(string $sessionId): bool
            {
                return $this->kind === 'unknown-reports-spent' ? true : isset($this->spent[$sessionId]);
            }
        };
        $reopen = static function (NonceStore $s) use ($kind): NonceStore {
            if ($kind === 'spent-forgotten-on-restart') {
                $s->spent = [];
            }
            if ($kind === 'live-lost-on-restart') {
                $s->live = [];
            }
            return $s;
        };
        return [static fn(): NonceStore => $st, $reopen];
    }

    private static function contract(Obj $a): mixed
    {
        try {
            $store = $a->get('store');
            if ($store === 'memory') {
                NonceStoreContract::assert(static fn(): NonceStore => new MemoryFrostNonceStore());
            } else {
                [$make, $reopen] = self::broken(substr($store, strlen('broken:')));
                NonceStoreContract::assert($make, $reopen);
            }
            return null;
        } catch (\Throwable $e) {
            throw $e; // the corpus expects the contract failure itself as a throw
        }
    }

    private static function asArray(Obj $o): array
    {
        $r = [];
        foreach ($o->keys() as $k) {
            $r[$k] = $o->get($k);
        }
        return $r;
    }

    private static function open(Obj $c, array $have): array
    {
        $w = $c->get('out');
        if ($w instanceof Obj && $w->get('reasonOpen') === true) {
            $c->set('out', $w->without('reason', 'reasonOpen'));
            unset($have['reason']);
        }
        return $have;
    }

    private static function guard(array $ops): array
    {
        $g = new EquivocationGuard();
        $out = [];
        foreach ($ops as $op) {
            try {
                if ($op->get('op') === 'forget') {
                    $g->forget($op->get('session_id'));
                } else {
                    $g->observe($op->get('session_id'), $op->get('round'), $op->get('identifier'), $op->get('message'));
                }
                $out[] = Obj::of(['ok' => true]);
            } catch (EquivocationError $e) {
                $out[] = Obj::of(['$throws' => $e->getMessage(), 'class' => 'EquivocationError', 'session_id' => $e->sessionId, 'round' => $e->round,
                    'identifier' => $e->identifier, 'previousDigest' => $e->previousDigest, 'offendingDigest' => $e->offendingDigest]);
            } catch (\Throwable $e) {
                $out[] = Obj::of(['$throws' => $e->getMessage()]);
            }
        }
        return $out;
    }

    private static function dec(array $d): Obj
    {
        return Obj::of(['identifier' => $d['identifier']] + (isset($d['hiding']) ? ['hiding' => Base::outBytes($d['hiding']), 'binding' => Base::outBytes($d['binding'])]
            : ['publicKey' => Base::outBytes($d['publicKey'])]));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => Obj::of(['ALLOW_TOKEN_TYP' => FrostNet::ALLOW_TOKEN_TYP, 'SIGNER_POP_DST' => FrostNet::SIGNER_POP_DST,
                'MAX_FROST_SIGNING_SET' => FrostNet::MAX_FROST_SIGNING_SET, 'DEFAULT_FROST_GROUP_ALG' => FrostPq::DEFAULT_GROUP_ALG,
                'PQ_QUORUM_VERSION' => FrostPq::PQ_QUORUM_VERSION, 'PQ_QUORUM_ALG' => FrostPq::PQ_QUORUM_ALG, 'MAX_PQ_QUORUM_ENTRIES' => FrostPq::MAX_PQ_QUORUM_ENTRIES]),
            'frostActionDigest' => static fn(array $a) => FrostNet::frostActionDigest(is_string($a[0]) ? [$a[0]] : self::conv($a[0])), // a JS string is not bytes
            'issueAllowToken' => static function (array $a) {
                $q = isset($a[2]) ? array_map(static fn($b) => self::b($b), $a[2]->get('$rng')) : [];
                return FrostNet::issueAllowToken(self::conv($a[0]), self::conv($a[1]), $q === [] ? null : static fn(): string => array_shift($q));
            },
            'verifyAllowToken' => static fn(array $a, Obj $c) => self::open($c, FrostNet::verifyAllowToken($a[0], self::asArray(self::conv($a[1])))),
            'equivocationGuard' => static fn(array $a) => self::guard($a[0]),
            'decodeCommitment' => static fn(array $a) => self::dec(FrostNet::decodeCommitment($a[0])),
            'decodeCommitments' => static fn(array $a) => array_map(self::dec(...), FrostNet::decodeCommitments($a[0])),
            'decodeVerificationShares' => static fn(array $a) => array_map(self::dec(...), FrostNet::decodeVerificationShares($a[0])),
            'createSignerPoP' => static function (array $a) {
                $o = self::asArray(self::conv($a[2]));
                if (isset($a[3]) && $a[3] instanceof Obj && $a[3]->has('$rng')) { // the reference draws its nonce from the scripted randomness (the last argument)
                    $o['nonce'] = self::b($a[3]->get('$rng')[0]);
                }
                return FrostNet::createSignerPoP($a[0], self::conv($a[1]), $o);
            },
            'verifySignerPoP' => static fn(array $a) => FrostNet::verifySignerPoP($a[0], self::conv($a[1])),
            'enrollVerificationShares' => static fn(array $a) => array_map(static fn(array $d): Obj => Obj::of(['identifier' => $d['identifier'], 'publicKey' => Base::outBytes($d['publicKey'])]),
                FrostNet::enrollVerificationShares(self::conv($a[0]), self::conv($a[1]))),
            'nonceStore' => static fn(array $a) => self::store($a[0]),
            'assertNonceStoreContract' => static fn(array $a) => self::contract($a[0]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
