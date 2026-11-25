<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attestation.php';

use Atlas\Pca\Attestation;
use Atlas\Pca\AttestationNonceStore;
use Atlas\Pca\DevAttestor;
use Atlas\Pca\Jsx;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryNonceStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\TransparencyLedger;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Software attestation against the TS reference: every case of test-data/ref-attestation-soft.json.gz (the binding, the dev attestor and
 * its documents, the registry, the nonce store and entropy gate, the agent-binding match, the verifier and its hook, the multi-root
 * verifier, evidence digest and anchoring). A hardware verifier is a spec `{result}` or `{throws}` of a constant verifier. Keys are
 * the seeds "att/<label>". RULING: `allowUnboundPq` is not ported; the verifyAttestation cases the reference accepts only through it
 * must be REFUSED. A reason that starts with "attestation verification error (fail closed):" carries the reference's own exception text:
 * only the prefix is compared.
 */
final class RefAttestationSoftDifferentialTest extends TestCase
{
    private const FILE = 'ref-attestation-soft.json.gz';
    private const UNBOUND_ONLY = 2;
    private const FAIL_CLOSED = 'attestation verification error (fail closed):';
    private const FNS = ['attestationBinding' => 27, 'attestationBindingB64u' => 27, 'attest' => 18, 'attestorPublicKey' => 3, 'attestationDigest' => 6, 'registry' => 6,
        'nonceStore' => 23, 'nonceEntropyOk' => 32, 'requiresAttestation' => 29, 'matchAgentBinding' => 170, 'nonceBinds' => 8, 'verifyAttestation' => 91,
        'attestationHook' => 23, 'multiRoot' => 27, 'attestationEvidenceDigest' => 11, 'anchorEvidence' => 10, 'constants' => 1];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function un(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::un($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::un(...), $v) : $v;
    }

    /** A secret as raw bytes: {$bytes: {$seed: label}}, {$seed: label} (sha256("atlas-pca-conformance/" . label)) or base64url text. */
    private static function secret(mixed $v): string
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            $v = $v->get('$bytes');
        }
        if ($v instanceof Obj && $v->has('$seed')) {
            return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
        }
        return (string)Pca::unb64u((string)$v);
    }

    private static function num(mixed $v): mixed
    {
        return $v instanceof Num ? $v->float() : $v;
    }

    /** A constant hardware verifier from its spec: `{result}` answers the result, `{throws}` throws. */
    private static function hw(mixed $h): ?\Closure
    {
        if ($h === null) {
            return null;
        }
        return static function (mixed $input) use ($h): mixed {
            if ($h->has('throws')) {
                throw new \RuntimeException($h->get('throws'));
            }
            return self::un($h->get('result'));
        };
    }

    private static function failClosed(mixed $have, mixed $want): mixed
    {
        $r = $have instanceof Obj ? $have->get('reason') : (is_array($have) ? ($have['reason'] ?? null) : null);
        $w = $want instanceof Obj ? $want->get('reason') : null;
        if (is_string($r) && is_string($w) && str_starts_with($r, self::FAIL_CLOSED) && str_starts_with($w, self::FAIL_CLOSED)) {
            $have['reason'] = $w;
        }
        return $have;
    }

    private static function nonceStore(array $a): array
    {
        $opts = self::un($a[1] ?? null);
        $o = $opts instanceof Obj ? Jsx::spread($opts) : new Obj();
        $t = 0;
        $o->set('now', static function () use (&$t) {
            return $t;
        });
        $s = new MemoryNonceStore($a[0] === null ? null : self::un($a[0]), $o);
        $out = [];
        foreach ($a[2] as $x) {
            if ($x[0] === 'clock') {
                $t = self::num(self::un($x[1]));
                $out[] = null;
            } else {
                $out[] = $s->consume($x[1]);
            }
        }
        return $out;
    }

    private static function constStore(bool $answer): AttestationNonceStore
    {
        return new class($answer) implements AttestationNonceStore {
            public function __construct(private readonly bool $a)
            {
            }

            public function consume(mixed $nonce): bool
            {
                return $this->a;
            }
        };
    }

    private static function hook(array $a): array
    {
        $op = self::un($a[0]);
        $now = self::num($op->get('now'));
        $o = new Obj();
        foreach ($op->keys() as $k) {
            if (!in_array($k, ['store', 'storeConsume', 'hardware', 'docs', 'binding', 'now'], true)) {
                $o->set($k, $op->get($k));
            }
        }
        $o->set('now', static fn() => $now);
        $o->set('hardware', self::hw($op->get('hardware')));
        $o->set('resolveDocument', Attestation::registry($op->get('docs') ?? []));
        $store = $op->get('store');
        if ($store instanceof Obj) {
            $o->set('nonceStore', new MemoryNonceStore($store->get('max'), Obj::of(['retentionMs' => $store->get('retentionMs'), 'now' => static fn() => $now])));
        }
        if ($op->has('storeConsume')) {
            $o->set('nonceStore', self::constStore($op->get('storeConsume') === true));
        }
        $b = $op->get('binding');
        if ($b === 'throws') {
            $o->set('expectedBinding', static function () {
                throw new \RuntimeException('boom');
            });
        } elseif ($b instanceof Obj) {
            $by = $b->get('byNonce');
            $o->set('expectedBinding', static function (mixed $ctx) use ($by) {
                $k = Jsx::get(Jsx::get(Jsx::get($ctx, 'pcactn'), 'attestation'), 'quote_digest');
                return is_string($k) && $by->has($k) ? $by->get($k) : Jsx::$U;
            });
        }
        $v = Attestation::createAttestationVerifier($o);
        return array_map(static fn($c) => $v($c), $a[1]);
    }

    private static function multiRoot(array $a): mixed
    {
        $pol = self::un($a[0]);
        $roots = [];
        foreach ($pol->get('roots') as $r) {
            $o = Obj::of(['id' => $r->get('id')]);
            foreach (['required', 'suite'] as $k) {
                if ($r->has($k)) {
                    $o->set($k, $r->get($k));
                }
            }
            $o->set('verifier', self::hw($r->get('hw')));
            $roots[] = $o;
        }
        $v = Attestation::createMultiRootVerifier(Obj::of(['threshold' => $pol->get('threshold'), 'roots' => $roots]));
        return $a[1] === null ? ['built' => true] : $v(self::un($a[1]));
    }

    private static function anchor(array $a): array
    {
        $op = self::un($a[1]);
        $ledger = $op->get('ledger') === 'ok' ? new TransparencyLedger($op->get('principal') ?? '') : null;
        for ($i = 0; $i < (int)Jsx::toNum($op->get('preload') ?? 0); $i++) {
            $ledger->appendCommitment('c' . $i);
        }
        $seed = $op->get('guardianSeed');
        $now = $op->has('now') ? self::num($op->get('now')) : null;
        return Attestation::anchorEvidence(self::un($a[0]), $ledger, $seed === null ? null : new KeyPair(self::secret($seed)), null, null, $op->get('instanceId'),
            $op->has('now') ? static fn() => $now : null, $op->get('required') === true);
    }

    private static function verify(array $a, Obj $c): mixed
    {
        $i = self::un($a[0]);
        $in = new Obj();
        foreach ($i->keys() as $k) {
            if ($k !== 'hardware') {
                $in->set($k, $i->get($k));
            }
        }
        $in->set('hardware', self::hw($i->get('hardware')));
        $have = Attestation::verifyAttestation($in);
        $want = $c->get('out');
        if ($i->get('allowUnboundPq') === true && $want instanceof Obj && $want->get('ok') === true) {
            Assert::assertFalse($have['ok'], 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
            return $want;
        }
        return self::failClosed($have, $want);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'attestationBinding' => static fn(array $a) => Base::outBytes(Attestation::binding(self::un($a[0]))),
            'attestationBindingB64u' => static fn(array $a) => Attestation::bindingB64u(self::un($a[0])),
            'attest' => static function (array $a) {
                $su = $a[1];
                $alg = $su === null ? null : $su->get('alg');
                $pq = $su === null || $alg === 'ed25519' ? null : new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed')));
                return (new DevAttestor(new KeyPair(self::secret($a[0])), $alg, $pq))->attest(self::un($a[2]));
            },
            'attestorPublicKey' => static function (array $a) {
                $su = $a[1];
                $alg = $su === null ? null : $su->get('alg');
                $pq = $su === null || $alg === 'ed25519' ? null : new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed')));
                return (new DevAttestor(new KeyPair(self::secret($a[0])), $alg, $pq))->publicKey;
            },
            'attestationDigest' => static fn(array $a) => Attestation::attestationDigest(self::un($a[0])),
            'registry' => static function (array $a) {
                $r = Attestation::registry($a[0]);
                return array_map(static fn($q) => $r(Obj::of(['pcactn' => Obj::of(['attestation' => Obj::of(['quote_digest' => $q])])])), $a[1]);
            },
            'nonceStore' => static fn(array $a) => self::nonceStore($a),
            'nonceEntropyOk' => static fn(array $a) => Attestation::nonceEntropyOk($a[0], $a[1] === null ? Attestation::MIN_NONCE_BYTES : self::un($a[1])),
            'requiresAttestation' => static fn(array $a) => Attestation::requiresAttestation($a[0]),
            'matchAgentBinding' => static fn(array $a) => Attestation::matchAgentBinding($a[0], $a[1]),
            'nonceBinds' => static fn(array $a) => Attestation::nonceBinds($a[0], $a[1]),
            'verifyAttestation' => static fn(array $a, Obj $c) => self::verify($a, $c),
            'attestationHook' => static fn(array $a, Obj $c) => array_map(static fn($r, $w) => self::failClosed($r, $w), self::hook($a), $c->get('out') ?? []),
            'multiRoot' => static fn(array $a) => self::multiRoot($a),
            'attestationEvidenceDigest' => static fn(array $a) => Attestation::evidenceDigest(self::un($a[0])),
            'anchorEvidence' => static fn(array $a) => self::anchor($a),
            'constants' => static fn(array $a) => ['ATTEST_ANCHOR_DOMAIN' => Attestation::ANCHOR_DOMAIN, 'ATTEST_BIND_DOMAIN' => Attestation::BIND_DOMAIN,
                'DEFAULT_NONCE_RETENTION_MS' => Attestation::DEFAULT_NONCE_RETENTION_MS, 'MAX_ATTESTATION_AGE_MS' => Attestation::MAX_AGE_MS,
                'MIN_ATTESTATION_NONCE_BYTES' => Attestation::MIN_NONCE_BYTES],
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        $unbound = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
            $unbound += str_contains($line, '"allowUnboundPq":true') && str_contains($line, '"out":{"ok":true') ? 1 : 0;
        }
        $this->assertSame(self::FNS, $have);
        $this->assertSame(self::UNBOUND_ONLY, $unbound);
    }
}
