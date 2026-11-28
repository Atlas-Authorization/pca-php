<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestAllowlist.php';
require_once __DIR__ . '/../src/AttestAllowlistAnchor.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\AttestAllowlist;
use Atlas\Pca\AttestAllowlistAnchor;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Pq;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An in-memory AtomicKv that can list its records. */
final class AllowlistTestKv implements AtomicKv
{
    /** @var array<string,string> */
    public array $m = [];

    public function get(string $key): ?string
    {
        return $this->m[$key] ?? null;
    }

    public function update(string $key, callable $fn): void
    {
        $next = $fn($this->m[$key] ?? null);
        if ($next !== null) {
            $this->m[$key] = $next;
        }
    }
}

/**
 * The signed measurement-allowlist manifests and their transparency anchor against the TS reference: every case of
 * test-data/ref-attest-allowlist.json.gz (verify under every suite, hostile shapes and bodies, durable verify, create / sign / revoke,
 * projection and the policy fields, the anchor commit, the operator log and the anchored verification, incl. the committed anchor vectors).
 * The reason text of a refusal is not part of the contract: only the code is compared. `{"$num": "NaN"|"Infinity"|"-Infinity"}` is that double;
 * a `{"$seed": label}` is sha256("atlas-pca-conformance/" . label).
 */
final class RefAttestAllowlistDifferentialTest extends TestCase
{
    private const FILE = 'ref-attest-allowlist.json.gz';
    private const FNS = ['constants' => 1, 'verifyAllowlistManifest' => 744, 'verifyAllowlistDurable' => 23, 'createAllowlistManifest' => 6, 'signAllowlistManifest' => 10,
        'revokeAllowlistEntry' => 11, 'driverVersionSlotHex' => 13, 'projectAllowlist' => 9, 'policyFields' => 45, 'anchorCommit' => 4, 'anchorEntryOf' => 1,
        'anchorOps' => 20, 'verifyAnchored' => 72];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function num(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF, default => throw new \LogicException('bad $num'),
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::num($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::num(...), $v) : $v;
    }

    private static function secret(mixed $v): string
    {
        return $v instanceof Obj && $v->has('$seed') ? hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true) : (string)Pca::unb64u((string)$v);
    }

    /** A refusal is compared by its code only. */
    private static function code(array $r): array
    {
        return $r['ok'] === true ? $r : ['ok' => false, 'code' => $r['code']];
    }

    private static function dropReason(Obj $c, ?string $member = null): void
    {
        $o = $c->get('out');
        if ($member !== null) {
            $o = $o->get($member);
            $o = is_array($o) ? array_map(static fn($x) => $x instanceof Obj ? $x->without('reason') : $x, $o) : $o;
            $c->set('out', $c->get('out')->without($member));
            $c->get('out')->set($member, $o);
            return;
        }
        $c->set('out', $o instanceof Obj ? $o->without('reason') : $o);
    }

    private static function durable(Obj $sc): Obj
    {
        $kv = new AllowlistTestKv();
        foreach ($sc->has('initial') ? $sc->get('initial')->keys() : [] as $k) {
            $kv->m[$k] = Json::canonicalizeLenient($sc->get('initial')->get($k));
        }
        $opts = self::num($sc->get('opts'));
        $results = [];
        foreach ($sc->get('steps') as $s) {
            $results[] = self::code(AttestAllowlist::verifyDurable(self::num($s), $opts, $kv));
        }
        $state = new Obj();
        foreach ($kv->m as $k => $t) {
            $state->set((string)$k, Json::parseLax($t));
        }
        return Obj::of(['results' => $results, 'kv' => $state]);
    }

    private static function keys(Obj $spec): array
    {
        $alg = $spec->get('alg');
        $suite = Pq::resolveSigAlg($alg);
        $ed = $spec->has('edSecret') ? new KeyPair(self::secret($spec->get('edSecret'))) : null;
        $pq = $spec->has('seed') && $suite !== null && $suite['family'] !== null ? new PqKeyPair($suite['family'], self::secret($spec->get('seed'))) : null;
        return [$ed, $pq];
    }

    private static function anchorOps(Obj $sc, array $want): array
    {
        $log = AttestAllowlistAnchor::createLog((string)$sc->get('instanceId'), (string)$sc->get('principal'));
        $secret = self::secret($sc->get('secret'));
        $out = [];
        foreach ($sc->get('ops') as $i => $op) {
            try {
                $out[] = match ($op->keys()[0]) {
                    'anchor' => AttestAllowlistAnchor::anchorHead($log, $op->get('anchor'), $secret, $op->get('nowMs')),
                    'refresh' => AttestAllowlistAnchor::refreshHead($log, $secret, $op->get('refresh')),
                    'evidenceFor' => AttestAllowlistAnchor::evidenceFor($log, $op->get('evidenceFor'), $op->has('cached') ? $op->get('cached') : null),
                    'latest' => $log->latest(),
                    default => $log->entries(),
                };
            } catch (\Throwable $e) {
                $w = $want[$i] ?? null;
                $out[] = Obj::of(['$throws' => $w instanceof Obj && $w->has('$throws') ? $w->get('$throws') : $e->getMessage()]);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['ALLOWLIST_KINDS' => AttestAllowlist::KINDS, 'DOMAIN' => AttestAllowlist::DOMAIN],
            'verifyAllowlistManifest' => static function (array $a, Obj $c) {
                self::dropReason($c);
                return self::code(AttestAllowlist::verify(self::num($a[0]), self::num($a[1])));
            },
            'verifyAllowlistDurable' => static function (array $a, Obj $c) {
                self::dropReason($c, 'results');
                return self::durable($a[0]);
            },
            'createAllowlistManifest' => static fn(array $a) => AttestAllowlist::create($a[0]),
            'signAllowlistManifest' => static function (array $a) {
                [$ed, $pq] = self::keys($a[1]->get('keySpec'));
                return AttestAllowlist::sign($a[0], (string)$a[1]->get('issuer'), $a[1]->get('alg'), $ed, $pq);
            },
            'revokeAllowlistEntry' => static fn(array $a) => AttestAllowlist::revokeEntry($a[0], $a[1], $a[2]),
            'driverVersionSlotHex' => static fn(array $a) => AttestAllowlist::driverVersionSlotHex($a[0]),
            'projectAllowlist' => static fn(array $a) => AttestAllowlist::project($a[0], $a[1]),
            'policyFields' => static fn(array $a) => match ($a[0]) {
                'azureMaaPolicyFields' => AttestAllowlist::azureMaaPolicyFields($a[1]),
                'intelDcapPolicyFields' => AttestAllowlist::intelDcapPolicyFields($a[1]),
                'sevSnpPolicyFields' => AttestAllowlist::sevSnpPolicyFields($a[1]),
                'gcpCsPolicyFields' => AttestAllowlist::gcpCsPolicyFields($a[1]),
                'nvidiaCcPolicyFields' => AttestAllowlist::nvidiaCcPolicyFields($a[1]),
            },
            'anchorCommit' => static fn(array $a) => AttestAllowlistAnchor::commit($a[0]),
            'anchorEntryOf' => static fn(array $a) => AttestAllowlistAnchor::entryOf($a[0]),
            'anchorOps' => static fn(array $a, Obj $c) => self::anchorOps($a[0], $c->get('out')),
            'verifyAnchored' => static function (array $a, Obj $c) {
                self::dropReason($c);
                return self::code(AttestAllowlistAnchor::verify($a[0]->get('verified'), $a[0]->get('evidence'), $a[0]->get('opts')));
            },
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
