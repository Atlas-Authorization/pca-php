<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AccumulatorError;
use Atlas\Pca\MemorySpentLeafStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Ratchet;
use Atlas\Pca\RatchetAccumulator;
use Atlas\Pca\RatchetBigint;
use Atlas\Pca\RatchetError;
use Atlas\Pca\RiskQuantizer;
use Atlas\Pca\SpentLeafStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The capability ratchet, risk accumulator, adapters and verifier bindings against the TS reference: test-data/ref-ratchet.json.gz.
 * Bigints cross as {"$bigint": decimal}, bytes as {"$bytes": b64url}. The provers draw fresh randomness, so a proof is not
 * comparable byte for byte: the corpus holds proofs the reference produced (and tampered copies) and the native must reach the same
 * verdict; the provers themselves are replayed for their refusals.
 */
final class RefRatchetDifferentialTest extends TestCase
{
    private const FILE = 'ref-ratchet.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {$bigint} -> RatchetBigint, recursively through lists (an Obj that is not a bigint is left as it is). */
    private static function rev(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            return $v->keys() === ['$bigint'] ? new RatchetBigint($v->get('$bigint')) : $v;
        }
        return is_array($v) && array_is_list($v) ? array_map(self::rev(...), $v) : $v;
    }

    private static function big(RatchetBigint|int $x): Obj
    {
        return Obj::of(['$bigint' => (string) $x]);
    }

    private static function bytes(mixed $v): ?string
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'] ? Base::bytes($v) : null;
    }

    /** A plain PHP value (assoc arrays, RatchetBigint-free) as the parsed-JSON model: Obj for objects. */
    private static function toObj(mixed $v): mixed
    {
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::toObj(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string) $k, self::toObj($x));
            }
            return $o;
        }
        return $v;
    }

    /** The reference's clonePath: `$node` with `$value` set (or deleted for "__DEL__") at `$path`; an empty path sets the member "undefined". */
    private static function setIn(mixed $node, array $path, mixed $value): mixed
    {
        $first = array_shift($path) ?? 'undefined';
        $key = $first instanceof Num ? $first->lexeme : (string) $first;
        if ($node instanceof Obj) {
            if ($path === []) {
                if ($value === '__DEL__') {
                    return $node->without($key);
                }
                $node->set($key, $value);
                return $node;
            }
            $child = $node->get($key);
            if ($child !== null) {
                $node->set($key, self::setIn($child, $path, $value));
            }
            return $node;
        }
        if (is_array($node) && array_is_list($node) && ctype_digit($key)) {
            $i = (int) $key;
            if ($path === []) {
                $node[$i] = $value === '__DEL__' ? null : $value;
            } elseif (isset($node[$i])) {
                $node[$i] = self::setIn($node[$i], $path, $value);
            }
        }
        return $node;
    }

    private static function scenario(Obj $spec): array
    {
        $state = null;
        $root = null;
        $sigs = [];
        $store = $spec->get('store') === 'throws'
            ? new class implements SpentLeafStore {
                public function claim(string $nullifier, string $record): array
                {
                    throw new \RuntimeException('boom');
                }
            }
            : new MemorySpentLeafStore();
        $out = [];
        foreach ($spec->get('ops') as $s) {
            try {
                switch ($s->get('op')) {
                    case 'derive':
                        $d = Ratchet::deriveRatchetRoot(self::bytes($s->get('seed')), $s->get('depth'));
                        $state = $d['state'];
                        $root = $d['rootCommitment'];
                        $out[] = ['root' => $root, 'leafPubKeys' => $state->leafPubKeys, 'available' => Ratchet::availableLeaves($state)];
                        break;
                    case 'sign':
                        $r = Ratchet::signAtLeaf($state, $s->get('leaf'), (string) self::bytes($s->get('msg')));
                        $state = $r['newState'];
                        $sigs[] = $r['signature'];
                        $out[] = ['signature' => $r['signature']];
                        break;
                    case 'avail':
                        $out[] = Ratchet::availableLeaves($state);
                        break;
                    case 'isAvail':
                        $out[] = Ratchet::isLeafAvailable($state, $s->get('leaf'));
                        break;
                    case 'verify':
                    case 'once':
                        $ref = $s->get('sigRef');
                        $sig = self::toObj($sigs[(int) (is_object($ref) ? $ref->lexeme : $ref)] ?? null);
                        foreach ($s->get('set') ?? [] as [$path, $value]) {
                            $sig = self::setIn($sig, $path, $value);
                        }
                        $rc = $s->get('root') === 'other' ? 'other-root' : $root;
                        $msg = (string) self::bytes($s->get('msg'));
                        $out[] = $s->get('op') === 'verify'
                            ? Ratchet::verifyLeafSignature($rc, $s->get('leaf'), $msg, $sig)
                            : Ratchet::verifyLeafSignatureOnce($rc, $s->get('leaf'), $msg, $sig, $store);
                        break;
                    default:
                        throw new \LogicException('bad op');
                }
            } catch (RatchetError | AccumulatorError $e) {
                $out[] = ['$err' => $e->errorCode];
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        return $out;
    }

    private static function quantizer(array $list): array
    {
        $q = new RiskQuantizer();
        $out = [];
        foreach ($list as $r) {
            try {
                $out[] = self::big($q->next($r));
            } catch (\Throwable) {
                $out[] = ['$err' => true];
            }
        }
        $out[] = self::big($q->totalUnits());
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $authority = str_repeat("\x07", 32);
        Base::run($file, $fn, $k, [
            'leafNullifier' => fn(array $a) => Ratchet::leafNullifier($a[0], $a[1]),
            'counterToLeafIndex' => fn(array $a) => Ratchet::counterToLeafIndex($a[0], $a[1]),
            'leafIndexToCounter' => fn(array $a) => Ratchet::leafIndexToCounter($a[0]),
            'leafIndexForAction' => fn(array $a) => Ratchet::leafIndexForAction($a[0], $a[1]),
            'riskToUnits' => fn(array $a) => self::big(Ratchet::riskToUnits($a[0])),
            'budgetCeilingUnits' => fn(array $a) => self::big(Ratchet::budgetCeilingUnits($a[0])),
            'quantizer' => fn(array $a) => self::quantizer($a[0]),
            'ratchet' => fn(array $a) => self::scenario($a[0]),
            'commitRisk' => function (array $a): array {
                $r = RatchetAccumulator::commitRisk(self::rev($a[0]), self::rev($a[1]));
                return ['commitment' => $r['commitment'], 'blinding' => self::big($r['blinding'])];
            },
            'addCommitments' => fn(array $a) => RatchetAccumulator::addCommitments($a[0]),
            'openCommitment' => fn(array $a) => RatchetAccumulator::openCommitment($a[0], self::rev($a[1]), self::rev($a[2])),
            'verifyRiskRange' => fn(array $a) => RatchetAccumulator::verifyRiskRange($a[0], $a[1]),
            'verifyBudget' => fn(array $a) => RatchetAccumulator::verifyBudget($a[0], self::rev($a[1]), $a[2]),
            'verifyBoundedBudget' => fn(array $a) => RatchetAccumulator::verifyBoundedBudget($a[0], $a[1], self::rev($a[2]), $a[3]),
            'proveBudget' => fn(array $a) => RatchetAccumulator::proveBudget(self::rev($a[0]), self::rev($a[1]), self::rev($a[2])),
            'proveRiskRange' => fn(array $a) => RatchetAccumulator::proveRiskRange(self::rev($a[0]), self::rev($a[1])),
            'issueRiskCommitment' => fn(array $a) => Ratchet::issueRiskCommitment(self::rev($a[0]), $a[1], ($a[2] ?? null) === 'short' ? 'abc' : $authority),
            'verifyRiskAttestation' => fn(array $a) => Ratchet::verifyRiskAttestation($a[0], $a[1], $a[2]),
            'verifyAttestedBudget' => fn(array $a) => Ratchet::verifyAttestedBudget($a[0], $a[1], $a[2], self::rev($a[3]), $a[4]),
        ]);
    }

    /** Independent known answers (ristretto255 encodings, an accumulator transcript from other implementations). */
    private static function kat(): array
    {
        return json_decode((string) gzdecode((string) file_get_contents(__DIR__ . '/../test-data/ref-ratchet-kat.json.gz')), true, 512, JSON_THROW_ON_ERROR);
    }

    public function testBaseMultiplesGeneratorAndPedersenMatchTheIndependentEncodings(): void
    {
        $kat = self::kat()['ristretto'];
        $hex = static fn(string $c): string => bin2hex((string) \Atlas\Pca\Pca::unb64u($c, 32));
        foreach ($kat['baseMultiples'] as $i => $expected) {
            self::assertSame($expected, $hex(RatchetAccumulator::commitRisk($i, new RatchetBigint('0'))['commitment']), "G * $i");
        }
        self::assertSame($kat['H'], $hex(RatchetAccumulator::commitRisk(0, new RatchetBigint('1'))['commitment']), 'H');
        foreach ($kat['pedersen'] as $p) {
            $b = RatchetBigint::fromLe((string) hex2bin($p['b']));
            self::assertSame($p['C'], $hex(RatchetAccumulator::commitRisk(new RatchetBigint($p['v']), $b)['commitment']));
        }
    }

    public function testBudgetVerdictsMatchTheIndependentVerifier(): void
    {
        foreach (self::kat()['ristretto']['budget'] as $b) {
            self::assertSame($b['oracle'] === '1', RatchetAccumulator::verifyBudget($b['sum'], new RatchetBigint($b['bMax']), $b['proof']), $b['name']);
        }
    }

    public function testTheRecordedTranscriptVerifiesAndIsBoundToItsStatement(): void
    {
        $k = self::kat()['r2'];
        [$cs, $rps, $bMax, $bp, $total] = [$k['commitments'], $k['rangeProofs'], $k['bMax'], $k['budgetProof'], $k['sum']];
        self::assertTrue(RatchetAccumulator::verifyRiskRange($cs[0], $rps[0]) && RatchetAccumulator::verifyRiskRange($cs[1], $rps[1]));
        self::assertTrue(RatchetAccumulator::verifyBudget($total, $bMax, $bp));
        self::assertTrue(RatchetAccumulator::verifyBoundedBudget($cs, $rps, $bMax, $bp));
        self::assertFalse(RatchetAccumulator::verifyRiskRange($cs[1], $rps[0]));
        self::assertFalse(RatchetAccumulator::verifyBudget($total, $bMax + 1, $bp));
        self::assertFalse(RatchetAccumulator::verifyBoundedBudget($cs, [...$rps, $rps[0]], $bMax, $bp));
    }

    public function testTheProversRoundTrip(): void
    {
        $risks = [30, 12];
        $blindings = [new RatchetBigint('11'), new RatchetBigint('22')];
        $total = RatchetAccumulator::addCommitments(array_map(fn($r, $b) => RatchetAccumulator::commitRisk($r, $b)['commitment'], $risks, $blindings));
        self::assertTrue(RatchetAccumulator::verifyBudget($total, 42, RatchetAccumulator::proveBudget($risks, $blindings, 42)));
        self::assertFalse(RatchetAccumulator::verifyBudget($total, 41, RatchetAccumulator::proveBudget($risks, $blindings, 41)));
    }

    public function testAHonestRoundTripVerifiesAndATamperedOneDoesNot(): void
    {
        $risks = [3, 4];
        $c = array_map(fn(int $r) => Ratchet::issueRiskCommitment($r, "digest-$r", str_repeat("\x07", 32)), $risks);
        $pk = \Atlas\Pca\Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32))));
        $proof = RatchetAccumulator::proveBudget($risks, array_map(fn(array $x) => $x['blinding'], $c), 10);
        $items = array_map(fn(array $x) => ['commitment' => $x['commitment'], 'rangeProof' => $x['rangeProof'], 'attestation' => $x['attestation']], $c);
        self::assertTrue(Ratchet::verifyAttestedBudget($items, ['digest-3', 'digest-4'], $pk, 10, $proof));
        self::assertFalse(Ratchet::verifyAttestedBudget($items, ['digest-3', 'digest-4'], $pk, 6, $proof), 'over the ceiling');
        self::assertFalse(Ratchet::verifyAttestedBudget($items, ['digest-4', 'digest-3'], $pk, 10, $proof), 'digests out of order');
        $d = Ratchet::deriveRatchetRoot(str_repeat("\x05", 32), 3);
        $r = Ratchet::signAtLeaf($d['state'], 5, 'm');
        self::assertTrue(Ratchet::verifyLeafSignature($d['rootCommitment'], 5, 'm', $r['signature']));
        self::assertFalse(Ratchet::isLeafAvailable($r['newState'], 5));
        $this->expectException(RatchetError::class);
        Ratchet::signAtLeaf($r['newState'], 5, 'm');
    }
}
