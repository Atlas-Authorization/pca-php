<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Oprf;
use Atlas\Pca\OprfAbsent;
use Atlas\Pca\OprfRateWindowCounter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9497 ristretto255-SHA512 OPRF / VOPRF / POPRF and the PCA private-revocation / rate-limit layer against the TS reference:
 * test-data/ref-oprf.json.gz. The keys are fixed throwaway test constants. A byte argument is a {"$bytes"} member: a plain corpus string
 * where bytes are expected is passed as a non-string, so the refusal the reference makes is replayed too.
 */
final class RefOprfDifferentialTest extends TestCase
{
    private const FILE = 'ref-oprf.json.gz';
    private const CAMEL = ['secret_key' => 'secretKey', 'public_key' => 'publicKey', 'blind' => 'blind', 'blinded_element' => 'blindedElement',
        'evaluated_element' => 'evaluatedElement', 'tweaked_key' => 'tweakedKey', 'proof' => 'proof'];

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    /** A byte argument: {"$bytes"} to raw bytes, a plain string to something that is not bytes, anything else as it is. */
    private static function by(mixed $v): mixed
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            return Base::bytes($v);
        }
        return is_string($v) ? ['text' => $v] : $v;
    }

    /** Optional trailing byte arguments from position $from: absent ones stay absent, a present null stays null (refused). */
    private static function opt(array $a, int $i): mixed
    {
        return array_key_exists($i, $a) ? self::by($a[$i]) : OprfAbsent::Absent;
    }

    private static function wire(array $d): Obj
    {
        $o = new Obj();
        foreach ($d as $k => $v) {
            $o->set(self::CAMEL[$k], Base::outBytes($v));
        }
        return $o;
    }

    private static function sk(mixed $o): mixed
    {
        return self::by($o->get('sk'));
    }

    private static function revocation(array $a, Obj $c): mixed
    {
        $x = Oprf::buildRevocationSet(self::by($a[0]), $a[1], $a[2]);
        $name = (string)$c->get('name');
        $outs = array_keys($x['outputs']);
        sort($outs, SORT_STRING);
        $o = Obj::of(['outputs' => $outs, 'mode' => $x['mode']]);
        if (isset($x['public_key']) && !str_ends_with($name, '-dups')) {
            $o->set('publicKey', Base::outBytes($x['public_key']));
        }
        return $o;
    }

    private static function revoked(array $a): bool
    {
        $op = $a[1];
        $sk = self::sk($op);
        $mode = $op->get('mode');
        $st = Oprf::buildRevocationSet($sk, $op->get('revoked'), $mode);
        $lie = $op->get('lie');
        $real = Oprf::makeRevocationEvaluator($lie === 'wrong-key' ? Oprf::serializeScalar(12345) : $sk, $mode);
        $ev = $lie === 'no-proof' ? static fn(string $b): array => ['evaluated_element' => $real($b)['evaluated_element']] : $real;
        return Oprf::isRevokedPrivate($a[0], $ev, $st);
    }

    private static function privateRate(array $a): mixed
    {
        $op = $a[2];
        $sk = self::sk($op);
        $pk = $op->has('pk') ? self::by($op->get('pk')) : Oprf::publicKeyFor($sk);
        return Base::outBytes(Oprf::privateRateToken($a[0], $a[1], Oprf::makeRateEvaluator($sk), $pk));
    }

    private static function counter(array $a): array
    {
        $c = new OprfRateWindowCounter($a[0]);
        $out = [];
        foreach ($a[1] as $s) {
            if ($s[0] === 'hit') {
                $r = $c->hit(Base::bytes($s[1]));
                $out[] = Obj::of(['count' => $r['count'], 'allowed' => $r['allowed']]);
            } elseif ($s[0] === 'count') {
                $out[] = $c->count(Base::bytes($s[1]));
            } else {
                $c->reset();
                $out[] = null;
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        Base::run($file, $fn, $k, [
            'deriveKeyPair' => fn(array $a) => self::wire(Oprf::deriveKeyPair(self::by($a[0]), self::by($a[1]), $a[2])),
            'publicKeyFor' => fn(array $a) => Base::outBytes(Oprf::publicKeyFor(self::by($a[0]))),
            'deserializeScalar' => fn(array $a) => gmp_strval(Oprf::deserializeScalar(self::by($a[0]))),
            'serializeScalar' => fn(array $a) => Base::outBytes(Oprf::serializeScalar($a[0])),
            'hashToGroup' => fn(array $a) => Base::outBytes(Oprf::hashToGroup(self::by($a[0]), $a[1])),
            'deserializeElement' => fn(array $a) => Base::outBytes(Oprf::deserializeElement(self::by($a[0]))),
            'blind' => fn(array $a) => self::wire(Oprf::blind(self::by($a[0]), $a[1], self::opt($a, 2))),
            'blindEvaluate' => fn(array $a) => self::wire(Oprf::blindEvaluate(self::by($a[0]), self::by($a[1]), $a[2], self::opt($a, 3), self::opt($a, 4))),
            'evaluate' => fn(array $a) => Base::outBytes(Oprf::evaluate(self::by($a[0]), self::by($a[1]), $a[2])),
            'finalize' => function (array $a): Obj {
                $o = ($a[4] ?? null) instanceof Obj ? $a[4] : new Obj();
                return Base::outBytes(Oprf::finalize(self::by($a[0]), self::by($a[1]), self::by($a[2]), $a[3], self::by($o->get('proof')),
                    self::by($o->get('publicKey')), self::by($o->get('blindedElement'))));
            },
            'blindPoprf' => fn(array $a) => self::wire(Oprf::blindPoprf(self::by($a[0]), self::by($a[1]), self::by($a[2]), self::opt($a, 3))),
            'blindEvaluatePoprf' => function (array $a, Obj $c): Obj {
                $r = self::wire(Oprf::blindEvaluatePoprf(self::by($a[0]), self::by($a[1]), self::by($a[2]), self::opt($a, 3)));
                if (str_ends_with((string)$c->get('name'), 'bep-sk0')) { // an unpinned proof nonce: only the evaluation is comparable
                    $c->set('out', Obj::of(['evaluatedElement' => $c->get('out')->get('evaluatedElement')]));
                    return Obj::of(['evaluatedElement' => $r->get('evaluatedElement')]);
                }
                return $r;
            },
            'finalizePoprf' => fn(array $a) => Base::outBytes(Oprf::finalizePoprf(self::by($a[0]), self::by($a[1]), self::by($a[2]), self::by($a[3]),
                self::by($a[4]->get('proof')), self::by($a[4]->get('blindedElement')), self::by($a[4]->get('tweakedKey')))),
            'evaluatePoprf' => fn(array $a) => Base::outBytes(Oprf::evaluatePoprf(self::by($a[0]), self::by($a[1]), self::by($a[2]))),
            'toHex' => fn(array $a) => Oprf::toHex(self::by($a[0])),
            'bytesEqual' => fn(array $a) => Oprf::bytesEqual(self::by($a[0]), self::by($a[1])),
            'buildRevocationSet' => fn(array $a, Obj $c) => self::revocation($a, $c),
            'isRevokedPrivate' => fn(array $a) => self::revoked($a),
            'rateToken' => fn(array $a) => Base::outBytes(Oprf::rateToken(self::by($a[0]), $a[1], $a[2])),
            'rateTokenHex' => fn(array $a) => Oprf::rateTokenHex(self::by($a[0]), $a[1], $a[2]),
            'privateRateToken' => fn(array $a) => self::privateRate($a),
            'rateCounter' => fn(array $a) => self::counter($a),
        ]);
    }
}
