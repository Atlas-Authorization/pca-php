<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Notary;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The notary attestation module against the TS reference: test-data/ref-notary.json.gz (body commitment, selective disclosure, PCActn binding, the attested_fact caveat, key rings). */
final class RefNotaryDifferentialTest extends TestCase
{
    private const FILE = 'ref-notary.json.gz';
    private const ERR = 'attested_fact evaluation error (fail closed)';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$bytes": b64url} -> Bytes, recursively. */
    private static function dec(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return new Bytes((string)Pca::unb64u($v->get('$bytes')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::dec($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::dec(...), $v) : $v;
    }

    private static function notarize(array $a): Obj
    {
        $n = 0;
        $rb = static function (int $k) use (&$n): string {
            $d = substr(hash('sha256', 'notary-oracle-salt/' . $n, true), 0, $k);
            $n++;
            return $d;
        };
        $o = $a[1];
        return Notary::notarizeResponse($a[0]->get('request'), $a[0]->get('response'), self::dec($o->get('notaryKey')), $o->get('observedAt'), $o->get('textChunkSize'), $rb);
    }

    private static function evaluate(array $a, Obj $case): array
    {
        $r = Notary::evaluateAttestedFactCaveat($a[0], $a[1], array_key_exists(2, $a) ? [$a[2]] : [], null);
        $want = $case->get('out');
        if ($want instanceof Obj && is_string($want->get('reason')) && str_starts_with($want->get('reason'), self::ERR)) {
            $case->set('out', Obj::of(['ok' => false, 'reason' => self::ERR]));
            $r['reason'] = str_starts_with((string)$r['reason'], self::ERR) ? self::ERR : $r['reason']; // the message after the prefix is the language's own
        }
        return $r;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => ['BODY_COMMIT_ALG' => Notary::BODY_COMMIT_ALG, 'ATTESTED_FACT_CAVEAT' => Notary::ATTESTED_FACT_CAVEAT],
            'notaryMessage' => fn(array $a) => Base::outBytes(Notary::notaryMessage($a[0])),
            'notarizeResponse' => fn(array $a) => self::notarize($a),
            'discloseField' => fn(array $a) => Notary::discloseField($a[0], $a[1], $a[2]),
            'verifyNotaryAttestation' => fn(array $a) => Notary::verifyNotaryAttestation($a[0], self::dec($a[1])),
            'verifyDisclosedField' => fn(array $a) => Notary::verifyDisclosedField($a[0], $a[1], self::dec($a[2])),
            'factRef' => fn(array $a) => Notary::factRef($a[0]),
            'bindFactToPcActn' => fn(array $a) => Notary::bindFactToPcActn($a[0], $a[1]),
            'factMatchesPcActn' => fn(array $a) => Notary::factMatchesPcActn($a[0], $a[1]),
            'requireAttestedFact' => function (array $a) {
                $o = $a[0];
                $opt = [];
                foreach (['url', 'bindToPcActn'] as $m) {
                    if ($o->has($m)) {
                        $opt[$m] = $o->get($m);
                    }
                }
                return Notary::requireAttestedFact(self::dec($o->get('notary')), $o->get('path'), $o->get('equals'), $opt);
            },
            'isAttestedFactCaveat' => fn(array $a) => Notary::isAttestedFactCaveat($a[0]),
            'notaryKeyUsable' => fn(array $a) => Notary::notaryKeyUsable($a[0], $a[1], $a[2]),
            'evaluateAttestedFactCaveat' => fn(array $a, Obj $c) => self::evaluate($a, $c),
        ]);
    }
}
