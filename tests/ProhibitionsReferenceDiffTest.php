<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The prohibition plane against the TS reference (packages/pca/src/prohibitions.ts), case by case: constitution and state validation, the
 * monitor, advance, evidence, signed evidence and check-and-advance (test-data/k05-prohibitions.json.gz). Secrets travel as the base64url
 * of the 32-byte Ed25519 seed. A JSON member that is present with value null is a present member (the reference tells it from absent).
 */
final class ProhibitionsReferenceDiffTest extends TestCase
{
    private const FILE = 'k05-prohibitions.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    /** A JSON object as the assoc array the expectation / option parameters take; a non-object stays out of the array form. */
    private static function assoc(mixed $v): mixed
    {
        if (!($v instanceof Obj)) {
            return is_array($v) ? null : $v;
        }
        $o = [];
        foreach ($v->keys() as $k) {
            $o[$k] = $v->get($k);
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'validateInvariant' => fn(array $a) => Prohibitions::validateInvariant($a[0]),
            'validateConstitution' => fn(array $a) => Prohibitions::validateConstitution($a[0]),
            'stateProblem' => fn(array $a) => Prohibitions::stateProblem($a[0]),
            'canonicalState' => fn(array $a) => Prohibitions::canonicalState($a[0]),
            'stateDigest' => fn(array $a) => Prohibitions::stateDigest($a[0]),
            'tickState' => fn(array $a) => Prohibitions::tickState($a[0], $a[1]),
            'emptyState' => function (array $a) {
                $n = Prohibitions::fin($a[0]);
                return $n === null ? [K05::SKIP, 'the typed API takes a number'] : Prohibitions::emptyState($n);
            },
            'checkProhibitions' => function (array $a) {
                $r = Prohibitions::check($a[0], $a[1], $a[2]);
                return ['ok' => $r['ok'], 'violated' => $r['violated'], 'reasons' => $r['reasons'], 'evaluated' => $r['evaluated']];
            },
            'advanceStateStrict' => fn(array $a) => count($a) > 3
                ? Prohibitions::advanceStrict($a[0], $a[1], $a[2], $a[3])
                : Prohibitions::advanceStrict($a[0], $a[1], $a[2]),
            'proveSafety' => fn(array $a) => Prohibitions::proveSafety($a[0], $a[1], $a[2]),
            'verifySafetyEvidence' => fn(array $a) => Prohibitions::verifySafetyEvidence($a[0], $a[1], $a[2], $a[3]),
            'safetyBindingId' => fn(array $a) => Prohibitions::safetyBindingId($a[0], $a[1]),
            'signSafetyEvidence' => function (array $a) {
                $key = KeyPair::fromSeedB64u($a[1]);
                return $a[2] === $key->public ? Prohibitions::signSafetyEvidence($a[0], $key) : [K05::SKIP, 'the signer is the key\'s own public key'];
            },
            'verifySignedSafetyEvidence' => fn(array $a) => Prohibitions::verifySignedSafetyEvidence($a[0], self::assoc($a[1])),
            'checkAndAdvance' => function (array $a) {
                $r = Prohibitions::checkAndAdvance($a[0], $a[1], $a[2], $a[3], count($a) > 4 ? self::assoc($a[4]) ?? [] : []);
                $out = ['allow' => $r['allow'], 'decidedBy' => $r['decidedBy'], 'evidence' => $r['evidence'], 'prohibition' => [
                    'ok' => $r['prohibition']['ok'], 'violated' => $r['prohibition']['violated'], 'reasons' => $r['prohibition']['reasons'],
                    'evaluated' => $r['prohibition']['evaluated']], 'next' => $r['next']];
                if (isset($r['reason'])) {
                    $out['reason'] = $r['reason'];
                }
                return $out;
            },
            'constitutionId' => fn(array $a) => Prohibitions::constitutionId($a[0]),
            'verifyConstitution' => fn(array $a) => count($a) > 1 ? Prohibitions::verifyConstitution($a[0], $a[1]) : Prohibitions::verifyConstitution($a[0]),
            'whenAffirmative' => fn(array $a) => Prohibitions::whenAffirmative($a[0], $a[1]),
        ]);
    }
}
