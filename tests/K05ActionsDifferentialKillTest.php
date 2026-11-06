<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The action kit against the TS reference: test-data/k05-actions.json.gz (k05-oracles/actions-oracle.mts): validateDef and its
 * sub-checks, id patterns, the strict JSON profile, profiles, trait registries, closure / floor / floorDecision, normalize and the
 * digests, effective, the reviewer pins and the signed confirmation, the schema floor checks, the pack Merkle tree.
 */
final class K05ActionsDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-actions.json.gz';
    private const TYPED = 'typed PHP signature: a non-list argument cannot be passed';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Actions::class, $m))->invoke(null, ...$a);
    }

    private static function regOf(mixed $custom): array
    {
        return $custom === null ? Actions::coreRegistry() : Actions::extendRegistry(Actions::coreRegistry(), $custom);
    }

    private static function listArg(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        K05::run($file, $fn, $k, [
            'validateDef' => fn(array $a) => Actions::validateDef($a[0]),
            'isRole' => fn(array $a) => self::priv('isRole', $a[0]),
            'isFormat' => fn(array $a) => self::priv('isFormat', $a[0]),
            'isContextKey' => fn(array $a) => self::priv('isContextKey', $a[0]),
            'paramNameError' => fn(array $a) => self::priv('paramNameError', $a[0]),
            'jsonProfileError' => fn(array $a) => Actions::jsonProfileError($a[0]),
            'idPatternError' => fn(array $a) => Actions::idPatternError($a[0]),
            'profileError' => fn(array $a) => Actions::profileError($a[0]),
            'registryError' => fn(array $a) => self::listArg($a[0]) ? Actions::registryError($a[0], $a[1] === true) : [K05::SKIP, self::TYPED],
            'closure' => fn(array $a) => Actions::closure(self::regOf($a[0]), $a[1]),
            'floorOf' => fn(array $a) => Actions::floorOf(self::regOf($a[0]), $a[1]),
            'topTraits' => fn(array $a) => Actions::topTraits(self::regOf($a[0])),
            'traitsDigest' => fn(array $a) => Actions::traitsDigest(self::regOf($a[0])),
            'tablesDigest' => fn() => Actions::tablesDigest(),
            'floorDecision' => fn(array $a) => Actions::floorDecision($a[0], $a[1], Actions::profFromObj($a[2])),
            'worstReversibility' => fn(array $a) => Actions::worstReversibility($a[0], $a[1]),
            'sensitivityFloor' => fn(array $a) => self::priv('effectiveParamSensitivity', $a[0]),
            'impliedFromFacts' => fn(array $a) => Actions::impliedFromFacts($a[0]->get('effects'), $a[0]->get('params'),
                $a[0]->get('scope'), $a[0]->get('worstRev')),
            'normalize' => fn(array $a) => Actions::normalize($a[0]),
            'defDigest' => fn(array $a) => Actions::defDigest($a[0]),
            'declProfile' => fn(array $a) => Actions::declProfile($a[0]),
            'hintTraits' => fn(array $a) => Actions::hintTraits($a[0]),
            'effective' => fn(array $a) => Actions::effective($a[0], $core, $a[1]),
            'reviewerPinsError' => fn(array $a) => Actions::reviewerPinsError($a[0]),
            'reviewMessage' => fn(array $a) => K05::outBytes(Actions::reviewMessage($a[0])),
            'isConfirmed' => fn(array $a) => Actions::isConfirmed($a[0], $core, $a[1]),
            'factsDigest' => fn(array $a) => Actions::factsDigest($a[0]),
            'schemaVerbFloorError' => fn(array $a) => Actions::schemaVerbFloorError($a[0], $core, $a[1]),
            'schemaFloorError' => fn(array $a) => Actions::schemaFloorError($a[0], $a[1]),
            'packRoot' => fn(array $a) => Actions::packRoot($a[0]),
            'packProof' => fn(array $a) => Actions::packProof($a[0], $a[1]),
        ]);
    }

    // ---- the reference fixes of d36d91ac7, one each ----

    public function testFloorDecisionDeniesANonIntegerTier(): void
    {
        $call = Obj::of(['context' => []]);
        $tiers = [[new Num('3'), new Num('3')], [null, new Num('2')], ['3', new Num('2')], [new Num('2.5'), new Num('2')],
            [new Num('3'), new Num('-1')], [new Num('-0'), new Num('0')], [new Num('3'), true]];
        foreach ($tiers as $i => [$max, $pre]) {
            $g = Obj::of(['caveats' => [], 'preauth_esc' => $pre]);
            if ($max !== null) {
                $g->set('max_esc', $max);   // null = missing
            }
            self::assertSame($i === 0 ? 'allow' : 'deny', Actions::floorDecision($g, $call, Actions::profile()), "tiers #$i");
        }
    }

    public function testAReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed(): void
    {
        $a = null;
        for ($k = 0; $a === null && ($cs = K05::cases(self::FILE, 'isConfirmed', $k)) !== []; $k++) {
            foreach ($cs as $c) {
                if ($c->get('name') === 'isConfirmed/read good') {
                    $a = $c->get('args');
                }
            }
        }
        $core = Actions::coreRegistry();
        self::assertTrue(Actions::isConfirmed($a[0], $core, $a[1]), 'control');
        foreach (['missing', null, ''] as $f) {
            $d = Json::parseLax(Json::canonicalizeLenient($a[0]));
            $att = $d->get('review')->get('attestation');
            $f === 'missing' ? $d->get('review')->set('attestation', $att->without('final_traits')) : $att->set('final_traits', $f);
            self::assertFalse(Actions::isConfirmed($d, $core, $a[1]), 'final_traits ' . var_export($f, true));
        }
    }

    public function testANullMaxItemsImpliesBulk(): void
    {
        foreach (['missing', null, new Num('10')] as $mi) {
            $p = Obj::of(['type' => 'array']);
            if ($mi !== 'missing') {
                $p->set('max_items', $mi);
            }
            self::assertSame(!($mi instanceof Num), in_array('pca.bulk', Actions::impliedFromFacts(['create'], [$p], null, 'reversible'), true));
        }
    }
}
