<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalCodec.php';
require_once __DIR__ . '/../src/GoalDigests.php';
require_once __DIR__ . '/../src/GoalNormalize.php';
require_once __DIR__ . '/../src/GoalFmt.php';
require_once __DIR__ . '/../src/GoalCard.php';
require_once __DIR__ . '/../src/GoalRefsem.php';
require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/GoalBinding.php';
require_once __DIR__ . '/../src/GoalSign.php';

use Atlas\Pca\GoalBinding as B;
use Atlas\Pca\GoalCard as CD;
use Atlas\Pca\GoalCodec as C;
use Atlas\Pca\GoalCompiler as CP;
use Atlas\Pca\GoalDigests as D;
use Atlas\Pca\GoalFmt as F;
use Atlas\Pca\GoalNormalize as N;
use Atlas\Pca\GoalRefsem as R;
use Atlas\Pca\GoalSign as S;
use Atlas\Pca\KeyPair;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The goal package against the TS reference: test-data/ref-goal.json.gz (token-tape codec, digests, canonical order, formatting,
 * policy card, reference semantics, policy digest, decision-to-effect binding and the signing envelope). Signer seeds in the
 * corpus are base64url strings; Ed25519 is deterministic, so signed artifacts compare byte for byte.
 */
final class RefGoalDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        // the corpus carries a seed label, not key bytes: {"$seed": label} is sha256("atlas-pca-conformance/" . label)
        $kp = static fn(mixed $seed): KeyPair => $seed instanceof \Atlas\Pca\Obj && $seed->keys() === ['$seed']
            ? new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $seed->get('$seed'), true))
            : KeyPair::fromSeedB64u((string)$seed);
        Base::run($file, $fn, $k, [
            'encodeGoal' => fn(array $a) => C::encodeGoal(...$a),
            'decodeGoal' => fn(array $a) => C::decodeGoal(...$a),
            'encodeOntology' => fn(array $a) => C::encodeOntology(...$a),
            'encodeAct' => fn(array $a) => C::encodeAct(...$a),
            'encodeHist' => fn(array $a) => C::encodeHist(...$a),
            'decodePolicy' => fn(array $a) => C::decodePolicy(...$a),
            'goalDigest' => fn(array $a) => D::goalDigest(...$a),
            'nlDigest' => fn(array $a) => D::nlDigest(...$a),
            'modelSetDigest' => fn(array $a) => D::modelSetDigest(...$a),
            'approvalDigest' => fn(array $a) => D::approvalDigest(...$a),
            'canonicalizeGoal' => fn(array $a) => N::canonicalizeGoal(...$a),
            'stable' => fn(array $a) => N::stable(...$a),
            'fmtMoney' => fn(array $a) => F::fmtMoney(...$a),
            'fmtQuantity' => fn(array $a) => F::fmtQuantity(...$a),
            'fmtValue' => fn(array $a) => F::fmtValue(...$a),
            'fmtAct' => fn(array $a) => F::fmtAct(...$a),
            'renderCard' => fn(array $a) => CD::renderCard(...$a),
            'renderCond' => fn(array $a) => CD::cond(...$a),
            'refExplain' => fn(array $a) => R::refExplain(...$a),
            'refDecide' => fn(array $a) => R::refDecide(...$a),
            'canonicalPolicy' => fn(array $a) => CP::canonicalPolicy(...$a),
            'policyDigest' => fn(array $a) => CP::policyDigest(...$a),
            'actionDigest' => fn(array $a) => B::actionDigest(...$a),
            'bindDecision' => fn(array $a) => B::bindDecision(...$a),
            'guardExecute' => fn(array $a) => B::guardExecute(...$a),
            'claimGate' => fn(array $a) => B::claimGate($a[0], $a[1], 0, $a[2] ?? null),
            'goalCommit' => fn(array $a) => B::goalCommit(...$a),
            'openCommit' => fn(array $a) => B::openCommit(...$a),
            'signPayloadSeed' => fn(array $a) => S::signPayload($a[0], $a[1], $kp($a[2])),
            'signGoalArtifactSeed' => fn(array $a) => S::signGoalArtifact($a[0], $a[1], $kp($a[2])),
            'signerId' => fn(array $a) => S::signerId($kp($a[0])),
            'goalDomain' => fn(array $a) => S::goalDomain(...$a),
            'verifyPayload' => fn(array $a) => S::verifyPayload(...$a),
            'verifyGoalArtifact' => fn(array $a) => S::verifyGoalArtifact(...$a),
        ]);
    }
}
