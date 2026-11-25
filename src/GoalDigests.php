<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/GoalNormalize.php';

/** Content digests of the goal-to-decision flow: strict canonical JSON, safe integers only (a float, undefined or cycle throws). */
final class GoalDigests
{
    /** Digest of the whole signed Goal. */
    public static function goalDigest(mixed $goal): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-ir/v1', 'goal' => $goal]));
    }

    /** Digest of the instruction text a goal was interpreted from (what the goal's nlDigest must equal). */
    public static function nlDigest(mixed $instruction): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-nl/v1', 'text' => $instruction]));
    }

    /** Digest of the model set that produced a goal: sorted (UTF-16 order), de-duplicated ids. */
    public static function modelSetDigest(mixed $models): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-model-set/v1', 'models' => GoalNormalize::sortedUnique($models)]));
    }

    /** Digest of an approval's covered fields: any changed member changes it. */
    public static function approvalDigest(mixed $body): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-approval-body/v1', 'body' => $body]));
    }
}
