<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Actions.php';
require_once __DIR__ . '/../src/Approval.php';
require_once __DIR__ . '/../src/PqThreshold.php';

use Atlas\Pca\Actions;
use Atlas\Pca\Approval;
use Atlas\Pca\PqThreshold;
use PHPUnit\Framework\TestCase;

/** The public constants the reference exports (def.ts, approval-render.ts, pca-pq-threshold) and how the code enforces them. */
final class PublicConstantsTest extends TestCase
{
    public function testActionDefConstantsAgreeWithTheEnforcedSets(): void
    {
        $r = new \ReflectionClass(Actions::class);
        self::assertSame($r->getConstant('PARAM_TYPES'), Actions::PARAM_TYPES_V1);
        self::assertSame(array_keys($r->getConstant('SENS_RANK')), Actions::SENSITIVITY_LEVELS);
        self::assertSame($r->getConstant('SENS_RANK'), Actions::SENSITIVITY_RANK);
        self::assertSame(1, Actions::ACTION_DEF_VERSION);
        self::assertSame('pca-action-pack', Actions::ACTION_PACK_KIND);
        self::assertSame(1, preg_match(Actions::TAINT_CONTEXT_RE, 'session_taint_max:pii'));
        self::assertSame(0, preg_match(Actions::TAINT_CONTEXT_RE, "session_taint_max:pii\n"));
        self::assertSame(0, preg_match(Actions::TAINT_CONTEXT_RE, 'session_taint_max:' . str_repeat('a', 17)));
        self::assertSame([128, 120, 1024, 64, 16, 32, 16, 16, 3, 8, 512, 4096], [Actions::MAX_VERB_BYTES, Actions::MAX_TITLE_BYTES, Actions::MAX_DESCRIPTION_BYTES,
            Actions::MAX_DEF_PARAMS, Actions::MAX_DEF_ALIASES, Actions::MAX_DEF_TRAITS, Actions::MAX_DEF_CONTEXT, Actions::MAX_DEF_SIDE_EFFECTS,
            Actions::MAX_PARAM_PATH_DEPTH, Actions::MAX_TRAIT_IMPLIES_DEPTH, Actions::MAX_REGISTRY_TRAITS, Actions::MAX_PACK_DEFS]);
    }

    public function testOtherConstants(): void
    {
        self::assertSame(2 ** -44, \Atlas\Pca\IntentClopper::CP_TOLERANCE);
        self::assertSame('pca-approval-render', Approval::APPROVAL_RENDER_KIND);
        self::assertSame(PqThreshold::MAX_PQ_QUORUM_ENTRIES, PqThreshold::MAX_PQ_SIGNER_ENTRIES);
    }
}
