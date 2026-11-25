<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A protocol abort of the networked MPC runner; `blamed` is null when the evidence names no culprit (then `reason` explains why). */
final class MpcNetAbort extends \RuntimeException
{
    public readonly ?string $reason;

    /** @param mixed $evidence any JSON-model value */
    public function __construct(
        public readonly string $kind,
        public readonly ?int $blamed,
        public readonly int $reporter,
        string $detail,
        public readonly ?string $claimedKind = null,
        public readonly ?int $claimedBlame = null,
        ?string $reason = null,
        public readonly mixed $evidence = null,
        public readonly ?int $deadlineMs = null,
    ) {
        parent::__construct('[' . $kind . '] blamed=' . ($blamed === null ? 'none' : (string) $blamed) . ' reporter=' . $reporter . ': ' . $detail);
        $this->reason = $blamed === null ? ($reason !== null && $reason !== '' ? $reason : 'unattributable: the evidence available to this party does not identify a culprit') : null;
    }
}
