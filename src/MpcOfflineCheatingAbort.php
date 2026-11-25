<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named). */
final class MpcOfflineCheatingAbort extends MpcMacCheckAbort
{
    /** @param list<int> $blamed */
    public function __construct(string $message, public readonly array $blamed)
    {
        parent::__construct($blamed === [] ? $message : $message . '; offline OT transcript names party ' . implode(', ', $blamed));
    }
}
