<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Raised when the MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output. */
class MpcMacCheckAbort extends \RuntimeException
{
}
