<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Raised when a received point fails on-curve / subgroup / identity validation. */
final class MpcPointError extends \RuntimeException
{
}
