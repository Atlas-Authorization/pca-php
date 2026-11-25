<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** No FN-DSA backend is installed, or the library behind {@see FndsaNative} cannot be loaded. */
final class FnDsaBackendMissing extends \RuntimeException
{
}
