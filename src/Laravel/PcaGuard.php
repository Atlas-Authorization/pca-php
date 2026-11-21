<?php
declare(strict_types=1);

namespace Atlas\Pca\Laravel;

use Atlas\Pca\HttpFoundationGuard;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

require_once __DIR__ . '/../HttpFoundationGuard.php';

/**
 * Laravel route middleware (alias `pca`, registered by {@see PcaServiceProvider}): verifies the request's PCActn through the shared
 * PSR-15 pipeline; a refusal is returned as is, a pass stores the verdict as the request attribute `pca` and continues.
 */
final class PcaGuard
{
    public function __construct(private readonly HttpFoundationGuard $guard)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        [$denial, $verdict] = $this->guard->check($request);
        if ($denial !== null) {
            return $denial;
        }
        $request->attributes->set('pca', $verdict);
        return $next($request);
    }
}
