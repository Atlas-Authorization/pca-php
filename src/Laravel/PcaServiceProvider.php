<?php
declare(strict_types=1);

namespace Atlas\Pca\Laravel;

use Atlas\Pca\HttpFoundationGuard;
use Atlas\Pca\PcaMiddleware;
use Illuminate\Support\ServiceProvider;

require_once __DIR__ . '/PcaGuard.php';

/**
 * Registers the PCA guard. config/pca.php: `middleware` => a callable returning the configured {@see PcaMiddleware} (audience,
 * grant resolver, AuthorizeOptions, ...); optional `attribute` (default 'pca'). Routes opt in with `->middleware('pca')`.
 * Without `middleware` configured the guard cannot be built and the route fails (never a silent pass).
 */
final class PcaServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(HttpFoundationGuard::class, function ($app): HttpFoundationGuard {
            $make = $app['config']->get('pca.middleware');
            $mw = is_callable($make) ? $make($app) : null;
            if (!$mw instanceof PcaMiddleware) {
                throw new \RuntimeException('config pca.middleware must be a callable returning an Atlas\Pca\PcaMiddleware');
            }
            return new HttpFoundationGuard($mw, (string)$app['config']->get('pca.attribute', 'pca'));
        });
    }

    public function boot(): void
    {
        $this->app['router']->aliasMiddleware('pca', PcaGuard::class);
    }
}
