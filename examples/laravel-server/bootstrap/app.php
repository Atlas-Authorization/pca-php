<?php

use App\Guard;
use App\PcaGuard;
use Atlas\Pca\Protect;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

$app = Application::configure(basePath: dirname(__DIR__))
    ->withRouting(api: __DIR__ . '/../routes/api.php', apiPrefix: '')
    ->withMiddleware(fn (Middleware $middleware) => $middleware->alias(['pca' => PcaGuard::class]))
    ->create();

// One guard per process (the replay store and the revocation list live in it).
$app->singleton(Protect::class, fn () => Guard::protect());

return $app;
