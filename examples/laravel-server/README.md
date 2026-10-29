# PCA on a Laravel route

A minimal Laravel 12 API with one route, `POST /refunds`, that runs only when the request carries a Proof-Carrying Authority proof (`PCA-Action` header) for exactly that operation. The guard is built with `Protect::protect()`: the grant comes from your own store (`grants.json` here), never from the request; the replay store, the revocation list and the single-step plan are filled in with safe defaults.

```
composer install
vendor/bin/phpunit
```

The smoke test sends a signed call with its provenance (allowed, `201`), sends it again (refused, `403`), and sends one with no proof, a changed amount or no provenance (refused). Every refusal body is JSON with `error`, `error_description` or `reason`, and `doc`, a link to the page that explains the refusal.

Files:

- `bootstrap/app.php` registers the guard and the `pca` route middleware.
- `app/Guard.php` is the configuration: audience, grants, the pinned provenance mediators (`mediators.json`) and the mapping from the request to the operation the route executes.

Provenance is checked by default: a refund is sensitive, so the call must also carry a `PCA-Provenance` header from a pinned mediator showing that the user, not content an agent read, chose it (the test builds one with `ArgProvenance::principalDirect`, as the refunds UI would). Without it the call is refused with `decision: escalate`.
- `app/PcaGuard.php` runs the PSR-15 middleware inside Laravel's pipeline (through the Symfony PSR-7 bridge).
- `routes/api.php` guards the route.

To revoke a grant at runtime: `app(Atlas\Pca\Protect::class)->revoke($grantId)`.

The replay store is in memory and lives for one PHP process, so under PHP-FPM it does not stop a replay across requests. In production pass a `PdoStateStore` as `stateStore`.

In your own project, install the package with `composer require atlas-auth/atlas-pca` instead of the path repository in `composer.json`.
