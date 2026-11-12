<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/PcaMiddleware.php';
require_once __DIR__ . '/StateStore.php';

/**
 * `Protect::protect()`: the secure defaults for a resource server, in one call (the PHP `protect()` of the TypeScript SDK).
 *
 *   $p = Protect::protect([
 *       'audience'  => 'ins_acme',
 *       'grants'    => [$grant],                                   // a list of grant Obj (looked up by `id`), or fn(string $ref): ?Obj
 *       'operation' => fn ($req) => ['verb' => 'stripe.refund', 'resource' => 'charge:ch_1', 'params' => [...]],
 *   ]);
 *   $p->middleware;          // a PSR-15 PcaMiddleware (also has Laravel-style handle($request, $next))
 *   $p->revoke($grant->get('id'));   // later: every action under that grant is refused
 *
 * It fills in only what every server otherwise wires by hand: the grant lookup (your own list or function, never the
 * request), a replay store (`MemoryStateStore` unless you pass `stateStore`; it lives for one process, so under PHP-FPM
 * pass a `PdoStateStore`), a revocation source, and `plan: 'single-step'` (the grant alone limits what runs). Everything
 * is still `Authorize::authorize`: bound to the operation your route executes, default-deny. Any option you pass wins.
 *
 * Not carried over from the TypeScript helper: catalog risk. This SDK has no connector catalog, so a grant that prices
 * risk needs its inputs from the `context` option.
 *
 * Options: `audience`, `grants`, `operation` are required. `isRevoked` is an extra `(Obj $pcactn, Obj $grant): bool` source
 * (true or any non-false value refuses). `clock`, `responseFactory`, `streamFactory`, `attribute`, `intentPolicy`, `intentV2`
 * and `freshAt` go to {@see PcaMiddleware}; every other key is a named argument of {@see AuthorizeOptions}. An unknown key
 * is an error, not ignored.
 */
final class Protect
{
    private const MIDDLEWARE_KEYS = ['clock', 'responseFactory', 'streamFactory', 'attribute', 'intentPolicy', 'intentV2', 'freshAt'];

    /** @param \ArrayObject<string,true> $revoked */
    private function __construct(public readonly PcaMiddleware $middleware, private readonly \ArrayObject $revoked)
    {
    }

    /** Refuse every further action under this grant id. */
    public function revoke(string $grantId): void
    {
        $this->revoked[$grantId] = true;
    }

    /** @param array<string,mixed> $opts */
    public static function protect(array $opts): self
    {
        foreach (['audience', 'grants', 'operation'] as $k) {
            if (!array_key_exists($k, $opts)) {
                throw new \InvalidArgumentException("Protect::protect: '$k' is required");
            }
        }
        $audience = $opts['audience'];
        $grants = $opts['grants'];
        $extra = $opts['isRevoked'] ?? null;
        if (!is_string($audience) || $audience === '') {
            throw new \InvalidArgumentException("Protect::protect: 'audience' must be a non-empty string");
        }
        if ($extra !== null && !is_callable($extra)) {
            throw new \InvalidArgumentException("Protect::protect: 'isRevoked' must be callable");
        }
        if (is_array($grants)) {
            $byId = [];
            foreach ($grants as $g) {
                $id = $g instanceof Obj ? $g->get('id') : null;
                if (!is_string($id) || $id === '') {
                    throw new \InvalidArgumentException("Protect::protect: every grant must be an Obj with a string 'id'");
                }
                $byId[$id] = $g;
            }
            $resolveGrant = static fn (string $ref): mixed => $byId[$ref] ?? null;
        } elseif (is_callable($grants)) {
            $resolveGrant = $grants;
        } else {
            throw new \InvalidArgumentException("Protect::protect: 'grants' must be a list of grants or a callable");
        }

        $mw = array_intersect_key($opts, array_flip(self::MIDDLEWARE_KEYS));
        $az = array_diff_key($opts, array_flip([...self::MIDDLEWARE_KEYS, 'audience', 'grants', 'isRevoked']));

        // an operation written as plain PHP arrays (the documented form) gets its params as a JSON object
        if (is_callable($az['operation'] ?? null)) {
            $map = $az['operation'];
            $az['operation'] = static function (mixed $request) use ($map): mixed {
                $op = $map($request);
                if (is_array($op) && is_array($op['params'] ?? null) && ($op['params'] === [] || !array_is_list($op['params']))) {
                    $op['params'] = Obj::of($op['params']);
                }
                return $op;
            };
        }

        $revoked = new \ArrayObject();
        $az += [
            'stateStore' => new MemoryStateStore(),
            'plan' => Authorize::SINGLE_STEP,
        ];
        // the revocation source is ours, plus your own if given; only an explicit false passes
        $az['isRevoked'] = static fn (mixed $pcactn, mixed $grant): bool => !($grant instanceof Obj) || isset($revoked[(string)$grant->get('id')])
            || ($extra !== null && $extra($pcactn, $grant) !== false);

        return new self(new PcaMiddleware(
            ...$mw,
            audience: $audience,
            resolveGrant: $resolveGrant,
            authorize: new AuthorizeOptions(...$az),
        ), $revoked);
    }
}
