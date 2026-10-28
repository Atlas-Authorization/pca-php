<?php

namespace App;

use Atlas\Pca\Json;
use Atlas\Pca\Protect;
use Psr\Http\Message\ServerRequestInterface;

/** The server's PCA configuration: secure defaults from Protect::protect(), plus this route's operation. */
final class Guard
{
    /** @param array<string,mixed> $override any Protect::protect() option; yours win */
    public static function protect(array $override = []): Protect
    {
        return Protect::protect($override + [
            'audience' => getenv('PCA_AUDIENCE') ?: 'payments-rs',
            // grants come from your own store (here a file), never from the request
            'grants' => Json::parseLax(file_get_contents(__DIR__ . '/../grants.json')),
            // the operation this route executes: the signed action must match it exactly
            'operation' => function (ServerRequestInterface $request): array {
                $body = json_decode((string) $request->getBody(), true) ?: [];
                return [
                    'verb' => 'payments.send',
                    'resource' => 'payments/' . ($body['account'] ?? ''),
                    'params' => ['amount' => $body['amount'] ?? null, 'currency' => $body['currency'] ?? null],
                ];
            },
        ]);
    }
}
