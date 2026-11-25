<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3.php';

use Atlas\Pca\Json;
use Atlas\Pca\K3;
use PHPUnit\Framework\TestCase;

/** The signed-message builders of the grant resource (grant-resource.ts). */
final class K3MessagesTest extends TestCase
{
    public function testMessagesAndDomains(): void
    {
        self::assertSame("atlas-pca/need-request/v1\0", K3::NEED_REQUEST_DOMAIN);
        self::assertSame("atlas-pca/grant-stepup/v1\0", K3::GRANT_STEPUP_DOMAIN);
        $needs = Json::parseLax('[{"verb":"v","resource":"r"}]');
        self::assertSame('{"grant":"g1","needs":[{"resource":"r","verb":"v"}],"rev":3}', Json::canonicalizeLenient(K3::needRequestMessage('g1', Json::parseLax('3'), $needs)));
        self::assertSame('{"challenge":"c1","grant":"g1","nonce":"n1"}', Json::canonicalizeLenient(K3::stepUpMessage('g1', 'c1', 'n1')));
    }
}
