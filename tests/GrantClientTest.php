<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FreshAtIssuer;
use Atlas\Pca\GrantApiError;
use Atlas\Pca\GrantClient;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The grant client folds only newer, verifiable freshness tokens and maps a non-2xx answer to GrantApiError. */
final class GrantClientTest extends TestCase
{
    public function testFoldsOnlyNewerVerifiedTokens(): void
    {
        $key = new KeyPair(hash('sha256', 'atlas-pca-conformance/c', true));
        $iss = new FreshAtIssuer($key, 'scope', Obj::of(['revocation_epoch' => 1, 'ledger_tree_size' => 1, 'budget_version' => 1, 'policy_revision' => 1, 'policy_digest' => 'pd']));
        $t1 = $iss->advance(Obj::of(['revocation_epoch' => 2]), 1_800_000_000_000);
        $older = clone $t1;
        $older->set('revocation_epoch', 0);
        $forged = clone $t1;
        $forged->set('sig', 'x');
        $toks = [$t1, $older, $forged];
        $sent = [];
        $fetch = static function (array $req) use (&$toks, &$sent): array {
            $sent[] = $req;
            return ['status' => 200, 'headers' => ['Pca-Fresh-At' => Js::stringify(array_shift($toks))], 'body' => '{"grants":[]}'];
        };
        $c = new GrantClient('https://as.example/', $fetch, $key->public);
        $c->list(['status' => 'active', 'limit' => 5]);
        self::assertSame('https://as.example/pca/grants?status=active&limit=5', $sent[0]['url']);
        self::assertSame(2.0, Js::num($c->freshAt()?->get('revocation_epoch')));
        $c->inspect('a/b');
        $c->inspect('a/b');
        self::assertSame(Js::stringify($t1), Js::stringify($c->freshAt()));
        self::assertArrayHasKey('pca-fresh-at', $sent[1]['headers']);
        self::assertStringEndsWith('/pca/grants/a%2Fb', $sent[1]['url']);
    }

    public function testNon2xxIsAnApiError(): void
    {
        $boom = static fn(array $req): array => ['status' => 409, 'headers' => [], 'body' => '{"error":"conflict","message":"m"}'];
        try {
            (new GrantClient('https://as.example', $boom))->denyNeeds('n');
            self::fail('expected a GrantApiError');
        } catch (GrantApiError $e) {
            self::assertSame(409, $e->status);
            self::assertSame('conflict', $e->errorCode);
        }
    }
}
