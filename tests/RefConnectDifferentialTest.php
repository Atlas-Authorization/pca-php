<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Connect;
use Atlas\Pca\ConnectReplay;
use Atlas\Pca\EncryptedConnectionStore;
use Atlas\Pca\InMemoryConnectionStore;
use Atlas\Pca\InMemoryReplayStore;
use Atlas\Pca\Js;
use Atlas\Pca\LocalKeyWrapper;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\TokenVault;
use Atlas\Pca\VaultError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The outbound token vault against the TS reference: test-data/ref-connect-v2.json.gz (oauth_scope caveats, refresh, extractor, receipts, encrypted store, vault scenarios). */
final class RefConnectDifferentialTest extends TestCase
{
    private const FILE = 'ref-connect-v2.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function u16(string $s): string
    {
        return (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    private static function granted(mixed $chain, mixed $provider): mixed
    {
        $r = Connect::grantedOAuthScopes($chain, $provider);
        if ($r === null) {
            return null;
        }
        usort($r, static fn($a, $b) => strcmp(self::u16($a), self::u16($b)));
        return $r;
    }

    private static function errOut(\Throwable $e): array
    {
        if ($e instanceof VaultError) {
            $out = ['ok' => false, 'name' => (new \ReflectionClass($e))->getShortName(), 'code' => $e->errorCode];
            if ($e->errorCode !== 'not_authorized') {
                $out['message'] = $e->getMessage();
            }
            if (property_exists($e, 'status') && $e->status !== null) {
                $out['status'] = $e->status;
            }
            if (property_exists($e, 'missing') && $e->missing !== []) {
                $out['missing'] = $e->missing;
            }
            return $out;
        }
        return ['ok' => false, 'name' => 'Error'];
    }

    /** @return \Closure|null a fetch over the scripted responses, logging every call into $log */
    private static function transport(mixed $script, array &$log): ?\Closure
    {
        if ($script === null) {
            return null;
        }
        $n = 0;
        return static function (mixed $url, Obj $init) use ($script, &$log, &$n): RefConnectResp {
            $log[] = ['url' => $url, 'method' => $init->get('method'), 'headers' => $init->get('headers'), 'body' => $init->get('body')];
            $r = $script[min($n, count($script) - 1)];
            $n++;
            if ($r->has('throws')) {
                throw new \RuntimeException((string)$r->get('throws'));
            }
            return new RefConnectResp($r);
        };
    }

    private static function refresh(Obj $c): array
    {
        $log = [];
        try {
            $v = Connect::refreshConnection($c->get('connection'), $c->get('config'), $c->get('refreshToken'), $c->get('requested'),
                self::transport($c->get('script'), $log), $c->get('now'), $c->get('defaultTokenLifetimeMs'));
            return ['ok' => true, 'value' => $v, 'calls' => $log];
        } catch (\Throwable $e) {
            return self::errOut($e) + ['calls' => $log];
        }
    }

    private static function decrypt(Obj $c): mixed
    {
        if (!function_exists('openssl_encrypt')) {
            return [Base::SKIP, 'no openssl'];
        }
        $inner = new InMemoryConnectionStore();
        $inner->set($c->get('record'));
        $ring = [];
        $r = $c->get('ring');
        foreach ($r->keys() as $k) {
            $ring[$k] = (string)Pca::unb64u($r->get($k));
        }
        $store = new EncryptedConnectionStore($inner, new LocalKeyWrapper($ring, $c->get('active')));
        try {
            $got = $store->get($c->get('key'));
            return ['ok' => true, 'value' => $got === null ? null : Connect::cloneConnection($got)];
        } catch (\Throwable $e) {
            return self::errOut($e);
        }
    }

    private static function vault(Obj $s): array
    {
        $now = $s->get('nowMs');
        $store = new InMemoryConnectionStore();
        $fetchLog = [];
        $proxyLog = [];
        $receipts = [];
        $op = $s->get('opts') ?? new Obj();
        $table = $s->get('actionsTable');
        $pi = 0;
        $kw = ['strict' => false, 'store' => $store, 'now' => static function () use (&$now) {
            return $now;
        }, 'fetch' => self::transport($s->get('fetchScript'), $fetchLog)];
        foreach (['insecureBearerRelease', 'insecureSkipPlanRootCheck', 'authorizedPlanRoots', 'audience', 'expiryLeewayMs', 'defaultTokenLifetimeMs',
            'requireActionBinding', 'defaultConnectionId', 'providers', 'pqPins', 'maxProxyResponseBytes'] as $k) {
            if (!$op->has($k)) {
                continue;
            }
            $v = $op->get($k);
            if ($v !== null && $v !== false) {
                $kw[$k] = $v;
            } elseif ($v === false && $k === 'requireActionBinding') {
                $kw[$k] = false;
            }
        }
        if ($op->has('useVerb')) {
            $kw['useVerb'] = $op->get('useVerb');
        }
        if (Js::truthy($op->get('replay'))) {
            $kw['replay'] = new InMemoryReplayStore();
        }
        if (Js::truthy($op->get('revoked'))) {
            $mode = $op->get('revoked');
            $kw['isRevoked'] = static function ($p) use ($mode): bool {
                if ($mode === 'throws') {
                    throw new \RuntimeException('src down');
                }
                return $mode === 'yes';
            };
        }
        if ($table instanceof Obj) {
            $kw['actions'] = static function ($verb) use ($table): ?Obj {
                if (!is_string($verb) || !$table->has($verb)) {
                    return null;
                }
                $t = $table->get($verb);
                $a = Obj::of(['verb' => $t->get('verb'), 'def_digest' => $t->get('def_digest'), 'confirmed' => $t->get('confirmed'), 'upstream' => $t->get('upstream')]);
                if (Js::truthy($t->get('extract'))) {
                    $a->set('extract', Connect::httpExtractor($t->get('extract')));
                }
                return $a;
            };
        }
        if (Js::truthy($op->get('proxy'))) {
            $script = $s->get('proxyScript');
            $kw['proxyFetch'] = static function (Obj $req) use (&$proxyLog, $script, &$pi): Obj {
                $proxyLog[] = ['method' => $req->get('method'), 'url' => $req->get('url'), 'headers' => $req->get('headers'), 'body' => $req->get('body'),
                    'redirect' => $req->get('redirect')];
                $r = $script[min($pi, count($script) - 1)];
                $pi++;
                if (Js::truthy($r->get('throws'))) {
                    throw new \RuntimeException('net');
                }
                return Obj::of(['status' => $r->get('status'), 'headers' => $r->get('headers'), 'body' => $r->get('body')]);
            };
        }
        if (Js::truthy($op->get('receiptSeed'))) {
            $failing = Js::truthy($op->get('failingSink'));
            $kw['receipts'] = Obj::of(['secretKey' => (string)Pca::unb64u($op->get('receiptSeed')), 'sink' => static function ($r) use (&$receipts, $failing): void {
                $receipts[] = $r;
                if ($failing) {
                    throw new \RuntimeException('sink');
                }
            }]);
        }
        $v = new TokenVault($kw);
        $results = [];
        $rec = static function (\Closure $f) use (&$results): void {
            try {
                $results[] = ['ok' => true, 'value' => $f()];
            } catch (\Throwable $e) {
                $results[] = self::errOut($e);
            }
        };
        foreach ($s->get('calls') as $c) {
            $a = $c->get('args');
            switch ($c->get('op')) {
                case 'put':
                    $rec(fn() => $v->putConnection($a->get('agentId'), $a->get('provider'), $a->get('accessToken'), $a->get('expiresAt'), $a->get('scopes'),
                        $a->get('authority'), $a->get('connectionId'), $a->get('refreshToken')));
                    break;
                case 'get':
                    $rec(fn() => $v->getConnectionToken($c->get('pcActn'), $a->get('provider'), $a->get('connectionId'), $a->get('scopes')));
                    break;
                case 'proxy':
                    $rec(fn() => $v->proxyCall($c->get('pcActn'), $c->get('request'), $a->get('provider'), $a->get('connectionId'), $a->get('scopes')));
                    break;
                case 'delete':
                    $rec(function () use ($v, $c): mixed {
                        $v->deleteConnection($c->get('agentId'), $c->get('provider'), $c->get('connectionId'));
                        return null;
                    });
                    break;
                case 'now':
                    $now = $c->get('now');
                    break;
            }
        }
        $out = [];
        foreach ($s->get('watch') ?? [] as $k) {
            $g = $store->get($k);
            $out[] = $g === null ? null : Connect::cloneConnection($g);
        }
        return ['results' => $results, 'store' => $out, 'receipts' => $receipts, 'fetchCalls' => $fetchLog, 'proxyCalls' => $proxyLog];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'oauthScopeCaveat' => fn(array $a) => Connect::oauthScopeCaveat(...$a),
            'isOAuthScopeCaveat' => fn(array $a) => Connect::isOAuthScopeCaveat(...$a),
            'grantedOAuthScopes' => fn(array $a) => self::granted(...$a),
            'httpExtractor' => fn(array $a) => (Connect::httpExtractor($a[0]))($a[1]),
            'checkProxyHeaders' => fn(array $a) => Connect::checkProxyHeaders(...$a),
            'DEFAULT_PROXY_HEADERS' => fn(array $a) => Connect::DEFAULT_PROXY_HEADERS,
            'outboundRequestDigest' => fn(array $a) => Connect::outboundRequestDigest(...$a),
            'signReleaseReceipt' => fn(array $a) => Connect::signReleaseReceipt($a[0], (string)Pca::unb64u($a[1])),
            'verifyReleaseReceipt' => fn(array $a) => Connect::verifyReleaseReceipt(...$a),
            'receiptActionDigest' => fn(array $a) => Connect::receiptActionDigest(...$a),
            'refreshConnection' => fn(array $a) => self::refresh($a[0]),
            'decryptRecord' => fn(array $a) => self::decrypt($a[0]),
            'vault' => fn(array $a) => self::vault($a[0]),
        ]);
    }

    /** A replayed nonce is refused once; the guard never throws. */
    public function testReplayGuardSpendsANonceOnce(): void
    {
        $store = new InMemoryReplayStore();
        $p = Obj::of(['grant_ref' => 'g', 'cap_chain' => [Obj::of(['holder' => 'h'])], 'nonce' => 'n', 'aud' => 'rs', 'counter' => new \Atlas\Pca\Num('1'),
            'iat' => new \Atlas\Pca\Num('1000'), 'exp' => new \Atlas\Pca\Num('2000')]);
        $this->assertTrue(ConnectReplay::guardPcactnReplay($store, $p, 'rs', 1500)['ok']);
        $second = ConnectReplay::guardPcactnReplay($store, $p, 'rs', 1500);
        $this->assertFalse($second['ok']);
        $this->assertSame('replay', $second['code']);
        $this->assertSame('audience', ConnectReplay::guardPcactnReplay($store, $p, 'other', 1500)['code']);
    }
}
