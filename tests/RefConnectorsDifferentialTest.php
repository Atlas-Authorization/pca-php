<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Connect;
use Atlas\Pca\ConnectorError;
use Atlas\Pca\Connectors;
use Atlas\Pca\InMemoryConnectionStore;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\ProviderRegistry;
use Atlas\Pca\TokenVault;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The connector catalog against the TS reference: test-data/ref-connectors.json.gz (manifests, registry, authorize URL, PKCE, exchange, refresh, vault bridge). */
final class RefConnectorsDifferentialTest extends TestCase
{
    private const FILE = 'ref-connectors.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** A connector error as data (class name and message); any other failure is the generic "Error". */
    private static function errOut(\Throwable $e): array
    {
        if ($e instanceof ConnectorError) {
            $out = ['ok' => false, 'name' => (new \ReflectionClass($e))->getShortName(), 'message' => $e->getMessage()];
            if (property_exists($e, 'issues') && $e->issues !== []) {
                $out['issues'] = $e->issues;
            }
            return $out;
        }
        return ['ok' => false, 'name' => 'Error'];
    }

    private static function guard(\Closure $f): array
    {
        try {
            return ['ok' => true, 'value' => $f()];
        } catch (\Throwable $e) {
            return self::errOut($e);
        }
    }

    private static function withReg(mixed $customs): ProviderRegistry
    {
        $r = Connectors::createDefaultRegistry();
        foreach ($customs ?? [] as $m) {
            $r->register($m);
        }
        return $r;
    }

    private static function buildAuthorize(mixed $pid, Obj $opts, mixed $customs): array
    {
        return self::guard(static function () use ($pid, $opts, $customs) {
            $o = new Obj();
            foreach ($opts->keys() as $k) {
                $o->set($k, $opts->get($k));
            }
            $o->set('registry', self::withReg($customs));
            return Connectors::buildAuthorizeUrl($pid, $o);
        });
    }

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

    private static function tokenRun(string $which): \Closure
    {
        return static function (Obj $c) use ($which): array {
            $log = [];
            $store = new InMemoryConnectionStore();
            $now = $c->get('now');
            $vault = new TokenVault(['strict' => false, 'insecureSkipPlanRootCheck' => true, 'store' => $store, 'now' => static fn() => $now]);
            $bind = $c->get('bind');
            $authority = Obj::of(['principal' => $bind->get('principal')]);
            foreach (['scopes', 'audience'] as $k) {
                if ($bind->has($k)) {
                    $authority->set($k, $bind->get($k));
                }
            }
            $args = new Obj();
            foreach ($c->keys() as $k) {
                if (!in_array($k, ['bind', 'script', 'customs'], true)) {
                    $args->set($k, $c->get($k));
                }
            }
            $args->set('fetch', self::transport($c->get('script'), $log));
            $args->set('registry', self::withReg($c->get('customs')));
            $b = Obj::of(['vault' => $vault, 'agentId' => $bind->get('agentId'), 'authority' => $authority]);
            if ($bind->has('connectionId')) {
                $b->set('connectionId', $bind->get('connectionId'));
            }
            $args->set('bind', $b);
            try {
                $result = ['ok' => true, 'value' => $which === 'exchange' ? Connectors::exchangeCode($args) : Connectors::refresh($args)];
            } catch (\Throwable $e) {
                $result = self::errOut($e);
            }
            $g = $store->get(Obj::of(['agentId' => $bind->get('agentId'), 'provider' => $c->get('providerId'),
                'connectionId' => $bind->has('connectionId') ? $bind->get('connectionId') : 'default']));
            return ['result' => $result, 'fetchCalls' => $log, 'stored' => $g === null ? null : Connect::cloneConnection($g)];
        };
    }

    private static function registryOps(Obj $s): array
    {
        $r = Js::truthy($s->get('empty')) ? new ProviderRegistry() : Connectors::createDefaultRegistry();
        $out = [];
        foreach ($s->get('ops') as $op) {
            try {
                $v = match ($op->get('op')) {
                    'register' => $r->register($op->get('manifest'), $op->get('opts')),
                    'get' => $r->get($op->get('id')),
                    'require' => $r->require($op->get('id')),
                    'has' => $r->has($op->get('id')),
                    'list' => $r->list(),
                    'ids' => $r->ids(),
                    default => Connectors::catalogDigest($r),
                };
                $out[] = ['ok' => true, 'value' => $v];
            } catch (\Throwable $e) {
                $out[] = self::errOut($e);
            }
        }
        return $out;
    }

    private static function catalog(): array
    {
        return ['ids' => array_map(static fn(Obj $m) => $m->get('id'), Connectors::listProviders()), 'manifests' => Connectors::listProviders(),
            'digest' => Connectors::catalogDigest(), 'google' => Connectors::getProvider('google'), 'nope' => Connectors::getProvider('nope')];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'validateManifest' => fn(array $a) => Connectors::validateManifest(...$a),
            'assertManifest' => fn(array $a) => self::guard(fn() => Connectors::assertManifest(...$a)),
            'manifestDigest' => fn(array $a) => Connectors::manifestDigest(...$a),
            'catalog' => fn(array $a) => self::catalog(),
            'registry' => fn(array $a) => self::registryOps($a[0]),
            'substituteVars' => fn(array $a) => self::guard(fn() => Connectors::substituteVars($a[0], $a[1])),
            'pkceChallenge' => fn(array $a) => self::guard(fn() => Connectors::pkceChallenge(...$a)),
            'buildAuthorizeUrl' => fn(array $a) => self::buildAuthorize($a[0], $a[1], $a[2] ?? null),
            'applyAccessToken' => fn(array $a) => self::guard(fn() => Connectors::applyAccessToken(...$a)),
            'manifestToProviderConfig' => fn(array $a) => self::guard(fn() => Connectors::manifestToProviderConfig(Connectors::getProvider($a[0]), $a[1])),
            'buildVaultProviders' => fn(array $a) => self::guard(fn() => Connectors::buildVaultProviders($a[0])),
            'exchange' => fn(array $a) => (self::tokenRun('exchange'))($a[0]),
            'refresh' => fn(array $a) => (self::tokenRun('refresh'))($a[0]),
        ]);
    }
}
