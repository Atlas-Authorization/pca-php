<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Gateway;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A replay guard double: a fixed answer, or (null) a store that is down. */
final class GatewayFixedGuard
{
    public function __construct(private readonly ?bool $answer)
    {
    }

    public function claim(mixed ...$args): bool
    {
        return $this->answer ?? throw new \RuntimeException('store down');
    }
}

/**
 * The gateway (canonical query, request binding, path hardening, replay guard, provenance log, presented artifacts, authorize /
 * createGateway over real signed proofs, the Envoy HTTP / gRPC shapes and the Lambda authorizers) against the TS reference:
 * test-data/ref-gateway.json.gz.
 *
 * Compared after masking: the verdict objects print "<verdict>" and the strict-JSON parser's own message in
 * "undecodable PCA-Action header: <message>" prints "<json>".
 */
final class RefGatewayDifferentialTest extends TestCase
{
    private const FILE = 'ref-gateway.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    public static function mask(mixed $v): mixed
    {
        if (is_string($v)) {
            return preg_replace('/undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*/', 'undecodable PCA-Action header: <json>', $v);
        }
        if (is_array($v) && array_is_list($v)) {
            return array_map(self::mask(...), $v);
        }
        if ($v instanceof Obj || is_array($v)) {
            $src = $v instanceof Obj ? $v : Obj::of($v);
            $out = new Obj();
            foreach ($src->keys() as $k) {
                $x = $src->get($k);
                $out->set($k, ($k === 'x-pca-verdict' || $k === 'pcaVerdict') && is_string($x) && $x !== '' ? '<verdict>' : self::mask($x));
            }
            $h = $out->get('header');
            if ($h instanceof Obj && $h->get('key') === 'x-pca-verdict' && $h->get('value') !== '') {
                $h2 = new Obj();
                foreach ($h->keys() as $k) {
                    $h2->set($k, $h->get($k));
                }
                $h2->set('value', '<verdict>');
                $out->set('header', $h2);
            }
            return $out;
        }
        return $v;
    }

    public static function build(Obj $spec): array
    {
        $now = $spec->get('now');
        $grants = $spec->get('grants');
        $opts = [
            'audience' => $spec->get('audience'),
            'routes' => $spec->get('routes'),
            'resolveGrant' => static fn($ref, $p = null) => is_string($ref) ? $grants->get($ref) : null,
            'now' => static fn() => $now,
        ];
        $b = $spec->get('bindRequest');
        if ($b === 'off') {
            $opts['bindRequest'] = false;
        } elseif ($b !== null) {
            $opts['bindRequest'] = $b;
        }
        foreach (['unmatched' => 'unmatchedRoute', 'pathPolicy' => 'pathPolicy', 'requireChecks' => 'requireChecks', 'realm' => 'realm', 'planRoots' => 'authorizedPlanRoots'] as $from => $to) {
            if ($spec->get($from) !== null) {
                $opts[$to] = $spec->get($from);
            }
        }
        if (Js::truthy($spec->get('skipPlan'))) {
            $opts['insecureSkipPlanRootCheck'] = true;
        }
        $guards = [
            'always' => static fn() => new GatewayFixedGuard(true),
            'false' => static fn() => new GatewayFixedGuard(false),
            'throws' => static fn() => new GatewayFixedGuard(null),
            'memory' => static fn() => Gateway::memoryReplayGuard(100000, static fn() => $now),
            'memory-full' => static fn() => Gateway::memoryReplayGuard(1, static fn() => $now),
        ];
        if ($spec->get('replay') !== 'none') {
            $opts['replayGuard'] = $guards[$spec->get('replay')]();
        }
        $revs = [
            'ok' => static fn($c) => ['enforced' => true, 'ok' => true],
            'revoked' => static fn($c) => ['enforced' => true, 'ok' => false, 'reason' => 'grant revoked'],
            'revoked-noreason' => static fn($c) => ['enforced' => true, 'ok' => false],
            'notEnforced' => static fn($c) => ['enforced' => false],
            'throws' => static function ($c) {
                throw new \RuntimeException('rev down');
            },
        ];
        if ($spec->get('revocation') !== 'none') {
            $opts['hooks'] = ['revocation' => $revs[$spec->get('revocation')]];
        }
        $cps = [
            'true' => static fn($c) => true,
            'false' => static fn($c) => false,
            'obj-true' => static fn($c) => ['allow' => true],
            'obj-false' => static fn($c) => ['allow' => false],
            'obj-false-reason' => static fn($c) => ['allow' => false, 'reason' => 'over limit'],
            'throws' => static function ($c) {
                throw new \RuntimeException('policy down');
            },
        ];
        if (Js::truthy($spec->get('checkProof'))) {
            $opts['checkProof'] = $cps[$spec->get('checkProof')];
        }
        $pol = $spec->get('policy');
        if ($pol === 'sig') {
            $opts['policy'] = ['mode' => 'signature-only'];
        } elseif ($pol === 'bogus') {
            $opts['policy'] = ['mode' => 'bogus'];
        } elseif ($pol === 'full-missing') {
            $opts['policy'] = ['mode' => 'full', 'params' => 'body'];
        }
        return $opts;
    }

    private static function proj(array $d): mixed
    {
        $out = Obj::of(['allow' => $d['allow'], 'status' => $d['status'], 'code' => $d['code'], 'reason' => $d['reason'], 'headers' => $d['headers']]);
        if (array_key_exists('matched', $d)) {
            $out->set('matched', $d['matched']);
        }
        if (isset($d['pcactn']) && $d['pcactn']->get('grant_ref') !== null) {
            $out->set('grant', $d['pcactn']->get('grant_ref'));
        }
        if (isset($d['verdict'])) {
            $out->set('verdictAllow', $d['verdict']['allow']);
        }
        return self::mask($out);
    }

    private static function authorizeScenario(Obj $spec): mixed
    {
        try {
            $gw = Gateway::createGateway(self::build($spec));
        } catch (\TypeError | \InvalidArgumentException $e) {
            return Obj::of(['create' => $e->getMessage()]);
        }
        $out = [];
        foreach ($spec->get('requests') as $r) {
            $out[] = self::proj($gw($r));
        }
        return $out;
    }

    private static function adapter(string $make, Obj $spec): mixed
    {
        try {
            $fn = Gateway::$make(self::build($spec));
        } catch (\TypeError | \InvalidArgumentException $e) {
            return Obj::of(['create' => $e->getMessage()]);
        }
        return self::mask($fn($spec->get('events')[0]));
    }

    private static function lambdaLone(string $make, Obj $spec): mixed
    {
        try {
            return self::mask(Gateway::$make(self::build($spec))($spec->get('events')[0]));
        } catch (\InvalidArgumentException $e) {
            return Obj::of(['threw' => $e->getMessage()]);
        }
    }

    private static function replay(Obj $spec): array
    {
        $clock = $spec->has('clock') ? $spec->get('clock') : 0;
        $g = Gateway::memoryReplayGuard((int)Js::num($spec->get('max')), static function () use (&$clock) {
            return $clock;
        });
        $out = [];
        foreach ($spec->get('ops') as $op) {
            if ($op->has('setClock')) {
                $clock = $op->get('setClock');
                continue;
            }
            try {
                $out[] = $g->claim($op->get('key'), $op->get('exp'), $op->has('now') ? $op->get('now') : null);
            } catch (\Throwable $e) {
                $out[] = Obj::of(['threw' => $e->getMessage()]);
            }
        }
        return $out;
    }

    private static function provLog(Obj $spec): array
    {
        $log = Gateway::memoryProvenanceLog((int)Js::num($spec->get('max')));
        $out = [];
        foreach ($spec->get('ops') as $op) {
            if (Js::truthy($op->get('add'))) {
                $log->add($op->get('session'), $op->get('o'));
                $out[] = 'added';
            } else {
                $out[] = $log->seen($op->get('session'));
            }
        }
        return $out;
    }

    private static function policy(string $kind): array
    {
        return $kind === 'body' ? ['params' => 'body'] : ['params' => static fn() => new Obj()];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            // JSON cannot carry an undefined argument: that case reaches PHP as null, which the reference never saw as null
            'canonicalQuery' => fn(array $a) => $a[0] === null ? [Base::SKIP, 'undefined argument'] : Gateway::canonicalQuery($a[0]),
            'requestBinding' => fn(array $a) => Gateway::requestBinding($a[0], $a[1] ?? null),
            'bindParams' => fn(array $a) => Gateway::bindParams($a[0], $a[1] ?? null),
            'ambiguousPathReason' => fn(array $a) => Gateway::ambiguousPathReason($a[0]),
            'replayScenario' => fn(array $a) => self::replay($a[0]),
            'provenanceLogScenario' => fn(array $a) => self::provLog($a[0]),
            'presentedProvenance' => function (array $a) {
                $v = Gateway::presentedProvenance($a[0], self::policy($a[1]));
                return $v === Gateway::ABSENT ? Obj::of(['undef' => true]) : $v;
            },
            'presentedArtifacts' => fn(array $a) => Gateway::presentedArtifacts($a[0], self::policy($a[1])),
            'authorizeScenario' => fn(array $a) => self::authorizeScenario($a[0]),
            'envoyScenario' => fn(array $a) => self::adapter('envoyExtAuthz', $a[0]),
            'grpcScenario' => fn(array $a) => self::adapter('envoyGrpcExtAuthz', $a[0]),
            'lambdaScenario' => fn(array $a) => self::lambdaLone('lambdaAuthorizer', $a[0]),
            'lambdaSimpleScenario' => fn(array $a) => self::lambdaLone('lambdaSimpleAuthorizer', $a[0]),
        ]);
    }
}
