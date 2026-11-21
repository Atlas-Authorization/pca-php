<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\TxnTokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** OAuth Transaction Tokens against the TS reference: test-data/ref-txn-tokens.json.gz. */
final class RefTxnTokensDifferentialTest extends TestCase
{
    private const FILE = 'ref-txn-tokens.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** Issue is random (iat, exp, jti / txn): {header, claims} with iat dropped, exp as `ttl`, a generated id as true. */
    private static function issue(Obj $a): Obj
    {
        $o = $a->without('seed');
        $o->set('issuerKey', Pca::unb64u($a->get('seed')));
        $tok = TxnTokens::toTransactionToken($o);
        [$h, $p] = explode('.', $tok);
        $header = Json::parseLax(Jose::lenientB64d($h));
        $c = Json::parseLax(Jose::lenientB64d($p));
        $keep = $c->without('iat', 'exp', 'jti', 'txn');
        $keep->set('ttl', \Atlas\Pca\Js::num($c->get('exp')) - \Atlas\Pca\Js::num($c->get('iat'))); // exact, a fractional ttl stays fractional
        if ($c->has('jti')) {
            $keep->set('jti', true);
        }
        if ($c->has('txn')) {
            $keep->set('txn', $a->has('txn') ? $c->get('txn') : true);
        }
        return Obj::of(['header' => $header, 'claims' => $keep]);
    }

    private static function verify(array $a): array
    {
        $w = $a[2] ?? new Obj();
        $o = [];
        foreach (['profile', 'audience', 'clockToleranceSec', 'nowMs'] as $k) {
            if ($w->has($k)) {
                $o[$k] = $w->get($k);
            }
        }
        if (is_array($w->get('seen'))) {
            $seen = $w->get('seen');
            $o['seenTxn'] = static fn(string $id): bool => in_array($id, $seen, true);
        }
        if ($w->get('unchecked') === true) {
            $o['replayCheck'] = 'unchecked';
        }
        return TxnTokens::fromTransactionToken($a[0], Pca::unb64u($a[1]), $o);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'subActChain' => fn(array $a) => TxnTokens::subActChain($a[0]),
            'actDepth' => fn(array $a) => TxnTokens::actDepth($a[0]),
            'toRfc8693Act' => fn(array $a) => TxnTokens::toRfc8693Act($a[0]),
            'toTransactionToken' => fn(array $a) => self::issue($a[0]),
            'fromTransactionToken' => fn(array $a) => self::verify($a),
        ]);
    }

    public function testAReplayedIdIsRefusedOnlyAfterEveryOtherCheck(): void
    {
        $by = [];
        foreach (Base::cases(self::FILE, 'fromTransactionToken', 0) as $c) {
            $by[substr((string)$c->get('name'), strlen('fromTransactionToken/'))] = $c->get('args');
        }
        $calls = [];
        try {
            TxnTokens::fromTransactionToken($by['act deep bad'][0], Pca::unb64u($by['draft ok'][1]), [
                'audience' => 'td.example', 'nowMs' => 1800000000500,
                'seenTxn' => static function (string $id) use (&$calls): bool {
                    $calls[] = $id;
                    return false;
                },
            ]);
            self::fail('a malformed act claim must be refused');
        } catch (\InvalidArgumentException) {
        }
        self::assertSame([], $calls, 'a token refused for another reason never burns its id');
    }
}
