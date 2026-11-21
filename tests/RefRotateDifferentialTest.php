<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\RevocationRegistry;
use Atlas\Pca\Revoke;
use Atlas\Pca\Rotate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Key rotation, subtree re-issue and applyRotation against the TS reference: test-data/ref-rotate.json.gz (keys cross as seeds). */
final class RefRotateDifferentialTest extends TestCase
{
    private const FILE = 'ref-rotate.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private static function clock(): float
    {
        return Base::clockMs(self::FILE);
    }

    /** A revokedAt within two minutes of the wall clock (live, or the corpus generator's frozen clock) is printed "<now>" (the reference does the same). */
    private static function norm(mixed $v): mixed
    {
        if (is_array($v)) {
            $o = [];
            foreach ($v as $k => $x) {
                $o[$k] = $k === 'revokedAt' && Js::isNum($x) && (abs(Js::num($x) - Revoke::nowMs()) < 120000 || abs(Js::num($x) - self::clock()) < 120000) ? '<now>' : self::norm($x);
            }
            return $o;
        }
        return $v;
    }

    private static function key(mixed $seed): ?KeyPair
    {
        return $seed === null ? null : KeyPair::fromSeedB64u($seed);
    }

    /** Options of a case: the keys plus the present `reason` / `now` members (a present null `now` must reach the refusal). */
    private static function opts(Obj $op, array $keys): array
    {
        $o = [];
        foreach ($keys as $to => $from) {
            $o[$to] = self::key($op->get($from));
        }
        foreach (['reason', 'now'] as $k) {
            if ($op->has($k)) {
                $o[$k] = $op->get($k);
            }
        }
        return $o;
    }

    private static function agent(array $a): mixed
    {
        return self::norm(Rotate::rotateAgentKey($a[0], self::opts($a[1], ['oldHolderSecret' => 'oldSeed', 'newKeyPair' => 'newSeed'])));
    }

    private static function principal(array $a): mixed
    {
        /** @var Obj $o */
        $o = $a[0];
        $args = self::opts($o, ['oldPrincipalSecret' => 'oldSeed', 'newPrincipalKeyPair' => 'newSeed']);
        foreach (['chain', 'oldRoot'] as $k) {
            if ($o->has($k)) {
                $args[$k] = $o->get($k);
            }
        }
        $hs = $o->get('holderSeeds');
        if ($o->has('holderSeeds')) {
            $args['holderSecrets'] = $hs === null ? null : array_map(self::key(...), $hs);
        }
        return self::norm(Rotate::rotatePrincipalKey($args));
    }

    private static function reissue(string $fn, array $a): mixed
    {
        return self::norm(Rotate::$fn($a[0], $a[1], self::opts($a[2], ['newKeyPair' => 'newSeed', 'ancestorSecret' => 'ancestorSeed'])));
    }

    private static function scenario(Obj $spec): mixed
    {
        $reg = new RevocationRegistry();
        foreach ($spec->get('pre') ?? [] as $id) {
            $reg->revoke(['kind' => 'cap', 'value' => $id, 'reason' => 'pre', 'revokedAt' => (int) self::clock()]);
        }
        $failAt = Js::num($spec->get('failAt'));
        $sink = new class ($reg, $failAt, $spec->get('failUnrevoke') === true) {
            private int $calls = 0;

            public function __construct(private readonly RevocationRegistry $reg, private readonly ?float $failAt, private readonly bool $failUnrevoke)
            {
            }

            public function revoke(mixed $input): void
            {
                $this->calls++;
                if ($this->failAt !== null && $this->failAt === (float) $this->calls) {
                    throw new \RuntimeException('sink down');
                }
                $this->reg->revoke($input);
            }

            public function unrevoke(mixed $key): bool
            {
                if ($this->failUnrevoke) {
                    throw new \RuntimeException('unrevoke down');
                }
                return $this->reg->unrevoke($key);
            }

            public function lookup(string $kind, string $value): ?array
            {
                return $this->reg->lookup($kind, $value);
            }
        };
        try {
            $result = Rotate::applyRotation($sink, $spec->get('records'), $spec->get('reissued'));
        } catch (\Throwable) {   // only the refusal is compared, not its message
            $result = ['$err' => true];
        }
        return ['result' => $result, 'list' => self::norm($reg->list())];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'rotateAgentKey' => fn(array $a) => self::agent($a),
            'rotatePrincipalKey' => fn(array $a) => self::principal($a),
            'revokeAndReissueSubtree' => fn(array $a) => self::reissue('revokeAndReissueSubtree', $a),
            'compromisedKeyFlow' => fn(array $a) => self::reissue('compromisedKeyFlow', $a),
            'applyRotationScenario' => fn(array $a) => self::scenario($a[0]),
        ]);
    }
}
