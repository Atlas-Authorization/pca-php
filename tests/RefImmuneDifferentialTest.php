<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Immune;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The immune system's adaptation, signed tightening proposals and durable store against the TS reference (test-data/ref-immune-java.json.gz).
 * Guardian keys are the seeds sha256("atlas-pca-conformance/immune/<label>").
 */
final class RefImmuneDifferentialTest extends TestCase
{
    private const FILE = 'ref-immune-java.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/immune/' . $label, true);
    }

    /** The pinned guardian "@g" is the public key of the seed labelled g. */
    private static function pin(mixed $opts): mixed
    {
        if (!($opts instanceof Obj) || $opts->get('guardian') !== '@g') {
            return $opts;
        }
        $c = new Obj();
        foreach ($opts->keys() as $k) {
            $c->set($k, $k === 'guardian' ? (new KeyPair(self::seed('g')))->public : $opts->get($k));
        }
        return $c;
    }

    private static function store(array $a): array
    {
        $subject = $a[0];
        $kv = new MemoryAtomicKv();
        $st = Immune::createImmuneStore($kv, $subject);
        $out = [];
        foreach ($a[1] as $op) {
            try {
                $out[] = match ($op[0]) {
                    'seed' => (function () use ($kv, $subject, $op) {
                        $kv->update("immune/state/$subject", static fn(?string $prev): string => \Atlas\Pca\Json::canonicalizeLenient($op[1]));
                        return null;
                    })(),
                    'get' => $st->get(),
                    'observe' => $st->observe($op[1]),
                    'lastEpoch' => $st->lastEpoch(),
                    'apply' => $st->apply($op[1], $op[2], self::pin($op[3])),
                    default => throw new \LogicException('op ' . $op[0]),
                };
            } catch (\Throwable) {
                $out[] = Obj::of(['$err' => 'Error']);
            }
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'adapt' => fn(array $a) => Immune::adapt($a[0], $a[1]),
            'noWidenViolation' => fn(array $a) => Immune::noWidenViolation($a[0], $a[1]),
            'policyDigest' => fn(array $a) => Immune::policyDigest($a[0]),
            'immuneStateDigest' => fn(array $a) => Immune::immuneStateDigest($a[0]),
            'issueTighteningProposal' => fn(array $a) => Immune::issueTighteningProposal($a[0], $a[1], $a[2], $a[3], self::seed($a[4])),
            'applyTightening' => fn(array $a) => Immune::applyTightening($a[0], $a[1], self::pin($a[2])),
            'store' => fn(array $a) => self::store($a),
        ]);
    }

    public function testObserveAndAssess(): void
    {
        $s = Immune::initialState();
        $this->assertSame('calm', Immune::assess($s)->get('level'));
        for ($i = 0; $i < 3; $i++) {
            $s = Immune::observe($s, Obj::of(['r' => 1, 'at' => 0, 'denied' => true]));
        }
        $a = Immune::assess($s);
        $this->assertSame('high', $a->get('level'));
        $this->assertEquals(1, $a->get('score'));
        $t = Immune::observe(Immune::observe(Immune::initialState(), Obj::of(['r' => 0.5, 'at' => 100])), Obj::of(['r' => 0.5, 'at' => NAN]));
        $this->assertEquals(100, $t->get('lastAt'));
        $bad = Immune::initialState();
        $bad->set('ewma', 2);
        $this->assertSame('high', Immune::assess($bad)->get('level'));
    }
}
