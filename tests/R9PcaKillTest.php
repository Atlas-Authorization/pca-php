<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\LessFfi;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Round r9 mutation kills for src/Pca.php. */
final class R9PcaKillTest extends TestCase
{
    public function testPureLessSignatureLengthIsTheRangeRule(): void
    {
        if (!Pca::suiteAvailable('less-cat1')) {
            $this->markTestSkipped('libatlas_less is not available on this host');
        }
        $m = new \ReflectionMethod(Pca::class, 'validateSuiteFields');
        $sig = static fn(int $n): string => rtrim(strtr(base64_encode(str_repeat("\x01", $n)), '+/', '-_'), '=');
        $mk = static function (int $n) use ($sig): Obj {
            $p = new Obj();
            $p->set('alg', 'less-cat1');
            $p->set('sig', $sig($n));
            return $p;
        };
        // LESS signatures are variable-length: a shorter, on-step length is well formed (the range rule, not a fixed size)
        self::assertNull($m->invoke(null, $mk(LessFfi::SIGNATURE_MAX_BYTES - 16), false));
        self::assertNull($m->invoke(null, $mk(LessFfi::SIGNATURE_MIN_BYTES), false));
        self::assertNotNull($m->invoke(null, $mk(LessFfi::SIGNATURE_MAX_BYTES - 1), false));
    }
}
