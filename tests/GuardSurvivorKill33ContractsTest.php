<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Contracts.php';

use Atlas\Pca\Contracts;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Contracts.php: the id of a non-object contract is the index-keyed object of its characters or items. */
final class GuardSurvivorKill33ContractsTest extends TestCase
{
    /** A string body is keyed by code point; a list by its position (not its PHP keys); a non-BMP string is refused. */
    public function testIdOfNonObjectBodies(): void
    {
        $this->assertSame(Pca::hashCanonical(Obj::of(['0' => 'a', '1' => 'b'])), Contracts::contractId('ab'));
        $this->assertSame(Pca::hashCanonical(Obj::of(['0' => 'é'])), Contracts::contractId('é'));
        $this->assertSame(Pca::hashCanonical(Obj::of(['0' => 'x'])), Contracts::contractId([5 => 'x']));
        try {
            Contracts::contractId("\u{1F600}");
            $this->fail('a non-BMP string got an id');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('canonicalize: lone surrogate in string', $e->getMessage());
        }
    }
}
