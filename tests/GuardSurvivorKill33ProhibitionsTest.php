<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Prohibitions.php: validateWhen renders its label as a JS template literal would. */
final class GuardSurvivorKill33ProhibitionsTest extends TestCase
{
    public function testLabelRendering(): void
    {
        foreach ([['abc', 'abc'], [null, 'null'], [true, 'true'], [false, 'false'], [new Num('1.5'), '1.5'], [new Num('-0'), '0'],
                  [3, '3'], [2.5, '2.5'], [-0.0, '0']] as [$label, $text]) {
            $this->assertSame("$text: not an object", Prohibitions::validateWhen(5, $label));
        }
    }

    public function testAnyOtherLabelIsATypeError(): void
    {
        try {
            Prohibitions::validateWhen(5, new Obj());
            $this->fail('an object label was rendered');
        } catch (\TypeError $e) {
            $this->assertSame('validateWhen: label must be a string', $e->getMessage());
        }
    }
}
