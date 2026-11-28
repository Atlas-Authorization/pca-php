<?php
declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\InvariantsArbitraries;
use Atlas\Pca\InvariantsProps;
use Atlas\Pca\InvariantsRng;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/InvariantsProps.php';

/**
 * Pins every invariant generator to its exact output for fixed mulberry32 seeds. Each digest is the sha256 of, per seed, the
 * generated value in a canonical rendering plus the bits of the stream's next draw (so an extra or missing draw also shows),
 * joined by newlines. The expected digests come from an independent port of the RNG and the generators.
 */
final class LintSurvivorKill22InvariantsArbitrariesTest extends TestCase
{
    /** Canonical rendering: Obj {k:v}, list [..], assoc <k:v>, Num/float as IEEE bits, string as hex, int i<n>, bool T/F, null N. */
    private static function ser(mixed $v): string
    {
        if ($v instanceof Obj) {
            $p = [];
            foreach ($v->keys() as $k) {
                $p[] = $k . ':' . self::ser($v->get($k));
            }
            return '{' . implode(',', $p) . '}';
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return '[' . implode(',', array_map(self::ser(...), $v)) . ']';
            }
            $p = [];
            foreach ($v as $k => $x) {
                $p[] = $k . ':' . self::ser($x);
            }
            return '<' . implode(',', $p) . '>';
        }
        if ($v instanceof Num) {
            return 'n' . bin2hex(pack('E', $v->float()));
        }
        if (is_bool($v)) {
            return $v ? 'T' : 'F';
        }
        if ($v === null) {
            return 'N';
        }
        if (is_string($v)) {
            return '"' . bin2hex($v) . '"';
        }
        if (is_int($v)) {
            return 'i' . $v;
        }
        if (is_float($v)) {
            return 'f' . bin2hex(pack('E', $v));
        }
        throw new \LogicException('unrenderable ' . get_debug_type($v));
    }

    /** @param iterable<int> $seeds */
    private static function digest(\Closure $gen, iterable $seeds): string
    {
        $parts = [];
        foreach ($seeds as $s) {
            $g = new InvariantsRng($s);
            $v = $gen($g);
            $parts[] = self::ser($v) . '|f' . bin2hex(pack('E', $g->next()));
        }
        return hash('sha256', implode("\n", $parts));
    }

    private static function priv(string $m): \ReflectionMethod
    {
        return new \ReflectionMethod(InvariantsArbitraries::class, $m);
    }

    public function testEveryPublicGeneratorIsPinnedForSeedsOneToForty(): void
    {
        $expect = [
            'seed32' => 'e1b0a5eae66b31b393c54548c4faf0b0cf1e0535e9dc046476ecb62ed9dc933f',
            'verb' => 'cb8ee63d5d97dfd4159d315e0e6be15fffafeaafe6db1309c1c3e37eb437644f',
            'resource' => 'f1d9d08e872577af01b4f1ca160c9d6e0d183c0800a4fb382b3a1c004b077641',
            'leafCondition' => '6ef4987cf4e39acda60a24e43250e21673453fab22d1c59c6c11cc2b2347b395',
            'predicate' => 'a8fb2cd5e1b20c2a51f8b36ebaadb2338fec66e83914a1fa53a3c1e8c89edd2c',
            'predicateList' => '03a8a5a969bf953f17b0cecc40ed2bcfc95ee13d15d065c6f9e12bbb3db17f5f',
            'actionContext' => '25a957d9fd315e7d89f01462697bdf76110186ad1ea8d7710ac5c110d9c9ab90',
            'caveatContext' => '22a94549bd2a7aeca665eec69e579b157b56d22af308f61b324538a4e117e815',
            'evalPoint' => '98f3e56089da643104bbc897694cf8a62d1b2b9ad02f1af84da7566b4560a3e0',
            'caveatSpec' => 'd16044e8ef4b94611477290f245be1ecf92bf828126faab4f2998228b43549bc',
            'chainModel' => 'cb085add71182d0eeeed93bb1e18a75fb29c25363d34e176d37efa61f4bb245e',
            'riskPolicy' => '44dd5545a0abd5ddc84dd5022153f782b1e5af2ea2ae2298ff905890b79369bf',
            'riskInputs' => '5c4eca379511ec29447c995a6c75d4fc54f8f5a6795cd205d61f28d99a53041b',
            'trustBudget' => '0e5d176b8ccac42413634a43b98234c499dbe38fd986e4310d2f4ab85bdd7a9d',
            'riskDeltas' => 'c8239e4c2e0ea218d28357ae7560ec0296f9a62033c3d0124b09c843f5bc0d78',
        ];
        foreach ($expect as $name => $hex) {
            // called from outside the class, so a generator made non-public fails here too
            $gen = static fn(InvariantsRng $g): mixed => InvariantsArbitraries::$name($g);
            $this->assertSame($hex, self::digest($gen, range(1, 40)), $name);
        }
    }

    public function testTheOneValueRenderingsAreReadable(): void
    {
        $this->assertSame('transfer', InvariantsArbitraries::verb(new InvariantsRng(1)));
        $spec = InvariantsArbitraries::caveatSpec(new InvariantsRng(1));
        $this->assertSame(['k', 'cls'], $spec->keys());
        $this->assertSame('reversibility_max', $spec->get('k'));
        $this->assertSame('reversible', $spec->get('cls'));
    }

    public function testThePrivateListBuildersArePinned(): void
    {
        $strings = self::priv('strings');
        $verbs = self::priv('verbs');
        $specs = self::priv('specs');
        $this->assertSame('2596102cf065f621241c731d1d765b3de23252c27039b03674e6b7ac6290d6e5',
            self::digest(static fn(InvariantsRng $g): array => $strings->invoke(null, $g, 0, 3), range(1, 40)));
        $this->assertSame('5dd23dd032ef9fec8cbd38a341b20024b9daa7577d92c4e8e1be115ba45c128f',
            self::digest(static fn(InvariantsRng $g): array => $verbs->invoke(null, $g), range(1, 40)));
        $this->assertSame('f984c16c7d5c0c032cb87a39cabfb0918d5e285eb2998f13bdf8a4000209c72c',
            self::digest(static fn(InvariantsRng $g): array => $specs->invoke(null, $g, 0, 3), range(1, 40)));
    }

    public function testEveryRegisteredCaseGeneratorIsPinned(): void
    {
        $expect = [
            '8c8d9c4c78818ae028598563a3bd5e19aba95f82ce374232696901e76f4e8a21',
            '14bbd1e8b672ca3a2a9350f44b38416cce234700a2dcf54129c27da27cdd79c4',
            '0c9e6878b6d6a195d125099c845f324baccb363878968873ec46d377fb95b782',
            '91aa0140beae5aad6aed81e73fe7d3cb02d8390c417d943e9ddabf3225d48240',
            'eee10186d8801afbbbe3669b9549446fcb17684a56833a9596e1e8bf22f309a0',
            '1b0bfd56e4b02d441555a5234cdf3b39a801be28ac4a953ff20dee21fe9ea441',
            'ea4a85b498bfc0f945dae11b68584469f7ac27fa03b33cea135b8b0c99eb7d1c',
            '5f5f2a52a23a01ce7dc410085c07339b3d297e27779afbba389ace5969541426',
            'caf3726d05afe41f7e59df74ec73def3c1a70431211ffdba9d0d4527c076f67b',
            'e891b43f2fd34c72ab5fbd4b40919e6509f48a7361d4551485240324b612c938',
            'e1fec52b1910fc360b5b82ee59078e640482362285a96a850e9cae7637ae340f',
            '30432228afa417c3e0edeb663cf22221277d3453d496f7f4b4f87f0dfb871762',
        ];
        $registry = (new \ReflectionMethod(InvariantsProps::class, 'registry'))->invoke(null);
        $this->assertCount(12, $registry);
        foreach ($registry as $i => $p) {
            $this->assertSame($expect[$i], self::digest($p['gen'], range(1, 15)), $p['name']);
        }
    }

    public function testTheUnknownCaveatTypeGeneratorRedrawsAKnownType(): void
    {
        // the first string this seed draws is exactly "rate", a known caveat type, so the generator must draw again
        $this->assertSame('rate', (new InvariantsRng(235529672))->string(1, 12));
        $registry = (new \ReflectionMethod(InvariantsProps::class, 'registry'))->invoke(null);
        $args = $registry[7]['gen'](new InvariantsRng(235529672));
        $this->assertSame(['XtJe', 4095022], $args);
    }
}
