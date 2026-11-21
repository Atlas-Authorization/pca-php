<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The reference corpora are the contract: this pins, for every corpus in test-data/, the full set of functions and the number of cases of each. A replay
 * test builds its datasets from the corpus itself (a function the test does not map fails), so the function set is replayed in full; this inventory is what
 * makes a truncated, emptied or silently swapped corpus fail loudly (the Kotlin lane found tests quietly running a fraction of theirs), and what makes a new
 * corpus an explicit decision. CI-generated companions (`-gen`) are not committed and are pinned by their own replay tests. After an intended corpus
 * regeneration refresh the pin: PCA_UPDATE_CORPUS_INVENTORY=1 vendor/bin/phpunit --filter CorpusInventoryTest
 */
final class CorpusInventoryTest extends TestCase
{
    private const PIN = __DIR__ . '/corpus-inventory.json';

    /** @return array<string,array<string,int>> */
    private static function actual(): array
    {
        $out = [];
        $files = glob(__DIR__ . '/../test-data/*.json.gz') ?: [];
        sort($files);
        foreach ($files as $path) {
            $f = basename($path);
            if (str_ends_with($f, '-gen.json.gz')) {
                continue;
            }
            $n = [];
            foreach (gzfile($path) ?: [] as $line) {
                if (preg_match('/\A\{"fn":"((?:[^"\\\\]|\\\\.)*)"/', $line, $m) === 1) {
                    $fn = json_decode('"' . $m[1] . '"');
                    $n[$fn] = ($n[$fn] ?? 0) + 1;
                }
            }
            ksort($n);
            $out[$f] = $n;
        }
        return $out;
    }

    public function testEveryCorpusHasItsPinnedFunctionsAndCaseCounts(): void
    {
        $have = self::actual();
        if (getenv('PCA_UPDATE_CORPUS_INVENTORY') === '1') {
            file_put_contents(self::PIN, json_encode($have, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            $this->markTestSkipped('corpus inventory rewritten');
        }
        $pin = json_decode((string)file_get_contents(self::PIN), true, 512, JSON_THROW_ON_ERROR);
        ksort($pin);
        $this->assertSame(array_keys($pin), array_keys($have), 'the set of corpora changed (a new or removed corpus must be an explicit decision)');
        foreach ($pin as $file => $fns) {
            ksort($fns);
            $this->assertSame($fns, $have[$file], "$file: functions or case counts differ from the pinned inventory");
            $this->assertGreaterThan(0, array_sum($have[$file]), "$file is empty");
        }
    }
}
