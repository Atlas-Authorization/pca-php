<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PolicyCi;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The policy-safety CI gate against the TS reference: test-data/ref-policy-ci.json.gz (normalization of every accepted input shape,
 * the lint rules over the analyzer, summary and exit codes, the pinned lint-rule digest, the authoring gates and the command line)
 * plus ref-policy-ci-java-extra.json.gz (schema, test and coverage cases). The command line runs against small files in a
 * temporary directory.
 */
final class RefPolicyCiDifferentialTest extends TestCase
{
    private const FILES = ['ref-policy-ci.json.gz', 'ref-policy-ci-java-extra.json.gz'];

    public static function provide(): array
    {
        $out = [];
        foreach (self::FILES as $f) {
            foreach (Base::datasets($f) as $name => $d) {
                $out["$f $name"] = $d;
            }
        }
        return $out;
    }

    /** Write each member of `files` (name => text) into a fresh directory, run the command line there, return {code, lines}. */
    private static function runCli(Obj $spec): Obj
    {
        $prev = getcwd();
        $dir = sys_get_temp_dir() . '/pci-' . bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        $files = $spec->get('files');
        foreach ($files->keys() as $name) {
            file_put_contents($dir . '/' . $name, $files->get($name));
        }
        $lines = [];
        try {
            chdir($dir);
            $code = PolicyCi::run($spec->get('argv'), static function (string $s) use (&$lines): void {
                $lines[] = $s;
            });
        } finally {
            chdir($prev);
            foreach ($files->keys() as $name) {
                @unlink($dir . '/' . $name);
            }
            @rmdir($dir);
        }
        return Obj::of(['code' => $code, 'lines' => $lines]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'normalizePolicyInput' => fn(array $a) => PolicyCi::normalizePolicyInput(...$a),
            'normalizeChain' => fn(array $a) => PolicyCi::normalizeChain(...$a),
            'isCapability' => fn(array $a) => PolicyCi::isCapability(...$a),
            'isEnvelope' => fn(array $a) => PolicyCi::isEnvelope(...$a),
            'lintPolicy' => fn(array $a) => PolicyCi::lintPolicy(...$a),
            'lintChain' => fn(array $a) => PolicyCi::lintChain(...$a),
            'lint' => fn(array $a) => PolicyCi::lint(...$a),
            'lintPolicies' => fn(array $a) => PolicyCi::lintPolicies(...$a),
            'summarize' => fn(array $a) => PolicyCi::summarize(...$a),
            'checkLintRulesPin' => fn(array $a) => PolicyCi::checkLintRulesPin(...$a),
            'toAnalyzerPolicy' => fn(array $a) => PolicyCi::toAnalyzerPolicy(...$a),
            'diffCommand' => fn(array $a) => PolicyCi::diffCommand(...$a),
            'testCommand' => fn(array $a) => PolicyCi::testCommand(...$a),
            'coverageCommand' => fn(array $a) => PolicyCi::coverageCommand(...$a),
            'parseArgs' => fn(array $a) => PolicyCi::parseArgs(...$a),
            'run' => fn($a) => self::runCli($a),
        ]);
    }
}
