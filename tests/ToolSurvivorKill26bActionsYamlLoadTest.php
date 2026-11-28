<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsYamlLoad as L;
use PHPUnit\Framework\TestCase;

/** The libyaml loader's candidates: the ATLAS_PCA_LIBYAML override (when non-empty) first, then the system names. */
final class ToolSurvivorKill26bActionsYamlLoadTest extends TestCase
{
    private const DEFAULTS = ['libyaml-0.so.2', 'libyaml.so.2', 'libyaml-0.2.dylib', 'libyaml.dylib', '/opt/homebrew/lib/libyaml.dylib', '/usr/local/lib/libyaml.dylib',
        'yaml.dll', 'libyaml-0-2.dll'];

    protected function tearDown(): void
    {
        L::$pathsHook = null;
    }

    /** A system name that loads here (the loader's own tests need one). */
    private static function realName(): string
    {
        foreach (self::DEFAULTS as $n) {
            try {
                \FFI::cdef('', $n);
                return $n;
            } catch (\Throwable) {
                // next
            }
        }
        self::fail('no libyaml on this host');
    }

    /**
     * Loads on a fresh loader with ATLAS_PCA_LIBYAML set to `$env`; the seam records the candidates and keeps only the entries before the
     * system names (the override). The loaded library and the env are restored after. @return array{0:list<string>,1:string} [candidates, outcome]
     */
    private static function fresh(string $env): array
    {
        $prop = new \ReflectionProperty(L::class, 'ffi');
        $saved = $prop->getValue();
        $old = getenv('ATLAS_PCA_LIBYAML');
        $seen = [];
        try {
            putenv('ATLAS_PCA_LIBYAML=' . $env);
            $prop->setValue(null, null);
            L::$pathsHook = static function (array $names) use (&$seen): array {
                $seen = $names;
                return array_slice($names, 0, count($names) - count(self::DEFAULTS));
            };
            try {
                L::parseDocument("a: 1\n");
                $outcome = 'loaded';
            } catch (\RuntimeException $e) {
                $outcome = $e->getMessage();
            }
            return [$seen, $outcome];
        } finally {
            L::$pathsHook = null;
            putenv($old === false ? 'ATLAS_PCA_LIBYAML' : 'ATLAS_PCA_LIBYAML=' . $old);
            $prop->setValue(null, $saved);
        }
    }

    public function testOverrideLoadsWhenSystemNamesAreMissing(): void
    {
        $real = self::realName();
        [$seen, $outcome] = self::fresh($real);
        self::assertSame([$real, ...self::DEFAULTS], $seen);
        self::assertSame('loaded', $outcome);
    }

    public function testEmptyOverrideIsNoCandidate(): void
    {
        [$seen, $outcome] = self::fresh('');
        self::assertSame(self::DEFAULTS, $seen);
        self::assertSame('YAML needs libyaml (apt install libyaml-dev / brew install libyaml)', $outcome);
    }
}
