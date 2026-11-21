<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The policy analyzer's single entry point: every public static function of the analyzer areas (core queries, exposure, coverage,
 * residual, narrowing, validation) is callable as `Analyzer::name(...)`. A call goes to the first area that defines a public static
 * method of that name; an area's file is loaded on first use.
 */
final class Analyzer
{
    private const AREAS = ['AnalyzerCore', 'AnalyzerExposure', 'AnalyzerCoverage', 'AnalyzerResidual', 'AnalyzerNarrowing', 'AnalyzerValidate'];

    /** @param list<mixed> $args */
    public static function __callStatic(string $name, array $args): mixed
    {
        foreach (self::AREAS as $area) {
            $file = __DIR__ . '/' . $area . '.php';
            if (!file_exists($file)) {
                continue;
            }
            require_once $file;
            $cls = __NAMESPACE__ . '\\' . $area;
            if (!class_exists($cls, false) || !method_exists($cls, $name)) {
                continue;
            }
            $m = new \ReflectionMethod($cls, $name);
            if ($m->isPublic() && $m->isStatic()) {
                return $m->invokeArgs(null, $args);
            }
        }
        throw new \BadMethodCallException('Unknown analyzer function ' . $name);
    }
}
