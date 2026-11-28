#!/usr/bin/env python3
"""Patches to the CI copy of Infection 0.29 (python3 infection-patch.py <vendor/infection/infection>). Each one must apply exactly
once, else the job fails (a new Infection release is then re-checked by hand, never silently run unpatched).

1. XmlCoverageParser keys a file's method line ranges by the bare method name, so in a multi-class file a later class's
   same-named method (run, charge, __construct, get, ...) overwrites an earlier one, whose signature mutants are then reported
   "not covered" and never run: key the ranges by position (the lookup scans every range for the line, the key is unused).
2. --only-covering-test-cases builds one --filter regex of every covering test case. PCRE compiles at most 64 KiB of pattern
   and PHPUnit then matches nothing ("No tests executed!", which Infection counts as ESCAPED): above 15000 characters no filter
   is passed and every test of the covering files runs, as without the option. A test class with #[Depends] is selected
   whole (a dependent test whose dependency is filtered out is SKIPPED, and the mutant would escape it).
3. The mutant process limit follows the mutant's own measured covering-test time (the JUnit times of the coverage run):
   timeout/600 times it (3x at the configured 1800 s), at least timeout/10, at most the configured timeout, or 1.5x the measured
   time where that is longer. A loop that never ends then costs minutes instead of half an hour; a mutant still gets 3x what its
   tests took on the unmutated source.
4. Infection never runs ("time-skipped", listed nowhere) a mutant whose measured covering-test time is >= the timeout: with 3.
   every mutant has a limit above its measured time, so every mutant runs.
"""
import pathlib, sys

root = pathlib.Path(sys.argv[1])

def patch(rel, old, new):
    p = root / rel
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        sys.exit(f"::error::the Infection patch no longer applies: {rel} has {n} occurrence(s) of {old.strip()[:80]!r}")
    p.write_text(s.replace(old, new))

patch('src/TestFramework/Coverage/XmlReport/XmlCoverageParser.php',
      '$methodsCoverage[$methodName] = new SourceMethodLineRange(',
      '$methodsCoverage[] = new SourceMethodLineRange(')

patch('src/TestFramework/PhpUnit/CommandLine/ArgumentsAndOptionsBuilder.php',
      "                    $testCaseString = sprintf('%s::%s', $classNameWithoutNamespace, $methodNameWithDataProvider);\n",
      "                    $testCaseString = sprintf('%s::%s', $classNameWithoutNamespace, $methodNameWithDataProvider);\n"
      "                    static $dependsIn = [];\n"
      "                    $testFile = (string) $testLocation->getFilePath();\n"
      "                    $dependsIn[$testFile] ??= str_contains((string) @file_get_contents($testFile), '#[Depends');\n"
      "                    if ($dependsIn[$testFile]) {\n"
      "                        $testCaseString = $classNameWithoutNamespace . '::';\n"
      "                    }\n")
patch('src/TestFramework/PhpUnit/CommandLine/ArgumentsAndOptionsBuilder.php',
      "            $options[] = '--filter';\n            $options[] = $filterString;\n",
      "            if (strlen($filterString) <= 15000) {\n"
      "                $options[] = '--filter';\n"
      "                $options[] = $filterString;\n"
      "            }\n")

patch('src/Process/Factory/MutantProcessFactory.php',
      '            timeout: $this->timeout,\n',
      '            timeout: min(\n'
      '                max($this->timeout, 1.5 * $mutant->getMutation()->getNominalTestExecutionTime()),\n'
      '                max($this->timeout / 10, $this->timeout / 600 * $mutant->getMutation()->getNominalTestExecutionTime()),\n'
      '            ),\n')

patch('src/Process/Runner/MutationTestingRunner.php',
      'if ($mutant->getMutation()->getNominalTestExecutionTime() < $this->timeout) {',
      'if ($mutant->getMutation()->getNominalTestExecutionTime() < INF) {')
print('infection patched: method ranges, covering-test filter (cap, #[Depends]), per-mutant limit, no time-skip')
