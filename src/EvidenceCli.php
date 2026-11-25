<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/EvidenceVerify.php';

/**
 * `pca-evidence`: the standalone replay verifier.
 *
 *   pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]
 *   pca-evidence digest <bundle.json>
 *
 * Exit codes: 0 consistent AND attributed (every signing session-root key is pinned in `principals`; unverified findings are listed but
 * do not fail); 1 at least one finding failed (wins over 3); 2 usage or parse error (including a malformed trust file); 3 consistent but
 * NOT attributed (no pinned principal keys: the bundle may be fabricated by whoever made its keys; `--allow-unpinned` exits 0 and prints
 * the keys to verify out of band). The trust file is JSON; ports (callables) cannot come from JSON: artifacts that need one are
 * reported as unverified.
 */
final class EvidenceCli
{
    private const USAGE = "usage: pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]\n       pca-evidence digest <bundle.json>";
    private const TRUST_KEYS = ['siteKeys', 'principals', 'sessionRootDigest', 'minTier', 'jitTier', 'typedValues', 'credentials', 'canaryLabels', 'oracleKeys',
        'judges', 'labelKeys', 'anchorGuardian', 'acc'];

    private static function readJson(string $path): mixed
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException("cannot read $path");
        }
        $text = file_get_contents($path);
        if ($text === false) {
            throw new \RuntimeException("cannot read $path");
        }
        return Json::parseStrict($text);
    }

    /** JSON.pretty_generate shape: two-space indent, empty containers as [] and {}. */
    private static function pretty(mixed $v, string $ind = ''): string
    {
        $in = $ind . '  ';
        if ($v instanceof Obj) {
            if ($v->keys() === []) {
                return '{}';
            }
            $parts = [];
            foreach ($v->keys() as $k) {
                $parts[] = $in . Js::stringify($k) . ': ' . self::pretty($v->get($k), $in);
            }
            return "{\n" . implode(",\n", $parts) . "\n$ind}";
        }
        if (is_array($v)) {
            if ($v === []) {
                return '[]';
            }
            return "[\n" . implode(",\n", array_map(static fn($x): string => $in . self::pretty($x, $in), $v)) . "\n$ind]";
        }
        return Js::stringify($v);
    }

    /**
     * Runs the command line (`$argv` without the program name); returns the exit code. `$out` / `$err` take one line of text.
     * @param list<string> $argv
     */
    public static function main(array $argv, ?callable $out = null, ?callable $err = null): int
    {
        $out ??= static function (string $s): void {
            fwrite(STDOUT, $s . "\n");
        };
        $err ??= static function (string $s): void {
            fwrite(STDERR, $s . "\n");
        };
        $cmd = $argv[0] ?? null;
        $rest = array_slice($argv, 1);
        if ($cmd !== 'verify' && $cmd !== 'digest') {
            $err(self::USAGE);
            return 2;
        }
        $file = null;
        $trustFile = null;
        $json = false;
        $allowUnpinned = false;
        for ($i = 0; $i < count($rest); $i++) {
            $a = $rest[$i];
            if ($a === '--json') {
                $json = true;
            } elseif ($a === '--allow-unpinned' && $cmd === 'verify') {
                $allowUnpinned = true;
            } elseif ($a === '--trust' && $cmd === 'verify') {
                $i++;
                $trustFile = $rest[$i] ?? null;
                if ($trustFile === null) {
                    $err(self::USAGE);
                    return 2;
                }
            } elseif (!str_starts_with($a, '--') && $file === null) {
                $file = $a;
            } else {
                $err(self::USAGE);
                return 2;
            }
        }
        if ($file === null) {
            $err(self::USAGE);
            return 2;
        }
        $trust = new Obj();
        try {
            $bundle = self::readJson($file);
            if ($trustFile !== null) {
                $t = self::readJson($trustFile);
                if (!($t instanceof Obj)) {
                    throw new \RuntimeException('trust file must be a JSON object');
                }
                foreach ($t->keys() as $k) {
                    if (!in_array($k, self::TRUST_KEYS, true)) {
                        throw new \RuntimeException("unknown trust member \"$k\"");
                    }
                }
                $ae = $t->has('acc') ? Evidence::accTrustError($t->get('acc')) : Evidence::accTrustError();
                if ($ae !== null) {
                    throw new \RuntimeException($ae);
                }
                $pe = $t->has('principals') ? Evidence::principalsTrustError($t->get('principals')) : Evidence::principalsTrustError();
                if ($pe !== null) {
                    throw new \RuntimeException($pe);
                }
                $trust = $t;
            }
        } catch (\Throwable $e) {
            $err('pca-evidence: ' . $e->getMessage());
            return 2;
        }
        if ($cmd === 'digest') {
            $bad = Evidence::bundleShapeError($bundle);
            if ($bad !== null) {
                $err("pca-evidence: $bad");
                return 2;
            }
            $out(Evidence::evidenceDigest($bundle));
            return 0;
        }
        $report = EvidenceVerify::verifyEvidenceBundle($bundle, $trust);
        $consistent = $report->get('consistent') === true;
        $unattributed = $consistent && $report->get('attributed') !== true;
        $keys = $report->get('summary')->get('attribution')->get('keys_to_check');
        if ($json) {
            $out(self::pretty($report));
        } else {
            $verdict = $report->get('ok') === true ? 'OK' : ($unattributed ? 'CONSISTENT BUT NOT ATTRIBUTED' : 'FAILED');
            $lines = ['bundle ' . ($report->get('digest') ?? '(malformed)') . ": $verdict" . ($report->get('complete') === true ? '' : ' (incomplete: some artifacts not verified here)')];
            foreach ($report->get('findings') as $x) {
                $lines[] = '[' . $x->get('status') . '] ' . $x->get('code') . ($x->get('refs') === [] ? '' : ' ' . implode(' ', $x->get('refs'))) . ': ' . $x->get('text');
            }
            $lines[] = 'Proven:';
            foreach ($report->get('summary')->get('proven') as $s) {
                $lines[] = "  - $s";
            }
            $lines[] = 'Not proven:';
            foreach ($report->get('summary')->get('not_proven') as $s) {
                $lines[] = "  - $s";
            }
            $lines[] = 'report ' . $report->get('report_digest');
            $out(implode("\n", $lines));
        }
        if (!$consistent) {
            return 1;
        }
        if ($unattributed) {
            if ($allowUnpinned) {
                $err('pca-evidence: principal keys to verify out of band: ' . implode(', ', $keys));
                return 0;
            }
            $err('pca-evidence: the bundle is internally consistent but NOT attributed to any known principal (no pinned "principals" in the trust file). '
                . 'Keys to verify out of band: ' . implode(', ', $keys) . '. Pass --allow-unpinned to accept anyway.');
            return 3;
        }
        return $report->get('ok') === true ? 0 : 1;
    }
}
