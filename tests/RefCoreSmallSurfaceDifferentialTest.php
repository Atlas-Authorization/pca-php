<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Oauth;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyBuilder;
use Atlas\Pca\PolicyLink;
use Atlas\Pca\PolicyTemplates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/Oauth.php';
require_once __DIR__ . '/../src/PolicyLink.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

/** Discovery documents, the built-in policy templates, the policy builder and template links against the TS reference: test-data/ref-core-small-surface.json.gz (the other functions of the file are replayed elsewhere). */
final class RefCoreSmallSurfaceDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-small-surface.json.gz';
    private const FNS = ['parseDiscoveryDocument', 'parseDiscoveryIntent', 'acceptsSuite', 'buildDiscoveryDocument', 'fetchDiscovery', 'listTemplates', 'fromTemplate', 'policyBuilder',
        'createLink', 'slotsDigest', 'linkDigest', 'limits'];
    private const DOC = '{"audience":"https://rs.example","pca_versions":[2],"signature_suites":["ed25519","ml-dsa-65"],"action_header":"PCA-Action"}';

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => in_array($d[1], self::FNS, true));
    }

    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/small/tpl/' . $label, true));
    }

    private static function fetch(string $base, string $mode): Obj
    {
        $urls = [];
        $f = static function (string $url, array $headers) use (&$urls, $mode): array {
            $urls[] = $url . '|' . substr($headers[0], strlen('accept: '));
            if ($mode === 'throw') {
                throw new \RuntimeException('boom');
            }
            return ['ok' => $mode !== '500', 'status' => $mode === '500' ? 500 : 200, 'body' => $mode === 'bad' ? '{"nope":1}' : self::DOC];
        };
        try {
            return Obj::of(['doc' => Oauth::fetchDiscovery($base, $f), 'urls' => $urls]);
        } catch (\Throwable) {
            return Obj::of(['error' => true, 'urls' => $urls]);
        }
    }

    /** A corpus value as plain PHP: objects to arrays, numbers to int or float (OracleData::plain keeps a number as its lexeme string). */
    private static function nat(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::nat($v->get($k));
            }
            return $o;
        }
        if ($v instanceof \Atlas\Pca\Num) {
            $f = $v->float();
            return $f == floor($f) && abs($f) <= 9007199254740991.0 && !str_starts_with($v->lexeme, '-0') ? (int)$f : $f;
        }
        return is_array($v) ? array_map(self::nat(...), $v) : $v;
    }

    /** @return array<string,mixed> */
    private static function fromTemplate(string $name, mixed $overrides): array
    {
        try {
            $h = PolicyTemplates::fromTemplate($name, self::key('p'), 'g', null, self::key('h'), 1_700_000_000_000, $overrides === null ? [] : self::nat($overrides));
            return ['ok' => true, 'predicates' => $h->policy['predicates'], 'caveats' => $h->policy['caveats'], 'riskPolicy' => $h->policy['riskPolicy'], 'budgetModel' => $h->policy['budgetModel']];
        } catch (\Throwable) {
            return ['ok' => false];
        }
    }

    /** @return array<string,mixed> */
    private static function policyBuilder(array $ops): array
    {
        try {
            $b = PolicyTemplates::policy();
            foreach ($ops as $op) {
                if ($op[0] === 'from') {
                    $b = PolicyBuilder::from($op[1]);
                } elseif ($op[0] === 'allow') {
                    $b->allow($op[1], $op[2]);
                } elseif ($op[0] === 'limit') {
                    $b->limit($op[1], $op[2]);
                } else {
                    $b->risk(self::nat($op[1]));
                }
            }
            $p = $b->build();
            $built = ['permissions' => $p['permissions'], 'limits' => $p['limits'] === [] ? new Obj() : $p['limits']];
            if (isset($p['riskPolicy'])) {
                $built['riskPolicy'] = $p['riskPolicy'];
            }
            return ['ok' => true, 'built' => $built];
        } catch (\Throwable) {
            return ['ok' => false];
        }
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'parseDiscoveryDocument' => fn(array $a) => Oauth::parseDiscoveryDocument($a[0]),
            'parseDiscoveryIntent' => fn(array $a) => Oauth::parseDiscoveryIntent($a[0]),
            'acceptsSuite' => fn(array $a) => Oauth::acceptsSuite($a[0], $a[1]),
            'buildDiscoveryDocument' => fn(array $a) => Oauth::buildDiscoveryDocument($a[0]),
            'fetchDiscovery' => fn(array $a) => self::fetch($a[0], $a[1]),
            'listTemplates' => fn(array $a) => PolicyTemplates::listTemplates(),
            'fromTemplate' => fn(array $a) => self::fromTemplate($a[0], $a[1] ?? null),
            'policyBuilder' => fn(array $a) => self::policyBuilder($a[0]),
            'createLink' => function (array $a): array {
                try {
                    return ['ok' => true, 'ref' => PolicyLink::createLink($a[0], $a[1], ($a[2] ?? false) === true)];
                } catch (\Throwable) {
                    return ['ok' => false];
                }
            },
            'slotsDigest' => fn(array $a) => PolicyLink::slotsDigest($a[0]),
            'linkDigest' => fn(array $a) => PolicyLink::linkDigest($a[0]),
            'limits' => fn(array $a) => ['MAX_SLOTS' => PolicyLink::MAX_SLOTS, 'MAX_SLOT_STRING' => PolicyLink::MAX_SLOT_STRING, 'MAX_SLOT_SET' => PolicyLink::MAX_SLOT_SET,
                'TEMPLATE_KIND' => PolicyLink::TEMPLATE_KIND, 'TIGHTEN_KIND' => PolicyLink::TIGHTEN_KIND],
        ]);
    }
}
