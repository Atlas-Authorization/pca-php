<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\ActionsHosted;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsHosted.php';
require_once __DIR__ . '/../src/ActionsBuiltin.php';

/** The hosted action registry (publish gate, verifier view, grant facts, call context, rate keys) against the TS reference: test-data/ref-actions-hosted-py.json.gz. */
final class RefActionsHostedDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-hosted-py.json.gz';
    private const GRANTS = [
        ['caveats' => [], 'max_esc' => 3, 'preauth_esc' => 0],
        ['caveats' => ['amount_cap', 'window', 'bogus'], 'max_esc' => 3, 'preauth_esc' => 3],
        ['caveats' => ['amount_cap', 'count_cap', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'], 'max_esc' => 1, 'preauth_esc' => 1],
        ['caveats' => [], 'max_esc' => 0, 'preauth_esc' => 0],
    ];
    private const CTXS = [[], ['fresh_revocation'], ['fresh_revocation', 'idempotency', 'approval_ref', 'revocable', 'dry_run_first']];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** One example call of a def: a value for every required parameter. */
    private static function sample(Obj $d): Obj
    {
        $out = new Obj();
        foreach ($d->get('params')->keys() as $k) {
            $p = $d->get('params')->get($k);
            if ($p->get('required') === false) {
                continue;
            }
            $role = $p->get('role');
            $t = $p->get('type');
            $out->set($k, is_string($role) && str_starts_with($role, 'id.') ? 'abc12345' : ($t === 'integer' ? new Num('7') : ($t === 'boolean' ? true
                : ($p->get('values') ? $p->get('values')[0] : ($t === 'array' ? ['x'] : ($t === 'set' ? [] : ($t === 'datetime' ? '2030-01-01T00:00:00Z' : 'val')))))));
        }
        return $out;
    }

    /** The fixed probe of the reference generator: lookups, provenance, floors and undo plans for the first 6 defs plus the 7th of the pack set. */
    private static function probe(array $versions, mixed $pins): array
    {
        $all = ActionsBuiltin::corePackDefs();
        $defs = array_merge(array_slice($all, 0, 6), [$all[6]]);
        $verbs = array_merge(array_map(static fn(Obj $d) => $d->get('verb'), array_slice($all, 0, 6)), [$all[6]->get('verb'), 'unknown.verb']);
        $v = ActionsHosted::hostedView($versions, $pins);
        $floors = [];
        foreach ($verbs as $x) {
            foreach (self::GRANTS as $g) {
                foreach (self::CTXS as $c) {
                    $floors[] = $v->floor($x, $g, $c);
                }
            }
        }
        return [
            'versions' => $v->versions,
            'lookups' => array_map(static fn($x) => $v->lookup($x), $verbs),
            'prov' => array_map(static fn($x) => $v->provenance(Obj::of(['verb' => $x])), $verbs),
            'floors' => $floors,
            'undo' => array_map(fn(Obj $d) => $v->undoPlan(Obj::of(['verb' => $d->get('verb'), 'params' => self::sample($d)])), $defs),
        ];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'publishGate' => fn(array $a) => ActionsHosted::publishGate($a[0]),
            'hostedVersionDigest' => fn(array $a) => ActionsHosted::hostedVersionDigest($a[0]),
            'rulesDocError' => fn(array $a) => ActionsHosted::rulesDocError($a[0], $a[1], $a[2]),
            'registryOfTraits' => fn(array $a) => ['digest' => Actions::traitsDigest(ActionsHosted::registryOfTraits($a[0]))],
            'hostedView' => fn(array $a) => self::probe($a[0], $a[1]),
            'grantFactsOf' => fn(array $a) => ActionsHosted::grantFactsOf($a[0]),
            'hostedCallContext' => fn(array $a) => ActionsHosted::hostedCallContext($a[0], $a[1]),
            'rateKeysOf' => fn(array $a) => ActionsHosted::rateKeysOf($a[0], $a[1]),
        ]);
    }
}
