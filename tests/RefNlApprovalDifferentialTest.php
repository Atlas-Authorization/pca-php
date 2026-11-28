<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/NlApproval.php';

use Atlas\Pca\Catalog;
use Atlas\Pca\KeyPair;
use Atlas\Pca\NlApproval;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The approval half of natural-language policy authoring against the TS reference: every case of test-data/ref-nl-approval.json.gz (the NL catalog digest,
 * the draft binding and digests, policy and draft from a model completion, v2 and legacy v1 approvals, loading with its rejection codes, minting an agent from an
 * approved draft: only the envelope's predicates, caveats, risk policy and agent binding are compared, the goal salt being random).
 * `extras` is null (the built-in catalog) or defineAction specs appended to the built-ins; the "model" is a fixed completion text ("THROWS": the completion throws).
 */
final class RefNlApprovalDifferentialTest extends TestCase
{
    private const FILE = 'ref-nl-approval.json.gz';
    private const FNS = ['constants' => 1, 'catalogDigest' => 3, 'draftBinding' => 6, 'draftDigest' => 7, 'draftDigestV2' => 10, 'policyFromNL' => 40, 'draftPolicyFromNL' => 42,
        'approveDraft' => 24, 'approveDraftLegacy' => 5, 'loadApproved' => 58, 'agentFromApproved' => 10];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function cat(mixed $extras): ?Catalog
    {
        if ($extras === null) {
            return null;
        }
        $out = Catalog::BUILTIN_ACTIONS;
        foreach ($extras as $e) {
            $out[] = Catalog::defineAction(Sign::plain($e));
        }
        return new Catalog($out);
    }

    private static function secret(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    private static function complete(string $raw): \Closure
    {
        return static function (string $prompt) use ($raw): string {
            if ($raw === 'THROWS') {
                throw new \RuntimeException('llm down');
            }
            return $raw;
        };
    }

    private static function loadOpts(mixed $o): Obj
    {
        $opts = new Obj();
        foreach ($o->keys() as $k) {
            $v = $o->get($k);
            $opts->set($k, $v instanceof Obj && $v->keys() === ['$num'] ? ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')] : $v); // a non-finite double
        }
        if ($o->has('extras')) {
            $c = self::cat($o->get('extras'));
            if ($c !== null) {
                $opts->set('catalog', $c);
            }
        }
        return $opts;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['NL_APPROVAL_DOMAIN' => NlApproval::DOMAIN, 'NL_APPROVAL_DOMAIN_V2' => NlApproval::DOMAIN_V2,
                'MAX_NL_OUTPUT_BYTES' => NlApproval::MAX_OUTPUT_BYTES, 'MAX_NL_APPROVAL_TTL_MS' => NlApproval::MAX_APPROVAL_TTL_MS],
            'catalogDigest' => static fn(array $a) => NlApproval::catalogDigest(self::cat($a[0])),
            'draftBinding' => static fn(array $a) => NlApproval::draftBinding($a[0], self::cat($a[1]), $a[2]),
            'draftDigest' => static fn(array $a) => NlApproval::draftDigest($a[0], $a[1], $a[2]),
            'draftDigestV2' => static fn(array $a) => NlApproval::draftDigestV2($a[0], $a[1], $a[2], $a[3]),
            'policyFromNL' => static fn(array $a) => NlApproval::policyFromNL($a[0], self::complete($a[1]), self::cat($a[2])),
            'draftPolicyFromNL' => static fn(array $a) => NlApproval::draftPolicyFromNL($a[0], self::complete($a[1]), self::cat($a[2]), $a[3]),
            'approveDraft' => static fn(array $a) => NlApproval::approveDraft($a[0], self::secret($a[1]), $a[2], (int) Base::clockMs(self::FILE)),
            'approveDraftLegacy' => static fn(array $a) => NlApproval::approveDraftLegacyV1($a[0], self::secret($a[1]), $a[2], (int) Base::clockMs(self::FILE)),
            'loadApproved' => static fn(array $a, Obj $c) => NlApproval::loadApproved($a[0], $a[1], self::loadOpts(Base::withClock(self::FILE, $c, $a[2])), (int) Base::clockMs(self::FILE)),
            'agentFromApproved' => static function (array $a) {
                $r = $a[0];
                $holder = $r->has('holderSeed') ? new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $r->get('holderSeed'), true)) : null;
                $res = NlApproval::agentFromApproved($r->get('draft'), $r->get('approval'), self::loadOpts($r->get('opts')),
                    new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $r->get('principalSeed'), true)), $r->get('goal'), $holder, $r->has('aud') ? $r->get('aud') : null);
                $env = null;
                foreach ($res['agent']->grant->get('caveats') as $cv) {
                    $env ??= $cv->get('type') === 'envelope' ? $cv : null;
                }
                return Obj::of(['reviewer' => $res['reviewer'], 'legacy_unbound_instruction' => $res['legacy_unbound_instruction'],
                    'envelope' => Obj::of(['predicates' => $env->get('predicates'), 'caveats' => $env->get('caveats'), 'risk_policy' => $env->get('risk_policy'),
                        'agent_binding' => $env->get('agent_binding')])]);
            },
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
