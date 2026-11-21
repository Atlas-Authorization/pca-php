<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionSchemaDraft.php';
require_once __DIR__ . '/../src/SignersMore.php';

use Atlas\Pca\ActionSchemaDraft;
use Atlas\Pca\IntentSchema;
use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentV2Schema;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\SignersMore;
use Atlas\Pca\Undef;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The action schema beyond the shared base corpora, against the TS reference: every case of test-data/ref-action-schema.json.gz (the constants, value-dependent
 * reversibility, the wallet floor test, the signing / key / digest / verification quartet under three suites, the MCP reversibility hints and the two drafting
 * importers with their todo lists, in order) and of ref-action-schema-draft.json.gz (the OpenAPI drafting corpus). A regex constant is `{"$regex": source}`.
 */
final class RefActionSchemaDifferentialTest extends TestCase
{
    private const FILE = 'ref-action-schema.json.gz';
    private const DRAFT = 'ref-action-schema-draft.json.gz';
    private const FNS = ['constants' => 1, 'reversibilityOf' => 20, 'floorApplies' => 19, 'schemaVerb' => 9, 'signActionSchema' => 12, 'actionSchemaKeyOf' => 6, 'actionSchemaDigest' => 4,
        'verifyActionSchema' => 30, 'reversibilityFromMcpHints' => 9, 'draftSchemaFromMcpTools' => 31, 'draftSchemaFromOpenApi' => 32];
    private const DRAFT_FNS = ['draftSchemaFromOpenApi' => 16, 'reversibilityFromMcpHints' => 9, 'reversibilityOf' => 72, 'schemaVerb' => 7];

    public static function provide(): array
    {
        $out = Base::datasets(self::FILE);
        foreach (Base::datasets(self::DRAFT) as $k => $v) {
            $out["draft $k"] = $v;
        }
        return $out;
    }

    private static function secret(mixed $v): string
    {
        $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? $v->get('$bytes') : $v;
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true);
    }

    /** @return array{0: ?string, 1: ?PqKeyPair} */
    private static function suite(mixed $su): array
    {
        if (!($su instanceof Obj)) {
            return [null, null];
        }
        return [$su->get('alg'), $su->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::secret($su->get('pqSeed'))) : null];
    }

    private static function re(string $pcre): Obj
    {
        return Obj::of(['$regex' => preg_replace(['/\A\/\\\\A/', '/\\\\z\/\z/'], ['^', '$'], $pcre)]);
    }

    /** `{"$regex": ...}` aside, the strings of a refusal that carry library text are compared by prefix. */
    private static function mask(mixed $x): mixed
    {
        if (is_string($x)) {
            return preg_replace(['/\Aschema verification error:.*\z/s', '/\Amalformed schema: canonical.*\z/s'], ['schema verification error:', 'malformed schema: canonicalization'], $x);
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::mask($x->get($k)));
            }
            return $o;
        }
        return is_array($x) ? array_map(self::mask(...), $x) : $x;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => [
                'ACTION_SCHEMA_DOMAIN' => IntentV2::ACTION_SCHEMA_DOMAIN, 'ACTION_SCHEMA_KIND' => IntentV2::ACTION_SCHEMA_KIND, 'ACTION_SCHEMA_REF_DOMAIN' => IntentV2::ACTION_SCHEMA_REF_DOMAIN,
                'DEFAULT_MAX_ITEMS' => IntentV2::DEFAULT_MAX_ITEMS, 'DEFAULT_MAX_LEN' => IntentV2::DEFAULT_MAX_LEN, 'MAX_SCHEMA_PARAMS' => IntentV2::MAX_SCHEMA_PARAMS,
                'MAX_SCHEMA_VALUES' => IntentV2::MAX_SCHEMA_VALUES, 'MAX_SCHEMA_VERBS' => IntentV2::MAX_SCHEMA_VERBS, 'PARAM_PATH_RE' => self::re(IntentV2::PARAM_PATH_RE),
                'PARAM_PATH_RE_V2' => self::re(IntentV2::PARAM_PATH_RE_V2), 'PARAM_TYPES' => IntentV2::PARAM_TYPES, 'PARAM_TYPES_V2' => IntentV2::PARAM_TYPES_V2,
                'SCHEMA_REVERSIBILITY' => IntentV2::SCHEMA_REVERSIBILITY, 'SCHEMA_V2_CAVEATS' => IntentV2::SCHEMA_V2_CAVEATS, 'SCHEMA_V2_CONTEXT' => IntentV2::SCHEMA_V2_CONTEXT,
                'SCHEMA_V2_EFFECTS' => IntentV2::SCHEMA_V2_EFFECTS, 'SCHEMA_V2_PROVENANCE' => IntentV2::SCHEMA_V2_PROVENANCE, 'SCHEMA_V2_PRULES' => IntentV2::SCHEMA_V2_PRULES,
                'SCHEMA_V2_TAGS' => IntentV2::SCHEMA_V2_TAGS, 'SENSITIVITIES' => IntentV2::SENSITIVITIES, 'UNIT_ID_RE' => self::re(IntentV2::UNIT_ID_RE),
                'WALLET_FLOOR_EXACT' => IntentSchema::WALLET_FLOOR_EXACT, 'WALLET_FLOOR_PREFIXES' => IntentSchema::WALLET_FLOOR_PREFIXES,
                'WELL_KNOWN_PCA_ACTIONS_PATH' => ActionSchemaDraft::WELL_KNOWN_PCA_ACTIONS_PATH,
            ],
            'reversibilityOf' => static fn(array $a) => ActionSchemaDraft::reversibilityOf($a[0], $a[1]),
            'floorApplies' => static fn(array $a) => ActionSchemaDraft::floorApplies($a[0], $a[1]),
            'schemaVerb' => static function (array $a) {
                $v = IntentV2::schemaVerb($a[0], $a[1]);
                return $v instanceof Undef || $v === IntentV2::undef() ? null : $v;
            },
            'signActionSchema' => static function (array $a) {
                [$alg, $pq] = self::suite($a[3]);
                return SignersMore::signActionSchema($a[0], $a[1], new KeyPair(self::secret($a[2])), $alg, $pq);
            },
            'actionSchemaKeyOf' => static function (array $a) {
                [$alg, $pq] = self::suite($a[2]);
                return SignersMore::actionSchemaKeyOf($a[0], new KeyPair(self::secret($a[1])), $alg, $pq);
            },
            'actionSchemaDigest' => static fn(array $a) => IntentV2::actionSchemaDigest($a[0]),
            'verifyActionSchema' => static function (array $a, Obj $c) {
                $c->set('out', self::mask($c->get('out')));
                return self::mask(IntentV2::verifyActionSchema($a[0], $a[1]));
            },
            'reversibilityFromMcpHints' => static fn(array $a) => ActionSchemaDraft::reversibilityFromMcpHints($a[0]),
            'draftSchemaFromMcpTools' => static fn(array $a) => ActionSchemaDraft::draftSchemaFromMcpTools($a[0], $a[1]),
            'draftSchemaFromOpenApi' => static fn(array $a) => ActionSchemaDraft::draftSchemaFromOpenApi($a[0], $a[1]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        foreach ([self::FILE => self::FNS, self::DRAFT => self::DRAFT_FNS] as $file => $fns) {
            $have = array_fill_keys(array_keys($fns), 0);
            foreach (gzfile(Base::path($file)) as $line) {
                foreach ($have as $fn => $_) {
                    $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
                }
            }
            $this->assertSame($fns, $have, $file);
        }
    }
}
