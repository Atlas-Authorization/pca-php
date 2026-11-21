<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsImportModel;
use Atlas\Pca\ActionsImportSuggest;
use Atlas\Pca\ModelAdapter;
use Atlas\Pca\ModelEnvConfig;
use Atlas\Pca\ModelHttpResponse;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImportSuggest.php';
require_once __DIR__ . '/../src/ActionsImportModel.php';

/** A model adapter built from a corpus spec {id, version?, answer?, throws?}. */
final class SpecAdapter implements ModelAdapter
{
    public function __construct(private readonly Obj $spec)
    {
    }

    public function id(): string
    {
        return $this->spec->get('id');
    }

    public function version(): ?string
    {
        return is_string($this->spec->get('version')) ? $this->spec->get('version') : null;
    }

    public function complete(Obj $req): mixed
    {
        if ($this->spec->has('throws')) {
            throw new \RuntimeException($this->spec->get('throws'));
        }
        return $this->spec->get('answer');
    }
}

/** The suggestion rules (validation, digest, signature, matching, application), the model assist and the provider adapters against the TS reference: test-data/ref-actions-import-suggest.json.gz. */
final class RefActionsImportSuggestDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-import-suggest.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function rules(mixed $x): mixed
    {
        return $x === 'default' ? ActionsImportSuggest::defaultRules() : $x;
    }

    /** @return array<string,mixed> */
    private static function reg(mixed $x): ?array
    {
        return $x === 'core' ? Actions::coreRegistry() : null;
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function provider(Obj $cfg, Obj $spec, Obj $req): Obj
    {
        $calls = [];
        $fetch = function (string $url, Obj $init) use (&$calls, $spec): ModelHttpResponse {
            $calls[] = Obj::of(['url' => $url, 'headers' => $init->get('headers'), 'body' => $init->get('body')]);
            if ($spec->has('throws')) {
                throw new \RuntimeException($spec->get('throws'));
            }
            return new ModelHttpResponse($spec->has('ok') ? $spec->get('ok') : true, $spec->has('status') ? $spec->get('status')->int() : 200, function () use ($spec) {
                if ($spec->get('badjson') === true) {
                    throw new \RuntimeException('bad json');
                }
                return $spec->get('json');
            });
        };
        $a = ActionsImportModel::providerAdapter(new ModelEnvConfig($cfg->get('provider'), $cfg->get('model'), $cfg->get('apiKey')), \Closure::fromCallable($fetch));
        try {
            return Obj::of(['call' => null, 'text' => $a->complete($req)]);
        } catch (\Throwable $e) {
            return Obj::of(['call' => $calls[0] ?? null, 'error' => $e->getMessage()]);
        }
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'stem' => fn(array $a) => ActionsImportSuggest::stem($a[0]),
            'factsOf' => fn(array $a) => ActionsImportSuggest::factsOf($a[0]),
            'DEFAULT_RULES' => fn(array $a) => ActionsImportSuggest::defaultRules(),
            'DEFAULT_RULES_SEALED_DIGEST' => fn(array $a) => ActionsImportSuggest::defaultRulesSealed()->get('digest'),
            'suggestRulesError' => fn(array $a) => ActionsImportSuggest::suggestRulesError(self::rules($a[0]), $a[1] ?? null),
            'rulesDigest' => fn(array $a) => ActionsImportSuggest::rulesDigest(self::rules($a[0])),
            'sealRules' => fn(array $a) => ActionsImportSuggest::sealRules($a[0]),
            'signRules' => fn(array $a) => ActionsImportSuggest::signRules($a[0], $a[1], self::seed($a[2])),
            'verifyRules' => fn(array $a) => ActionsImportSuggest::verifyRules($a[0], $a[1]),
            'suggestWithRules' => fn(array $a) => ActionsImportSuggest::suggestWithRules($a[0], self::rules($a[1]), self::reg($a[2] ?? null)),
            'applySuggestion' => fn(array $a) => ActionsImportSuggest::applySuggestion($a[0], $a[1], $a[2]),
            'unionSuggestions' => fn(array $a) => ActionsImportSuggest::unionSuggestions($a[0], $a[1]),
            'vocabulary' => fn(array $a) => ActionsImportModel::vocabulary(self::reg($a[0]) ?? $core),
            'promptDigest' => fn(array $a) => ActionsImportModel::promptDigest(self::reg($a[0]) ?? $core),
            'buildRequest' => fn(array $a) => ActionsImportModel::buildRequest($a[0], $core),
            'parseTraitList' => fn(array $a) => ActionsImportModel::parseTraitList($a[0], $core),
            'suggestWithModels' => fn(array $a) => ActionsImportModel::suggestWithModels($a[0], array_map(fn($s) => new SpecAdapter($s), $a[1]), $core),
            'modelConfigFromEnv' => fn(array $a) => ActionsImportModel::modelConfigFromEnv($a[0], $a[1])->toObj(),
            'providerAdapterComplete' => fn(array $a) => self::provider($a[0], $a[1], $a[2]),
        ]);
    }

    public function testTheShippedRulesVersionConstantMatchesTheData(): void
    {
        self::assertSame(ActionsImportSuggest::DEFAULT_RULES_VERSION, ActionsImportSuggest::defaultRules()->get('version'));
        self::assertNull(ActionsImportSuggest::suggestRulesError(ActionsImportSuggest::defaultRules()));
    }

    public function testAConfigNeverShowsItsKey(): void
    {
        $c = ActionsImportModel::modelConfigFromEnv(Obj::of(['ANTHROPIC_API_KEY' => 'sk-secret']), Obj::of(['model' => 'claude-x']));
        self::assertStringNotContainsString('sk-secret', print_r($c, true));
        self::assertStringNotContainsString('sk-secret', var_export($c->toObj(), true));
        $this->expectException(\LogicException::class);
        serialize($c);
    }
}
