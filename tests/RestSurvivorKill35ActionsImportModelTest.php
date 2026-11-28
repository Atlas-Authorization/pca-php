<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsImportModel;
use Atlas\Pca\ModelAdapter;
use Atlas\Pca\ModelEnvConfig;
use Atlas\Pca\ModelHttpResponse;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the model-assisted trait suggestion. */
final class RestSurvivorKill35ActionsImportModelTest extends TestCase
{
    private static function adapter(string $id, \Closure $f): ModelAdapter
    {
        return new class ($id, $f) implements ModelAdapter {
            public function __construct(private string $i, private \Closure $f)
            {
            }

            public function id(): string
            {
                return $this->i;
            }

            public function version(): ?string
            {
                return null;
            }

            public function complete(Obj $req): mixed
            {
                return ($this->f)($req);
            }
        };
    }

    private static function def(string $title = 't', string $desc = 'd'): Obj
    {
        return Obj::of(['verb' => 'x.y', 'title' => $title, 'description' => $desc, 'effects' => ['read'], 'params' => new Obj()]);
    }

    private static function refusal(\Closure $f): string
    {
        try {
            $f();
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    /** Registry ids are strings even when PHP made a numeric key an int. */
    public function testVocabularyIdsAreStrings(): void
    {
        $this->assertSame(['5', 'pca.x'], ActionsImportModel::vocabulary(['5' => 1, 'pca.x' => 1, 'pca.unreviewed' => 1]));
    }

    /** The title is clipped to 120 bytes and the description to 300. */
    public function testRequestClips(): void
    {
        $u = ActionsImportModel::buildRequest(self::def(str_repeat('a', 121), str_repeat('b', 301)), [])->get('user');
        $this->assertStringContainsString("\nTitle: " . str_repeat('a', 120) . "\n", $u);
        $this->assertStringContainsString("\nDescription: " . str_repeat('b', 300) . "\n", $u);
    }

    /** A non-string completion is read as its JS string, never refused as an error. */
    public function testNonStringCompletionIsStringified(): void
    {
        $r = ActionsImportModel::suggestWithModels(self::def(), [self::adapter('m', static fn(): array => ['pca.bulk'])], ['pca.bulk' => 1]);
        $this->assertSame([], $r->get('errors'));
        $this->assertSame([], $r->get('models')[0]->get('traits'));
    }

    /** The output digest covers the first 65536 bytes of the completion only. */
    public function testOutputDigestClipsTheCompletion(): void
    {
        $dig = static fn(int $n): string => ActionsImportModel::suggestWithModels(self::def(), [self::adapter('m', static fn(): string => str_repeat('a', $n))], [])
            ->get('models')[0]->get('output_digest');
        $this->assertSame($dig(65536), $dig(65537));
        $this->assertNotSame($dig(65535), $dig(65536));
    }

    /** A failing adapter is recorded with its id clipped to 128 bytes and its error to 200. */
    public function testErrorsAreClipped(): void
    {
        $r = ActionsImportModel::suggestWithModels(self::def(), [self::adapter(str_repeat('i', 129), static function (): never {
            throw new \RuntimeException(str_repeat('e', 201));
        })], []);
        $e = $r->get('errors')[0];
        $this->assertSame([str_repeat('i', 128), str_repeat('e', 200)], [$e->get('model'), $e->get('error')]);
    }

    /** An unknown provider and a missing key are refused with their reasons. */
    public function testConfigRefusals(): void
    {
        $this->assertSame('unknown provider (one of anthropic, openai)', self::refusal(static fn() => ActionsImportModel::modelConfigFromEnv(['ATLAS_PCA_SUGGEST_PROVIDER' => 'x'])));
        $this->assertSame('ANTHROPIC_API_KEY is not set', self::refusal(static fn() => ActionsImportModel::modelConfigFromEnv(['ATLAS_PCA_SUGGEST_MODEL' => 'm1'])));
    }

    /** The provider adapter is named provider:model and POSTs with a 30 s default timeout. */
    public function testProviderAdapterRequest(): void
    {
        $seen = null;
        $fetch = static function (string $url, Obj $init) use (&$seen): ModelHttpResponse {
            $seen = $init;
            return new ModelHttpResponse(true, 200, static fn(): Obj => Obj::of(['content' => [Obj::of(['type' => 'text', 'text' => '[]'])]]));
        };
        $a = ActionsImportModel::providerAdapter(new ModelEnvConfig('anthropic', 'm1', 'k'), $fetch);
        $this->assertSame('anthropic:m1', $a->id());
        $this->assertSame('[]', $a->complete(ActionsImportModel::buildRequest(self::def(), [])));
        $this->assertSame('POST', $seen->get('method'));
        $this->assertSame('30000', $seen->get('timeout_ms')->lexeme);
    }
}
