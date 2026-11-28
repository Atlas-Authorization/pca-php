<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsAuthor;
use Atlas\Pca\ActionsYamlLoad;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsAuthor.php';

/**
 * loadActionsText when libyaml cannot be used. ATLAS_PCA_LIBYAML only prepends a candidate (the fixed sonames and Homebrew paths are
 * always tried after it), so the seam is the loader cache: an FFI handle that declares nothing makes every libyaml call fail with a
 * non-YAML error, exactly as a missing library does; without ext-ffi the real loader refuses on its own.
 */
final class SchemaSurvivorKill12bAuthorTest extends TestCase
{
    private const DOC = '{"ns":"acme","actions":[{"verb":"acme.note.read","effects":["read"],"resource":"acme.note"}]}';

    /** Run $f with the libyaml handle replaced by one that cannot parse; returns [$f(), the error libyaml use raises]. */
    private static function withoutLibyaml(callable $f): array
    {
        $prop = new \ReflectionProperty(ActionsYamlLoad::class, 'ffi');
        $saved = $prop->getValue();
        try {
            if (extension_loaded('FFI')) {
                $empty = \FFI::cdef('');
                $prop->setValue(null, $empty);
                try {
                    $empty->new('yaml_parser_alloc_t');
                    $why = '';
                } catch (\Throwable $e) {
                    $why = $e->getMessage();
                }
            } else {
                $prop->setValue(null, null);
                $why = 'YAML needs ext-ffi and libyaml (apt install libyaml-dev / brew install libyaml)';
            }
            return [$f(), $why];
        } finally {
            $prop->setValue(null, $saved);
        }
    }

    /** YAML without libyaml is one "not YAML: <reason>" error at 1:1 and nothing loaded. */
    public function testYamlWithoutLibyaml(): void
    {
        [$res, $why] = self::withoutLibyaml(static fn() => ActionsAuthor::loadActionsText("ns: acme\nactions: []\n"));
        $this->assertNotSame('', $why);
        $err = $res->get('errors');
        $this->assertCount(1, $err);
        $this->assertSame(['not YAML: ' . $why, 1, 1], [$err[0]->get('message'), $err[0]->get('line')->int(), $err[0]->get('column')->int()]);
        $this->assertSame('{"defs":[],"locs":{},"notes":[],"rules":{}}', Json::canonicalizeStrict($res->without('errors')));
    }

    /** JSON without libyaml still loads the value; only the positions are missing. */
    public function testJsonWithoutLibyaml(): void
    {
        [$res] = self::withoutLibyaml(static fn() => ActionsAuthor::loadActionsText(self::DOC, 'json'));
        $this->assertSame([], $res->get('errors'));
        $this->assertCount(1, $res->get('defs'));
        $this->assertSame('acme.note.read', $res->get('defs')[0]->get('verb'));
        $this->assertSame([], $res->get('locs')->keys());
        $this->assertSame('acme', $res->get('ns'));
    }
}
