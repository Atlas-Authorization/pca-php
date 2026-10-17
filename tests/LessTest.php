<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\LessFfi;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * LESS suites through libatlas_less (LessFfi): the known answers of packages/pca/conformance/less-vectors.json (incl. the
 * seed-padding malleation every verifier must refuse) when the library is present (build: sdks/pca-less-c/build.sh), else
 * both suites are unsupported and refused with `unsupported_suite`.
 */
final class LessTest extends TestCase
{
    public function testManifestListsBothOrNeither(): void
    {
        $s = Pca::supportedSuites();
        $this->assertSame(LessFfi::available(), in_array('less-cat1', $s, true));
        $this->assertSame(LessFfi::available(), in_array('hybrid-ed25519-less-cat1', $s, true));
    }

    public function testKnownAnswers(): void
    {
        if (!LessFfi::available()) {
            $this->markTestSkipped('libatlas_less not built (sdks/pca-less-c/build.sh) or not at ATLAS_PCA_LIBLESS');
        }
        $doc = json_decode((string)file_get_contents(__DIR__ . '/../conformance/less-vectors.json'), true);
        $this->assertGreaterThanOrEqual(25, count($doc['vectors']));
        foreach ($doc['vectors'] as $v) {
            $key = $doc['keys'][$v['key']];
            $art = ['alg' => $v['alg'], 'sig' => $v['sig'], 'pq_pk' => $v['pq_pk_override'] ?? $key['pq_pk'], 'ed_pub' => $key['ed_pub']];
            if (isset($v['pq_sig'])) {
                $art['pq_sig'] = $v['pq_sig'];
            }
            $msg = Pca::unb64u($v['message']);
            $this->assertNotNull($msg, $v['name']);
            $got = Pca::verifyArtifact(Json::parseLax((string)json_encode($art)), $msg);
            $this->assertSame($v['expect']['allow'], $got, $v['name']);
        }
    }

    public function testRefusedWithoutLibrary(): void
    {
        if (LessFfi::available()) {
            $this->markTestSkipped('libatlas_less present');
        }
        $this->assertNotContains('less-cat1', Pca::supportedSuites());
        $this->assertFalse(LessFfi::verify(str_repeat("\0", LessFfi::PUBLIC_KEY_BYTES), 'm', str_repeat("\0", LessFfi::SIGNATURE_MIN_BYTES)));
    }
}
