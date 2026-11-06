<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\ProvenanceRecorder;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Provenance by default against the TS reference: test-data/k05-argprov.json.gz (k05-oracles/argprov-oracle.mts). */
final class K05ArgProvenanceDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-argprov.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    /** The recorder harness of the oracle: {pin, outs: [receipt | bundle | {$throws}]} (a throw's text is engine-specific). */
    private static function recorder(Obj $spec, Obj $c): Obj
    {
        $clock = array_map(static fn(Num $n) => $n->isInt() ? $n->int() : $n->float(), $spec->get('clock'));
        $last = 0;
        $now = static function () use (&$clock, &$last) {
            if ($clock !== []) {
                $last = array_shift($clock);
            }
            return $last;
        };
        $rec = new ProvenanceRecorder($spec->get('mediator'), $spec->get('kid'), new KeyPair(Pca::unb64u($spec->get('sk')) ?? ''), $spec->get('session'), $now);
        $outs = [];
        foreach ($spec->get('steps') as $s) {
            try {
                $outs[] = match ($s[0]) {
                    'principal' => $rec->principal($s[1]),
                    'tool' => $rec->tool($s[1], $s[2]),
                    'retrieval' => $rec->retrieval($s[1], $s[2]),
                    'web' => $rec->web($s[1], $s[2]),
                    'action' => $rec->forAction($s[1]),
                    'direct' => ArgProvenance::principalDirect($rec, $s[1]),
                };
            } catch (\Throwable) {
                $outs[] = Obj::of(['$throws' => true]);
            }
        }
        $w = $c->get('out');
        if ($w instanceof Obj && is_array($w->get('outs'))) {
            $w->set('outs', array_map(static fn($o) => $o instanceof Obj && $o->has('$throws') ? Obj::of(['$throws' => true]) : $o, $w->get('outs')));
        }
        return Obj::of(['pin' => $rec->pin, 'outs' => $outs]);
    }

    /** The middleware's request reader (header PCA-Provenance, else body.pca_provenance). */
    private static function readBundle(Obj $a, Obj $c): mixed
    {
        $w = $c->get('out');
        if ($w instanceof Obj && $w->has('$throws')) {
            $w->set('code', null); // the reference's error code (invalid_pca_header) has no PHP twin: the reader throws, the gate refuses
        }
        $req = new ServerRequest('POST', '/', $a->has('header') ? ['PCA-Provenance' => $a->get('header')] : [], $a->has('body') ? $a->get('body') : null);
        $mw = (new \ReflectionClass(PcaMiddleware::class))->newInstanceWithoutConstructor();
        return (new \ReflectionMethod(PcaMiddleware::class, 'provenanceOf'))->invoke($mw, $req);
    }

    /** The reference's camelCase input members under the PHP API's names (principal_plan / principal_control). */
    private static function snakeInput(mixed $in): mixed
    {
        if (!($in instanceof Obj)) {
            return $in;
        }
        $out = new Obj();
        foreach ($in->keys() as $k) {
            $out->set(['principalPlan' => 'principal_plan', 'principalControl' => 'principal_control'][$k] ?? $k, $in->get($k));
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'provReceiptWireError' => fn(array $a) => ArgProvenance::receiptWireError($a[0]),
            'isProvMediatorPin' => fn(array $a) => ArgProvenance::isMediatorPin($a[0]),
            'provActionInfoError' => fn(array $a) => ArgProvenance::actionInfoError($a[0]),
            'isReadOnlyAction' => fn(array $a) => ArgProvenance::isReadOnlyAction($a[0]),
            'provEnvelopeError' => fn(array $a) => ArgProvenance::envelopeError($a[0]),
            'occursAsToken' => fn(array $a) => ArgProvenance::occursAsToken($a[0], $a[1]),
            'provLeaves' => fn(array $a) => ArgProvenance::leaves($a[0]),
            'decideArgProvenance' => fn(array $a) => ArgProvenance::decide(self::snakeInput($a[0])),
            'recorder' => fn(array $a, Obj $c) => self::recorder($a[0], $c),
            'provActionDigest' => fn(array $a) => ArgProvenance::actionDigest($a[0]->get('verb'), $a[0]->get('resource'), $a[0]->get('params')),
            'provReceiptRef' => fn(array $a) => ArgProvenance::receiptRef($a[0]),
            'defaultProvenanceBundle' => fn(array $a, Obj $c) => self::readBundle($a[0], $c),
        ]);
    }
}
