<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** The forbid-wins evaluators against forbid-certificate-vectors.json (decide, table) and prohibition-vectors.json (clauses, check). */
final class K05HardForbidVectorsTest extends TestCase
{
    private static function plainValues(array $values): array
    {
        return array_map(static fn(array $v): array => ['id' => $v['id'], 'kind' => $v['kind'], 'value' => $v['value']], $values);
    }

    private static function plainExpect(Obj $x): array
    {
        $values = [];
        foreach ($x->get('values') as $v) {
            $values[] = ['id' => $v->get('id'), 'kind' => $v->get('kind'), 'value' => $v->get('value')];
        }
        return $values;
    }

    private static function options(mixed $o): array
    {
        $out = [];
        if ($o instanceof Obj) {
            foreach (['precedence', 'permitSigners'] as $k) {
                if ($o->has($k)) {
                    $out[$k] = $o->get($k);
                }
            }
        }
        return $out;
    }

    public function testForbidCertificateDecideVectors(): void
    {
        $rows = Vectors::load('forbid-certificate-vectors.json')->get('decide');
        $this->assertGreaterThanOrEqual(11, count($rows));
        foreach ($rows as $c) {
            $x = $c->get('expect');
            $opts = self::options($c->get('options') ?? null);
            $d = ForbidCertificate::decide($c->get('clauses'), $c->get('action'), $opts);
            $n = $c->get('name');
            $this->assertSame($x->get('decision'), $d['decision'], $n);
            $this->assertSame($x->get('winner')->get('kind'), $d['witness']['winner']['kind'], "$n winner kind");
            $this->assertSame($x->get('winner')->get('id'), $d['witness']['winner']['id'], "$n winner id");
            $this->assertSame($x->get('shadowed'), $d['witness']['shadowed'], "$n shadowed");
            $this->assertSame(self::plainExpect($x), self::plainValues($d['values']), "$n values");
            $this->assertSame($x->get('certificate_digest'), Pca::hashCanonical(ForbidCertificate::certify($c->get('clauses'), $c->get('action'), $opts)), "$n certificate digest");
        }
    }

    public function testForbidCertificateTableVectors(): void
    {
        $rows = Vectors::load('forbid-certificate-vectors.json')->get('table');
        $this->assertGreaterThanOrEqual(19, count($rows));
        foreach ($rows as $c) {
            $o = $c->get('options');
            $prec = $o instanceof Obj && $o->has('precedence') ? $o->get('precedence') : [];
            $this->assertSame($c->get('expect')->get('consistent'), ForbidCertificate::consistent($c->get('certificate'), $prec), $c->get('name'));
        }
    }

    public function testProhibitionClauseVectors(): void
    {
        $rows = Vectors::load('prohibition-vectors.json')->get('clauses');
        $this->assertGreaterThanOrEqual(20, count($rows));
        foreach ($rows as $c) {
            $x = $c->get('expect');
            $n = $c->get('name');
            $this->assertSame($x->get('error'), ForbidCertificate::clausesError($c->get('clauses')), "$n error");
            $d = ForbidCertificate::decide($c->get('clauses'), $c->get('action'));
            $this->assertSame($x->get('decision'), $d['decision'], "$n decision");
            $this->assertSame($x->get('winner')->get('kind'), $d['witness']['winner']['kind'], "$n winner kind");
            $this->assertSame($x->get('winner')->get('id'), $d['witness']['winner']['id'], "$n winner id");
            $this->assertSame($x->get('shadowed'), $d['witness']['shadowed'], "$n shadowed");
            $this->assertSame(self::plainExpect($x), self::plainValues($d['values']), "$n values");
        }
    }

    public function testProhibitionCheckVectors(): void
    {
        $rows = Vectors::load('prohibition-vectors.json')->get('check');
        $this->assertGreaterThanOrEqual(11, count($rows));
        foreach ($rows as $c) {
            $x = $c->get('expect');
            $r = ForbidCertificate::check($c->get('certificate'), $c->get('clauses'), $c->get('action'), self::options($c->get('options') ?? null));
            $this->assertSame($x->get('ok'), $r['ok'], $c->get('name'));
            if ($x->has('reason')) {
                $this->assertSame($x->get('reason'), $r['reason'] ?? null, $c->get('name') . ' reason');
            }
        }
    }
}
