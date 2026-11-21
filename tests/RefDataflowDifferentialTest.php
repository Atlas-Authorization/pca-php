<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Dataflow;
use Atlas\Pca\FlowCapability;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Tagged;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The data-flow model, the trace rules and the detector adapters against the TS reference: test-data/ref-dataflow-py.json.gz (tagged
 * values are rebuilt from the JSON specs; Ed25519 receipts are deterministic and compared byte for byte) and ref-dataflow-rs.json.gz.
 */
final class RefDataflowDifferentialTest extends TestCase
{
    public static function provide(): array
    {
        return [...Base::datasets('ref-dataflow-py.json.gz'), ...Base::datasets('ref-dataflow-rs.json.gz')];
    }

    private static function readers(Obj $s): ?array
    {
        $r = $s->has('readers') ? $s->get('readers') : null;
        return is_array($r) ? $r : null;
    }

    private static function set(mixed $a): mixed
    {
        return is_array($a) && array_is_list($a) ? Dataflow::toSet($a) : $a;
    }

    private static function build(Obj $s): mixed
    {
        switch ($s->get('k')) {
            case 'trusted':
                return Dataflow::fromTrustedQuery($s->get('value'), self::readers($s));
            case 'tool':
                return Dataflow::fromToolOutput($s->get('name'), $s->get('value'), self::readers($s));
            case 'source':
                return Dataflow::fromSource($s->get('source'), $s->get('value'), $s->has('trusted') ? $s->get('trusted') : false, self::readers($s));
            case 'tag':
                $c = $s->get('cap');
                if (!($c instanceof Obj)) {
                    return Dataflow::tag($s->get('value'), $c);
                }
                return Dataflow::tag($s->get('value'), new FlowCapability(self::set($c->get('sources')), $c->has('isTrusted') ? $c->get('isTrusted') : null, $c->has('readers') ? self::set($c->get('readers')) : null));
            case 'derive':
                $op = $s->get('op');
                $f = match ($op) {
                    'concat' => static fn(...$a) => implode('|', $a),
                    'first' => static fn(...$a) => $a[0],
                    'count' => static fn(...$a) => count($a),
                };
                return Dataflow::derive(array_map(fn($x) => self::build($x), $s->get('inputs')), $f);
            case 'raw':
                return $s->get('value');
            case 'fake':
                return Obj::of(['value' => $s->get('value'), 'cap' => new Obj()]);
        }
        throw new \LogicException('unknown spec');
    }

    private static function capJson(FlowCapability $c): Obj
    {
        $o = Obj::of(['sources' => Dataflow::sorted($c->sources), 'isTrusted' => $c->isTrusted]);
        if ($c->readers !== null) {
            $o->set('readers', Dataflow::sorted($c->readers));
        }
        return $o;
    }

    private static function outT(mixed $t): Obj
    {
        if (!($t instanceof Tagged)) {
            return Obj::of(['tagged' => false]);
        }
        $o = Obj::of(['tagged' => true, 'value' => $t->value]);
        foreach (self::capJson($t->cap)->keys() as $k) {
            $o->set($k, self::capJson($t->cap)->get($k));
        }
        return $o;
    }

    private static function sinkOf(mixed $s): mixed
    {
        if (!($s instanceof Obj)) {
            return $s;
        }
        $a = $s->get('accepts');
        if (!($a instanceof Obj)) {
            return Obj::of(['id' => $s->get('id'), 'accepts' => $a]);
        }
        return Obj::of(['id' => $s->get('id'), 'accepts' => Obj::of([
            'external' => $a->get('external'), 'require_trusted' => $a->get('require_trusted'),
            'allowed_sources' => self::set($a->get('allowed_sources')), 'denied_sources' => self::set($a->get('denied_sources')),
        ])]);
    }

    private static function governor(Obj $g): \Closure
    {
        return static function ($act) use ($g) {
            $kind = $g->get('kind');
            if ($kind === 'throw') {
                throw new \RuntimeException('no sink');
            }
            if ($kind === 'byVerb') {
                $m = $g->get('map');
                $v = $act->get('verb');
                return self::sinkOf($m->has($v) ? $m->get($v) : $g->get('default'));
            }
            return self::sinkOf($g->get('sink'));
        };
    }

    private static function mk(mixed $args): mixed
    {
        return is_array($args) && array_is_list($args) ? array_map(fn($s) => $s === null ? null : self::build($s), $args) : $args;
    }

    private static function label(Obj $c): string
    {
        $n = (string)$c->get('name');
        $n = substr($n, (int)strpos($n, '/') + 1);
        $h = strpos($n, '#');
        return $h === false ? $n : substr($n, 0, $h);
    }

    private static function T(mixed $v): Obj
    {
        return Obj::of(['k' => 'trusted', 'value' => $v]);
    }

    private static function L(string $name, mixed $v): Obj
    {
        return Obj::of(['k' => 'tool', 'name' => $name, 'value' => $v]);
    }

    private static function caps(Obj ...$specs): array
    {
        return array_map(fn($s) => self::build($s)->cap, $specs);
    }

    private static function ctx(Obj $c): array
    {
        $o = ['detector' => $c->get('detector'), 'version' => $c->get('version'), 'content' => $c->get('content'),
            'secretKey' => new KeyPair(str_repeat(chr((int)$c->get('seed')->float()), 32)), 'now' => $c->get('now')];
        if ($c->has('session')) {
            $o['session'] = $c->get('session');
        }
        if ($c->has('calibration_ref')) {
            $o['calibrationRef'] = $c->get('calibration_ref');
        }
        return $o;
    }

    private static function key(mixed $n): KeyPair
    {
        return new KeyPair(str_repeat(chr((int)$n->float()), 32));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'build' => fn(array $a) => self::outT(self::build($a[0])),
            'levelOf' => function (array $a, Obj $c) {
                switch (self::label($c)) {
                    case 'null':
                        return Dataflow::levelOf(null);
                    case 'string':
                        return Dataflow::levelOf('trusted');
                    case 'mixed tool+user':
                        return Dataflow::levelOf(Dataflow::derive([Dataflow::fromToolOutput('a', 1), Dataflow::fromSource('user', 2)], fn($x, $y) => $x + $y));
                    case 'empty derive':
                        return Dataflow::levelOf(Dataflow::derive([], fn() => 1));
                }
                return Dataflow::levelOf(self::build($a[0]));
            },
            'toolProvenance' => fn(array $a) => Dataflow::toolProvenance($a[0]),
            'combineCaps' => function (array $a, Obj $c) {
                $l = self::label($c);
                if ($l === 'empty') {
                    return self::capJson(Dataflow::combineCaps([]));
                }
                if ($l === 'three') {
                    return self::capJson(Dataflow::combineCaps(self::caps(self::T('a'), Obj::of(['k' => 'trusted', 'value' => 'b', 'readers' => ['x', 'y']]), Obj::of(['k' => 'trusted', 'value' => 'c', 'readers' => ['y']]))));
                }
                return self::capJson(Dataflow::combineCaps(self::caps(self::T('a'), self::L('w', 'b'))));
            },
            'unionSources' => fn(array $a) => Dataflow::sorted(Dataflow::unionSources(self::caps(self::T('a'), self::L('w', 'b')))),
            'classifyFlow' => fn(array $a) => Dataflow::classifyFlow(self::build($a[0]), self::sinkOf($a[1])),
            'canFlow' => fn(array $a) => Dataflow::canFlow(self::build($a[0]), self::sinkOf($a[1])),
            'externalSendSink' => fn(array $a) => Dataflow::externalSendSink($a[0]),
            'sensitiveSink' => fn(array $a) => Obj::of(['id' => $a[0], 'accepts' => Obj::of(['requireTrusted' => true])]),
            'checkAction' => fn(array $a) => Dataflow::checkAction($a[0], self::mk($a[1]), self::governor($a[2]), $a[3] ?? null),
            'dualContext' => function (array $a) {
                $qs = ['tool' => fn($p) => Dataflow::fromToolOutput('q', 'r:' . $p), 'trusted' => fn($p) => Dataflow::fromTrustedQuery($p),
                    'raw' => fn($p) => $p, 'fake' => fn($p) => Obj::of(['value' => $p, 'cap' => new Obj()])];
                $r = Dataflow::dualContext(self::build($a[0]), fn($x) => 'plan:' . $x, $qs[$a[1]]);
                return Obj::of(['plan' => $r['plan'], 'result' => self::outT($r['result'])]);
            },
            'lakeraReceipt' => fn(array $a) => Dataflow::lakeraReceipt($a[0], self::ctx($a[1])),
            'promptSecurityReceipt' => fn(array $a) => Dataflow::promptSecurityReceipt($a[0], self::ctx($a[1])),
            'genericReceipt' => fn(array $a) => Dataflow::genericReceipt($a[0], self::ctx($a[1])),
            'detectorInputDigest' => fn(array $a) => Dataflow::detectorInputDigest($a[0]),
            'signDetectorReceipt' => fn(array $a) => Dataflow::signDetectorReceipt($a[0], self::key($a[1]), $a[2] ?? null),
            'detectorReceiptShapeError' => fn(array $a) => Dataflow::detectorReceiptShapeError($a[0]),
            'detectorReceiptRef' => fn(array $a) => Dataflow::detectorReceiptRef($a[0]),
            // trace rules
            'parseTraceRule' => fn(array $a) => Dataflow::parseTraceRule(...$a),
            'parseInvariantRule' => function (array $a) {
                $o = $a[2] ?? null;
                $o = $o instanceof Obj ? $o : new Obj();
                return Dataflow::parseInvariantRule($a[0], $a[1], $o->has('horizon') ? $o->get('horizon') : null, $o->has('dropUnsupported') ? $o->get('dropUnsupported') : false);
            },
            'compileTexts' => fn(array $a) => Dataflow::compileTraceRules(array_map(fn($p) => Dataflow::parseTraceRule($p[0], $p[1]), $a[0]), $a[1]),
            'compileTraceRules' => fn(array $a) => Dataflow::compileTraceRules($a[0], $a[1]),
            'lethalTrifecta' => function (array $a) {
                $o = $a[2] ?? null;
                $o = $o instanceof Obj ? $o : new Obj();
                return Dataflow::lethalTrifecta($a[0], $a[1], $o->has('untrusted') ? $o->get('untrusted') : null, $o->has('untrusted_traits') ? $o->get('untrusted_traits') : null);
            },
            'categoryId' => fn(array $a) => Dataflow::categoryId($a[0]),
        ]);
    }
}
