<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalOntologies.php';
require_once __DIR__ . '/../src/GoalInterpret.php';
require_once __DIR__ . '/../src/GoalRoundtrip.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalInterpret as I;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\GoalRoundtrip;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The goal interpreters against the TS reference: test-data/ref-goal-interpret.json.gz (candidate extraction, slot filling, the rule,
 * form and model interpreters, prompts and keys, grounding, vendor completions over an injected fetch, the typed refund form and the
 * lexical comparator). A shipped ontology travels by name and is resolved from the shipped data.
 */
final class RefGoalInterpretDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-interpret.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function ont(mixed $x): mixed
    {
        if (is_string($x)) {
            $o = GoalOntologies::shippedOntology($x);
            if ($o !== null && $o !== false) {
                return $o;
            }
        }
        return $x;
    }

    /** The request `{principal, text, ontology[, sources]}`. */
    private static function req(mixed $on, mixed $text, mixed $src, string $principal = 'p1'): Obj
    {
        $r = Obj::of(['principal' => $principal, 'text' => $text, 'ontology' => self::ont($on)]);
        if ($src !== null) {
            $r->set('sources', $src);
        }
        return $r;
    }

    private static function find(mixed $list, string $key, mixed $val): mixed
    {
        foreach ($list as $x) {
            if ($x->get($key) === $val) {
                return $x;
            }
        }
        return null;
    }

    private static function vendor(array $a): Obj
    {
        [, $kind, $cfg, $fake, $system, $user] = $a;
        $req = new Obj();
        if (!($fake instanceof Obj) || $fake->keys() === []) { // the generator's plain success stub
            $fake = Obj::of(['ok' => true, 'status' => 200, 'body' => $kind === 'anthropic'
                ? Obj::of(['content' => [Obj::of(['type' => 'text', 'text' => 'x'])]])
                : Obj::of(['choices' => [Obj::of(['message' => Obj::of(['content' => 'x'])])]])]);
        }
        $fetch = static function (string $url, Obj $init) use ($req, $fake): object {
            $req->set('url', $url);
            $req->set('method', $init->get('method'));
            $req->set('headers', $init->get('headers'));
            $req->set('body', $init->get('body'));
            if (AnalyzerJs::truthy(Js::opt($fake, 'throwMsg'))) {
                throw new \RuntimeException($fake->get('throwMsg'));
            }
            return (object)['ok' => Js::opt($fake, 'ok'), 'status' => Js::opt($fake, 'status'), 'json' => Js::opt($fake, 'body')];
        };
        $c = $kind === 'anthropic'
            ? I::anthropicCompletion($cfg->get('apiKey'), $cfg->get('model'), $fetch, $cfg->has('maxTokens') ? (int)Js::num($cfg->get('maxTokens')) : 1024)
            : I::openaiCompletion($cfg->get('apiKey'), $cfg->get('model'), $fetch, Js::opt($cfg, 'baseUrl'));
        try {
            return Obj::of(['text' => $c(Obj::of(['system' => $system, 'user' => $user])), 'req' => $req]);
        } catch (\Throwable $e) {
            return Obj::of(['error' => $e->getMessage(), 'req' => $req]);
        }
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'slotStemsOf' => fn(array $a) => I::slotStems($a[0]),
            'sourceDigest' => fn(array $a) => I::sourceDigest($a[0]),
            'extractCandidates' => fn(array $a) => I::extractCandidates($a[1], self::ont($a[0]), $a[2] ?? null),
            'fillTemplateById' => function (array $a) {
                $o = self::ont($a[0]);
                return I::fillTemplate(self::find(AnalyzerJs::jget($o, 'templates'), 'id', $a[1]), $o, $a[2], $a[3] ?? null);
            },
            'interpretRule' => fn(array $a) => I::ruleInterpreter('rule', $a[3] ?? null)->interpret(self::req($a[0], $a[1], $a[2] ?? null)),
            'buildPromptOf' => fn(array $a) => I::buildPrompt(self::req($a[0], $a[1], $a[2] ?? null, 'p'), AnalyzerJs::truthy($a[3] ?? null)),
            'interpretForm' => function (array $a) {
                $req = self::req($a[0], $a[2], $a[2] === 'form text' ? ['s'] : null);
                if ($a[1] !== null) {
                    $req->set('form', $a[1]);
                }
                return I::formInterpreter()->interpret($req);
            },
            'interpretLlm' => function (array $a) {
                [$on, $text, $src, $mode, $inc] = $a;
                $complete = static function (mixed $p) use ($mode): mixed {
                    if (AnalyzerJs::truthy(Js::opt($mode, 'throw'))) {
                        throw new \RuntimeException('boom');
                    }
                    return Js::opt($mode, 'raw');
                };
                return I::llmInterpreter('m', 'f', $complete, AnalyzerJs::truthy($inc), $a[5] ?? null)->interpret(self::req($on, $text, $src));
            },
            'promptKeyOf' => fn(array $a) => I::promptKey($a[1], Obj::of(['system' => $a[2], 'user' => $a[3]])),
            'replayLookup' => fn(array $a) => (I::replayCompletion($a[1], $a[2]))(Obj::of(['system' => $a[3], 'user' => $a[4]])),
            'parseTemplateJSON' => fn(array $a) => I::parseTemplateJSON($a[0]),
            'groundedOf' => function (array $a) {
                $o = self::ont($a[0]);
                $t = self::find(AnalyzerJs::jget($o, 'templates'), 'id', $a[1]);
                $s = self::find(AnalyzerJs::jget($t, 'slots'), 'name', $a[2]);
                return I::grounded($s, $a[3], I::extractCandidates($a[4], $o), $o);
            },
            'vendor' => fn(array $a) => self::vendor($a),
            'interpretRefundForm' => fn(array $a) => I::interpretForm($a[0], $a[1], ($a[2] ?? null) === null ? 'pr1' : $a[2]),
            'lexicalCompare' => fn(array $a) => GoalRoundtrip::lexicalComparator(self::ont($a[0]))->equivalent($a[1], $a[2]),
        ]);
    }

    public function testEveryFunctionIsMapped(): void
    {
        $fns = [];
        foreach (self::provide() as $d) {
            $fns[$d[1]] = true;
        }
        $have = array_keys($fns);
        sort($have);
        $want = ['buildPromptOf', 'extractCandidates', 'fillTemplateById', 'groundedOf', 'interpretForm', 'interpretLlm', 'interpretRefundForm', 'interpretRule',
            'lexicalCompare', 'parseTemplateJSON', 'promptKeyOf', 'replayLookup', 'slotStemsOf', 'sourceDigest', 'vendor'];
        $this->assertSame($want, $have);
    }
}
