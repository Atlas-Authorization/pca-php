<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\OpenAiAgents;
use Atlas\Pca\PcaToolDenied;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The OpenAI Agents adapter (proof sources, guard pipeline, per-tool option merging, guardrails, step-up) against the TS reference:
 * test-data/ref-openai-agents.json.gz. Tools, verifiers and hooks are rebuilt from the declarative descriptors the oracle recorded.
 * The language-specific tails of two messages are cut on both sides, and the reference's name for the guard is used.
 */
final class RefOpenAiAgentsDifferentialTest extends TestCase
{
    private const FILE = 'ref-openai-agents.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function norm(string $m): string
    {
        $m = preg_replace('/proof could not be decoded: [\s\S]*\z/', 'proof could not be decoded: ', $m) ?? $m;
        $m = preg_replace('/(full policy mode is missing)[\s\S]*\z/', '$1', $m) ?? $m;
        return str_replace('withPcaTool', 'with_pca_tool', $m);
    }

    private static function clean(mixed $v): mixed
    {
        if (is_string($v)) {
            return self::norm($v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::clean($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::clean(...), $v) : $v;
    }

    /** @param array<mixed> $calls */
    private static function stub(Obj $d, array &$calls): \Closure
    {
        return function (mixed $p) use ($d, &$calls): array {
            $calls[] = ['verify', $d->get('stub'), $p instanceof Obj ? Js::opt(Js::opt($p, 'action'), 'verb') : null];
            if (Js::truthy($d->get('throws'))) {
                throw new \Exception((string)$d->get('throws'));
            }
            $allow = Js::truthy($d->get('allow'));
            $out = ['allow' => $allow, 'checks' => ['sig' => $allow ? 'pass' : 'fail']];
            if ($d->has('reason')) {
                $out['reason'] = $d->get('reason');
            }
            return $out;
        };
    }

    private static function nonEmpty(mixed $v): bool
    {
        return Js::truthy($v) && !($v instanceof Obj && $v->keys() === []);
    }

    /** @param array<mixed> $calls @return array<string,mixed> */
    private static function buildOpts(Obj $d, array &$calls): array
    {
        $out = [];
        foreach (['mode', 'verb', 'audience', 'name'] as $k) {
            if ($d->has($k)) {
                $out[$k] = $d->get($k);
            }
        }
        if (self::nonEmpty($d->get('verify'))) {
            $out['verify'] = self::stub($d->get('verify'), $calls);
        }
        if ($d->get('authorize') !== null) {
            $out['authorize'] = $d->get('authorize');
        }
        if (self::nonEmpty($d->get('require'))) {
            $r = $d->get('require');
            $out['require'] = $r->has('headers') ? OpenAiAgents::proofFromInputHeaders(...$r->get('headers')) : (static fn(mixed ...$a) => $r->get('const'));
        }
        if (Js::truthy($d->get('onDeny'))) {
            $out['onDeny'] = static function ($e, $i) use (&$calls): void {
                $calls[] = ['onDeny', $e->kind, $i];
            };
        }
        if (Js::truthy($d->get('onVerified'))) {
            $out['onVerified'] = static function ($r, $p, $i) use (&$calls): void {
                $calls[] = ['onVerified', Js::opt($r, 'allow'), Js::opt(Js::opt($p, 'action'), 'verb'), $i];
            };
        }
        if (Js::truthy($d->get('recorder'))) {
            $rec = static function (string $n, mixed $o) use (&$calls): void {
                $calls[] = ['recorded', $n, $o];
            };
            $out['recorder'] = new class($rec) {
                public function __construct(private readonly \Closure $f)
                {
                }

                public function tool(string $n, mixed $o): void
                {
                    ($this->f)($n, $o);
                }
            };
        }
        return $out;
    }

    /** @param array<mixed> $calls @return array<string,mixed> */
    private static function tool(Obj $td, array &$calls): array
    {
        $t = ['name' => $td->get('name'), 'description' => 'd'];
        $extra = $td->get('extra');
        if ($extra instanceof Obj) {
            foreach ($extra->keys() as $k) {
                $t[$k] = $extra->get($k);
            }
        }
        if ($td->get('noExecute') !== true) {
            $t['execute'] = static function (mixed $input, mixed $rc = null) use ($td, &$calls): array {
                $calls[] = ['exec', $td->get('name'), $input];
                if (Js::truthy($td->get('throws'))) {
                    throw new \Exception((string)$td->get('throws'));
                }
                return ['echo' => $input, 'tool' => $td->get('name')];
            };
        }
        return $t;
    }

    private static function errKind(\Throwable $e): string
    {
        return $e instanceof PcaToolDenied ? 'PcaToolDenied' : ($e instanceof \TypeError ? 'TypeError' : 'Error');
    }

    /** @param array<mixed> $calls @return array<string,mixed> */
    private static function errOf(\Throwable $e, array $calls): array
    {
        $out = ['err' => self::errKind($e), 'message' => $e->getMessage(), 'calls' => $calls];
        if ($e instanceof PcaToolDenied) {
            $out['kind'] = $e->kind;
            $out['verb'] = $e->verb;
            if ($e->checks !== null) {
                $out['checks'] = $e->checks;
            }
        }
        return $out;
    }

    /** @param array<string,mixed> $t @param array<mixed> $calls @return array<string,mixed> */
    private static function outcome(array $t, mixed $input, mixed $rc, bool $noRc, array &$calls): array
    {
        try {
            $out = ($t['execute'])($input, $noRc ? null : $rc);
        } catch (\Throwable $e) {
            return self::errOf($e, $calls);
        }
        return ['ok' => true, 'out' => $out, 'calls' => $calls, 'name' => $t['name'] ?? null, 'extra' => $t['extra'] ?? null,
            'hasNeedsApproval' => array_key_exists('needsApproval', $t)];
    }

    /** @param array<mixed> $calls @return array<string,mixed> */
    private static function buildError(\Throwable $e, array $calls): array
    {
        return ['err' => $e instanceof \TypeError ? 'TypeError' : 'Error', 'message' => $e->getMessage(), 'calls' => $calls, 'build' => true];
    }

    private static function withTool(Obj $a): array
    {
        $calls = [];
        try {
            $t = OpenAiAgents::withPcaTool(self::tool($a->get('tool'), $calls), self::buildOpts($a->get('options'), $calls));
        } catch (\Throwable $e) {
            return self::buildError($e, $calls);
        }
        return self::outcome($t, $a->get('input'), $a->get('runContext'), Js::truthy($a->get('noRunContext')), $calls);
    }

    private static function toolsOf(Obj $a): array
    {
        $calls = [];
        $tools = [];
        $td = $a->get('tools');
        foreach ($td->keys() as $k) {
            $tools[$k] = self::tool($td->get($k), $calls);
        }
        $o = $a->get('options');
        $opts = self::buildOpts($o, $calls);
        if ($o->has('per')) {
            $opts['per'] = [];
            foreach ($o->get('per')->keys() as $k) {
                $opts['per'][$k] = self::buildOpts($o->get('per')->get($k), $calls);
            }
        }
        if ($o->get('only') !== null) {
            $opts['only'] = $o->get('only');
        }
        try {
            $g = OpenAiAgents::pcaTools($tools, $opts);
        } catch (\Throwable $e) {
            return self::buildError($e, $calls);
        }
        $res = [];
        foreach ($g as $k => $t) {
            $r = self::outcome($t, $a->get('input'), $a->get('runContext'), false, $calls);
            $r['same'] = $t === $tools[$k];
            $res[$k] = $r;
        }
        foreach ($res as $k => $_) {
            if (array_key_exists('calls', $res[$k])) {
                $res[$k]['calls'] = $calls; // the reference's log is one array shared by every tool, serialized after all ran
            }
        }
        return $res;
    }

    private static function guardrail(Obj $a): array
    {
        $calls = [];
        $kw = self::buildOpts($a->get('options'), $calls);
        unset($kw['mode']);
        $g = $a->get('kind') === 'input' ? OpenAiAgents::pcaInputGuardrail($kw) : OpenAiAgents::pcaToolGuard($kw);
        try {
            $r = $g->execute($a->get('args'));
        } catch (\Throwable $e) {
            return ['err' => 'Error', 'message' => $e->getMessage(), 'calls' => $calls];
        }
        return ['name' => $g->name, 'result' => $r, 'calls' => $calls];
    }

    private static function intentNull(array &$calls): \Closure
    {
        return static function ($t, $i) use (&$calls) {
            $calls[] = ['intent', $t, $i];
            return null;
        };
    }

    private static function review(Obj $a): array
    {
        $calls = [];
        $r = OpenAiAgents::reviewToolCall(null, $a->get('tool'), $a->get('input'), ['intent' => self::intentNull($calls)]);
        return ['r' => $r, 'calls' => $calls];
    }

    private static function needs(Obj $a): array
    {
        $calls = [];
        $kw = ['intent' => self::intentNull($calls)];
        if ($a->get('toolName') !== null) {
            $kw['toolName'] = $a->get('toolName');
        }
        $rc = new Obj();
        if ($a->get('via') === 'direct') {
            $f = OpenAiAgents::pcaNeedsApproval(null, $kw);
            return ['value' => $f($rc, $a->get('input'), 'c1'), 'calls' => $calls];
        }
        $t = ['name' => $a->get('tool')->get('name'), 'description' => 'd', 'execute' => static fn() => 1];
        $t = OpenAiAgents::withApproval($t, null, $kw);
        return ['value' => ($t['needsApproval'])($rc, $a->get('input'), 'c1'), 'calls' => $calls, 'name' => $t['name'], 'extra' => null,
            'hasExecute' => is_callable($t['execute'] ?? null)];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $wrap = static fn(callable $f): \Closure => static function (array $args, Obj $c) use ($f) {
            $c->set('out', self::clean($c->get('out')));
            return self::clean($f($args[0] ?? null));
        };
        Base::run($file, $fn, $k, [
            'proofFromRunContext' => $wrap(static fn(Obj $a) => OpenAiAgents::proofFromRunContext($a->get('input'), $a->get('runContext'))),
            'guardrailProofFromContext' => $wrap(static fn(Obj $a) => OpenAiAgents::guardrailProofFromContext($a->get('args'))),
            'provenanceFromRunContext' => $wrap(static fn(Obj $a) => OpenAiAgents::provenanceFromRunContext(null, $a->get('runContext'))),
            'proofFromInputHeaders' => $wrap(static fn(Obj $a) => OpenAiAgents::proofFromInputHeaders(
                $a->has('field') ? $a->get('field') : 'headers', $a->has('header') ? $a->get('header') : 'PCA-Action')($a->get('input'))),
            'pendingStepUps' => $wrap(static fn(array $r) => OpenAiAgents::pendingStepUps($r)),
            'withPcaTool' => $wrap(static fn(Obj $a) => self::withTool($a)),
            'pcaTools' => $wrap(static fn(Obj $a) => self::toolsOf($a)),
            'guardrail' => $wrap(static fn(Obj $a) => self::guardrail($a)),
            'reviewToolCall' => $wrap(static fn(Obj $a) => self::review($a)),
            'needsApproval' => $wrap(static fn(Obj $a) => self::needs($a)),
        ]);
    }
}
