<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentPolicy.php';

/**
 * Outcome verification: postconditions on observed effects, evaluated by the one predicate evaluator. Three-valued: ok, violated,
 * pending. verifyOutcome calls IntentMapKit::applyDivergence (the learner kit) for a violation.
 */
final class IntentEffects
{
    /** @var list<Obj>|null */
    private static ?array $defaults = null;

    private static function eff(string $field): string
    {
        return 'env.effect.' . $field;
    }

    private static function pc(string $id, string $verb, string $description, array $where): Obj
    {
        return Obj::of(['id' => $id, 'verb' => $verb, 'description' => $description, 'where' => $where]);
    }

    private static function leaf(string $field, string $op, mixed $v, bool $ref = false): Obj
    {
        $o = Obj::of(['field' => $field, 'op' => $op]);
        $o->set($ref ? 'ref' : 'value', $v);
        return $o;
    }

    /** @return list<Obj> the built-in postconditions for the catalog verbs */
    public static function defaultPostconditions(): array
    {
        if (self::$defaults !== null) {
            return self::$defaults;
        }
        $amt = static fn(): array => [self::leaf(self::eff('amount'), 'lte', 'action.params.amount', true), self::leaf(self::eff('amount'), 'gte', 0)];
        $eq = static fn(string $f, string $ref): array => [self::leaf(self::eff($f), 'eq', $ref, true)];
        return self::$defaults = [
            self::pc('stripe.refund.amount', 'stripe.refund', 'the refunded amount is at most the requested amount', $amt()),
            self::pc('stripe.refund.recipient', 'stripe.refund', 'the refund went to the requested recipient', $eq('recipient', 'action.params.recipient')),
            self::pc('stripe.charge.amount', 'stripe.charge', 'the charged amount is at most the requested amount', $amt()),
            self::pc('stripe.payout.amount', 'stripe.payout', 'the paid-out amount is at most the requested amount', $amt()),
            self::pc('stripe.payout.recipient', 'stripe.payout', 'the payout went to the requested recipient', $eq('recipient', 'action.params.recipient')),
            self::pc('gmail.send.to', 'gmail.send', 'the mail went only to the requested address', $eq('to', 'action.params.to')),
            self::pc('slack.post_message.channel', 'slack.post_message', 'the message was posted in the requested channel', $eq('channel', 'action.params.channel')),
            self::pc('files.write.path', 'files.write', 'the written path is the requested resource', $eq('path', 'action.resource')),
            self::pc('files.delete.path', 'files.delete', 'the deleted path is the requested resource', $eq('path', 'action.resource')),
            self::pc('github.merge_pr.repo', 'github.merge_pr', 'the merge landed in the requested repository', $eq('repo', 'action.resource')),
            self::pc('calendar.create_event.hour', 'calendar.create_event', 'the event starts at the requested hour', $eq('hour', 'env.hour')),
        ];
    }

    /** @param list<array{field:string,ref?:string}> $out */
    private static function leaves(mixed $c, array &$out): void
    {
        if (!($c instanceof Obj)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && is_array($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::leaves($x, $out);
                }
            } elseif ($c->has('any_of') && is_array($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::leaves($x, $out);
                }
            } elseif ($c->has('not')) {
                self::leaves($c->get('not'), $out);
            }
            return;
        }
        if (Predicates::isLeafCondition($c)) {
            $d = ['field' => $c->get('field')];
            if (is_string($c->get('ref'))) {
                $d['ref'] = $c->get('ref');
            }
            $out[] = $d;
        }
    }

    private static function get(mixed $root, string $path): mixed
    {
        $cur = $root;
        foreach (explode('.', $path) as $k) {
            if ($cur instanceof Obj && $cur->has($k)) {
                $cur = $cur->get($k);
            } elseif (is_array($cur) && array_is_list($cur) && preg_match('/\A(?:0|[1-9][0-9]*)\z/', $k) === 1 && (int)$k < count($cur)) {
                $cur = $cur[(int)$k];
            } else {
                return Jsx::$U;
            }
        }
        return $cur;
    }

    /** The evaluator's context for an action plus its observed effect. */
    public static function effectContext(mixed $vs, mixed $o, mixed $effect): Obj
    {
        $a = IntentPolicy::outcomeToAction($vs, $o);
        $action = Obj::of(['verb' => $a->get('verb'), 'resource' => $a->get('resource'), 'params' => $a->get('params')]);
        if (Js::has($vs, 'reversibility')) {
            $action->set('reversibility_class', Js::opt($vs, 'reversibility'));
        }
        $ctx = Obj::of(['action' => $action]);
        if ($a->has('subject')) {
            $ctx->set('subject', $a->get('subject'));
        }
        $env = new Obj();
        $ae = $a->get('env');
        if ($ae instanceof Obj) {
            foreach ($ae->keys() as $k) {
                $env->set($k, $ae->get($k));
            }
        }
        $env->set('effect', $effect);
        $ctx->set('env', $env);
        return $ctx;
    }

    /**
     * Check an observed effect against the postconditions of the outcome's verb (default: the built-in ones).
     * @return array{status:string,violated:list<string>,missing:list<string>,checked:list<string>,notApplicable:list<string>}
     */
    public static function checkPostconditions(mixed $vs, mixed $o, mixed $effect, ?array $pcs = null): array
    {
        $pcs ??= self::defaultPostconditions();
        $ctx = self::effectContext($vs, $o, $effect);
        $violated = $missing = $checked = $notApplicable = [];
        foreach ($pcs as $pc) {
            if (Js::opt($pc, 'verb') !== Js::opt($o, 'verb')) {
                continue;
            }
            $ls = [];
            foreach (Js::opt($pc, 'where') as $c) {
                self::leaves($c, $ls);
            }
            $na = false;
            foreach ($ls as $l) {
                if (isset($l['ref']) && !str_starts_with($l['ref'], 'env.effect.') && self::get($ctx, $l['ref']) instanceof Undef) {
                    $na = true;
                    break;
                }
            }
            if ($na) {
                $notApplicable[] = Js::opt($pc, 'id');
                continue;
            }
            $need = [];
            foreach ($ls as $l) {
                foreach (array_merge([$l['field']], isset($l['ref']) && $l['ref'] !== '' ? [$l['ref']] : []) as $f) {
                    if (str_starts_with($f, 'env.effect.') && !in_array($f, $need, true)) {
                        $need[] = $f;
                    }
                }
            }
            $lacking = array_values(array_filter($need, static fn(string $f) => self::get($ctx, $f) instanceof Undef));
            if ($lacking) {
                array_push($missing, ...$lacking);
                continue;
            }
            $checked[] = Js::opt($pc, 'id');
            $r = Predicates::evaluatePredicates([Obj::of(['verb' => Js::opt($o, 'verb'), 'resource' => '*', 'where' => Js::opt($pc, 'where')])], $ctx);
            if (!$r['allowed']) {
                $violated[] = Js::opt($pc, 'id');
            }
        }
        $missing = array_values(array_unique($missing));
        usort($missing, static fn($a, $b) => Jsx::cmp($a, $b));
        return ['status' => $violated ? 'violated' : ($missing ? 'pending' : 'ok'), 'violated' => $violated, 'missing' => $missing,
            'checked' => $checked, 'notApplicable' => $notApplicable];
    }

    /**
     * Check an executed action's effect and feed the result back: a violation is a negative runtime observation that vetoes the
     * action's cell. `ok` and `pending` change nothing. $l is an IntentLearner.
     * @return array<string,mixed> {report, divergence?}
     */
    public static function verifyOutcome(object $l, mixed $o, mixed $effect, ?array $pcs = null): array
    {
        $vs = null;
        foreach (Js::opt($l->omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === Js::opt($o, 'verb')) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            throw new \InvalidArgumentException('verifyOutcome: no verb ' . Js::opt($o, 'verb') . " in \u{03A9}");
        }
        $report = self::checkPostconditions($vs, $o, $effect, $pcs);
        if ($report['status'] !== 'violated') {
            return ['report' => $report];
        }
        require_once __DIR__ . '/IntentMapKit.php';
        return ['report' => $report, 'divergence' => IntentMapKit::applyDivergence($l, $o, 0)];
    }
}
