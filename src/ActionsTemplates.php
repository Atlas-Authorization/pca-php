<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsTemplatesData.php';

/**
 * Starter packs a platform can begin from (native port of templates.ts of the reference actions package): typical actions of five business types in
 * the authoring YAML form, with custom traits and business rules. Every action is an authored draft: a template never confirms anything. The data is
 * generated from the reference (ActionsTemplatesData); the namespace is substituted into it. The YAML is returned as text.
 */
final class StarterTemplate
{
    public function __construct(public readonly string $id, public readonly string $title, public readonly string $description, public readonly string $ns,
        private readonly mixed $traitList, private readonly string $yamlText)
    {
    }

    /** The pack's custom traits under namespace $ns (ids `<ns>.<name>`). @return list<Obj> */
    public function traits(mixed $ns): array
    {
        return ActionsTemplates::sub($this->traitList, ActionsTemplates::checkNs($ns));
    }

    /** The authoring YAML under namespace $ns, with `rules:` blocks and their examples. */
    public function yaml(mixed $ns): string
    {
        return str_replace(ActionsTemplatesData::MARKER, ActionsTemplates::checkNs($ns), $this->yamlText);
    }
}

final class ActionsTemplates
{
    /** @var list<StarterTemplate>|null */
    private static ?array $all = null;

    /** The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`. */
    public static function checkNs(mixed $ns): string
    {
        if (!is_string($ns) || preg_match('/\A[a-z][a-z0-9_]{0,31}\z/', $ns) !== 1) {
            throw new ActionKitError('bad_ns', 'ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)');
        }
        if ($ns === 'pca') {
            throw new ActionKitError('bad_ns', "the namespace 'pca' is reserved for core traits");
        }
        return $ns;
    }

    /** @internal */
    public static function sub(mixed $x, string $ns): mixed
    {
        if (is_string($x)) {
            return str_replace(ActionsTemplatesData::MARKER, $ns, $x);
        }
        if (is_array($x)) {
            return array_map(static fn($v) => self::sub($v, $ns), $x);
        }
        if ($x instanceof Obj) {
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::sub($x->get($k), $ns));
            }
            return $o;
        }
        return $x;
    }

    /** @return list<StarterTemplate> */
    public static function starterTemplates(): array
    {
        if (self::$all === null) {
            self::$all = array_map(static fn(Obj $t): StarterTemplate => new StarterTemplate($t->get('id'), $t->get('title'), $t->get('description'), $t->get('ns'),
                $t->get('traits'), $t->get('yaml')), (new Parser(ActionsTemplatesData::JSON, PHP_INT_MAX))->run());
        }
        return self::$all;
    }

    public static function starterTemplate(string $id): ?StarterTemplate
    {
        foreach (self::starterTemplates() as $t) {
            if ($t->id === $id) {
                return $t;
            }
        }
        return null;
    }
}
