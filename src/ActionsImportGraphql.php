<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsImport.php';
require_once __DIR__ . '/Js.php';

/** The parser state of one GraphQL SDL source. @internal */
final class GraphqlSdlParser
{
    private int $i = 0;

    /** @param list<array{string,string}> $toks */
    public function __construct(private readonly array $toks, private readonly Obj $schema, private readonly int $maxDepth)
    {
    }

    /** @return array{string,string} */
    public function cur(): array
    {
        return $this->toks[$this->i];
    }

    public function atEof(): bool
    {
        return $this->cur()[0] === 'eof';
    }

    /** @return array{string,string} */
    private function next(): array
    {
        $t = $this->toks[$this->i];
        if ($t[0] !== 'eof') {
            $this->i++;
        }
        return $t;
    }

    private function is(string $v): bool
    {
        return $this->cur()[0] !== 'str' && $this->cur()[1] === $v;
    }

    private function eat(string $v): bool
    {
        if ($this->is($v)) {
            $this->i++;
            return true;
        }
        return false;
    }

    private function expect(string $v): void
    {
        if (!$this->eat($v)) {
            throw new ActionKitError('bad_source', "GraphQL parse error: expected '$v' near '" . ActionsImport::clip($this->cur()[1], 30) . "'");
        }
    }

    private function name(): string
    {
        $t = $this->next();
        if ($t[0] !== 'name') {
            throw new ActionKitError('bad_source', "GraphQL parse error: expected a name near '" . ActionsImport::clip($t[1], 30) . "'");
        }
        return $t[1];
    }

    private function desc(): ?string
    {
        return $this->cur()[0] === 'str' ? $this->next()[1] : null;
    }

    /** @return array<string,mixed> */
    private function type(int $depth = 0): array
    {
        if ($depth > $this->maxDepth) {
            throw new ActionKitError('import_limit', 'GraphQL type nesting is too deep');
        }
        if ($this->eat('[')) {
            $t = ['k' => 'list', 'of' => $this->type($depth + 1)];
            $this->expect(']');
        } else {
            $t = ['k' => 'named', 'name' => $this->name()];
        }
        return $this->eat('!') ? ['k' => 'nonnull', 'of' => $t] : $t;
    }

    private function value(int $depth = 0): void
    {
        if ($depth > $this->maxDepth) {
            throw new ActionKitError('import_limit', 'GraphQL value nesting is too deep');
        }
        $t = $this->cur();
        if ($t[0] === 'str' || $t[0] === 'int' || $t[0] === 'name') {
            $this->i++;
            return;
        }
        if ($this->eat('[')) {
            while (!$this->is(']') && $this->cur()[0] !== 'eof') {
                $this->value($depth + 1);
            }
            $this->expect(']');
            return;
        }
        if ($this->eat('{')) {
            while (!$this->is('}') && $this->cur()[0] !== 'eof') {
                $this->name();
                $this->expect(':');
                $this->value($depth + 1);
            }
            $this->expect('}');
            return;
        }
        if ($this->eat('$')) {
            $this->name();
            return;
        }
        throw new ActionKitError('bad_source', "GraphQL parse error: unexpected '" . ActionsImport::clip($t[1], 30) . "'");
    }

    private function directives(): bool
    {
        $deprecated = false;
        while ($this->eat('@')) {
            if ($this->name() === 'deprecated') {
                $deprecated = true;
            }
            if ($this->eat('(')) {
                while (!$this->is(')') && $this->cur()[0] !== 'eof') {
                    $this->name();
                    $this->expect(':');
                    $this->value();
                }
                $this->expect(')');
            }
        }
        return $deprecated;
    }

    /** @return list<array<string,mixed>> */
    private function args(): array
    {
        $out = [];
        if (!$this->eat('(')) {
            return $out;
        }
        while (!$this->is(')')) {
            if ($this->cur()[0] === 'eof') {
                throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated argument list');
            }
            $desc = $this->desc();
            $name = $this->name();
            $this->expect(':');
            $ty = $this->type();
            if ($this->eat('=')) {
                $this->value();
            }
            $this->directives();
            $a = ['name' => $name, 'type' => $ty];
            if ($desc !== null && $desc !== '') {
                $a['desc'] = $desc;
            }
            $out[] = $a;
        }
        $this->expect(')');
        return $out;
    }

    /** @return list<array<string,mixed>> */
    private function fields(bool $inp): array
    {
        $out = [];
        if (!$this->eat('{')) {
            return $out;
        }
        while (!$this->is('}')) {
            if ($this->cur()[0] === 'eof') {
                throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated field list');
            }
            $desc = $this->desc();
            $name = $this->name();
            $args = $inp ? [] : $this->args();
            $this->expect(':');
            $ty = $this->type();
            if ($inp && $this->eat('=')) {
                $this->value();
            }
            $d = $this->directives();
            $f = ['name' => $name, 'args' => $args, 'type' => $ty, 'deprecated' => $d];
            if ($desc !== null && $desc !== '') {
                $f['desc'] = $desc;
            }
            $out[] = $f;
        }
        $this->expect('}');
        return $out;
    }

    public function def(): void
    {
        $this->desc();
        $kw = $this->name();
        if ($kw === 'extend') {
            $this->def();
            return;
        }
        if ($kw === 'schema') {
            $this->directives();
            $this->expect('{');
            while (!$this->is('}')) {
                if ($this->cur()[0] === 'eof') {
                    throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated schema block');
                }
                $op = $this->name();
                $this->expect(':');
                $ty = $this->name();
                if (in_array($op, ['query', 'mutation', 'subscription'], true)) {
                    $this->schema->set($op, $ty);
                }
            }
            $this->expect('}');
            return;
        }
        if ($kw === 'scalar') {
            $n = $this->name();
            $this->directives();
            $this->merge(['kind' => 'scalar', 'name' => $n, 'fields' => [], 'values' => []]);
            return;
        }
        if ($kw === 'directive') {
            $this->expect('@');
            $this->name();
            $this->args();
            if ($this->cur()[1] === 'repeatable') {
                $this->i++;
            }
            if ($this->cur()[1] === 'on') {
                $this->i++;
            }
            $this->eat('|');
            $this->name();
            while ($this->eat('|')) {
                $this->name();
            }
            return;
        }
        if ($kw === 'type' || $kw === 'interface' || $kw === 'input') {
            $n = $this->name();
            if ($this->cur()[1] === 'implements') {
                $this->i++;
                $this->eat('&');
                $this->name();
                while ($this->eat('&')) {
                    $this->name();
                }
            }
            $this->directives();
            $this->merge(['kind' => $kw === 'type' ? 'object' : ($kw === 'input' ? 'input' : 'interface'), 'name' => $n, 'fields' => $this->fields($kw === 'input'), 'values' => []]);
            return;
        }
        if ($kw === 'union') {
            $n = $this->name();
            $this->directives();
            if ($this->eat('=')) {
                $this->eat('|');
                $this->name();
                while ($this->eat('|')) {
                    $this->name();
                }
            }
            $this->merge(['kind' => 'union', 'name' => $n, 'fields' => [], 'values' => []]);
            return;
        }
        if ($kw === 'enum') {
            $n = $this->name();
            $this->directives();
            $values = [];
            if ($this->eat('{')) {
                while (!$this->is('}')) {
                    if ($this->cur()[0] === 'eof') {
                        throw new ActionKitError('bad_source', 'GraphQL parse error: unterminated enum');
                    }
                    $this->desc();
                    $values[] = $this->name();
                    $this->directives();
                }
                $this->expect('}');
            }
            $this->merge(['kind' => 'enum', 'name' => $n, 'fields' => [], 'values' => $values]);
            return;
        }
        throw new ActionKitError('bad_source', "GraphQL parse error: unsupported definition '" . ActionsImport::clip($kw, 30) . "' (only type-system definitions are imported)");
    }

    /** @param array<string,mixed> $d */
    private function merge(array $d): void
    {
        $types = $this->schema->get('types');
        $old = $types->get($d['name']);
        if ($old === null) {
            $types->set($d['name'], $d);
            return;
        }
        $old['fields'] = array_merge($old['fields'], $d['fields']);
        $old['values'] = array_merge($old['values'], $d['values']);
        $types->set($d['name'], $old);
    }
}

/**
 * GraphQL SDL or introspection JSON to drafts (native port of import/graphql.ts of the reference actions package). Query fields are reads, Mutation fields
 * are writes, Subscription fields are streaming reads; arguments and input objects are flattened to dotted params. There is no method signal, so everything
 * stays `unreviewed`. A schema is an Obj {types: Obj name => typedef, query?, mutation?, subscription?}; a typedef is {kind, name, fields: [{name, args,
 * type, desc?, deprecated}], values}; a type is {k: "named"|"list"|"nonnull", ...}.
 */
final class ActionsImportGraphql
{
    /** The default token cap of parseGraphqlSdl. */
    public const DEFAULT_MAX_TOKENS = 2000000;
    private const NAME_START = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_';
    private const NAME_REST = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_0123456789';
    private const NUM_START = '-0123456789';
    private const NUM_REST = '-+.0123456789eE';
    private const PUNCT = '!$&():=@[]{|}';
    private const KINDS = ['OBJECT' => 'object', 'INPUT_OBJECT' => 'input', 'ENUM' => 'enum', 'SCALAR' => 'scalar', 'INTERFACE' => 'interface', 'UNION' => 'union'];
    private const SCALARS = [
        'Int' => ['type' => 'integer', 'format' => 'int32'], 'String' => ['type' => 'string'], 'ID' => ['type' => 'string'], 'Boolean' => ['type' => 'boolean'],
        'Float' => ['type' => 'number'], 'Date' => ['type' => 'string', 'format' => 'date'], 'DateTime' => ['type' => 'string', 'format' => 'date-time'],
        'Email' => ['type' => 'string', 'format' => 'email'], 'UUID' => ['type' => 'string', 'format' => 'uuid'], 'URL' => ['type' => 'string', 'format' => 'url'],
        'URI' => ['type' => 'string', 'format' => 'url'],
    ];

    /** The byte length of the UTF-8 character that starts with `$lead`. */
    private static function charLen(string $lead): int
    {
        $b = ord($lead);
        return $b >= 0xF0 ? 4 : ($b >= 0xE0 ? 3 : ($b >= 0xC0 ? 2 : 1));
    }

    /** @return list<array{string,string}> */
    private static function lex(string $src, int $maxTokens): array
    {
        $out = [];
        $n = strlen($src);
        $i = 0;
        $push = static function (array $t) use (&$out, $maxTokens): void {
            if (count($out) >= $maxTokens) {
                throw new ActionKitError('import_limit', 'the GraphQL source has too many tokens');
            }
            $out[] = $t;
        };
        while ($i < $n) {
            $ch = $src[$i];
            if ($ch === ' ' || $ch === "\t" || $ch === "\n" || $ch === "\r" || $ch === ',') {
                $i++;
                continue;
            }
            if ($ch === "\xEF" && substr($src, $i, 3) === "\xEF\xBB\xBF") {
                $i += 3;
                continue;
            }
            if ($ch === '#') {
                while ($i < $n && $src[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($ch === '"') {
                if (substr($src, $i, 3) === '"""') {
                    $j = $i + 3;
                    $s = '';
                    while ($j < $n && substr($src, $j, 3) !== '"""') {
                        if (substr($src, $j, 4) === '\\"""') {
                            $s .= '"""';
                            $j += 4;
                        } else {
                            $s .= $src[$j];
                            $j++;
                        }
                    }
                    if ($j >= $n) {
                        throw new ActionKitError('bad_source', 'unterminated GraphQL block string');
                    }
                    $push(['str', $s]);
                    $i = $j + 3;
                } else {
                    $j = $i + 1;
                    $s = '';
                    while ($j < $n && $src[$j] !== '"') {
                        if ($src[$j] === "\n") {
                            throw new ActionKitError('bad_source', 'unterminated GraphQL string');
                        }
                        if ($src[$j] === '\\') {
                            if ($j + 1 < $n) {
                                $len = self::charLen($src[$j + 1]);
                                $s .= substr($src, $j + 1, $len);
                                $j += 1 + $len;
                            } else {
                                $j += 2;
                            }
                        } else {
                            $s .= $src[$j];
                            $j++;
                        }
                    }
                    if ($j >= $n) {
                        throw new ActionKitError('bad_source', 'unterminated GraphQL string');
                    }
                    $push(['str', $s]);
                    $i = $j + 1;
                }
                continue;
            }
            if (strpos(self::NAME_START, $ch) !== false) {
                $j = $i + 1;
                while ($j < $n && strpos(self::NAME_REST, $src[$j]) !== false) {
                    $j++;
                }
                $push(['name', substr($src, $i, $j - $i)]);
                $i = $j;
                continue;
            }
            if (strpos(self::NUM_START, $ch) !== false) {
                $j = $i + 1;
                while ($j < $n && strpos(self::NUM_REST, $src[$j]) !== false) {
                    $j++;
                }
                $push(['int', substr($src, $i, $j - $i)]);
                $i = $j;
                continue;
            }
            if (substr($src, $i, 3) === '...') {
                $push(['punct', '...']);
                $i += 3;
                continue;
            }
            if (strpos(self::PUNCT, $ch) !== false) {
                $push(['punct', $ch]);
                $i++;
                continue;
            }
            throw new ActionKitError('bad_source', 'unexpected character in GraphQL source at offset ' . Js::len(substr($src, 0, $i)));
        }
        $push(['eof', '']);
        return $out;
    }

    /** SDL text to a schema model. */
    public static function parseGraphqlSdl(string $src, int $maxTokens = self::DEFAULT_MAX_TOKENS): Obj
    {
        $toks = self::lex($src, $maxTokens);
        $schema = Obj::of(['types' => new Obj()]);
        $p = new GraphqlSdlParser($toks, $schema, 32);
        while (!$p->atEof()) {
            $p->def();
        }
        return $schema;
    }

    // ---- introspection -> model -----------------------------------------------------------------------------------------

    /** @return array<string,mixed> */
    private static function introspectType(mixed $t, int $depth = 0): array
    {
        if ($depth > 16 || !($t instanceof Obj)) {
            throw new ActionKitError('bad_source', 'malformed introspection type reference');
        }
        if ($t->get('kind') === 'NON_NULL') {
            return ['k' => 'nonnull', 'of' => self::introspectType($t->get('ofType'), $depth + 1)];
        }
        if ($t->get('kind') === 'LIST') {
            return ['k' => 'list', 'of' => self::introspectType($t->get('ofType'), $depth + 1)];
        }
        if (!is_string($t->get('name'))) {
            throw new ActionKitError('bad_source', 'malformed introspection type reference');
        }
        return ['k' => 'named', 'name' => $t->get('name')];
    }

    /** @return array<string,mixed>|null */
    private static function fieldOf(mixed $f): ?array
    {
        if (!($f instanceof Obj) || !is_string($f->get('name'))) {
            return null;
        }
        $raw = $f->get('args');
        $args = [];
        foreach (is_array($raw) && array_is_list($raw) ? $raw : [] as $a) {
            if ($a instanceof Obj && is_string($a->get('name'))) {
                $e = ['name' => $a->get('name'), 'type' => self::introspectType($a->get('type'))];
                if (is_string($a->get('description'))) {
                    $e['desc'] = $a->get('description');
                }
                $args[] = $e;
            }
        }
        $out = ['name' => $f->get('name'), 'args' => $args, 'type' => !$f->has('type') ? ['k' => 'named', 'name' => 'String'] : self::introspectType($f->get('type')),
            'deprecated' => $f->get('isDeprecated') === true];
        if (is_string($f->get('description'))) {
            $out['desc'] = $f->get('description');
        }
        return $out;
    }

    /** An introspection result (`{data: {__schema}}` or `{__schema}`) to a schema model. Throws ActionKitError bad_source. */
    public static function fromIntrospection(mixed $doc): Obj
    {
        $root = $doc instanceof Obj && $doc->get('data') instanceof Obj ? $doc->get('data') : $doc;
        $s = $root instanceof Obj && $root->get('__schema') instanceof Obj ? $root->get('__schema') : null;
        if ($s === null || !is_array($s->get('types')) || !array_is_list($s->get('types'))) {
            throw new ActionKitError('bad_source', 'not a GraphQL introspection result (no __schema.types)');
        }
        $schema = Obj::of(['types' => new Obj()]);
        foreach (['query' => 'queryType', 'mutation' => 'mutationType', 'subscription' => 'subscriptionType'] as $key => $k) {
            $r = $s->get($k);
            $n = $r instanceof Obj && is_string($r->get('name')) ? $r->get('name') : null;
            if ($n !== null && $n !== '') {
                $schema->set($key, $n);
            }
        }
        foreach ($s->get('types') as $t) {
            if (!($t instanceof Obj) || !is_string($t->get('name')) || !is_string($t->get('kind'))) {
                continue;
            }
            if (str_starts_with($t->get('name'), '__')) {
                continue;
            }
            $kind = self::KINDS[$t->get('kind')] ?? null;
            if ($kind === null) {
                continue;
            }
            $raw = $kind === 'input' ? $t->get('inputFields') : $t->get('fields');
            $ev = $t->get('enumValues');
            $fields = [];
            foreach (is_array($raw) && array_is_list($raw) ? $raw : [] as $x) {
                $f = self::fieldOf($x);
                if ($f !== null) {
                    $fields[] = $f;
                }
            }
            $values = [];
            foreach (is_array($ev) && array_is_list($ev) ? $ev : [] as $e) {
                if ($e instanceof Obj && is_string($e->get('name'))) {
                    $values[] = $e->get('name');
                }
            }
            $schema->get('types')->set($t->get('name'), ['kind' => $kind, 'name' => $t->get('name'), 'fields' => $fields, 'values' => $values]);
        }
        return $schema;
    }

    // ---- model -> JSON-schema-like -> params ----------------------------------------------------------------------------

    /**
     * @param array<string,mixed> $t
     * @param list<string> $stack
     * @return array{Obj,bool} (the JSON-schema-like node, whether the type is non-null)
     */
    private static function schemaOf(array $t, Obj $gs, ImportCtx $c, ImportBudget $bud, array $stack, string $where): array
    {
        $nonnull = false;
        $cur = $t;
        while ($cur['k'] === 'nonnull') {
            $nonnull = true;
            $cur = $cur['of'];
        }
        if ($cur['k'] === 'list') {
            return [Obj::of(['type' => 'array', 'items' => self::schemaOf($cur['of'], $gs, $c, $bud, $stack, $where)[0]]), $nonnull];
        }
        $name = $cur['name'];
        $spent = $bud->left <= 0;
        $bud->left--;
        if ($spent) {
            if (!$bud->exhausted) {
                $bud->exhausted = true;
                ActionsImport::addTodo($c, $where, 'ref_budget', 'type expansion stopped at the node budget (declared string; refine or drop)');
            }
            return [new Obj(), $nonnull];
        }
        if (isset(self::SCALARS[$name])) {
            return [Obj::of(self::SCALARS[$name]), $nonnull];
        }
        $d = $gs->get('types')->get($name);
        if ($d === null) {
            ActionsImport::addTodo($c, $where, 'unknown_type', "type '" . ActionsImport::clip($name, 60) . "' is not defined in the schema (declared string)");
            return [new Obj(), $nonnull];
        }
        if ($d['kind'] === 'enum') {
            return [Obj::of(['type' => 'string', 'enum' => array_values(array_unique($d['values']))]), $nonnull];
        }
        if ($d['kind'] === 'scalar') {
            return [Obj::of(['type' => 'string']), $nonnull];
        }
        if ($d['kind'] === 'input') {
            if (in_array($name, $stack, true)) {
                ActionsImport::addTodo($c, $where, 'cyclic_ref', "input type '" . ActionsImport::clip($name, 60) . "' is recursive (declared string; refine or drop)");
                return [new Obj(), $nonnull];
            }
            $properties = new Obj();
            $required = [];
            foreach ($d['fields'] as $f) {
                [$r, $nn] = self::schemaOf($f['type'], $gs, $c, $bud, [...$stack, $name], $where);
                if ($f['name'] !== '__proto__') { // assigning `__proto__` on a JS object sets its prototype: never a member
                    $p = $r->without();
                    if (isset($f['desc']) && $f['desc'] !== '') {
                        $p->set('description', $f['desc']);
                    }
                    $properties->set($f['name'], $p);
                }
                if ($nn) {
                    $required[] = $f['name'];
                }
            }
            return [Obj::of(['type' => 'object', 'properties' => $properties, 'required' => $required]), $nonnull];
        }
        ActionsImport::addTodo($c, $where, 'output_type', "type '" . ActionsImport::clip($name, 60) . "' is an output type and cannot be an argument (declared string)");
        return [new Obj(), $nonnull];
    }

    /** `$source` is SDL text or an introspection result (parsed JSON). */
    public static function importGraphql(mixed $source, mixed $opts): Obj
    {
        $c = ActionsImport::newCtx('graphql', $source, $opts);
        $gs = is_string($source) ? self::parseGraphqlSdl($source) : self::fromIntrospection($source);
        $roots = [[$gs->has('query') ? $gs->get('query') : 'Query', 'query'], [$gs->has('mutation') ? $gs->get('mutation') : 'Mutation', 'mutation'],
            [$gs->has('subscription') ? $gs->get('subscription') : 'Subscription', 'subscription']];
        foreach ($roots as [$rootName, $op]) {
            $rt = $gs->get('types')->get($rootName);
            if ($rt === null) {
                continue;
            }
            $fields = $rt['fields'];
            usort($fields, static fn(array $a, array $b): int => strcmp($a['name'], $b['name']));
            foreach ($fields as $f) {
                $where = $op . ' ' . ActionsImport::clip($f['name'], 80);
                $c->root = null;
                $bud = ActionsImport::newBudget($c);
                $properties = new Obj();
                $required = [];
                foreach ($f['args'] as $a) {
                    [$r, $nn] = self::schemaOf($a['type'], $gs, $c, $bud, [], $where . '(' . $a['name'] . ')');
                    if ($a['name'] !== '__proto__') {
                        $p = $r->without();
                        if (isset($a['desc']) && $a['desc'] !== '') {
                            $p->set('description', $a['desc']);
                        }
                        $properties->set($a['name'], $p);
                    }
                    if ($nn) {
                        $required[] = $a['name'];
                    }
                }
                $params = new Obj();
                ActionsImport::flattenObject(Obj::of(['type' => 'object', 'properties' => $properties, 'required' => $required]), $c, $bud, $where, $params);
                if ($f['deprecated']) {
                    ActionsImport::addTodo($c, $where, 'deprecated', 'the field is marked @deprecated');
                }
                $desc = $f['desc'] ?? null;
                ActionsImport::emitDef(
                    $c, $f['name'], $op === 'mutation' ? ['update'] : ['read'], 'one', $params, Obj::of(['graphql' => Obj::of(['op' => $op, 'field' => ActionsImport::clip($f['name'], 200)])]),
                    null, $desc !== null && $desc !== '' ? explode("\n", $desc)[0] : $f['name'], $desc, $op !== 'mutation' ? Obj::of(['mode' => 'natural']) : null,
                    $op === 'subscription' ? ActionsImport::withTrait(null, 'pca.bulk') : null,
                );
            }
        }
        return ActionsImport::finish($c);
    }
}
