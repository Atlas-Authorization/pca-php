<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jsx.php';

/**
 * JSON Schema (draft 2020-12) documents for the PCA wire types (PCActn, Capability, the discovery document) and a small
 * dependency-free STRUCTURAL validator (the reference's pca-schema). The schemas describe structure only (fields, JSON types,
 * required); they cannot express security invariants (signature, attenuation, plan membership, iat < exp). Passing means
 * "well-formed", never "authorized". Every object is open (additionalProperties true) so an unknown future field never fails.
 *
 * The validator implements only the keywords these schemas use: type (incl. unions), enum, required, properties,
 * additionalProperties:false, items, and local '#/...' $ref. No pattern/format/oneOf/anyOf/bounds (minItems is published for
 * external validators but, as in the reference, not enforced here).
 */
final class PcaSchema
{
    public const DRAFT = 'https://json-schema.org/draft/2020-12/schema';

    private const ALL_JSON = <<<'JSON'
{
"PCActn":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/pcactn.schema.json","title":"PCActn","description":"Proof-Carrying Authority action object (spec §7, wire format v2).","type":"object","required":["ver","action","grant_ref","cap_chain","plan","attestation","provenance","freshness","counter","risk_claim","aud","iat","exp","sig"],"properties":{"ver":{"type":"integer"},"action":{"$ref":"#/$defs/action"},"grant_ref":{"type":"string"},"cap_chain":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/capability"}},"plan":{"$ref":"#/$defs/plan"},"attestation":{"$ref":"#/$defs/attestation"},"provenance":{"$ref":"#/$defs/provenance"},"freshness":{"$ref":"#/$defs/freshness"},"counter":{"type":"integer"},"risk_claim":{"$ref":"#/$defs/riskClaim"},"aud":{"type":"string"},"iat":{"type":"integer"},"exp":{"type":"integer"},"nonce":{"type":"string"},"caution":{"type":"number"},"rationale_commitment":{"type":"string"},"progress_step":{"type":"object","additionalProperties":true},"prohibition_evidence":{"type":["object","array"]},"tool_binding":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"sig":{"type":"string"},"pq_sig":{"type":"string"},"threshold":{"type":"object","additionalProperties":true},"zk_compliance":{"description":"Opaque zk-compliance proof; shape is verifier-defined."},"bond_ref":{"type":"string"}},"additionalProperties":true,"$defs":{"caveat":{"type":"object","required":["type"],"properties":{"type":{"type":"string"}},"additionalProperties":true},"capability":{"type":"object","required":["id","issuer","holder","caveats","body_digest","sig"],"properties":{"id":{"type":"string"},"issuer":{"type":"string"},"holder":{"type":"string"},"caveats":{"type":"array","items":{"$ref":"#/$defs/caveat"}},"parent":{"type":"string"},"body_digest":{"type":"string"},"sig":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"pq_sig":{"type":"string"}},"additionalProperties":true},"action":{"type":"object","required":["verb","resource","params_digest","reversibility_class"],"properties":{"verb":{"type":"string"},"resource":{"type":"string"},"params_digest":{"type":"string"},"reversibility_class":{"type":"string"}},"additionalProperties":true},"inclusionProof":{"type":"object","required":["index","size","path"],"properties":{"index":{"type":"integer"},"size":{"type":"integer"},"path":{"type":"array","items":{"type":"object","additionalProperties":true}}},"additionalProperties":true},"plan":{"type":"object","required":["root","inclusion_proof","node_id"],"properties":{"root":{"type":"string"},"inclusion_proof":{"$ref":"#/$defs/inclusionProof"},"node_id":{"type":"string"},"conditions_digest":{"type":"string"}},"additionalProperties":true},"riskClaim":{"type":"object","required":["r","inputs"],"properties":{"r":{"type":"number"},"inputs":{"type":"object","additionalProperties":true}},"additionalProperties":true},"attestation":{"type":"object","required":["quote_digest","epoch","model_id","measurement","operator"],"properties":{"quote_digest":{"type":"string"},"epoch":{"type":"integer"},"model_id":{"type":"string"},"measurement":{"type":"string"},"operator":{"type":"string"}},"additionalProperties":true},"provenance":{"type":"object","required":["causal_hash","taint_level","trusted_refs"],"properties":{"causal_hash":{"type":"string"},"taint_level":{"type":"number"},"trusted_refs":{"type":"array","items":{"type":"string"}}},"additionalProperties":true},"freshness":{"type":"object","required":["beacon_ref","epoch","accumulator_witness"],"properties":{"beacon_ref":{"type":"string"},"epoch":{"type":"integer"},"accumulator_witness":{"type":"string"}},"additionalProperties":true}}},
"Capability":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/capability.schema.json","title":"Capability","description":"An attenuable capability chain hop (spec §5.2).","type":"object","required":["id","issuer","holder","caveats","body_digest","sig"],"properties":{"id":{"type":"string"},"issuer":{"type":"string"},"holder":{"type":"string"},"caveats":{"type":"array","items":{"$ref":"#/$defs/caveat"}},"parent":{"type":"string"},"body_digest":{"type":"string"},"sig":{"type":"string"},"alg":{"type":"string","enum":["ed25519","ml-dsa-65","hybrid-ed25519-ml-dsa-65"]},"pq_pk":{"type":"string"},"pq_sig":{"type":"string"}},"additionalProperties":true,"$defs":{"caveat":{"type":"object","required":["type"],"properties":{"type":{"type":"string"}},"additionalProperties":true}}},
"PcaDiscoveryDocument":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://atlasauth.net/schemas/pca/discovery.schema.json","title":"PcaDiscoveryDocument","description":"The .well-known/pca-configuration discovery document (internet-wide integration).","type":"object","required":["audience","pca_versions","signature_suites","action_header"],"properties":{"audience":{"type":"string"},"pca_versions":{"type":"array","items":{"type":"integer"}},"signature_suites":{"type":"array","items":{"type":"string"}},"action_header":{"type":"string"},"required_checks":{"type":"array","items":{"type":"string"}},"endpoints":{"$ref":"#/$defs/endpoints"},"trusted_roots":{"type":"array","items":{"type":"string"}},"metadata":{"type":"object","additionalProperties":true}},"additionalProperties":true,"$defs":{"endpoints":{"type":"object","properties":{"attestation_challenge":{"type":"string"},"revocation_epoch":{"type":"string"},"liveness_beacon":{"type":"string"},"stepup":{"type":"string"},"grant":{"type":"string"}},"additionalProperties":true}}}
}

JSON;

    private static ?Obj $all = null;

    /** The published schemas by name: PCActn, Capability, PcaDiscoveryDocument. */
    public static function allSchemas(): Obj
    {
        return self::$all ??= (new Parser(self::ALL_JSON, PHP_INT_MAX))->run();
    }

    public static function named(string $name): Obj
    {
        $all = self::allSchemas();
        if (!$all->has($name)) {
            throw new \OutOfBoundsException("unknown schema $name");
        }
        return $all->get($name);
    }

    private static function isRecord(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function isInteger(mixed $v): bool
    {
        if (!Js::isNum($v)) {
            return false;
        }
        $f = Js::num($v);
        return $f !== null && is_finite($f) && floor($f) === $f;
    }

    /** A zero written with a minus sign: JSON.parse gives -0, which the reference does not count as an integer. */
    private static function negZero(mixed $v): bool
    {
        if ($v instanceof Num) {
            return $v->float() == 0.0 && str_starts_with($v->lexeme, '-');
        }
        return is_float($v) && $v == 0.0 && fdiv(1.0, $v) < 0;
    }

    public static function jsonTypeOf(mixed $v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (self::isList($v)) {
            return 'array';
        }
        if (is_bool($v)) {
            return 'boolean';
        }
        if (Js::isNum($v)) {
            return self::isInteger($v) ? 'integer' : 'number';
        }
        return is_string($v) ? 'string' : 'object';
    }

    private static function matchesType(mixed $expected, mixed $v): bool
    {
        switch ($expected) {
            case 'object':
                return self::isRecord($v);
            case 'array':
                return self::isList($v);
            case 'string':
                return is_string($v);
            case 'number':
                return Js::isNum($v) && is_finite((float)Js::num($v));
            case 'integer':
                return self::isInteger($v) && !self::negZero($v);
            case 'boolean':
                return is_bool($v);
            case 'null':
                return $v === null;
        }
        return false;
    }

    /** A local '#/...' pointer walked over own keys of objects only; null when it does not name an object. */
    private static function resolveRef(mixed $root, string $ref): ?Obj
    {
        if (!str_starts_with($ref, '#/')) {
            return null;
        }
        $cur = $root;
        foreach (explode('/', substr($ref, 2)) as $token) {
            if (!self::isRecord($cur) || !$cur->has($token)) {
                return null;
            }
            $cur = $cur->get($token);
        }
        return self::isRecord($cur) ? $cur : null;
    }

    private static function label(string $path): string
    {
        return $path === '' ? '(root)' : $path;
    }

    /** JS === over decoded JSON: objects and arrays never match (identity). */
    private static function strictEqual(mixed $a, mixed $b): bool
    {
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        if ($a === null || $b === null) {
            return $a === null && $b === null;
        }
        if (Js::isNum($a) && Js::isNum($b)) {
            return Js::num($a) == Js::num($b);
        }
        return is_string($a) && is_string($b) && $a === $b;
    }

    private static function join(string $path, string $key): string
    {
        return $path === '' ? $key : $path . '.' . $key;
    }

    /** @param list<string> $errors */
    private static function checkNode(mixed $schema, mixed $value, string $path, mixed $root, array &$errors): void
    {
        if ($schema === null) {
            throw new \TypeError('schema node is null');
        }
        if (!self::isRecord($schema)) {
            return; // a boolean/number schema constrains nothing in this subset
        }
        $ref = $schema->get('$ref');
        if (is_string($ref)) {
            $resolved = self::resolveRef($root, $ref);
            if ($resolved === null) {
                $errors[] = sprintf("%s: unresolved \$ref '%s'", self::label($path), $ref);
                return;
            }
            self::checkNode($resolved, $value, $path, $root, $errors);
            return;
        }
        if ($schema->has('type')) {
            $t = $schema->get('type');
            $types = self::isList($t) ? $t : [$t];
            $ok = false;
            foreach ($types as $x) {
                if (self::matchesType($x, $value)) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                $errors[] = sprintf('%s: expected type %s, got %s', self::label($path), implode('|', array_map(static fn($x) => Js::str($x), $types)), self::jsonTypeOf($value));
                return; // a wrong base type makes any deeper check meaningless
            }
        }
        $enum = $schema->get('enum');
        if (self::isList($enum)) {
            $found = false;
            foreach ($enum as $e) {
                if (self::strictEqual($e, $value)) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $errors[] = sprintf('%s: value is not one of [%s]', self::label($path), implode(', ', array_map(static fn($e) => Js::stringify($e), $enum)));
            }
        }
        if (self::isRecord($value)) {
            $required = $schema->get('required');
            if (self::isList($required)) {
                foreach ($required as $key) {
                    if (!is_string($key)) {
                        throw new \TypeError('unhashable required key');
                    }
                    if (!$value->has($key)) {
                        $errors[] = sprintf("%s: missing required property '%s'", self::join($path, $key), $key);
                    }
                }
            }
            $props = $schema->get('properties');
            if (Jsx::truthy($props) && self::isRecord($props)) {
                foreach ($props->keys() as $key) {
                    if ($value->has($key)) {
                        self::checkNode($props->get($key), $value->get($key), self::join($path, $key), $root, $errors);
                    }
                }
            }
            if ($schema->get('additionalProperties') === false && Jsx::truthy($props) && self::isRecord($props)) {
                foreach ($value->keys() as $key) {
                    if (!$props->has($key)) {
                        $errors[] = sprintf('%s: additional property not allowed', self::join($path, $key));
                    }
                }
            }
        }
        $items = $schema->get('items');
        if (self::isList($value) && Jsx::truthy($items)) {
            foreach ($value as $i => $el) {
                self::checkNode($items, $el, sprintf('%s[%d]', $path, $i), $root, $errors);
            }
        }
    }

    /** Structural validation: {valid, errors} (errors empty when valid). Never throws on a bad value. A string schema names a published one. */
    public static function validate(mixed $schema, mixed $value): Obj
    {
        $errors = [];
        $schema = is_string($schema) ? self::named($schema) : $schema;
        self::checkNode($schema, $value, '', $schema, $errors);
        return Obj::of(['valid' => $errors === [], 'errors' => $errors]);
    }
}
