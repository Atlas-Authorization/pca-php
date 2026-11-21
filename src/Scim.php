<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentV2.php';

/**
 * SCIM 2.0 provisioning for PCA agents: the passport <-> SCIM `Agent` mapping, the framework-agnostic `/Agents` handler
 * (GET list + `eq` filter + paging, GET one, POST, PUT, PATCH, DELETE) over a pluggable AgentStore, and the outbound push
 * adapters for Microsoft Entra Agent ID and Okta with an injected fetch. Values are the parsed-JSON model (Obj, lists, Num).
 *
 * AGENT_SCHEMA_URN is a PCA-defined extension schema, not registered with IANA or the IETF.
 */
final class Scim
{
    public const AGENT_SCHEMA_URN = 'urn:ietf:params:scim:schemas:atlas:2.0:Agent';
    public const LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
    public const PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
    public const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
    public const AGENT_RESOURCE_TYPE = 'Agent';
    public const ENTRA_AGENT_EXTENSION_URN = 'urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent';
    public const OKTA_AGENT_EXTENSION_URN = 'urn:okta:scim:schemas:custom:1.0:Agent';
    public const SCIM_CONTENT_TYPE = 'application/scim+json';

    private const FILTERABLE = ['userName', 'displayName', 'externalId', 'id', 'active', 'owner'];
    private const MUTABLE_PATHS = ['active', 'displayName', 'externalId', 'owner', 'capabilities', 'holder'];

    // ---- passport re-exports ----------------------------------------------------------------------------------------

    public static function issuePassport(mixed $identity): Obj
    {
        return Sign::issuePassport($identity);
    }

    public static function passportFingerprint(mixed $identity): string
    {
        return Sign::passportFingerprint($identity);
    }

    /** @param list<Obj> $passports */
    public static function buildRegistry(array $passports): PassportRegistry
    {
        return new PassportRegistry($passports);
    }

    // ---- time -------------------------------------------------------------------------------------------------------

    /** Date.prototype.toISOString of new Date(ms): truncated to an integer ms, RangeError outside +-8.64e15. */
    public static function isoAt(mixed $ms): string
    {
        $f = Js::num($ms) ?? NAN;
        if (is_nan($f) || abs($f) > 8.64e15) {
            throw new \RangeError('Invalid time value');
        }
        $t = (int)($f < 0 ? ceil($f) : floor($f));
        $sec = intdiv($t, 1000) - (($t % 1000) < 0 ? 1 : 0);
        $msPart = $t - $sec * 1000;
        $dt = (new \DateTimeImmutable('@' . $sec))->setTimezone(new \DateTimeZone('UTC'));
        $y = (int)$dt->format('Y');
        $ys = $y >= 0 && $y <= 9999 ? sprintf('%04d', $y) : ($y < 0 ? '-' : '+') . sprintf('%06d', abs($y));
        return $ys . $dt->format('-m-d\TH:i:s') . sprintf('.%03dZ', $msPart);
    }

    private static function clock(mixed $now): string
    {
        return self::isoAt($now === null ? floor(microtime(true) * 1000) : $now());
    }

    // ---- passport <-> SCIM ------------------------------------------------------------------------------------------

    /** Build the `meta` block; `version` is an ETag over the resource without `meta`. */
    private static function buildMeta(string $id, Obj $sansMeta, mixed $input): Obj
    {
        $now = Js::opt($input, 'now');
        $base = Js::has($input, 'baseUrl') ? (string)preg_replace('#/+\z#', '', Js::str(Js::opt($input, 'baseUrl'))) : '';
        $location = $base . '/Agents/' . Js::encodeURIComponent($id);
        $created = Js::opt($input, 'created') ?? self::clock($now);
        $lastModified = Js::opt($input, 'lastModified') ?? self::clock($now);
        return Obj::of(['resourceType' => self::AGENT_RESOURCE_TYPE, 'created' => $created, 'lastModified' => $lastModified, 'location' => $location,
            'version' => 'W/"' . IntentV2::hashCanonical($sansMeta) . '"']);
    }

    /** Project a passport plus its governance attributes into a SCIM Agent; the passport id is the immutable SCIM id. */
    public static function passportToScim(Obj $passport, mixed $proj, mixed $meta = []): Obj
    {
        if (!Js::has($proj, 'owner')) {
            throw new JsonError('canonicalize: unsupported type undefined'); // owner is required; the reference fails hashing it
        }
        $id = $passport->get('id');
        $caps = Js::opt($proj, 'capabilities');
        $base = Obj::of([
            'schemas' => [self::AGENT_SCHEMA_URN],
            'id' => $id,
            'displayName' => Js::opt($proj, 'displayName') ?? (Js::str($passport->get('model_id')) . ' (' . Js::str($passport->get('operator')) . ')'),
            'active' => Js::opt($proj, 'active') ?? true,
            'owner' => Js::opt($proj, 'owner'),
            'capabilities' => Js::truthy($caps) ? Js::spread($caps) : [],
            'passportRef' => $id,
            'passport' => $passport,
        ]);
        foreach (['externalId', 'holder'] as $k) {
            if (Js::has($proj, $k)) {
                $base->set($k, Js::opt($proj, $k));
            }
        }
        $out = $base->without();
        $out->set('meta', self::buildMeta(Js::str($id), $base, $meta));
        return $out;
    }

    private static function asRecord(mixed $v): ?Obj
    {
        return $v instanceof Obj ? $v : null;
    }

    private static function asString(mixed $v): ?string
    {
        return is_string($v) ? $v : null;
    }

    private static function asBoolean(mixed $v): ?bool
    {
        return is_bool($v) ? $v : ($v === 'true' ? true : ($v === 'false' ? false : null));
    }

    private static function asStringArray(mixed $v): ?array
    {
        return Js::isStrList($v) ? $v : null;
    }

    private static function readIdentity(Obj $body): Obj
    {
        $nested = self::asRecord($body->get('passport'));
        if ($nested !== null) {
            $modelId = self::asString($nested->get('model_id'));
            $operator = self::asString($nested->get('operator'));
            if ($modelId === null || $operator === null) {
                throw new ScimValueError('invalidValue', 'passport.model_id and passport.operator are required');
            }
            $at = $nested->get('issued_at');
            $identity = Obj::of(['model_id' => $modelId, 'operator' => $operator, 'hardware_rooted' => self::asBoolean($nested->get('hardware_rooted')) ?? false,
                'issued_at' => Js::isNum($at) ? $at : 0]);
            foreach (['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'runtime_measurement'] as $k) {
                $s = self::asString($nested->get($k));
                if ($s !== null) {
                    $identity->set($k, $s);
                }
            }
            $measured = self::asBoolean($nested->get('weights_measured'));
            if ($measured !== null) {
                $identity->set('weights_measured', $measured);
            }
            return $identity;
        }
        $modelId = self::asString($body->get('model')) ?? self::asString($body->get('model_id'));
        $operator = self::asString($body->get('operator'));
        if ($modelId === null || $operator === null) {
            throw new ScimValueError('invalidValue', 'an Agent requires either a `passport` object or `model` + `operator`');
        }
        return Obj::of(['model_id' => $modelId, 'operator' => $operator, 'hardware_rooted' => self::asBoolean($body->get('hardwareRooted')) ?? false, 'issued_at' => 0]);
    }

    private static function readProjection(Obj $body): Obj
    {
        $owner = self::asString($body->get('owner')) ?? self::asString($body->get('operator'))
            ?? self::asString(self::asRecord($body->get('passport'))?->get('operator')) ?? '';
        $proj = Obj::of(['owner' => $owner]);
        $vals = ['displayName' => self::asString($body->get('displayName')), 'externalId' => self::asString($body->get('externalId')),
            'active' => self::asBoolean($body->get('active')), 'capabilities' => self::asStringArray($body->get('capabilities')), 'holder' => self::asString($body->get('holder'))];
        foreach ($vals as $k => $v) {
            if ($v !== null) {
                $proj->set($k, $v);
            }
        }
        return $proj;
    }

    /** Distil an untrusted SCIM Agent write body into {identity, projection}. Throws ScimValueError on a malformed body. */
    public static function scimToProvisioningRequest(mixed $value): Obj
    {
        $body = self::asRecord($value);
        if ($body === null) {
            throw new ScimValueError('invalidSyntax', 'request body must be a JSON object');
        }
        // RFC 7644 3.3: a body that declares schemas without the Agent one is not an Agent
        if ($body->has('schemas')) {
            $s = $body->get('schemas');
            if (!(is_array($s) && array_is_list($s) && in_array(self::AGENT_SCHEMA_URN, $s, true))) {
                throw new ScimValueError('invalidValue', 'schemas must include ' . self::AGENT_SCHEMA_URN);
            }
        }
        return Obj::of(['identity' => self::readIdentity($body), 'projection' => self::readProjection($body)]);
    }

    // ---- envelopes --------------------------------------------------------------------------------------------------

    public static function scimError(mixed $status, string $detail, ?string $scimType = null): Obj
    {
        $b = Obj::of(['schemas' => [self::ERROR_SCHEMA], 'status' => Js::str($status), 'detail' => $detail]);
        if ($scimType !== null) {
            $b->set('scimType', $scimType);
        }
        return $b;
    }

    public static function scimListResponse(array $resources, mixed $totalResults, mixed $startIndex): Obj
    {
        return Obj::of(['schemas' => [self::LIST_RESPONSE_SCHEMA], 'totalResults' => $totalResults, 'startIndex' => $startIndex,
            'itemsPerPage' => count($resources), 'Resources' => $resources]);
    }

    // ---- filter -----------------------------------------------------------------------------------------------------

    /**
     * Parse the `attr eq "value"` / `attr eq true|false` subset into {attr, value}. Byte-wise matching reproduces the
     * reference's non-unicode regex: ASCII \w and case folding, the JS whitespace set, `.` excluding line terminators.
     */
    public static function parseFilter(mixed $filter): Obj
    {
        if (!is_string($filter)) {
            throw new ScimValueError('invalidFilter', 'filter must be a string');
        }
        $ws = '(?:' . IntentWb::JS_WS . ')';
        $re = '/\A' . $ws . '*(\w+)' . $ws . '+eq' . $ws . '+(?:"((?:[^"\\\\]|\\\\(?![\n\r]|\xE2\x80[\xA8\xA9])[\s\S])*)"|(true|false))' . $ws . '*\z/i';
        if (preg_match($re, $filter, $m, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new ScimValueError('invalidFilter', 'unsupported filter (only `attr eq "value"` is supported): ' . $filter);
        }
        $attr = $m[1];
        if (!in_array($attr, self::FILTERABLE, true)) {
            throw new ScimValueError('invalidFilter', 'filter attribute not supported: ' . $attr);
        }
        if (($m[3] ?? null) !== null) {
            return Obj::of(['attr' => $attr, 'value' => strtolower($m[3]) === 'true']);
        }
        return Obj::of(['attr' => $attr, 'value' => (string)preg_replace('/\\\\([\s\S])/', '$1', $m[2] ?? '')]);
    }

    private static function matchesFilter(Obj $agent, Obj $f): bool
    {
        $v = $f->get('value');
        return match ($f->get('attr')) {
            'userName', 'displayName' => $agent->get('displayName') === $v,
            'externalId' => $agent->has('externalId') && $agent->get('externalId') === $v,
            'id' => $agent->get('id') === $v,
            'owner' => $agent->get('owner') === $v,
            'active' => $agent->get('active') === $v,
            default => false,
        };
    }

    // ---- PATCH ------------------------------------------------------------------------------------------------------

    /** @return list<Obj> */
    private static function readPatchOps(mixed $value): array
    {
        $body = self::asRecord($value);
        if ($body === null) {
            throw new ScimValueError('invalidSyntax', 'PATCH body must be a JSON object');
        }
        $ops = $body->get('Operations');
        if (!is_array($ops) || !array_is_list($ops) || $ops === []) {
            throw new ScimValueError('invalidValue', 'PATCH requires a non-empty Operations array');
        }
        $out = [];
        foreach ($ops as $raw) {
            $o = self::asRecord($raw);
            $rawOp = $o?->has('op') ? $o->get('op') : JsUndefined::U;
            $op = is_string($rawOp) ? mb_strtolower($rawOp, 'UTF-8') : null;
            if ($op !== 'add' && $op !== 'replace' && $op !== 'remove') {
                throw new ScimValueError('invalidValue', 'unsupported PATCH op: ' . ($rawOp === JsUndefined::U ? 'undefined' : Js::str($rawOp)));
            }
            $parsed = Obj::of(['op' => $op]);
            $path = self::asString($o->get('path'));
            if ($path !== null) {
                $parsed->set('path', $path);
            }
            if ($o->has('value')) {
                $parsed->set('value', $o->get('value'));
            }
            $out[] = $parsed;
        }
        return $out;
    }

    private static function projectionOf(Obj $resource): Obj
    {
        $proj = Obj::of(['owner' => $resource->get('owner'), 'active' => $resource->get('active'), 'capabilities' => Js::spread($resource->get('capabilities'))]);
        foreach (['displayName', 'externalId', 'holder'] as $k) {
            if ($resource->has($k)) {
                $proj->set($k, $resource->get($k));
            }
        }
        return $proj;
    }

    private static function applyScalar(Obj $proj, string $path, string $op, mixed $value): void
    {
        if ($path === 'active') {
            if ($op === 'remove') {
                $proj->set('active', true);
                return;
            }
            $b = self::asBoolean($value);
            if ($b === null) {
                throw new ScimValueError('invalidValue', '`active` must be a boolean');
            }
            $proj->set('active', $b);
            return;
        }
        if ($path === 'capabilities') {
            if ($op === 'remove') {
                $proj->set('capabilities', []);
                return;
            }
            $arr = self::asStringArray($value);
            if ($arr === null) {
                throw new ScimValueError('invalidValue', '`capabilities` must be a string array');
            }
            $proj->set('capabilities', $op === 'add' ? [...($proj->get('capabilities') ?? []), ...$arr] : $arr);
            return;
        }
        if ($op === 'remove') {
            if ($path === 'displayName' || $path === 'owner') {
                throw new ScimValueError('mutability', "`$path` cannot be removed");
            }
            $proj->set($path, JsUndefined::U); // deleted; Scim::defined drops it before the resource is rebuilt
            return;
        }
        $s = self::asString($value);
        if ($s === null) {
            throw new ScimValueError('invalidValue', "`$path` must be a string");
        }
        $proj->set($path, $s);
    }

    private static function applyPatchOp(Obj $proj, Obj $op): void
    {
        if (!$op->has('path')) {
            if ($op->get('op') === 'remove') {
                throw new ScimValueError('noTarget', 'a `remove` op requires a `path`');
            }
            $obj = self::asRecord($op->get('value'));
            if ($obj === null) {
                throw new ScimValueError('invalidValue', 'a pathless PATCH value must be an object');
            }
            foreach (Js::ownKeys($obj->keys()) as $key) {
                if (!in_array($key, self::MUTABLE_PATHS, true)) {
                    throw new ScimValueError('mutability', 'attribute is immutable or unknown: ' . $key);
                }
                self::applyScalar($proj, $key, 'replace', $obj->get($key));
            }
            return;
        }
        $path = $op->get('path');
        if (!in_array($path, self::MUTABLE_PATHS, true)) {
            throw new ScimValueError('mutability', 'attribute is immutable or unknown: ' . $path);
        }
        self::applyScalar($proj, $path, $op->get('op'), $op->get('value'));
    }

    // ---- the /Agents handler ----------------------------------------------------------------------------------------

    private static function response(int $status, mixed $body, array $headers = []): Obj
    {
        return Obj::of(['status' => $status, 'body' => $body, 'headers' => Obj::of(['content-type' => self::SCIM_CONTENT_TYPE] + $headers)]);
    }

    private static function errorResponse(int $status, string $detail, ?string $scimType = null): Obj
    {
        return self::response($status, self::scimError($status, $detail, $scimType));
    }

    private static function resourceResponse(int $status, Obj $resource): Obj
    {
        $meta = $resource->get('meta');
        return self::response($status, $resource, ['location' => $meta->get('location'), 'etag' => $meta->get('version')]);
    }

    /** ECMAScript Number() of a query value. */
    private static function toNumber(mixed $v): float
    {
        return match (true) {
            $v === null => 0.0,
            is_bool($v) => $v ? 1.0 : 0.0,
            Js::isNum($v) => (float)Js::num($v),
            is_string($v) => IntentWb::jsNumber($v),
            is_array($v) && array_is_list($v) => IntentWb::jsNumber(Js::str($v)),
            default => NAN,
        };
    }

    private static function parseIntParam(mixed $q, string $k, float $fallback): float
    {
        if (!Js::has($q, $k)) {
            return $fallback;
        }
        $n = self::toNumber(Js::opt($q, $k));
        return is_finite($n) && floor($n) === $n ? $n : $fallback;
    }

    private static function jsInt(float $f): int|float
    {
        return abs($f) <= 9007199254740992.0 ? (int)$f : $f;
    }

    /**
     * A SCIM 2.0 `/Agents` handler over `$store`: fn(request) => {status, body, headers}. A request is {method, id?, query?,
     * body?}. `authenticate` (a callable that must return exactly true) is required unless `allowUnauthenticated` is true.
     */
    public static function scimHandler(AgentStore $store, mixed $options = []): \Closure
    {
        $authenticate = Js::opt($options, 'authenticate');
        $isFn = $authenticate instanceof \Closure || (is_object($authenticate) && is_callable($authenticate));
        if (!$isFn && Js::opt($options, 'allowUnauthenticated') !== true) {
            throw new \TypeError('scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)');
        }
        $metaInput = static function () use ($options): array {
            $in = [];
            foreach (['baseUrl', 'now'] as $k) {
                if (Js::has($options, $k)) {
                    $in[$k] = Js::opt($options, $k);
                }
            }
            return $in;
        };
        $find = static fn(mixed $id): ?array => is_string($id) ? $store->get($id) : null;
        $notFound = static fn(mixed $id): Obj => self::errorResponse(404, 'Agent ' . Js::str($id) . ' not found');

        $list = static function (mixed $query) use ($store): Obj {
            $items = array_map(static fn(array $s) => $s['resource'], $store->all());
            // a list query's .filter is Array.prototype.filter: present and not a string
            $isList = is_array($query) && array_is_list($query) && $query !== [];
            if ($isList || (Js::has($query, 'filter') && Js::opt($query, 'filter') !== '')) {
                try {
                    $parsed = self::parseFilter($isList ? $query : Js::opt($query, 'filter'));
                } catch (ScimValueError $e) {
                    return self::errorResponse(400, $e->getMessage(), $e->scimType);
                }
                $items = array_values(array_filter($items, static fn(Obj $a) => self::matchesFilter($a, $parsed)));
            }
            $q = Js::isObj($query) ? $query : null;
            $total = count($items);
            $start = max(1.0, self::parseIntParam($q, 'startIndex', 1.0));
            $count = Js::has($q, 'count') ? max(0.0, self::parseIntParam($q, 'count', (float)$total)) : null;
            $from = (int)min($start - 1, (float)$total);
            $to = $count === null ? $total : (int)min((float)$total, $start - 1 + $count);
            $page = array_slice($items, $from, max(0, $to - $from));
            return self::response(200, self::scimListResponse($page, $total, self::jsInt($start)));
        };

        $rematerialize = static function (array $existing, Obj $proj) use ($metaInput): Obj {
            $meta = $metaInput();
            $meta['created'] = $existing['resource']->get('meta')->get('created');
            return self::passportToScim($existing['passport'], $proj, $meta);
        };

        $create = static function (mixed $body) use ($store, $metaInput): Obj {
            try {
                $req = self::scimToProvisioningRequest($body);
            } catch (ScimValueError $e) {
                return self::errorResponse(400, $e->getMessage(), $e->scimType);
            }
            $passport = Sign::issuePassport($req->get('identity'));
            if ($store->get($passport->get('id')) !== null) {
                return self::errorResponse(409, 'an agent with this attested identity already exists (id ' . $passport->get('id') . ')', 'uniqueness');
            }
            $resource = self::passportToScim($passport, $req->get('projection'), $metaInput());
            $store->put(['resource' => $resource, 'passport' => $passport]);
            return self::resourceResponse(201, $resource);
        };

        $replace = static function (mixed $id, mixed $body) use ($store, $find, $notFound, $rematerialize): Obj {
            $existing = $find($id);
            if ($existing === null) {
                return $notFound($id);
            }
            $b = self::asRecord($body);
            if ($b === null) {
                return self::errorResponse(400, 'request body must be a JSON object', 'invalidSyntax');
            }
            $proj = self::readProjection($b);
            if ($proj->get('owner') === '') {
                $proj->set('owner', $existing['resource']->get('owner')); // PUT keeps the existing owner when omitted
            }
            $resource = $rematerialize($existing, $proj);
            $store->put(['resource' => $resource, 'passport' => $existing['passport']]);
            return self::resourceResponse(200, $resource);
        };

        $patch = static function (mixed $id, mixed $body) use ($store, $find, $notFound, $rematerialize): Obj {
            $existing = $find($id);
            if ($existing === null) {
                return $notFound($id);
            }
            $proj = self::projectionOf($existing['resource']);
            try {
                foreach (self::readPatchOps($body) as $op) {
                    self::applyPatchOp($proj, $op);
                }
            } catch (ScimValueError $e) {
                return self::errorResponse(400, $e->getMessage(), $e->scimType);
            }
            $resource = $rematerialize($existing, self::defined($proj));
            $store->put(['resource' => $resource, 'passport' => $existing['passport']]);
            return self::resourceResponse(200, $resource);
        };

        return static function (mixed $req) use ($store, $authenticate, $isFn, $find, $notFound, $list, $create, $replace, $patch): Obj {
            if ($isFn) {
                try {
                    $ok = $authenticate($req) === true;
                } catch (\Throwable) {
                    $ok = false;
                }
                if (!$ok) {
                    $r = self::errorResponse(401, 'authentication required');
                    $r->set('headers', Obj::of(['content-type' => self::SCIM_CONTENT_TYPE, 'www-authenticate' => 'Bearer']));
                    return $r;
                }
            }
            $hasId = Js::has($req, 'id');
            $id = Js::opt($req, 'id');
            $method = Js::has($req, 'method') ? Js::opt($req, 'method') : JsUndefined::U;
            switch ($method) {
                case 'GET':
                    if (!$hasId) {
                        return $list(Js::has($req, 'query') ? Js::opt($req, 'query') : null);
                    }
                    $e = $find($id);
                    return $e === null ? $notFound($id) : self::resourceResponse(200, $e['resource']);
                case 'POST':
                    return $hasId ? self::errorResponse(405, 'POST is not allowed on an individual Agent') : $create(Js::opt($req, 'body'));
                case 'PUT':
                    return $hasId ? $replace($id, Js::opt($req, 'body')) : self::errorResponse(405, 'PUT requires an Agent id');
                case 'PATCH':
                    return $hasId ? $patch($id, Js::opt($req, 'body')) : self::errorResponse(405, 'PATCH requires an Agent id');
                case 'DELETE':
                    if (!$hasId) {
                        return self::errorResponse(405, 'DELETE requires an Agent id');
                    }
                    if (!is_string($id) || !$store->delete($id)) {
                        return $notFound($id);
                    }
                    return Obj::of(['status' => 204, 'headers' => new Obj()]);
                default:
                    return self::errorResponse(405, 'method not allowed: ' . ($method === JsUndefined::U ? 'undefined' : Js::str($method)));
            }
        };
    }

    /** The projection without members a PATCH `remove` cleared. */
    private static function defined(Obj $proj): Obj
    {
        $out = new Obj();
        foreach ($proj->keys() as $k) {
            if ($proj->get($k) !== JsUndefined::U) {
                $out->set($k, $proj->get($k));
            }
        }
        return $out;
    }

    // ---- push adapters ----------------------------------------------------------------------------------------------

    private static function extensionAttributes(Obj $agent): Obj
    {
        $p = $agent->get('passport');
        $attrs = Obj::of(['owner' => $agent->get('owner'), 'model' => Js::get($p, 'model_id'), 'operator' => Js::get($p, 'operator'),
            'hardwareRooted' => Js::get($p, 'hardware_rooted'), 'capabilities' => Js::spread($agent->get('capabilities')), 'passportRef' => $agent->get('passportRef')]);
        if ($agent->has('holder')) {
            $attrs->set('holder', $agent->get('holder'));
        }
        return $attrs;
    }

    /** The provisioning body for Microsoft Entra Agent ID; externalId falls back to the content-addressed passport id. */
    public static function toEntraAgentPayload(Obj $agent): Obj
    {
        return Obj::of(['schemas' => [self::AGENT_SCHEMA_URN, self::ENTRA_AGENT_EXTENSION_URN], 'externalId' => $agent->get('externalId') ?? $agent->get('passportRef'),
            'displayName' => $agent->get('displayName'), 'active' => $agent->get('active'), self::ENTRA_AGENT_EXTENSION_URN => self::extensionAttributes($agent)]);
    }

    /** The provisioning body for Okta: userName is the stable passport id, the agent attributes sit under a custom extension. */
    public static function toOktaScimPayload(Obj $agent): Obj
    {
        return Obj::of(['schemas' => [self::AGENT_SCHEMA_URN, self::OKTA_AGENT_EXTENSION_URN], 'userName' => $agent->get('passportRef'),
            'externalId' => $agent->get('externalId') ?? $agent->get('passportRef'), 'displayName' => $agent->get('displayName'), 'active' => $agent->get('active'),
            self::OKTA_AGENT_EXTENSION_URN => self::extensionAttributes($agent)]);
    }

    /**
     * POST a shaped payload to `target.endpoint` with `Bearer target.token`. `target.fetch` is required (PHP has no global
     * fetch): fn(string $url, array{method, headers, body} $init) => array{ok: bool, status: int, json: callable(): mixed}.
     * A body that fails to parse reads as null. Returns {ok, status, body}.
     */
    public static function pushProvision(Obj $payload, mixed $target): Obj
    {
        $f = Js::opt($target, 'fetch');
        if (!is_callable($f) || is_string($f)) {
            throw new \InvalidArgumentException('pushProvision: no fetch available — pass one explicitly');
        }
        $res = $f(Js::str(Js::opt($target, 'endpoint')), ['method' => 'POST',
            'headers' => ['authorization' => 'Bearer ' . Js::str(Js::opt($target, 'token')), 'content-type' => self::SCIM_CONTENT_TYPE], 'body' => Js::stringify($payload)]);
        try {
            $body = ($res['json'])();
        } catch (\Throwable) {
            $body = null;
        }
        return Obj::of(['ok' => (bool)$res['ok'], 'status' => $res['status'], 'body' => $body]);
    }

    public static function pushToEntra(Obj $agent, mixed $target): Obj
    {
        return self::pushProvision(self::toEntraAgentPayload($agent), $target);
    }

    public static function pushToOkta(Obj $agent, mixed $target): Obj
    {
        return self::pushProvision(self::toOktaScimPayload($agent), $target);
    }
}

/** A malformed SCIM value; `scimType` is the RFC 7644 error type (invalidSyntax, invalidValue, invalidFilter, mutability, noTarget). */
final class ScimValueError extends \InvalidArgumentException
{
    public function __construct(public readonly string $scimType, string $detail)
    {
        parent::__construct($detail);
    }
}

/** A read-only passport registry. */
final class PassportRegistry
{
    /** @var array<string, Obj> */
    private array $byId = [];

    /** @param list<Obj> $passports */
    public function __construct(array $passports)
    {
        foreach ($passports as $p) {
            $this->byId['k' . Js::str($p->get('id'))] = $p;
        }
    }

    public function get(string $id): ?Obj
    {
        return $this->byId['k' . $id] ?? null;
    }

    public function has(string $id): bool
    {
        return isset($this->byId['k' . $id]);
    }

    /** @return list<Obj> */
    public function all(): array
    {
        return array_values($this->byId);
    }
}

/**
 * The persistence seam the SCIM handler writes through; a stored agent is ['resource' => Obj, 'passport' => Obj]. All SCIM
 * semantics live in Scim::scimHandler; a store only stores and fetches.
 */
interface AgentStore
{
    /** @return list<array{resource: Obj, passport: Obj}> */
    public function all(): array;

    /** @return array{resource: Obj, passport: Obj}|null */
    public function get(string $id): ?array;

    /** Create or replace by resource id. */
    public function put(array $stored): void;

    /** Remove by id; whether a row existed. */
    public function delete(string $id): bool;

    public function registry(): PassportRegistry;
}

/** The default in-memory AgentStore; insertion order is kept for stable list output. */
final class MemoryAgentStore implements AgentStore
{
    private array $byId = [];

    public function __construct(array $seed = [])
    {
        foreach ($seed as $s) {
            $this->put($s);
        }
    }

    public function all(): array
    {
        return array_values($this->byId);
    }

    public function get(string $id): ?array
    {
        return $this->byId['k' . $id] ?? null;
    }

    public function put(array $stored): void
    {
        $this->byId['k' . Js::str($stored['resource']->get('id'))] = $stored;
    }

    public function delete(string $id): bool
    {
        if (!array_key_exists('k' . $id, $this->byId)) {
            return false;
        }
        unset($this->byId['k' . $id]);
        return true;
    }

    public function registry(): PassportRegistry
    {
        return new PassportRegistry(array_map(static fn(array $s) => $s['passport'], $this->all()));
    }
}
