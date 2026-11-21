<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/SsfStream.php';

/** One managed stream: owned by exactly one receiver. `subjects` maps a canonical subject key to its verified flag. */
final class StreamRecord implements \JsonSerializable
{
    /** @param list<string>|null $eventsRequested what the receiver asked for (a change of events_supported recomputes events_delivered) */
    public function __construct(
        public mixed $receiver,
        public Obj $config,
        public string $status = 'enabled',
        public ?array $eventsRequested = null,
        public ?string $statusReason = null,
        public ?Obj $subjects = null,
        public ?float $lastVerification = null,
    ) {
        $this->subjects ??= new Obj();
    }

    public function copy(): self
    {
        $c = clone $this;
        $c->config = SsfManage::deepCopy($this->config);
        $c->subjects = SsfManage::deepCopy($this->subjects);
        return $c;
    }

    /** @return array<string,mixed> */
    public function jsonSerialize(): array
    {
        $o = ['receiver' => $this->receiver, 'config' => $this->config];
        if ($this->eventsRequested !== null) {
            $o['events_requested'] = $this->eventsRequested;
        }
        $o['status'] = $this->status;
        if ($this->statusReason !== null) {
            $o['status_reason'] = $this->statusReason;
        }
        $o['subjects'] = $this->subjects;
        if ($this->lastVerification !== null) {
            $o['lastVerification'] = $this->lastVerification;
        }
        return $o;
    }
}

/** Where streams live. A store is any object with these four methods (get returns a COPY the caller may mutate, then `put`s back). */
interface StreamStore
{
    public function get(string $id): ?StreamRecord;

    public function put(string $id, StreamRecord $r): void;

    public function delete(string $id): void;

    /** @return list<array{0:string,1:StreamRecord}> */
    public function listByReceiver(mixed $receiver): array;
}

final class MemoryStreamStore implements StreamStore
{
    /** @var array<string,array{0:string,1:StreamRecord}> */
    private array $m = [];

    public function get(string $id): ?StreamRecord
    {
        return isset($this->m['k' . $id]) ? $this->m['k' . $id][1]->copy() : null;
    }

    public function put(string $id, StreamRecord $r): void
    {
        $this->m['k' . $id] = [$id, $r->copy()];
    }

    public function delete(string $id): void
    {
        unset($this->m['k' . $id]);
    }

    public function listByReceiver(mixed $receiver): array
    {
        $out = [];
        foreach ($this->m as [$id, $r]) {
            if ($r->receiver === $receiver) {
                $out[] = [$id, $r->copy()];
            }
        }
        return $out;
    }
}

/**
 * SSF stream management API (OpenID Shared Signals Framework 1.0, 8.1 and 7.1): create / read / update (PATCH) / replace (PUT) /
 * delete a stream, read / update its status, add / remove subjects, request a verification event, and the transmitter configuration
 * metadata. Framework-neutral: a request (Obj or array with method, path, query, body) in, ['status' => int, 'body' => ...] out. The HOST
 * authenticates the receiver and returns {id, aud}; a stream belongs to exactly one receiver and anyone else sees 404, never 403.
 */
final class SsfManage
{
    /** A deep copy of a parsed JSON value (Obj and lists are copied; scalars are immutable). */
    public static function deepCopy(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::deepCopy($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::deepCopy(...), $v) : $v;
    }

    /** SSF 7.1 transmitter configuration metadata (served at `/.well-known/ssf-configuration`). Options: issuer, deliveryMethods. */
    public static function transmitterMetadata(mixed $o, mixed $base, mixed $jwksUri = null): Obj
    {
        $out = Obj::of(['spec_version' => '1_0', 'issuer' => Js::opt($o, 'issuer')]);
        if (Js::truthy($jwksUri)) {
            $out->set('jwks_uri', $jwksUri);
        }
        $b = Js::str($base);
        $out->set('delivery_methods_supported', Js::opt($o, 'deliveryMethods') ?? [SsfStream::DELIVERY_PUSH, SsfStream::DELIVERY_POLL]);
        $out->set('configuration_endpoint', "$b/ssf/configuration");
        $out->set('status_endpoint', "$b/ssf/status");
        $out->set('add_subject_endpoint', "$b/ssf/add_subject");
        $out->set('remove_subject_endpoint', "$b/ssf/remove_subject");
        $out->set('verification_endpoint', "$b/ssf/verification");
        $out->set('default_subjects', 'NONE');
        return $out;
    }

    /**
     * The management handler. Options: store (a StreamStore), issuer, eventsSupported (list), pollEndpoint (Closure over the stream id),
     * signingKey, deliver (Closure over the StreamRecord and the verification SET), now (Closure, epoch seconds), and optional
     * deliveryMethods, maxStreamsPerReceiver (1), maxSubjectsPerStream (10000), newId (Closure). `$authenticate(req)` returns
     * the receiver {id, aud} or null (401). Any failure inside the handler is a 500 value, never an exception.
     *
     * @return \Closure(mixed):array{status:int,body?:mixed}
     */
    public static function ssfManagementHandler(mixed $o, \Closure $authenticate): \Closure
    {
        $api = new SsfManagementApi($o);
        return static function (mixed $req) use ($api, $authenticate): array {
            try {
                $rcv = $authenticate($req);
                if (!Js::truthy($rcv)) {
                    return ['status' => 401, 'body' => ['error' => 'unauthenticated']];
                }
                return $api->route($req, $rcv);
            } catch (\Throwable) {
                return ['status' => 500, 'body' => ['error' => 'server_error']];
            }
        };
    }
}

/** @internal the request router behind {@see SsfManage::ssfManagementHandler} */
final class SsfManagementApi
{
    /** @var list<string> */
    private array $methods;
    private StreamStore $store;
    private float $maxStreams;
    private float $maxSubjects;

    public function __construct(private readonly mixed $o)
    {
        $m = Js::opt($o, 'deliveryMethods');
        $this->methods = $m ?? [SsfStream::DELIVERY_PUSH, SsfStream::DELIVERY_POLL];
        $this->store = Js::opt($o, 'store');
        $this->maxStreams = (float) Js::num(Js::opt($o, 'maxStreamsPerReceiver') ?? 1);
        $this->maxSubjects = (float) Js::num(Js::opt($o, 'maxSubjectsPerStream') ?? 10000);
    }

    private function newId(): string
    {
        $f = Js::opt($this->o, 'newId');
        return $f !== null ? $f() : rtrim(strtr(base64_encode(random_bytes(12)), '+/', '-_'), '=');
    }

    private static function bad(string $m): array
    {
        return ['status' => 400, 'body' => ['error' => 'invalid_request', 'description' => $m]];
    }

    private static function notFound(): array
    {
        return ['status' => 404, 'body' => ['error' => 'not_found']];
    }

    private static function notAllowed(): array
    {
        return ['status' => 405, 'body' => ['error' => 'method_not_allowed']];
    }

    private function own(mixed $rcv, mixed $id): ?StreamRecord
    {
        if (!is_string($id)) {
            return null;
        }
        $r = $this->store->get($id);
        return $r !== null && $r->receiver === Js::opt($rcv, 'id') ? $r : null;
    }

    /** @return list<string> */
    private function delivered(?array $requested): array
    {
        $sup = Js::opt($this->o, 'eventsSupported');
        return $requested === null ? array_values($sup) : array_values(array_filter($sup, static fn($e) => in_array($e, $requested, true)));
    }

    private static function requestedOk(mixed $v): bool
    {
        if (!is_array($v) || !array_is_list($v) || $v === []) {
            return false;
        }
        foreach ($v as $e) {
            if (!is_string($e) || $e === '') {
                return false;
            }
        }
        return true;
    }

    /** @return array{0:bool,1:mixed} [ok, delivery Obj | reason] */
    private function deliveryFor(string $id, mixed $d, bool $given): array
    {
        $poll = fn(): Obj => Obj::of(['method' => SsfStream::DELIVERY_POLL, 'endpoint_url' => (Js::opt($this->o, 'pollEndpoint'))($id)]);
        if (!$given) {
            return in_array(SsfStream::DELIVERY_POLL, $this->methods, true) ? [true, $poll()] : [false, 'delivery is required: this transmitter does not support poll'];
        }
        $method = Js::opt($d, 'method');
        if (!Js::isObj($d) || !is_string($method) || !in_array($method, $this->methods, true)) {
            return [false, 'delivery.method is not supported by this transmitter'];
        }
        if ($method === SsfStream::DELIVERY_POLL) {
            return [true, $poll()]; // transmitter-set; a receiver value is ignored
        }
        $url = Js::opt($d, 'endpoint_url');
        if (!SsfStream::isHttpsUrl($url)) {
            return [false, 'push delivery needs an https endpoint_url'];
        }
        return [true, Obj::of(['method' => SsfStream::DELIVERY_PUSH, 'endpoint_url' => $url])];
    }

    /** `s.slice(0, n)` by UTF-16 code units (a cut surrogate pair leaves its lone high surrogate, as in JS). */
    private static function slice(string $s, int $n): string
    {
        if (Js::len($s) <= $n) {
            return $s;
        }
        $cps = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
        if ($cps === false) {
            return substr($s, 0, $n);
        }
        $out = '';
        $used = 0;
        foreach ($cps as $cp) {
            $u = strlen($cp) === 4 ? 2 : 1;
            if ($used + $u > $n) {
                if ($u === 2 && $used === $n - 1) {
                    $hi = 0xD800 + ((mb_ord($cp, 'UTF-8') - 0x10000) >> 10);
                    $out .= chr(0xE0 | ($hi >> 12)) . chr(0x80 | (($hi >> 6) & 0x3F)) . chr(0x80 | ($hi & 0x3F));
                }
                break;
            }
            $out .= $cp;
            $used += $u;
        }
        return $out;
    }

    private function build(string $id, mixed $rcv, ?array $requested, Obj $delivery, mixed $description): Obj
    {
        $c = Obj::of([
            'stream_id' => $id, 'iss' => Js::opt($this->o, 'issuer'), 'aud' => Js::opt($rcv, 'aud'),
            'events_supported' => array_values(Js::opt($this->o, 'eventsSupported')), 'events_delivered' => $this->delivered($requested), 'delivery' => $delivery,
        ]);
        if ($description !== null) {
            $c->set('description', self::slice($description, 256));
        }
        return $c;
    }

    /** The canonical key of a subject identifier (members sorted by UTF-16 code units, then JSON), or null when it is not one. */
    private static function subjectKey(mixed $s): ?string
    {
        $f = Js::opt($s, 'format');
        if (!($s instanceof Obj) || !is_string($f) || $f === '') {
            return null;
        }
        $u16 = static fn(string $k): string => (string) mb_convert_encoding($k, 'UTF-16BE', 'UTF-8');
        $keys = Js::ownKeys($s->keys());
        usort($keys, static fn(string $a, string $b): int => strcmp($u16($a), $u16($b)));
        $sorted = new Obj();
        foreach ($keys as $k) {
            $sorted->set($k, $s->get($k));
        }
        try {
            return Js::stringify($sorted);
        } catch (\Throwable) {
            return null;
        }
    }

    private static function statusBody(string $id, StreamRecord $s): array
    {
        $b = ['stream_id' => $id, 'status' => $s->status];
        if ($s->statusReason !== null) {
            $b['reason'] = $s->statusReason;
        }
        return ['status' => 200, 'body' => $b];
    }

    public function route(mixed $req, mixed $rcv): array
    {
        $path = Signals::prop($req, 'path');
        if (!is_string($path)) {
            throw new \TypeError('req.path.split is not a function');
        }
        $segs = array_values(array_filter(explode('/', $path), static fn(string $x): bool => $x !== ''));
        $seg = $segs === [] ? '' : $segs[count($segs) - 1];
        $q = Js::opt($req, 'query') ?? new Obj();
        $body = Js::opt($req, 'body');
        $b = $body instanceof Obj ? $body : null;
        $method = Js::opt($req, 'method');
        if (!is_string($method)) {
            throw new \TypeError('req.method.toUpperCase is not a function');
        }
        $m = mb_strtoupper($method);
        if (!in_array($seg, ['configuration', 'status', 'add_subject', 'remove_subject', 'verification'], true)) {
            return self::notFound();
        }
        $qid = Js::opt($q, 'stream_id');
        $qHas = Js::has($q, 'stream_id');

        if ($seg === 'configuration') {
            return match ($m) {
                'POST' => $this->create($rcv, $b),
                'GET' => $this->read($rcv, $qid, $qHas),
                'PATCH', 'PUT' => $this->update($rcv, $b, $m === 'PUT'),
                'DELETE' => $this->remove($rcv, $qid),
                default => self::notAllowed(),
            };
        }
        if ($seg === 'status') {
            return match ($m) {
                'GET' => $this->statusGet($rcv, $qid, $qHas),
                'POST' => $this->statusSet($rcv, $b),
                default => self::notAllowed(),
            };
        }
        if ($seg === 'add_subject' || $seg === 'remove_subject') {
            return $m === 'POST' ? $this->subject($rcv, $b, $seg === 'add_subject') : self::notAllowed();
        }
        return $m === 'POST' ? $this->verify($rcv, $b) : self::notAllowed();
    }

    private function create(mixed $rcv, ?Obj $b): array
    {
        if ($b === null) {
            return self::bad('a JSON object body is required');
        }
        foreach (Js::ownKeys($b->keys()) as $k) {
            if (!in_array($k, ['events_requested', 'delivery', 'description'], true)) {
                return self::bad("'$k' is not a receiver-supplied member");
            }
        }
        if ($b->has('events_requested') && !self::requestedOk($b->get('events_requested'))) {
            return self::bad('events_requested must be a non-empty array of event type URIs');
        }
        if ($b->has('description') && !is_string($b->get('description'))) {
            return self::bad('description must be a string');
        }
        if (!((float) count($this->store->listByReceiver(Js::opt($rcv, 'id'))) < $this->maxStreams)) {
            return ['status' => 409, 'body' => ['error' => 'conflict', 'description' => 'this receiver already has the maximum number of streams']];
        }
        $id = $this->newId();
        [$ok, $d] = $this->deliveryFor($id, $b->get('delivery'), $b->has('delivery'));
        if (!$ok) {
            return self::bad($d);
        }
        $requested = $b->has('events_requested') ? $b->get('events_requested') : null;
        if ($this->delivered($requested) === []) {
            return self::bad('none of events_requested is supported by this transmitter');
        }
        $config = $this->build($id, $rcv, $requested, $d, $b->has('description') ? $b->get('description') : null);
        $problems = SsfStream::validateStreamConfig($config);
        if ($problems !== []) {
            return self::bad(implode('; ', $problems));
        }
        $this->store->put($id, new StreamRecord(Js::opt($rcv, 'id'), $config, 'enabled', $requested));
        return ['status' => 201, 'body' => $config];
    }

    private function read(mixed $rcv, mixed $qid, bool $qHas): array
    {
        if (!$qHas) {
            return ['status' => 200, 'body' => array_map(static fn(array $p) => $p[1]->config, $this->store->listByReceiver(Js::opt($rcv, 'id')))];
        }
        $s = $this->own($rcv, $qid);
        return $s !== null ? ['status' => 200, 'body' => $s->config] : self::notFound();
    }

    private function update(mixed $rcv, ?Obj $b, bool $put): array
    {
        if ($b === null) {
            return self::bad('a JSON object body is required');
        }
        $s = $this->own($rcv, $b->get('stream_id'));
        if (!is_string($b->get('stream_id'))) {
            return self::bad('stream_id is required');
        }
        if ($s === null) {
            return self::notFound();
        }
        $supplied = ['events_requested', 'delivery', 'description', 'stream_id', 'iss', 'aud', 'events_supported', 'events_delivered', 'min_verification_interval'];
        foreach (Js::ownKeys($b->keys()) as $k) {
            if (!in_array($k, $supplied, true)) {
                return self::bad("unknown member '$k'");
            }
        }
        // Transmitter-supplied members may be present but must equal the expected value, checked BEFORE any update is applied.
        foreach (['stream_id', 'iss', 'aud', 'events_supported', 'events_delivered', 'min_verification_interval'] as $k) {
            if (!$b->has($k)) {
                continue;
            }
            $expected = $s->config->has($k) ? Js::stringify($s->config->get($k)) : null;
            if (Js::stringify($b->get($k)) !== $expected) {
                return self::bad("'$k' is transmitter-supplied and does not match");
            }
        }
        if ($b->has('events_requested') && !self::requestedOk($b->get('events_requested'))) {
            return self::bad('events_requested must be a non-empty array of event type URIs');
        }
        if ($b->has('description') && !is_string($b->get('description'))) {
            return self::bad('description must be a string');
        }
        $delivery = $s->config->get('delivery');
        if ($b->has('delivery') || $put) { // PUT: a missing delivery is a deleted one, i.e. the default
            [$ok, $d] = $this->deliveryFor((string) $s->config->get('stream_id'), $b->get('delivery'), $b->has('delivery'));
            if (!$ok) {
                return self::bad($d);
            }
            if ($d->get('method') !== Js::opt($s->config->get('delivery'), 'method')) {
                return self::bad('delivery.method cannot be changed: create a new stream');
            }
            $delivery = $d;
        }
        $requested = $put ? ($b->has('events_requested') ? $b->get('events_requested') : null) : ($b->has('events_requested') ? $b->get('events_requested') : $s->eventsRequested);
        $description = $put ? ($b->has('description') ? $b->get('description') : null) : ($b->has('description') ? $b->get('description') : $s->config->get('description'));
        if ($this->delivered($requested) === []) {
            return self::bad('none of events_requested is supported by this transmitter');
        }
        $id = (string) $s->config->get('stream_id');
        $next = $this->build($id, $rcv, $requested, $delivery, $description);
        if ($s->config->has('min_verification_interval')) {
            $next->set('min_verification_interval', $s->config->get('min_verification_interval'));
        }
        $s->config = $next;
        $s->eventsRequested = $requested;
        $this->store->put($id, $s);
        return ['status' => 200, 'body' => $next];
    }

    private function remove(mixed $rcv, mixed $qid): array
    {
        if ($this->own($rcv, $qid) === null) {
            return self::notFound();
        }
        $this->store->delete($qid);
        return ['status' => 204];
    }

    private function statusGet(mixed $rcv, mixed $qid, bool $qHas): array
    {
        $s = $this->own($rcv, $qid);
        if ($s === null) {
            return $qHas ? self::notFound() : self::bad('stream_id is required');
        }
        return self::statusBody($qid, $s);
    }

    private function statusSet(mixed $rcv, ?Obj $b): array
    {
        if ($b === null || !is_string($b->get('stream_id'))) {
            return self::bad('stream_id is required');
        }
        if (!in_array($b->get('status'), SsfStream::STREAM_STATUSES, true)) {
            return self::bad("status must be 'enabled', 'paused' or 'disabled'");
        }
        if ($b->has('reason') && !is_string($b->get('reason'))) {
            return self::bad('reason must be a string');
        }
        $s = $this->own($rcv, $b->get('stream_id'));
        if ($s === null) {
            return self::notFound();
        }
        $s->status = $b->get('status');
        $s->statusReason = $b->has('reason') ? $b->get('reason') : null;
        $this->store->put($b->get('stream_id'), $s);
        return self::statusBody($b->get('stream_id'), $s);
    }

    private function subject(mixed $rcv, ?Obj $b, bool $add): array
    {
        if ($b === null || !is_string($b->get('stream_id'))) {
            return self::bad('stream_id is required');
        }
        $key = self::subjectKey($b->get('subject'));
        if ($key === null) {
            return self::bad('subject must be a Subject Identifier object with a format');
        }
        if ($b->has('verified') && !is_bool($b->get('verified'))) {
            return self::bad('verified must be a boolean');
        }
        $s = $this->own($rcv, $b->get('stream_id'));
        if ($s === null) {
            return self::notFound();
        }
        $subjects = $s->subjects ?? new Obj();
        if ($add) {
            if (!$subjects->has($key) && (float) count($subjects->keys()) >= $this->maxSubjects) {
                return ['status' => 429, 'body' => ['error' => 'too_many_requests', 'description' => 'subject limit reached']];
            }
            $subjects->set($key, $b->has('verified') ? $b->get('verified') : true); // SSF: SHOULD assume verified when omitted
            $this->store->put($b->get('stream_id'), $s);
            return ['status' => 200];
        }
        $s->subjects = $subjects->without($key); // an unknown subject is silently ignored (204)
        $this->store->put($b->get('stream_id'), $s);
        return ['status' => 204];
    }

    private function verify(mixed $rcv, ?Obj $b): array
    {
        if ($b === null) {
            return self::bad('a JSON object body is required');
        }
        $id = $b->get('stream_id');
        $s = $this->own($rcv, $id);
        if ($s === null) {
            return is_string($id) ? self::notFound() : self::bad('stream_id is required');
        }
        if ($s->status === 'disabled') {
            return self::bad('the stream is disabled');
        }
        $now = Js::opt($this->o, 'now');
        $view = new VerificationStream($s->config, $s->lastVerification);
        $vreq = Obj::of(['stream_id' => $id]);
        if ($b->has('state')) {
            $vreq->set('state', $b->get('state'));
        }
        $out = SsfStream::handleVerificationRequest([$id => $view], $vreq, $now(), Js::opt($this->o, 'signingKey'));
        if ($out['status'] !== 204) {
            return ['status' => $out['status'], 'body' => ['error' => $out['status'] === 429 ? 'too_many_requests' : 'invalid_request', 'description' => $out['error']]];
        }
        $s->lastVerification = (float) Js::num($now());
        $this->store->put((string) $s->config->get('stream_id'), $s);
        (Js::opt($this->o, 'deliver'))($s, $out['set']);
        return ['status' => 204];
    }
}
