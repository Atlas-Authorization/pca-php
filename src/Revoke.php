<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * A revocation store. Entries are assoc arrays {kind, value, prefix?, reason, revokedAt (epoch ms), notBefore?}, the same JSON
 * shape the TypeScript package stores. `all()` is a snapshot; `add` at an existing (kind, value) replaces.
 */
interface RevocationStore
{
    public function add(array $entry): void;

    public function remove(string $kind, string $value): bool;

    public function get(string $kind, string $value): ?array;

    /** @return list<array> */
    public function all(): array;

    public function clear(): void;
}

/** In-memory store (the default). One process; swap in a shared store for a fleet. */
class InMemoryRevocationStore implements RevocationStore
{
    /** @var array<string,array> "kind\0value" => entry, in insertion order */
    protected array $m = [];

    protected static function key(mixed $kind, mixed $value): string
    {
        return Js::stringify([is_string($kind) ? $kind : null, is_string($value) ? $value : null]);
    }

    public function add(array $entry): void
    {
        $this->m[self::key($entry['kind'] ?? null, $entry['value'] ?? null)] = $entry;
    }

    public function remove(string $kind, string $value): bool
    {
        $k = self::key($kind, $value);
        if (!array_key_exists($k, $this->m)) {
            return false;
        }
        unset($this->m[$k]);
        return true;
    }

    public function get(string $kind, string $value): ?array
    {
        return $this->m[self::key($kind, $value)] ?? null;
    }

    public function all(): array
    {
        return array_values($this->m);
    }

    public function clear(): void
    {
        $this->m = [];
    }
}

/**
 * A durable store backed by one JSON file. Every change is written to a temporary file, flushed, then renamed over the real file,
 * so a crash leaves the old or the new contents, never a torn file. Single process: two processes must not share one file.
 * Fail closed: a file that exists but does not hold a valid entry list makes the constructor throw (starting empty would
 * un-revoke everything).
 */
final class FileRevocationStore extends InMemoryRevocationStore
{
    public function __construct(private readonly string $path)
    {
        if (!file_exists($path)) {
            return;
        }
        $text = @file_get_contents($path);
        try {
            $parsed = $text === false ? null : Json::parseLax($text);
        } catch (\Throwable) {
            $parsed = null;
        }
        if ($text === false || $parsed === null) {
            throw new \UnexpectedValueException('FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty');
        }
        $list = Js::opt($parsed, 'entries');
        $entries = [];
        foreach (is_array($list) && array_is_list($list) ? $list : [null] as $e) {
            $a = Revoke::toArray($e);
            if ($a === null || !Revoke::validEntry($a)) {
                throw new \UnexpectedValueException('FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty');
            }
            $entries[] = $a;
        }
        foreach ($entries as $e) {
            $this->m[self::key($e['kind'], $e['value'])] = $e;
        }
    }

    private function flush(): void
    {
        $tmp = $this->path . '.tmp';
        $body = Js::stringify(['v' => 1, 'entries' => array_values($this->m)]);
        $h = @fopen($tmp, 'wb');
        if ($h === false) {
            throw new \RuntimeException('FileRevocationStore: cannot write the revocation file');
        }
        try {
            @chmod($tmp, 0600);
            if (fwrite($h, $body) !== strlen($body) || !fflush($h) || (function_exists('fsync') && !fsync($h))) {
                throw new \RuntimeException('FileRevocationStore: cannot write the revocation file');
            }
        } finally {
            fclose($h);
        }
        if (!@rename($tmp, $this->path)) {
            throw new \RuntimeException('FileRevocationStore: cannot replace the revocation file');
        }
    }

    /** Apply a change and flush; on a failed flush put memory back, so memory never claims more than disk. */
    private function write(callable $change): mixed
    {
        $before = $this->m;
        $out = $change();
        try {
            $this->flush();
        } catch (\Throwable $e) {
            $this->m = $before;
            throw $e;
        }
        return $out;
    }

    public function add(array $entry): void
    {
        $this->write(fn() => parent::add($entry));
    }

    public function remove(string $kind, string $value): bool
    {
        return $this->write(fn(): bool => parent::remove($kind, $value));
    }

    public function clear(): void
    {
        $this->write(fn() => parent::clear());
    }
}

/** A live, mutable registry of revocations over any store (the in-memory one by default). */
final class RevocationRegistry
{
    public readonly RevocationStore $store;

    public function __construct(?RevocationStore $store = null)
    {
        $this->store = $store ?? new InMemoryRevocationStore();
    }

    /**
     * Revoke a capability id, holder key, issuer key, or subtree prefix; returns the stored entry. `$input` is {kind, value |
     * prefix, reason?, revokedAt?, notBefore?} (an Obj or an assoc array); a malformed one throws \TypeError.
     */
    public function revoke(mixed $input): array
    {
        if (!Js::isObj($input)) {
            throw new \TypeError('revoke: input must be an object');
        }
        $revokedAt = Js::opt($input, 'revokedAt') ?? Revoke::nowMs();
        $reason = Js::opt($input, 'reason') ?? '';
        if (!Revoke::finite($revokedAt)) {
            throw new \TypeError('revoke: revokedAt must be a finite number');
        }
        $hasNb = Js::has($input, 'notBefore');
        if ($hasNb && !Revoke::finite(Js::opt($input, 'notBefore'))) {
            throw new \TypeError('revoke: notBefore must be a finite number');
        }
        if (!is_string($reason)) {
            throw new \TypeError('revoke: reason must be a string');
        }
        $kind = Js::opt($input, 'kind');
        if ($kind === 'prefix') {
            $p = Js::opt($input, 'prefix');
            if (!is_array($p) || !array_is_list($p) || $p === []) {
                throw new \TypeError('revoke: a prefix revocation requires a non-empty cap-id path');
            }
            foreach ($p as $x) {
                // the path is joined with ',': an element holding one would alias a different path
                if (!is_string($x) || $x === '' || str_contains($x, Revoke::PREFIX_SEP)) {
                    throw new \TypeError("revoke: every prefix element must be a non-empty string without ','");
                }
            }
            $entry = ['kind' => 'prefix', 'value' => implode(Revoke::PREFIX_SEP, $p), 'prefix' => $p, 'reason' => $reason, 'revokedAt' => $revokedAt];
        } else {
            // stricter than the reference, which would store a kind-less entry that no lookup can ever match
            if (!is_string($kind)) {
                throw new \TypeError('revoke: kind must be a string');
            }
            $value = Js::opt($input, 'value');
            if (!is_string($value) || $value === '') {
                throw new \TypeError("revoke: a $kind revocation requires a non-empty value");
            }
            $entry = ['kind' => $kind, 'value' => $value, 'reason' => $reason, 'revokedAt' => $revokedAt];
        }
        if ($hasNb) {
            $entry['notBefore'] = Js::opt($input, 'notBefore');
        }
        $this->store->add($entry);
        return $entry;
    }

    /**
     * Revoke a delegation subtree: a root cap id (string) revokes every chain through it; an ordered cap-id path (list) revokes
     * every chain whose hops begin with it. Options: reason, revokedAt, notBefore.
     */
    public function revokeSubtree(mixed $target, mixed $opts = null): array
    {
        $in = is_array($target) && array_is_list($target) ? ['kind' => 'prefix', 'prefix' => $target] : ['kind' => 'cap', 'value' => $target];
        foreach ($opts instanceof Obj ? $opts->keys() : (is_array($opts) ? array_keys($opts) : []) as $k) {
            $in[(string)$k] = Js::opt($opts, (string)$k);
        }
        return $this->revoke($in);
    }

    /** Remove a revocation ({kind, value} or {kind: 'prefix', prefix}); true when one was removed. */
    public function unrevoke(mixed $key): bool
    {
        if (!Js::isObj($key)) {
            throw new \TypeError('unrevoke: key must be an object');
        }
        $kind = Js::opt($key, 'kind');
        if ($kind === 'prefix') {
            $p = Js::opt($key, 'prefix');
            // a non-string element could never have been stored; refusing keeps the revocation (fail closed)
            if (!Js::isStrList($p) || $p === []) {
                return false;
            }
            return $this->store->remove('prefix', implode(Revoke::PREFIX_SEP, $p));
        }
        $value = Js::opt($key, 'value');
        return is_string($kind) && is_string($value) && $this->store->remove($kind, $value);
    }

    /** @return list<array> */
    public function list(): array
    {
        return $this->store->all();
    }

    public function lookup(string $kind, string $value): ?array
    {
        return $this->store->get($kind, $value);
    }

    /** @return list<array> */
    public function prefixes(): array
    {
        return array_values(array_filter($this->store->all(), static fn(array $e): bool => ($e['kind'] ?? null) === 'prefix'));
    }

    public function clear(): void
    {
        $this->store->clear();
    }

    /** KILL-SWITCH: instantly revoke an agent by its holder key (no notBefore, so it bites at once). */
    public function killAgent(mixed $holder, mixed $reason = null, mixed $revokedAt = null): array
    {
        return $this->revoke(['kind' => 'holder', 'value' => $holder, 'reason' => $reason ?? 'kill-switch: agent killed', 'revokedAt' => $revokedAt]);
    }

    /** KILL-SWITCH: instantly revoke the delegation subtree rooted at a cap id. */
    public function killSubtree(mixed $rootCapId, mixed $reason = null, mixed $revokedAt = null): array
    {
        return $this->revoke(['kind' => 'cap', 'value' => $rootCapId, 'reason' => $reason ?? 'kill-switch: subtree killed', 'revokedAt' => $revokedAt]);
    }
}

/**
 * Realtime revocation and a mid-run kill-switch (the TypeScript reference, @atlasauth/pca-revoke). The core verifier is a pull
 * check; this adds the ACTIVE boundary: checkRevocation walks EVERY hop of a PCActn's cap_chain and fails closed;
 * verifyWithRevocation ANDs the core outcome with that gate; ingestCaepEvent turns an OpenID Shared-Signals / CAEP event into
 * registry entries.
 */
final class Revoke
{
    public const PREFIX_SEP = ',';
    public const KINDS = ['cap', 'holder', 'issuer', 'prefix'];
    public const CAEP_EVENT_TYPES = [
        'sessionRevoked' => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'grantRevoked' => 'https://atlasauth.net/caep/grant-revoked',
        'killSwitch' => 'https://atlasauth.net/caep/kill-switch',
    ];

    public static function nowMs(): int
    {
        return (int)floor(microtime(true) * 1000);
    }

    /** A finite JSON number (not a bool). */
    public static function finite(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f);
    }

    private static function nonEmpty(mixed $v): bool
    {
        return is_string($v) && $v !== '';
    }

    /** An entry-shaped JSON object as an assoc array, else null. */
    public static function toArray(mixed $e): ?array
    {
        if ($e instanceof Obj) {
            $a = [];
            foreach ($e->keys() as $k) {
                $a[$k] = $e->get($k);
            }
            return $a;
        }
        return is_array($e) && ($e === [] || !array_is_list($e)) ? $e : null;
    }

    public static function validEntry(array $e): bool
    {
        if (!in_array($e['kind'] ?? null, self::KINDS, true) || !self::nonEmpty($e['value'] ?? null) || !is_string($e['reason'] ?? null)
            || !self::finite($e['revokedAt'] ?? null)) {
            return false;
        }
        if (array_key_exists('notBefore', $e) && !self::finite($e['notBefore'])) {
            return false;
        }
        if ($e['kind'] === 'prefix') {
            $p = $e['prefix'] ?? null;
            if (!Js::isStrList($p) || $p === [] || in_array('', $p, true) || implode(self::PREFIX_SEP, $p) !== $e['value']) {
                return false;
            }
        }
        return true;
    }

    /** True when a revocation is in effect at `$now` (a future notBefore has not yet been reached). */
    public static function isActiveAt(mixed $entry, mixed $now): bool
    {
        if (!Js::has($entry, 'notBefore')) {
            return true;
        }
        $nb = Js::opt($entry, 'notBefore');
        // a non-finite clock or schedule can never be shown to be "in the future", so it bites
        if (!self::finite($now) || !self::finite($nb)) {
            return true;
        }
        return Js::num($now) >= Js::num($nb);
    }

    private static function matchReason(array $e): string
    {
        $base = "{$e['kind']} {$e['value']} is revoked";
        return $e['reason'] !== '' ? "$base: {$e['reason']}" : $base;
    }

    private static function startsWith(array $ids, mixed $prefix): bool
    {
        if (!is_array($prefix) || $prefix === [] || count($ids) < count($prefix)) {
            return false;
        }
        foreach (array_values($prefix) as $i => $p) {
            if ($ids[$i] !== $p) {
                return false;
            }
        }
        return true;
    }

    private static function closed(string $why): array
    {
        return ['revoked' => true, 'reason' => 'revocation check failed closed: ' . $why];
    }

    /**
     * Is any authority in this PCActn's cap_chain revoked at `$now` (default: the clock)? Never throws and never reports "not
     * revoked" because it could not look: a missing or malformed chain, a hop whose id, issuer or holder is not a non-empty
     * string, a non-finite now, or a store that throws all yield revoked: true with a reason starting "revocation check failed closed".
     */
    public static function checkRevocation(mixed $p, RevocationRegistry $registry, mixed $now = null): array
    {
        $now ??= self::nowMs();
        if (!self::finite($now)) {
            return self::closed('clock is not a finite number');
        }
        $chain = Js::opt($p, 'cap_chain');
        if (!is_array($chain) || !array_is_list($chain) || $chain === []) {
            return self::closed('the action carries no capability chain');
        }
        foreach ($chain as $hop) {
            foreach (['id', 'issuer', 'holder'] as $k) {
                if (!self::nonEmpty(Js::opt($hop, $k))) {
                    return self::closed("a chain hop has no $k");
                }
            }
        }
        try {
            $ids = [];
            foreach ($chain as $hop) {
                // root -> leaf; cap id, then issuer, then holder
                foreach (['cap' => 'id', 'issuer' => 'issuer', 'holder' => 'holder'] as $kind => $f) {
                    $e = $registry->lookup($kind, Js::opt($hop, $f));
                    if ($e !== null && self::isActiveAt($e, $now)) {
                        return ['revoked' => true, 'matched' => $e, 'reason' => self::matchReason($e)];
                    }
                }
                $ids[] = Js::opt($hop, 'id');
            }
            foreach ($registry->prefixes() as $e) {
                if (self::startsWith($ids, $e['prefix'] ?? null) && self::isActiveAt($e, $now)) {
                    return ['revoked' => true, 'matched' => $e, 'reason' => self::matchReason($e)];
                }
            }
            return ['revoked' => false];
        } catch (\Throwable) {
            return self::closed('the revocation store failed (Error)');
        }
    }

    /** Allow ONLY if the core verified (allow === true) AND nothing in the chain is revoked. */
    public static function verifyWithRevocation(mixed $p, mixed $coreVerifyResult, RevocationRegistry $registry, mixed $now = null): array
    {
        $coreAllow = Js::opt($coreVerifyResult, 'allow') === true;
        $revocation = self::checkRevocation($p, $registry, $now);
        $allow = $coreAllow && !$revocation['revoked'];
        $out = ['allow' => $allow, 'coreAllow' => $coreAllow, 'revocation' => $revocation];
        if (!$allow) {
            $out['reason'] = !$coreAllow ? (Js::opt($coreVerifyResult, 'reason') ?? 'core verification failed') : ($revocation['reason'] ?? 'revoked');
        }
        return $out;
    }

    /** CAEP event_timestamp is integer SECONDS; the registry records epoch ms (Math.round). */
    private static function revokedAtFrom(mixed $ts): int|float
    {
        if (!self::finite($ts)) {
            return self::nowMs();
        }
        $v = floor(Js::num($ts) * 1000 + 0.5);
        return abs($v) < 2 ** 53 ? (int)$v : $v;
    }

    private static function stringField(mixed $subject, string $k): ?string
    {
        $v = Js::opt($subject, $k);
        return self::nonEmpty($v) ? $v : null;
    }

    /**
     * Bridge a CAEP revocation event {type, payload} into registry entries (returned): grant-revoked revokes the cap id grant_ref;
     * kill-switch kills the agent holder (and grant_ref's cap when named); session-revoked kills the subject's holder / agent / id
     * key when it carries one. A missing payload throws \TypeError.
     * @return list<array>
     */
    public static function ingestCaepEvent(mixed $event, RevocationRegistry $registry): array
    {
        if (!Js::isObj($event)) {
            throw new \TypeError('ingestCaepEvent: event must be an object');
        }
        $payload = Js::opt($event, 'payload');
        if ($payload === null) {
            throw new \TypeError('ingestCaepEvent: event has no payload');
        }
        $ev = Js::isObj($payload) ? $payload : [];
        $g = static fn(string $k): mixed => Js::opt($ev, $k);
        $added = [];
        $t = Js::opt($event, 'type');
        if ($t === self::CAEP_EVENT_TYPES['grantRevoked']) {
            if (self::nonEmpty($g('grant_ref'))) {
                $added[] = $registry->revoke(['kind' => 'cap', 'value' => $g('grant_ref'), 'reason' => $g('reason') ?? 'CAEP grant-revoked', 'revokedAt' => self::revokedAtFrom($g('event_timestamp'))]);
            }
        } elseif ($t === self::CAEP_EVENT_TYPES['killSwitch']) {
            $at = self::revokedAtFrom($g('event_timestamp'));
            if (self::nonEmpty($g('agent'))) {
                $added[] = $registry->killAgent($g('agent'), $g('reason') ?? 'CAEP kill-switch', $at);
            }
            if (self::nonEmpty($g('grant_ref'))) {
                $added[] = $registry->revoke(['kind' => 'cap', 'value' => $g('grant_ref'), 'reason' => $g('reason') ?? 'CAEP kill-switch', 'revokedAt' => $at]);
            }
        } else {
            $subject = $g('subject');
            if (Js::has($ev, 'subject') && $subject === null) {
                throw new \TypeError('ingestCaepEvent: subject is null');
            }
            $holder = self::stringField($subject, 'holder') ?? self::stringField($subject, 'agent') ?? self::stringField($subject, 'id');
            if ($holder !== null) {
                $added[] = $registry->killAgent($holder, $g('reason_admin') ?? $g('reason_user') ?? 'CAEP session-revoked', self::revokedAtFrom($g('event_timestamp')));
            }
        }
        return $added;
    }

    /**
     * Conformance cases for a revocation store (the single-process subset: PHP has no shared-memory threads). `$make` returns a
     * fresh, empty store; a persistent store passes `$reopen(previous)` to run the durability case. Returns the failure
     * descriptions (an empty list means the store conforms).
     * @param callable(): RevocationStore $make @param ?callable(RevocationStore): RevocationStore $reopen
     * @return list<string>
     */
    public static function runRevocationStoreConformance(callable $make, ?callable $reopen = null): array
    {
        $e = static function (string $kind, string $value, array $extra = []): array {
            $x = ['kind' => $kind, 'value' => $value, 'reason' => "r-$kind-$value", 'revokedAt' => 1000];
            if ($kind === 'prefix') {
                $x['prefix'] = explode(',', $value);
            }
            return $extra + $x;
        };
        $eq = static function (mixed $a, mixed $b): void {
            if ($a !== $b) {
                throw new \UnexpectedValueException(var_export($a, true) . ' !== ' . var_export($b, true));
            }
        };
        $sorted = static function (array $xs): array {
            usort($xs, static fn(array $a, array $b): int => strcmp($a['kind'] . $a['value'], $b['kind'] . $b['value']));
            return $xs;
        };
        $cases = [
            'starts empty' => function () use ($make, $eq): void {
                $eq($make()->all(), []);
                $eq($make()->get('cap', 'x'), null);
            },
            'add then get returns the whole entry, including notBefore' => function () use ($make, $eq, $e): void {
                $s = $make();
                $x = $e('cap', 'c1', ['notBefore' => 5000]);
                $s->add($x);
                $eq($s->get('cap', 'c1'), $x);
            },
            'the same value under different kinds is kept apart' => function () use ($make, $eq, $e): void {
                $s = $make();
                foreach (['cap', 'holder', 'issuer'] as $k) {
                    $s->add($e($k, 'k'));
                }
                $eq(count($s->all()), 3);
                $eq($s->remove('holder', 'k'), true);
                $eq($s->get('cap', 'k')['kind'] ?? null, 'cap');
                $eq($s->get('holder', 'k'), null);
            },
            'add at an existing key replaces, it does not duplicate' => function () use ($make, $eq, $e): void {
                $s = $make();
                $s->add($e('cap', 'c', ['reason' => 'first']));
                $s->add($e('cap', 'c', ['reason' => 'second']));
                $eq(count($s->all()), 1);
                $eq($s->get('cap', 'c')['reason'] ?? null, 'second');
            },
            'remove reports whether something was removed, and only once' => function () use ($make, $eq, $e): void {
                $s = $make();
                $s->add($e('cap', 'c'));
                $eq($s->remove('cap', 'c'), true);
                $eq($s->remove('cap', 'c'), false);
                $eq($s->remove('cap', 'never-added'), false);
            },
            'prefix paths that differ stay distinct' => function () use ($make, $eq, $e, $sorted): void {
                $s = $make();
                foreach (['a,b', 'a', 'b,a'] as $v) {
                    $s->add($e('prefix', $v));
                }
                $eq($s->remove('prefix', 'a'), true);
                $eq(array_column($sorted($s->all()), 'value'), ['a,b', 'b,a']);
            },
            'clear drops everything' => function () use ($make, $eq, $e): void {
                $s = $make();
                $s->add($e('cap', 'c'));
                $s->add($e('prefix', 'a,b'));
                $s->clear();
                $eq($s->all(), []);
                $eq($s->get('cap', 'c'), null);
            },
        ];
        if ($reopen !== null) {
            $cases['entries survive reopening the store'] = function () use ($make, $reopen, $eq, $e, $sorted): void {
                $s = $make();
                $a = $e('cap', 'durable', ['notBefore' => 9000]);
                $b = $e('prefix', 'r,m');
                $s->add($a);
                $s->add($b);
                $s->add($e('holder', 'gone'));
                $s->remove('holder', 'gone');
                $eq(Js::stringify($sorted($reopen($s)->all())), Js::stringify($sorted([$a, $b])));
            };
        }
        $fail = [];
        foreach ($cases as $name => $run) {
            try {
                $run();
            } catch (\Throwable $x) {
                $fail[] = "$name: " . get_class($x) . ': ' . $x->getMessage();
            }
        }
        return $fail;
    }
}
