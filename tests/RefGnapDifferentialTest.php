<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Gnap;
use Atlas\Pca\InteractionError;
use Atlas\Pca\InteractionServer;
use Atlas\Pca\Jose;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The GNAP bridge against the TS reference (test-data/ref-gnap.json.gz): access rights, holders, grant requests -> chains, action
 * authorization, bound tokens, jwsd proofs (sign / verify / replay store), the step-up continuation, and the interaction modes,
 * including the AS state machine as scripted scenarios. Secrets cross as base64url seeds; {"$bytes"} values are raw bytes.
 */
final class RefGnapDifferentialTest extends TestCase
{
    private const FILE = 'ref-gnap.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $s): mixed
    {
        return is_string($s) ? new Bytes(Jose::lenientB64d($s)) : $s;
    }

    private static function unbytes(mixed $x): mixed
    {
        return $x instanceof Obj && $x->keys() === ['$bytes'] && is_string($x->get('$bytes')) ? new Bytes(Jose::lenientB64d($x->get('$bytes'))) : $x;
    }

    /** A copy of `$o` with member `$k` mapped (when present). */
    private static function with(mixed $o, string $k, callable $f): mixed
    {
        if (!($o instanceof Obj) || !$o->has($k)) {
            return $o;
        }
        $c = new Obj();
        foreach ($o->keys() as $x) {
            $c->set($x, $x === $k ? $f($o->get($x)) : $o->get($x));
        }
        return $c;
    }

    private static function sign(Obj $a): array
    {
        $a = self::with($a, 'key', static fn($k) => $k instanceof Obj
            ? Obj::of(['secretKey' => self::seed($k->get('secretKey')), 'publicKey' => self::seed($k->get('publicKey'))]) : $k);
        return Gnap::signGnapRequest(self::with($a, 'body', self::unbytes(...)));
    }

    private static function verify(Obj $a): array
    {
        $seen = [];
        $mode = $a->get('seenProofMode');
        $args = self::with($a->without('seenProofMode'), 'body', self::unbytes(...));
        if (in_array($mode, ['fresh', 'replayed', 'throws', 'undefined'], true)) {
            $args->set('seenProof', static function (string $id, $exp) use (&$seen, $mode) {
                $seen[] = [$id, $exp];
                if ($mode === 'throws') {
                    throw new \RuntimeException('store down');
                }
                return ['fresh' => false, 'replayed' => true, 'undefined' => null][$mode];
            });
        }
        $r = Gnap::verifyGnapRequest($args);
        if (isset($r['reason'])) {
            $r['reason'] = (string)preg_replace('/(bad-json) \(.*\)$/s', '$1', $r['reason']);
        }
        return ['result' => $r, 'seen' => $seen];
    }

    private static function complete(Obj $a): array
    {
        $a = self::with($a, 'agentLeafSecret', self::seed(...));
        $a = self::with($a, 'cosignSecrets', static fn($cs) => is_array($cs)
            ? array_map(static fn($c) => self::with($c, 'secret', self::seed(...)), $cs) : $cs);
        return Gnap::completeGnapContinuation($a);
    }

    // ---- the interaction server, scripted --------------------------------------------------------------------------------

    private static function plain(mixed $v): mixed
    {
        if ($v instanceof \JsonSerializable) {
            return self::plain($v->jsonSerialize());
        }
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return $o === [] ? new Obj() : $o;
        }
        return is_array($v) ? array_map(self::plain(...), $v) : $v;
    }

    /** @param list<array{0:?string,1:string}> $pairs */
    private static function redact(mixed $v, array $pairs): mixed
    {
        if (is_string($v)) {
            foreach ($pairs as [$k, $t]) {
                if ($k !== null && $k !== '') {
                    $v = str_replace($k, $t, $v);
                }
            }
            return $v;
        }
        return is_array($v) ? array_map(static fn($x) => self::redact($x, $pairs), $v) : $v;
    }

    private static function scenario(Obj $s): array
    {
        $clock = 1000;
        $opts = $s->get('opts');
        $ge = $opts->get('grantEndpoint') ?? 'https://as.example/tx';
        $o = ['grantEndpoint' => $ge, 'supports' => $opts->get('supports'), 'redirectUri' => static fn(string $id): string => "https://as.example/i/$id",
            'now' => static function () use (&$clock): int {
                return $clock;
            }];
        if ($opts->get('app')) {
            $o['appUri'] = static fn(string $id): string => "app://as/$id";
        }
        if ($opts->get('userCodeUri')) {
            $o['userCodeUri'] = $opts->get('userCodeUri');
        }
        if ($opts->has('ttlSec')) {
            $o['ttlSec'] = $opts->get('ttlSec')->int();
        }
        $srv = new InteractionServer($o);
        $v = [];
        $last = null;
        $sub = static function (mixed $x) use (&$v): mixed {
            if (!is_string($x) || !str_starts_with($x, '$')) {
                return $x;
            }
            $code = $v['code'] ?? '';
            return match ($x) {
                '$code:lower' => strtolower($code),
                '$code:spaced' => substr($code, 0, 4) . ' - ' . substr($code, 4),
                default => $v[substr($x, 1)] ?? $x,
            };
        };
        $trace = [];
        $started = [];
        foreach ($s->get('steps') as $st) {
            $op = $st->get('op');
            try {
                if ($op === 'start') {
                    $last = $st->get('req');
                    $r = $srv->start($last);
                    $it = $r['interaction'];
                    [$v['id'], $v['code'], $v['asnonce']] = [$it->id, $it->userCode ?? '', $it->finish['asNonce'] ?? ''];
                    $started[] = [$v['id'], $v['code'], $v['asnonce']];
                    $value = ['interaction' => $it, 'response' => $r['response']];
                } elseif ($op === 'lookup') {
                    $value = $srv->lookupUserCode($sub($st->get('code')));
                } elseif ($op === 'approve') {
                    $r = $srv->approve($sub($st->get('id')));
                    $v['ref'] = $r['interactRef'];
                    $it = $srv->get($v['id'] ?? '');
                    $fin = $r['finish'] ?? null;
                    $m = null;
                    if ($fin !== null && $fin['method'] === 'push') {
                        $m = $fin['body']['hash'];
                    } elseif ($fin !== null && preg_match('/[?&]hash=([^&]+)/', $fin['url'], $mm) === 1) {
                        $m = $mm[1];
                    }
                    $v['hash'] = $m ?? '';
                    $expected = $it?->finish === null ? null : Gnap::interactionHash(['clientNonce' => $it->finish['clientNonce'], 'asNonce' => $it->finish['asNonce'],
                        'interactRef' => $r['interactRef'], 'grantEndpoint' => $it->grantEndpoint, 'hashMethod' => $it->finish['hashMethod']]);
                    $value = ['result' => $r, 'hashOk' => $m === $expected];
                } elseif ($op === 'consume') {
                    $value = $srv->consume($sub($st->get('ref')));
                } elseif ($op === 'finalize') {
                    $srv->finalize($sub($st->get('id')));
                    $value = null;
                } elseif ($op === 'get') {
                    $value = $srv->get($sub($st->get('id')));
                } elseif ($op === 'advance') {
                    $clock += $st->get('sec')->int();
                    $value = $clock;
                } else { // accept
                    $fin = $last->get('finish');
                    $ctx = ['clientNonce' => $fin->get('nonce'), 'asNonce' => $v['asnonce'] ?? null, 'grantEndpoint' => $ge];
                    if ($fin->get('hash_method')) {
                        $ctx['hashMethod'] = $fin->get('hash_method');
                    }
                    $value = Gnap::acceptFinish(Obj::of(['hash' => $sub($st->get('hash')), 'interact_ref' => $sub($st->get('ref'))]), $ctx);
                }
                $pairs = [[$v['ref'] ?? null, '<REF>'], [$v['hash'] ?? null, '<HASH>'], [$v['asnonce'] ?? null, '<ASNONCE>'], [$v['id'] ?? null, '<ID>'], [$v['code'] ?? null, '<CODE>']];
                foreach (array_slice($started, 0, -1) as $n => [$sid, $scode, $snonce]) { // an earlier start (number n, from 0) is <ID:n> / <CODE:n> / <ASNONCE:n>
                    array_push($pairs, [$sid, "<ID:$n>"], [$scode, "<CODE:$n>"], [$snonce, "<ASNONCE:$n>"]);
                }
                $trace[] = ['op' => $op, 'ok' => true, 'value' => self::redact(self::plain($value), $pairs)];
            } catch (\Throwable $e) {
                $trace[] = ['op' => $op, 'ok' => false, 'code' => $e instanceof InteractionError ? $e->errorCode : 'other'];
            }
        }
        return $trace;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn() => ['GNAP_GRANT_CAVEAT' => Gnap::GNAP_GRANT_CAVEAT, 'GNAP_ACCESS_CAVEAT' => Gnap::GNAP_ACCESS_CAVEAT,
                'MAX_DETACHED_JWS_CHARS' => Gnap::MAX_DETACHED_JWS_CHARS, 'START_MODES' => Gnap::START_MODES, 'FINISH_METHODS' => Gnap::FINISH_METHODS,
                'HASH_METHODS' => array_keys(Gnap::HASH_METHODS)],
            'AGENT_GNAP_PROFILE' => fn() => Gnap::agentGnapProfile(),
            'gnapActionResource' => fn(array $a) => Gnap::gnapActionResource($a[0], $a[1]),
            'normalizeAccess' => fn(array $a) => Gnap::normalizeAccess($a[0]),
            'accessToPredicates' => fn(array $a) => Gnap::accessToPredicates($a[0]),
            'accessContains' => fn(array $a) => Gnap::accessContains($a[0], $a[1]),
            'accessWithin' => fn(array $a) => Gnap::accessWithin($a[0], $a[1]),
            'clampAccess' => fn(array $a) => Gnap::clampAccess($a[0], $a[1]),
            'resolveHolder' => fn(array $a) => Gnap::resolveHolder($a[0], $a[1] ?? null, count($a) > 1),
            'holderJwk' => fn(array $a) => Gnap::holderJwk($a[0]),
            'grantRequestToCapability' => fn(array $a) => Gnap::grantRequestToCapability($a[0], self::with($a[1], 'issuerSecret', self::seed(...))),
            'grantedAccessOf' => fn(array $a) => Gnap::grantedAccessOf($a[0]),
            'authorizeGnapAction' => fn(array $a) => Gnap::authorizeGnapAction($a[0], $a[1], $a[2] ?? null),
            'encodeBoundToken' => fn(array $a) => Gnap::encodeBoundToken($a[0]),
            'capabilityToGrantResponse' => fn(array $a) => Gnap::capabilityToGrantResponse($a[0], $a[1] ?? null),
            'verifyGnapToken' => fn(array $a) => Gnap::verifyGnapToken($a[0], $a[1] ?? null),
            'gnapContentDigest' => fn(array $a) => Base::outBytes(Gnap::gnapContentDigest(self::unbytes($a[0]))),
            'gnapContentDigestAbsent' => fn() => Base::outBytes(Gnap::gnapContentDigest(null, false)),
            'signGnapRequest' => fn(array $a) => self::sign($a[0]),
            'verifyGnapRequest' => fn(array $a) => self::verify($a[0]),
            'gnapRequestRequiresStepUp' => fn(array $a) => Gnap::gnapRequestRequiresStepUp($a[0], $a[1] ?? null),
            'beginGnapContinuation' => fn(array $a) => Gnap::beginGnapContinuation($a[0]),
            'gnapStepUpShare' => fn(array $a) => Gnap::gnapStepUpShare($a[0], $a[1], Jose::lenientB64d($a[2]), $a[3], $a[4]),
            'completeGnapContinuation' => fn(array $a) => self::complete($a[0]),
            'callbackUriOk' => fn(array $a) => Gnap::callbackUriOk($a[0]),
            'validateInteractRequest' => fn(array $a) => Gnap::validateInteractRequest($a[0]),
            'interactionHash' => fn(array $a) => Gnap::interactionHash($a[0]),
            'verifyInteractionHash' => fn(array $a) => Gnap::verifyInteractionHash($a[0], $a[1]),
            'acceptFinish' => fn(array $a) => Gnap::acceptFinish($a[0], $a[1]),
            'newUserCode' => fn(array $a) => Gnap::newUserCode($a[0]),
            'accessToNeeds' => fn(array $a) => Gnap::accessToNeeds($a[0]),
            'interactionScenario' => fn(array $a) => self::scenario($a[0]),
        ]);
    }

    public function testAJwsdProofRoundTripsAndIsBoundToItsBody(): void
    {
        $seed = str_repeat("\x07", 32);
        $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $body = Obj::of(['a' => 1]);
        $p = Gnap::signGnapRequest(['body' => $body, 'key' => ['secretKey' => $seed, 'publicKey' => $pub], 'htm' => 'post', 'uri' => 'https://as/x', 'created' => 1000]);
        $args = ['detachedJws' => $p['detachedJws'], 'body' => $body, 'holder' => $p['holder'], 'htm' => 'POST', 'uri' => 'https://as/x', 'now' => 1000500, 'replayCheck' => 'unchecked'];
        $this->assertTrue(Gnap::verifyGnapRequest($args)['ok']);
        $this->assertFalse(Gnap::verifyGnapRequest(['body' => Obj::of(['a' => 2])] + $args)['ok']);
        $this->expectException(\RuntimeException::class); // no replay store and no explicit opt-out
        Gnap::verifyGnapRequest(array_diff_key($args, ['replayCheck' => 1]));
    }
}
