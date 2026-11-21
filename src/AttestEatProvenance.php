<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The artifact attestation verifier: Sigstore provenance joined to runtime attestation, issued as a K1 discharge. The verifier that
 * holds the `artifact`-class key runs, for one discharge request: the bundle against the pinned trust roots (offline, fail closed),
 * the provenance gate over the verifier's own policy and the running image digest, then signs the discharge the request asks for
 * with the gate's claims. Any failure returns no discharge, so the caveat refuses: provenance can only remove authority.
 */
final class AttestEatProvenance
{
    /**
     * The unsigned discharge body after a passing gate: the request's binding and the gate's claims. Throws when the gate refused or
     * `$ttlMs` exceeds the request's.
     * @param array{ok:bool,code?:string,claims?:array} $gate
     */
    public static function provenanceDischargeBody(Obj $request, array $gate, int $iat, int $ttlMs, string $nonce): Obj
    {
        if (($gate['ok'] ?? false) !== true) {
            throw new \InvalidArgumentException('provenanceDischargeBody: the provenance gate refused (' . ($gate['code'] ?? '?') . ')');
        }
        $reqTtl = $request->get('ttl_ms');
        if ($reqTtl instanceof Num && $ttlMs > $reqTtl->float()) {
            throw new \InvalidArgumentException('provenanceDischargeBody: ttl_ms exceeds what the caveat accepts');
        }
        $b = Obj::of(['v' => 1, 'kind' => 'pca-discharge', 'caveat_id' => $request->get('caveat_id'), 'issuer' => $request->get('issuer'),
            'cap_hash' => $request->get('cap_hash'), 'bind' => $request->get('bind')]);
        if ($request->has('action_digest')) {
            $b->set('action_digest', $request->get('action_digest'));
        }
        $b->set('claims', Obj::of($gate['claims']));
        $b->set('iat', $iat);
        $b->set('not_after', $iat + $ttlMs);
        $b->set('nonce', $nonce);
        return $b;
    }

    /**
     * Issue an artifact discharge. `$i`: `bundle` (a parsed Sigstore bundle), `roots` (SigstoreBundle::parseTrustedRoot), `policy` (the
     * provenance gate policy), `runtime` ({alg, digest} from AttestEat::runtimeDigestFromEat; omit the key only when the policy does not
     * require the join; an explicit null is a failed join), `request` (an Obj), `now` (verifier clock, epoch ms int), `issuerKey` (the
     * `artifact`-class KeyPair), `ttl_ms`? (default the request's). The 16-byte nonce comes from `$nonce` (default random_bytes).
     * @param array<string,mixed> $i
     * @return array{ok:true,discharge:Obj,facts:Obj,level:int}|array{ok:false,stage:string,code:string,detail?:string}
     */
    public static function issueArtifactDischarge(array $i, ?\Closure $nonce = null): array
    {
        $v = SigstoreBundle::verify($i['bundle'] ?? null, $i['roots'] ?? []);
        if (!$v['ok']) {
            return ['ok' => false, 'stage' => 'sigstore', 'code' => $v['code'], 'detail' => $v['detail']];
        }
        $gateFail = static fn(string $code): array => ['ok' => false, 'stage' => 'gate', 'code' => $code];
        $hasRuntime = array_key_exists('runtime', $i);
        if ($hasRuntime && $i['runtime'] === null) {
            return $gateFail('no_runtime'); // an EAT that yielded no digest is not "no runtime": it is a failed join
        }
        $now = $i['now'] ?? null;
        if (!is_int($now)) {
            throw new \InvalidArgumentException('issueArtifactDischarge: now must be an integer epoch ms');
        }
        $in = Obj::of(['facts' => $v['facts'], 'policy' => $i['policy'] ?? null, 'now' => (int) floor($now / 1000)]);
        if ($hasRuntime) {
            $in->set('runtime', $i['runtime']);
        }
        $gate = ProvenanceGate::gate($in);
        if (($gate['ok'] ?? false) !== true) {
            return $gateFail($gate['code'] ?? 'malformed_facts');
        }
        $request = $i['request'] ?? null;
        if (!$request instanceof Obj) {
            throw new \InvalidArgumentException('issueArtifactDischarge: request must be an object');
        }
        $ttl = $i['ttl_ms'] ?? ($request->get('ttl_ms') instanceof Num ? (int) $request->get('ttl_ms')->float() : null);
        if (!is_int($ttl)) {
            throw new \InvalidArgumentException('issueArtifactDischarge: ttl_ms must be an integer');
        }
        $n = Pca::b64u($nonce !== null ? $nonce() : random_bytes(16));
        $body = self::provenanceDischargeBody($request, $gate, $now, $ttl, $n);
        $digest = $request->get('action_digest');
        $discharge = Sign::signDischarge($i['issuerKey'], (string) $body->get('caveat_id'), (string) $body->get('issuer'), (string) $body->get('cap_hash'),
            $body->get('claims'), $now, $now + $ttl, (string) $body->get('bind'), is_string($digest) ? $digest : null, $n);
        return ['ok' => true, 'discharge' => $discharge, 'facts' => $v['facts'], 'level' => $gate['level']];
    }
}
