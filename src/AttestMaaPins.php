<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AttestAllowlist.php';
require_once __DIR__ . '/AttestMaaPinsData.php';
require_once __DIR__ . '/Json.php';

/**
 * The built-in, release-signed pins for the Azure MAA token-signing keys: the offline root of a first accepted key set. A signed allowlist
 * manifest shipped with the package carries the self-signed instance key pins, the Microsoft chain root and intermediate pins and a signed
 * corroboration record (>= 3 independent vantages). It is verified at load against the embedded release issuer key with the usual window,
 * version floor and a 400-day lifetime cap; a pin set that fails any check is unusable (the trust then fails closed).
 */
final class AttestMaaPins
{
    /** The leaf CN Microsoft's MAA signing certificates carry. */
    public const CHAIN_LEAF_CN = ['Microsoft Azure Attestation 2020'];
    private const MAX_LIFETIME_MS = 400 * 24 * 3600000;
    private const MIN_VANTAGES = 3;

    public static function issuerId(): string
    {
        return AttestMaaPinsData::ISSUER_ID;
    }

    /** The embedded release issuer key registry `{<issuer id>: {alg, keys}}`. */
    public static function issuerKeys(): Obj
    {
        return Obj::of([AttestMaaPinsData::ISSUER_ID => Json::parseLax(AttestMaaPinsData::ISSUER_KEY_JSON)]);
    }

    /** @return array<string,mixed> */
    private static function evaluate(mixed $manifest, mixed $issuerKeys, mixed $minVersion, mixed $nowMs): array
    {
        $nb = Jsx::get(Jsx::get($manifest, 'body'), 'notBefore');
        $v0 = AttestAllowlist::verify($manifest, Obj::of(['issuerKeys' => $issuerKeys, 'nowMs' => $nb instanceof Undef || $nb === null ? $nowMs : $nb,
            'minVersion' => $minVersion, 'maxLifetimeMs' => self::MAX_LIFETIME_MS]));
        if ($v0['ok'] !== true) {
            return ['ok' => false, 'reason' => $v0['code'] . ': ' . $v0['reason']];
        }
        $body = $v0['body'];
        $p = AttestAllowlist::project(Obj::of($v0), Obj::of(['nowMs' => $body->get('notBefore')]));
        $corr = $p['corroboration'];
        if (count($corr) !== 1) {
            return ['ok' => false, 'reason' => 'manifest must carry exactly one attest-corroboration entry'];
        }
        $m = preg_match('/\Avantages=([0-9]+);method=(.*)\z/', (string)$corr[0]->get('label'), $mm) === 1;
        $vantages = $m ? (int)$mm[1] : 0;
        if (!$m || $vantages < self::MIN_VANTAGES) {
            return ['ok' => false, 'reason' => "corroboration records $vantages vantages < required " . self::MIN_VANTAGES];
        }
        if ($p['maaSigningSpkis']->keys() === []) {
            return ['ok' => false, 'reason' => 'manifest pins no MAA signing key'];
        }
        if ($p['maaChainRootSpkis'] === [] || $p['maaChainIntermediateSpkis'] === []) {
            return ['ok' => false, 'reason' => 'manifest lacks the Microsoft chain root / intermediate pins'];
        }
        $revoked = new Obj();
        foreach ($p['revoked'] as $r) {
            if ($r->get('kind') === 'maa-signing-spki') {
                $cur = $revoked->has($r->get('label')) ? $revoked->get($r->get('label')) : [];
                $cur[] = $r->get('value');
                $revoked->set($r->get('label'), $cur);
            }
        }
        return ['ok' => true, 'notBefore' => $body->get('notBefore'), 'expiresAt' => $body->get('expiresAt'), 'value' => [
            'ok' => true, 'version' => $v0['version'], 'digest' => $v0['digest'], 'expiresAt' => $body->get('expiresAt'),
            'maaSigningSpkis' => $p['maaSigningSpkis'], 'revokedSigningSpkis' => $revoked, 'maaChainRootSpkis' => $p['maaChainRootSpkis'],
            'maaChainIntermediateSpkis' => $p['maaChainIntermediateSpkis'], 'vantages' => $vantages, 'method' => $mm[2]]];
    }

    /**
     * Load and verify the pin set at `{nowMs, source?}`; `source` is `{manifest, issuerKeys, minVersion?}` (default floor 1) or the shipped pins.
     * Never throws. @return array<string,mixed> the pins (`ok: true`, version, digest, expiresAt, maaSigningSpkis, revokedSigningSpkis, maaChainRootSpkis,
     * maaChainIntermediateSpkis, vantages, method) or `{ok: false, reason}`
     */
    public static function load(mixed $opts): array
    {
        try {
            $nowV = Jsx::get($opts, 'nowMs');
            $f = Js::num($nowV);
            if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0) {
                return ['ok' => false, 'reason' => 'nowMs must be an integer'];
            }
            $src = Jsx::get($opts, 'source');
            if ($src instanceof Undef || $src === null) {
                $r = self::evaluate(Json::parseLax(AttestMaaPinsData::MANIFEST_JSON), self::issuerKeys(), AttestMaaPinsData::MIN_VERSION, $nowV);
            } else {
                $mv = Jsx::get($src, 'minVersion');
                $r = self::evaluate(Jsx::get($src, 'manifest'), Jsx::get($src, 'issuerKeys'), $mv instanceof Undef || $mv === null ? 1 : $mv, $nowV);
            }
            if ($r['ok'] !== true) {
                return $r;
            }
            if (!($f >= Js::num($r['notBefore']))) {
                return ['ok' => false, 'reason' => 'built-in pins are not yet valid (clock behind the release)'];
            }
            if (!($f <= Js::num($r['expiresAt']))) {
                return ['ok' => false, 'reason' => 'built-in pins expired; update the package or pass explicit initialPins'];
            }
            return $r['value'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => $e->getMessage() === '' ? 'built-in pins error' : $e->getMessage()];
        }
    }
}
