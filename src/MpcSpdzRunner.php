<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The malicious-secure (SPDZ) runner: the same composition as MpcRunner::composeSecure, but every shared value carries a MAC and
 * nothing is accepted as output until the batched MAC-check passes (correct result or MpcMacCheckAbort). Offline phase: a
 * no-dealer provider (the default, OT-based: MpcMascot), a caller-supplied
 * MpcOfflineProvider, or an explicit trusted dealer with sacrifice-certified triples.
 */
final class MpcSpdzRunner
{
    private const T_M = 3;

    /**
     * $cfg keys (all optional): Q ?int, seed ?GMP, deviations list<Deviation>, offline ?MpcOfflineProvider, insecureTrustedDealer bool,
     * dealer ['verifyTriples' => ?bool, 'partners' => ?int, 'fault' => ?DealerFault] (honoured only with insecureTrustedDealer).
     *
     * @param list<array{allow:int,t:int,rQuant:int}> $vectors
     * @return array{composed:array,parties:int,Q:int,opens:int,multiplications:int,offlineMode:string,triplesVerified:bool,macChecked:bool}
     */
    public static function composeSecureMalicious(array $vectors, array $cfg = []): array
    {
        $n = count($vectors);
        if ($n === 0) {
            throw new \InvalidArgumentException('composeSecureMalicious: no parties (fail closed)');
        }
        $Q = $cfg['Q'] ?? MpcParty::DEFAULT_Q;
        MpcCompose::assertDecisionVectors($vectors, $Q);
        $seed = $cfg['seed'] ?? null;
        $rng = $seed === null ? MpcFieldRng::secure() : new MpcFieldRng($seed);
        $offline = $cfg['offline'] ?? null;
        $trusted = ($cfg['insecureTrustedDealer'] ?? false) === true;
        $dealer = $cfg['dealer'] ?? null;

        if ($offline !== null && $trusted) {
            throw new \LogicException('composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)');
        }
        if ($dealer !== null && !$trusted && $offline === null) {
            throw new \LogicException('composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)');
        }
        if ($offline === null && !$trusted) {
            $offline = MpcMascot::make($n, $seed);
        }
        if ($offline !== null && $offline->n() !== $n) {
            throw new \LogicException('composeSecureMalicious: offline provider party count != number of vectors');
        }
        $ctx = $offline !== null ? $offline->macContext() : MpcSpdz::setupMac($n, $rng);
        $engine = new MpcSpdzEngine($ctx, $cfg['deviations'] ?? []);
        $mults = 0;
        $verify = $dealer === null || ($dealer['verifyTriples'] ?? null) === null || $dealer['verifyTriples'];

        $nextTriple = static function () use ($offline, $verify, $dealer, $ctx, $rng): array {
            if ($offline !== null) {
                return $offline->genAuthTriple();
            }
            $fault = $dealer['fault'] ?? null;
            if (!$verify) {
                return $fault !== null ? MpcSpdz::genTripleWithPartners($ctx, $rng, 1, $fault)['keep'] : MpcSpdz::genAuthTriple($ctx, $rng);
            }
            $dealt = MpcSpdz::genTripleWithPartners($ctx, $rng, $dealer['partners'] ?? MpcSpdz::SACRIFICE_PARTNERS, $fault);
            return MpcSpdz::sacrificeVerify([$dealt], $ctx, $rng, [])[0];
        };
        $shareBit = static fn(int $bit, int $owner): array => $offline !== null
            ? $offline->authInput(gmp_init($bit), $owner) : MpcSpdz::authShare(gmp_init($bit), $ctx, $rng);
        $and = static function (array $bits) use ($ctx, $engine, $nextTriple, &$mults): array {
            if ($bits === []) {
                return MpcSpdz::authConstant(gmp_init(1), $ctx);
            }
            $acc = $bits[0];
            for ($i = 1; $i < count($bits); $i++) {
                $acc = MpcSpdz::beaverMulAuth($acc, $bits[$i], $nextTriple(), $ctx, $engine, "and$i");
                $mults++;
            }
            return $acc;
        };
        $or = static function (array $bits) use ($ctx, $engine, $nextTriple, &$mults): array {
            if ($bits === []) {
                return MpcSpdz::authConstant(gmp_init(0), $ctx);
            }
            $prod = MpcSpdz::notBitAuth($bits[0], $ctx);
            for ($i = 1; $i < count($bits); $i++) {
                $prod = MpcSpdz::beaverMulAuth($prod, MpcSpdz::notBitAuth($bits[$i], $ctx), $nextTriple(), $ctx, $engine, "or$i");
                $mults++;
            }
            return MpcSpdz::notBitAuth($prod, $ctx);
        };

        $allowBits = [];
        for ($p = 0; $p < $n; $p++) {
            $allowBits[] = $shareBit($vectors[$p]['allow'], $p);
        }
        $allowSV = $and($allowBits);

        $tTherm = [];
        for ($p = 0; $p < $n; $p++) {
            $tTherm[$p] = MpcThermometer::thermometerEncode((float) $vectors[$p]['t'], self::T_M);
        }
        $tGe = [];
        for ($k = 0; $k < self::T_M; $k++) {
            $bits = [];
            for ($p = 0; $p < $n; $p++) {
                $bits[] = $shareBit($tTherm[$p][$k], $p);
            }
            $tGe[] = $or($bits);
        }
        $rTherm = [];
        for ($p = 0; $p < $n; $p++) {
            $rTherm[$p] = MpcThermometer::thermometerEncode((float) $vectors[$p]['rQuant'], $Q);
        }
        $rGe = [];
        for ($k = 0; $k < $Q; $k++) {
            $bits = [];
            for ($p = 0; $p < $n; $p++) {
                $bits[] = $shareBit($rTherm[$p][$k], $p);
            }
            $rGe[] = $or($bits);
        }

        $allowOpen = $engine->open($allowSV, 'out:allow');
        $tOpen = [];
        for ($k = 0; $k < self::T_M; $k++) {
            $tOpen[] = gmp_cmp($engine->open($tGe[$k], 'out:t.ge' . ($k + 1)), 1) === 0 ? 1 : 0;
        }
        $rOpen = [];
        for ($k = 0; $k < $Q; $k++) {
            $rOpen[] = gmp_cmp($engine->open($rGe[$k], 'out:r.ge' . ($k + 1)), 1) === 0 ? 1 : 0;
        }

        $engine->macCheck($rng);

        $allow = gmp_cmp($allowOpen, 1) === 0 ? 1 : 0;
        $t = min(3, max(1, MpcThermometer::thermometerDecode($tOpen)));
        $rQuant = MpcThermometer::thermometerDecode($rOpen);
        return ['composed' => ['allow' => $allow, 't' => $t, 'rQuant' => $rQuant], 'parties' => $n, 'Q' => $Q, 'opens' => $engine->openCount(),
            'multiplications' => $mults, 'offlineMode' => $offline !== null ? 'no-dealer' : 'trusted-dealer', 'triplesVerified' => $offline !== null || $verify, 'macChecked' => true];
    }
}
