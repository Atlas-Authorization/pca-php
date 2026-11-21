<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Acp;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ACP delegated payment tokens, x402 v1 / v2 (and its HTTP transport) and Stripe Shared Payment Granted Tokens against the TS
 * reference: test-data/ref-acp.json.gz, plus ref-acp-java-extra.json.gz (a real grant and a real signed PCActn, so the full proof
 * re-verification runs to an allow). Ed25519 is deterministic, so a minted token compares byte for byte. The corpus names the signing
 * key as "$seed:acp/signer"; the key is derived here from that label. Stores, verifiers and settle steps are built from the specs the
 * corpus names. A reason that embeds a library message is cut after "token signature did not verify" / "bound proof failed to verify".
 */
final class RefAcpDifferentialTest extends TestCase
{
    private const FILES = ['ref-acp.json.gz', 'ref-acp-java-extra.json.gz'];

    public static function provide(): array
    {
        $out = [];
        foreach (self::FILES as $f) {
            foreach (Base::datasets($f) as $name => $d) {
                $out["$f $name"] = $d;
            }
        }
        return $out;
    }

    /** Replace the corpus's seed placeholder by the key derived from the oracle's seed label. */
    private static function unseed(mixed $v): mixed
    {
        if ($v === '$seed:acp/signer') {
            return rtrim(strtr(base64_encode(hash('sha256', 'atlas-pca-conformance/acp/signer', true)), '+/', '-_'), '=');
        }
        if ($v instanceof Obj && $v->keys() === ['$seed']) { // the regenerated corpus names the key by a {"$seed": label} object
            return rtrim(strtr(base64_encode(hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true)), '+/', '-_'), '=');
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::unseed($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::unseed(...), $v) : $v;
    }

    private static function store(mixed $spec): mixed
    {
        return match ($spec) {
            'once' => new class {
                /** @var array<string,bool> */
                private array $seen = [];

                public function claim(string $jti, float $exp): bool
                {
                    if (isset($this->seen[$jti])) {
                        return false;
                    }
                    $this->seen[$jti] = true;
                    return true;
                }
            },
            'always' => new class {
                public function claim(string $jti, float $exp): bool
                {
                    return true;
                }
            },
            'never' => new class {
                public function claim(string $jti, float $exp): bool
                {
                    return false;
                }
            },
            'throw' => new class {
                public function claim(string $jti, float $exp): bool
                {
                    throw new \RuntimeException('store down');
                }
            },
            'truthy' => new class {
                public function claim(string $jti, float $exp): int
                {
                    return 1;
                }
            },
            default => $spec,
        };
    }

    private static function withStore(mixed $op): mixed
    {
        if (!($op instanceof Obj) || !$op->has('singleUse')) {
            return $op;
        }
        $o = new Obj();
        foreach ($op->keys() as $k) {
            $o->set($k, $k === 'singleUse' ? self::store($op->get($k)) : $op->get($k));
        }
        return $o;
    }

    private static function norm(Obj $r): Obj
    {
        $o = new Obj();
        foreach ($r->keys() as $k) {
            $v = $r->get($k);
            if ($k === 'reason' && is_string($v)) {
                $v = preg_replace('/\A(token signature did not verify|bound proof failed to verify): .*\z/s', '$1', $v);
            } elseif ($k === 'pcaResult' && $v instanceof Obj) {
                $v = Obj::of(['allow' => $v->get('allow')]);
            }
            $o->set($k, $v);
        }
        return $o;
    }

    private static function times(array $a): int
    {
        return count($a) > 2 ? (int)Js::num($a[2]) : 1;
    }

    private static function verifyToken(array $a): mixed
    {
        $op = self::withStore(self::unseed($a[1]));
        $rs = [];
        for ($i = 0, $n = self::times($a); $i < $n; $i++) {
            $rs[] = self::norm(Acp::verifyDelegatedPaymentToken($a[0], $op));
        }
        return self::times($a) === 1 ? $rs[0] : $rs;
    }

    private static function verifier(array $a): mixed
    {
        $fn = Acp::acpX402Verifier(self::withStore($a[1]));
        $rs = [];
        for ($i = 0, $n = self::times($a); $i < $n; $i++) {
            $rs[] = self::norm($fn($a[0]));
        }
        return self::times($a) === 1 ? $rs[0] : $rs;
    }

    private static function settle(array $a): mixed
    {
        $spec = $a[1];
        $opts = ['verify' => static function (mixed $p) use ($spec): mixed {
            if ($spec === 'throw') {
                throw new \RuntimeException('verify down');
            }
            return $spec;
        }];
        $s = $a[2] ?? null;
        if ($s === 'echo') {
            $opts['settle'] = static function (mixed $p, mixed $c): Obj {
                $o = Obj::of(['jti' => Js::opt($c, 'jti')]);
                if (Js::has($p, 'token')) { // an absent member stays absent (JS drops an undefined value)
                    $o->set('token', Js::opt($p, 'token'));
                }
                return $o;
            };
        } elseif ($s === 'value') {
            $opts['settle'] = static fn(): string => 'receipt-1';
        } elseif ($s === 'throw') {
            $opts['settle'] = static function (): never {
                throw new \RuntimeException('settle down');
            };
        } elseif ($s === 'undef') {
            $opts['settle'] = static fn(): mixed => null;
        }
        return Acp::x402Settle($a[0], $opts);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => [
                'v' => Acp::ACP_DELEGATED_TOKEN_VERSION, 't' => Acp::ACP_DELEGATED_TOKEN_TYPE, 's' => Acp::SPEND_CAP_CAVEAT,
                'm' => Acp::MERCHANT_ALLOW_CAVEAT, 'c' => Acp::MERCHANT_CATEGORY_CAVEAT, 'h' => Acp::HUMAN_PRESENT_CAVEAT,
                'x1' => Acp::X402_VERSION_1, 'x2' => Acp::X402_VERSION_2, 'sup' => Acp::X402_SUPPORTED_VERSIONS,
                'pr' => Acp::X402_V2_PAYMENT_REQUIRED_HEADER, 'ps' => Acp::X402_PAYMENT_SIGNATURE_HEADER,
                'pe' => Acp::X402_PAYMENT_RESPONSE_HEADER, 'st' => Acp::X402_HTTP_STATUS, 'spt' => Acp::STRIPE_SPT_OBJECT,
            ],
            'spendCapCaveat' => fn(array $a) => Acp::spendCapCaveat(...$a),
            'merchantAllowCaveat' => fn(array $a) => Acp::merchantAllowCaveat($a[0]),
            'merchantCategoryCaveat' => fn(array $a) => Acp::merchantCategoryCaveat($a[0]),
            'humanPresentCaveat' => fn(array $a) => Acp::humanPresentCaveat(...$a),
            'extractPaymentAuthority' => fn(array $a) => Acp::extractPaymentAuthority($a[0]),
            'checkPaymentAuthority' => fn(array $a) => Acp::checkPaymentAuthority($a[0], $a[1]),
            'mintDelegatedPaymentToken' => fn(array $a) => Acp::mintDelegatedPaymentToken($a[0], self::unseed($a[1])),
            'verifyDelegatedPaymentToken' => fn(array $a) => self::verifyToken($a),
            'x402Challenge' => fn(array $a) => Acp::x402Challenge($a[0], $a[1]),
            'x402ChallengeV2' => fn(array $a) => Acp::x402ChallengeV2($a[0], $a[1]),
            'x402Settle' => fn(array $a) => self::settle($a),
            'acpX402Verifier' => fn(array $a) => self::verifier($a),
            'toAcpAllowance' => fn(array $a) => Acp::toAcpAllowance($a[0]),
            'resourceInfoProblems' => fn(array $a) => Acp::resourceInfoProblems($a[0]),
            'requirementV2Problems' => fn(array $a) => Acp::requirementV2Problems($a[0]),
            'paymentRequiredV2Problems' => fn(array $a) => Acp::paymentRequiredV2Problems($a[0]),
            'paymentPayloadV2Problems' => fn(array $a) => Acp::paymentPayloadV2Problems($a[0]),
            'settlementResponseProblems' => fn(array $a) => Acp::settlementResponseProblems($a[0]),
            'stripeSptProblems' => fn(array $a) => Acp::stripeSptProblems($a[0]),
            'encodePaymentRequiredHeader' => fn(array $a) => Acp::encodePaymentRequiredHeader($a[0]),
            'decodePaymentRequiredHeader' => fn(array $a) => Acp::decodePaymentRequiredHeader($a[0]),
            'encodePaymentSignatureHeader' => fn(array $a) => Acp::encodePaymentSignatureHeader($a[0]),
            'decodePaymentSignatureHeader' => fn(array $a) => Acp::decodePaymentSignatureHeader($a[0]),
            'encodePaymentResponseHeader' => fn(array $a) => Acp::encodePaymentResponseHeader($a[0]),
            'decodePaymentResponseHeader' => fn(array $a) => Acp::decodePaymentResponseHeader($a[0]),
            'x402Negotiate' => fn(array $a) => Acp::x402Negotiate(...$a),
            'x402AcceptedMatches' => fn(array $a) => Acp::x402AcceptedMatches($a[0], $a[1]),
            'normalizeX402Payload' => fn(array $a) => Acp::normalizeX402Payload($a[0]),
            'readPaymentSignature' => fn(array $a) => Acp::readPaymentSignature($a[0]),
            'x402SettlementResponse' => fn(array $a) => Acp::x402SettlementResponse($a[0], $a[1]),
            'x402PaymentSignatureHeaders' => fn(array $a) => Acp::x402PaymentSignatureHeaders($a[0]),
            'parseStripeSpt' => fn(array $a) => Acp::parseStripeSpt($a[0]),
            'stripeSptUsable' => fn(array $a) => Acp::stripeSptUsable($a[0], $a[1]),
            'stripeUsageLimitsFor' => fn(array $a) => Acp::stripeUsageLimitsFor($a[0]),
            'stripeSptWithinClaims' => fn(array $a) => Acp::stripeSptWithinClaims($a[0], $a[1]),
        ]);
    }
}
