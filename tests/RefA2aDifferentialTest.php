<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\A2a;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The A2A package surface against the TS reference: test-data/ref-a2a.json.gz (proof-carrying tasks, signed and extended Agent Cards,
 * RFC 8785, the A2A 1.0 card schema, the extension declaration, AUTH_REQUIRED, per-hop delegation, push tokens, the payment-mandate
 * envelope and signed task-update receipts). Ed25519 is deterministic, so signed cards and receipts compare byte for byte. The
 * corpus names the card signing key as "$seed:<label>"; the key is derived here from that label. Every verify case here is refused
 * before a full verifier would run. A reason that quotes the JOSE library or a runtime error is compared up to the first colon.
 */
final class RefA2aDifferentialTest extends TestCase
{
    private const FILE = 'ref-a2a.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    /** Replace a "$seed:<label>" placeholder by the base64url of the seed the oracle derived from that label. */
    private static function unseed(mixed $v): mixed
    {
        if (is_string($v) && str_starts_with($v, '$seed:')) {
            return rtrim(strtr(base64_encode(self::seed(substr($v, 6))), '+/', '-_'), '=');
        }
        if ($v instanceof Obj && $v->keys() === ['$seed'] && is_string($v->get('$seed'))) { // the corpus's object form of the same placeholder
            return rtrim(strtr(base64_encode(self::seed($v->get('$seed'))), '+/', '-_'), '=');
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

    private static function norm(mixed $r): mixed
    {
        if ($r instanceof Obj && is_string($r->get('reason')) && preg_match('/\A(signature \d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): /', $r->get('reason'), $m) === 1) {
            $o = new Obj();
            foreach ($r->keys() as $k) {
                $o->set($k, $k === 'reason' ? $m[1] : $r->get($k));
            }
            return $o;
        }
        return $r;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => [
                'PCA_A2A_EXTENSION_URI' => A2a::PCA_A2A_EXTENSION_URI, 'TASK_STATE_AUTH_REQUIRED' => A2a::TASK_STATE_AUTH_REQUIRED,
                'TASK_STATE_INPUT_REQUIRED' => A2a::TASK_STATE_INPUT_REQUIRED, 'A2A_AP2_CONTEXT' => A2a::A2A_AP2_CONTEXT,
                'A2A_RECEIPT_DOMAIN' => A2a::A2A_RECEIPT_DOMAIN, 'RECEIPT_KEY' => A2a::RECEIPT_KEY,
            ],
            'jcsBytes' => fn(array $a) => Base::outBytes(A2a::jcsBytes($a[0])),
            'validateAgentCard1' => fn(array $a) => A2a::validateAgentCard1($a[0]),
            'attachPcaToA2ATask' => fn(array $a) => A2a::attachPcaToA2ATask($a[0], $a[1]),
            'attachPcaToA2AMessage' => fn(array $a) => A2a::attachPcaToA2AMessage($a[0], $a[1]),
            'extractPca' => fn(array $a) => A2a::extractPca($a[0]),
            'extractPcaFromMessage' => fn(array $a) => A2a::extractPcaFromMessage($a[0]),
            'issueSignedAgentCard' => fn(array $a) => A2a::issueSignedAgentCard($a[0], self::unseed($a[1]), $a[2] ?? null),
            'verifyAgentCard' => fn(array $a) => self::norm(A2a::verifyAgentCard($a[0], self::unseed($a[1]))),
            'verifyA2ATask' => fn(array $a) => self::norm(A2a::verifyA2ATask($a[0], $a[1] ?? null)),
            'middleware' => fn(array $a) => self::norm((A2a::pcaA2AMiddleware($a[1] ?? null))($a[0])),
            'resumeAuthRequired' => fn(array $a) => self::norm(A2a::resumeAuthRequired($a[0], $a[1], $a[2])),
            'verifyA2ADelegation' => fn(array $a) => self::norm(A2a::verifyA2ADelegation($a[0])),
            'a2aPaymentMandateFromPca' => fn(array $a) => A2a::a2aPaymentMandateFromPca($a[0], $a[1]),
            'pcaBindingFromA2APaymentMandate' => fn(array $a) => A2a::pcaBindingFromA2APaymentMandate($a[0]),
            'verifyA2APaymentMandate' => fn(array $a) => self::norm(A2a::verifyA2APaymentMandate($a[0], $a[1], $a[2] ?? null)),
            'pcaExtensionDeclaration' => fn(array $a) => A2a::pcaExtensionDeclaration(...$a),
            'readPcaExtension' => fn(array $a) => A2a::readPcaExtension($a[0]),
            'clientOptsIntoPca' => fn(array $a) => A2a::clientOptsIntoPca($a[0]),
            'isAuthRequired' => fn(array $a) => A2a::isAuthRequired($a[0]),
            'authRequiredStatus' => fn(array $a) => A2a::authRequiredStatus($a[0], $a[1]),
            'readAuthRequiredNeed' => fn(array $a) => A2a::readAuthRequiredNeed($a[0]),
            'answerMessage' => fn(array $a) => A2a::answerMessage($a[0], $a[1], $a[2]),
            'resumeGate' => fn(array $a) => A2a::resumeGateObj($a[0]),
            'chainExtends' => fn(array $a) => A2a::chainExtends($a[0], $a[1]),
            'checkChainExtension' => fn(array $a) => A2a::checkChainExtension($a[0]),
            'pcaPushToken' => fn(array $a) => A2a::pcaPushToken(...$a),
            'checkPushNotification' => fn(array $a) => A2a::checkPushNotification($a[0], $a[1]),
            'uniformTaskNotFound' => fn(array $a) => A2a::uniformTaskNotFound(),
            'signTaskReceipt' => fn(array $a) => A2a::signTaskReceipt(self::seed((string)$a[0]), $a[1]),
            'verifyTaskReceipt' => fn(array $a) => A2a::verifyTaskReceipt($a[0], $a[1]),
            'receiptDigest' => fn(array $a) => A2a::receiptDigest($a[0]),
            'checkReceiptChain' => fn(array $a) => A2a::checkReceiptChainOf($a[0], $a[1]),
            'mayTriggerNext' => fn(array $a) => A2a::mayTriggerNextOf($a[0], $a[1]),
            'attachReceipt' => fn(array $a) => A2a::attachReceipt($a[0], $a[1]),
            'receiptOfPayload' => fn(array $a) => A2a::receiptOfPayload($a[0]),
            'extendedAgentCard' => fn(array $a) => A2a::extendedAgentCard($a[0], $a[1]),
        ]);
    }
}
