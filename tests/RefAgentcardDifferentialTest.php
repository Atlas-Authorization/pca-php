<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agentcard;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Signed Agent Cards, AgentFacts, hosting handlers and registry entries against the TS reference:
 * test-data/ref-agentcard.json.gz. Signatures are Ed25519 (deterministic), so issued output compares byte for byte. A refusal reason
 * that quotes the JOSE library is compared up to the first colon, as the corpus does.
 */
final class RefAgentcardDifferentialTest extends TestCase
{
    private const FILE = 'ref-agentcard.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function fix(mixed $s): mixed
    {
        return is_string($s) ? preg_replace('/\A(signature( \d+)? did not verify|could not resolve verification key): .*\z/s', '$1', $s) : $s;
    }

    /** @param array<string,mixed> $r */
    private static function norm(array $r): array
    {
        if (isset($r['reason'])) {
            $r['reason'] = self::fix($r['reason']);
        }
        if (isset($r['attestations']) && is_array($r['attestations'])) {
            $r['attestations'] = array_map(static function (array $a): array {
                if (isset($a['reason'])) {
                    $a['reason'] = self::fix($a['reason']);
                }
                return $a;
            }, $r['attestations']);
        }
        return $r;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => [
                'DEFAULT_ALG' => Agentcard::DEFAULT_ALG, 'AGENT_FACTS_CONTEXT' => Agentcard::AGENT_FACTS_CONTEXT,
                'PCA_ATTESTOR_ID' => Agentcard::PCA_ATTESTOR_ID, 'WELL_KNOWN_AGENT_CARD_PATH' => Agentcard::WELL_KNOWN_AGENT_CARD_PATH,
                'WELL_KNOWN_AGENT_FACTS_PATH' => Agentcard::WELL_KNOWN_AGENT_FACTS_PATH,
            ],
            'jcsBytes' => fn(array $a) => Base::outBytes(Agentcard::jcsBytes($a[0])),
            'validateAgentCard1' => fn(array $a) => Agentcard::validateAgentCard1($a[0]),
            'buildAgentCard' => fn(array $a) => Agentcard::buildAgentCard($a[0], $a[1]),
            'issueSignedAgentCard' => fn(array $a) => Agentcard::issueSignedAgentCard($a[0], $a[1], $a[2] ?? null),
            'verifyAgentCard' => fn(array $a) => self::norm(Agentcard::verifyAgentCard($a[0], $a[1])),
            'issueAgentFacts' => fn(array $a) => Agentcard::issueAgentFacts($a[0], $a[1]),
            'addAttestation' => fn(array $a) => Agentcard::addAttestation($a[0], $a[1]),
            'verifyAgentFacts' => fn(array $a) => self::norm(Agentcard::verifyAgentFacts($a[0], $a[1])),
            'agentCardHandler' => fn(array $a) => Agentcard::agentCardHandler($a[0], $a[1])($a[2]),
            'agentFactsHandler' => fn(array $a) => Agentcard::agentFactsHandler($a[0], $a[1])($a[2]),
            'toRegistryEntry' => fn(array $a) => Agentcard::toRegistryEntry($a[0], $a[1]),
        ]);
    }
}
