<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The authorize pipeline's 0.5 pieces against the TS reference: test-data/k05-authorize.json.gz (k05-oracles/authorize-oracle.mts):
 * tool_schema validation / evaluation, the risk policy, the envelope reader and whole authorize() scenarios (provenance by
 * default, fresh_at, escalation answers, undo admissions), projected exactly as the generator projects the TS result.
 */
final class K05AuthorizeDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-authorize.json.gz';
    /** The checks the projection keeps (the generator's KEY). */
    private const KEY = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'plan_root_authorized',
        'leaf_signature', 'counter_format', 'fresh_at', 'attestation', 'revocation', 'grant_ref', 'operation', 'params_digest', 'delegated_caveats',
        'policy', 'replay', 'provenance_flow', 'undo_window', 'escalation'];
    private const OWN = ['provenance_flow: ', 'undo_window: ', 'escalation: ', 'fresh_at: '];

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Authorize::class, $m))->invoke(null, ...$a);
    }

    /** One scenario: a fresh store, the config's hooks, every step projected like the generator's `scenario`. */
    private static function scenario(Obj $sc): array
    {
        $cfg = $sc->get('config');
        $grant = $sc->get('grant');
        $store = new MemoryStateStore();
        $revoked = false;
        $facts = $cfg->get('actions');
        $observed = $cfg->get('observed');
        $undo = $cfg->get('undo');
        $esc = $cfg->get('escalation');
        $out = [];
        foreach ($sc->get('steps') as $s) {
            $revoked = $s->get('revoked') === true;
            $r = Authorize::authorize($s->get('pcactn'), $s->get('operation'), $cfg->get('audience'),
                static fn($ref) => $ref === $grant->get('id') ? $grant : null, $store, static fn() => $revoked, $cfg->get('now')->int(), 'single-step',
                escalationPrincipals: $esc instanceof Obj ? $esc->get('principals') : null,
                escalationAnswer: $s->has('escalationAnswer') ? $s->get('escalationAnswer') : null,
                freshAt: $cfg->get('freshAt'),
                escalationRender: $esc instanceof Obj && $esc->has('render_digest') ? static fn() => $esc->get('render_digest') : null,
                insecureUnboundApproval: $esc instanceof Obj && $esc->get('insecureUnboundApproval') === true,
                provenance: $s->get('provenance'),
                provenanceMediators: $cfg->get('mediators'),
                provenanceActions: $facts instanceof Obj ? static fn(array $op) => $facts->get((string) $op['verb']) : null,
                provenanceObserved: $observed !== null ? static fn() => $observed : null,
                undo: $undo instanceof Obj ? static fn($p, $g, array $op) => $undo->has((string) $op['verb']) ? $undo->get((string) $op['verb']) : null : null,
            );
            // the PHP result names the capability chain check `chain` (the reference: cap_chain), and has no attestation verifier, so
            // an attestation check it does not report is the reference's `not-enforced` (a required one is reported as a fail)
            $named = [];
            foreach ($r->checks as $n => $st) {
                $named[$n === 'chain' ? 'cap_chain' : $n] = $st;
            }
            $named['attestation'] ??= 'not-enforced';
            $checks = [];
            foreach (self::KEY as $k) {
                if (isset($named[$k])) {
                    $checks[$k] = $named[$k];
                }
            }
            $out[] = [
                'allow' => $r->allow, 'decision' => $r->decision, 'status' => $r->status, 'checks' => $checks === [] ? new Obj() : $checks,
                'failed' => array_values(array_filter(self::KEY, static fn($k) => ($named[$k] ?? null) === 'fail')),
                'reasons' => array_values(array_filter($r->reasons, static fn($x) => array_filter(self::OWN, static fn($o) => str_starts_with($x, $o)) !== [])),
                'escalation' => $r->escalation === null ? null : ($r->allow ? $r->escalation : ['request' => true]),
                'undo' => $r->undo,
            ];
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'validateArgSchema' => fn(array $a) => Authorize::validateArgSchema($a[0]),
            'evaluateToolSchema' => function (array $a) {
                [$ok, $why] = Authorize::evaluateToolSchema($a[0], $a[1]);
                return $ok ? ['ok' => true] : ['ok' => false, 'reason' => $why];
            },
            'validateRiskPolicy' => fn(array $a) => self::priv('riskPolicyError', $a[0]),
            'readEnvelope' => fn(array $a) => Authorize::readEnvelope($a[0]),
            'requiresAttestation' => fn(array $a) => self::priv('requiresAttestation', $a[0]),
            'authorize' => fn(array $a) => self::scenario($a[0]),
        ]);
    }
}
