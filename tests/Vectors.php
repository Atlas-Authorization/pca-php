<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Pca.php';
require_once __DIR__ . '/../src/Decision.php';
require_once __DIR__ . '/../src/ForbidCertificate.php';
require_once __DIR__ . '/../src/PolicyLink.php';
require_once __DIR__ . '/../src/Escalation.php';
require_once __DIR__ . '/../src/CaveatLang.php';
require_once __DIR__ . '/../src/Passport.php';
require_once __DIR__ . '/../src/Authorize.php';
require_once __DIR__ . '/../src/Attest/Factory.php';
require_once __DIR__ . '/../src/Ledger.php';
require_once __DIR__ . '/../src/Optimistic.php';
require_once __DIR__ . '/../src/Mesh.php';
require_once __DIR__ . '/../src/IntentHistory.php';
require_once __DIR__ . '/../src/K3.php';
require_once __DIR__ . '/../src/PcaGrant.php';
require_once __DIR__ . '/../src/Blueprint.php';
require_once __DIR__ . '/../src/K4.php';
require_once __DIR__ . '/../src/RuntimeClaim.php';
require_once __DIR__ . '/../src/A2a.php';
require_once __DIR__ . '/../src/Workflow.php';
require_once __DIR__ . '/../src/ReadSide.php';
require_once __DIR__ . '/../src/ReadVault.php';
require_once __DIR__ . '/../src/Authorize.php';
require_once __DIR__ . '/../src/Lease.php';
require_once __DIR__ . '/../src/BreakGlass.php';
require_once __DIR__ . '/../src/MissingContext.php';
require_once __DIR__ . '/../src/PolicyClasses.php';
require_once __DIR__ . '/../src/Obligations.php';
require_once __DIR__ . '/../src/ProvenanceGate.php';
require_once __DIR__ . '/../src/SigstoreBundle.php';
require_once __DIR__ . '/OracleData.php';
require_once __DIR__ . '/NativeParityVectors.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\CaveatLang;
use Atlas\Pca\Decision;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Escalation;
use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\PolicyLink;
use Atlas\Pca\HistoryError;
use Atlas\Pca\IntentHistory;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\Ledger;
use Atlas\Pca\Mesh;
use Atlas\Pca\Optimistic;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
use Atlas\Pca\PcaGrant;
use Atlas\Pca\Blueprint;
use Atlas\Pca\K4;
use Atlas\Pca\RuntimeClaim;
use Atlas\Pca\A2a;
use Atlas\Pca\Workflow;
use Atlas\Pca\ReadSide;
use Atlas\Pca\ReadVault;
use Atlas\Pca\MemoryVault;
use Atlas\Pca\BreakGlass;
use Atlas\Pca\BreakGlassRegistry;
use Atlas\Pca\Lease;
use Atlas\Pca\MissingContext;
use Atlas\Pca\PolicyClasses;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\Obligations;
use Atlas\Pca\ProvenanceGate;
use Atlas\Pca\SigstoreBundle;
use Atlas\Pca\PdoStateStore;
use Atlas\Pca\Pca;

/**
 * Replay of the shared native-parity conformance vectors (packages/pca/conformance): one static method per family, each
 * returning [number of vectors run, list of failures]. Used by conformance-vectors.php (plain runner, one CI step per family)
 * and by VectorsTest (PHPUnit). A missing vector file is a FAILURE (never a skip): the mirror vendoring refuses without them.
 */
final class Vectors
{
    public const DIR = __DIR__ . '/../conformance/';

    /** The parsed file; throws when the file is missing or unreadable (a family that cannot run fails). */
    public static function load(string $file): Obj
    {
        $path = self::DIR . $file;
        if (!is_file($path) && is_file(__DIR__ . '/../conformance/' . $file)) {
            $path = __DIR__ . '/../conformance/' . $file; // the SDK mirror vendors the corpus beside the package
        }
        $alt = getenv('PCA_CONFORMANCE_DIR');
        if (!is_file($path) && is_string($alt) && $alt !== '') {
            $path = rtrim($alt, '/') . '/' . $file; // a corpus kept outside the tree (a flagship checkout, a generated artifact)
        }
        $text = is_file($path) ? file_get_contents($path) : false;
        if ($text === false) {
            throw new \RuntimeException("conformance vector file missing: $file");
        }
        $doc = Json::parseLax($text);
        if (!($doc instanceof Obj)) {
            throw new \RuntimeException("conformance vector file is not an object: $file");
        }
        return $doc;
    }

    /** @return array{int, list<string>} */
    public static function run(string $family): array
    {
        try {
            return match ($family) {
                'decision' => self::decision(),
                'escalation' => self::escalation(),
                'caveat-lang' => self::caveatLang(),
                'passport' => self::passport(),
                'passport-hardware' => self::passportHardware(),
                'intent-state' => self::intentState(),
                'ledger' => self::ledger(),
                'optimistic' => self::optimistic(),
                'mesh' => self::mesh(),
                'model-rules' => self::modelRules(),
                'attestation' => self::attestation(),
                'goal' => NativeParityVectors::goal(),
                'staleness' => NativeParityVectors::staleness(),
                'operations' => NativeParityVectors::operations(),
                'plans' => NativeParityVectors::plans(),
                'assurance' => NativeParityVectors::assurance(),
                'policy-authoring' => self::policyAuthoring(),
                'k3' => self::k3(),
                'fresh-at' => self::freshAt(),
                'pca-grant' => self::pcaGrant(),
                'blueprint' => self::blueprint(),
                'k4' => self::k4(),
                'runtime-claim' => self::runtimeClaim(),
                'a2a' => self::a2a(),
                'workflow' => self::workflow(),
                'readside' => self::readside(),
                'vault-aggregate' => self::vaultAggregate(),
                'authorize-workflow' => self::authorizeWorkflow(),
                'lease' => self::lease(),
                'obligations' => self::obligations(),
                'break-glass' => self::breakGlass(),
                'missing-context' => self::missingContext(),
                'policy-classes' => self::policyClasses(),
                'provenance' => self::provenance(),
                'sigstore' => self::sigstore(),
                default => throw new \InvalidArgumentException("unknown vector family: $family"),
            };
        } catch (\Throwable $e) {
            return [0, ["$family: " . $e->getMessage()]];
        }
    }

    public const FAMILIES = ['decision', 'escalation', 'caveat-lang', 'passport', 'passport-hardware', 'intent-state', 'ledger', 'optimistic', 'mesh', 'model-rules', 'attestation', 'goal', 'staleness', 'operations', 'plans', 'assurance', 'policy-authoring', 'k3', 'fresh-at', 'pca-grant', 'blueprint', 'a2a', 'k4', 'workflow', 'readside', 'vault-aggregate', 'authorize-workflow', 'lease', 'obligations', 'break-glass', 'missing-context', 'policy-classes', 'provenance', 'sigstore', 'runtime-claim'];

    /** Number-aware structural equality of two JSON values (Num by value). */
    public static function same(mixed $a, mixed $b): bool
    {
        if ($a instanceof Num || $b instanceof Num) {
            return $a instanceof Num && $b instanceof Num && $a->float() === $b->float();
        }
        if ($a instanceof Obj && $b instanceof Obj) {
            $ka = $a->keys();
            $kb = $b->keys();
            sort($ka);
            sort($kb);
            if ($ka !== $kb) {
                return false;
            }
            foreach ($ka as $k) {
                if (!self::same($a->get($k), $b->get($k))) {
                    return false;
                }
            }
            return true;
        }
        if (is_array($a) && is_array($b)) {
            if (count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $i => $x) {
                if (!array_key_exists($i, $b) || !self::same($x, $b[$i])) {
                    return false;
                }
            }
            return true;
        }
        return $a === $b;
    }

    // ---- forbid-certificate-vectors.json (table) and policy-link-vectors.json -------------------------------------------

    /** @return array{int, list<string>} */
    public static function policyAuthoring(): array
    {
        $n = 0;
        $fails = [];
        $fc = self::load('forbid-certificate-vectors.json')->get('table');
        if (!is_array($fc) || count($fc) < 19) {
            $fails[] = 'forbid-certificate table: fewer than 19 vectors';
        }
        foreach ($fc as $e) {
            $n++;
            $prec = $e->has('options') && $e->get('options')->has('precedence') ? $e->get('options')->get('precedence') : [];
            if (ForbidCertificate::consistent($e->get('certificate'), $prec) !== $e->get('expect')->get('consistent')) {
                $fails[] = 'forbid-certificate ' . $e->get('name');
            }
        }
        $doc = self::load('policy-link-vectors.json');
        $def = $doc->get('template')->get('def');
        $n++;
        if (PolicyLink::templateDigest($def) !== $doc->get('template')->get('digest')) {
            $fails[] = 'policy-link: template digest';
        }
        foreach ($doc->get('def_errors') as $e) {
            $n++;
            if (PolicyLink::templateDefError($e->get('def')) !== $e->get('expect')) {
                $fails[] = 'policy-link def ' . $e->get('name');
            }
        }
        $res = static function (array $r): ?string {
            return $r['ok'] ? null : $r['reason'];
        };
        foreach ($doc->get('instantiate') as $e) {
            $n++;
            $r = PolicyLink::instantiateTemplate($def, $e->get('slots'));
            $x = $e->get('expect');
            $ok = $x->get('ok') === true ? $r['ok'] && self::same($r['policy'], $x->get('policy')) : !$r['ok'] && $r['reason'] === $x->get('reason');
            if (!$ok) {
                $fails[] = 'policy-link instantiate ' . $e->get('name') . ': ' . json_encode($r['reason'] ?? 'ok');
            }
        }
        foreach ($doc->get('verify') as $e) {
            $n++;
            $r = $e->get('kind') === 'template' ? PolicyLink::verifyTemplate($e->get('signed'), $e->get('trusted')) : PolicyLink::verifyTighten($e->get('signed'), $e->get('trusted'));
            $x = $e->get('expect');
            if ($r['ok'] !== $x->get('ok') || ($r['ok'] === false && $r['reason'] !== $x->get('reason'))) {
                $fails[] = 'policy-link verify ' . $e->get('name');
            }
        }
        foreach ($doc->get('ref_errors') as $e) {
            $n++;
            if (PolicyLink::templateRefError($e->get('ref')) !== $e->get('expect')) {
                $fails[] = 'policy-link ref ' . $e->get('name');
            }
        }
        foreach ($doc->get('resolve') as $e) {
            $n++;
            $r = PolicyLink::resolveLink($e->get('ref'), $e->get('registry'));
            $x = $e->get('expect');
            $ok = $x->get('ok') === true
                ? $r['ok'] && self::same($r['policy'], $x->get('policy')) && $r['overlays'] === $x->get('overlays')->int()
                : !$r['ok'] && $r['reason'] === $x->get('reason');
            if (!$ok) {
                $fails[] = 'policy-link resolve ' . $e->get('name') . ': ' . json_encode($r['reason'] ?? 'ok');
            }
        }
        return [$n, $fails];
    }

    // ---- k3-vectors.json: the K3 operational-plane artifacts -------------------------------------------------------------

    /** The row counts the reference generated: a table that shrank (or a runner that skipped rows) fails. */
    private const K3_ROWS = ['fresh_at_verify' => 5, 'fresh_at_digest' => 2, 'fresh_at_check' => 14, 'bundle_digest' => 2, 'bundle_verify' => 15,
        'log_commit' => 3, 'log_head_verify' => 4, 'log_inclusion' => 6, 'log_batch_verify' => 9, 'list_objects_digest' => 1,
        'list_receipt_verify' => 6, 'list_bind' => 2, 'list_cursor_verify' => 11, 'authority_digest' => 2, 'authority_compare' => 11,
        'amend_verify' => 16, 'revoke_verify' => 7, 'need_approve_verify' => 11];

    public static function k3(): array
    {
        $prims = self::load('k3-vectors.json')->get('primitives');
        $n = 0;
        $fails = [];
        foreach (self::K3_ROWS as $kind => $want) {
            $rows = $prims->get($kind);
            if (!is_array($rows) || count($rows) !== $want) {
                $fails[] = "$kind: " . (is_array($rows) ? count($rows) : 'no') . " rows, the reference has $want";
                continue;
            }
            foreach ($rows as $v) {
                $n++;
                try {
                    $got = K3::run($kind, $v->get('input'));
                } catch (\Throwable $e) {
                    $fails[] = "$kind/" . $v->get('name') . ': threw ' . $e->getMessage();
                    continue;
                }
                if (!self::same($got, $v->get('expect'))) {
                    $fails[] = "$kind/" . $v->get('name') . ': got ' . Json::canonicalizeLenient($got) . ' want ' . Json::canonicalizeLenient($v->get('expect'));
                }
            }
        }
        return [$n, $fails];
    }

    // ---- fresh-at-vectors.json: the `fresh_at` PCActn member -------------------------------------------------------------

    public static function freshAt(): array
    {
        $rows = self::load('fresh-at-vectors.json')->get('vectors');
        $fails = [];
        if (!is_array($rows) || count($rows) !== 28) {
            $fails[] = 'fresh-at: ' . (is_array($rows) ? count($rows) : 'no') . ' vectors, the reference has 28';
            $rows = is_array($rows) ? $rows : [];
        }
        foreach ($rows as $v) {
            $name = $v->get('name');
            $ctx = $v->get('context');
            $x = $v->get('expect');
            $r = Pca::verifyPcactnCore($v->get('pcactn'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'), null, null, null,
                $ctx->has('fresh_at') ? $ctx->get('fresh_at') : null);
            $got = $r['checks'];
            $wireFail = ($got['wire'] ?? true) === false;
            $fresh = $wireFail || !array_key_exists('fresh_at', $got) ? 'absent' : ($got['fresh_at'] ? 'pass' : 'fail');
            $checks = [];
            foreach ($got as $k => $ok) {
                if ($k !== 'fresh_at') {
                    $checks[$k] = $ok;
                }
            }
            $status = [];
            foreach ($got as $k => $ok) {
                $status[$k] = $ok ? 'pass' : 'fail';
            }
            $decision = Decision::decisionOf($r['allow'], $status, $r['reasons'] ?? ($r['reason'] !== '' ? [$r['reason']] : []));
            $wantChecks = [];
            foreach ($x->get('checks')->keys() as $k) {
                $wantChecks[$k] = $x->get('checks')->get($k);
            }
            $bad = [];
            $r['allow'] !== $x->get('allow') && $bad[] = 'allow';
            $checks !== $wantChecks && $bad[] = 'checks ' . json_encode($checks);
            $fresh !== $x->get('fresh_at') && $bad[] = "fresh_at $fresh";
            $decision !== $x->get('decision') && $bad[] = "decision $decision";
            // the leaf-signature reason text is this SDK's own wording (the vectors pin the check, not that prose)
            if ($x->has('reason') && !str_starts_with($x->get('reason'), 'leaf_signature:') && $r['reason'] !== $x->get('reason')) {
                $bad[] = 'reason ' . $r['reason'];
            }
            if (!$x->has('reason') && $r['allow'] !== true) {
                $bad[] = 'unexpected refusal ' . $r['reason'];
            }
            if ($bad !== []) {
                $fails[] = "fresh-at/$name: " . implode('; ', $bad);
            }
        }
        return [count($rows), $fails];
    }

    // ---- pca-grant-vectors.json: the `pca_grant` authorization-details type ------------------------------------------------

    public static function pcaGrant(): array
    {
        $doc = self::load('pca-grant-vectors.json');
        $fails = [];
        $n = 0;
        foreach ($doc->get('digest') as $v) {
            $n++;
            $ids = $v->get('ids');
            PcaGrant::chainDigest($ids) !== $v->get('digest') && $fails[] = 'pca-grant/digest ' . implode(',', $ids);
        }
        foreach ($doc->get('detail') as $v) {
            $n++;
            $code = PcaGrant::validate($v->get('input'));
            $x = $v->get('expect');
            if (($code === null) !== $x->get('ok') || ($code !== null && $code !== $x->get('code'))) {
                $fails[] = 'pca-grant/detail/' . $v->get('name') . ': ' . ($code ?? 'ok');
            }
        }
        foreach ($doc->get('array') as $v) {
            $n++;
            [$list, $code] = PcaGrant::parse($v->get('input'));
            $x = $v->get('expect');
            $ok = ($code === null) === $x->get('ok')
                && ($code === null ? count($list) === $x->get('count')->int() : $code === $x->get('code'));
            $ok || $fails[] = 'pca-grant/array/' . $v->get('name') . ': ' . ($code ?? 'ok');
        }
        foreach ($doc->get('presentation') as $v) {
            $n++;
            $p = $v->get('presented');
            [$idx, $code] = PcaGrant::check($v->get('details'), $p->get('resource'), $p->get('chain_ids'), $p->get('proof_verified'));
            $x = $v->get('expect');
            $ok = ($code === null) === $x->get('allow')
                && ($code === null ? $idx === $x->get('index')->int() : $code === $x->get('code'));
            $ok || $fails[] = 'pca-grant/presentation/' . $v->get('name') . ': ' . ($code ?? "allow $idx");
        }
        return [$n, $fails];
    }

    // ---- blueprint-vectors.json: agent blueprints (ceiling and group kill) -----------------------------------------------------

    /** Runtime-class claims: runtime-claim-vectors.json (a missing file fails). */
    public static function runtimeClaim(): array
    {
        $doc = self::load('runtime-claim-vectors.json');
        $t = $doc->get('trust');
        $pinned = array_values($t->get('pinnedAttestors'));
        $pd = $t->get('passportDigest');
        $ev = array_values($t->get('verifiedEvidenceDigests'));
        $fails = [];
        $n = 0;
        foreach ($doc->get('cases') as $c) {
            $n++;
            $g = RuntimeClaim::verifiedClass($c->get('claim'), $pinned, $pd, $ev, $c->get('now'));
            $g === $c->get('expect') || $fails[] = 'runtime-claim/' . $c->get('name') . ': ' . $g;
        }
        $first = $doc->get('cases')[0];
        $n += 3;
        RuntimeClaim::verifiedClass($first->get('claim'), [], $pd, $ev, $first->get('now')) === 'none' || $fails[] = 'runtime-claim/unpinned accepted';
        RuntimeClaim::verifiedClass($first->get('claim'), $pinned, $pd, [], $first->get('now')) === 'none' || $fails[] = 'runtime-claim/unverified evidence accepted';
        RuntimeClaim::verifiedClass(null, $pinned, $pd, $ev, 0) === 'none' || $fails[] = 'runtime-claim/null accepted';
        return [$n, $fails];
    }

    public static function blueprint(): array
    {
        $doc = self::load('blueprint-vectors.json');
        $recs = $doc->get('records');
        $fails = [];
        $n = 0;
        foreach ($recs as $i => $r) {
            $n++;
            Blueprint::verify($r) !== ($i !== 8) && $fails[] = "blueprint/record $i";
        }
        foreach ($doc->get('scenarios') as $s) {
            $store = [];
            foreach ($s->get('steps') as $st) {
                $n++;
                $x = $st->get('expect');
                if ($st->get('op') === 'accept') {
                    $g = Blueprint::accept($store, [$doc->get('operator')], $recs[$st->get('record')->int()]);
                    $ok = $g['ok'] === $x->get('ok') && ($g['ok'] ? $g['replaced'] === $x->get('replaced') : $g['code'] === $x->get('code'));
                } else {
                    $o = $st->get('opts');
                    $g = Blueprint::check($st->get('chain'), $store, $o->get('now'), $o->get('mode'), $o->has('minEpoch') ? $o->get('minEpoch')->int() : null);
                    $ok = $g['decision'] === $x->get('decision')
                        && (!$x->has('code') || $g['code'] === $x->get('code'))
                        && (!$x->has('blueprint') || ($g['blueprint'] ?? null) === $x->get('blueprint'))
                        && (!$x->has('governed') || $g['governed'] === $x->get('governed'))
                        && ($x->get('decision') !== 'escalate' || ($g['have'] === $x->get('have')->int() && $g['need'] === $x->get('need')->int()));
                }
                $ok || $fails[] = 'blueprint/' . $s->get('name') . ': ' . json_encode($g);
            }
        }
        return [$n, $fails];
    }

    // ---- k4-vectors.json: escalation pricing, network-token binding, ERC-7715 permission check --------------------------------

    public static function k4(): array
    {
        $doc = self::load('k4-vectors.json');
        $fails = [];
        $n = 0;
        $esc = $doc->get('escalation');
        foreach ($esc->get('config_cases') as $c) {
            $n++;
            K4::pricingConfigError($c->get('config')) === $c->get('expect') || $fails[] = 'k4/config/' . $c->get('name');
        }
        foreach ($esc->get('decisions') as $c) {
            $n++;
            $g = K4::decide($esc->get('config'), $c->get('calibration'), $c->get('risk'));
            ($g['ask'] === $c->get('expect')->get('ask') && $g['reason'] === $c->get('expect')->get('reason')) || $fails[] = 'k4/decision/' . json_encode($g);
        }
        foreach ($esc->get('calibration') as $c) {
            $n++;
            $risks = [];
            foreach ($c->get('risks')->keys() as $k) {
                $risks[$k] = $c->get('risks')->get($k);
            }
            $g = K4::updateCalibration($c->get('config'), $c->get('start')->get('multiplierPpm')->int(), $c->get('start')->get('seen'), $c->get('answers'), $risks);
            $x = $c->get('expect');
            ($g['mult'] === $x->get('multiplierPpm')->int() && $g['seen'] === $x->get('seen')) || $fails[] = 'k4/calibration/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('network_binding')->get('cases') as $c) {
            $n++;
            $e = $c->get('expect_in');
            K4::verifyBinding($c->get('binding'), $e->get('grant'), $e->get('holder'), $e->get('issuer_nonce'), $e->has('provider') ? $e->get('provider') : null) === $c->get('expect')
                || $fails[] = 'k4/binding/' . $c->get('name');
        }
        foreach ($doc->get('erc7715')->get('cases') as $c) {
            $n++;
            $o = $c->get('opts');
            $ctx = $o->has('contexts') ? $o->get('contexts') : new Obj();
            K4::verifyGranted($c->get('envelope'), $c->get('sent'), $c->get('got'), $o->get('allowedManagers'), static fn (string $k): ?string => $ctx->get($k)) === $c->get('expect')
                || $fails[] = 'k4/erc7715/' . $c->get('name');
        }
        return [$n, $fails];
    }

    // ---- a2a-vectors.json: the A2A binding (typed needs, chain extension, resume gate, push tokens, receipts) ------------------

    public static function a2a(): array
    {
        $doc = self::load('a2a-vectors.json');
        $fails = [];
        $n = 0;
        $strs = static fn (mixed $l): array => array_values($l);
        foreach ($doc->get('need') as $c) {
            $n++;
            [$need, $code] = A2a::decodeNeed($c->get('input') instanceof Num ? $c->get('input')->lexeme : $c->get('input'));
            $x = $c->get('expect');
            $ok = ($code === null) === $x->get('ok') && ($code === null ? A2a::needDigest($need) === $x->get('digest') : $code === $x->get('code'));
            $ok || $fails[] = 'a2a/need/' . $c->get('name') . ': ' . ($code ?? 'ok');
        }
        $push = $doc->get('push');
        foreach ($push->get('tokens') as $t) {
            $n++;
            A2a::pushToken($t->get('task_id'), $strs($t->get('chain_ids')), $t->get('salt')) !== $t->get('token') && $fails[] = 'a2a/push/token';
        }
        foreach ($push->get('weak_salts') as $s) {
            $n++;
            A2a::pushToken('t', ['a'], $s) !== null && $fails[] = 'a2a/push/weak-salt';
        }
        foreach ($push->get('checks') as $c) {
            $n++;
            $e = $c->get('expected');
            $d = $c->get('delivered');
            $g = A2a::checkPush($e->get('task_id'), $strs($e->get('chain_ids')), $e->get('salt'), $d->get('token'), $d->get('payload'));
            $x = $c->get('expect');
            $ok = $g['ok'] === $x->get('ok') && ($g['ok'] || $g['reason'] === $x->get('reason'));
            $ok || $fails[] = 'a2a/push/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('chains') as $c) {
            $n++;
            $lists = array_map($strs, $c->get('chains'));
            $g = A2a::checkChainExtension($lists);
            $x = $c->get('expect');
            $ok = $g['ok'] === $x->get('ok') && ($g['ok'] || ($g['reason'] === $x->get('reason') && $g['failedHop'] === $x->get('failedHop')->int()));
            $ok || $fails[] = 'a2a/chains/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('resume') as $c) {
            $n++;
            $g = A2a::resumeGate($c->get('state'), $c->get('need_encoded'), $c->get('answer_need_digest'), $c->get('proof_action'));
            $g !== $c->get('expect') && $fails[] = 'a2a/resume/' . $c->get('name') . ': ' . json_encode($g);
        }
        $R = $doc->get('receipts');
        $recs = $R->get('records');
        $signer = $R->get('signer');
        foreach ($R->get('verify') as $v) {
            $n++;
            A2a::verifyReceipt($recs[$v->get('record')->int()], $signer) !== $v->get('ok') && $fails[] = 'a2a/receipts/verify ' . $v->get('record')->lexeme;
        }
        foreach ($R->get('digests') as $d) {
            $n++;
            A2a::receiptDigest($recs[$d->get('record')->int()]) !== $d->get('digest') && $fails[] = 'a2a/receipts/digest';
        }
        foreach ($R->get('scenarios') as $s) {
            $n++;
            $list = array_map(static fn ($i) => $recs[$i->int()], $s->get('indices'));
            $g = A2a::checkReceiptChain($list, $signer, $s->get('task_id'), $strs($s->get('chain_ids')));
            $x = $s->get('expect');
            $ok = $g['ok'] === $x->get('ok')
                && ($g['ok'] ? ($g['terminal'] === $x->get('terminal') && $g['last_state'] === $x->get('last_state'))
                    : ($g['code'] === $x->get('code') && (!$x->has('at') || $g['at'] === $x->get('at')->int())));
            $ok && A2a::mayTriggerNext($list, $signer, $s->get('task_id'), $strs($s->get('chain_ids'))) === $s->get('may_trigger_next') || $fails[] = 'a2a/receipts/' . $s->get('name') . ': ' . json_encode($g);
        }
        return [$n, $fails];
    }

    // ---- workflow-vectors.json / readside-vectors.json: K5 workflow admission and read-side authorization ---------------------

    /** Field-for-field equality of a result (PHP arrays, Obj, ints) with an expected parsed-JSON value; an integer is exactly a Num integer. */
    private static function eqK5(mixed $actual, mixed $exp): bool
    {
        if ($exp instanceof Num) {
            $v = $actual instanceof Num ? $actual->lexeme : (is_int($actual) ? (string)$actual : null);
            return $v !== null && $exp->lexeme === $v;
        }
        if ($exp instanceof Obj) {
            if (is_array($actual) && !array_is_list($actual)) {
                $actual = Obj::of($actual);
            }
            if (!($actual instanceof Obj) || count($actual->keys()) !== count($exp->keys())) {
                return false;
            }
            foreach ($exp->keys() as $k) {
                if (!$actual->has($k) || !self::eqK5($actual->get($k), $exp->get($k))) {
                    return false;
                }
            }
            return true;
        }
        if (is_array($exp)) {
            if (!is_array($actual) || !array_is_list($actual) || count($actual) !== count($exp)) {
                return false;
            }
            foreach ($exp as $i => $x) {
                if (!self::eqK5($actual[$i], $x)) {
                    return false;
                }
            }
            return true;
        }
        return $actual === $exp;
    }

    public static function workflow(): array
    {
        $doc = self::load('workflow-vectors.json');
        $fails = [];
        $n = 0;
        $W = $doc->get('workflows');
        $keys = $doc->get('keys');
        $input = static fn (Obj $c): Obj => Obj::of(['workflow' => $W->get($c->get('workflow')), 'principal' => $c->get('principal'), 'rsSigner' => $c->get('rs_signer'),
            'receipts' => $c->get('receipts'), 'now' => $c->get('now'), 'request' => $c->get('request')]);
        $seen = [];
        foreach (['admit' => 'admitStep', 'bind' => 'bindPromises'] as $table => $fn) {
            $rows = $doc->get($table);
            if (!is_array($rows) || count($rows) !== ($table === 'admit' ? 62 : 5)) {
                $fails[] = "workflow/$table: row count changed";
            }
            foreach ($rows as $c) {
                $n++;
                $g = Workflow::$fn($input($c));
                self::eqK5($g, $c->get('expect')) || $fails[] = "workflow/$table/" . $c->get('name') . ': ' . json_encode($g);
                $code = $c->get('expect')->get('code');
                $code === null || $seen[$code] = true;
            }
        }
        foreach ($doc->get('plan_root') as $c) {
            $n++;
            Workflow::planRootAuthorized($W->get($c->get('workflow')), $c->get('principal'), $c->get('now'), $c->get('root')) !== $c->get('expect') && $fails[] = 'workflow/plan_root/' . $c->get('name');
        }
        $d = $doc->get('digests');
        $n++;
        Workflow::workflowDigest($W->get('main')->get('body')) !== $d->get('workflow') && $fails[] = 'workflow/digest';
        foreach ($d->get('values') as $v) {
            $n++;
            Workflow::valueDigest($v->get('value')) !== $v->get('digest') && $fails[] = 'workflow/value-digest';
        }
        count($d->get('receipt_refs')) === 4 || $fails[] = 'workflow/receipt_refs';
        foreach (['bad_workflow', 'bad_dag', 'bad_signature', 'not_yet', 'expired', 'goal_mismatch', 'plan_root_mismatch', 'bad_receipt', 'unplanned_step', 'step_mismatch', 'params_mismatch', 'already_done', 'budget_exceeded', 'deps_unmet', 'dep_failed', 'stale_dep', 'edge_missing', 'edge_unit', 'edge_digest', 'edge_value', 'edge_relation', 'taint_flow', 'pipeline_unconstrained', 'taint_escalate'] as $code) {
            $n++;
            isset($seen[$code]) || $fails[] = "workflow/code never exercised: $code";
        }
        // hostile input never throws and always denies
        $main = $W->get('main');
        foreach ([null, 1, 'x', [], new Obj(), Obj::of(['body' => null]), Obj::of(['body' => new Obj(), 'sig' => new Num('1')])] as $x) {
            $n++;
            $g = Workflow::admitStep(Obj::of(['workflow' => $x, 'principal' => $keys->get('principal'), 'rsSigner' => $keys->get('rs'), 'receipts' => [], 'now' => new Num('1'), 'request' => $x]));
            $g['decision'] === 'deny' || $fails[] = 'workflow/hostile';
        }
        foreach (['x', null, new Obj()] as $r) {
            $n++;
            Workflow::admitStep(Obj::of(['workflow' => $main, 'principal' => $keys->get('principal'), 'rsSigner' => $keys->get('rs'), 'receipts' => $r, 'now' => new Num('1'), 'request' => new Obj()]))['decision'] === 'deny' || $fails[] = 'workflow/hostile-receipts';
        }
        Workflow::admitStep(null)['code'] === 'bad_workflow' || $fails[] = 'workflow/non-object-input';
        return [$n, $fails];
    }

    public static function readside(): array
    {
        $doc = self::load('readside-vectors.json');
        $fails = [];
        $n = 0;
        $G = $doc->get('grants');
        $rows = $doc->get('redact');
        count($rows) === 31 || $fails[] = 'readside/redact: row count changed';
        foreach ($rows as $c) {
            $n++;
            $in = $c->get('input')->without();
            $in->set('grant', $G->get($c->get('grant')));
            $g = ReadSide::redactRead($in);
            self::eqK5($g, $c->get('expect')) || $fails[] = 'readside/redact/' . $c->get('name') . ': ' . json_encode($g);
        }
        $sinks = $doc->get('sinks');
        count($sinks) === 18 || $fails[] = 'readside/sinks: row count changed';
        foreach ($sinks as $c) {
            $n++;
            $g = ReadSide::checkSink(Obj::of(['grant' => $G->get($c->get('grant')), 'principal' => $c->get('principal'), 'rsSigner' => $c->get('rs_signer'),
                'now' => $c->get('now'), 'sink' => $c->get('sink'), 'receipts' => $c->get('receipts')]));
            self::eqK5($g, $c->get('expect')) || $fails[] = 'readside/sink/' . $c->get('name') . ': ' . json_encode($g);
        }
        $d = $doc->get('digests');
        $n++;
        ReadSide::readGrantDigest($G->get('main')->get('body')) !== $d->get('grant') && $fails[] = 'readside/grant-digest';
        $chain = null;
        foreach ($sinks as $c) {
            $c->get('name') === 'chain-of-two-public-reads' && $chain = $c->get('receipts');
        }
        $n++;
        self::eqK5(ReadSide::readChainLabels($chain, $doc->get('keys')->get('rs'), $d->get('grant'), new Num('1800000000000')), $d->get('chain_labels')) || $fails[] = 'readside/chain-labels';
        // the masked view never contains a dropped value
        foreach ($rows as $c) {
            if ($c->get('name') === 'support-view') {
                $n++;
                $view = '';
                foreach ($c->get('expect')->get('view')->keys() as $k) {
                    $view .= $k . '=' . (($v = $c->get('expect')->get('view')->get($k)) instanceof Num ? $v->lexeme : $v) . ';';
                }
                foreach (['sk_live_x', '123-45-6789', 'dev-1', 'c_77', 'not in the schema'] as $secret) {
                    str_contains($view, $secret) && $fails[] = "readside/view leaks $secret";
                }
            }
        }
        // hostile input never throws and always denies
        foreach ([null, 1, 'x', [], new Obj()] as $x) {
            $n++;
            ReadSide::redactRead($x)['decision'] === 'deny' || $fails[] = 'readside/hostile-redact';
            ReadSide::checkSink($x)['decision'] === 'deny' || $fails[] = 'readside/hostile-sink';
        }
        return [$n, $fails];
    }

    /** vault-aggregate-vectors.json: the sampler streams, the tokenisation vault and the aggregate scenarios (C-315..C-319). */
    public static function vaultAggregate(): array
    {
        $doc = self::load('vault-aggregate-vectors.json');
        $fails = [];
        $n = 0;
        foreach ($doc->get('sampler')->get('uniform') as $u) {
            $n++;
            $d = ReadVault::seededDraws($u->get('seed'));
            $got = [];
            foreach ($u->get('bounds') as $b) {
                $got[] = $d->uniform(Workflow::iv($b));
            }
            self::eqK5($got, $u->get('draws')) || $fails[] = 'vault-aggregate/uniform/' . $u->get('seed') . ': ' . json_encode($got);
        }
        foreach ($doc->get('sampler')->get('laplace') as $l) {
            $n++;
            $d = ReadVault::seededDraws($l->get('seed'));
            $got = [];
            foreach ($l->get('values') as $_) {
                $got[] = ReadVault::discreteLaplace($d, Workflow::iv($l->get('s')), Workflow::iv($l->get('t')));
            }
            self::eqK5($got, $l->get('values')) || $fails[] = 'vault-aggregate/laplace/' . $l->get('seed') . ': ' . json_encode($got);
        }
        $G = $doc->get('grants');
        foreach ($doc->get('vault') as $c) {
            $n++;
            $store = new MemoryVault();
            $in = $c->get('redact')->without();
            $in->set('grant', $G->get('vault')->get($c->get('redact_grant')));
            $red = ReadVault::redactReadWithVault($in, $store);
            $token = $c->get('token') ?? ($red['view']->has((string)$c->get('field')) ? $red['view']->get($c->get('field')) : null);
            $d = $c->get('detok')->without('token');
            $d->set('grant', $G->get('vault')->get($c->get('detok_grant')));
            $d->set('token', $token ?? $c->get('detok')->get('token'));
            $d->set('store', $store);
            $g = ReadVault::detokenize($d);
            self::eqK5($g, $c->get('expect')) || $fails[] = 'vault-aggregate/vault/' . $c->get('name') . ': ' . json_encode($g);
        }
        $keys = $doc->get('keys');
        foreach ($doc->get('aggregate') as $c) {
            $state = $c->get('initial_state');
            foreach ($c->get('steps') as $i => $s) {
                $n++;
                $in = Obj::of(['principal' => $keys->get('principal'), 'now' => 1800000000000, 'verb' => 'orders.stats', 'resource' => 'orders/eu', 'purpose' => 'analytics',
                    'fn' => 'sum', 'values' => [10, 20, 500, -900], 'salt' => 'a-per-read-secret-salt', 'noise' => 'seeded']);
                foreach ($s->get('input')->keys() as $k) {
                    $in->set($k, $s->get('input')->get($k));
                }
                $gname = $s->get('input')->has('grant') ? $s->get('input')->get('grant') : 'main';
                $in->set('grant', $G->get('aggregate')->get($gname));
                $in->set('state', $state);
                $g = ReadVault::aggregateRead($in);
                self::eqK5($g, $s->get('expect')) || $fails[] = 'vault-aggregate/aggregate/' . $c->get('name') . "#$i: " . json_encode($g);
                $state = $g['state'];
            }
        }
        // the production 'secure' mode draws a fresh CSPRNG seed per call: two streams differ (values are not pinned)
        $n++;
        ReadVault::secureDraws()->uniform(140737488355328) !== ReadVault::secureDraws()->uniform(140737488355328) || $fails[] = 'vault-aggregate/secure-streams-equal';
        // hostile input never throws and always denies
        foreach ([null, 1, 'x', [], new Obj()] as $x) {
            $n++;
            ReadVault::aggregateRead($x)['decision'] === 'deny' || $fails[] = 'vault-aggregate/hostile-aggregate';
            ReadVault::detokenize($x)['decision'] === 'deny' || $fails[] = 'vault-aggregate/hostile-detokenize';
        }
        return [$n, $fails];
    }

    /** authorize-workflow-fixtures.json: workflow admission inside Authorize::authorize (C-308); each case threads its steps through ONE replay store. */
    public static function authorizeWorkflow(): array
    {
        $F = self::load('authorize-workflow-fixtures.json');
        $fails = [];
        $n = 0;
        $F->get('format') === 'pca-authorize-workflow-fixtures/1' || $fails[] = 'authorize-workflow: format';
        count($F->get('cases')) >= 14 || $fails[] = 'authorize-workflow: case count changed';
        $grant = $F->get('grant');
        $plan = $F->get('plan');
        foreach ($F->get('cases') as $c) {
            $store = new MemoryStateStore();
            foreach ($c->get('steps') as $i => $s) {
                $n++;
                $w = $s->get('workflow');
                $r = Authorize::authorize($s->get('pcactn'), $s->get('operation'), $F->get('audience'), static fn ($ref) => $ref === $grant->get('id') ? $grant : null,
                    $store, static fn () => false, Workflow::iv($F->get('now')), null, static fn () => Obj::of(['plan' => $plan, 'plan_authorized' => true]),
                    workflow: Obj::of(['principal' => $F->get('principal'), 'rsSigner' => $F->get('rs_signer'), 'required' => $c->get('required')]),
                    workflowCall: $w === null ? null : Obj::of(['commitment' => $w->get('commitment'), 'receipts' => $w->get('receipts'), 'step' => $w->get('step'),
                        'units' => $w->get('units'), 'goal_digest' => $w->get('goal_digest')]));
                $failed = array_keys(array_filter($r->checks, static fn ($v) => $v === 'fail'));
                sort($failed);
                $e = $s->get('expect');
                $want = [];
                foreach ($e->get('failed') as $f) {
                    $want[] = $f;
                }
                $tag = 'authorize-workflow/' . $c->get('name') . "#$i";
                [$r->allow, $r->decision, $r->status, $failed] === [$e->get('allow'), $e->get('decision'), Workflow::iv($e->get('status')), $want]
                    || $fails[] = "$tag: " . json_encode([$r->allow, $r->decision, $r->status, $failed, $r->reason]);
                $e->has('reason') && !str_contains((string)$r->reason, $e->get('reason')) && $fails[] = "$tag: reason " . json_encode($r->reason);
            }
        }
        return [$n, $fails];
    }

    // ---- lease-vectors.json and obligations-vectors.json ----------------------------------------------------------------------

    /** A parsed JSON value as plain PHP (Obj to array, Num to int or float), with assoc keys sorted, for exact comparison. */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Num) {
            return $v->isInt() ? $v->int() : $v->float();
        }
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            ksort($o);
            return $o;
        }
        if (is_array($v)) {
            $o = array_map(self::plain(...), $v);
            array_is_list($o) || ksort($o);
            return $o;
        }
        return $v;
    }

    public static function lease(): array
    {
        $doc = self::load('lease-vectors.json');
        $fails = [];
        $n = 0;
        $recs = $doc->get('records');
        $revs = $doc->get('revocations');
        foreach ($doc->get('scenarios') as $s) {
            $policy = ['authorities' => [$doc->get('authority')]];
            if ($s->has('policy')) {
                $p = $s->get('policy');
                $p->has('minApprovals') && $policy['minApprovals'] = $p->get('minApprovals')->int();
                $p->has('eligibleApprovers') && $policy['eligibleApprovers'] = $p->get('eligibleApprovers');
                $p->has('freshJustification') && $policy['freshJustification'] = $p->get('freshJustification');
            }
            $reg = new LeaseRegistry($policy);
            foreach ($s->get('steps') as $st) {
                $n++;
                $op = $st->get('op');
                $e = self::plain($st->get('expect'));
                $label = 'lease/' . $s->get('name') . '/' . $op;
                if ($op === 'accept') {
                    $g = $reg->accept($recs[$st->get('record')->int()], $st->has('chain') ? $st->get('chain') : []);
                    $want = $e['ok'] ? ['ok' => true, 'replaced' => $e['replaced'], 'seq' => $e['seq']] : ['ok' => false, 'code' => $e['code']];
                    $got = array_intersect_key($g, $want);
                } elseif ($op === 'revoke') {
                    $g = $reg->revoke($revs[$st->get('revocation')->int()]);
                    $want = $e['ok'] ? ['ok' => true, 'revoked' => $e['revoked']] : ['ok' => false, 'code' => $e['code']];
                    $got = array_intersect_key($g, $want);
                } elseif ($op === 'check') {
                    $got = Lease::check($recs[$st->get('record')->int()], $reg, $st->get('now'));
                    $want = $e;
                } else {
                    $fails[] = "$label: unknown op";
                    continue;
                }
                ksort($got);
                ksort($want);
                $got === $want || $fails[] = "$label: " . json_encode($got) . ' want ' . json_encode($want);
            }
        }
        return [$n, $fails];
    }

    public static function obligations(): array
    {
        $doc = self::load('obligations-vectors.json');
        $fails = [];
        $n = 0;
        foreach ($doc->get('validate') as $c) {
            $n++;
            (Obligations::listError($c->get('input')) === null) === $c->get('expect')->get('ok') || $fails[] = 'obligations/validate/' . $c->get('name');
        }
        foreach ($doc->get('merge') as $c) {
            $n++;
            $g = Obligations::merge(...$c->get('inputs'));
            $x = $c->get('expect');
            $ok = $g['ok'] === $x->get('ok') && (!$g['ok'] || self::plain($g['obligations']) === self::plain($x->get('obligations')));
            $ok || $fails[] = 'obligations/merge/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('gate') as $c) {
            $n++;
            $g = Obligations::gate($c->get('decision'), $c->get('answered'), $c->get('obligations'), $c->get('supported'));
            unset($g['reason']);
            self::plain($g) === self::plain($c->get('expect')) || $fails[] = 'obligations/gate/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('outcome') as $c) {
            $n++;
            $g = self::plain(Obligations::outcome($c->get('obligations'), $c->get('fulfilled'), $c->get('now')));
            $g === self::plain($c->get('expect')) || $fails[] = 'obligations/outcome/' . $c->get('name') . ': ' . json_encode($g);
        }
        return [$n, $fails];
    }

    public static function breakGlass(): array
    {
        $doc = self::load('break-glass-vectors.json');
        $fails = [];
        $n = 0;
        $grants = $doc->get('grants');
        $reviews = $doc->get('reviews');
        foreach ($doc->get('scenarios') as $s) {
            $reviewers = [$doc->get('reviewer')];
            if ($s->has('extra_reviewers')) {
                $reviewers = array_merge($reviewers, $s->get('extra_reviewers'));
            }
            $reg = new BreakGlassRegistry(['authorities' => [$doc->get('authority')], 'reviewers' => $reviewers]);
            foreach ($s->get('steps') as $st) {
                $n++;
                $op = $st->get('op');
                $want = self::plain($st->get('expect'));
                $label = 'break-glass/' . $s->get('name') . '/' . $op;
                $now = $st->get('now');
                $got = match ($op) {
                    'accept' => $reg->accept($grants[$st->get('grant')->int()], $now),
                    'use' => $reg->use($st->get('id'), $st->get('holder'), $st->get('action_digest'), $now, $st->get('notified')),
                    'review' => $reg->review($reviews[$st->get('review')->int()], $st->get('holder'), $now),
                    'frozen' => $reg->frozen($st->get('holder'), $now),
                    default => null,
                };
                self::plain($got) === $want || $fails[] = "$label: " . json_encode($got) . ' want ' . json_encode($want);
            }
        }
        return [$n, $fails];
    }

    public static function missingContext(): array
    {
        $doc = self::load('missing-context-vectors.json');
        $fails = [];
        $n = 0;
        foreach ($doc->get('decide') as $c) {
            $n++;
            $g = MissingContext::decide($c->get('where'), $c->get('bound'), $c->get('supplied'), $c->get('suppliers'));
            self::plain($g) === self::plain($c->get('expect')) || $fails[] = 'missing-context/decide/' . $c->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('bind') as $c) {
            $n++;
            $g = MissingContext::bindContext($c->get('bound'), $c->get('supplied'), $c->get('suppliers'));
            self::plain($g) === self::plain($c->get('expect')) || $fails[] = 'missing-context/bind/' . $c->get('name');
        }
        return [$n, $fails];
    }

    public static function policyClasses(): array
    {
        $doc = self::load('policy-classes-vectors.json');
        $fails = [];
        $n = 0;
        foreach ($doc->get('validate') as $c) {
            $n++;
            (PolicyClasses::listError($c->get('input')) === null) === $c->get('expect')->get('ok') || $fails[] = 'policy-classes/validate/' . $c->get('name');
        }
        foreach ($doc->get('decide') as $c) {
            $n++;
            $g = PolicyClasses::decide($c->get('input'));
            self::plain($g) === self::plain($c->get('expect')) || $fails[] = 'policy-classes/decide/' . $c->get('name') . ': ' . json_encode($g);
        }
        return [$n, $fails];
    }

    // ---- decision-vectors.json: rules 20 / 21 and the ternary decision -------------------------------------------------

    /** The row counts the reference generated: a table that shrank (or a runner that skipped rows) fails. */
    private const DECISION_ROWS = ['intent_units' => 85, 'intent_tighten' => 73, 'decision_of' => 25, 'decision_lattice' => 31,
        'escalation_fold' => 18, 'escalation_truncate' => 11, 'escalation_answer' => 85];

    /** `input_text` is raw JSON text each runner parses itself (key order is part of the input); else `input`. */
    private static function inputOf(Obj $e): mixed
    {
        return $e->has('input_text') ? Json::parseLax($e->get('input_text')) : $e->get('input');
    }

    /** @return list<Obj> the table, its row count checked against the reference's */
    private static function table(Obj $doc, string $name, array &$fails): array
    {
        $rows = $doc->get($name);
        $rows = is_array($rows) ? $rows : [];
        if (count($rows) !== self::DECISION_ROWS[$name]) {
            $fails[] = "$name: " . count($rows) . ' rows, the reference has ' . self::DECISION_ROWS[$name];
        }
        return $rows;
    }

    public static function decision(): array
    {
        $doc = self::load('decision-vectors.json')->get('primitives');
        $n = 0;
        $fails = [];
        foreach (self::table($doc, 'intent_units', $fails) as $e) {
            $n++;
            $r = Decision::decideUnits(self::inputOf($e));
            $x = $e->get('expect');
            if ($r['ok'] !== $x->get('ok') || ($r['ok'] === false && ($r['reason'] ?? null) !== $x->get('reason'))) {
                $fails[] = 'units ' . $e->get('name') . ': ' . json_encode($r);
            }
        }
        foreach (self::table($doc, 'intent_tighten', $fails) as $e) {
            $n++;
            $r = Decision::decideTighten(self::inputOf($e));
            $x = $e->get('expect');
            if ($r['outcome'] !== $x->get('outcome') || $r['legacy'] !== $x->get('legacy') || $r['offending'] !== $x->get('offending')
                || ($r['reason'] ?? null) !== ($x->has('reason') ? $x->get('reason') : null)) {
                $fails[] = 'tighten ' . $e->get('name') . ': ' . json_encode($r);
            }
        }
        foreach (self::table($doc, 'decision_of', $fails) as $e) {
            $n++;
            $got = Decision::decisionOfVerdict($e->get('input'));
            if ($got !== $e->get('expect')->get('decision')) {
                $fails[] = 'decision_of ' . $e->get('name') . ": $got";
            }
        }
        foreach (self::table($doc, 'decision_lattice', $fails) as $e) {
            $n++;
            $i = $e->get('input');
            $name = $e->get('name');
            $got = match (true) {
                str_starts_with($name, 'meet-') => Decision::meet($i->get('a'), $i->get('b')),
                str_starts_with($name, 'pep-') => Decision::pepDecision($i->get('decision'), $i->get('answered')),
                default => Decision::tighten($i->get('decision'), $i->get('signal')),
            };
            if ($got !== $e->get('expect')->get('decision')) {
                $fails[] = "lattice $name: " . json_encode($got);
            }
        }
        foreach (self::table($doc, 'escalation_fold', $fails) as $e) {
            $n++;
            $i = $e->get('input');
            $v2 = [];
            foreach ($i->get('v2') as $c) {
                $row = ['name' => $c->get('name'), 'ok' => $c->get('ok')];
                if ($c->has('reason')) {
                    $row['reason'] = $c->get('reason');
                }
                $v2[] = $row;
            }
            $checks = [];
            foreach ($i->get('checks')->keys() as $k) {
                $checks[$k] = $i->get('checks')->get($k);
            }
            $reasons = Decision::foldV2Reasons($i->get('core_reasons'), $v2);
            $dec = in_array('fail', $checks, true) ? Decision::decisionOf(false, $checks, $reasons) : 'allow';
            $x = $e->get('expect');
            if ($reasons !== $x->get('reasons') || $dec !== $x->get('decision')) {
                $fails[] = 'fold ' . $e->get('name') . ': ' . json_encode([$reasons, $dec]);
            }
        }
        foreach (self::table($doc, 'escalation_truncate', $fails) as $e) {
            $n++;
            $req = Escalation::buildRequest('a', Obj::of(['id' => 'g']), Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r'])]),
                null, $e->get('input')->get('reasons'), 1);
            if (Escalation::reasonsWire($req) !== $e->get('expect')->get('wire')) {
                $fails[] = 'truncate ' . $e->get('name');
            }
        }
        return [$n, $fails];
    }

    // ---- primitives.escalation_answer ------------------------------------------------------------------------------------

    public static function escalation(): array
    {
        $doc = self::load('decision-vectors.json')->get('primitives');
        $n = 0;
        $fails = [];
        foreach (self::table($doc, 'escalation_answer', $fails) as $e) {
            $n++;
            $i = self::inputOf($e);
            $x = $e->get('expect');
            $r = Escalation::verifyAnswer($i->get('answer'), $i->get('principals'), $i->get('bind'), $i->get('now'));
            $name = $e->get('name');
            $need = $e->get('requires_suite');
            if (is_string($need) && !in_array($need, Pca::supportedSuites(), true)) {
                // a suite this verifier cannot verify must be refused with the distinct unsupported_suite reason
                if ($r['ok'] !== false || !str_contains($r['reason'], 'unsupported_suite')) {
                    $fails[] = "$name: want unsupported_suite, got " . json_encode($r);
                }
                continue;
            }
            if ($r['ok'] !== $x->get('ok')) {
                $fails[] = "$name: ok=" . var_export($r['ok'], true) . ' ' . ($r['reason'] ?? '');
            } elseif ($r['ok'] && ($r['principal'] !== $x->get('principal') || $r['decision'] !== $x->get('decision'))) {
                $fails[] = "$name: principal/decision differ";
            } elseif (!$r['ok'] && !str_contains($r['reason'], $x->get('reason_contains'))) {
                $fails[] = "$name: reason '" . $r['reason'] . "' lacks '" . $x->get('reason_contains') . "'";
            }
        }
        return [$n, $fails];
    }

    // ---- caveat-lang-vectors.json: the caveat language v2 (track K1) ---------------------------------------------------

    /** The row counts the reference generated, per primitive: a table that shrank (or a runner that skipped rows) fails. */
    public const CAVEAT_LANG_ROWS = ['discharge_verify' => 60, 'k1_eval' => 110, 'caveat_shape' => 52, 'uses_key' => 5,
        'uses_reserve' => 12, 'spiffe_id' => 24, 'k1_unconfigured' => 9, 'consume_once_ttl' => 9, 'k1_headers' => 15];

    public static function caveatLang(): array
    {
        $doc = self::load('caveat-lang-vectors.json')->get('primitives');
        $n = 0;
        $fails = [];
        foreach (self::CAVEAT_LANG_ROWS as $table => $want) {
            $rows = $doc instanceof Obj ? $doc->get($table) : null;
            $rows = is_array($rows) ? $rows : [];
            if (count($rows) !== $want) {
                $fails[] = "$table: " . count($rows) . " rows, the reference has $want";
            }
            foreach ($rows as $e) {
                $n++;
                $name = $table . ' ' . $e->get('name');
                $i = $e->get('input');
                $x = $e->get('expect');
                try {
                    $msg = match ($table) {
                        'discharge_verify' => self::dischargeRow($e, $i, $x),
                        'k1_eval' => self::k1Row($i, $x),
                        'caveat_shape' => self::shapeRow($i, $x),
                        'uses_key' => CaveatLang::maxUsesSlotKey($i->get('cap_hash'), $i->get('id'), self::intOf($i->get('i'))) === $x->get('key')
                            ? null : 'slot key differs',
                        'uses_reserve' => self::reserveRow($i, $x),
                        'spiffe_id' => (CaveatLang::spiffeIdError($i->get('id')) === null) === $x->get('valid') ? null : 'validity differs',
                        'k1_unconfigured' => self::unconfiguredRow($i, $x),
                        'consume_once_ttl' => self::consumeOnceRow($i, $x),
                        'k1_headers' => self::headersRow($i, $x),
                    };
                } catch (\Throwable $t) {
                    $msg = 'threw ' . $t->getMessage();
                }
                if ($msg !== null) {
                    $fails[] = "$name: $msg";
                }
            }
        }
        return [$n, $fails];
    }

    private static function dischargeRow(Obj $e, Obj $i, Obj $x): ?string
    {
        $r = CaveatLang::verifyDischarge($i->get('discharge'), $i->get('caveat'), $i->get('binding'));
        $need = $e->get('requires_suite');
        if (is_string($need) && !in_array($need, Pca::supportedSuites(), true)) {
            // a suite this verifier cannot verify must be refused with the distinct unsupported_suite reason
            return $r['ok'] === false && str_contains($r['reason'], 'unsupported_suite') ? null : 'want unsupported_suite, got ' . json_encode($r);
        }
        if ($r['ok'] !== $x->get('ok')) {
            return 'ok=' . var_export($r['ok'], true) . ' ' . ($r['reason'] ?? '');
        }
        if ($r['ok']) {
            return $r['digest'] === $x->get('digest') && self::same($r['claims'], $x->get('claims')) ? null : 'digest/claims differ';
        }
        return str_contains($r['reason'], $x->get('reason_contains')) ? null : "reason '" . $r['reason'] . "' lacks '" . $x->get('reason_contains') . "'";
    }

    private static function k1Row(Obj $i, Obj $x): ?string
    {
        [$allow, $failed] = CaveatLang::evaluateCaveatsK1($i->get('grant'), $i->get('chain'), $i->get('k1'), $i->get('context'));
        return $allow === $x->get('allow') && $failed === $x->get('failed') ? null : 'got ' . json_encode([$allow, $failed]);
    }

    private static function unconfiguredRow(Obj $i, Obj $x): ?string
    {
        [$allow, $failed] = CaveatLang::evaluateCaveatsK1($i->get('grant'), $i->get('chain'), null, $i->get('context'));
        return $allow === $x->get('allow') && $failed === $x->get('failed') ? null : 'got ' . json_encode([$allow, $failed]);
    }

    /** The memory store and the PDO (SQLite) store must both answer every step exactly as the reference store does. */
    private static function consumeOnceRow(Obj $i, Obj $x): ?string
    {
        $pdo = new PdoStateStore(new \PDO('sqlite::memory:'));
        $pdo->createTable();
        foreach (['memory' => new MemoryStateStore(), 'pdo' => $pdo] as $label => $store) {
            foreach ($i->get('steps') as $k => $st) {
                try {
                    $got = $store->consumeOnce($st->get('key'), self::intOf($st->get('retain_until')), self::intOf($st->get('now'))) ? 'true' : 'false';
                } catch (\InvalidArgumentException) {
                    $got = 'error';
                }
                if ($got !== $x->get('results')[$k]) {
                    return "$label step $k: got $got";
                }
            }
        }
        return null;
    }

    private static function headersRow(Obj $i, Obj $x): ?string
    {
        $r = CaveatLang::presentedK1($i->get('headers'));
        if ($r['ok'] !== $x->get('ok')) {
            return 'ok=' . var_export($r['ok'], true);
        }
        return !$r['ok'] || self::same($r['value'], $x->get('value')) ? null : 'value differs';
    }

    private static function shapeRow(Obj $i, Obj $x): ?string
    {
        $c = $i->get('caveat');
        $err = match ($c->get('type')) {
            'needs_discharge' => CaveatLang::needsDischargeError($c),
            'max_uses' => CaveatLang::maxUsesError($c),
            'derive' => CaveatLang::deriveError($c),
            'spiffe_bound' => CaveatLang::spiffeBoundError($c),
        };
        return ($err === null) === $x->get('valid') ? null : 'validity differs: ' . var_export($err, true);
    }

    private static function reserveRow(Obj $i, Obj $x): ?string
    {
        $store = new MemoryStateStore();
        $want = $x->get('results');
        foreach ($i->get('calls') as $k => $call) {
            $r = CaveatLang::reserveMaxUses($store, $i->get('bound'), $call->get('now'));
            $w = $want[$k];
            if ($r['ok'] !== $w->get('ok')) {
                return "call $k: " . json_encode($r);
            }
            if ($r['ok'] ? $r['spent'] !== self::intOf($w->get('spent')) : !str_contains($r['reason'], $w->get('reason_contains'))) {
                return "call $k: " . json_encode($r);
            }
        }
        return null;
    }

    // ---- passport-vectors.json ---------------------------------------------------------------------------------------------

    private static function intOf(mixed $n): int
    {
        return $n instanceof Num ? (int)$n->float() : (int)$n;
    }

    /**
     * Replay of `passport_vectors`: every signature suite this verifier implements (a suite it does not implement must answer
     * `unsupported_suite`), and the hardware branch through a stub verifier that answers what the vector says.
     */
    public static function passport(): array
    {
        $doc = self::load('passport-vectors.json');
        $rows = $doc->get('passport_vectors');
        if (!is_array($rows) || count($rows) < 74) {
            return [0, ['passport-vectors.json: passport_vectors missing or fewer than 74 rows']];
        }
        [$n, $fails, $suites] = self::passportRows($rows, []);
        // the floor applies only when the runtime supports a post-quantum suite THIS corpus exercises (e.g. a runtime with only
        // less-cat1 and no ML-DSA exercises none: those rows answer unsupported_suite instead)
        $used = [];
        foreach ($rows as $v) {
            $signed = $v->has('signed') ? $v->get('signed') : null;
            $used[] = $signed instanceof Obj ? $signed->get('alg') : null;
        }
        $needPq = array_filter(Pca::supportedSuites(), static fn(string $a): bool => $a !== 'ed25519' && in_array($a, $used, true)) !== [];
        if ($needPq && $suites < 3) {
            $fails[] = "only $suites vectors exercised a supported post-quantum suite";
        }
        return [$n, $fails];
    }

    /**
     * Replay of `passport_hardware_vectors`: hardware-rooted passports verified by the REAL vendor verifiers built from the
     * vendor configuration (verifier_from_config) through the `defaultHardware` seam. The table is produced by the TypeScript
     * generator; its absence is a failure, never a skip.
     */
    public static function passportHardware(): array
    {
        $doc = self::load('passport-vectors.json');
        $rows = $doc->get('passport_hardware_vectors');
        if (!is_array($rows)) {
            return [0, ['passport-vectors.json has no passport_hardware_vectors table: regenerate it with the TypeScript reference '
                . '(tsx scripts/gen-conformance-passport.ts in packages/pca)']];
        }
        if (count($rows) < 40) {
            return [0, ['only ' . count($rows) . ' passport_hardware_vectors']];
        }
        $docs = [];
        foreach ($doc->get('passport_vectors') as $r) {
            $docs[$r->get('name')] = $r->has('signed_ref') ? ($docs[$r->get('signed_ref')] ?? null) : $r->get('signed');
        }
        [$n, $fails] = self::passportRows($rows, $docs);
        return [$n, $fails];
    }

    /** @return array{int, list<string>, int} */
    private static function passportRows(array $rows, array $docs): array
    {
        $supported = Pca::supportedSuites();
        $fails = [];
        $suites = 0;
        foreach ($rows as $v) {
            $name = $v->get('name');
            $signed = $v->has('signed_ref') ? ($docs[$v->get('signed_ref')] ?? null) : $v->get('signed');
            $docs[$name] = $signed;
            $revoked = array_map('strval', $v->get('revoked'));
            $o = ['trustedIssuers' => $v->get('trustedIssuers'), 'now' => self::intOf($v->get('now')),
                'revocation' => static fn(array $p): bool => in_array($p['id'], $revoked, true)];
            foreach (['clockSkewMs', 'maxEvidenceAgeMs'] as $k) {
                if ($v->has($k)) {
                    $o[$k] = self::intOf($v->get($k));
                }
            }
            if ($v->has('subject')) {
                $o['subject'] = $v->get('subject');
            }
            if ($v->has('pqPins')) {
                $pins = $v->get('pqPins');
                foreach ($pins->keys() as $k) {
                    $o['pqPins'][$k] = $pins->get($k);
                }
            }
            $got = null;
            if ($v->has('hardware')) {
                $h = $v->get('hardware');
                $o['attest'] = static function (Obj $docu, array $expected) use ($h, &$got): array {
                    $got = $expected;
                    if ($h->get('throws') === true) {
                        throw new \RuntimeException('verifier down');
                    }
                    return ['ok' => $h->get('ok') === true, 'bound' => $h->get('bound') === true, 'measured' => $h->get('measured')];
                };
            }
            if ($v->has('hardware_verifier')) {
                $hv = $v->get('hardware_verifier');
                try {
                    $ver = \Atlas\Pca\Attest\Factory::verifierFromConfig($hv->get('vendor'), $hv->get('config'));
                } catch (\Throwable $e) {
                    $fails[] = "$name: " . $e->getMessage();
                    continue;
                }
                $evidence = $hv->get('evidence');
                $o['defaultHardware'] = new \Atlas\Pca\Attest\DefaultHardware($ver, static fn(Obj $d): ?Obj => $evidence instanceof Obj ? $evidence : null);
            }
            $r = Passport::verify($signed, $o);
            $e = $v->get('expect');
            $want = $e->get('ok') === true ? '' : $e->get('reason');
            $alg = $signed instanceof Obj ? $signed->get('alg') : null;
            if (is_string($alg) && !in_array($alg, $supported, true)) {
                $want = 'unsupported_suite';
            } elseif (is_string($alg)) {
                $suites++;
            }
            $gotReason = $r['ok'] ? '' : $r['reason'];
            if ($gotReason !== $want) {
                $fails[] = "$name: got '$gotReason' want '$want'" . (isset($r['detail']) ? ' (' . $r['detail'] . ')' : '');
            }
            if ($v->has('expectBinding')) {
                $eb = $v->get('expectBinding');
                if ($got === null || $got['holderPub'] !== $eb->get('holderPub') || $got['grantRef'] !== $eb->get('grantRef')
                    || (float)$got['epoch'] !== (float)self::intOf($eb->get('epoch')) || $got['nonce'] !== $eb->get('nonce')) {
                    $fails[] = "$name: the verifier was not handed the expected binding";
                }
            }
        }
        return [count($rows), $fails, $suites];
    }

    // ---- ledger-vectors.json / optimistic-vectors.json -------------------------------------------------------------------------

    private static function ok(bool $b): Obj
    {
        return Obj::of(['ok' => $b]);
    }

    private static function chk(string $c): Obj
    {
        $o = new Obj();
        $o->set('ok', $c === 'ok');
        $o->set('check', $c);
        return $o;
    }

    /** The row counts of the committed extension corpus, asserted against the REAL table sizes (not only the file's own `counts`). */
    private const EXPECTED_COUNTS = [
        'optimistic_claim' => 52, 'optimistic_window' => 25, 'optimistic_fraud_proof' => 37, 'optimistic_settlement' => 102,
        'ledger_inclusion' => 96, 'ledger_consistency' => 149, 'ledger_tree_head' => 64, 'ledger_cosign' => 56,
        'ledger_head_consistency' => 26, 'ledger_checkpoint_chain' => 23, 'ledger_witnessed_head' => 30, 'ledger_equivocation' => 7,
    ];

    /** `requires_suite` names a registered suite this runtime may lack: it must then refuse (false / `suite`), never accept. */
    private static function lacks(Obj $v): bool
    {
        if ($v->has('requires_suite') && !in_array($v->get('requires_suite'), \Atlas\Pca\Pca::supportedSuites(), true)) {
            return true;
        }
        // the post-quantum rows are not all tagged: a registered suite named anywhere in the input (not in `expect`) counts too
        foreach ($v->keys() as $k) {
            if ($k !== 'expect' && self::namesMissingSuite($v->get($k))) {
                return true;
            }
        }
        return false;
    }

    /** True when `alg` anywhere inside `$x` is a registered suite this runtime cannot verify. */
    private static function namesMissingSuite(mixed $x): bool
    {
        if (is_array($x)) {
            foreach ($x as $e) {
                if (self::namesMissingSuite($e)) {
                    return true;
                }
            }
            return false;
        }
        if (!($x instanceof Obj)) {
            return false;
        }
        $alg = $x->has('alg') ? $x->get('alg') : null;
        if (is_string($alg) && in_array($alg, Pca::REGISTERED_SUITES, true) && !in_array($alg, Pca::supportedSuites(), true)) {
            return true;
        }
        foreach ($x->keys() as $k) {
            if (self::namesMissingSuite($x->get($k))) {
                return true;
            }
        }
        return false;
    }

    /** The vector's `pins`; null when ABSENT (cosigners then fall back to the policy), an empty Obj for `pins: {}`. */
    private static function pins(Obj $v): mixed
    {
        return $v->has('pins') ? $v->get('pins') : null;
    }

    /** Replay every table named in `counts` of an extension-layer file; the row count must equal the recorded count. */
    private static function tables(Obj $doc, callable $fn): array
    {
        $n = 0;
        $fails = [];
        $counts = $doc->get('counts');
        foreach ($counts->keys() as $table) {
            $rows = $doc->get($table);
            if (!is_array($rows) || count($rows) !== (int)$counts->get($table)->float()) {
                $fails[] = "$table: row count differs from counts.$table";
                continue;
            }
            if (count($rows) !== (self::EXPECTED_COUNTS[$table] ?? -1)) {
                $fails[] = "$table: " . count($rows) . ' rows, this runner pins ' . (self::EXPECTED_COUNTS[$table] ?? 'no size');
                continue;
            }
            foreach ($rows as $v) {
                $n++;
                try {
                    $got = $fn($table, $v, $doc);
                } catch (\Throwable $e) {
                    $fails[] = "$table/" . $v->get('name') . ': threw ' . $e->getMessage();
                    continue;
                }
                $want = $v->get('expect');
                if (self::lacks($v)) {
                    // a refusal: nothing accepted; a settlement record answers `suite`
                    $refused = $got->get('ok') !== true && $got->get('equivocation') !== true && (!$got->has('check') || $got->get('check') === 'suite');
                    $want = $refused ? $got : $want;
                }
                if (!self::same($got, $want)) {
                    $fails[] = "$table/" . $v->get('name') . ': got ' . Json::canonicalizeLenient($got) . ' want ' . Json::canonicalizeLenient($v->get('expect'));
                }
            }
        }
        return [$n, $fails];
    }

    public static function ledger(): array
    {
        $doc = self::load('ledger-vectors.json');
        $fails = [];
        if ($doc->get('empty_tree_root') !== Ledger::emptyTreeRoot()) {
            $fails[] = 'empty_tree_root differs';
        }
        if ($doc->get('domains')->get('sth') !== Ledger::STH_DOMAIN || $doc->get('domains')->get('sth_witness') !== Ledger::STH_WITNESS_DOMAIN) {
            $fails[] = 'domain constants differ';
        }
        [$n, $f] = self::tables($doc, static function (string $table, Obj $v): Obj {
            switch ($table) {
                case 'ledger_inclusion':
                    return self::ok(Ledger::verifyInclusion($v->get('root'), $v->get('proof'), $v->get('leaf')));
                case 'ledger_consistency':
                    return self::ok(Ledger::verifyConsistency($v->get('old_root'), $v->get('new_root'), $v->get('proof')));
                case 'ledger_tree_head':
                    return self::ok(Ledger::verifyTreeHead($v->get('sth'), $v->get('guardian_public'), null, self::pins($v)));
                case 'ledger_cosign':
                    return self::ok(Ledger::verifyTreeHead($v->get('sth'), $v->get('guardian_public'), $v->get('policy'), self::pins($v)));
                case 'ledger_head_consistency':
                    return self::ok(Ledger::verifyHeadConsistency($v->get('older'), $v->get('newer'), $v->get('proof'), $v->get('guardian_public'), null, self::pins($v)));
                case 'ledger_checkpoint_chain':
                    $r = Ledger::verifyCheckpointChain($v->get('chain'), $v->get('guardian_public'), $v->get('policy'), self::pins($v));
                    $o = self::ok($r['ok']);
                    if (!$r['ok']) {
                        $o->set('at', new Num((string)$r['at']));
                    }
                    return $o;
                case 'ledger_witnessed_head':
                    return self::ok(Ledger::verifyWitnessedHead($v->get('head'), $v->get('witness_public'), self::pins($v)));
                case 'ledger_equivocation':
                    return Obj::of(['equivocation' => Ledger::detectEquivocation($v->get('a'), $v->get('b'), $v->get('witness_public'), self::pins($v))]);
                default:
                    throw new \RuntimeException("unknown ledger table $table");
            }
        });
        return [$n, array_merge($fails, $f)];
    }

    public static function optimistic(): array
    {
        $doc = self::load('optimistic-vectors.json');
        return self::tables($doc, static function (string $table, Obj $v, Obj $d): Obj {
            switch ($table) {
                case 'optimistic_claim':
                    return self::chk(Optimistic::claimCheck($v->get('claim'), $v->get('pcactn_digest'), $v->get('signer_public'),
                        $v->get('server_now'), $d->get('window_policy')));
                case 'optimistic_window':
                    $c = Obj::of(['issued_at' => $v->get('issued_at'), 'challenge_window_ms' => $v->get('challenge_window_ms')]);
                    return Obj::of([
                        'end' => new Num(\Atlas\Pca\IntentWb::jsNumStr(Optimistic::challengeWindowEnd($c))),
                        'within' => Optimistic::withinChallengeWindow($c, $v->get('now')),
                        'phase' => Optimistic::claimStatus($c, $v->get('now')),
                    ]);
                case 'optimistic_fraud_proof':
                    return self::chk(Optimistic::fraudProofWireCheck($v->get('claim'), $v->get('proof')));
                case 'optimistic_settlement':
                    return self::chk(Optimistic::settlementWireCheck($v->get('record'), $v->get('guardian_public'), self::pins($v)));
                default:
                    throw new \RuntimeException("unknown optimistic table $table");
            }
        });
    }

    // ---- mesh-vectors.json -------------------------------------------------------------------------------------------------------

    /**
     * Every mesh proof: `ok` always, `reason` and `hop` unless the reference reason is a `chain:` refusal (a chain refusal only
     * has to be a chain refusal: its wording is the capability verifier's).
     */
    public static function mesh(): array
    {
        $doc = self::load('mesh-vectors.json');
        $rows = $doc->get('mesh');
        if (!is_array($rows) || count($rows) < 100) {
            return [0, ['expected at least 100 mesh vectors']];
        }
        $fails = [];
        foreach ($rows as $v) {
            $name = $v->get('name');
            $e = $v->get('expect');
            $got = Mesh::verify($v->get('proof'), $v->get('trust'));
            if ($got['ok'] !== $e->get('ok')) {
                $fails[] = "$name: ok=" . var_export($got['ok'], true) . ' (' . ($got['reason'] ?? '') . ') want ' . var_export($e->get('ok'), true)
                    . ' (' . ($e->get('reason') ?? '') . ')';
                continue;
            }
            if ($e->get('ok') === true) {
                continue;
            }
            $want = (string)$e->get('reason');
            if (str_starts_with($want, 'chain:')) {
                if (!str_starts_with($got['reason'], 'chain:')) {
                    $fails[] = "$name: reason '" . $got['reason'] . "' want a chain refusal ('$want')";
                }
                continue;
            }
            $wantHop = $e->has('hop') ? (int)$e->get('hop')->float() : -1;
            if ($got['reason'] !== $want || $got['hop'] !== $wantHop) {
                $fails[] = "$name: got '" . $got['reason'] . "' hop " . $got['hop'] . " want '$want' hop $wantHop";
            }
        }
        return [count($rows), $fails];
    }

    // ---- intent-state-vectors.json -----------------------------------------------------------------------------------------------

    private static function intArg(mixed $n): int
    {
        return $n instanceof Num ? $n->int() : (int)$n;
    }

    /** The function table of the intent-state corpus: the accumulator / receipt functions of IntentV2 and the session history. */
    private static function intentFn(string $fn, array $a): mixed
    {
        $agg = static fn(mixed $x): Obj => Obj::of(['agg' => $x]);
        try {
            switch ($fn) {
                case 'accumulatorDeclError':
                    return IntentV2::accumulatorDeclError($a[0]);
                case 'monitorDeclError':
                    return IntentV2::monitorDeclError($a[0]);
                case 'monitorStates':
                    return IntentV2::monitorStates($a[0]);
                case 'trackedKeySetError':
                    return IntentV2::trackedKeySetError($a[0]);
                case 'preStateError':
                    return IntentV2::preStateError($agg($a[0]), $a[1]);
                case 'preValue':
                    return IntentV2::preValue($agg($a[0]), $a[1]);
                case 'combineAcc':
                    return IntentV2::combineAcc($agg($a[0]), $a[1], ['val' => self::intArg($a[2]->get('val')), 'key' => $a[2]->get('key')]);
                case 'accSelects':
                    return IntentV2::accSelects($a[0], $a[1], $a[2]);
                case 'accValueOf':
                    $r = IntentV2::accValueOf($a[0], $a[1], $a[2], $a[3]);
                    if ($r['ok']) {
                        $r['key'] ??= null; // the reference spells an absent key as null
                    }
                    return $r;
                case 'receiptArithmeticOk':
                    return IntentV2::receiptArithmeticOk($agg($a[0]), $a[1], self::intArg($a[2]));
                case 'pcactnReservationDigest':
                    return IntentV2::pcactnReservationDigest($a[0]);
                case 'receiptShapeError':
                    return IntentV2::accReceiptShapeError($a[0]);
                case 'keySetShapeError':
                    return IntentV2::sequencerKeySetShapeError($a[0]);
                case 'verifyKeySet':
                    return IntentV2::verifySequencerKeySet($a[0], $a[1], $a[3] === true ? $a[2] : null);
                case 'verifyReceiptSignature':
                    $pinKey = null;
                    $pinPq = null;
                    $pins = $a[2]; // the pqPins map {signer: pq_pk}
                    foreach ($pins instanceof Obj ? $pins->keys() : [] as $k) {
                        $pinKey = $k;
                        $pinPq = $pins->get($k);
                    }
                    return $a[0] instanceof Obj ? IntentV2::verifyAccReceiptSignature($a[0], $a[1], $pinKey, $pinPq) : false;
                case 'verifyReceiptAgainstHolder':
                    return IntentV2::verifyReceiptAgainstHolder($a[0], $a[1], $a[2], $a[3], $a[4], $a[5], null, $a[6]) === 'valid';
                case 'inWindow':
                    return IntentHistory::inWindow($a[0], $a[1], $a[2]);
                case 'accKeyOf':
                    return IntentHistory::accKeyOf($a[0], $a[1]);
                case 'accPreState':
                    return IntentHistory::accPreState($a[0], $a[1], $a[2]->get('params'), $a[2]->get('t'), $a[3]);
                case 'accPost':
                    return IntentHistory::accPost($a[0], $a[1], $a[2]->get('verb'), $a[2]->get('params'), $a[2]->get('t'), $a[3]);
                case 'monitorStep':
                    return IntentHistory::monitorStep($a[0], $a[1], $a[2]);
                case 'monitorState':
                    return IntentHistory::monitorState($a[0], $a[1]);
                default:
                    return 'UNKNOWN FUNCTION ' . $fn;
            }
        } catch (HistoryError) {
            return Obj::of(['throws' => true]);
        }
    }

    /**
     * Every case of intent-state-vectors.json through this verifier, compared as strict canonical JSON with the reference
     * output. A case that names a post-quantum suite this runtime lacks (OpenSSL < 3.5) cannot agree and is not counted.
     */
    public static function intentState(): array
    {
        $doc = self::load('intent-state-vectors.json');
        if ($doc->get('format') !== 'pca-intent-state-vectors') {
            return [0, ['not an intent-state vector file']];
        }
        $cases = $doc->get('cases');
        if (!is_array($cases) || count($cases) < 3000) {
            return [0, ['expected more than 3000 intent-state cases']];
        }
        $pqMissing = OracleData::pqMissing();
        $n = 0;
        $fails = [];
        $fns = [];
        foreach ($cases as $c) {
            $fn = $c->get('fn');
            $fns[$fn] = true;
            if ($pqMissing && OracleData::mentionsPq($c->get('args'))) {
                continue;
            }
            $n++;
            try {
                $got = self::intentFn($fn, $c->get('args'));
                $g = Json::canonicalizeStrict(OracleData::asJson($got));
            } catch (\Throwable $e) {
                $g = 'THREW ' . $e::class . ': ' . $e->getMessage();
            }
            $want = Json::canonicalizeStrict($c->get('out'));
            if ($g !== $want) {
                $fails[] = $c->get('name') . ": got $g want $want";
            }
        }
        foreach (['inWindow', 'accKeyOf', 'accPreState', 'accPost', 'monitorStep', 'monitorState', 'verifyReceiptAgainstHolder'] as $fn) {
            if (!isset($fns[$fn])) {
                $fails[] = "no case ran for $fn";
            }
        }
        return [$n, $fails];
    }

    // ---- model-rules-vectors.json: rules 20 / 21 end to end through authorize() ----------------------------------------------------

    /** Signed cases decided by the reference: decision, status, failing checks, the exact reasons in pipeline order, degraded. */
    public static function modelRules(): array
    {
        $doc = self::load('model-rules-vectors.json');
        $cases = $doc->get('cases');
        if (!is_array($cases) || count($cases) !== 32) {
            return [0, ['expected exactly 32 model-rules cases']];
        }
        $now = (int)$doc->get('now')->float();
        $fails = [];
        foreach ($cases as $c) {
            $name = $c->get('name');
            $g = $c->get('grant');
            $ctx = $c->get('context');
            $r = Authorize::authorize($c->get('pcactn'), $c->get('operation'), $doc->get('audience'),
                static fn($ref) => $ref === $g->get('id') ? $g : null, new MemoryStateStore(), static fn() => false, $now, 'single-step',
                $ctx instanceof Obj ? static fn() => $ctx : null, null, $c->get('intent_v2'));
            $e = $c->get('expect');
            $failed = array_keys(array_filter($r->checks, static fn($v) => $v === 'fail'));
            sort($failed);
            $wantFailed = $e->get('failed');
            sort($wantFailed);
            $bad = [];
            if ($r->allow !== $e->get('allow')) {
                $bad[] = 'allow';
            }
            if ($r->decision !== $e->get('decision')) {
                $bad[] = 'decision ' . $r->decision;
            }
            if ($r->status !== (int)$e->get('status')->float()) {
                $bad[] = 'status ' . $r->status;
            }
            if ($failed !== $wantFailed) {
                $bad[] = 'failed ' . implode(',', $failed);
            }
            if ($r->reasons !== $e->get('reasons')) {
                $bad[] = 'reasons ' . json_encode($r->reasons);
            }
            foreach (['units', 'tighten'] as $k) {
                if ($e->has($k) && ($r->checks[$k] ?? null) !== $e->get($k)) {
                    $bad[] = "$k=" . ($r->checks[$k] ?? 'absent');
                }
            }
            $wantDeg = [];
            if ($e->has('degraded')) {
                foreach ($e->get('degraded')->keys() as $k) {
                    $wantDeg[$k] = $e->get('degraded')->get($k);
                }
            }
            if ($r->degraded !== $wantDeg) {
                $bad[] = 'degraded ' . json_encode($r->degraded);
            }
            if ($bad !== []) {
                $fails[] = "$name: " . implode('; ', $bad);
            }
        }
        return [count($cases), $fails];
    }

    // ---- attestation-evidence-vectors.json -----------------------------------------------------------------------------------------

    /** Replace every `{"$blob": id}` with `blobs[id]`. */
    private static function hydrate(mixed $x, Obj $blobs): mixed
    {
        if (is_array($x)) {
            return array_map(static fn($e) => self::hydrate($e, $blobs), $x);
        }
        if ($x instanceof Obj) {
            if ($x->keys() === ['$blob']) {
                return $blobs->get($x->get('$blob'));
            }
            $o = new Obj();
            foreach ($x->keys() as $k) {
                $o->set($k, self::hydrate($x->get($k), $blobs));
            }
            return $o;
        }
        return $x;
    }

    /** A verifier result (PHP arrays) as a parsed JSON value, comparable to a recorded `expect`. */
    private static function asJson(mixed $v): mixed
    {
        return OracleData::asJson(self::normalise($v));
    }

    private static function normalise(mixed $v): mixed
    {
        if (is_array($v)) {
            if ($v === []) {
                return [];
            }
            if (array_is_list($v)) {
                return array_map([self::class, 'normalise'], $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::normalise($x));
            }
            return $o;
        }
        return $v;
    }

    /** The whole result equals the recorded one (a `reason_match: prefix` row compares the stable reason prefix, everything else exactly). */
    private static function attestationSame(array $got, Obj $want): bool
    {
        $g = self::asJson($got);
        if ($want->get('reason_match') === 'prefix') {
            $prefix = $want->get('reason_prefix');
            $reason = $g->get('reason');
            return is_string($reason) && str_starts_with($reason, $prefix)
                && self::same($g->without('reason'), $want->without('reason', 'reason_match', 'reason_prefix'));
        }
        return self::same($g, $want);
    }

    /**
     * Every vendor evidence row (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM) through the
     * verifier built from the row's config, and every strict X.509 reader row: the WHOLE result must equal the TypeScript
     * reference's. The file is generated by the reference's CI; its absence is a failure.
     */
    public static function attestation(): array
    {
        $doc = self::load('attestation-evidence-vectors.json');
        $rows = $doc->get('attestation_vectors');
        $x509 = $doc->get('x509_vectors');
        if (!is_array($rows) || !is_array($x509)) {
            return [0, ['attestation-evidence-vectors.json has no attestation_vectors / x509_vectors']];
        }
        $fails = [];
        $byVendor = [];
        foreach ($rows as $r) {
            $byVendor[$r->get('vendor')] = ($byVendor[$r->get('vendor')] ?? 0) + 1;
        }
        foreach (['amd-sev-snp' => 200, 'intel-tdx-dcap' => 250, 'azure-maa' => 150, 'gcp-confidential-space' => 80, 'nvidia-gpu-spdm' => 70] as $vendor => $min) {
            if (($byVendor[$vendor] ?? 0) < $min) {
                $fails[] = "$vendor: fewer than $min rows";
            }
        }
        if (count($x509) < 90) {
            $fails[] = 'fewer than 90 x509 rows';
        }
        $blobs = $doc->get('blobs');
        foreach ($rows as $r) {
            $h = self::hydrate($r, $blobs);
            $got = \Atlas\Pca\Attest\Factory::runAttestationVector($h);
            if (!self::attestationSame($got, $h->get('expect'))) {
                $fails[] = $r->get('id') . ': got ' . substr(Json::canonicalizeLenient(self::asJson($got)), 0, 300);
            }
        }
        foreach ($x509 as $r) {
            $got = \Atlas\Pca\Attest\Factory::runX509Vector($r->get('fn'), $r->get('input'));
            if (!self::same(self::asJson($got), $r->get('expect'))) {
                $fails[] = $r->get('id') . ': got ' . substr(Json::canonicalizeLenient(self::asJson($got)), 0, 300);
            }
        }
        return [count($rows) + count($x509), $fails];
    }

    // ---- provenance-vectors.json: build provenance gates (track K9) --------------------------------------------------------------

    /** A vector value as plain PHP (Obj -> assoc array, Num -> int), for exact comparison with gate(). */
    private static function plainRaw(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $a = [];
            foreach ($v->keys() as $k) {
                $a[$k] = self::plainRaw($v->get($k));
            }
            return $a;
        }
        if ($v instanceof Num) {
            return $v->int();
        }
        return is_array($v) ? array_map([self::class, 'plainRaw'], $v) : $v;
    }

    public static function provenance(): array
    {
        $doc = self::load('provenance-vectors.json')->get('primitives');
        $fails = [];
        $n = 0;
        foreach ($doc->get('merkle_inclusion') as $v) {
            $n++;
            $i = $v->get('input');
            $ok = ProvenanceGate::verifyRfc9162Inclusion(ProvenanceGate::rfc9162LeafHash(hex2bin($i->get('leaf_hex'))), $i->get('index'), $i->get('size'),
                array_map('hex2bin', $i->get('proof_hex')), hex2bin($i->get('root_hex')));
            $ok === $v->get('expect')->get('ok') || $fails[] = 'provenance/merkle/' . $v->get('name');
        }
        foreach ($doc->get('gate') as $v) {
            $n++;
            $g = ProvenanceGate::gate($v->get('input'));
            $g === self::plainRaw($v->get('expect')) || $fails[] = 'provenance/gate/' . $v->get('name') . ': ' . json_encode($g);
        }
        foreach ($doc->get('model_path') as $v) {
            $n++;
            Decision::isModelDerivedPath($v->get('input')->get('path')) === $v->get('expect')->get('model') || $fails[] = 'provenance/model_path/' . $v->get('name');
        }
        $c = ProvenanceGate::caveat(['issuer' => 'ci', 'min_level' => 3]);
        $n++;
        CaveatLang::needsDischargeError($c) === null && count($c->get('require')) === 2 && $c->get('issuer_class') === 'artifact'
            || $fails[] = 'provenance/caveat: ' . CaveatLang::needsDischargeError($c);
        return [$n, $fails];
    }

    // ---- sigstore-vectors.json: offline Sigstore bundle verification (track K9) ----------------------------------------------
    // Every case: `ok` and the refusal `code` must match the reference; on ok the whole `core` must match. Plus hostile inputs that must not throw.

    public static function sigstore(): array
    {
        $doc = self::load('sigstore-vectors.json');
        $roots = [];
        foreach ($doc->get('roots')->keys() as $k) {
            $roots[$k] = SigstoreBundle::parseTrustedRoot($doc->get('roots')->get($k));
        }
        $fails = [];
        $n = 0;
        $npm = null;
        foreach ($doc->get('cases') as $c) {
            $n++;
            $want = $c->get('expect');
            $r = SigstoreBundle::verifyCore($c->get('bundle'), $roots[$c->get('roots')]);
            if ($r['ok'] !== $want->get('ok')) {
                $fails[] = 'sigstore/' . $c->get('name') . ': ' . ($r['ok'] ? 'accepted' : "refused {$r['code']}: {$r['detail']}");
            } elseif (!$r['ok'] && $r['code'] !== $want->get('code')) {
                $fails[] = 'sigstore/' . $c->get('name') . ": refused {$r['code']}, want " . $want->get('code') . ": {$r['detail']}";
            } elseif ($r['ok'] && $r['core'] !== self::plainRaw($want->get('core'))) {
                $fails[] = 'sigstore/' . $c->get('name') . ': core ' . json_encode($r['core']);
            }
            $c->get('name') === 'npm/sigstore-5.0.0' && $npm = $c;
        }
        $n < 30 && $fails[] = "sigstore: only $n cases";
        // the SLSA facts feed ProvenanceGate (facts shape accepted)
        $n++;
        $root = $roots[$npm->get('roots')];
        $f = SigstoreBundle::verify($npm->get('bundle'), $root);
        ($f['ok'] && ProvenanceGate::factsError($f['facts']) === null && $f['facts']->get('integrated_time') === $npm->get('expect')->get('core')->get('signed_time')->int())
            || $fails[] = 'sigstore/facts: ' . json_encode($f['ok'] ? ProvenanceGate::factsError($f['facts']) : $f);
        // hostile inputs: a refusal with a code, never an exception
        $mutate = static function (mixed $v, array $path, mixed $value) use (&$mutate): mixed {
            $k = array_shift($path);
            if ($v instanceof Obj) {
                $o = Obj::of([]);
                foreach ($v->keys() as $kk) {
                    $o->set($kk, $kk === $k ? ($path === [] ? $value : $mutate($v->get($kk), $path, $value)) : $v->get($kk));
                }
                return $o;
            }
            $v[$k] = $path === [] ? $value : $mutate($v[$k], $path, $value);
            return $v;
        };
        $ok = $npm->get('bundle');
        $vm = $ok->get('verificationMaterial');
        $cases = [[null, null, null], [[], null, null], ['x', null, null],
            [$ok, ['verificationMaterial', 'certificate', 'rawBytes'], substr($vm->get('certificate')->get('rawBytes'), 0, 40)],
            [$ok, ['verificationMaterial', 'tlogEntries', 0, 'canonicalizedBody'], substr($vm->get('tlogEntries')[0]->get('canonicalizedBody'), 0, -8)],
            [$ok, ['verificationMaterial', 'tlogEntries', 0, 'logIndex'], new Num('7')],
            [$ok, ['verificationMaterial', 'tlogEntries', 0, 'inclusionProof', 'hashes'], [null]],
            [$ok, ['dsseEnvelope', 'payload'], 'e30='],
            [$ok, ['dsseEnvelope', 'signatures'], [Obj::of(['sig' => null])]]];
        foreach ($cases as $i => [$b, $path, $value]) {
            $n++;
            try {
                $r = SigstoreBundle::verify($path === null ? $b : $mutate($b, $path, $value), $root);
                ($r['ok'] === false && is_string($r['code'])) || $fails[] = "sigstore/hostile/$i: accepted";
            } catch (\Throwable $e) {
                $fails[] = "sigstore/hostile/$i: threw " . $e->getMessage();
            }
        }
        return [$n, $fails];
    }
}
