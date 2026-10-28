<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Json.php';
require_once __DIR__ . '/../src/Pca.php';
require_once __DIR__ . '/../src/Predicates.php';
require_once __DIR__ . '/../src/IntentV2.php';
require_once __DIR__ . '/../src/Actions.php';
require_once __DIR__ . '/../src/ActionsRegistry.php';
require_once __DIR__ . '/../src/Approval.php';
require_once __DIR__ . '/../src/Escalation.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Approval;
use Atlas\Pca\Escalation;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsRegistry as R;
use Atlas\Pca\PackTracker;
use Atlas\Pca\Num;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;

/**
 * Replay of the shared action-kit vectors (monorepo: packages/pca-conformance/vectors/actions; mirror: conformance/actions): every
 * vector must reproduce its `expect` exactly (compared as strict canonical JSON). A missing directory or a kind that ran too few
 * vectors is a FAILURE (never a skip). Used by conformance-actions.php (plain runner) and ActionVectorsTest (PHPUnit).
 */
final class ActionVectors
{
    public const KINDS = ['parse', 'digest', 'effective', 'expand', 'floor', 'conform', 'pack', 'schema_verb',
        'schema_shape', 'rule22', 'rule22_schema', 'pack_verify', 'evolution_verify', 'reapproval_verify', 'pin', 'pack_proof_verify', 'tracker', 'approval_render', 'approval_digest', 'approval_challenge', 'approval_escalation'];

    public static function dir(): string
    {
        foreach ([__DIR__ . '/../../../packages/pca-conformance/vectors/actions', __DIR__ . '/../conformance/actions', __DIR__ . '/../../conformance/actions'] as $d) {
            if (is_dir($d)) {
                return $d;
            }
        }
        $env = getenv('PCA_ACTION_VECTORS_DIR');
        if (is_string($env) && is_dir($env)) {
            return $env;
        }
        throw new \RuntimeException('the action-kit vectors are missing (a vector directory is never skipped)');
    }

    /** @return list<Obj> */
    public static function cases(): array
    {
        $dir = self::dir();
        $files = glob($dir . '/*.json') ?: [];
        sort($files, SORT_STRING);
        $out = [];
        foreach ($files as $f) {
            $c = Json::parseLax((string)file_get_contents($f));
            if (!($c instanceof Obj)) {
                throw new \RuntimeException("vector is not an object: $f");
            }
            $out[] = $c;
        }
        return $out;
    }

    private static function pins(Obj $i): ?Obj
    {
        return $i->has('pins') ? $i->get('pins') : null;
    }

    private static function codeOf(?string $e): Obj
    {
        return $e === null ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'code' => preg_split('/[: ]/', $e)[0]]);
    }

    public static function replay(Obj $c): mixed
    {
        $i = $c->get('input');
        switch ($c->get('kind')) {
            case 'parse':
                return Obj::of(['ok' => Actions::validateDef($i->get('def')) === null]);
            case 'digest':
                return Obj::of(['digest' => Actions::defDigest($i->get('def')), 'normalized' => Actions::normalize($i->get('def'))]);
            case 'effective':
                $e = Actions::effective($i->get('def'), Actions::coreRegistry(), self::pins($i));
                return Obj::of(['confirmed' => $e['confirmed'], 'traits' => $e['traits'], 'closure' => $e['closure'], 'eff' => Actions::profObj($e['eff'])]);
            case 'expand':
            case 'schema_verb':
                try {
                    $reg = $i->has('custom_traits') && $i->get('custom_traits') !== [] ? Actions::extendRegistry(Actions::coreRegistry(), $i->get('custom_traits')) : Actions::coreRegistry();
                    if ($c->get('kind') === 'expand') {
                        return Obj::of(['closure' => Actions::closure($reg, $i->get('traits')), 'floor' => Actions::profObj(Actions::floorOf($reg, $i->get('traits')))]);
                    }
                    return self::codeOf(Actions::schemaVerbFloorError($i->get('verb'), $reg, self::pins($i)));
                } catch (ActionKitError) {
                    return Obj::of(['error' => true]);
                }
            case 'floor':
                return Obj::of(['decision' => Actions::floorDecision($i->get('grant'), $i->get('call'), Actions::profFromObj($i->get('profile')))]);
            case 'conform':
                $r = IntentV2::conformAction($i->get('schema'), $i->get('verb'), $i->get('params'));
                return $r['ok'] ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'code' => $r['code']]);
            case 'pack':
                $ds = $i->get('digests');
                $n = (int)$i->get('index')->lexeme;
                return Obj::of(['root' => Actions::packRoot($ds), 'proof' => Actions::packProof($ds, $ds[$n])]);
            case 'schema_shape':
                return Obj::of(['ok' => IntentV2::actionSchemaShapeError($i->get('doc'), false) === null]);
            case 'rule22_schema':
                $g = R::rule22Integrity($i->get('doc'), self::pins($i));
                return $g['ok'] ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'code' => $g['code']]);
            case 'rule22':
                $g = R::rule22Integrity($i->get('doc'), self::pins($i));
                if (!$g['ok']) {
                    return Obj::of(['integrity' => $g['code'], 'decision' => 'deny']);
                }
                return Obj::of(['integrity' => 'ok', 'decision' => R::rule22Decide($i->get('doc'), $i->get('verb'), $i->get('grant'), $i->get('context'))]);
            case 'pack_verify':
                $v = R::verifyPack($i->get('pack'), $i->get('keys'), $i->has('shards') ? $i->get('shards') : null);
                return $v['ok'] ? Obj::of(['ok' => true, 'digest' => $v['digest'], 'defs' => new Num((string)count($v['defs']))]) : Obj::of(['ok' => false]);
            case 'evolution_verify':
                try {
                    $d = R::evolutionDiffDigest($i->get('record'));
                } catch (\Throwable) {
                    $d = null;
                }
                return Obj::of(['ok' => R::verifyEvolutionRecord($i->get('record'), $i->get('keys'))['ok'], 'diff' => $d]);
            case 'reapproval_verify':
                $gr = $i->get('grant');
                return Obj::of(['ok' => R::reapprovalValid($i->get('reapproval'), $gr->get('id'), $gr->get('issuer'), $i->get('verb'), $i->get('diff'))]);
            case 'pin':
                $d = R::decidePin(['pin' => $i->get('pin'), 'doc' => $i->get('doc'), 'verb' => $i->get('verb'), 'records' => $i->get('records'),
                    'keys' => $i->get('keys'), 'reapprovals' => $i->get('reapprovals'), 'grant' => $i->get('grant')]);
                if ($d['ok']) {
                    return Obj::of(['ok' => true, 'via' => $d['via']]);
                }
                $o = Obj::of(['ok' => false, 'code' => $d['code'], 'escalate' => $d['escalate']]);
                if (isset($d['needs_reapproval'])) {
                    $o->set('needs_reapproval', $d['needs_reapproval']);
                }
                return $o;
            case 'pack_proof_verify':
                return Obj::of(['ok' => Actions::verifyPackProof($i->get('root'), $i->get('proof'), $i->get('digest'))]);
            case 'tracker':
                $t = new PackTracker($i->get('keys'));
                $out = [];
                foreach ($i->get('steps') as $st) {
                    $r = $t->accept($st->get('pack'), $st->has('shards') ? $st->get('shards') : null);
                    $out[] = $r['ok'] ? Obj::of(['ok' => true, 'status' => $r['status']]) : Obj::of(['ok' => false, 'code' => $r['code']]);
                }
                return $out;
            case 'approval_render':
                try {
                    $r = Approval::render($i->get('def'), $i->get('params'), $i->get('confirmed') === true);
                    $d = Approval::renderDigest($r);
                    return Obj::of(['ok' => true, 'render' => $r, 'digest' => $d, 'words' => Approval::bindingWords($d)]);
                } catch (ActionKitError $e) {
                    return Obj::of(['ok' => false, 'code' => $e->codeName]);
                }
            case 'approval_digest':
                return Approval::renderShapeError($i->get('render')) !== null ? Obj::of(['ok' => false])
                    : Obj::of(['ok' => true, 'digest' => Approval::renderDigest($i->get('render'))]);
            case 'approval_challenge':
                try {
                    return Obj::of(['ok' => true, 'challenge' => Approval::challenge($i->get('action_digest'), $i->get('render_digest'))]);
                } catch (\InvalidArgumentException) {
                    return Obj::of(['ok' => false]);
                }
            case 'approval_escalation':
                $v = Escalation::verifyAnswer($i->get('answer'), $i->get('principals'), $i->get('bind'), $i->get('now'));
                return $v['ok'] ? Obj::of(['ok' => true, 'decision' => $v['decision']]) : Obj::of(['ok' => false, 'reason' => $v['reason']]);
            case 'approval_psd2':
                try {
                    return Obj::of(['ok' => true, 'linking' => Approval::psd2Linking($i->get('render'))]);
                } catch (ActionKitError $e) {
                    return Obj::of(['ok' => false, 'code' => $e->codeName]);
                }
            case 'approval_batch':
                try {
                    $b = Approval::batch($i->get('items'));
                    return Obj::of(['ok' => true, 'batch' => $b->get('batch'), 'action_digest' => $b->get('action_digest'), 'render_digest' => $b->get('render_digest'),
                        'challenge' => $b->get('challenge'), 'words' => $b->get('words')]);
                } catch (ActionKitError $e) {
                    return Obj::of(['ok' => false, 'code' => $e->codeName]);
                }
        }
        throw new \RuntimeException('unknown vector kind ' . $c->get('kind'));
    }

    /** @return array{0:int,1:list<string>} [profile vectors run, failures] */
    public static function runProfiles(): array
    {
        $dir = null;
        foreach ([__DIR__ . '/../../../packages/pca-conformance/vectors/approval-profiles', __DIR__ . '/../conformance/approval-profiles', __DIR__ . '/../../conformance/approval-profiles'] as $d) {
            if (is_dir($d)) {
                $dir = $d;
                break;
            }
        }
        if ($dir === null) {
            return [0, ['the approval profile vectors are missing (a vector directory is never skipped)']];
        }
        $files = glob($dir . '/*.json') ?: [];
        sort($files, SORT_STRING);
        $fails = [];
        foreach ($files as $f) {
            $c = Json::parseLax((string)file_get_contents($f));
            try {
                $got = IntentV2::canonicalize(self::replay($c));
                $want = IntentV2::canonicalize($c->get('expect'));
                if ($got !== $want) {
                    $fails[] = $c->get('id') . ": got $got, want $want";
                }
            } catch (\Throwable $e) {
                $fails[] = $c->get('id') . ': ' . $e->getMessage();
            }
        }
        if (count($files) < 12) {
            $fails[] = 'only ' . count($files) . ' approval profile vectors';
        }
        return [count($files), $fails];
    }

    /** @return array{0:int,1:list<string>} [vectors run, failures] */
    public static function run(): array
    {
        $fails = [];
        $kinds = [];
        $n = 0;
        foreach (self::cases() as $c) {
            $n++;
            $k = (string)$c->get('kind');
            $kinds[$k] = ($kinds[$k] ?? 0) + 1;
            try {
                $got = IntentV2::canonicalize(self::replay($c));
                $want = IntentV2::canonicalize($c->get('expect'));
                if ($got !== $want) {
                    $fails[] = $c->get('id') . ": got $got, want $want";
                }
            } catch (\Throwable $e) {
                $fails[] = $c->get('id') . ': ' . $e->getMessage();
            }
        }
        foreach (self::KINDS as $k) {
            if (($kinds[$k] ?? 0) < 8) {
                $fails[] = "kind $k ran too few vectors";
            }
        }
        if ($n < 781) {
            $fails[] = "only $n vectors ran (need 781)";
        }
        return [$n, $fails];
    }
}
