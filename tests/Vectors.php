<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Pca.php';
require_once __DIR__ . '/../src/Decision.php';
require_once __DIR__ . '/../src/Escalation.php';
require_once __DIR__ . '/../src/Passport.php';
require_once __DIR__ . '/../src/Authorize.php';
require_once __DIR__ . '/../src/Attest/Factory.php';
require_once __DIR__ . '/../src/Ledger.php';
require_once __DIR__ . '/../src/Optimistic.php';
require_once __DIR__ . '/../src/Mesh.php';
require_once __DIR__ . '/../src/IntentHistory.php';
require_once __DIR__ . '/OracleData.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\Decision;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Escalation;
use Atlas\Pca\HistoryError;
use Atlas\Pca\IntentHistory;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Ledger;
use Atlas\Pca\Mesh;
use Atlas\Pca\Optimistic;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Passport;
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
                'passport' => self::passport(),
                'passport-hardware' => self::passportHardware(),
                'intent-state' => self::intentState(),
                'ledger' => self::ledger(),
                'optimistic' => self::optimistic(),
                'mesh' => self::mesh(),
                'model-rules' => self::modelRules(),
                'attestation' => self::attestation(),
                default => throw new \InvalidArgumentException("unknown vector family: $family"),
            };
        } catch (\Throwable $e) {
            return [0, ["$family: " . $e->getMessage()]];
        }
    }

    public const FAMILIES = ['decision', 'escalation', 'passport', 'passport-hardware', 'intent-state', 'ledger', 'optimistic', 'mesh', 'model-rules', 'attestation'];

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
}
