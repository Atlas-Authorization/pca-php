<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentMisc.php';
require_once __DIR__ . '/../src/IntentHistory.php';
require_once __DIR__ . '/../src/IntentJit.php';
require_once __DIR__ . '/../src/IntentSessionStore.php';
require_once __DIR__ . '/../src/IntentV2Acc.php';
require_once __DIR__ . '/../src/IntentV2Session.php';

use Atlas\Pca\IntentHistory;
use Atlas\Pca\IntentJit;
use Atlas\Pca\IntentMisc;
use Atlas\Pca\IntentSessionStore;
use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentV2Acc;
use Atlas\Pca\IntentV2Session;
use Atlas\Pca\IntentWb;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\SessionTx;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An in-memory session store with a configurable durability flag (absent = not durable) whose log is visible to the test. */
final class MisclogStore implements IntentSessionStore
{
    /** @var array<string,list<Obj>> */
    public array $ev = [];

    public function __construct(private readonly bool $isDurable)
    {
    }

    public function durable(): bool
    {
        return $this->isDurable;
    }

    public function withSession(string $session, callable $fn): mixed
    {
        $this->ev[$session] ??= [];
        $log = &$this->ev[$session];
        return $fn(new class ($log) implements SessionTx {
            public function __construct(private array &$log)
            {
            }

            public function events(): array
            {
                return array_map(static fn(Obj $e): Obj => $e->without(), $this->log);
            }

            public function append(Obj $e): void
            {
                $this->log[] = $e->without();
            }

            public function setStatus(string $id, string $status): bool
            {
                foreach ($this->log as $x) {
                    if ($x->get('id') === $id) {
                        $x->set('status', $status);
                        return true;
                    }
                }
                return false;
            }
        });
    }
}

/**
 * The core intent-required, intent-classifier, intent-artifacts and accumulator helper functions against the TS reference: every case of
 * test-data/ref-intent-misc2.json.gz except the four signers replayed in the signers test. Keys travel as labels (a secret is sha256("atlas-pca-conformance/" . label);
 * a suite {alg, pqSeed} is ML-DSA-65 from that seed). The constants are rebuilt from the native modules with the regexes in the reference's source form.
 */
final class RefIntentMisc2DifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-misc2.json.gz';
    private const FNS = ['intentRequiredShapeError' => 90, 'decideClassifierDimensions' => 44, 'intentProblem' => 42, 'validateClassifierPolicy' => 42, 'cellCoordsError' => 26,
        'verifyIntentRequired' => 26, 'verifyIntentRequiredAt' => 26, 'validateClassifierVerdictWire' => 26, 'resolveParamPath' => 25, 'isParamPath' => 25, 'verifyArtifactSig' => 18,
        'distinctKey' => 18, 'isPathSegment' => 16, 'isScalar' => 16, 'setNested' => 14, 'monitorStates' => 13, 'monitorInitialState' => 13, 'accContextFor' => 13, 'isSafeInt' => 12,
        'isClock' => 12, 'isBoundedString' => 12, 'isDigest' => 12, 'artifactSuiteError' => 12, 'classifierContentDigest' => 12, 'scalarEq' => 11, 'ownGet' => 11,
        'classifierCheckActive' => 11, 'verifyClassifierAttestation' => 11, 'admit' => 11, 'artifactMessage' => 10, 'isPlainObject' => 8, 'closedMembers' => 8, 'signArtifact' => 8,
        'artifactRef' => 8, 'signIntentRequired' => 8, 'verifyReceiptSignature' => 8, 'verifyKeySet' => 8, 'utf8Len' => 7, 'sortedDistinct' => 7, 'pinPqOk' => 6, 'intentActionDigest' => 6,
        'classifierVerdictRef' => 5, 'accReceiptDigest' => 4, 'sequencerKeySetDigest' => 3, 'publicKeyB64u' => 2, 'constants' => 1, 'nullRecord' => 1];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => isset(self::FNS[$d[1]]));
    }

    private static function raw(mixed $v): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $v->get('$bytes')->get('$seed'), true);
    }

    private static function key(mixed $v): KeyPair
    {
        return new KeyPair(self::raw($v));
    }

    /** @return array{0:?string,1:?PqKeyPair} */
    private static function suite(mixed $s): array
    {
        if (!($s instanceof Obj)) {
            return [null, null];
        }
        return [$s->get('alg'), $s->has('pqSeed') ? new PqKeyPair('ML-DSA-65', self::raw($s->get('pqSeed'))) : null];
    }

    /** {"$num": "NaN"} becomes the float, at any depth. */
    private static function un(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::un(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if ($v->keys() === ['$num']) {
            return ['NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF][$v->get('$num')];
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::un($v->get($k)));
        }
        return $o;
    }

    /** A PHP PCRE constant in the reference's JavaScript source form. */
    private static function rx(string $re): Obj
    {
        $s = substr($re, 1, strrpos($re, '/') - 1);
        return Obj::of(['$regex' => str_replace(['\A', '\z'], ['^', '$'], $s)]);
    }

    private static function constants(): Obj
    {
        return Obj::of([
            'DATA_CLASS_RE' => self::rx(IntentWb::DATA_CLASS_RE), 'INTENT_NAME_RE' => self::rx(IntentWb::INTENT_NAME_RE), 'PARAM_SEGMENT_RE' => self::rx(IntentWb::PARAM_SEGMENT_RE),
            'SUITE_MEMBERS' => IntentWb::SUITE_MEMBERS, 'FRICTIONS' => IntentMisc::FRICTIONS, 'INTENT_ACTION_DOMAIN' => IntentJit::INTENT_ACTION_DOMAIN,
            'INTENT_PROBLEM_KINDS' => IntentMisc::INTENT_PROBLEM_KINDS, 'INTENT_REQUIRED_DOMAIN' => SignersMore::INTENT_REQUIRED_DOMAIN, 'PROBLEM_BASE' => IntentMisc::PROBLEM_BASE,
            'INTENT_CLASSIFIER_DOMAIN' => IntentWb::INTENT_CLASSIFIER_DOMAIN, 'INTENT_CLASSIFIER_REF_DOMAIN' => IntentWb::INTENT_CLASSIFIER_REF_DOMAIN,
            'MAX_CLASSIFIER_LABELS' => IntentWb::MAX_CLASSIFIER_LABELS, 'MAX_COMMITTED_CLASSES' => IntentWb::MAX_COMMITTED_CLASSES, 'ACC_AGGS' => IntentV2::ACC_AGGS,
            'ACC_ID_RE' => self::rx(IntentV2::ACC_ID_RE), 'ACC_RECEIPT_CORE_DOMAIN' => SignersMore::ACC_RECEIPT_CORE_DOMAIN, 'ACC_RECEIPT_DOMAIN' => IntentV2::ACC_RECEIPT_DOMAIN,
            'ACC_RECEIPT_REF_DOMAIN' => IntentV2::ACC_RECEIPT_REF_DOMAIN, 'ACC_RESERVE_DOMAIN' => IntentV2::ACC_RESERVE_DOMAIN, 'ACC_SCOPES' => SignersMore::ACC_SCOPES,
            'DEFAULT_MAX_KEYSET_AGE_MS' => IntentV2::DEFAULT_MAX_KEYSET_AGE_MS, 'DEFAULT_MAX_RECEIPT_AGE_MS' => IntentV2::DEFAULT_MAX_RECEIPT_AGE_MS, 'KID_RE' => self::rx(IntentV2::KID_RE),
            'MAX_MONITOR_WITHIN' => IntentV2::MAX_MONITOR_WITHIN, 'MAX_RECEIPT_LIFETIME_MS' => IntentV2::MAX_RECEIPT_LIFETIME_MS, 'MAX_SESSION_ACCUMULATORS' => IntentV2::MAX_SESSION_ACCUMULATORS,
            'MAX_SESSION_MONITORS' => IntentV2::MAX_SESSION_MONITORS, 'MONITOR_KINDS' => IntentV2::MONITOR_KINDS, 'RECEIPT_SKEW_MS' => IntentV2::RECEIPT_SKEW_MS,
            'SEQUENCER_KEYS_DOMAIN' => IntentV2::SEQUENCER_KEYS_DOMAIN, 'SEQUENCER_KEYS_REF_DOMAIN' => IntentV2::SEQUENCER_KEYS_REF_DOMAIN,
            'COUNTED_STATUSES' => IntentHistory::COUNTED_STATUSES, 'EVENT_STATUSES' => IntentHistory::EVENT_STATUSES,
        ]);
    }

    private static function admit(array $ops): array
    {
        $st = new MisclogStore(true);
        $out = [];
        foreach ($ops as $op) {
            try {
                $kind = $op[0];
                if ($kind === 'store') {
                    $d = $op[1]->get('durable');
                    $st = new MisclogStore($d === 'absent' ? false : $d !== false);
                    $out[] = null;
                } elseif ($kind === 'admit') {
                    $a = $op[1];
                    $args = ['session' => $a->get('session'), 'root' => $a->get('root'), 'event' => $a->get('event'),
                        'verify' => static function (array $acc) use ($a, &$out): array {
                            if ($a->get('verifyAs') === 'throws') {
                                throw new \RuntimeException('verify boom');
                            }
                            $out[] = Obj::of(['acc' => $acc]);
                            return ['allow' => $a->get('verifyAs')->get('allow')];
                        }];
                    if ($a->has('schema') && $a->get('schema')) {
                        $args['schema'] = $a->get('schema');
                    }
                    if ($a->has('requireDurable')) {
                        $args['requireDurable'] = $a->get('requireDurable');
                    }
                    $v = IntentHistory::admitIntentAction($st, $args);
                    $out[] = Obj::of(['allow' => is_array($v) ? $v['allow'] : $v->get('allow')]);
                } elseif ($kind === 'settle') {
                    $out[] = IntentHistory::settleIntentEvent($st, $op[1], $op[2], $op[3]);
                } elseif ($kind === 'events') {
                    $out[] = array_map(static fn(Obj $e): Obj => $e->without(), $st->ev[$op[1]] ?? []);
                } else {
                    $out[] = Obj::of(['$err' => 'op']);
                }
            } catch (\Throwable) {
                $out[] = Obj::of(['$err' => true]);
            }
        }
        return $out;
    }

    private static function pin(mixed $p): array
    {
        if ($p instanceof Obj && $p->has('pqPins')) { // {pqPins: {issuerKey: pqPublicKey}}: the pin of the receipt's own signer
            $m = $p->get('pqPins');
            $k = $m instanceof Obj ? ($m->keys()[0] ?? null) : null;
            return [$k, $k === null ? null : $m->get($k)];
        }
        return $p instanceof Obj ? [$p->get('pk'), $p->has('pq_pk') ? $p->get('pq_pk') : null] : [$p, null];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => self::constants(),
            'isPathSegment' => static fn(array $a) => IntentWb::isPathSegment($a[0]),
            'isPlainObject' => static fn(array $a) => IntentMisc::isPlainObject(self::un($a[0])),
            'isSafeInt' => static fn(array $a) => IntentMisc::isSafeInt(self::un($a[0])),
            'isScalar' => static fn(array $a) => IntentMisc::isScalar(self::un($a[0])),
            'isClock' => static fn(array $a) => IntentMisc::isClock(self::un($a[0])),
            'scalarEq' => static fn(array $a) => IntentMisc::scalarEq(self::un($a[0]), self::un($a[1])),
            'utf8Len' => static fn(array $a) => IntentMisc::utf8Len($a[0]),
            'isBoundedString' => static fn(array $a) => IntentMisc::isBoundedString($a[0], self::un($a[1])),
            'isDigest' => static fn(array $a) => IntentWb::isDigest($a[0]),
            'closedMembers' => static fn(array $a) => IntentWb::closedMembers($a[0], $a[1], $a[2] ?? [], $a[3] ?? 'object'),
            'pinPqOk' => static fn(array $a) => IntentWb::pinPqOk($a[0]),
            'artifactSuiteError' => static fn(array $a) => IntentWb::artifactSuiteError($a[0]),
            'artifactMessage' => static fn(array $a) => Base::outBytes(IntentWb::artifactMessage($a[0], self::un($a[1]))),
            'signArtifact' => static fn(array $a) => Sign::signArtifact($a[0], self::un($a[1]), self::key($a[2]), ...self::suite($a[3])),
            'verifyArtifactSig' => static fn(array $a) => IntentWb::verifyArtifactSig($a[0], $a[1], $a[2]),
            'artifactRef' => static fn(array $a) => IntentWb::artifactRef($a[0], $a[1], self::un($a[2])),
            'publicKeyB64u' => static fn(array $a) => IntentMisc::publicKeyB64u(self::raw($a[0])),
            'resolveParamPath' => static fn(array $a) => IntentWb::resolveParamPath($a[0], $a[1]),
            'isParamPath' => static fn(array $a) => IntentWb::isParamPath($a[0]),
            'setNested' => static function (array $a) {
                $root = $a[0]->get('root');
                $ok = IntentWb::setNested($root, $a[0]->get('path'), $a[0]->get('value'));
                return Obj::of(['ok' => $ok, 'root' => $root]);
            },
            'ownGet' => static fn(array $a) => IntentMisc::ownGet($a[0], $a[1]),
            'nullRecord' => static fn(array $a) => IntentMisc::nullRecord(),
            'intentActionDigest' => static fn(array $a) => IntentJit::intentActionDigest($a[0]),
            'cellCoordsError' => static fn(array $a) => SignersMore::cellCoordsError(self::un($a[0])),
            'intentRequiredShapeError' => static fn(array $a) => IntentMisc::intentRequiredShapeError($a[0], $a[1] ?? null),
            'signIntentRequired' => static fn(array $a) => SignersMore::signIntentRequired(self::un($a[0]), $a[1], self::key($a[2]), ...self::suite($a[3])),
            'verifyIntentRequired' => static fn(array $a) => IntentV2::verifyIntentRequired($a[0], $a[1], self::un($a[2])),
            'verifyIntentRequiredAt' => static fn(array $a) => IntentMisc::verifyIntentRequiredAt($a[0], $a[1], self::un($a[2])),
            'intentProblem' => static fn(array $a) => IntentMisc::intentProblem($a[0], $a[1] ?? null),
            'validateClassifierVerdictWire' => static fn(array $a) => IntentWb::validateClassifierVerdictWire(self::un($a[0])),
            'classifierContentDigest' => static fn(array $a) => IntentMisc::classifierContentDigest(self::un($a[0])),
            'classifierVerdictRef' => static fn(array $a) => IntentWb::classifierVerdictRef(self::un($a[0])),
            'validateClassifierPolicy' => static fn(array $a) => IntentWb::validateClassifierPolicy(self::un($a[0])),
            'classifierCheckActive' => static fn(array $a) => IntentWb::classifierCheckActive(self::un($a[0])),
            'decideClassifierDimensions' => static fn(array $a) => IntentWb::decideClassifierDimensions(self::un($a[0])),
            'verifyClassifierAttestation' => static fn(array $a) => IntentMisc::verifyClassifierAttestation($a[0], $a[1] ?? null, $a[2] ?? null),
            'monitorStates' => static fn(array $a) => IntentV2::monitorStates($a[0]),
            'monitorInitialState' => static fn(array $a) => IntentMisc::monitorInitialState($a[0]),
            'distinctKey' => static fn(array $a) => IntentV2::distinctKey(self::un($a[0])),
            'sortedDistinct' => static fn(array $a) => IntentMisc::sortedDistinct($a[0]),
            'accReceiptDigest' => static fn(array $a) => IntentV2::accReceiptDigest($a[0]),
            'sequencerKeySetDigest' => static fn(array $a) => IntentV2::sequencerKeySetDigest($a[0]),
            'verifyReceiptSignature' => static function (array $a, Obj $c) {
                $have = IntentV2::verifyAccReceiptSignature($a[0], $a[1], ...self::pin($a[2] ?? null));
                if ($c->get('out') === true && ($a[2] ?? null) instanceof Obj && $a[2]->get('allowUnboundPq') === true) {
                    // RULING: allowUnboundPq is not ported, so what the reference accepts only through it must be refused
                    \PHPUnit\Framework\Assert::assertFalse($have, 'allowUnboundPq is not ported: the native verifier refuses what only that opt-out accepts');
                    return $c->get('out'); // refused, as the ruling requires: counted as run, never skipped
                }
                return $have;
            },
            'verifyKeySet' => static fn(array $a) => IntentV2::verifySequencerKeySet($a[0], $a[1], $a[2] ?? null),
            'accContextFor' => static fn(array $a) => IntentHistory::accContextFor($a[0], $a[1], $a[2], $a[3] ?? null),
            'admit' => static fn(array $a) => self::admit($a[0]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
