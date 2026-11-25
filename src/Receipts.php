<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * Action receipts (receipt.ts): a tamper-evident client-side record. The transparency ledger is the server's witnessed record; a receipt log is the
 * PRINCIPAL's local, hash-chained copy of what their agents did and how each action was verified. Each receipt commits to the previous one, so a dropped
 * or altered entry is detectable. Pure (hashing only). A receipt is an {@see Obj} with the reference's members: `seq`, `at`, `actionDigest`, `verb`,
 * `resource`, `outcome`, `checks` (optional), `prev` and `hash`. A log is a list of receipts.
 */
final class Receipts
{
    private const DOMAIN = 'atlas-pca/receipt/v1';

    private static function body(Obj $r): Obj
    {
        $b = Obj::of(['d' => self::DOMAIN, 'seq' => $r->get('seq'), 'at' => $r->get('at'), 'actionDigest' => $r->get('actionDigest'), 'verb' => $r->get('verb'),
            'resource' => $r->get('resource'), 'outcome' => $r->get('outcome')]);
        $b->set('checks', $r->has('checks') ? $r->get('checks') : null);
        $b->set('prev', $r->get('prev'));
        return $b;
    }

    /**
     * The next receipt in a chain for a verified action. `$p` is the PCActn (Obj); `$verify` is a verdict with `allow` and optional `checks` (an array or
     * Obj); `$at` defaults to the PCActn's `iat`.
     */
    public static function receiptFor(string $prevHash, int $seq, Obj $p, mixed $verify, ?int $at = null): Obj
    {
        $allow = Js::opt($verify, 'allow') === true;
        $checks = Js::opt($verify, 'checks');
        $action = $p->get('action');
        $r = Obj::of(['seq' => new Num((string)$seq), 'at' => $at !== null ? new Num((string)$at) : $p->get('iat'), 'actionDigest' => Pca::hashCanonical($p),
            'verb' => $action->get('verb'), 'resource' => $action->get('resource'), 'outcome' => $allow ? 'allow' : 'deny']);
        if ($checks !== null) {
            $r->set('checks', Sign::n($checks));
        }
        $r->set('prev', $prevHash);
        $r->set('hash', Pca::hashCanonical(self::body($r)));
        return $r;
    }

    /** Append a verified action to a receipt log, chaining to the last entry. Returns a new list. @param list<Obj> $log @return list<Obj> */
    public static function appendReceipt(array $log, Obj $p, mixed $verify, ?int $at = null): array
    {
        $last = $log === [] ? null : $log[count($log) - 1];
        $seq = $last === null ? 0 : (int)Js::num($last->get('seq')) + 1;
        return [...$log, self::receiptFor($last === null ? '' : $last->get('hash'), $seq, $p, $verify, $at)];
    }

    /**
     * Verify a receipt log is an intact hash chain (sequential, correctly linked, each hash matches): `['ok' => true]` or `['ok' => false, 'brokenAt', 'reason']`.
     * @param list<Obj> $log
     * @return array{ok:bool,brokenAt?:mixed,reason?:string}
     */
    public static function verifyReceiptChain(array $log): array
    {
        $prev = '';
        foreach (array_values($log) as $i => $r) {
            if (!($r instanceof Obj)) {
                throw new \TypeError("Cannot read properties of " . ($r === null ? 'null' : 'a non-object') . " (reading 'seq')");
            }
            $seq = $r->get('seq');
            if (!(Js::isNum($seq) && Js::num($seq) === (float)$i)) {
                $bad = ['ok' => false];
                if ($r->has('seq')) { // an undefined seq leaves no brokenAt
                    $bad['brokenAt'] = Js::isNum($seq) ? Js::num($seq) : $seq;
                }
                $bad['reason'] = 'seq ' . ($r->has('seq') ? Js::str($seq) : 'undefined') . " out of order (expected $i)";
                return $bad;
            }
            if ($r->get('prev') !== $prev) {
                return ['ok' => false, 'brokenAt' => $i, 'reason' => "prev link mismatch at seq $i"];
            }
            // a body member the receipt lacks is undefined, which the canonical form refuses (the reference throws)
            foreach (['at', 'actionDigest', 'verb', 'resource', 'outcome'] as $k) {
                if (!$r->has($k)) {
                    throw new JsonError('canonicalize: unsupported type undefined');
                }
            }
            if (Pca::hashCanonical(self::body($r)) !== $r->get('hash')) {
                return ['ok' => false, 'brokenAt' => $i, 'reason' => "hash mismatch at seq $i (tampered body)"];
            }
            $prev = $r->get('hash');
        }
        return ['ok' => true];
    }

    /** The head hash of a log: a single value that commits to the entire history ('' for an empty log). @param list<Obj> $log */
    public static function receiptHead(array $log): string
    {
        return $log === [] ? '' : (string)$log[count($log) - 1]->get('hash');
    }
}
