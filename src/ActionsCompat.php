<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * Migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary (compat.ts of pca-actions). Every conversion is
 * total and fails closed. A catalog spec is an assoc array (`connector`, `action`, `verb`, `description`, `reversibility`, `blastRadius`, optional
 * `amountField` and `resource`); a def is an {@see Obj}.
 */
final class ActionsCompat
{
    private const REV_RANK = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];
    private const BLAST_RADII = ['one', 'bounded', 'tenant', 'global'];
    private const BLAST_PPM = ['one' => 50000, 'bounded' => 300000, 'tenant' => 700000, 'global' => 1000000];
    private const PPM_MAX = 1000000;

    /** Any old reversibility word to the canonical class; anything unknown is irreversible (fail closed). */
    public static function normalizeReversibility(mixed $x): string
    {
        if (!is_string($x)) {
            return 'irreversible';
        }
        return match ($x) {
            'reversible', 'read' => 'reversible',
            'rate_limited', 'costly' => 'rate_limited',
            default => 'irreversible',
        };
    }

    /** The operations-side word for the revocation staleness table (rate_limited -> costly). */
    public static function legacyOperationsClass(string $r): string
    {
        return $r === 'rate_limited' ? 'costly' : $r;
    }

    public static function maxRevOf(string $a, string $b): string
    {
        return self::REV_RANK[$a] >= self::REV_RANK[$b] ? $a : $b;
    }

    /** The schema `units` entry / envelope UnitTag of a def's unit; null for a money unit whose currency is a parameter reference. */
    public static function unitTagOf(Obj $u): ?Obj
    {
        if ($u->get('kind') !== 'money') {
            return Obj::of(['kind' => $u->get('kind')]);
        }
        if (!is_string($u->get('ccy'))) {
            return null;
        }
        $out = Obj::of(['kind' => 'money', 'currency' => $u->get('ccy')]);
        if ($u->has('exp')) {
            $out->set('exponent', $u->get('exp'));
        }
        return $out;
    }

    private static function ppmOf(mixed $x): int
    {
        $f = $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
        $v = $f !== null && is_finite($f) ? $f : 1.0;
        return (int)min(self::PPM_MAX, max(0, floor($v * 1000000 + 0.5)));
    }

    /** The smallest radius whose default covers the float, and the integer ppm. @return array{radius:string,ppm:int} */
    public static function blastOfFloat(mixed $x): array
    {
        $ppm = self::ppmOf($x);
        foreach (self::BLAST_RADII as $r) {
            if (self::BLAST_PPM[$r] >= $ppm) {
                return ['radius' => $r, 'ppm' => $ppm];
            }
        }
        return ['radius' => 'global', 'ppm' => $ppm];
    }

    /** A legacy float kept exactly: the largest radius whose default does not exceed it, the ppm override carrying the exact value. @return array{radius:string,ppm:int} */
    public static function blastExactOfFloat(mixed $x): array
    {
        $ppm = self::ppmOf($x);
        foreach (array_reverse(self::BLAST_RADII) as $r) {
            if (self::BLAST_PPM[$r] <= $ppm) {
                return ['radius' => $r, 'ppm' => $ppm];
            }
        }
        return ['radius' => 'one', 'ppm' => $ppm];
    }

    /**
     * Convert an old catalog entry: effects inferred conservatively from the action name (an unknown write is `update`, never `read`); an `amountField`
     * becomes a bounded money.amount parameter; the result is `authored`. `$o`: ccy, exp, maxAmount.
     * @param array<string,mixed> $s
     * @param array<string,mixed> $o
     */
    public static function fromCatalogSpec(array $s, array $o = []): Obj
    {
        $hasAmount = array_key_exists('amountField', $s);
        $effects = [];
        if ($hasAmount) {
            $effects[] = 'pay';
        }
        if (preg_match('/\A(?:read|get|list|view|search|fetch|head)(?:_|\z)/', (string)$s['action']) === 1) {
            $effects[] = 'read';
        }
        if (preg_match('/(?:\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\z)/', (string)$s['action']) === 1) {
            $effects[] = 'delete';
        }
        if (preg_match('/(?:\A|_)(?:send|post|publish|notify|email|sms)(?:_|\z)/', (string)$s['action']) === 1) {
            $effects[] = 'send';
        }
        if ($effects === []) {
            $effects[] = 'update';
        }
        $params = new Obj();
        if ($hasAmount) {
            $params->set($s['amountField'], Sign::n(['type' => 'integer', 'role' => 'money.amount', 'min' => 0, 'max' => $o['maxAmount'] ?? 100000000000,
                'unit' => ['kind' => 'money', 'ccy' => $o['ccy'] ?? 'USD', 'exp' => $o['exp'] ?? 2]]));
            $params->set('idempotency_key', Sign::n(['type' => 'string', 'max_len' => 128]));
        }
        $b = self::blastOfFloat($s['blastRadius']);
        $wildcard = !array_key_exists('resource', $s) || $s['resource'] === '*';
        $desc = (string)$s['description'];
        $title = Js::len($desc) > 120 ? self::utf16Prefix($desc, 117) . '...' : $desc;
        $out = Sign::n(['v' => 1, 'kind' => 'pca-action-def', 'verb' => $s['verb'], 'title' => $title, 'description' => $desc, 'effects' => $effects,
            'resource' => ['type' => $s['connector'], 'id' => $wildcard ? '*' : ['prefix' => '', 'class' => 'any_safe', 'len' => [1, 128]], 'scope' => $wildcard ? 'set' : 'one'],
            'params' => $params, 'reversibility' => self::normalizeReversibility($s['reversibility']), 'blast' => ['radius' => $b['radius'], 'ppm' => $b['ppm']]]);
        if ($hasAmount) {
            $out->set('idempotency', Sign::n(['mode' => 'key_param', 'param' => 'idempotency_key']));
        }
        $out->set('review', Sign::n(['state' => 'authored']));
        return $out;
    }

    /** The first `$units` UTF-16 code units of `$s` (a split surrogate pair is cut like the reference's slice). */
    private static function utf16Prefix(string $s, int $units): string
    {
        $u = (string)mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
        return (string)mb_convert_encoding(substr($u, 0, $units * 2), 'UTF-8', 'UTF-16LE');
    }

    /**
     * Convert a list of old catalog entries.
     * @param list<array<string,mixed>> $specs
     * @param array<string,mixed> $o
     * @return list<Obj>
     */
    public static function fromCatalog(array $specs, array $o = []): array
    {
        return array_map(static fn(array $s): Obj => self::fromCatalogSpec($s, $o), $specs);
    }
}
