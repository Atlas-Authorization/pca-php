<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';

/**
 * Forbid-wins certificate check (security contract C-241): a port of `certificateConsistent` in
 * packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative). The certificate's own table entails its decision:
 * any matched forbid denies (the most authoritative signer is named, ties by id); otherwise no matched permit denies; otherwise
 * a matched escalate clause escalates; otherwise allow. No predicate evaluator is needed. Total: never throws; a certificate
 * that cannot be read is not consistent.
 */
final class ForbidCertificate
{
    private const KINDS = ['permit', 'forbid', 'escalate'];
    private const VALUES = ['true', 'false', 'unknown'];

    /** @param list<string> $precedence signers, most authoritative first */
    public static function consistent(mixed $cert, array $precedence = []): bool
    {
        try {
            if (!($cert instanceof Obj) || !self::isOne($cert->get('v')) || $cert->get('kind') !== 'forbid-wins' || !is_array($cert->get('clauses')) || !array_is_list($cert->get('clauses'))) {
                return false;
            }
            $rows = $cert->get('clauses');
            $winner = $cert->get('winner');
            $shadowed = $cert->get('shadowed');
            if (!($winner instanceof Obj) || !is_array($shadowed)) {
                return false;
            }
            if ($winner->get('kind') === 'malformed') {
                return $rows === [] && $cert->get('decision') === 'deny' && $winner->get('id') === null && $shadowed === [];
            }
            foreach ($rows as $r) {
                if (!($r instanceof Obj) || !is_string($r->get('id')) || !in_array($r->get('kind'), self::KINDS, true) || !in_array($r->get('value'), self::VALUES, true)) {
                    return false;
                }
            }
            $rank = static function (Obj $r) use ($precedence): int {
                $i = is_string($r->get('signer')) ? array_search($r->get('signer'), $precedence, true) : false;
                return $i === false ? count($precedence) : $i; // an unlisted (or absent) signer ranks last
            };
            $hit = static fn (string $kind): array => array_values(array_filter($rows, static fn (Obj $r): bool => $r->get('kind') === $kind && $r->get('value') !== 'false'));
            $forbids = $hit('forbid');
            usort($forbids, static function (Obj $a, Obj $b) use ($rank): int {
                return $rank($a) <=> $rank($b) ?: strcmp(self::u16($a->get('id')), self::u16($b->get('id')));
            });
            $permits = $hit('permit');
            $escalates = $hit('escalate');
            if ($forbids !== []) {
                [$win, $decision, $kind] = [$forbids[0], 'deny', 'forbid'];
            } elseif ($permits === []) {
                [$win, $decision, $kind] = [null, 'deny', 'none'];
            } elseif ($escalates !== []) {
                [$win, $decision, $kind] = [$escalates[0], 'escalate', 'escalate'];
            } else {
                [$win, $decision, $kind] = [$permits[0], 'allow', 'permit'];
            }
            $others = [];
            foreach (array_merge($forbids, $permits, $escalates) as $r) {
                if ($r !== $win) {
                    $others[] = $r->get('id');
                }
            }
            return $cert->get('decision') === $decision
                && $winner->get('kind') === $kind
                && $winner->get('id') === ($win?->get('id'))
                && $shadowed === $others;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function isOne(mixed $v): bool
    {
        return $v instanceof Num && $v->lexeme === '1';
    }

    /** UTF-16BE bytes: the reference orders ids by UTF-16 code unit (JavaScript `<`). */
    private static function u16(mixed $s): string
    {
        return mb_convert_encoding((string)$s, 'UTF-16BE', 'UTF-8');
    }
}
