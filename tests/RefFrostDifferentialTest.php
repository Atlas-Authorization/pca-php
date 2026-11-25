<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Frost;
use Atlas\Pca\FrostNonces;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * FROST(Ed25519, SHA-512), RFC 9591, against the TS reference: test-data/ref-frost.json.gz (scalar reduction, the five hashes, strict
 * point decoding, dealer key generation, commit, sign, aggregate, the per-share check and the one-shot coordinator). Hostile shapes (a
 * missing member, a non-integer identifier) are refused while decoding, as the reference refuses them. The dealer secrets are throwaway
 * constants derived from fixed seeds.
 */
final class RefFrostDifferentialTest extends TestCase
{
    private const FILE = 'ref-frost.json.gz';

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    private static function bytes(mixed $v): string
    {
        $b = Base::bytes($v);
        if (!is_string($b)) {
            throw new \InvalidArgumentException('not bytes');
        }
        return $b;
    }

    /** Descriptors of a secret in the corpus: {"$seed": label}, {"$share": {t, n, secret, coefficients, identifiers, id}}, {"$nonce": {r, share}}. */
    private static function secretBytes(mixed $v): string
    {
        if ($v instanceof Obj && $v->keys() === ['$bytes']) {
            return self::bytes($v);
        }
        $o = self::obj($v);
        $k = $o->keys()[0] ?? '';
        $x = $o->get($k);
        switch ($k) {
            case '$seed':
                return hash('sha256', 'atlas-pca-conformance/' . $x, true);
            case '$nonce':
                return Frost::h3(self::secretBytes($x->get('r')) . Frost::bytesToScalar(self::secretBytes($x->get('share'))));
            case '$share':
                $secret = $x->get('secret') === null ? null : self::secretBytes($x->get('secret'));
                $coeffs = array_map(self::secretBytes(...), self::list($x->get('coefficients') ?? []));
                $ids = $x->get('identifiers') === null ? null : array_map(self::idInt(...), self::list($x->get('identifiers')));
                $kg = Frost::trustedDealerKeygen(self::idInt($x->get('t')), self::idInt($x->get('n')), $secret, $coeffs, $ids);
                $id = self::idInt($x->get('id'));
                foreach ($kg['participantShares'] as $p) {
                    if ($p['identifier'] === $id) {
                        return $p['share'];
                    }
                }
                throw new \InvalidArgumentException('no such participant');
            default:
                throw new \InvalidArgumentException('unknown descriptor');
        }
    }

    /** Resolves every descriptor of an argument tree to {"$bytes"}. */
    private static function restore(mixed $v): mixed
    {
        if (is_array($v)) {
            return array_map(self::restore(...), $v);
        }
        if (!($v instanceof Obj)) {
            return $v;
        }
        if (count($v->keys()) === 1 && in_array($v->keys()[0], ['$seed', '$share', '$nonce'], true)) {
            return self::b(self::secretBytes($v));
        }
        $o = new Obj();
        foreach ($v->keys() as $k) {
            $o->set($k, self::restore($v->get($k)));
        }
        return $o;
    }

    /** The native result with every value the reference hides behind {"$sha256"} hashed the same way. */
    private static function mask(mixed $have, mixed $want): mixed
    {
        if ($want instanceof Obj && $want->keys() === ['$sha256'] && $have instanceof Obj && $have->keys() === ['$bytes']) {
            return Obj::of(['$sha256' => Pca::b64u(hash('sha256', self::bytes($have), true))]);
        }
        if (is_array($have)) {
            $w = is_array($want) ? $want : [];
            return array_map(static fn($x, $i) => self::mask($x, $w[$i] ?? null), $have, array_keys($have));
        }
        if ($have instanceof Obj) {
            $o = new Obj();
            foreach ($have->keys() as $k) {
                $o->set($k, self::mask($have->get($k), $want instanceof Obj && $want->has($k) ? $want->get($k) : null));
            }
            return $o;
        }
        return $have;
    }

    private static function idInt(mixed $v): int
    {
        if ($v instanceof Num && $v->isInt()) {
            return $v->int();
        }
        throw new \InvalidArgumentException('not a safe integer');
    }

    private static function obj(mixed $v): Obj
    {
        if (!($v instanceof Obj)) {
            throw new \InvalidArgumentException('malformed object');
        }
        return $v;
    }

    private static function list(mixed $v): array
    {
        if (!is_array($v) || !array_is_list($v)) {
            throw new \InvalidArgumentException('not a list');
        }
        return $v;
    }

    private static function commitment(mixed $v): array
    {
        $o = self::obj($v);
        return ['identifier' => self::idInt($o->get('identifier')), 'hiding' => self::bytes($o->get('hiding')), 'binding' => self::bytes($o->get('binding'))];
    }

    private static function commitments(mixed $v): array
    {
        return array_map(self::commitment(...), self::list($v));
    }

    private static function sigShares(mixed $v): array
    {
        return array_map(static fn($s) => ['identifier' => self::idInt(self::obj($s)->get('identifier')), 'sigShare' => self::bytes($s->get('sigShare'))], self::list($v));
    }

    private static function vss(mixed $v): ?array
    {
        if ($v === null) {
            return null;
        }
        return array_map(static fn($s) => ['identifier' => self::idInt(self::obj($s)->get('identifier')), 'publicKey' => self::bytes($s->get('publicKey'))], self::list($v));
    }

    private static function participant(mixed $v): array
    {
        $o = self::obj($v);
        try {
            $pk = self::bytes($o->get('publicKey'));
        } catch (\Throwable) {
            $pk = '';
        }
        return ['identifier' => self::idInt($o->get('identifier')), 'share' => self::bytes($o->get('share')), 'publicKey' => $pk];
    }

    private static function b(string $x): Obj
    {
        return Base::outBytes($x);
    }

    private static function commitJson(array $c): Obj
    {
        return Obj::of(['identifier' => new Num((string)$c['identifier']), 'hiding' => self::b($c['hiding']), 'binding' => self::b($c['binding'])]);
    }

    private static function keygenJson(array $k): Obj
    {
        return Obj::of(['groupPublicKey' => self::b($k['groupPublicKey']),
            'participantShares' => array_map(static fn(array $p) => Obj::of(['identifier' => new Num((string)$p['identifier']), 'share' => self::b($p['share']),
                'publicKey' => self::b($p['publicKey'])]), $k['participantShares']),
            'groupCommitment' => array_map(self::b(...), $k['groupCommitment'])]);
    }

    private static function keygen(mixed $o): array
    {
        $o = self::obj($o);
        $t = $o->get('t');
        $n = $o->get('n');
        if (!($t instanceof Num && $t->isInt() && $n instanceof Num && $n->isInt())) {
            throw new \InvalidArgumentException('t and n must be integers');
        }
        $secret = $o->get('secret') === null ? null : self::bytes($o->get('secret'));
        $coeffs = $o->get('coefficients') === null ? null : array_map(self::bytes(...), self::list($o->get('coefficients')));
        $ids = $o->get('identifiers') === null ? null : array_map(self::idInt(...), self::list($o->get('identifiers')));
        return Frost::trustedDealerKeygen($t->int(), $n->int(), $secret, $coeffs, $ids);
    }

    private static function opts(mixed $o): array
    {
        if ($o === null) {
            return [];
        }
        $o = self::obj($o);
        $s = ['threshold' => $o->get('threshold')];
        if ($o->has('verificationShare') && $o->get('verificationShare') !== null) {
            $s['verificationShare'] = self::bytes($o->get('verificationShare'));
        }
        $vs = self::vss($o->get('verificationShares'));
        if ($vs !== null) {
            $s['verificationShares'] = $vs;
        }
        return $s;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        $map = [
            'scalar' => fn(array $a) => self::b(Frost::bytesToScalar(self::bytes($a[0]))),
            'isCanonicalScalar' => fn(array $a) => Frost::isCanonicalScalar(Base::bytes($a[0])),
            'hash' => function (array $a): Obj {
                $m = self::bytes($a[1]);
                return self::b(match ($a[0]) {
                    'H1' => Frost::h1($m), 'H2' => Frost::h2($m), 'H3' => Frost::h3($m), 'H4' => Frost::h4($m), 'H5' => Frost::h5($m),
                    default => throw new \InvalidArgumentException('unknown hash'),
                });
            },
            'decodeSafePoint' => fn(array $a) => self::b(Frost::decodeSafePoint(Base::bytes($a[0]))),
            'keygen' => fn(array $a) => self::keygenJson(self::keygen($a[0])),
            'verifyingShare' => fn(array $a) => self::b(Frost::verifyingShare(self::bytes($a[0]))),
            'commit' => function (array $a): Obj {
                $r = Frost::commit(['identifier' => self::idInt($a[0]), 'share' => self::bytes($a[1])], self::bytes($a[2]), self::bytes($a[3]));
                return Obj::of(['hidingNonce' => self::b($r['hidingNonce']), 'bindingNonce' => self::b($r['bindingNonce']), 'commitment' => self::commitJson($r['commitment'])]);
            },
            'flow' => function (mixed $a): Obj {
                $a = $a instanceof Obj ? [$a] : $a; // the generated corpus carries the one argument unwrapped
                $kg = self::keygen($a[0]);
                $message = self::bytes($a[0]->get('message'));
                $signers = self::list($a[0]->get('signers'));
                $rnd = self::list($a[0]->get('randomness'));
                $quorum = array_map(static function ($s) use ($kg): array {
                    $i = self::idInt($s);
                    foreach ($kg['participantShares'] as $p) {
                        if ($p['identifier'] === $i) {
                            return $p;
                        }
                    }
                    throw new \InvalidArgumentException('unknown signer');
                }, $signers);
                if (count($rnd) < count($quorum)) {
                    throw new \InvalidArgumentException('randomness');
                }
                $commits = [];
                foreach ($quorum as $i => $p) {
                    $commits[] = Frost::commit($p, self::bytes(self::obj($rnd[$i])->get('hr')), self::bytes($rnd[$i]->get('br')));
                }
                $cs = array_map(static fn(array $c): array => $c['commitment'], $commits);
                $vs = array_map(static fn(array $p): array => ['identifier' => $p['identifier'], 'publicKey' => $p['publicKey']], $quorum);
                $thr = $a[0]->get('threshold');
                $shares = [];
                foreach ($quorum as $i => $p) {
                    $shares[] = Frost::sign($p['identifier'], $p['share'], $kg['groupPublicKey'], new FrostNonces($commits[$i]['hidingNonce'], $commits[$i]['bindingNonce']),
                        $message, $cs, ['threshold' => $thr, 'verificationShare' => $p['publicKey'], 'verificationShares' => $vs]);
                }
                $agg = Frost::aggregate($message, $cs, $shares, $kg['groupPublicKey'], $thr, $vs);
                $out = self::keygenJson($kg);
                $out->set('commitments', array_map(self::commitJson(...), $cs));
                $out->set('sigShares', array_map(static fn(array $s) => Obj::of(['identifier' => new Num((string)$s['identifier']), 'sigShare' => self::b($s['sigShare'])]), $shares));
                $out->set('aggregate', self::b($agg));
                return $out;
            },
            'sign' => function (array $a): Obj {
                $nonces = null;
                if (($a[3] ?? null) !== null) {
                    $n = self::obj($a[3]);
                    $nonces = new FrostNonces(self::bytes($n->get('hiding')), self::bytes($n->get('binding')));
                }
                $r = Frost::sign(self::idInt($a[0]), self::bytes($a[1]), self::bytes($a[2]), $nonces, self::bytes($a[4] ?? null), self::commitments($a[5] ?? null), self::opts($a[6] ?? null));
                return Obj::of(['identifier' => new Num((string)$r['identifier']), 'sigShare' => self::b($r['sigShare'])]);
            },
            'aggregate' => function (array $a): Obj {
                $o = $a[4] ?? null;
                $thr = $o instanceof Obj ? $o->get('threshold') : null;
                return self::b(Frost::aggregate(self::bytes($a[0]), self::commitments($a[1]), self::sigShares($a[2]), self::bytes($a[3] ?? null), $thr,
                    self::vss($o instanceof Obj ? $o->get('verificationShares') : null)));
            },
            'verifySigShare' => function (array $a): bool {
                try {
                    $p = self::obj($a[0]);
                    $share = self::obj($p->get('sigShare'));
                    return Frost::verifySigShare(self::idInt($p->get('identifier')), self::bytes($p->get('publicKey')), self::commitment($p->get('commitment')),
                        ['identifier' => self::idInt($share->get('identifier')), 'sigShare' => self::bytes($share->get('sigShare'))],
                        self::commitments($p->get('signingCommitments')), self::bytes($p->get('groupPublicKey')), self::bytes($p->get('message')));
                } catch (\Throwable) {
                    return false;
                }
            },
            'cosign' => function (array $a): bool {
                $o = $a[3] ?? null;
                Frost::cosign(self::bytes($a[0]), array_map(self::participant(...), self::list($a[1])), self::bytes($a[2]), $o instanceof Obj ? $o->get('threshold') : null);
                return true;
            },
        ];
        $wrapped = array_map(static fn(callable $f): \Closure => static function (mixed $a, Obj $c) use ($f) {
            $have = $f(self::restore($a), $c);
            return self::mask($have, $c->get('out'));
        }, $map);
        Base::run($file, $fn, $k, $wrapped);
    }

    public function testBaseAndIdentity(): void
    {
        $this->assertSame("\x58" . str_repeat("\x66", 31), Frost::mulBase("\x01" . str_repeat("\0", 31)));
        $this->assertSame("\x01" . str_repeat("\0", 31), Frost::mulBase(str_repeat("\0", 32)));
        $k = Frost::trustedDealerKeygen(1, 1, "\x01");
        $this->assertSame("\x58" . str_repeat("\x66", 31), $k['groupPublicKey']);
    }
}
