<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3.php';

use Atlas\Pca\Json;
use Atlas\Pca\K3;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for K3 (bundles, log batches, list receipts/cursors, authority algebra, amendments, need approvals). */
final class K05KillK3Test extends TestCase
{
    /** @return array{0: string, 1: string} [public b64u, secret] */
    private static function key(int $seed): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr($seed), 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $sk, string $domain, mixed $body): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($domain . Json::canonicalizeStrict($body), $sk));
    }

    private static function n(string $l): Num
    {
        return new Num($l);
    }

    /** nest(0) = [], nest(k) = [nest(k-1)] */
    private static function nest(int $k): array
    {
        return $k === 0 ? [] : [self::nest($k - 1)];
    }

    private static function bundle(array $over = []): Obj
    {
        return Obj::of(array_merge([
            'v' => self::n('1'), 'kind' => 'pca-policy-bundle', 'revision' => self::n('1'), 'issued_at' => self::n('100'),
            'grants' => ['g'], 'template_digests' => [], 'min_verifier_version' => '1.0',
        ], $over));
    }

    public function testCompareVersion(): void
    {
        $this->assertSame(0, K3::compareVersion('1', '1.0'));
        $this->assertSame(0, K3::compareVersion('1.2', '1.2'));
        $this->assertSame(-1, K3::compareVersion('1', '2'));
        $this->assertSame(1, K3::compareVersion('2', '1'));
        $this->assertSame(1, K3::compareVersion('1.x', '1'));
        // bundle.ts split('.').map(Number): every JS number form reads as JS reads it
        $this->assertSame(0, K3::compareVersion('0x10', '16'));
        $this->assertSame(0, K3::compareVersion('1e3', '1000'));
        $this->assertSame(0, K3::compareVersion(' 1', '+1'));
        $this->assertSame(0, K3::compareVersion('1.', '1.0'));
        $this->assertSame(1, K3::compareVersion('1_0', '1')); // NaN compares as greater
    }

    public function testBundleShapeError(): void
    {
        $this->assertNull(K3::bundleShapeError(self::bundle()));
        $this->assertSame('bad revision or time', K3::bundleShapeError(self::bundle(['revision' => self::n('0')])));
        $prevMsg = 'prev must be absent at revision 1 and present after';
        $this->assertNull(K3::bundleShapeError(self::bundle(['revision' => self::n('2'), 'prev' => str_repeat('p', 128)])));
        $this->assertSame($prevMsg, K3::bundleShapeError(self::bundle(['revision' => self::n('2'), 'prev' => str_repeat('p', 129)])));
        $this->assertSame('bad grants', K3::bundleShapeError(self::bundle(['grants' => 'x'])));
        $this->assertSame('bad grants', K3::bundleShapeError(self::bundle(['grants' => ['']])));
        $this->assertNull(K3::bundleShapeError(self::bundle(['grants' => array_fill(0, 4096, 'g')])));
        $this->assertSame('bad grants', K3::bundleShapeError(self::bundle(['grants' => array_fill(0, 4097, 'g')])));
        $this->assertNull(K3::bundleShapeError(self::bundle(['grants' => [str_repeat('g', 128)]])));
        $this->assertSame('bad grants', K3::bundleShapeError(self::bundle(['grants' => [str_repeat('g', 129)]])));
        $this->assertSame('bad template_digests', K3::bundleShapeError(self::bundle(['template_digests' => 'x'])));
        $this->assertSame('bad schema_digest', K3::bundleShapeError(self::bundle(['schema_digest' => ''])));
        $this->assertNull(K3::bundleShapeError(self::bundle(['constitution_digest' => str_repeat('c', 128)])));
        $this->assertSame('bad constitution_digest', K3::bundleShapeError(self::bundle(['constitution_digest' => str_repeat('c', 129)])));
    }

    public function testVerifyBundle(): void
    {
        [$pk, $sk] = self::key(3);
        $opts = Obj::of(['signers' => [$pk], 'threshold' => self::n('1'), 'verifierVersion' => '1.0']);
        $signed = static function (Obj $b) use ($pk, $sk): Obj {
            $b->set('sigs', [Obj::of(['signer' => $pk, 'sig' => self::sign($sk, K3::BUNDLE_DOMAIN, $b)])]);
            return $b;
        };
        $b = $signed(self::bundle());
        $digest = K3::bundleDigest($b);
        $this->assertIsString($digest);
        $this->assertSame(['ok' => true, 'revision' => 1, 'digest' => $digest, 'signers' => [$pk]], K3::verifyBundle($b, $opts));

        $malformed = ['ok' => false, 'code' => 'malformed', 'reason' => 'bad sigs or threshold'];
        $this->assertSame(['ok' => false, 'code' => 'below_threshold', 'reason' => '0 valid pinned signature(s), need 1'],
            K3::verifyBundle(self::bundle(['sigs' => array_fill(0, 64, null)]), $opts));
        $this->assertSame($malformed, K3::verifyBundle(self::bundle(['sigs' => array_fill(0, 65, null)]), $opts));
        $this->assertSame($malformed, K3::verifyBundle($b, Obj::of(['signers' => [$pk], 'threshold' => self::n('1.5'), 'verifierVersion' => '1.0'])));

        // a validly signed body that is too deep to digest (the reference's bundleDigest throws) is malformed, never ok
        $deep = $signed(self::bundle(['x' => self::nest(30)]));
        $this->assertSame($malformed, K3::verifyBundle($deep, $opts));
    }

    public function testBatchReasonRendering(): void
    {
        $state = Obj::of(['next' => self::n('1')]);
        $r = static fn(Obj $b): array => K3::verifyBatch($b, $state, null);
        $gap = static fn(string $s): array => ['ok' => false, 'reason' => "gap or replay: batch starts at $s, expected 1"];
        $this->assertSame($gap('x'), $r(Obj::of(['from' => 'x'])));
        $this->assertSame($gap('null'), $r(Obj::of(['from' => null])));
        $this->assertSame($gap('true'), $r(Obj::of(['from' => true])));
        $this->assertSame($gap('false'), $r(Obj::of(['from' => false])));
        $this->assertSame($gap('[object Object]'), $r(Obj::of(['from' => new Obj()])));
        $this->assertSame($gap('0'), $r(Obj::of(['from' => self::n('-0')])));
        $this->assertSame($gap('1.5'), $r(Obj::of(['from' => self::n('1.5')])));
        $this->assertSame($gap('undefined'), $r(new Obj()));
    }

    public function testVerifyBatch(): void
    {
        [$pk, $sk] = self::key(4);
        $head = static function (string $size, string $lc) use ($pk, $sk): Obj {
            $h = Obj::of(['v' => self::n('1'), 'signer' => $pk, 'size' => self::n($size), 'issued_at' => self::n('1'), 'root' => 'r', 'last_commit' => $lc]);
            $h->set('sig', self::sign($sk, K3::LOG_HEAD_DOMAIN, $h));
            return $h;
        };
        $state = Obj::of(['next' => self::n('0'), 'lastCommit' => 'L0']);
        $rec = Obj::of(['seq' => self::n('0'), 'prev' => 'L0']);
        $commit = K3::recordCommit($rec);
        $this->assertIsString($commit);
        $batch = static fn(Obj $h, mixed $recs): Obj => Obj::of(['from' => self::n('0'), 'head' => $h, 'records' => $recs]);
        $mal = ['ok' => false, 'reason' => 'malformed batch'];
        $h1 = $head('1', $commit);

        $this->assertSame(['ok' => true, 'next' => 1, 'lastCommit' => $commit], K3::verifyBatch($batch($h1, [$rec]), $state, $pk));
        $this->assertSame($mal, K3::verifyBatch($batch($h1, 'x'), $state, $pk));
        $this->assertSame($mal, K3::verifyBatch($batch($h1, [null]), $state, $pk));
        $this->assertSame(['ok' => false, 'reason' => 'chain broken at seq undefined'], K3::verifyBatch($batch($h1, ['x']), $state, $pk));
        $this->assertSame(['ok' => false, 'reason' => 'chain broken at seq 5'],
            K3::verifyBatch($batch($h1, [Obj::of(['seq' => self::n('5'), 'prev' => 'L0'])]), $state, $pk));
        $this->assertSame($mal, K3::verifyBatch($batch($h1, [Obj::of(['seq' => self::n('0'), 'prev' => 'L0', 'bad' => self::n('1e2')])]), $state, $pk));
        $this->assertSame(['ok' => false, 'reason' => 'batch is longer than the signed head'], K3::verifyBatch($batch($head('0', $commit), [$rec]), $state, $pk));
        $this->assertSame(['ok' => false, 'reason' => 'batch end does not match the signed head'], K3::verifyBatch($batch($head('1', 'wrong'), [$rec]), $state, $pk));
        // no records: the state's (non-string) last commit is reported as a string
        $this->assertSame(['ok' => true, 'next' => 0, 'lastCommit' => ''],
            K3::verifyBatch($batch($h1, []), Obj::of(['next' => self::n('0'), 'lastCommit' => null]), $pk));
    }

    public function testListReceipt(): void
    {
        [$pk, $sk] = self::key(5);
        $objs = ['a', 'b'];
        $mk = static function (string $count) use ($pk, $sk, $objs): Obj {
            $r = Obj::of(['v' => self::n('1'), 'signer' => $pk, 'subject' => 's', 'resource_type' => 't', 'count' => self::n($count),
                'issued_at' => self::n('1'), 'objects_digest' => K3::objectsDigest($objs)]);
            $r->set('sig', self::sign($sk, K3::LIST_RECEIPT_DOMAIN, $r));
            return $r;
        };
        $this->assertTrue(K3::verifyListReceipt($mk('2'), $pk));
        $this->assertTrue(K3::verifyListReceipt($mk('2'), $pk, $objs, true));
        $this->assertFalse(K3::verifyListReceipt($mk('3'), $pk, $objs, true));
        $this->assertIsString(K3::listBind(Obj::of(['subject' => 's', 'resourceType' => 't', 'filterId' => 'f', 'policyDigest' => 'p', 'limit' => self::n('5')])));
    }

    public function testListCursor(): void
    {
        [$pk, $sk] = self::key(6);
        $tok = static function (array $f, bool $signIt = true) use ($pk, $sk): string {
            $c = Obj::of($f);
            return Pca::b64u(Json::canonicalizeStrict($c)) . '.' . ($signIt ? self::sign($sk, K3::LIST_CURSOR_DOMAIN, $c) : 'AAAA');
        };
        $base = ['v' => self::n('1'), 'bind' => 'b', 'skip' => self::n('2'), 'signer' => $pk];
        $this->assertSame(['ok' => true, 'skip' => 2], K3::verifyListCursor($tok($base), $pk));
        $this->assertSame(['ok' => true, 'skip' => 2, 'inner' => 'i'], K3::verifyListCursor($tok($base + ['inner' => 'i']), $pk));

        $bad = ['ok' => false, 'reason' => 'malformed'];
        $this->assertSame($bad, K3::verifyListCursor($tok(['skip' => self::n('-1')] + $base, false), $pk));
        $this->assertSame($bad, K3::verifyListCursor($tok(['bind' => self::n('5')] + $base, false), $pk));
        $this->assertSame($bad, K3::verifyListCursor($tok(['v' => self::n('2')] + $base, false), $pk));
        $this->assertSame($bad, K3::verifyListCursor($tok($base + ['inner' => self::n('5')], false), $pk));
        $this->assertSame($bad, K3::verifyListCursor(Pca::b64u(Json::canonicalizeStrict(Obj::of($base))), $pk));
        $this->assertSame($bad, K3::verifyListCursor($tok($base) . '.z', $pk));
        $this->assertSame($bad, K3::verifyListCursor(Pca::b64u('{') . '.x', $pk));
        $this->assertSame(['ok' => false, 'reason' => 'signature'], K3::verifyListCursor($tok($base, false), $pk));
    }

    public function testAuthorityOk(): void
    {
        $a = static fn(array $over): Obj => Obj::of(array_merge(['verbs' => ['r'], 'resources' => ['x']], $over));
        $this->assertTrue(K3::authorityOk($a([])));
        $this->assertFalse(K3::authorityOk(null));
        $this->assertTrue(K3::authorityOk($a(['verbs' => array_fill(0, 256, 'v')])));
        $this->assertFalse(K3::authorityOk($a(['verbs' => array_fill(0, 257, 'v')])));
        $this->assertTrue(K3::authorityOk($a(['verbs' => [str_repeat('v', 128)]])));
        $this->assertFalse(K3::authorityOk($a(['verbs' => [str_repeat('v', 129)]])));
        $this->assertTrue(K3::authorityOk($a(['resources' => array_fill(0, 1024, 'x')])));
        $this->assertFalse(K3::authorityOk($a(['resources' => array_fill(0, 1025, 'x')])));
        $this->assertTrue(K3::authorityOk($a(['resources' => [str_repeat('x', 512)]])));
        $this->assertFalse(K3::authorityOk($a(['resources' => [str_repeat('x', 513)]])));
        $this->assertFalse(K3::authorityOk($a(['verbs' => 'x'])));
        $this->assertFalse(K3::authorityOk($a(['verbs' => ['']])));
        $this->assertFalse(K3::authorityOk($a(['limits' => self::n('5')])));
        $this->assertFalse(K3::authorityOk($a(['limits' => Obj::of(['a' => self::n('-1')])])));
        $this->assertTrue(K3::authorityOk($a(['limits' => Obj::of(['a' => self::n('0')])])));
        $this->assertFalse(K3::authorityOk($a(['limits' => Obj::of(['a' => 'q'])])));
        $this->assertFalse(K3::authorityOk($a(['expires_at' => self::n('-1')])));
        $this->assertTrue(K3::authorityOk($a(['expires_at' => self::n('5')])));
    }

    public function testAuthorityDigest(): void
    {
        $d = static fn(array $a): ?string => K3::authorityDigest(Obj::of($a));
        $this->assertSame($d(['verbs' => ['a', 'b'], 'resources' => ['x', 'y']]), $d(['verbs' => ['b', 'a'], 'resources' => ['y', 'x']]));
        $this->assertNotNull($d(['verbs' => 'x', 'resources' => []]));
        $this->assertNotSame($d(['verbs' => ['a'], 'resources' => ['x'], 'extra' => ['a', 'b']]), $d(['verbs' => ['a'], 'resources' => ['x'], 'extra' => ['b', 'a']]));
    }

    public function testCompareAuthority(): void
    {
        $a = static fn(array $res, array $over = []): Obj => Obj::of(array_merge(['verbs' => ['r'], 'resources' => $res], $over));
        $this->assertSame('equal', K3::compareAuthority($a(['x']), $a(['x'])));
        $this->assertSame('incomparable', K3::compareAuthority($a(['ab*']), $a(['ac'])));
        // a non-object `limits` reads as no limits
        $this->assertSame('equal', K3::compareAuthority($a(['x'], ['limits' => self::n('5')]), $a(['x'], ['limits' => self::n('5')])));
    }

    public function testMergeAuthority(): void
    {
        $m = K3::mergeAuthority(Obj::of(['verbs' => ['a', 'b'], 'resources' => ['x']]), Obj::of(['verbs' => ['a', 'c'], 'resources' => ['x', 'y']]));
        $this->assertSame(['a', 'b', 'c'], $m->get('verbs'));
        $this->assertSame(['x', 'y'], $m->get('resources'));
        $this->assertFalse($m->has('limits'));
        $this->assertFalse($m->has('expires_at'));

        $five = self::n('5');
        $m = K3::mergeAuthority(Obj::of(['verbs' => [], 'resources' => [], 'limits' => Obj::of(['x' => $five]), 'expires_at' => $five]),
            Obj::of(['verbs' => [], 'resources' => [], 'limits' => Obj::of(['x' => 5]), 'expires_at' => 5]));
        $this->assertSame($five, $m->get('limits')->get('x'));
        $this->assertSame($five, $m->get('expires_at'));

        $one = self::n('1');
        $m = K3::mergeAuthority(Obj::of(['verbs' => [], 'resources' => [], 'limits' => Obj::of(['x' => $one])]), Obj::of(['verbs' => [], 'resources' => []]));
        $this->assertSame($one, $m->get('limits')->get('x'));
    }

    public function testVerifyAmendment(): void
    {
        [$pk, $sk] = self::key(7);
        $auth = Obj::of(['verbs' => ['r'], 'resources' => ['x']]);
        $cur = Obj::of(['status' => 'active', 'authority' => $auth, 'id' => 'g', 'rev' => self::n('1'), 'principal' => $pk, 'agent' => $pk]);
        $req = static fn(array $over): Obj => Obj::of(array_merge(['action' => 'replace', 'authority' => $auth, 'sig' => 'x', 'signed_by' => 'holder'], $over));
        $this->assertSame(['ok' => false, 'code' => 'bad_signature'], K3::verifyAmendment($cur, $req([]), true));
        $this->assertSame(['ok' => false, 'code' => 'signature_required'], K3::verifyAmendment($cur, $req(['signed_by' => 'bogus']), true));
        $this->assertSame(['ok' => false, 'code' => 'signature_required'], K3::verifyAmendment($cur, $req(['sig' => self::n('5')]), true));
        $broken = Obj::of(['status' => 'active', 'authority' => null, 'id' => 'g', 'rev' => self::n('1'), 'principal' => $pk, 'agent' => $pk]);
        $this->assertSame(['ok' => false, 'code' => 'bad_request'], K3::verifyAmendment($broken, $req([]), true));

        // an authority too deep to digest never yields a message binding `authority: null` (the reference throws: bad_request)
        $deep = Obj::of(['verbs' => ['r'], 'resources' => ['x'], 'extra' => self::nest(30)]);
        $this->assertNull(K3::authorityDigest($deep));
        $sig = self::sign($sk, K3::GRANT_AMEND_DOMAIN, Obj::of(['grant' => 'g', 'rev' => self::n('1'), 'action' => 'replace', 'authority' => null]));
        $this->assertSame(['ok' => false, 'code' => 'bad_request'], K3::verifyAmendment($cur, $req(['authority' => $deep, 'sig' => $sig]), true));
    }

    public function testVerifyNeedApproval(): void
    {
        [$pk, $sk] = self::key(8);
        $grantAuth = Obj::of(['verbs' => ['v0'], 'resources' => ['r0'], 'limits' => Obj::of(['x' => self::n('1')])]);
        $run = static function (mixed $needs, mixed $approved, mixed $gAuth = null) use ($pk, $sk, $grantAuth): array {
            $nr = Obj::of(['status' => 'pending', 'id' => 'n', 'grant_id' => 'g', 'needs' => $needs]);
            $g = Obj::of(['rev' => self::n('1'), 'principal' => $pk, 'authority' => $gAuth === false ? null : ($gAuth ?? $grantAuth)]);
            $sig = self::sign($sk, K3::NEED_APPROVE_DOMAIN, Obj::of(['need' => 'n', 'grant' => 'g', 'rev' => self::n('1'), 'approved' => $approved]));
            return K3::verifyNeedApproval($nr, $g, $approved, $sig, true);
        };
        $vr = static fn(string $v, string $r, ?array $lim = null): Obj => Obj::of(array_merge(['verb' => $v, 'resource' => $r], $lim === null ? [] : ['limits' => Obj::of($lim)]));
        $lowered = ['ok' => false, 'code' => 'need_not_lowered_only'];

        $ok = $run([$vr('v', 'r')], [$vr('v', 'r')]);
        $this->assertTrue($ok['ok']);
        $this->assertSame(['v0', 'v'], $ok['authority']->get('verbs'));
        $this->assertSame(['r0', 'r'], $ok['authority']->get('resources'));

        $this->assertSame($lowered, $run([], Obj::of(['a' => 'b'])));
        $this->assertSame($lowered, $run([$vr('v', 'r')], ['x']));
        $this->assertSame($lowered, $run(['x'], [$vr('v', 'r')]));
        $this->assertSame($lowered, $run([$vr('w', 'r')], [$vr('v', 'r')]));
        $five = self::n('5');
        $this->assertSame($lowered, $run([Obj::of(['verb' => $five, 'resource' => 'r'])], [Obj::of(['verb' => $five, 'resource' => 'r'])]));
        $this->assertSame($lowered, $run([$vr('v', 'r')], [$vr('v', 'r', ['x' => self::n('5')])]));
        $this->assertSame($lowered, $run([$vr('v', 'r', ['x' => self::n('5')])], [$vr('v', 'r', ['x' => 'q'])]));

        $eq = $run([$vr('v', 'r', ['x' => self::n('5')])], [$vr('v', 'r', ['x' => self::n('5')])]);
        $this->assertTrue($eq['ok']);
        $this->assertSame('5', $eq['authority']->get('limits')->get('x')->lexeme);

        $max = $run([$vr('v', 'r', ['x' => self::n('7')]), $vr('w', 's', ['x' => self::n('3')])], [$vr('v', 'r', ['x' => self::n('7')]), $vr('w', 's', ['x' => self::n('3')])]);
        $this->assertTrue($max['ok']);
        $this->assertSame('7', $max['authority']->get('limits')->get('x')->lexeme);

        $tie = $run([$vr('v', 'r', ['x' => self::n('5')]), $vr('w', 's', ['x' => self::n('5')])], [$vr('v', 'r', ['x' => self::n('5')]), $vr('w', 's', ['x' => self::n('05')])]);
        $this->assertTrue($tie['ok']);
        $this->assertSame('5', $tie['authority']->get('limits')->get('x')->lexeme);

        $this->assertSame(['ok' => false, 'code' => 'bad_request'], $run([], [], false));
        $this->assertSame(['ok' => false, 'code' => 'bad_request'], K3::verifyNeedApproval(Obj::of(['status' => 'done']), null, [], 'x', true));
    }

    public function testRunRejectsUnknownPrimitive(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        K3::run('nope', new Obj());
    }

    /** A non-Obj object that answers get/has like one (from a fixed map). */
    private static function fake(array $m): object
    {
        return new class($m) {
            public function __construct(private array $m)
            {
            }

            public function get(string $k): mixed
            {
                return $this->m[$k] ?? null;
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->m);
            }

            public function without(string $k): string
            {
                return 'x';
            }
        };
    }

    public function testNonObjInputsAreRefusedEvenWhenTheyQuackLikeObj(): void
    {
        $this->assertNull(K3::bundleDigest(self::fake([])));

        $mal = ['ok' => false, 'reason' => 'malformed batch'];
        $this->assertSame($mal, K3::verifyBatch(Obj::of(['from' => self::n('0')]), self::fake(['next' => self::n('1')]), null));
        $this->assertSame($mal, K3::verifyBatch(self::fake(['from' => self::n('0')]), Obj::of(['next' => self::n('1')]), null));

        $auth = Obj::of(['verbs' => ['r'], 'resources' => ['x']]);
        $bad = ['ok' => false, 'code' => 'bad_request'];
        $this->assertSame($bad, K3::verifyAmendment(Obj::of(['status' => 'paused']), self::fake(['action' => 'replace', 'authority' => $auth]), true));
        $this->assertSame($bad, K3::verifyAmendment(self::fake(['status' => 'paused']), Obj::of(['action' => 'replace', 'authority' => $auth]), true));

        $this->assertSame($bad, K3::verifyNeedApproval(self::fake(['status' => 'done']), Obj::of(['rev' => self::n('1')]), [], 'x', true));
    }

    public function testBatchWithAnObjectLastCommitIsMalformed(): void
    {
        [$pk, $sk] = self::key(4);
        $h = Obj::of(['v' => self::n('1'), 'signer' => $pk, 'size' => self::n('1'), 'issued_at' => self::n('1'), 'root' => 'r', 'last_commit' => 'L']);
        $h->set('sig', self::sign($sk, K3::LOG_HEAD_DOMAIN, $h));
        $batch = Obj::of(['from' => self::n('0'), 'head' => $h, 'records' => []]);
        $this->assertTrue(K3::verifyBatch($batch, Obj::of(['next' => self::n('0'), 'lastCommit' => 'L0']), $pk)['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'malformed batch'],
            K3::verifyBatch($batch, Obj::of(['next' => self::n('0'), 'lastCommit' => new Obj()]), $pk));
    }

    public function testRecordInclusionErrorIsFalse(): void
    {
        $called = false;
        K3::$testHook = static function () use (&$called): void {
            $called = true;
            throw new \RuntimeException('boom');
        };
        try {
            $this->assertFalse(K3::verifyRecordInclusion(new Obj(), null, null, null));
        } finally {
            K3::$testHook = null;
        }
        $this->assertTrue($called, 'the error path is the hook, not the empty record');
    }

    public function testToJsonKeysAreStrings(): void
    {
        $o = (new \ReflectionMethod(K3::class, 'toJson'))->invoke(null, [5 => 'a', 'n' => 7]);
        $this->assertSame(['5', 'n'], $o->keys());
        $this->assertSame('a', $o->get('5'));
        $this->assertSame('7', $o->get('n')->lexeme);
    }
}
