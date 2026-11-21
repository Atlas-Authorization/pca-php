<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\K3Sig;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Js;
use Atlas\Pca\Sandbox;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The sandbox policy logic (policy compile, OS profiles, runtime claims, receipt chain, handle table, egress policy, address rule, tool builders) against the TS reference: test-data/ref-sandbox.json.gz. */
final class RefSandboxDifferentialTest extends TestCase
{
    private const FILE = 'ref-sandbox.json.gz';

    /** These vectors predate the parsed-address rule: they read these spellings as public. The native rule, like the current reference, refuses all of them. */
    private const STRICTER_PRIVATE = ['0:0:0:0:0:0:0:1', '0:0:0:0:0:0:0:0', '::ffff:7f00:1', '::ffff:0:0', '::1%eth0', '::127.0.0.1', '::ffff:1.2.3.4%x',
        '::2', 'fec0::1', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:1.2.3.4', 'f::'];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    private static function pub(string $seed): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    }

    private static function res(mixed $allow, mixed $bind): Obj
    {
        $r = Obj::of(['allow' => $allow]);
        if (\Atlas\Pca\Jsx::truthy($bind)) {
            $id = $bind->get('id');
            $r->set('operation', Obj::of(['verb' => $bind->get('verb'), 'resource' => $bind->get('resource'),
                'params_digest' => Pca::hashCanonical($bind->get('params')), 'id' => $id !== null ? $id : 'op']));
        }
        return $r;
    }

    private static function receiptLog(Obj $spec): array
    {
        $t = new Num('0');
        $log = new SandboxReceiptLog(static function () use (&$t) {
            return $t;
        }, $spec->get('sign') === true ? static fn(string $d): string => 'sig:' . $d : null);
        $outs = [];
        foreach ($spec->get('appends') as $a) {
            $t = $a->get('t');
            try {
                $outs[] = $log->append($a->get('rc'), $a->get('body'));
            } catch (\Throwable) {
                $outs[] = Obj::of(['$err' => true]);
            }
        }
        return $outs;
    }

    private static function compile(Obj $spec): Obj
    {
        $items = [];
        foreach ($spec->get('items') as $it) {
            $items[] = Obj::of(['result' => self::res($it->get('allow'), $it->get('bind')), 'operation' => $it->get('operation')]);
        }
        $needs = $spec->get('needs');
        return Sandbox::compilePolicy($items, static fn($op) => $needs->get($op->get('verb') . ' ' . $op->get('resource')), $spec->get('proxyPort'));
    }

    private static function egress(Obj $spec): array
    {
        $t = new Num('0');
        $p = new SandboxEgressPolicy(static function () use (&$t) {
            return $t;
        });
        $outs = [];
        foreach ($spec->get('steps') as $st) {
            try {
                if ($st->get('op') === 'now') {
                    $t = $st->get('t');
                    $outs[] = null;
                } elseif ($st->get('op') === 'admit') {
                    $tpl = $st->get('template');
                    $p->admit(self::res($st->get('allow'), $st->get('bind')), $st->get('operation'), static fn($op) => $tpl, $st->get('opts') ?? new Obj());
                    $outs[] = 'ok';
                } else {
                    $r = $st->get('req');
                    $req = Obj::of(['method' => $r->get('method')]);
                    foreach (['url', 'body'] as $k) {
                        if ($r->has($k)) {
                            $req->set($k, $k === 'body' ? Base::bytes($r->get($k)) : $r->get($k));
                        }
                    }
                    $outs[] = $p->claim($req);
                }
            } catch (\Throwable) {
                $outs[] = Obj::of(['$err' => true]);
            }
        }
        return $outs;
    }

    private static function handles(Obj $spec): Obj
    {
        $t = new Num('0');
        $now = static function () use (&$t) {
            return $t;
        };
        $log = new SandboxReceiptLog($now);
        $exec = [
            'fs.read' => static fn($op) => new Bytes("\x01\x02\x03"),
            'fs.echo' => static fn($op) => new Bytes(Js::stringify($op)),
            'fs.throw' => static function ($op) {
                throw new \RuntimeException('boom');
            },
            'fs.notbytes' => static fn($op) => 'nope',
        ];
        $table = new SandboxHandleTable($spec->get('cls'), $log, $exec, $now);
        $outs = [];
        foreach ($spec->get('steps') as $st) {
            try {
                switch ($st->get('op')) {
                    case 'now':
                        $t = $st->get('t');
                        $outs[] = null;
                        break;
                    case 'mint':
                        if ($st->has('bind')) {
                            $bind = $st->get('bind');
                        } else {
                            $bind = new Obj();
                            foreach ($st->get('operation')->keys() as $k) {
                                $bind->set($k, $st->get('operation')->get($k));
                            }
                            $bind->set('id', $st->has('id') ? $st->get('id') : 'op-h');
                        }
                        $outs[] = $table->mint(self::res($st->has('allow') ? $st->get('allow') : true, $bind), $st->get('operation'), $st->get('opts') ?? new Obj());
                        break;
                    case 'attenuate':
                        $outs[] = $table->attenuate($st->get('index'), $st->get('narrower') ?? new Obj());
                        break;
                    case 'revoke':
                        $table->revoke($st->get('index'));
                        $outs[] = null;
                        break;
                    case 'use':
                        $r = $table->use($st->get('index'));
                        if ($r->get('result') instanceof Bytes) {
                            $r->set('result', Base::outBytes($r->get('result')->raw));
                        }
                        $outs[] = $r;
                        break;
                    case 'verbOf':
                        $outs[] = $table->verbOf($st->get('index'));
                        break;
                    case 'size':
                        $outs[] = $table->size();
                        break;
                }
            } catch (\Throwable) {
                $outs[] = Obj::of(['$err' => true]);
            }
        }
        return Obj::of(['outs' => $outs, 'log' => $log->entries]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'moduleConsts' => fn(array $a) => Sandbox::moduleConsts(),
            'satisfiesRuntimeClass' => fn(array $a) => Sandbox::satisfiesRuntimeClass(...$a),
            'receiptLog' => fn(array $a) => self::receiptLog($a[0]),
            'verifyReceiptChain' => fn(array $a) => Sandbox::verifyReceiptChain($a[0], ($a[1] ?? null) === 'tag' ? static fn($d, $s) => $s === 'sig:' . $d : null),
            'policyFromNeeds' => fn(array $a) => Sandbox::policyFromNeeds($a[0], $a[1] ?? null),
            'compilePolicy' => fn(array $a) => self::compile($a[0]),
            'seccompProfile' => fn(array $a) => Sandbox::seccompProfile($a[0]),
            'landlockRuleset' => fn(array $a) => Sandbox::landlockRuleset($a[0]),
            'macosProfile' => fn(array $a) => Sandbox::macosProfile($a[0]),
            'confineArgs' => fn(array $a) => Sandbox::confineArgs($a[0]),
            'isPrivateAddress' => function (array $a, Obj $c) {
                $r = Sandbox::isPrivateAddress($a[0]);
                if (!is_string($a[0])) {
                    return $c->get('out') instanceof Obj ? [Base::SKIP, 'a non-string is refused (stricter than the throw)'] : $r;
                }
                // the vectors predate the parsed-address rule: these spellings read as public there
                return ($r === true && $c->get('out') === false && in_array($a[0], self::STRICTER_PRIVATE, true)) ? false : $r;
            },
            'egress' => fn(array $a) => self::egress($a[0]),
            'handles' => fn(array $a) => self::handles($a[0]),
            'signRuntimeClaim' => function (array $a) {
                $sk = is_string($a[0]) ? self::seed($a[0]) : pack('C*', ...array_map(static fn($n) => (int)K3Sig::num($n), $a[0]->get('short')));
                return Sandbox::signRuntimeClaim($sk, self::pub(self::seed(is_string($a[1]) ? $a[1] : 'x')), $a[2]);
            },
            'verifiedRuntimeClass' => fn(array $a) => Sandbox::verifiedRuntimeClass(...$a),
            'passportDigest' => fn(array $a) => Sandbox::passportDigest(...$a),
            'evidenceDigest' => fn(array $a) => Sandbox::evidenceDigest(...$a),
            'buildTool' => fn(array $a) => Base::outBytes(Sandbox::buildTool($a[0])),
            'buildProbeTool' => fn(array $a) => Base::outBytes(isset($a[0]) ? Sandbox::buildProbeTool((int)K3Sig::num($a[0])) : Sandbox::buildProbeTool()),
            'referenceComponentWat' => fn(array $a) => Sandbox::referenceComponentWat($a[0] ?? null),
        ]);
    }

    public function testParsedAddressRuleRefusesEveryReferenceMiss(): void
    {
        foreach (self::STRICTER_PRIVATE as $ip) {
            $this->assertTrue(Sandbox::isPrivateAddress($ip), $ip);
        }
        foreach (['0::1', '::FFFF:7F00:0001', '::7f00:1', '64:ff9b::7f00:1', '64:ff9b::10.0.0.1', 'fe80::1%25eth0', '2606:4700::1111%eth0', 'FE80::1', 'fc::1',
            '1fff::1', '4000::1', '1::2::3', '::00001', '::01.2.3.4', '[::1]', ' ::1', null, 1] as $ip) {
            $this->assertTrue(Sandbox::isPrivateAddress($ip), var_export($ip, true));
        }
        foreach (['2606:4700:0:0:0:0:0:1111', '2001:DB8::1', '::ffff:808:808', '::ffff:8.8.8.8', '64:ff9b::8.8.8.8', '2000::', '3fff::1', '8.8.8.8'] as $ip) {
            $this->assertFalse(Sandbox::isPrivateAddress($ip), $ip);
        }
    }
}
