<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\MpcNetCrashParty;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetPartyMain;
use Atlas\Pca\MpcNetProtocol;
use Atlas\Pca\MpcNetSilentParty;
use PHPUnit\Framework\TestCase;

/** The exit seam's stand-in: carries the code the process would have exited with. */
final class Kill17bExit extends \RuntimeException
{
    public function __construct(public readonly int $exitCode)
    {
        parent::__construct("exit($exitCode)");
    }
}

/** A mesh that records what main() asks of it (no sockets): listen, setPeerPort, connect, close. */
final class Kill17bMesh extends MpcNetMesh
{
    /** @var list<array<int,mixed>> */
    public array $log = [];
    public ?\Throwable $connectError = null;
    public ?MpcNetAbort $failure = null;

    /** @param array<string,mixed> $mc */
    public function __construct(public array $mc)
    {
        $self = (int) $mc['selfId'];
        \Closure::bind(function () use ($self): void {
            $this->selfId = $self;
        }, $this, MpcNetMesh::class)();
        $this->events = ['ev-1'];
    }

    public function __destruct()
    {
    }

    public function listen(): int
    {
        $this->log[] = ['listen'];
        return 4242;
    }

    public function setPeerPort(int $id, int $port): void
    {
        $this->log[] = ['port', $id, $port];
    }

    public function connect(): void
    {
        $this->log[] = ['connect'];
        if ($this->connectError !== null) {
            throw $this->connectError;
        }
    }

    public function failed(): ?MpcNetAbort
    {
        return $this->failure;
    }

    public function stats(): array
    {
        return [['peer' => 0, 'framesIn' => 2]];
    }

    public function close(): void
    {
        $this->log[] = ['close'];
    }
}

/**
 * Mutation kills for the node's CLI entry point, driven in-process through its seams: argv handling and usage texts, the config
 * reader, the test-hook refusal, the mesh config, bind-first port exchange over stdin, what each role is run with and reports,
 * the abort report, the crash exit and the silent party's bounded wait.
 */
final class ProtoSurvivorKill17bMpcNetPartyMainTest extends TestCase
{
    /** @var list<array{0:int,1:string}> */
    private array $writes = [];
    private ?Kill17bMesh $mesh = null;
    /** @var list<array<int,mixed>> */
    private array $runs = [];
    /** @var list<array{0:string,1:int}> */
    private array $waits = [];
    /** @var list<string> */
    private array $tmp = [];
    private int $monoNow = 0;
    private int $monoTick = 10;
    private int $monoReads = 0;
    private mixed $runResult = ['r' => 1];
    private ?\Throwable $runError = null;
    private ?\Closure $meshSetup = null;
    /** @var list<string|false> */
    private array $stdin = [];

    protected function setUp(): void
    {
        $nowCalls = 0;
        MpcNetPartyMain::$writeHook = function (int $fd, string $text): void {
            $this->writes[] = [$fd, $text];
        };
        MpcNetPartyMain::$meshHook = function (array $mc): MpcNetMesh {
            $this->mesh = new Kill17bMesh($mc);
            if ($this->meshSetup !== null) {
                ($this->meshSetup)($this->mesh);
            }
            return $this->mesh;
        };
        MpcNetPartyMain::$runHook = function (string $what, mixed ...$args): mixed {
            $this->runs[] = [$what, ...$args];
            if ($this->runError !== null) {
                throw $this->runError;
            }
            return $this->runResult;
        };
        MpcNetPartyMain::$nowHook = static function () use (&$nowCalls): float {
            return $nowCalls++ === 0 ? 10.0 : 11.0;
        };
        MpcNetPartyMain::$monoHook = function (): int {
            $this->monoReads++;
            $v = $this->monoNow;
            $this->monoNow += $this->monoTick;
            return $v;
        };
        MpcNetPartyMain::$waitHook = function (string $kind, int $ms): void {
            $this->waits[] = [$kind, $ms];
        };
        MpcNetPartyMain::$exitHook = static function (int $code): void {
            throw new Kill17bExit($code);
        };
        MpcNetPartyMain::$stdinHook = function (): string|false {
            return array_shift($this->stdin) ?? false;
        };
        putenv('PCA_MPC_UNSAFE_TEST_HOOKS');
    }

    protected function tearDown(): void
    {
        foreach (['writeHook', 'meshHook', 'runHook', 'nowHook', 'monoHook', 'waitHook', 'exitHook', 'stdinHook'] as $h) {
            MpcNetPartyMain::$$h = null;
        }
        putenv('PCA_MPC_UNSAFE_TEST_HOOKS');
        foreach ($this->tmp as $f) {
            if (is_dir($f)) {
                MpcNetCerts::rmTree($f);
            } elseif (is_file($f)) {
                unlink($f);
            }
        }
    }

    private function file(string $content): string
    {
        $f = tempnam(sys_get_temp_dir(), 'k17b');
        file_put_contents($f, $content);
        $this->tmp[] = $f;
        return $f;
    }

    /** @return array<string,mixed> */
    private function cfg(array $over = []): array
    {
        return $over + ['role' => 'party', 'id' => 1, 'n' => 3, 'sessionId' => 's1', 'keyPath' => $this->file('KEY'), 'certPath' => $this->file('CERT'),
            'nodes' => [['id' => 0, 'host' => 'h0', 'port' => 7000, 'certPath' => $this->file('C0')], ['id' => 1, 'host' => 'h1', 'port' => 7001, 'certPath' => $this->file('C1')]],
            'input' => ['allow' => true]];
    }

    private function main(array $cfg): int
    {
        return MpcNetPartyMain::main(['pca-mpc-party', $this->file(json_encode($cfg))]);
    }

    /** @return list<mixed> every stdout line, decoded */
    private function out(): array
    {
        $o = [];
        foreach ($this->writes as [$fd, $t]) {
            if ($fd === 1) {
                $this->assertStringEndsWith("\n", $t);
                $o[] = json_decode($t, true, 512, JSON_THROW_ON_ERROR);
            }
        }
        return $o;
    }

    /** @return list<string> */
    private function err(): array
    {
        return array_values(array_map(static fn(array $w): string => $w[1], array_filter($this->writes, static fn(array $w): bool => $w[0] === 2)));
    }

    /** No arguments, or keygen without a directory: the usage line on stderr and exit code 2, nothing else. */
    public function testUsage(): void
    {
        $this->assertSame(2, MpcNetPartyMain::main(['pca-mpc-party']));
        $this->assertSame(["usage: pca-mpc-party <config.json> | keygen <dir> [cn]\n"], $this->err());
        $this->writes = [];
        $this->assertSame(2, MpcNetPartyMain::main(['pca-mpc-party', 'keygen']));
        $this->assertSame(["usage: pca-mpc-party keygen <dir> [cn]\n"], $this->err());
        $this->assertSame([], $this->out());
        $this->assertNull($this->mesh);
    }

    /** A missing file, invalid JSON and a JSON scalar are all the unreadable-config refusal (code 2). */
    public function testUnreadableConfig(): void
    {
        foreach ([sys_get_temp_dir() . '/k17b-missing-' . bin2hex(random_bytes(4)), $this->file('[1'), $this->file('5')] as $i => $path) {
            $this->writes = [];
            $this->assertSame(2, MpcNetPartyMain::main(['pca-mpc-party', $path]), "case $i");
            $this->assertSame(["pca-mpc-party: unreadable config\n"], $this->err(), "case $i");
        }
        // argv[0] is the program, never the config
        $this->writes = [];
        $this->assertSame(2, MpcNetPartyMain::main(['keygen']));
        $this->assertSame(["usage: pca-mpc-party <config.json> | keygen <dir> [cn]\n"], $this->err());
        $this->assertNull($this->mesh);
    }

    /** keygen writes key.pem and cert.pem under the directory, for the given common name or mpc-node, and prints both paths. */
    public function testKeygen(): void
    {
        if (($why = RefMpcNetSupport::meshUnavailable()) !== null) {
            $this->markTestSkipped($why);
        }
        foreach ([['cnX'], []] as $extra) {
            $this->writes = [];
            $dir = sys_get_temp_dir() . '/k17b-keys-' . bin2hex(random_bytes(6));
            $this->tmp[] = $dir;
            $this->assertSame(0, MpcNetPartyMain::main(['pca-mpc-party', 'keygen', $dir, ...$extra]));
            $this->assertSame([['keyPath' => "$dir/key.pem", 'certPath' => "$dir/cert.pem"]], $this->out());
            $this->assertSame([], $this->err());
            $x = openssl_x509_parse((string) file_get_contents("$dir/cert.pem"));
            $this->assertSame($extra[0] ?? 'mpc-node', $x['subject']['CN']);
        }
    }

    /** A test-hook key alone (behavior, frameFault or dealerFault) without the opt-in is refused before any mesh exists. */
    public function testHooksAreRefusedWithoutTheOptIn(): void
    {
        $refusal = ['ok' => false, 'role' => 'party', 'id' => 1, 'error' => ['kind' => 'local', 'blamed' => null, 'reporter' => 1,
            'message' => 'refusing to start: test hooks (behavior/frameFault) are not enabled in this environment']];
        $cases = [
            'behavior only' => [['behavior' => ['x' => 1]], null],
            'frameFault only' => [['frameFault' => ['round' => 'r']], null],
            'dealerFault only' => [['dealerFault' => []], null],
            'opt-in without the env' => [['behavior' => ['x' => 1], 'unsafeTestHooks' => true], null],
            'env without the opt-in' => [['behavior' => ['x' => 1]], '1'],
            'opt-in not exactly true' => [['behavior' => ['x' => 1], 'unsafeTestHooks' => 'true'], '1'],
            'env not exactly 1' => [['behavior' => ['x' => 1], 'unsafeTestHooks' => true], '2'],
        ];
        foreach ($cases as $name => [$over, $env]) {
            $this->writes = [];
            putenv($env === null ? 'PCA_MPC_UNSAFE_TEST_HOOKS' : "PCA_MPC_UNSAFE_TEST_HOOKS=$env");
            $this->assertSame(3, $this->main($this->cfg($over)), $name);
            $this->assertSame([$refusal], $this->out(), $name);
            $this->assertNull($this->mesh, $name);
        }
    }

    /** With no hook key the node starts; with the opt-in AND the env the hooks are passed on (mesh and party). */
    public function testHooksWithTheOptInStart(): void
    {
        $this->assertSame(0, $this->main($this->cfg()));
        $this->assertArrayNotHasKey('unsafeTestHooks', $this->mesh->mc);
        $this->assertArrayNotHasKey('behavior', $this->runs[0][1]);
        putenv('PCA_MPC_UNSAFE_TEST_HOOKS=1');
        $this->mesh = null;
        $this->runs = [];
        $this->assertSame(0, $this->main($this->cfg(['behavior' => ['x' => 1], 'unsafeTestHooks' => true])));
        $this->assertTrue($this->mesh->mc['unsafeTestHooks']);
        $this->assertSame(['x' => 1], $this->runs[0][1]['behavior']);
        $this->assertTrue($this->runs[0][1]['unsafeTestHooks']);
    }

    /** The mesh config: ids, hosts, ports and the session id cast to their types, PEMs read from the paths, the optional timeouts. */
    public function testMeshConfig(): void
    {
        $cfg = $this->cfg(['id' => '1', 'n' => '3', 'sessionId' => 7, 'listenHost' => '127.0.0.9', 'recvTimeoutMs' => 111, 'connectTimeoutMs' => 222,
            'nodes' => [['id' => '0', 'host' => 5, 'port' => '7000', 'certPath' => $this->file('C0')]]]);
        $this->assertSame(0, $this->main($cfg));
        $this->assertSame(['selfId' => 1, 'nodes' => [['id' => 0, 'host' => '5', 'port' => 7000, 'certPem' => 'C0']], 'keyPem' => 'KEY', 'certPem' => 'CERT',
            'sessionId' => '7', 'listenHost' => '127.0.0.9', 'recvTimeoutMs' => 111, 'connectTimeoutMs' => 222], $this->mesh->mc);
        $this->assertSame([['connect'], ['close']], $this->mesh->log);
        $this->assertSame([['drain', 300]], $this->waits);
        $this->assertSame(3, $this->runs[0][1]['n']);
        $this->assertSame(1, $this->runs[0][1]['id']);
    }

    /** A dealer links only to the parties (ids below n), as a list. */
    public function testDealerLinksOnlyToParties(): void
    {
        $nodes = [];
        foreach ([3, 0, 1, 2] as $i) {
            $nodes[] = ['id' => $i, 'host' => "h$i", 'port' => 7000 + $i, 'certPath' => $this->file("C$i")];
        }
        $this->assertSame(0, $this->main($this->cfg(['role' => 'dealer', 'id' => 3, 'nodes' => $nodes, 'insecureTrustedDealer' => true])));
        $this->assertSame([0, 1, 2], $this->mesh->mc['linkTo']);
    }

    /** A dealer runs with the defaults (Q 100, no seed, no trusted-dealer flag, no faults) and reports ok with its links and events. */
    public function testDealerDefaults(): void
    {
        $this->assertSame(0, $this->main($this->cfg(['role' => 'dealer'])));
        $this->assertCount(1, $this->runs);
        [$what, $a] = $this->runs[0];
        $this->assertSame('dealer', $what);
        $this->assertSame($this->mesh, $a['mesh']);
        unset($a['mesh']);
        $this->assertSame(['n' => 3, 'Q' => MpcNetProtocol::DEFAULT_Q, 'seed' => null, 'insecureTrustedDealer' => false, 'macFaultAtInput' => null, 'fault' => null], $a);
        $this->assertSame([['ok' => true, 'role' => 'dealer', 'id' => 1, 'connectMs' => 1000, 'links' => [['peer' => 0, 'framesIn' => 2]], 'events' => ['ev-1']]], $this->out());
    }

    /** A dealer with Q, a seed, the trusted-dealer flag and a full dealerFault gets them as bigints. */
    public function testDealerWithFaults(): void
    {
        putenv('PCA_MPC_UNSAFE_TEST_HOOKS=1');
        $this->assertSame(0, $this->main($this->cfg(['role' => 'dealer', 'Q' => 5, 'dealerSeed' => 123, 'insecureTrustedDealer' => true, 'unsafeTestHooks' => true,
            'dealerFault' => ['macFaultAtInput' => 2, 'keepCDelta' => 5, 'partnerCDelta' => [null, '7']]])));
        $a = $this->runs[0][1];
        $this->assertSame(5, $a['Q']);
        $this->assertSame('123', gmp_strval($a['seed']));
        $this->assertTrue($a['insecureTrustedDealer']);
        $this->assertSame(2, $a['macFaultAtInput']);
        $this->assertSame('5', gmp_strval($a['fault']['keepCDelta']));
        $this->assertNull($a['fault']['partnerCDelta'][0]);
        $this->assertSame('7', gmp_strval($a['fault']['partnerCDelta'][1]));
        $this->assertCount(2, $a['fault']['partnerCDelta']);

        $this->runs = [];
        $this->assertSame(0, $this->main($this->cfg(['role' => 'dealer', 'unsafeTestHooks' => true, 'dealerFault' => ['x' => 1]])));
        $this->assertSame(['keepCDelta' => null, 'partnerCDelta' => null], $this->runs[0][1]['fault']);
        $this->assertNull($this->runs[0][1]['macFaultAtInput']);
    }

    /** Seeds and deltas are read as decimal text: a fraction is the bigint parser's refusal (reported as a local abort). */
    public function testDealerSeedsAreDecimalText(): void
    {
        putenv('PCA_MPC_UNSAFE_TEST_HOOKS=1');
        $cases = [['dealerSeed' => 1.5], ['dealerFault' => ['keepCDelta' => 1.5]], ['dealerFault' => ['partnerCDelta' => [1.5]]]];
        foreach ($cases as $i => $over) {
            $this->writes = [];
            $this->runs = [];
            $this->assertSame(3, $this->main($this->cfg(['role' => 'dealer', 'unsafeTestHooks' => true] + $over)), "case $i");
            $this->assertSame([], $this->runs);
            $o = $this->out();
            $this->assertCount(1, $o);
            $this->assertSame('local', $o[0]['error']['kind']);
            $this->assertStringContainsString('is not an integer string', $o[0]['error']['message'], "case $i");
        }
    }

    /** The OT sides: sender to peer 1, receiver to peer 0, ec x 128 by default, kind and count cast; the report carries the result. */
    public function testOtRoles(): void
    {
        $this->runResult = ['matched' => true];
        $this->assertSame(0, $this->main($this->cfg(['role' => 'ot-sender'])));
        $this->assertSame([['ot-sender', $this->mesh, 1, 'ec', 128]], $this->runs);
        $this->assertSame([['ok' => true, 'role' => 'ot-sender', 'connectMs' => 1000, 'result' => ['matched' => true], 'links' => [['peer' => 0, 'framesIn' => 2]],
            'events' => ['ev-1']]], $this->out());
        $this->runs = [];
        $this->writes = [];
        $this->assertSame(0, $this->main($this->cfg(['role' => 'ot-receiver', 'ot' => ['kind' => 5, 'count' => '3']])));
        $this->assertSame([['ot-receiver', $this->mesh, 0, '5', 3]], $this->runs);
        $this->assertSame('ot-receiver', $this->out()[0]['role']);
    }

    /** A party runs with its id, n, input, session and the defaults (no-dealer offline, no trusted dealer); Q only when given. */
    public function testPartyRun(): void
    {
        $this->assertSame(0, $this->main($this->cfg(['sessionId' => 9])));
        [$what, $pc] = $this->runs[0];
        $this->assertSame('party', $what);
        unset($pc['mesh']);
        $this->assertSame(['id' => 1, 'n' => 3, 'input' => ['allow' => true], 'sessionId' => '9', 'offline' => 'no-dealer', 'insecureTrustedDealer' => false], $pc);
        $this->assertSame([['ok' => true, 'role' => 'party', 'connectMs' => 1000, 'result' => ['r' => 1], 'links' => [['peer' => 0, 'framesIn' => 2]],
            'events' => ['ev-1']]], $this->out());
        $this->runs = [];
        $this->assertSame(0, $this->main($this->cfg(['Q' => 7, 'offline' => 'dealer', 'insecureTrustedDealer' => true])));
        $pc = $this->runs[0][1];
        $this->assertSame(7, $pc['Q']);
        $this->assertSame('dealer', $pc['offline']);
        $this->assertTrue($pc['insecureTrustedDealer']);
    }

    /** Without a role the node is a party; a non-string role is reported as text; the report keeps slashes as they are. */
    public function testRoleDefaultAndCast(): void
    {
        $this->runError = new \RuntimeException('a/b');
        $cfg = $this->cfg();
        unset($cfg['role']);
        $this->assertSame(3, $this->main($cfg));
        $this->assertStringContainsString('reporter=1: a/b"', $this->writes[0][1]); // one line, slashes unescaped
        $this->assertSame('party', $this->runs[0][0]);
        $this->assertSame('party', $this->out()[0]['role']);
        $this->writes = [];
        $this->assertSame(3, $this->main($this->cfg(['role' => 5])));
        $this->assertSame('5', $this->out()[0]['role']);
    }

    /** bindFirst (exactly true): report the bound port, then dial each peer except itself on the ports from one stdin line. */
    public function testBindFirst(): void
    {
        $this->stdin = ['{"ports":{"01":9,"0":7000,"1":7001,"2":"7002"}}'];
        $this->assertSame(0, $this->main($this->cfg(['bindFirst' => true])));
        $this->assertSame(['listening' => 4242, 'id' => 1], $this->out()[0]);
        $this->assertSame([['listen'], ['port', 0, 7000], ['port', 2, 7002], ['connect'], ['close']], $this->mesh->log);

        $this->stdin = ['{"ports":5}'];
        $this->writes = [];
        $this->assertSame(0, $this->main($this->cfg(['bindFirst' => true])));
        $this->assertSame([['listen'], ['port', 0, 5], ['connect'], ['close']], $this->mesh->log);

        $this->stdin = ['{}'];
        $this->assertSame(0, $this->main($this->cfg(['bindFirst' => true])));
        $this->assertSame([['listen'], ['connect'], ['close']], $this->mesh->log);

        foreach ([null, 1] as $bf) {
            $this->stdin = ['{"ports":{"0":1}}'];
            $this->writes = [];
            $this->assertSame(0, $this->main($this->cfg($bf === null ? [] : ['bindFirst' => $bf])));
            $this->assertSame([['connect'], ['close']], $this->mesh->log);
            $this->assertCount(1, $this->out());
            $this->assertSame(['{"ports":{"0":1}}'], $this->stdin);
        }
    }

    /** A closed stdin before the port map is a local abort naming it (code 3), and the mesh is still drained and closed. */
    public function testBindFirstClosedStdin(): void
    {
        $this->stdin = [false];
        $this->assertSame(3, $this->main($this->cfg(['bindFirst' => true])));
        $o = $this->out();
        $this->assertSame('[local] blamed=none reporter=1: stdin closed before the port map arrived', $o[1]['error']['message']);
        $this->assertSame([['listen'], ['close']], $this->mesh->log);
        $this->assertSame([], $this->runs);
    }

    /** An abort is reported field by field with its own blame; drain then close; exit code 3. */
    public function testAbortReport(): void
    {
        $this->runError = new MpcNetAbort('commitment', 2, 1, 'bad open', 'malformed', 0, null, ['e' => 1], 99);
        $this->assertSame(3, $this->main($this->cfg()));
        $this->assertSame([['ok' => false, 'role' => 'party', 'id' => 1, 'error' => ['kind' => 'commitment', 'blamed' => 2, 'reporter' => 1,
            'claimedKind' => 'malformed', 'claimedBlame' => 0, 'reason' => null, 'evidence' => ['e' => 1], 'deadlineMs' => 99,
            'message' => '[commitment] blamed=2 reporter=1: bad open'], 'links' => [['peer' => 0, 'framesIn' => 2]], 'events' => ['ev-1']]], $this->out());
        $this->assertSame([['drain', 300]], $this->waits);
        $this->assertSame([['connect'], ['close']], $this->mesh->log);
    }

    /** Any other error is the mesh's recorded failure when there is one, else a local abort with the error's text. */
    public function testOtherErrorsBecomeAborts(): void
    {
        $this->runError = new \RuntimeException('boom');
        $this->assertSame(3, $this->main($this->cfg()));
        $e = $this->out()[0]['error'];
        $this->assertSame('[local] blamed=none reporter=1: boom', $e['message']);
        $this->assertSame('local', $e['kind']);
        $this->assertNull($e['blamed']);
        $this->assertSame('unattributable: the evidence available to this party does not identify a culprit', $e['reason']);

        $this->writes = [];
        $this->meshSetup = static function (Kill17bMesh $m): void {
            $m->failure = new MpcNetAbort('timeout', 0, 1, 'peer 0 silent');
            $m->connectError = new \RuntimeException('dial failed');
        };
        $this->runs = [];
        $this->assertSame(3, $this->main($this->cfg()));
        $this->assertSame('[timeout] blamed=0 reporter=1: peer 0 silent', $this->out()[0]['error']['message']);
        $this->assertSame([], $this->runs);
    }

    /** A crash-test party exits with code 7 at once: nothing printed, no drain, no close. */
    public function testCrashExitsSeven(): void
    {
        $this->runError = new MpcNetCrashParty();
        try {
            $this->main($this->cfg());
            $this->fail('expected the exit');
        } catch (Kill17bExit $e) {
            $this->assertSame(7, $e->exitCode);
        }
        $this->assertSame([], $this->writes);
        $this->assertSame([], $this->waits);
        $this->assertSame([['connect']], $this->mesh->log);
    }

    /** A silent party waits 4 x recvTimeoutMs on the loop clock in 50 ms steps, then returns 0 with nothing printed or closed. */
    public function testSilentPartyWaitsFourTimeouts(): void
    {
        $this->runError = new MpcNetSilentParty();
        // (int) 10.5 = 10: the window is 40 ms; reads at 0 (start), 10, 20, 30 (step each) and 40 (stop)
        $this->assertSame(0, $this->main($this->cfg(['recvTimeoutMs' => 10.5])));
        $this->assertSame(array_fill(0, 3, ['step', 50]), $this->waits);
        $this->assertSame(5, $this->monoReads);
        $this->assertSame([], $this->writes);
        $this->assertSame([['connect']], $this->mesh->log);
    }

    /** The default window is 4 x 20000 ms. */
    public function testSilentPartyDefaultWindow(): void
    {
        $this->runError = new MpcNetSilentParty();
        $this->monoTick = 1;
        $steps = 0;
        MpcNetPartyMain::$waitHook = static function (string $kind, int $ms) use (&$steps): void {
            $steps += $kind === 'step' && $ms === 50 ? 1 : 1000000;
        };
        $this->assertSame(0, $this->main($this->cfg()));
        $this->assertSame(79999, $steps);
        $this->assertSame(80001, $this->monoReads);
    }
}
