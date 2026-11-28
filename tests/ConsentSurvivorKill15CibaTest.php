<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ApprovalStore;
use Atlas\Pca\ApprovalStoreError;
use Atlas\Pca\Ciba;
use Atlas\Pca\CibaClient;
use Atlas\Pca\CibaProviderError;
use Atlas\Pca\CibaStoreConformance;
use Atlas\Pca\DirectoryKv;
use Atlas\Pca\DurableCibaBroker;
use Atlas\Pca\FileApprovalStore;
use Atlas\Pca\JsonError;
use Atlas\Pca\MemoryApprovalStore;
use Atlas\Pca\MemoryKv;
use PHPUnit\Framework\TestCase;

/** An ApprovalStore whose compare-and-set always loses, holding one fixed record under "a:x". */
final class K15LosingStore implements ApprovalStore
{
    public function get(string $key): ?array
    {
        return $key === 'a:x' ? ['version' => 1, 'value' => ['request' => ['auth_req_id' => 'x'], 'createdAt' => 0, 'expiresAt' => 1.0e15, 'interval' => 5]] : null;
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        return false;
    }
}

/** A memory store whose first compare-and-set loses (another writer got there first), then behaves. */
final class K15LoseOnceStore implements ApprovalStore
{
    private MemoryApprovalStore $m;
    public int $lost = 0;

    public function __construct()
    {
        $this->m = new MemoryApprovalStore();
    }

    public function get(string $key): ?array
    {
        return $this->m->get($key);
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        if ($this->lost === 0) {
            $this->lost = 1;
            return false;
        }
        return $this->m->cas($key, $expectedVersion, $value);
    }
}

/** A store that says every write succeeded but never keeps anything. */
final class K15ForgetfulStore implements ApprovalStore
{
    public function get(string $key): ?array
    {
        return null;
    }

    public function cas(string $key, int|float $expectedVersion, mixed $value): bool
    {
        return true;
    }
}

/** group 15 mutation kills for src/Ciba.php: binding-message encodings, refusals with their exact reasons, the stores and the default transport. */
final class ConsentSurvivorKill15CibaTest extends TestCase
{
    private const SERVER = <<<'SRV'
$s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($s === false) {
    fwrite(STDERR, $errstr);
    exit(1);
}
$name = (string) stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, (int) strrpos($name, ':') + 1) . "\n");
foreach ($responses as $resp) {
    $c = @stream_socket_accept($s, 5);
    if ($c === false) {
        break;
    }
    $req = '';
    while (!str_contains($req, "\r\n\r\n")) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    $parts = explode("\r\n\r\n", $req, 2);
    $len = preg_match('/\r\ncontent-length: *([0-9]+)/i', $parts[0], $m) === 1 ? (int) $m[1] : 0;
    $body = $parts[1] ?? '';
    while (strlen($body) < $len) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $body .= $b;
    }
    fwrite($c, str_replace('{REQ}', base64_encode($parts[0] . "\r\n\r\n" . $body), $resp));
    fclose($c);
}
SRV;

    private array $dirs = [];

    protected function tearDown(): void
    {
        DirectoryKv::$clockHook = null;
        foreach ($this->dirs as $d) {
            self::rmTree($d);
        }
    }

    private static function rmTree(string $p): void
    {
        if (is_dir($p)) {
            foreach (scandir($p) ?: [] as $e) {
                if ($e !== '.' && $e !== '..') {
                    self::rmTree("$p/$e");
                }
            }
            @rmdir($p);
        } elseif (file_exists($p)) {
            @unlink($p);
        }
    }

    private function tmp(): string
    {
        $d = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k15-' . bin2hex(random_bytes(6));
        mkdir($d, 0700);
        $this->dirs[] = $d;
        return $d;
    }

    private static function su(array $extra = []): array
    {
        return ['id' => 'su1', 'verb' => 'v', 'resource' => 'r'] + $extra;
    }

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('expected a throw');
    }

    private static function assertThrown(string $class, string $message, callable $f): \Throwable
    {
        $e = self::thrown($f);
        self::assertSame($class, get_class($e), $e->getMessage());
        self::assertSame($message, $e->getMessage());
        return $e;
    }

    private static function client(array $extra = []): CibaClient
    {
        return new CibaClient($extra + ['backchannelAuthenticationEndpoint' => 'https://op.example/bc', 'tokenEndpoint' => 'https://op.example/token',
            'clientId' => 'c', 'clientSecret' => 's', 'fetch' => static fn(string $u, array $i): array => ['status' => 500, 'body' => '{}']]);
    }

    // ---- binding message encodings -----------------------------------------------------------------------------------------

    /** Lone surrogates in the goal survive the /u shielding byte for byte (U+DBFF and U+D800 round-trip exactly). */
    public function testLoneSurrogatesInTheGoalRoundTrip(): void
    {
        $r = Ciba::toCibaAuthRequest(self::su(['goal' => "x\xED\xAF\xBFy\xED\xA0\x80z"]));
        $this->assertSame("Approve v on r \u{2014} because you asked your agent to 'x\xED\xAF\xBFy\xED\xA0\x80z'", $r['binding_message']);
    }

    /** A goal commitment cut inside an astral character keeps that character's high surrogate (as JS slice does). */
    public function testGoalCommitCutKeepsTheHighSurrogate(): void
    {
        $max = Ciba::toCibaAuthRequest(self::su(['goalCommit' => "abcdefghi\u{10FFFF}zz"]));
        $this->assertSame("Approve v on r \u{2014} because you asked your agent to 'goal abcdefghi\xED\xAF\xBF\u{2026}'", $max['binding_message']);
        $min = Ciba::toCibaAuthRequest(self::su(['goalCommit' => "abcdefghi\u{10000}zz"]));
        $this->assertSame("Approve v on r \u{2014} because you asked your agent to 'goal abcdefghi\xED\xA0\x80\u{2026}'", $min['binding_message']);
        $whole = Ciba::toCibaAuthRequest(self::su(['goalCommit' => "abcdefgh\u{10000}zz"]));
        $this->assertSame("Approve v on r \u{2014} because you asked your agent to 'goal abcdefgh\u{10000}\u{2026}'", $whole['binding_message'], 'control: a pair that fits stays whole');
    }

    /** A goal that does not fit maxChars is clipped to the room left, inside the quotes. */
    public function testGoalClippedToTheRoomLeft(): void
    {
        $r = Ciba::toCibaAuthRequest(self::su(['goal' => 'abcdefghijklmnopqrstuvwxyz']), ['bindingMessage' => ['maxChars' => 61]]);
        $this->assertSame("Approve v on r \u{2014} because you asked your agent to 'abcdefghi\u{2026}'", $r['binding_message']);
    }

    /** IDNA-refused payee words fall back to \u{..} escapes for every non-ASCII code point (valid UTF-8 and WTF-8 alike). */
    public function testAsciiFormEscapes(): void
    {
        $this->assertSame('plain \u{e9}~:a', Ciba::asciiForm("plain \u{e9}~:a"));
        $this->assertSame('\u{dbff}:\u{d800}', Ciba::asciiForm("\xED\xAF\xBF:\xED\xA0\x80"));
        $this->assertSame('ok', Ciba::asciiForm('ok'), 'control');
    }

    // ---- refusals --------------------------------------------------------------------------------------------------------------

    /** A non-empty list commitment is refused rather than rendered. */
    public function testListGoalCommitRefused(): void
    {
        self::assertThrown(\RangeException::class, 'ciba: the goal commitment must be a string', static fn() => Ciba::toCibaAuthRequest(self::su(['goalCommit' => ['a']])));
    }

    /** A tokenOnly message whose payee tokenises to nothing is refused (the person would not see who is paid). */
    public function testTokenOnlyEmptyPayeeRefused(): void
    {
        self::assertThrown(\RangeException::class, 'ciba: tokenOnly binding message cannot represent the verb, payee or resource',
            static fn() => Ciba::toCibaAuthRequest(self::su(['params' => ['payee' => '!!!']]), ['bindingMessage' => ['tokenOnly' => true]]));
        $ok = Ciba::toCibaAuthRequest(self::su(['params' => ['payee' => 'bob']]), ['bindingMessage' => ['tokenOnly' => true]]);
        $this->assertSame('Approve-v-to-bob-r', $ok['binding_message'], 'control');
    }

    /** Null options, a non-string actsFor and a step-up without id or authReqId throw the reference's errors. */
    public function testAuthRequestInputErrors(): void
    {
        self::assertThrown(\TypeError::class, "Cannot read properties of null (reading 'actsFor')", static fn() => Ciba::toCibaAuthRequest(self::su(), null));
        self::assertThrown(\TypeError::class, 'value.replace is not a function', static fn() => Ciba::toCibaAuthRequest(self::su(), ['actsFor' => 5]));
        self::assertThrown(JsonError::class, 'canonicalize: unsupported type undefined', static fn() => Ciba::toCibaAuthRequest(['verb' => 'v', 'resource' => 'r']));
    }

    /** A step_up review without a request is a TypeError, never a silent "no CIBA needed". */
    public function testRequiresCibaWithoutRequest(): void
    {
        self::assertThrown(\TypeError::class, "Cannot read properties of undefined (reading 'tier')", static fn() => Ciba::requiresCiba(['kind' => 'step_up']));
        $this->assertTrue(Ciba::requiresCiba(['kind' => 'step_up', 'request' => ['tier' => 3]]), 'control');
    }

    /** A flow whose client_notification_token is not a string refuses the ping with its own TypeError. */
    public function testPingWithNonStringFlowToken(): void
    {
        self::assertThrown(\TypeError::class, 'ciba: the flow client_notification_token is not a string',
            static fn() => Ciba::verifyPingCallback(['authorization' => 'Bearer abc'], ['clientNotificationToken' => 5, 'authReqId' => 'x']));
    }

    /** initiate() with null options is the reference's TypeError, not the "exactly one hint" refusal. */
    public function testInitiateNullOptions(): void
    {
        self::assertThrown(\TypeError::class, "Cannot read properties of null (reading 'loginHint')", static fn() => self::client()->initiate(self::su(), null));
    }

    /** createCibaClient is public and builds a client. */
    public function testCreateCibaClient(): void
    {
        $this->assertInstanceOf(CibaClient::class, Ciba::createCibaClient(['backchannelAuthenticationEndpoint' => 'https://op.example/bc', 'tokenEndpoint' => 'https://op.example/t']));
    }

    /** withAuthReqId copies every option of an assoc array, a numeric key as its string. */
    public function testWithAuthReqIdCopiesArrayOptions(): void
    {
        $o = Ciba::withAuthReqId([1 => 'a', 'x' => 'b'], 'ID');
        $this->assertSame(['1', 'x', 'authReqId'], $o->keys());
        $this->assertSame('a', $o->get('1'));
        $this->assertSame('b', $o->get('x'));
        $this->assertSame('ID', $o->get('authReqId'));
    }

    // ---- stores -------------------------------------------------------------------------------------------------------------

    /** MemoryKv refuses a swap from the wrong expected text and keeps the value. */
    public function testMemoryKvRefusesStaleSwap(): void
    {
        $kv = new MemoryKv();
        $this->assertTrue($kv->putIfEquals('k', null, 'a'));
        $this->assertFalse($kv->putIfEquals('k', 'zzz', 'b'));
        $this->assertSame('a', $kv->get('k'));
    }

    /** FileApprovalStore: versions read back, a stale cas is refused, a record without version reads version 0, an absent key is null. */
    public function testFileApprovalStoreRoundTrip(): void
    {
        $p = $this->tmp() . DIRECTORY_SEPARATOR . 'store.json';
        $s = new FileApprovalStore($p);
        $this->assertNull($s->get('k'));
        $this->assertTrue($s->cas('k', 0, 'v'));
        $this->assertSame(['version' => 1.0, 'value' => 'v'], $s->get('k'));
        $this->assertFalse($s->cas('k', 5, 'w'));
        $this->assertFalse($s->cas('other', 3, 'w'));
        $this->assertSame(['version' => 1.0, 'value' => 'v'], $s->get('k'));
        $this->assertNull($s->get('other'));
        file_put_contents($p, '{"k":{"value":"x"}}');
        $this->assertSame(['version' => 0, 'value' => 'x'], $s->get('k'));
    }

    /** A store file that is valid JSON but not an object is corrupt: fail closed. */
    public function testFileApprovalStoreCorrupt(): void
    {
        $p = $this->tmp() . DIRECTORY_SEPARATOR . 'store.json';
        file_put_contents($p, '[1]');
        self::assertThrown(\RuntimeException::class, 'ciba: approval store file is corrupt', static fn() => (new FileApprovalStore($p))->get('k'));
    }

    /** A write that cannot land throws instead of reporting success. */
    public function testFileApprovalStoreWriteFailure(): void
    {
        $p = $this->tmp() . DIRECTORY_SEPARATOR . 'missing' . DIRECTORY_SEPARATOR . 'store.json';
        self::assertThrown(\RuntimeException::class, 'ciba: could not write the approval store file', static fn() => (new FileApprovalStore($p))->cas('k', 0, 'v'));
    }

    /** DirectoryKv option, directory and key refusals. */
    public function testDirectoryKvRefusals(): void
    {
        $d = $this->tmp();
        self::assertThrown(\InvalidArgumentException::class, 'createDirectoryKv: lockTimeoutMs must be a positive number', static fn() => new DirectoryKv($d, ['lockTimeoutMs' => 0]));
        file_put_contents("$d/file", 'x');
        self::assertThrown(\RuntimeException::class, 'ciba: could not create the store directory', static fn() => new DirectoryKv("$d/file/sub"));
        $e = self::assertThrown(ApprovalStoreError::class, 'ciba: store key must be a non-empty string', static fn() => (new DirectoryKv($d))->get(''));
        $this->assertSame('bad_key', $e->errorCode);
    }

    /** DirectoryKv refuses a stale swap, keeps the value and releases its lock. */
    public function testDirectoryKvRefusesStaleSwap(): void
    {
        $d = $this->tmp();
        $kv = new DirectoryKv($d);
        $this->assertTrue($kv->putIfEquals('k', null, 'a'));
        $this->assertFalse($kv->putIfEquals('k', 'zzz', 'b'));
        $this->assertSame('a', $kv->get('k'));
        $this->assertFileDoesNotExist("$d/" . hash('sha256', 'k') . '.lock');
    }

    /** A temp file that cannot be opened makes the swap throw and still releases the lock. */
    public function testDirectoryKvTempFileFailure(): void
    {
        $d = $this->tmp();
        $f = "$d/" . hash('sha256', 'k');
        mkdir("$f." . getmypid() . '.tmp');
        self::assertThrown(\RuntimeException::class, 'ciba: could not write the store', static fn() => (new DirectoryKv($d))->putIfEquals('k', null, 'a'));
        $this->assertFileDoesNotExist("$f.lock");
        $this->assertFileDoesNotExist($f);
    }

    /** A held lock times out at exactly the deadline (clock read: deadline, before, at), leaving the holder's lock in place. */
    public function testDirectoryKvLockTimesOutAtTheDeadline(): void
    {
        $d = $this->tmp();
        $kv = new DirectoryKv($d, ['lockTimeoutMs' => 1000]);
        $lock = "$d/" . hash('sha256', 'k') . '.lock';
        file_put_contents($lock, '');
        $seq = [1000.0, 1000.5, 1001.0];
        $calls = 0;
        DirectoryKv::$clockHook = static function () use (&$seq, &$calls): float {
            $calls++;
            return array_shift($seq) ?? 1.0e12;
        };
        $e = self::assertThrown(ApprovalStoreError::class, 'ciba: could not take the store lock in time', static fn() => $kv->putIfEquals('k', null, 'a'));
        $this->assertSame('lock_timeout', $e->errorCode);
        $this->assertSame(3, $calls);
        $this->assertFileExists($lock);
        $this->assertNull($kv->get('k'));
    }

    /** A lock that cannot be created and does not exist (the directory is gone) is a hard error, not a wait. */
    public function testDirectoryKvLockCannotBeCreated(): void
    {
        $d = $this->tmp();
        $kv = new DirectoryKv($d);
        rmdir($d);
        $calls = 0;
        DirectoryKv::$clockHook = static function () use (&$calls): float {
            return $calls++ === 0 ? 1000.0 : 1.0e12;
        };
        self::assertThrown(\RuntimeException::class, 'ciba: could not take the store lock', static fn() => $kv->putIfEquals('k', null, 'a'));
    }

    // ---- durable broker contention -----------------------------------------------------------------------------------------------

    /** A store that never lets a write land makes start() and token() give up loudly. */
    public function testContentionGivesUp(): void
    {
        $b = new DurableCibaBroker(['store' => new K15LosingStore(), 'now' => static fn(): int => 1000]);
        self::assertThrown(\RuntimeException::class, 'ciba: approval store contention, gave up', static fn() => $b->start(self::su()));
        self::assertThrown(\RuntimeException::class, 'ciba: approval store contention, gave up', static fn() => $b->token('x'));
    }

    /** start() retries with a fresh auth_req_id after losing one create race. */
    public function testStartRetriesAfterALostCreate(): void
    {
        $store = new K15LoseOnceStore();
        $b = new DurableCibaBroker(['store' => $store, 'now' => static fn(): int => 1000]);
        $req = $b->start(self::su());
        $this->assertSame(1, $store->lost);
        $this->assertSame('pending', $b->poll($req['auth_req_id'])['status']);
    }

    /** The conformance helper names the field, the wanted and the actual value. */
    public function testConformanceFailureMessage(): void
    {
        $case = CibaStoreConformance::approvalStoreCases(static fn(): ApprovalStore => new K15ForgetfulStore())[1];
        self::assertThrown(\LogicException::class, 'get: want {"version":1,"value":{"a":1,"nested":{"b":["x",2,null]}}}, have null', $case['run']);
    }

    // ---- the default sleep and transport -------------------------------------------------------------------------------------------

    /** The default sleep takes fractional and negative milliseconds without error. */
    public function testDefaultSleepAcceptsFractionsAndNegatives(): void
    {
        $c = new CibaClient(['backchannelAuthenticationEndpoint' => 'https://op.example/bc', 'tokenEndpoint' => 'https://op.example/t']);
        ($c->sleep)(0.001);
        ($c->sleep)(-1);
        $this->assertInstanceOf(\Closure::class, $c->sleep);
    }

    /** @return array{0:resource,1:array,2:int} */
    private static function serve(array $responses): array
    {
        $code = '$responses = ' . var_export($responses, true) . ";\n" . self::SERVER;
        $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        $port = (int) trim((string) fgets($pipes[1]));
        self::assertGreaterThan(0, $port);
        return [$p, $pipes, $port];
    }

    private static function stop(array $srv): void
    {
        proc_terminate($srv[0]);
        fclose($srv[1][1]);
        fclose($srv[1][2]);
        proc_close($srv[0]);
    }

    private static function httpClient(int $port, array $extra = []): CibaClient
    {
        return new CibaClient($extra + ['backchannelAuthenticationEndpoint' => "http://127.0.0.1:$port/bc", 'tokenEndpoint' => "http://127.0.0.1:$port/t",
            'clientId' => 'c', 'clientSecret' => 's', 'allowInsecureHttp' => true]);
    }

    /** The default transport POSTs the form with every header, keeps an error status with its body and reads the status from the status line. */
    public function testDefaultTransportShape(): void
    {
        $srv = self::serve(["HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n{REQ}"]);
        try {
            $r = self::httpClient($srv[2])->post("http://127.0.0.1:{$srv[2]}/bc", [['a', 'b c']]);
        } finally {
            self::stop($srv);
        }
        $this->assertSame(['status', 'body'], array_keys($r));
        $this->assertSame(404, $r['status']);
        $req = (string) base64_decode($r['body'], true);
        $this->assertStringStartsWith('POST /bc HTTP/1.', $req);
        $this->assertStringContainsString("\r\nauthorization: Basic Yzpz\r\n", $req);
        $this->assertStringContainsString("\r\ncontent-type: application/x-www-form-urlencoded\r\n", $req);
        $this->assertStringContainsString("\r\naccept: application/json\r\n", $req);
        $this->assertStringEndsWith("\r\n\r\na=b+c", $req);
    }

    /** A redirect is never followed: the 302 itself comes back. */
    public function testDefaultTransportDoesNotFollowRedirects(): void
    {
        $srv = self::serve(["HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfollowed"]);
        try {
            $r = self::httpClient($srv[2])->post("http://127.0.0.1:{$srv[2]}/bc", [['a', 'b']]);
        } finally {
            self::stop($srv);
        }
        $this->assertSame(['status' => 302, 'body' => ''], $r);
    }

    private static function assertNetworkError(callable $f): void
    {
        $e = self::thrown($f);
        self::assertInstanceOf(CibaProviderError::class, $e);
        self::assertSame(0, $e->status);
        self::assertSame('network_error', $e->error);
        self::assertSame('request failed', $e->errorDescription);
        self::assertTrue($e->retryable);
    }

    /** A status line without a three-digit code, a refused connection and a silent server are all transport failures. */
    public function testDefaultTransportFailures(): void
    {
        $srv = self::serve(["HTTP/1.1 20 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"]);
        try {
            self::assertNetworkError(static fn() => self::httpClient($srv[2])->post("http://127.0.0.1:{$srv[2]}/bc", [['a', 'b']]));
        } finally {
            self::stop($srv);
        }
        $s = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($s);
        $name = (string) stream_socket_get_name($s, false);
        $port = (int) substr($name, (int) strrpos($name, ':') + 1);
        try {
            // accepted by the kernel, never answered: the read timeout (200 ms) ends it
            self::assertNetworkError(static fn() => self::httpClient($port, ['timeoutMs' => 200])->post("http://127.0.0.1:$port/bc", [['a', 'b']]));
        } finally {
            fclose($s);
        }
        self::assertNetworkError(static fn() => self::httpClient($port)->post("http://127.0.0.1:$port/bc", [['a', 'b']]));
    }
}
