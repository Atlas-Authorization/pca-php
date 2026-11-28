<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\NativeDir;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use Atlas\Pca\SandboxWasmHost;
use PHPUnit\Framework\TestCase;

/** Group 25 kills for src/SandboxWasmHost.php: the packaged host lookup, verb replies and a host that stops reading its input. */
final class SysSurvivorKill25SandboxWasmHostTest extends TestCase
{
    /** handle 1 is fs.read, returning `$result` */
    private static function table(string $result): SandboxHandleTable
    {
        $t = new SandboxHandleTable('wasi_no_ambient', new SandboxReceiptLog(), ['fs.read' => static fn($op) => new Bytes($result)]);
        $op = Obj::of(['verb' => 'fs.read', 'resource' => '/x', 'params' => new Obj()]);
        $t->mint(Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'fs.read', 'resource' => '/x',
            'params_digest' => Pca::hashCanonical(new Obj()), 'id' => 'op'])]), $op);
        return $t;
    }

    /** A fake host: a shell script, or on Windows a command file running the same protocol as PHP. */
    private static function fake(string $tag, string $sh, string $php): SandboxWasmHost
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-host-k25-' . getmypid() . '-' . $tag;
        @mkdir($dir, 0700, true);
        if (PHP_OS_FAMILY === 'Windows') {
            file_put_contents("$dir\\host.php", "<?php\n$php\n");
            $script = "@\"" . PHP_BINARY . "\" \"$dir\\host.php\"\r\n";
            file_put_contents("$dir\\host.cmd", $script);
            return new SandboxWasmHost("$dir\\host.cmd", hash('sha256', $script));
        }
        $script = "#!/bin/sh\n$sh\n";
        file_put_contents("$dir/host.sh", $script);
        chmod("$dir/host.sh", 0755);
        return new SandboxWasmHost("$dir/host.sh", hash('sha256', $script));
    }

    /** packaged() finds native/<os>-<arch>/pca-wasmtime-host and pins it to the trimmed digest beside it; without the digest there is no packaged host. */
    public function testPackagedHostIsFoundAndPinnedToItsDigest(): void
    {
        $dir = NativeDir::dir();
        $exe = $dir . '/pca-wasmtime-host' . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');
        if (is_file($exe) || is_file($exe . '.sha256')) {
            $this->markTestSkipped('this tree carries a packaged host');
        }
        // parallel mutation workers share this directory: one at a time
        $lock = fopen(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k25-packaged-host.lock', 'c');
        $this->assertIsResource($lock);
        flock($lock, LOCK_EX);
        $made = !is_dir($dir) && @mkdir($dir, 0777, true);
        try {
            $bytes = "pca-k25-host-bytes\n";
            file_put_contents($exe, $bytes);
            file_put_contents($exe . '.sha256', hash('sha256', $bytes) . "\n");
            $host = SandboxWasmHost::packaged();
            $this->assertInstanceOf(SandboxWasmHost::class, $host);
            $this->assertNull($host->verify(), 'the packaged host matches its trimmed digest');
            unlink($exe . '.sha256');
            $this->assertNull(SandboxWasmHost::packaged(), 'a host without its digest is not a packaged host');
            unlink($exe);
            $this->assertNull(SandboxWasmHost::packaged());
        } finally {
            @unlink($exe . '.sha256');
            @unlink($exe);
            if ($made) {
                @rmdir($dir);
            }
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** verb answers {"ok":<verb>} for a live handle and exactly {"err":-1} for an unknown one. */
    public function testVerbRepliesForKnownAndUnknownHandles(): void
    {
        $sh = <<<'SH'
printf '{"op":"verb","h":1}\n'; read a; printf '{"op":"verb","h":99}\n'; read b
if [ "$a" = '{"ok":"fs.read"}' ] && [ "$b" = '{"err":-1}' ]; then printf '{"done":3}\n'; else printf '{"fail":"bad_verb_reply"}\n'; fi
SH;
        $php = <<<'PHP'
echo "{\"op\":\"verb\",\"h\":1}\n"; $a = trim((string)fgets(STDIN));
echo "{\"op\":\"verb\",\"h\":99}\n"; $b = trim((string)fgets(STDIN));
echo ($a === '{"ok":"fs.read"}' && $b === '{"err":-1}') ? "{\"done\":3}\n" : "{\"fail\":\"bad_verb_reply\"}\n";
PHP;
        $r = self::fake('verb', $sh, $php)->runComponent(self::table("\x07"), 'x', 1000);
        $this->assertNull($r->get('reason'));
        $this->assertTrue($r->get('ok'));
        $this->assertSame(3, $r->get('value'));
    }

    /**
     * A host that asks for a reply larger than its input pipe holds and then stops reading is refused as a timeout: the client keeps
     * waiting for the pipe to drain instead of treating a half-sent reply as sent and acting on the host's next line.
     */
    public function testHalfSentReplyIsNotTreatedAsSent(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('the relay socket buffers differ on Windows; the pipe case is the one under test');
        }
        $r = self::fake('halfsent', "printf '{\"op\":\"invoke\",\"h\":1}\\n{\"done\":1}\\n'; exec sleep 30", '')
            ->runComponent(self::table(str_repeat("\x07", 262144)), 'x', 1000, 400);
        $this->assertFalse($r->get('ok'));
        $this->assertSame('timeout', $r->get('reason'));
    }
}
