<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\CborMap;
use Atlas\Pca\CborTag;
use Atlas\Pca\DurableTransparencyService;
use Atlas\Pca\FileScittLogStore;
use Atlas\Pca\MemoryScittLogStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Scitt;
use Atlas\Pca\ScittLog;
use Atlas\Pca\TransparencyService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SCITT receipts against the TS reference: test-data/ref-scitt.json.gz (the deterministic CBOR codec, the RFC 9162 tree, COSE Signed
 * Statements and Receipts (EdDSA byte-exact, ES256 by verification outcome), the in-memory and durable transparency services and the
 * file-backed log store). The corpus carries seed labels ("$seed:<label>") instead of private key material; the keys are derived
 * here as sha256("atlas-pca-conformance/" + label) (an ES256 scalar additionally clears the top bit of its first byte).
 */
final class RefScittDifferentialTest extends TestCase
{
    private const FILE = 'ref-scitt.json.gz';
    private const HALF_N = '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8';

    /** @var int */
    private static int $n = 0;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    // ---- keys and value forms -----------------------------------------------------------------------------------------

    private static function seedBytes(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    /** A corpus key member: a "$seed:<label>" placeholder or base64url bytes. */
    private static function member(mixed $v, bool $es): string
    {
        if ($v instanceof Obj && $v->keys() === ['$seed']) { // the regenerated corpus names a key by a {"$seed": label} object
            $v = '$seed:' . $v->get('$seed');
        }
        if (is_string($v) && str_starts_with($v, '$seed:')) {
            $s = self::seedBytes(substr($v, 6));
            if ($es) {
                $s[0] = chr(ord($s[0]) & 0x7f);
            }
            return $s;
        }
        return (string)Pca::unb64u($v);
    }

    /** A corpus key spec -> the native key: raw seed / public key (EdDSA) or a JWK (ES256). */
    private static function key(mixed $spec, bool $priv): mixed
    {
        if ($spec->get('alg') === 'EdDSA') {
            return $priv ? self::member($spec->get('seed'), false) : (string)Pca::unb64u($spec->get('pub'));
        }
        $o = Obj::of(['kty' => 'EC', 'crv' => 'P-256']);
        if ($priv) {
            $o->set('d', Pca::b64u(self::member($spec->get('d'), true)));
        }
        $o->set('x', $spec->get('x'));
        $o->set('y', $spec->get('y'));
        return $o;
    }

    private static function fromCj(mixed $v): mixed
    {
        if ($v instanceof Num) {
            $f = $v->float();
            if ($f == 0.0 && str_starts_with($v->lexeme, '-')) {
                return -0.0; // JSON.parse reads "-0" as negative zero
            }
            return $f == floor($f) && abs($f) <= 9007199254740991.0 ? (int)$f : $f;
        }
        if (is_array($v)) {
            return array_map(self::fromCj(...), $v);
        }
        if ($v instanceof Obj) {
            if ($v->has('$bytes')) {
                return new Bytes((string)Pca::unb64u($v->get('$bytes')));
            }
            if ($v->has('$map')) {
                $pairs = [];
                foreach ($v->get('$map') as $kv) {
                    $key = self::fromCj($kv[0]);
                    $pairs[] = [$key === 0.0 ? 0 : $key, self::fromCj($kv[1])]; // a JS Map keeps -0 as +0
                }
                return CborMap::of($pairs);
            }
            if ($v->has('$tag')) {
                return new CborTag(self::fromCj($v->get('$tag')), self::fromCj($v->get('v')));
            }
            throw new \InvalidArgumentException('bad cj');
        }
        return $v;
    }

    private static function toCj(mixed $v): mixed
    {
        if ($v instanceof Bytes) {
            return Base::outBytes($v->raw);
        }
        if ($v instanceof CborTag) {
            return Obj::of(['$tag' => $v->tag, 'v' => self::toCj($v->value)]);
        }
        if ($v instanceof CborMap) {
            return Obj::of(['$map' => array_map(fn(array $e) => [$e[0], self::toCj($e[1])], $v->entries())]);
        }
        if (is_array($v)) {
            return array_map(self::toCj(...), $v);
        }
        return $v;
    }

    /** One bytes argument, or a list of them. */
    private static function bs(mixed $v): mixed
    {
        return is_array($v) ? array_map(self::bs(...), $v) : Base::bytes($v);
    }

    private static function ob(?string $raw): mixed
    {
        return $raw === null ? null : Base::outBytes($raw);
    }

    /** @param list<string> $l */
    private static function obs(array $l): array
    {
        return array_map(self::ob(...), $l);
    }

    private static function wrap(array $r, array $bytesKeys): array
    {
        foreach ($bytesKeys as $k) {
            if (array_key_exists($k, $r)) {
                $r[$k] = self::ob($r[$k]);
            }
        }
        return $r;
    }

    // ---- fn adapters --------------------------------------------------------------------------------------------------

    /** The signing options a corpus spec {alg, key, issuer, subject?, contentType?} stands for. */
    private static function signOpts(Obj $spec): array
    {
        $o = ['alg' => $spec->get('alg'), 'key' => self::key($spec->get('key'), true)];
        foreach (['issuer', 'subject', 'contentType'] as $m) {
            if ($spec->has($m)) {
                $o[$m] = $spec->get($m);
            }
        }
        return $o;
    }

    private static function verifyOpts(mixed $op): array
    {
        $o = [];
        if (!($op instanceof Obj)) {
            return $o;
        }
        if ($op->has('treeRoot')) {
            $o['treeRoot'] = $op->get('treeRoot');
        }
        foreach (['verificationKey', 'statementKey'] as $m) {
            if ($op->has($m)) { // a member that is present is passed (null as is, so it is checked and refused)
                $o[$m] = $op->get($m) === null ? null : self::key($op->get($m), false);
            }
        }
        if ($op->has('allowHighS')) {
            $o['allowHighS'] = $op->get('allowHighS');
        }
        return $o;
    }

    private static function decodeCose(array $a): array
    {
        $c = Scitt::decodeCoseSign1(self::bs($a[0]));
        return [
            'protectedBytes' => self::ob($c['protectedBytes']), 'protectedMap' => self::toCj($c['protectedMap']), 'unprotected' => self::toCj($c['unprotected']),
            'payload' => self::ob($c['payload']), 'signature' => self::ob($c['signature']),
        ];
    }

    private static function es256SignVerify(Obj $key, mixed $payload, string $issuer): array
    {
        $st = Scitt::signStatement($payload, ['alg' => 'ES256', 'key' => self::key($key, true), 'issuer' => $issuer]);
        $c = Scitt::decodeCoseSign1($st);
        $pub = self::key(Obj::of(['alg' => 'ES256', 'x' => $key->get('x'), 'y' => $key->get('y')]), false);
        return [
            'check' => Scitt::checkStatement($st, $pub), 'payload' => self::ob(Scitt::statementPayload($st)),
            'lowS' => strcmp(bin2hex(substr($c['signature'], 32)), self::HALF_N) <= 0, 'protectedBytes' => self::ob($c['protectedBytes']),
        ];
    }

    private static function es256Receipt(Obj $key, mixed $n, mixed $index, Obj $edPriv, Obj $wrongPub): array
    {
        $n = (int)\Atlas\Pca\Js::num($n);
        $ts = new TransparencyService(['alg' => 'ES256', 'key' => self::key($key, true), 'issuer' => 'ts']);
        $edSeed = self::key($edPriv, true);
        $sts = [];
        for ($i = 0; $i < $n; $i++) {
            $sts[] = $ts->appendAndReceipt(Obj::of(['i' => new \Atlas\Pca\Num((string)$i)]), ['alg' => 'EdDSA', 'key' => $edSeed, 'issuer' => 'iss'])['statement'];
        }
        $pub = self::key(Obj::of(['alg' => 'ES256', 'x' => $key->get('x'), 'y' => $key->get('y')]), false);
        $r = $ts->getReceipt($index);
        $ix = (int)\Atlas\Pca\Js::num($index);
        $st = $sts[$ix];
        $edPub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($edSeed));
        return [
            'key' => Scitt::verifyReceipt($r['receipt'], $st, ['verificationKey' => $pub]),
            'root' => Scitt::verifyReceipt($r['receipt'], $st, ['treeRoot' => $r['root']]),
            'both' => Scitt::verifyReceipt($r['receipt'], $st, ['treeRoot' => $r['root'], 'verificationKey' => $pub, 'statementKey' => $edPub]),
            'wrongKey' => Scitt::verifyReceipt($r['receipt'], $st, ['verificationKey' => self::key($wrongPub, false)]),
            'otherStatement' => Scitt::verifyReceipt($r['receipt'], $sts[($ix + 1) % $n] ?? "\0\0\0", ['verificationKey' => $pub]),
            'none' => Scitt::verifyReceipt($r['receipt'], $st),
        ];
    }

    private static function service(Obj $spec): array
    {
        $key = self::key($spec->get('key'), true);
        $alg = $spec->get('key')->get('alg');
        $opts = ['alg' => $alg, 'key' => $key];
        if ($spec->has('issuer')) {
            $opts['issuer'] = $spec->get('issuer');
        }
        $memory = $spec->get('kind') === 'memory';
        if ($memory) {
            $svc = new TransparencyService($opts);
        } else {
            $f = $spec->has('storeFault') ? $spec->get('storeFault') : null;
            $svc = new DurableTransparencyService($opts + ['store' => $f !== null ? new FaultyStore($f) : new MemoryScittLogStore()]);
        }
        $stmtKey = self::key($spec->get('stmtKey'), true);
        $res = [];
        foreach ($spec->get('ops') as $op) {
            try {
                switch ($op->get('op')) {
                    case 'append':
                        $so = ['alg' => 'EdDSA', 'key' => $stmtKey, 'issuer' => 'https://issuer.example'];
                        if ($op->has('subject')) {
                            $so['subject'] = $op->get('subject');
                        }
                        if ($op->has('contentType')) {
                            $so['contentType'] = $op->get('contentType');
                        }
                        $v = self::wrap($svc->appendAndReceipt($op->get('payload'), $so), ['statement', 'receipt']);
                        break;
                    case 'register':
                        $v = self::wrap($svc->register((string)self::bs($op->get('statement'))), ['receipt']);
                        break;
                    case 'receipt':
                        $v = self::wrap($svc->getReceipt($op->get('i')), ['receipt']);
                        break;
                    case 'consistency':
                        $v = self::wrap($svc->consistencyProof($op->get('m')), ['proof']);
                        break;
                    case 'entry':
                        $v = self::ob($svc->getEntry($op->get('i')));
                        break;
                    case 'snapshot':
                        if (!$memory) {
                            throw new \BadMethodCallException('no snapshot');
                        }
                        $v = $svc->snapshot();
                        break;
                    case 'root':
                        $v = $svc->root();
                        break;
                    case 'size':
                        $v = $svc->size();
                        break;
                    default:
                        throw new \InvalidArgumentException('op');
                }
                $res[] = Obj::of(['ok' => $v]);
            } catch (\Throwable $e) {
                $res[] = Obj::of(['err' => property_exists($e, 'codeName') && is_string($e->codeName) ? $e->codeName : true]);
            }
        }
        return $res;
    }

    private static function path(): string
    {
        self::$n++;
        $dir = sys_get_temp_dir() . '/scitt-php-' . getmypid();
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        return $dir . '/f' . self::$n . '.log';
    }

    private static function fileStoreBytes(array $ops): Obj
    {
        $p = self::path();
        $s = FileScittLogStore::open($p);
        try {
            foreach ($ops as $op) {
                $nodes = [];
                foreach ($op->get('nodes') as $n) {
                    $nodes[] = ['level' => $n[0], 'index' => $n[1], 'hash' => Pca::unb64u($n[2]) ?? ''];
                }
                try {
                    $s->append($op->get('expected'), (string)self::bs($op->get('entry')), $nodes);
                } catch (\Throwable) {
                    // a refused / malformed append writes nothing
                }
            }
        } finally {
            $s->close();
        }
        return Base::outBytes((string)file_get_contents($p));
    }

    private static function fileStoreOpen(mixed $blob): array
    {
        $p = self::path();
        file_put_contents($p, (string)self::bs($blob));
        $s = FileScittLogStore::open($p);
        try {
            $size = $s->size();
            $entries = [];
            $nodes0 = [];
            for ($i = 0; $i < $size; $i++) {
                $entries[] = self::ob($s->getEntry($i));
                $nodes0[] = self::ob($s->getNode(0, $i));
            }
        } finally {
            $s->close();
        }
        return ['size' => $size, 'entries' => $entries, 'nodes0' => $nodes0, 'after' => Base::outBytes((string)file_get_contents($p))];
    }

    private static function checkStore(string $kind): array
    {
        if ($kind === 'memory') {
            return ScittLog::checkScittLogStore(fn() => new MemoryScittLogStore());
        }
        return ScittLog::checkScittLogStore(fn() => FileScittLogStore::open(self::path()));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'cborEncode' => fn(array $a) => Base::outBytes(Scitt::encode(self::fromCj($a[0]))),
            'cborDecode' => fn(array $a) => self::toCj(Scitt::decode(self::bs($a[0]))),
            'emptyRoot' => fn(array $a) => Base::outBytes(Scitt::emptyRoot()),
            'leafHash' => fn(array $a) => Base::outBytes(Scitt::leafHash(self::bs($a[0]))),
            'nodeHash' => fn(array $a) => Base::outBytes(Scitt::nodeHash(self::bs($a[0]), self::bs($a[1]))),
            'treeHash' => fn(array $a) => Base::outBytes(Scitt::treeHash(self::bs($a[0]))),
            'inclusionPath' => fn(array $a) => self::obs(Scitt::inclusionPath(self::bs($a[0]), $a[1])),
            'rootFromInclusionPath' => fn(array $a) => self::ob(Scitt::rootFromInclusionPath(self::bs($a[0]), $a[1], $a[2], self::bs($a[3]))),
            'verifyInclusionPath' => fn(array $a) => Scitt::verifyInclusionPath(self::bs($a[0]), $a[1], $a[2], self::bs($a[3]), self::bs($a[4])),
            'consistencyPath' => fn(array $a) => self::obs(Scitt::consistencyPath(self::bs($a[0]), $a[1])),
            'verifyConsistencyPath' => fn(array $a) => Scitt::verifyConsistencyPath($a[0], $a[1], self::bs($a[2]), self::bs($a[3]), self::bs($a[4])),
            'siblingSides' => fn(array $a) => Scitt::siblingSides($a[0], $a[1]),
            'encodeInclusionProof' => fn(array $a) => Base::outBytes(Scitt::encodeInclusionProof($a[0])),
            'decodeInclusionProof' => fn(array $a) => Scitt::decodeInclusionProof(self::bs($a[0])),
            'signStatement' => fn(array $a) => Base::outBytes(Scitt::signStatement($a[0], self::signOpts($a[1]))),
            'decodeCoseSign1' => fn(array $a) => self::decodeCose($a),
            'checkStatement' => fn(array $a) => Scitt::checkStatement(self::bs($a[0]), self::key($a[1], false), $a[2] ?? null),
            'verifyStatement' => fn(array $a) => Scitt::verifyStatement(self::bs($a[0]), self::key($a[1], false), $a[2] ?? null),
            'statementPayload' => fn(array $a) => Base::outBytes(Scitt::statementPayload(self::bs($a[0]))),
            'statementLeaf' => fn(array $a) => Scitt::statementLeaf(self::bs($a[0])),
            'buildReceipt' => fn(array $a) => Base::outBytes(Scitt::buildReceipt($a[0], $a[1], self::signOpts($a[2]))),
            'verifyReceipt' => fn(array $a) => Scitt::verifyReceipt(self::bs($a[0]), self::bs($a[1]), self::verifyOpts($a[2] ?? null)),
            'verifyConsistencyProof' => fn(array $a) => Scitt::verifyConsistencyProof(self::bs($a[0]), $a[1], $a[2]),
            'constants' => fn(array $a) => Obj::of(array_combine(
                ['COSE_SIGN1_TAG', 'HDR_ALG', 'HDR_CONTENT_TYPE', 'HDR_CWT_CLAIMS', 'CWT_ISS', 'CWT_SUB', 'HDR_VDS', 'HDR_VDS_PROOFS', 'VDS_RFC9162_SHA256', 'PROOF_TYPE_INCLUSION', 'DEFAULT_CONTENT_TYPE'],
                array_map(fn(string $c) => constant(Scitt::class . '::' . $c), ['COSE_SIGN1_TAG', 'HDR_ALG', 'HDR_CONTENT_TYPE', 'HDR_CWT_CLAIMS', 'CWT_ISS', 'CWT_SUB', 'HDR_VDS', 'HDR_VDS_PROOFS', 'VDS_RFC9162_SHA256', 'PROOF_TYPE_INCLUSION', 'DEFAULT_CONTENT_TYPE']),
            )),
            'es256SignVerify' => fn(array $a) => self::es256SignVerify($a[0], $a[1], $a[2]),
            'es256Receipt' => fn(array $a) => self::es256Receipt($a[0], $a[1], $a[2], $a[3], $a[4]),
            'service' => fn(array $a) => self::service($a[0]),
            'fileStoreBytes' => fn(array $a) => self::fileStoreBytes($a[0]),
            'fileStoreOpen' => fn(array $a) => self::fileStoreOpen($a[0]),
            'checkScittLogStore' => fn(array $a) => self::checkStore((string)$a[0]),
        ]);
    }

    public function testFileStoreReopensWhatItWrote(): void
    {
        $p = self::path();
        $s = FileScittLogStore::open($p);
        $svc = new DurableTransparencyService(['store' => $s, 'alg' => 'EdDSA', 'key' => str_repeat("\0", 32)]);
        for ($i = 0; $i < 5; $i++) {
            $svc->appendAndReceipt(Obj::of(['i' => new \Atlas\Pca\Num((string)$i)]), ['alg' => 'EdDSA', 'key' => str_repeat("\x01", 32), 'issuer' => 'iss']);
        }
        $root = $svc->root();
        $s->close();
        $again = new DurableTransparencyService(['store' => FileScittLogStore::open($p), 'alg' => 'EdDSA', 'key' => str_repeat("\0", 32)]);
        $this->assertSame(5, $again->size());
        $this->assertSame($root, $again->root());
    }

    /** A key that is passed but null / empty is checked (and fails), never skipped; only an omitted key means "no key". */
    public function testVerifyReceiptPresentButEmptyKeyIsRefused(): void
    {
        $seed = hash('sha256', 'scitt-empty-key', true);
        $ts = new TransparencyService(['alg' => 'EdDSA', 'key' => $seed, 'issuer' => 'ts']);
        $r0 = $ts->appendAndReceipt(Obj::of(['i' => 0]), ['alg' => 'EdDSA', 'key' => $seed, 'issuer' => 'iss']);
        $st = $r0['statement'];
        $rc = $ts->getReceipt(0);
        $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $this->assertTrue(Scitt::verifyReceipt($rc['receipt'], $st, ['verificationKey' => $pub]));
        $this->assertTrue(Scitt::verifyReceipt($rc['receipt'], $st, ['treeRoot' => $rc['root']]));
        foreach (['', null] as $bad) {
            $this->assertFalse(Scitt::verifyReceipt($rc['receipt'], $st, ['verificationKey' => $bad]));
            $this->assertFalse(Scitt::verifyReceipt($rc['receipt'], $st, ['treeRoot' => $rc['root'], 'verificationKey' => $bad]));
            $this->assertFalse(Scitt::verifyReceipt($rc['receipt'], $st, ['treeRoot' => $rc['root'], 'statementKey' => $bad]));
        }
    }

    public function testServicesRefuseAnEmptySigningKey(): void
    {
        foreach ([null, ''] as $bad) {
            try {
                new TransparencyService(['alg' => 'EdDSA', 'key' => $bad]);
                $this->fail('a TransparencyService accepted an empty key');
            } catch (\InvalidArgumentException) {
                $this->assertTrue(true);
            }
            try {
                new DurableTransparencyService(['store' => new MemoryScittLogStore(), 'alg' => 'EdDSA', 'key' => $bad]);
                $this->fail('a DurableTransparencyService accepted an empty key');
            } catch (\InvalidArgumentException) {
                $this->assertTrue(true);
            }
        }
    }
}

/** The reference's store fault injection over the in-memory store. */
final class FaultyStore
{
    private MemoryScittLogStore $inner;

    public function __construct(private readonly Obj $f)
    {
        $this->inner = new MemoryScittLogStore();
    }

    private function flag(string $k): mixed
    {
        return $this->f->has($k) ? $this->f->get($k) : null;
    }

    public function size(): int
    {
        return $this->flag('negSize') ? -1 : $this->inner->size();
    }

    public function getEntry(mixed $i): ?string
    {
        return $this->inner->getEntry($i);
    }

    public function getNode(mixed $level, mixed $i): ?string
    {
        $drop = $this->flag('dropNode');
        if (is_array($drop) && \Atlas\Pca\Js::num($drop[0]) === \Atlas\Pca\Js::num($level) && \Atlas\Pca\Js::num($drop[1]) === \Atlas\Pca\Js::num($i)) {
            return null;
        }
        $short = $this->flag('shortNode');
        if (is_array($short) && \Atlas\Pca\Js::num($short[0]) === \Atlas\Pca\Js::num($level) && \Atlas\Pca\Js::num($short[1]) === \Atlas\Pca\Js::num($i)) {
            return str_repeat("\0", 31);
        }
        return $this->inner->getNode($level, $i);
    }

    public function append(mixed $n, string $e, array $nodes): bool
    {
        return $this->flag('stale') ? false : $this->inner->append($n, $e, $nodes);
    }
}
