<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Webbotauth;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Web Bot Auth against the TS reference: test-data/ref-webbotauth.json.gz (RFC 9421 message signatures in the web-bot-auth profile
 * including the RFC and draft vectors, the signed key directory, Content-Digest, the PCA proof binding, the replay cache and the scripted
 * directory fetch). Ed25519 is deterministic, so signed output compares byte for byte. A reason "invalid PCActn in PCA-Action: <detail>"
 * is cut after the colon (the detail quotes the reference's own parser).
 */
final class RefWebbotauthDifferentialTest extends TestCase
{
    private const FILE = 'ref-webbotauth.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** The oracle's key-resolver spec: keyid => {"$bytes"} | JWK | null | {"$throw": true}; an unlisted keyid resolves to null. */
    private static function resolver(Obj $spec): \Closure
    {
        return static function (string $kid) use ($spec): mixed {
            $v = $spec->get($kid);
            if ($v instanceof Obj && $v->get('$throw') === true) {
                throw new \RuntimeException('resolver down');
            }
            return $v instanceof Obj && $v->has('$bytes') ? Base::bytes($v) : $v;
        };
    }

    private static function cache(mixed $spec): mixed
    {
        return match (true) {
            $spec === 'always' => static fn(string $k, float $e, float $n): bool => true,
            $spec === 'never' => static fn(string $k, float $e, float $n): bool => false,
            $spec === 'throw' => static function (string $k, float $e, float $n): bool {
                throw new \RuntimeException('cache down');
            },
            $spec === 'memory' => Webbotauth::memoryReplayCache(),
            is_string($spec) && str_starts_with($spec, 'memory:') => Webbotauth::memoryReplayCache((int)substr($spec, 7)),
            default => throw new \InvalidArgumentException('unknown cache spec'),
        };
    }

    private static function vopts(Obj $op): Obj
    {
        $out = new Obj();
        foreach ($op->keys() as $k) {
            $v = $op->get($k);
            $out->set($k, match (true) {
                $k === 'resolveKey' && $v instanceof Obj => self::resolver($v),
                $k === 'maxLifetimeSec' && $v === 'Infinity' => INF,
                $k === 'replayCache' => self::cache($v),
                default => $v,
            });
        }
        return $out;
    }

    private static function norm(array $r): array
    {
        if (isset($r['reason']) && is_string($r['reason'])) {
            $r['reason'] = preg_replace('/\A(invalid PCActn in PCA-Action): .*\z/s', '$1', $r['reason']);
        }
        return $r;
    }

    /** @return list<array<string,mixed>> directory key inputs with the {"$bytes"} public keys as raw bytes */
    private static function dirKeys(mixed $list): array
    {
        $keys = [];
        foreach ($list as $k) {
            $e = new Obj();
            foreach ($k->keys() as $n) {
                $e->set($n, $n === 'publicKey' ? Base::bytes($k->get($n)) : $k->get($n));
            }
            $keys[] = $e;
        }
        return $keys;
    }

    private static function body(mixed $b): mixed
    {
        return Base::bytes($b);
    }

    private static function verify(array $a): mixed
    {
        $times = count($a) > 2 ? (int)Js::num($a[2]) : 1;
        $vo = self::vopts($a[1]);
        $rs = [];
        for ($i = 0; $i < $times; $i++) {
            $rs[] = self::norm(Webbotauth::verifySignedRequest($a[0], $vo));
        }
        return $times === 1 ? $rs[0] : $rs;
    }

    private static function fetch(array $a): array
    {
        $spec = $a[1];
        $res = $spec->get('response');
        $called = null;
        $fetcher = static function (string $url, array $headers, int $timeout) use ($res, &$called): array {
            $called = Obj::of(['url' => $url, 'headers' => Obj::of($headers), 'redirect' => 'error']);
            if ($res === 'throw') {
                throw new \RuntimeException('network down');
            }
            $hs = [];
            $h = $res->get('headers');
            foreach ($h instanceof Obj ? $h->keys() : [] as $n) {
                $hs[strtolower($n)] = $h->get($n);
            }
            return ['status' => (int)Js::num($res->get('status')), 'headers' => $hs, 'body' => $res->get('body')];
        };
        $options = new Obj();
        $given = $spec->get('options');
        foreach ($given instanceof Obj ? $given->keys() : [] as $k) {
            $options->set($k, $given->get($k));
        }
        $options->set('fetch', $fetcher);
        $out = [];
        try {
            $out['directory'] = Webbotauth::fetchKeyDirectory($a[0], $options);
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            $out['error'] = true;
            $out['message'] = str_starts_with($msg, 'directory ') || $msg === 'Invalid URL' ? preg_replace('/\A(directory signature): .*\z/s', '$1', $msg) : 'other';
        }
        $out['called'] = $called;
        return $out;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => fn(array $a) => [
                'tag' => Webbotauth::WEB_BOT_AUTH_TAG, 'alg' => Webbotauth::WEB_BOT_AUTH_ALG, 'path' => Webbotauth::WELL_KNOWN_DIRECTORY_PATH,
                'ct' => Webbotauth::DIRECTORY_CONTENT_TYPE, 'label' => Webbotauth::DEFAULT_SIGNATURE_LABEL, 'exp' => Webbotauth::DEFAULT_EXPIRES_SEC,
                'agent' => Webbotauth::SIGNATURE_AGENT_HEADER, 'pca' => Webbotauth::PCA_HEADER, 'comp' => Webbotauth::PCA_PROOF_COMPONENT,
                'cd' => Webbotauth::CONTENT_DIGEST_HEADER, 'algs' => Webbotauth::CONTENT_DIGEST_ALGS, 'dtag' => Webbotauth::DIRECTORY_SIGNATURE_TAG,
            ],
            'jwkThumbprint' => fn(array $a) => Webbotauth::jwkThumbprint(Base::bytes($a[0])),
            'signRequest' => fn(array $a) => Webbotauth::signRequest($a[0]),
            'verifySignedRequest' => fn(array $a) => self::verify($a),
            'verifySignedRequestWithProof' => fn(array $a) => self::norm(Webbotauth::verifySignedRequestWithProof($a[0], self::vopts($a[1]))),
            'buildKeyDirectory' => fn(array $a) => Webbotauth::buildKeyDirectory(self::dirKeys($a[0])),
            'resolveFromDirectory' => fn(array $a) => Webbotauth::resolveFromDirectory($a[0], $a[1]),
            'directoryHandler' => function (array $a): array {
                $h = Webbotauth::directoryHandler(self::dirKeys($a[0]));
                return array_map($h, $a[1]);
            },
            'memoryReplayCache' => function (array $a): array {
                $c = $a[0] === null ? Webbotauth::memoryReplayCache() : Webbotauth::memoryReplayCache((int)Js::num($a[0]));
                $out = [];
                foreach ($a[1] as $op) {
                    try {
                        $out[] = $c->claim($op[0], (float)Js::num($op[1]), (float)Js::num($op[2]));
                    } catch (\Throwable) {
                        $out[] = 'throw';
                    }
                }
                return $out;
            },
            'proofHeaders' => fn(array $a) => Webbotauth::proofHeaders($a[0]),
            'decodeProofHeader' => fn(array $a) => Webbotauth::decodeProofHeader($a[0]),
            'signRequestWithProof' => fn(array $a) => Webbotauth::signRequestWithProof($a[0]),
            'contentDigestBytes' => fn(array $a) => Base::outBytes(Webbotauth::contentDigestBytes(self::body($a[0]), $a[1])),
            'contentDigestHeader' => fn(array $a) => count($a) > 1 ? Webbotauth::contentDigestHeader(self::body($a[0]), $a[1]) : Webbotauth::contentDigestHeader(self::body($a[0])),
            'parseContentDigest' => function (array $a): Obj {
                $o = new Obj();
                foreach (Webbotauth::parseContentDigest($a[0]) as $name => $bytes) {
                    $o->set((string)$name, Base::outBytes($bytes));
                }
                return $o;
            },
            'verifyContentDigest' => function (array $a): array {
                $req = count($a) > 2 && $a[2] instanceof Obj ? $a[2]->get('require') : null;
                return Webbotauth::verifyContentDigest($a[0], self::body($a[1]), $req);
            },
            'parseKeyDirectory' => fn(array $a) => Webbotauth::parseKeyDirectory($a[0]),
            'signDirectoryResponse' => fn(array $a) => Webbotauth::signDirectoryResponse($a[0]),
            'verifyDirectoryResponse' => fn(array $a) => Webbotauth::verifyDirectoryResponse($a[0]),
            'fetchKeyDirectory' => fn(array $a) => self::fetch($a),
        ]);
    }
}
