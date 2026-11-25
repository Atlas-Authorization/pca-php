<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Vc;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * did:key, the passport SD-JWT VC and RFC 9421 request signatures against the TS reference: test-data/ref-vc.json.gz. The
 * reference ran with its clock pinned to NOW, so every clock here is NOW too. Issuance compares a normalized form (salts are
 * random): header, payload without the digest list, [name, value] disclosures, digest agreement, and whether it verifies.
 */
final class RefVcDifferentialTest extends TestCase
{
    private const FILE = 'ref-vc.json.gz';
    private const NOW = 1_700_000_100_000;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** {"$bytes": b64u} at any depth becomes the raw bytes. */
    private static function rev(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return new Bytes((string)Pca::unb64u($v->get('$bytes')));
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::rev($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::rev(...), $v) : $v;
    }

    private static function p1(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x01", 32)));
    }

    private static function dec(string $seg): mixed
    {
        return Js::parse(Jose::lenientB64d($seg));
    }

    private static function normVc(string $sd): array
    {
        $parts = explode('~', $sd);
        $ds = array_slice($parts, 1, -1);
        [$h, $p] = array_map(self::dec(...), array_slice(explode('.', $parts[0]), 0, 2));
        $cs = $p->get('vc')?->get('credentialSubject');
        $sdl = $cs instanceof Obj ? ($cs->get('_sd') ?? []) : [];
        sort($sdl, SORT_STRING);
        if ($cs instanceof Obj) {
            $p->get('vc')->set('credentialSubject', $cs->without('_sd'));
        }
        try {
            Vc::verifyPassportVC($sd, self::p1(), ['nowMs' => self::NOW]);
            $verified = true;
        } catch (\Throwable) {
            $verified = false;
        }
        $dig = array_map(static fn(string $d) => Jose::b64u(hash('sha256', $d, true)), $ds);
        sort($dig, SORT_STRING);
        $disc = array_map(static fn(string $d) => array_slice(self::dec($d), 1, 2), $ds);
        usort($disc, static fn(array $a, array $b) => strcmp(mb_convert_encoding((string)$a[0], 'UTF-16BE', 'UTF-8'), mb_convert_encoding((string)$b[0], 'UTF-16BE', 'UTF-8')));
        return ['end' => $parts[count($parts) - 1], 'header' => $h, 'payload' => $p, 'n' => count($ds), 'digestsOk' => $dig === $sdl, 'disclosures' => $disc,
            'verified' => $verified];
    }

    private static function passportToVc(array $a): array
    {
        $o = $a[1];
        $m = ['issuerKey' => self::rev($o->get('issuer_seed')), 'now' => self::NOW];
        foreach (['issuer_did' => 'issuerDid', 'subject_did' => 'subjectDid', 'ttl_sec' => 'ttlSec'] as $k => $c) {
            if ($o->has($k)) {
                $m[$c] = $o->get($k);
            }
        }
        return self::normVc(Vc::passportToVC($a[0], $m));
    }

    private static function verifyVc(array $a): Obj
    {
        $m = ['nowMs' => self::NOW];
        if (($a[2] ?? null) instanceof Obj) {
            foreach ($a[2]->keys() as $k) {
                $m[$k] = $a[2]->get($k);
            }
        }
        return Vc::verifyPassportVC($a[0], self::rev($a[1]), $m);
    }

    private static function sign(Obj $a): Obj
    {
        $m = ['method' => $a->get('method'), 'url' => $a->get('url'), 'headers' => $a->get('headers'), 'key' => self::rev($a->get('key')), 'keyid' => $a->get('keyid')];
        if ($a->has('created')) {
            $m['created'] = $a->get('created') ?? intdiv(self::NOW, 1000); // the reference clock
        }
        if ($a->has('signature_agent')) {
            $m['signatureAgent'] = $a->get('signature_agent');
        }
        return Vc::signRequestMessage($m);
    }

    private static function verifyReq(Obj $a, mixed $key): bool
    {
        $m = [];
        foreach (['method' => 'method', 'url' => 'url', 'headers' => 'headers', 'signature_input' => 'signatureInput', 'signature' => 'signature',
            'signature_agent' => 'signatureAgent', 'required_components' => 'requiredComponents', 'max_age_sec' => 'maxAgeSec', 'now_sec' => 'nowSec'] as $k => $c) {
            if ($a->has($k)) {
                $m[$c] = $a->get($k);
            }
        }
        if (!array_key_exists('nowSec', $m) || $m['nowSec'] === null) {
            $m['nowSec'] = intdiv(self::NOW, 1000);
        }
        return Vc::verifyRequestSignature($m, self::rev($key));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'base58btcEncode' => fn(array $a) => Vc::base58btcEncode(self::rev($a[0])),
            'base58btcDecode' => fn(array $a) => Base::outBytes(Vc::base58btcDecode($a[0])->raw),
            'didKeyFromEd25519' => fn(array $a) => Vc::didKeyFromEd25519(self::rev($a[0])),
            'ed25519FromDidKey' => fn(array $a) => Base::outBytes(Vc::ed25519FromDidKey($a[0])->raw),
            'constants' => fn() => ['VC_CONTEXT' => Vc::VC_CONTEXT, 'AGENT_PASSPORT_CONTEXT' => Vc::AGENT_PASSPORT_CONTEXT, 'AGENT_PASSPORT_VC_TYPE' => Vc::AGENT_PASSPORT_VC_TYPE,
                'AGENT_PASSPORT_CONTEXT_DIGEST' => Vc::contextDigest(), 'AGENT_PASSPORT_CONTEXT_DOC' => Vc::contextDoc()],
            'resolveAgentPassportContext' => fn(array $a) => Vc::resolveAgentPassportContext($a[0]),
            'passportToVC' => fn(array $a) => self::passportToVc($a),
            'verifyPassportVC' => fn(array $a) => self::verifyVc($a),
            'signRequestMessage' => fn(array $a) => self::sign($a[0]),
            'verifyRequestSignature' => fn(array $a) => self::verifyReq($a[0], $a[1]),
        ]);
    }
}
