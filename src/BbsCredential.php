<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is `iss`, `sub`, then one
 * message per caveat named `cav:<i>:<type>` whose value is the strict-canonical JSON of the caveat; each message's octets are
 * utf8(name) || 0x00 || utf8(value). Capabilities, credentials, attributes and presentations are parsed-JSON `Obj`s with the same
 * member names as the TypeScript types. The verifiers never throw: a malformed structure is a plain `false`.
 */
final class BbsCredential
{
    private function __construct()
    {
    }

    /** UTF-8 with U+FFFD for a lone surrogate (what a JavaScript TextEncoder produces; the parser keeps lone surrogates as WTF-8). */
    private static function utf8(string $s): string
    {
        return (string) preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $s);
    }

    public static function encodeAttribute(mixed $name, mixed $value): string
    {
        if (!is_string($name) || !is_string($value)) {
            throw new \InvalidArgumentException('attribute name and value must be strings');
        }
        if (str_contains($name, "\0")) {
            throw new \InvalidArgumentException('attribute name must not contain NUL');
        }
        return self::utf8($name) . "\0" . self::utf8($value);
    }

    private static function obj(mixed $o): Obj
    {
        if (!$o instanceof Obj) {
            throw new \InvalidArgumentException('not an object');
        }
        return $o;
    }

    /** @return list<mixed> */
    private static function list(mixed $o): array
    {
        if (!is_array($o) || !array_is_list($o)) {
            throw new \InvalidArgumentException('not an array');
        }
        return $o;
    }

    private static function encode(mixed $attr): string
    {
        $a = self::obj($attr);
        return self::encodeAttribute($a->get('name'), $a->get('value'));
    }

    /** @return list<string> */
    private static function encodeAll(mixed $attrs): array
    {
        return array_map(self::encode(...), self::list($attrs));
    }

    private static function attr(int $index, string $name, mixed $value): Obj
    {
        return Obj::of(['index' => $index, 'name' => $name, 'value' => $value]);
    }

    /** The ordered attribute vector for a capability: issuer, holder, then each caveat. @return list<Obj> */
    public static function capabilityAttributes(Obj $capability): array
    {
        $attrs = [self::attr(0, 'iss', $capability->get('issuer')), self::attr(1, 'sub', $capability->get('holder'))];
        $cs = $capability->get('caveats');
        if (is_array($cs) && array_is_list($cs)) {
            foreach ($cs as $i => $cv) {
                $cv = self::obj($cv);
                $type = $cv->get('type');
                if (!is_string($type)) {
                    throw new \InvalidArgumentException('caveat type must be a string');
                }
                $attrs[] = self::attr($i + 2, "cav:$i:$type", Json::canonicalizeNative($cv));
            }
        }
        return $attrs;
    }

    /** Sign a capability's attributes as a BBS credential; `$header` is optional application context. */
    public static function issueCapabilityCredential(Obj $capability, \GMP $sk, string $pk, ?string $header = null): Obj
    {
        $attributes = self::capabilityAttributes($capability);
        $hdr = $header ?? '';
        $signature = Bbs::sign($sk, $pk, $hdr, self::encodeAll($attributes));
        return Obj::of([
            'issuerPublicKey' => Pca::b64u($pk),
            'header' => Pca::b64u($hdr),
            'attributes' => $attributes,
            'signature' => Pca::b64u($signature),
        ]);
    }

    /** Verify a whole credential against its issuer key (every attribute). Never throws. */
    public static function verifyCredential(mixed $cred): bool
    {
        try {
            $c = self::obj($cred);
            $pk = Pca::unb64u($c->get('issuerPublicKey'));
            $header = Pca::unb64u($c->get('header'));
            $signature = Pca::unb64u($c->get('signature'));
            if ($pk === null || $header === null || $signature === null) {
                return false;
            }
            return Bbs::verify($pk, $signature, $header, self::encodeAll($c->get('attributes')));
        } catch (\Throwable) {
            return false;
        }
    }

    private static function indexOf(mixed $attr): int
    {
        $i = self::obj($attr)->get('index');
        $d = $i instanceof Num ? $i->float() : (is_int($i) ? (float) $i : NAN);
        if (!is_finite($d) || $d !== floor($d) || abs($d) > 2147483647) {
            throw new \InvalidArgumentException('attribute index is not an integer');
        }
        return (int) $d;
    }

    /**
     * Selective-disclosure presentation revealing only the named attributes; `$presentationHeader` binds it to a context. The proof is
     * randomized, so it is covered by round trips, not byte comparison.
     *
     * @param list<string> $disclose
     */
    public static function presentCredential(Obj $cred, array $disclose, ?string $presentationHeader = null): Obj
    {
        $pk = Pca::unb64u($cred->get('issuerPublicKey'));
        $header = Pca::unb64u($cred->get('header'));
        $signature = Pca::unb64u($cred->get('signature'));
        if ($pk === null || $header === null || $signature === null) {
            throw new \InvalidArgumentException('presentCredential: credential fields are not canonical base64url');
        }
        $ph = $presentationHeader ?? '';
        $wanted = array_values(array_unique($disclose));
        $attrs = self::list($cred->get('attributes'));
        $messages = self::encodeAll($attrs);
        $idx = [];
        $disclosed = [];
        foreach ($attrs as $a) {
            if (in_array(self::obj($a)->get('name'), $wanted, true)) {
                $idx[] = self::indexOf($a);
                $disclosed[] = $a;
            }
        }
        $have = array_map(static fn($d) => $d->get('name'), $disclosed);
        $missing = array_values(array_filter($wanted, static fn($w) => !in_array($w, $have, true)));
        if ($missing !== []) {
            throw new \InvalidArgumentException('presentCredential: unknown attribute(s): ' . implode(', ', $missing));
        }
        $proof = Bbs::proofGen($pk, $signature, $header, $ph, $messages, $idx);
        return Obj::of([
            'issuerPublicKey' => $cred->get('issuerPublicKey'),
            'header' => $cred->get('header'),
            'presentationHeader' => Pca::b64u($ph),
            'messageCount' => count($attrs),
            'disclosed' => $disclosed,
            'proof' => Pca::b64u($proof),
        ]);
    }

    /**
     * Check a presentation. `$pk`, `$disclosed` and `$presentationHeader` default (when null) to the values the presentation carries;
     * pass them to assert the verifier's own expectations. Never throws.
     *
     * @param list<mixed>|null $disclosed
     */
    public static function verifyPresentation(mixed $pres, ?string $pk = null, ?array $disclosed = null, ?string $presentationHeader = null): bool
    {
        try {
            $p = self::obj($pres);
            $pkb = $pk ?? Pca::unb64u($p->get('issuerPublicKey'));
            $header = Pca::unb64u($p->get('header'));
            $proof = Pca::unb64u($p->get('proof'));
            if ($pkb === null || $header === null || $proof === null) {
                return false;
            }
            if ($pk !== null && Pca::b64u($pk) !== $p->get('issuerPublicKey')) {
                return false;
            }
            $ph = $presentationHeader ?? Pca::unb64u($p->get('presentationHeader'));
            if ($ph === null) {
                return false;
            }
            if ($presentationHeader !== null && $presentationHeader !== '' && Pca::b64u($ph) !== $p->get('presentationHeader')) {
                return false;
            }
            return self::verifyInner($p, $pkb, $header, $proof, $ph, $disclosed);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function key(mixed $x): string
    {
        $a = self::obj($x);
        if (!is_string($a->get('name')) || !is_string($a->get('value'))) {
            throw new \InvalidArgumentException('attribute name and value must be strings');
        }
        return self::indexOf($x) . "\0" . $a->get('name') . "\0" . $a->get('value');
    }

    private static function sameDisclosure(array $a, array $b): bool
    {
        if (count($a) !== count($b)) {
            return false;
        }
        $sa = array_map(self::key(...), $a);
        $sb = array_map(self::key(...), $b);
        sort($sa, SORT_STRING);
        sort($sb, SORT_STRING);
        return $sa === $sb;
    }

    private static function verifyInner(Obj $pres, string $pk, string $header, string $proof, string $ph, ?array $optsDisclosed): bool
    {
        $disclosed = $optsDisclosed ?? self::list($pres->get('disclosed'));
        if ($optsDisclosed !== null && !self::sameDisclosure($optsDisclosed, self::list($pres->get('disclosed')))) {
            return false;
        }
        $ordered = array_values($disclosed);
        $idx = array_map(self::indexOf(...), $ordered); // an attribute without an integer index fails closed
        $order = array_keys($idx);
        usort($order, static fn(int $x, int $y) => $idx[$x] <=> $idx[$y]); // stable
        $msgs = [];
        $sorted = [];
        foreach ($order as $o) {
            $msgs[] = self::encode($ordered[$o]);
            $sorted[] = $idx[$o];
        }
        $mc = $pres->get('messageCount');
        $count = $mc instanceof Num ? $mc->float() : (is_int($mc) ? (float) $mc : NAN); // NaN: no bound here, proofVerify checks the indexes
        foreach ($sorted as $i) {
            if ($i >= $count || $i < 0) {
                return false;
            }
        }
        return Bbs::proofVerify($pk, $proof, $header, $ph, $msgs, $sorted);
    }
}
