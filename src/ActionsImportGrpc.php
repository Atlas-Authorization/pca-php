<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsImport.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';

/** The parser state of one `.proto` source. @internal */
final class ProtoTextParser
{
    private int $i = 0;
    private string $pkg = '';
    private Obj $messages;
    private Obj $enums;
    /** @var list<array<string,mixed>> */
    private array $services = [];

    /** @param list<array{string,string}> $toks */
    public function __construct(private readonly array $toks, private readonly int $maxDepth)
    {
        $this->messages = new Obj();
        $this->enums = new Obj();
    }

    /** @return array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} */
    public function model(): array
    {
        return ['messages' => $this->messages, 'enums' => $this->enums, 'services' => $this->services];
    }

    /** @return array{string,string}|null */
    private function cur(): ?array
    {
        return $this->toks[$this->i] ?? null;
    }

    private function is(string $v): bool
    {
        $t = $this->cur();
        return $t !== null && $t[0] !== 'str' && $t[1] === $v;
    }

    private function eat(string $v): bool
    {
        if ($this->is($v)) {
            $this->i++;
            return true;
        }
        return false;
    }

    private function fail(string $msg): never
    {
        $t = $this->cur();
        throw new ActionKitError('bad_source', "proto parse error: $msg near '" . ActionsImport::clip($t !== null ? $t[1] : '<end>', 30) . "'");
    }

    private function expect(string $v): void
    {
        if (!$this->eat($v)) {
            $this->fail("expected '$v'");
        }
    }

    private function id(): string
    {
        $t = $this->cur();
        if ($t === null || $t[0] !== 'id') {
            $this->fail('expected an identifier');
        }
        $this->i++;
        return $t[1];
    }

    /** @return array{string,string}|null */
    private function take(): ?array
    {
        $t = $this->cur();
        $this->i++;
        return $t;
    }

    private function skipTo(string $open, string $close, int $depth = 1): void
    {
        while ($depth > 0) {
            $t = $this->take();
            if ($t === null) {
                $this->fail('unterminated block');
            }
            if ($t[0] === 'p') {
                if ($t[1] === $open) {
                    $depth++;
                } elseif ($t[1] === $close) {
                    $depth--;
                }
            }
        }
    }

    private function skipStatement(): void
    {
        while ($this->cur() !== null && !$this->is(';')) {
            if ($this->is('{')) {
                $this->i++;
                $this->skipTo('{', '}');
                return;
            }
            $this->i++;
        }
        $this->eat(';');
    }

    private static function qual(string $scope, string $name): string
    {
        return $scope === '' ? $name : "$scope.$name";
    }

    public function file(): void
    {
        while ($this->cur() !== null) {
            if ($this->eat(';')) {
                continue;
            }
            $kw = $this->id();
            if ($kw === 'package') {
                $this->pkg = $this->id();
                $this->expect(';');
            } elseif ($kw === 'message') {
                $this->message($this->pkg, 0);
            } elseif ($kw === 'enum') {
                $this->enumDef($this->pkg);
            } elseif ($kw === 'service') {
                $this->service();
            } elseif ($kw === 'extend') {
                $this->id();
                $this->expect('{');
                $this->skipTo('{', '}');
            } else {
                $this->skipStatement();
            }
        }
    }

    private function enumDef(string $scope): void
    {
        $full = self::qual($scope, $this->id());
        $this->expect('{');
        $values = [];
        while (!$this->is('}')) {
            if ($this->cur() === null) {
                $this->fail('unterminated enum');
            }
            if ($this->is('option') || $this->is('reserved')) {
                $this->skipStatement();
                continue;
            }
            $values[] = $this->id();
            $this->skipStatement();
        }
        $this->expect('}');
        $this->enums->set($full, ['full' => $full, 'values' => $values]);
    }

    /** @return list<string> */
    private function fieldOptions(): array
    {
        $behavior = [];
        if (!$this->eat('[')) {
            return $behavior;
        }
        $depth = 1;
        $inBehavior = false;
        while ($depth > 0) {
            $t = $this->take();
            if ($t === null) {
                $this->fail('unterminated field options');
            }
            if ($t[0] === 'p') {
                if ($t[1] === '[' || $t[1] === '{') {
                    $depth++;
                } elseif ($t[1] === ']' || $t[1] === '}') {
                    $depth--;
                } elseif ($t[1] === ',') {
                    $inBehavior = false;
                }
            } elseif ($t[0] === 'id') {
                if (str_ends_with($t[1], 'field_behavior')) {
                    $inBehavior = true;
                } elseif ($inBehavior && preg_match('/\A[A-Z_]+\z/', $t[1]) === 1) {
                    $behavior[] = $t[1];
                }
            }
        }
        return $behavior;
    }

    /** @param array<string,mixed> $msg */
    private function field(array &$msg, ?string $label, bool $oneof, string $full): void
    {
        $repeated = $label === 'repeated';
        $typ = $this->id();
        $fmap = null;
        if ($typ === 'map' && $this->eat('<')) {
            $k = $this->id();
            $this->expect(',');
            $v = $this->id();
            $this->expect('>');
            $fmap = [$k, $v];
            $typ = 'map';
            $repeated = false;
        }
        $fname = $this->id();
        $this->expect('=');
        $this->i++; // field number
        $behavior = $this->fieldOptions();
        $this->expect(';');
        $f = ['name' => $fname, 'type' => $typ, 'scope' => $full, 'repeated' => $repeated, 'optional' => $label === 'optional' || $oneof, 'behavior' => $behavior];
        if ($fmap !== null) {
            $f['map'] = $fmap;
        }
        $msg['fields'][] = $f;
    }

    private function message(string $scope, int $depth): void
    {
        if ($depth > $this->maxDepth) {
            throw new ActionKitError('import_limit', 'proto message nesting is too deep');
        }
        $full = self::qual($scope, $this->id());
        $msg = ['full' => $full, 'fields' => [], 'mapEntry' => false];
        $this->messages->set($full, $msg);
        $this->expect('{');
        while (!$this->is('}')) {
            $t = $this->cur();
            if ($t === null) {
                $this->fail('unterminated message');
            }
            if ($this->eat(';')) {
                continue;
            }
            $kw = $t[0] === 'id' ? $t[1] : '';
            if ($kw === 'message') {
                $this->i++;
                $this->message($full, $depth + 1);
                continue;
            }
            if ($kw === 'enum') {
                $this->i++;
                $this->enumDef($full);
                continue;
            }
            if ($kw === 'oneof') {
                $this->i++;
                $this->id();
                $this->expect('{');
                while (!$this->is('}')) {
                    if ($this->cur() === null) {
                        $this->fail('unterminated oneof');
                    }
                    if ($this->is('option')) {
                        $this->skipStatement();
                        continue;
                    }
                    $this->field($msg, null, true, $full);
                }
                $this->expect('}');
                continue;
            }
            if ($kw === 'option' || $kw === 'reserved' || $kw === 'extensions') {
                $this->skipStatement();
                continue;
            }
            if ($kw === 'extend') {
                $this->i++;
                $this->id();
                $this->expect('{');
                $this->skipTo('{', '}');
                continue;
            }
            if ($kw === 'group') {
                $this->skipStatement();
                continue;
            }
            if ($kw === 'repeated' || $kw === 'optional' || $kw === 'required') {
                $this->i++;
                $this->field($msg, $kw, false, $full);
                continue;
            }
            $this->field($msg, null, false, $full);
        }
        $this->expect('}');
        $this->messages->set($full, $msg); // the same slot: nested messages were added after it
    }

    private function stream(): bool
    {
        $t = $this->cur();
        if ($t !== null && $t[1] === 'stream' && $t[0] === 'id') {
            $this->i++;
            return true;
        }
        return false;
    }

    private function service(): void
    {
        $name = $this->id();
        $svc = ['full' => self::qual($this->pkg, $name), 'name' => $name, 'methods' => []];
        $this->expect('{');
        while (!$this->is('}')) {
            if ($this->cur() === null) {
                $this->fail('unterminated service');
            }
            if ($this->eat(';')) {
                continue;
            }
            if ($this->id() !== 'rpc') {
                $this->skipStatement();
                continue;
            }
            $mname = $this->id();
            $this->expect('(');
            $cs = $this->stream();
            $inp = $this->id();
            $this->expect(')');
            if ($this->id() !== 'returns') {
                $this->fail("expected 'returns'");
            }
            $this->expect('(');
            $ss = $this->stream();
            $out = $this->id();
            $this->expect(')');
            $m = ['name' => $mname, 'input' => $inp, 'output' => $out, 'cs' => $cs, 'ss' => $ss, 'scope' => $this->pkg];
            if ($this->eat('{')) {
                while (!$this->is('}')) {
                    if ($this->cur() === null) {
                        $this->fail('unterminated rpc body');
                    }
                    if (!$this->is('option')) {
                        $this->skipStatement();
                        continue;
                    }
                    $this->i++;
                    if ($this->eat('(')) {
                        $oname = $this->id();
                        $this->expect(')');
                    } else {
                        $oname = $this->id();
                    }
                    $this->expect('=');
                    if ($this->is('{')) {
                        $this->i++;
                        $depth = 1;
                        while ($depth > 0) {
                            $t = $this->take();
                            if ($t === null) {
                                $this->fail('unterminated option');
                            }
                            if ($t[0] === 'p') {
                                if ($t[1] === '{') {
                                    $depth++;
                                } elseif ($t[1] === '}') {
                                    $depth--;
                                }
                                continue;
                            }
                            if ($depth === 1 && str_ends_with($oname, 'http') && $t[0] === 'id' && in_array($t[1], ['get', 'put', 'post', 'delete', 'patch'], true) && $this->is(':')) {
                                $this->i++;
                                $c = $this->cur();
                                $path = $c !== null && $c[0] === 'str' ? $c[1] : '';
                                $this->i++;
                                if (!isset($m['http'])) {
                                    $m['http'] = ['method' => strtoupper($t[1]), 'path' => $path];
                                }
                            } elseif ($depth === 1 && str_ends_with($oname, 'http') && $t[0] === 'id' && $t[1] === 'body' && $this->is(':')) {
                                $this->i++;
                                $c = $this->cur();
                                if ($c !== null && $c[0] === 'str' && isset($m['http'])) {
                                    $m['http']['body'] = $c[1];
                                }
                                $this->i++;
                            }
                        }
                        $this->eat(';');
                    } else {
                        $v = $this->cur();
                        $this->i++;
                        if (str_ends_with($oname, 'idempotency_level') && $v !== null) {
                            $m['idem'] = $v[1];
                        }
                        $this->eat(';');
                    }
                }
                $this->expect('}');
                $this->eat(';');
            } else {
                $this->expect(';');
            }
            $svc['methods'][] = $m;
        }
        $this->expect('}');
        $this->services[] = $svc;
    }
}

/** A cursor over protobuf wire bytes. @internal */
final class ProtoReader
{
    public int $p = 0;
    public int $end;

    public function __construct(private readonly string $b, ?int $end = null)
    {
        $this->end = $end ?? strlen($b);
    }

    public function more(): bool
    {
        return $this->p < $this->end;
    }

    /** A JavaScript number: accumulated in double arithmetic, as the reference does (a 10-byte varint loses low bits). */
    public function varint(): float
    {
        $r = 0.0;
        $mul = 1.0;
        for ($k = 0; $k < 10; $k++) {
            if ($this->p >= $this->end) {
                throw new ActionKitError('bad_source', 'truncated descriptor');
            }
            $byte = ord($this->b[$this->p]);
            $this->p++;
            $r += (float)($byte & 0x7F) * $mul;
            if (($byte & 0x80) === 0) {
                return $r;
            }
            $mul *= 128.0;
        }
        throw new ActionKitError('bad_source', 'overlong varint in descriptor');
    }

    public function len(): self
    {
        $n = $this->varint();
        if ($n > $this->end - $this->p) {
            throw new ActionKitError('bad_source', 'descriptor length exceeds the buffer');
        }
        $r = new self($this->b, $this->p + (int)$n);
        $r->p = $this->p;
        $this->p += (int)$n;
        return $r;
    }

    public function skip(float $wt): void
    {
        if ($wt === 0.0) {
            $this->varint();
        } elseif ($wt === 1.0) {
            $this->adv(8);
        } elseif ($wt === 2.0) {
            $this->len();
        } elseif ($wt === 5.0) {
            $this->adv(4);
        } else {
            throw new ActionKitError('bad_source', 'unsupported wire type ' . (int)$wt . ' in descriptor');
        }
    }

    public function adv(int $n): void
    {
        if ($n > $this->end - $this->p) {
            throw new ActionKitError('bad_source', 'truncated descriptor');
        }
        $this->p += $n;
    }

    /** A length-delimited UTF-8 string, decoded as TextDecoder does (a leading byte-order mark dropped, invalid bytes become U+FFFD). */
    public function str(): string
    {
        $r = $this->len();
        $raw = substr($this->b, $r->p, $r->end - $r->p);
        if (str_starts_with($raw, "\xEF\xBB\xBF")) {
            $raw = substr($raw, 3);
        }
        return self::decode($raw);
    }

    private static function decode(string $s): string
    {
        if (preg_match('//u', $s) === 1) {
            return $s;
        }
        $out = '';
        $n = strlen($s);
        $i = 0;
        while ($i < $n) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $out .= $s[$i];
                $i++;
                continue;
            }
            if ($b >= 0xC2 && $b <= 0xDF) {
                [$need, $lo, $hi] = [1, 0x80, 0xBF];
            } elseif ($b === 0xE0) {
                [$need, $lo, $hi] = [2, 0xA0, 0xBF];
            } elseif (($b >= 0xE1 && $b <= 0xEC) || $b === 0xEE || $b === 0xEF) {
                [$need, $lo, $hi] = [2, 0x80, 0xBF];
            } elseif ($b === 0xED) {
                [$need, $lo, $hi] = [2, 0x80, 0x9F];
            } elseif ($b === 0xF0) {
                [$need, $lo, $hi] = [3, 0x90, 0xBF];
            } elseif ($b >= 0xF1 && $b <= 0xF3) {
                [$need, $lo, $hi] = [3, 0x80, 0xBF];
            } elseif ($b === 0xF4) {
                [$need, $lo, $hi] = [3, 0x80, 0x8F];
            } else {
                $out .= "\xEF\xBF\xBD";
                $i++;
                continue;
            }
            $j = $i + 1;
            $ok = true;
            for ($k = 0; $k < $need; $k++) {
                $c = $j < $n ? ord($s[$j]) : -1;
                if ($c < ($k === 0 ? $lo : 0x80) || $c > ($k === 0 ? $hi : 0xBF)) {
                    $ok = false;
                    break;
                }
                $j++;
            }
            $out .= $ok ? substr($s, $i, $j - $i) : "\xEF\xBF\xBD"; // a maximal invalid subpart is one replacement character
            $i = $j;
        }
        return $out;
    }
}

/**
 * Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet (native port of import/grpc.ts of the reference actions package).
 * `service.method` becomes the verb; `google.api.http` gives method and path; `idempotency_level` gives read / idempotent; field behavior (REQUIRED,
 * OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no code generation. A model is {messages: Obj full => {full, fields,
 * mapEntry}, enums: Obj full => {full, values}, services: [{full, name, methods}]}. The reference tells `.proto` text (a string) from a binary descriptor
 * set (a Uint8Array); here the text is a PHP string and the descriptor set is a {@see Bytes}.
 */
final class ActionsImportGrpc
{
    private const SCALAR_NAMES = ['double', 'float', 'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'fixed32', 'fixed64', 'sfixed32', 'sfixed64', 'bool', 'string', 'bytes'];
    private const ID_START = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.';
    private const ID_REST = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.0123456789';
    private const NUM_START = '-0123456789';
    private const NUM_REST = '-+.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    private const PUNCT = '{}[]()<>=;,:';
    private const FTYPES = [1 => 'double', 2 => 'float', 3 => 'int64', 4 => 'uint64', 5 => 'int32', 6 => 'fixed64', 7 => 'fixed32', 8 => 'bool', 9 => 'string', 12 => 'bytes',
        13 => 'uint32', 15 => 'sfixed32', 16 => 'sfixed64', 17 => 'sint32', 18 => 'sint64'];
    private const BEHAV = ['2' => 'REQUIRED', '3' => 'OUTPUT_ONLY', '4' => 'INPUT_ONLY', '5' => 'IMMUTABLE'];
    private const HTTP_VERBS = [2 => 'GET', 3 => 'PUT', 4 => 'POST', 5 => 'DELETE', 6 => 'PATCH'];
    private const WKT_STRING = ['google.protobuf.StringValue', 'google.protobuf.BytesValue'];
    private const WKT_INT = ['google.protobuf.Int32Value', 'google.protobuf.Int64Value', 'google.protobuf.UInt32Value', 'google.protobuf.UInt64Value'];

    /** The byte length of a JS whitespace character at `$i` (0 when there is none). */
    private static function wsLen(string $src, int $i): int
    {
        $b = ord($src[$i]);
        if ($b < 0x80) {
            return $b === 32 || ($b >= 9 && $b <= 13) ? 1 : 0;
        }
        return preg_match('/\G(?:' . IntentWb::JS_WS . ')/', $src, $m, 0, $i) === 1 ? strlen($m[0]) : 0;
    }

    private static function charLen(string $lead): int
    {
        $b = ord($lead);
        return $b >= 0xF0 ? 4 : ($b >= 0xE0 ? 3 : ($b >= 0xC0 ? 2 : 1));
    }

    /** @return list<array{string,string}> */
    private static function lex(string $src, int $maxTokens): array
    {
        $out = [];
        $n = strlen($src);
        $i = 0;
        $push = static function (array $t) use (&$out, $maxTokens): void {
            if (count($out) >= $maxTokens) {
                throw new ActionKitError('import_limit', 'the proto source has too many tokens');
            }
            $out[] = $t;
        };
        while ($i < $n) {
            $ch = $src[$i];
            $w = self::wsLen($src, $i);
            if ($w > 0) {
                $i += $w;
                continue;
            }
            if ($ch === '/' && ($src[$i + 1] ?? '') === '/') {
                while ($i < $n && $src[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($ch === '/' && ($src[$i + 1] ?? '') === '*') {
                $j = strpos($src, '*/', $i + 2);
                if ($j === false) {
                    throw new ActionKitError('bad_source', 'unterminated comment in proto source');
                }
                $i = $j + 2;
                continue;
            }
            if ($ch === '"' || $ch === "'") {
                $j = $i + 1;
                $s = '';
                while ($j < $n && $src[$j] !== $ch) {
                    if ($src[$j] === "\n") {
                        throw new ActionKitError('bad_source', 'unterminated string in proto source');
                    }
                    if ($src[$j] === '\\') {
                        if ($j + 1 < $n) {
                            $len = self::charLen($src[$j + 1]);
                            $s .= substr($src, $j + 1, $len);
                            $j += 1 + $len;
                        } else {
                            $j += 2;
                        }
                    } else {
                        $s .= $src[$j];
                        $j++;
                    }
                }
                if ($j >= $n) {
                    throw new ActionKitError('bad_source', 'unterminated string in proto source');
                }
                $push(['str', $s]);
                $i = $j + 1;
                continue;
            }
            if (strpos(self::ID_START, $ch) !== false) {
                $j = $i + 1;
                while ($j < $n && strpos(self::ID_REST, $src[$j]) !== false) {
                    $j++;
                }
                $push(['id', substr($src, $i, $j - $i)]);
                $i = $j;
                continue;
            }
            if (strpos(self::NUM_START, $ch) !== false) {
                $j = $i + 1;
                while ($j < $n && strpos(self::NUM_REST, $src[$j]) !== false) {
                    $j++;
                }
                $push(['num', substr($src, $i, $j - $i)]);
                $i = $j;
                continue;
            }
            if (strpos(self::PUNCT, $ch) !== false) {
                $push(['p', $ch]);
                $i++;
                continue;
            }
            throw new ActionKitError('bad_source', 'unexpected character in proto source at offset ' . Js::len(substr($src, 0, $i)));
        }
        return $out;
    }

    /** `.proto` text to a model. @return array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} */
    public static function parseProto(string $src, int $maxTokens = 2000000): array
    {
        $p = new ProtoTextParser(self::lex($src, $maxTokens), 32);
        $p->file();
        return $p->model();
    }

    // ---- binary descriptor set ------------------------------------------------------------------------------------------

    /** @return array{float,float} (field number, wire type) */
    private static function tag(ProtoReader $r): array
    {
        $t = $r->varint();
        return [floor($t / 8), fmod($t, 8.0)];
    }

    private static function qual(string $scope, string $name): string
    {
        return $scope === '' ? $name : "$scope.$name";
    }

    private static function readEnum(ProtoReader $r, string $scope, Obj $enums): void
    {
        $name = '';
        $values = [];
        while ($r->more()) {
            [$f, $wt] = self::tag($r);
            if ($f == 1 && $wt == 2) {
                $name = $r->str();
            } elseif ($f == 2 && $wt == 2) {
                $v = $r->len();
                while ($v->more()) {
                    [$vf, $vw] = self::tag($v);
                    if ($vf == 1 && $vw == 2) {
                        $values[] = $v->str();
                    } else {
                        $v->skip($vw);
                    }
                }
            } else {
                $r->skip($wt);
            }
        }
        $full = self::qual($scope, $name);
        $enums->set($full, ['full' => $full, 'values' => $values]);
    }

    private static function readMsg(ProtoReader $r, string $scope, int $depth, Obj $messages, Obj $enums): void
    {
        if ($depth > 32) {
            throw new ActionKitError('import_limit', 'descriptor message nesting is too deep');
        }
        $name = '';
        $fields = [];
        $nested = [];
        $enumRs = [];
        $mapEntry = false;
        while ($r->more()) {
            [$f, $wt] = self::tag($r);
            if ($f == 1 && $wt == 2) {
                $name = $r->str();
            } elseif ($f == 2 && $wt == 2) {
                $fr = $r->len();
                $fd = ['name' => '', 'type' => 0.0, 'label' => 1.0, 'typeName' => '', 'proto3opt' => false, 'behavior' => []];
                while ($fr->more()) {
                    [$ff, $fw] = self::tag($fr);
                    if ($ff == 1 && $fw == 2) {
                        $fd['name'] = $fr->str();
                    } elseif ($ff == 4 && $fw == 0) {
                        $fd['label'] = $fr->varint();
                    } elseif ($ff == 5 && $fw == 0) {
                        $fd['type'] = $fr->varint();
                    } elseif ($ff == 6 && $fw == 2) {
                        $fd['typeName'] = $fr->str();
                    } elseif ($ff == 17 && $fw == 0) {
                        $fd['proto3opt'] = $fr->varint() == 1;
                    } elseif ($ff == 8 && $fw == 2) {
                        $o = $fr->len();
                        while ($o->more()) {
                            [$of, $ow] = self::tag($o);
                            if ($of == 1052 && $ow == 0) {
                                $fd['behavior'][] = IntentWb::jsNumStr($o->varint());
                            } elseif ($of == 1052 && $ow == 2) {
                                $pk = $o->len();
                                while ($pk->more()) {
                                    $fd['behavior'][] = IntentWb::jsNumStr($pk->varint());
                                }
                            } else {
                                $o->skip($ow);
                            }
                        }
                    } else {
                        $fr->skip($fw);
                    }
                }
                $fields[] = $fd;
            } elseif ($f == 3 && $wt == 2) {
                $nested[] = $r->len();
            } elseif ($f == 4 && $wt == 2) {
                $enumRs[] = $r->len();
            } elseif ($f == 7 && $wt == 2) {
                $o = $r->len();
                while ($o->more()) {
                    [$of, $ow] = self::tag($o);
                    if ($of == 7 && $ow == 0) {
                        $mapEntry = $o->varint() == 1;
                    } else {
                        $o->skip($ow);
                    }
                }
            } else {
                $r->skip($wt);
            }
        }
        $full = self::qual($scope, $name);
        $out = [];
        foreach ($fields as $fd) {
            $t = $fd['type'];
            $out[] = ['name' => $fd['name'], 'scope' => $full, 'repeated' => $fd['label'] == 3, 'optional' => $fd['proto3opt'],
                'type' => $fd['typeName'] !== '' ? $fd['typeName'] : ($t >= 0 && $t < 100 && $t == floor($t) ? (self::FTYPES[(int)$t] ?? 'bytes') : 'bytes'),
                'behavior' => array_map(static fn($b) => self::BEHAV[$b] ?? '', $fd['behavior'])];
        }
        $messages->set($full, ['full' => $full, 'mapEntry' => $mapEntry, 'fields' => $out]);
        foreach ($nested as $n) {
            self::readMsg($n, $full, $depth + 1, $messages, $enums);
        }
        foreach ($enumRs as $e) {
            self::readEnum($e, $full, $enums);
        }
    }

    /** The binary FileDescriptorSet to a model. @return array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} */
    public static function parseDescriptorSet(string $data): array
    {
        $messages = new Obj();
        $enums = new Obj();
        $services = [];
        $top = new ProtoReader($data);
        while ($top->more()) {
            [$f, $wt] = self::tag($top);
            if ($f != 1 || $wt != 2) {
                $top->skip($wt);
                continue;
            }
            $fr = $top->len();
            $pkg = '';
            $msgs = [];
            $enumRs = [];
            $svcs = [];
            while ($fr->more()) { // package may follow the messages in the wire order: collect first, then resolve scopes
                [$ff, $fw] = self::tag($fr);
                if ($ff == 2 && $fw == 2) {
                    $pkg = $fr->str();
                } elseif ($ff == 4 && $fw == 2) {
                    $msgs[] = $fr->len();
                } elseif ($ff == 5 && $fw == 2) {
                    $enumRs[] = $fr->len();
                } elseif ($ff == 6 && $fw == 2) {
                    $svcs[] = $fr->len();
                } else {
                    $fr->skip($fw);
                }
            }
            foreach ($msgs as $r) {
                self::readMsg($r, $pkg, 0, $messages, $enums);
            }
            foreach ($enumRs as $r) {
                self::readEnum($r, $pkg, $enums);
            }
            foreach ($svcs as $r) {
                $name = '';
                $methods = [];
                while ($r->more()) {
                    [$sf, $sw] = self::tag($r);
                    if ($sf == 1 && $sw == 2) {
                        $name = $r->str();
                    } elseif ($sf == 2 && $sw == 2) {
                        $mr = $r->len();
                        $me = ['name' => '', 'input' => '', 'output' => '', 'cs' => false, 'ss' => false, 'scope' => $pkg];
                        while ($mr->more()) {
                            [$mf, $mw] = self::tag($mr);
                            if ($mf == 1 && $mw == 2) {
                                $me['name'] = $mr->str();
                            } elseif ($mf == 2 && $mw == 2) {
                                $me['input'] = $mr->str();
                            } elseif ($mf == 3 && $mw == 2) {
                                $me['output'] = $mr->str();
                            } elseif ($mf == 5 && $mw == 0) {
                                $me['cs'] = $mr->varint() == 1;
                            } elseif ($mf == 6 && $mw == 0) {
                                $me['ss'] = $mr->varint() == 1;
                            } elseif ($mf == 4 && $mw == 2) {
                                $o = $mr->len();
                                while ($o->more()) {
                                    [$of, $ow] = self::tag($o);
                                    if ($of == 34 && $ow == 0) {
                                        $v = $o->varint();
                                        $me['idem'] = $v == 1 ? 'NO_SIDE_EFFECTS' : ($v == 2 ? 'IDEMPOTENT' : 'IDEMPOTENCY_UNKNOWN');
                                    } elseif ($of == 72295728 && $ow == 2) {
                                        $h = $o->len();
                                        while ($h->more()) {
                                            [$hf, $hw] = self::tag($h);
                                            if ($hw == 2 && $hf >= 2 && $hf <= 6 && $hf == floor($hf)) {
                                                if (!isset($me['http'])) {
                                                    $me['http'] = ['method' => self::HTTP_VERBS[(int)$hf], 'path' => $h->str()];
                                                } else {
                                                    $h->str();
                                                }
                                            } elseif ($hf == 7 && $hw == 2) {
                                                $b = $h->str();
                                                if (isset($me['http'])) {
                                                    $me['http']['body'] = $b;
                                                }
                                            } else {
                                                $h->skip($hw);
                                            }
                                        }
                                    } else {
                                        $o->skip($ow);
                                    }
                                }
                            } else {
                                $mr->skip($mw);
                            }
                        }
                        $methods[] = $me;
                    } else {
                        $r->skip($sw);
                    }
                }
                $services[] = ['full' => self::qual($pkg, $name), 'name' => $name, 'methods' => $methods];
            }
        }
        return ['messages' => $messages, 'enums' => $enums, 'services' => $services];
    }

    // ---- model -> params ------------------------------------------------------------------------------------------------

    /** @param array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} $m */
    private static function resolveName(array $m, string $name, string $scope): ?string
    {
        if (str_starts_with($name, '.')) {
            return substr($name, 1);
        }
        $parts = $scope === '' ? [] : explode('.', $scope);
        for ($k = count($parts); $k >= 0; $k--) {
            $cand = implode('.', [...array_slice($parts, 0, $k), $name]);
            if ($m['messages']->has($cand) || $m['enums']->has($cand)) {
                return $cand;
            }
        }
        return $m['messages']->has($name) || $m['enums']->has($name) ? $name : null;
    }

    /**
     * @param array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} $m
     * @param array<string,mixed> $f
     * @param list<string> $stack
     * @param array{n:int} $budget
     */
    private static function fieldSchema(array $m, array $f, ImportCtx $c, array $stack, string $where, array &$budget): Obj
    {
        if (isset($f['map']) && $f['map'] !== []) {
            return Obj::of(['type' => 'object']);
        }
        $s = self::oneSchema($m, $f['type'], $f['scope'], $c, $stack, $where, $budget);
        return $f['repeated'] ? Obj::of(['type' => 'array', 'items' => $s]) : $s;
    }

    /**
     * @param array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} $m
     * @param list<string> $stack
     * @param array{n:int} $budget
     */
    private static function oneSchema(array $m, string $typ, string $scope, ImportCtx $c, array $stack, string $where, array &$budget): Obj
    {
        if (in_array($typ, self::SCALAR_NAMES, true)) {
            if (str_contains($typ, 'int') || str_contains($typ, 'fixed')) {
                return Obj::of(['type' => 'integer', 'format' => 'int64']);
            }
            if ($typ === 'bool') {
                return Obj::of(['type' => 'boolean']);
            }
            if ($typ === 'string' || $typ === 'bytes') {
                return Obj::of(['type' => 'string']);
            }
            return Obj::of(['type' => 'number']);
        }
        $ab = str_starts_with($typ, '.') ? substr($typ, 1) : null;
        if ($ab === 'google.protobuf.Timestamp' || $typ === 'google.protobuf.Timestamp') {
            return Obj::of(['type' => 'string', 'format' => 'date-time']);
        }
        $t = $ab ?? $typ;
        if (in_array($t, self::WKT_STRING, true)) {
            return Obj::of(['type' => 'string']);
        }
        if (in_array($t, self::WKT_INT, true)) {
            return Obj::of(['type' => 'integer', 'format' => 'int64']);
        }
        if ($t === 'google.protobuf.BoolValue') {
            return Obj::of(['type' => 'boolean']);
        }
        if (str_starts_with($t, 'google.protobuf.')) {
            return new Obj();
        }
        $full = self::resolveName($m, $typ, $scope);
        if ($full === null) {
            ActionsImport::addTodo($c, $where, 'unknown_type', "type '" . ActionsImport::clip($typ, 60) . "' is not defined in the proto source (declared string)");
            return new Obj();
        }
        $en = $m['enums']->get($full);
        if ($en !== null) {
            return Obj::of(['type' => 'string', 'enum' => array_values(array_unique($en['values']))]);
        }
        return self::msgSchema($m, $full, $c, $stack, $where, $budget);
    }

    /**
     * @param array{messages:Obj,enums:Obj,services:list<array<string,mixed>>} $m
     * @param list<string> $stack
     * @param array{n:int} $budget
     */
    private static function msgSchema(array $m, string $full, ImportCtx $c, array $stack, string $where, array &$budget): Obj
    {
        $msg = $m['messages']->get($full);
        if ($msg === null) {
            return new Obj();
        }
        if (in_array($full, $stack, true)) {
            ActionsImport::addTodo($c, $where, 'cyclic_ref', "message '" . ActionsImport::clip($full, 80) . "' is recursive (declared string; refine or drop)");
            return new Obj();
        }
        $stop = count($stack) > $c->lim['max_ref_depth'];
        if (!$stop) {
            $budget['n']--;
            $stop = $budget['n'] <= 0;
        }
        if ($stop) {
            ActionsImport::addTodo($c, $where, 'ref_budget', 'message expansion stopped at the bound (declared string; refine or drop)');
            return new Obj();
        }
        $properties = new Obj();
        $required = [];
        foreach ($msg['fields'] as $f) {
            if (in_array('OUTPUT_ONLY', $f['behavior'], true)) {
                continue;
            }
            if ($f['name'] !== '__proto__') {
                $properties->set($f['name'], self::fieldSchema($m, $f, $c, [...$stack, $full], $where . '.' . $f['name'], $budget));
            }
            if (in_array('REQUIRED', $f['behavior'], true)) {
                $required[] = $f['name'];
            }
        }
        return Obj::of(['type' => 'object', 'properties' => $properties, 'required' => $required]);
    }

    /** `$source` is `.proto` text (a string) or the bytes ({@see Bytes}) of a binary FileDescriptorSet. */
    public static function importGrpc(mixed $source, mixed $opts): Obj
    {
        $c = ActionsImport::newCtx('grpc', $source, $opts);
        if (is_string($source)) {
            $m = self::parseProto($source);
        } elseif ($source instanceof Bytes) {
            $m = self::parseDescriptorSet($source->raw);
        } else {
            throw new ActionKitError('bad_source', 'a gRPC source is .proto text or a binary FileDescriptorSet');
        }
        $services = $m['services'];
        usort($services, static fn(array $a, array $b): int => strcmp($a['full'], $b['full']));
        foreach ($services as $svc) {
            $methods = $svc['methods'];
            usort($methods, static fn(array $a, array $b): int => strcmp($a['name'], $b['name']));
            foreach ($methods as $me) {
                $where = $svc['name'] . '/' . $me['name'];
                $c->root = null;
                $bud = ActionsImport::newBudget($c);
                $inp = self::resolveName($m, $me['input'], $me['scope']);
                $inp = $inp ?? (string)preg_replace('/\A\./', '', $me['input']);
                $budget = ['n' => $c->lim['max_ref_nodes']];
                $schema = self::msgSchema($m, $inp, $c, [], $where, $budget);
                $params = new Obj();
                if ($schema->has('properties')) {
                    ActionsImport::flattenObject($schema, $c, $bud, $where, $params);
                } elseif (!$m['messages']->has($inp) && !str_starts_with($inp, 'google.protobuf.')) {
                    ActionsImport::addTodo($c, $where, 'unknown_type', "request type '" . ActionsImport::clip($me['input'], 60) . "' is not defined in the source (no parameters)");
                }
                $http = $me['http'] ?? null;
                $hm = $http !== null ? $http['method'] : null;
                $idem = $me['idem'] ?? null;
                $effects = $hm === 'GET' ? ['read'] : ($hm === 'DELETE' ? ['delete'] : ($hm === 'POST' ? ['create'] : ($hm === 'PUT' || $hm === 'PATCH' ? ['update']
                    : ($idem === 'NO_SIDE_EFFECTS' ? ['read'] : ['update']))));
                $natural = $idem === 'NO_SIDE_EFFECTS' || $idem === 'IDEMPOTENT' || $hm === 'GET' || $hm === 'PUT' || $hm === 'DELETE';
                $traits = null;
                if ($me['cs'] || $me['ss']) {
                    $traits = ActionsImport::withTrait($traits, 'pca.bulk');
                    ActionsImport::addTodo($c, $where, 'streaming', 'a streaming method: acts on many messages (pca.bulk added)');
                }
                $bindings = Obj::of(['grpc' => Obj::of(['service' => ActionsImport::clip($svc['full'], 250), 'method' => ActionsImport::clip($me['name'], 250)])]);
                if ($http !== null && $http['path'] !== '') {
                    $bindings->set('http', Obj::of(['method' => $http['method'], 'path' => ActionsImport::clip($http['path'], 250)]));
                }
                ActionsImport::emitDef($c, $svc['name'] . ' ' . $me['name'], $effects, 'one', $params, $bindings, null,
                    (string)preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $me['name']), null, $natural ? Obj::of(['mode' => 'natural']) : null, $traits);
            }
        }
        return ActionsImport::finish($c);
    }
}
