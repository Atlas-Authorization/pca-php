<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalIrError.php';

/**
 * Token-tape form of the Goal IR. A tape is a list of [tag, value] tokens, tag 'k' (keyword number) | 'i' (integer) | 's'
 * (string). Encoding is strict: anything that is not exactly an IR value throws GoalIrError (or the TypeError a JavaScript
 * property read of null would). IR values are parsed-JSON trees (Obj with a 'k' discriminant).
 */
final class GoalCodec
{
    public const MAX_SAFE = 9007199254740991;
    public const OPS = ['eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'in', 'nin'];
    public const AGGS = ['count', 'sum', 'max', 'distinct'];
    public const UNITS = ['count' => 301, 'duration' => 302, 'instant' => 303, 'bytes' => 304, 'ratio' => 305];
    public const UNIT_TAGS = [301 => 'count', 302 => 'duration', 303 => 'instant', 304 => 'bytes', 305 => 'ratio'];

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    /** @return array{0:string,1:int} */
    private static function kk(int $n): array
    {
        return ['k', $n];
    }

    /** A JSON number that is a safe integer (not -0, not fractional, not beyond 2^53 - 1). */
    public static function safeInt(mixed $n): bool
    {
        $f = Js::num($n);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= self::MAX_SAFE && !($f == 0.0 && fdiv(1.0, $f) < 0);
    }

    /** @return array{0:string,1:int} */
    private static function ii(mixed $n): array
    {
        if (!self::safeInt($n)) {
            throw new GoalIrError('not a safe integer');
        }
        return ['i', (int)Js::num($n)];
    }

    /** @return array{0:string,1:string} */
    private static function ss(mixed $s): array
    {
        if (!is_string($s)) {
            throw new GoalIrError('string expected');
        }
        return ['s', $s];
    }

    private static function bad(string $what): never
    {
        throw new GoalIrError("unknown $what");
    }

    /** @return list<array{0:string,1:mixed}> */
    private static function lst(mixed $xs, callable $f): array
    {
        if (!is_array($xs) || !array_is_list($xs)) {
            throw new GoalIrError('array expected');
        }
        return array_merge([self::ii(count($xs))], ...array_map($f, $xs));
    }

    private static function strs(mixed $xs): array
    {
        return self::lst($xs, fn($s) => [self::ss($s)]);
    }

    private static function b(mixed $v): array
    {
        return [self::ii(AnalyzerJs::truthy($v) ? 1 : 0)];
    }

    private static function encUnit(mixed $u): array
    {
        $k = self::g($u, 'k');
        if ($k === 'money') {
            return [self::kk(300), self::ss(self::g($u, 'ccy'))];
        }
        if (is_string($k) && isset(self::UNITS[$k])) {
            return [self::kk(self::UNITS[$k])];
        }
        self::bad('unit');
    }

    private static function encQ(mixed $q): array
    {
        return array_merge(self::encUnit(self::g($q, 'u')), [self::ii(self::g($q, 'n'))]);
    }

    private static function encTy(mixed $t): array
    {
        $k = self::g($t, 'k');
        if ($k === 'q') {
            return array_merge([self::kk(310)], self::encUnit(self::g($t, 'u')));
        }
        return $k === 's' ? [self::kk(311)] : self::bad('type');
    }

    private static function encAtom(mixed $a): array
    {
        $k = self::g($a, 'k');
        if ($k === 'q') {
            return array_merge([self::kk(320)], self::encQ(self::g($a, 'q')));
        }
        if ($k === 's') {
            return [self::kk(321), self::ss(self::g($a, 's'))];
        }
        self::bad('set member (sets hold quantities and strings only)');
    }

    private static function encV(mixed $v): array
    {
        $k = self::g($v, 'k');
        if ($k === 'q') {
            return array_merge([self::kk(330)], self::encQ(self::g($v, 'q')));
        }
        if ($k === 's') {
            return [self::kk(331), self::ss(self::g($v, 's'))];
        }
        if ($k === 'set') {
            return array_merge([self::kk(332)], self::lst(self::g($v, 'items'), fn($a) => self::encAtom($a)));
        }
        self::bad('value');
    }

    private static function encTerm(mixed $t): array
    {
        $k = self::g($t, 'k');
        if ($k === 'param') {
            return array_merge([self::kk(340), self::ss(self::g($t, 'path'))], self::encTy(self::g($t, 'ty')));
        }
        if ($k === 'lit') {
            return array_merge([self::kk(341)], self::encV(self::g($t, 'v')));
        }
        if ($k === 'hist') {
            return array_merge([self::kk(342), self::ss(self::g($t, 'bid'))], self::encUnit(self::g($t, 'u')));
        }
        self::bad('term');
    }

    private static function encOp(mixed $op): array
    {
        $i = is_string($op) ? array_search($op, self::OPS, true) : false;
        return $i === false ? self::bad('operator') : [self::kk(350 + $i)];
    }

    private static function encCond(mixed $c): array
    {
        $k = self::g($c, 'k');
        return match ($k) {
            'true' => [self::kk(360)],
            'cmp' => array_merge([self::kk(361)], self::encOp(self::g($c, 'op')), self::encTerm(self::g($c, 'l')), self::encTerm(self::g($c, 'r'))),
            'and' => array_merge([self::kk(362)], self::encCond(self::g($c, 'a')), self::encCond(self::g($c, 'b'))),
            'or' => array_merge([self::kk(363)], self::encCond(self::g($c, 'a')), self::encCond(self::g($c, 'b'))),
            'not' => array_merge([self::kk(364)], self::encCond(self::g($c, 'c'))),
            default => self::bad('condition'),
        };
    }

    private static function encPart(mixed $s): array
    {
        $k = self::g($s, 'k');
        if ($k === 'exact') {
            return [self::kk(375), self::ss(self::g($s, 'id'))];
        }
        if ($k === 'oneof') {
            return array_merge([self::kk(376)], self::strs(self::g($s, 'ids')));
        }
        if ($k === 'related') {
            return [self::kk(377), self::ss(self::g($s, 'rel')), self::ss(self::g($s, 'anchor'))];
        }
        self::bad('resource part');
    }

    private static function encRes(mixed $s): array
    {
        $k = self::g($s, 'k');
        return match ($k) {
            'exact' => [self::kk(370), self::ss(self::g($s, 'id'))],
            'oneof' => array_merge([self::kk(371)], self::strs(self::g($s, 'ids'))),
            'related' => [self::kk(372), self::ss(self::g($s, 'rel')), self::ss(self::g($s, 'anchor'))],
            'any' => [self::kk(373), self::ss(self::g($s, 'reason'))],
            'all_of' => array_merge([self::kk(374)], self::lst(self::g($s, 'parts'), fn($p) => self::encPart($p))),
            default => self::bad('resource selector'),
        };
    }

    private static function encGrant(mixed $g): array
    {
        return array_merge([self::kk(380), self::ss(self::g($g, 'gid')), self::ss(self::g($g, 'verb'))], self::encRes(self::g($g, 'res')), self::encCond(self::g($g, 'cond')));
    }

    private static function encTarget(mixed $t): array
    {
        $k = self::g($t, 'k');
        if ($k === 'verb') {
            return [self::kk(390), self::ss(self::g($t, 'verb'))];
        }
        return $k === 'effect' ? [self::kk(391), self::ss(self::g($t, 'cls'))] : self::bad('prohibit target');
    }

    private static function encProhibit(mixed $p): array
    {
        return array_merge([self::kk(392), self::ss(self::g($p, 'pid'))], self::encTarget(self::g($p, 'target')), self::encRes(self::g($p, 'res')), self::encCond(self::g($p, 'cond')));
    }

    private static function encSel(mixed $s): array
    {
        $k = self::g($s, 'k');
        if ($k === 'gids') {
            return array_merge([self::kk(410)], self::strs(self::g($s, 'gids')));
        }
        return $k === 'effect' ? [self::kk(411), self::ss(self::g($s, 'cls'))] : self::bad('selection');
    }

    private static function encWindow(mixed $w): array
    {
        $k = self::g($w, 'k');
        return match ($k) {
            'task' => [self::kk(420)],
            'sliding' => [self::kk(421), self::ii(self::g($w, 'ms'))],
            'period' => [self::kk(422), self::ii(self::g($w, 'ms')), self::ii(self::g($w, 't0'))],
            'lifetime' => [self::kk(423)],
            default => self::bad('window'),
        };
    }

    private static function encScope(mixed $s): array
    {
        $k = self::g($s, 'k');
        return match ($k) {
            'session' => [self::kk(430)],
            'principal' => [self::kk(431)],
            'org' => [self::kk(432)],
            'fleet' => array_merge([self::kk(433)], self::strs(self::g($s, 'agents'))),
            default => self::bad('scope'),
        };
    }

    private static function encOnExceed(mixed $o): array
    {
        if ($o === 'deny') {
            return [self::kk(440)];
        }
        return $o === 'escalate' ? [self::kk(441)] : self::bad('on_exceed');
    }

    private static function encBcore(mixed $b): array
    {
        $agg = self::g($b, 'agg');
        $i = is_string($agg) ? array_search($agg, self::AGGS, true) : false;
        if ($i === false) {
            self::bad('aggregate');
        }
        return array_merge([self::kk(450), self::kk(400 + $i)], self::encTerm(self::g($b, 'value')), [self::ss(self::g($b, 'key'))],
            self::encWindow(self::g($b, 'window')), self::encScope(self::g($b, 'scope')), self::encQ(self::g($b, 'cap')), self::encOnExceed(self::g($b, 'onExceed')));
    }

    private static function encBound(mixed $b): array
    {
        return array_merge([self::kk(451), self::ss(self::g($b, 'bid'))], self::encSel(self::g($b, 'sel')), self::encBcore($b));
    }

    private static function encValidity(mixed $v): array
    {
        return [self::kk(460), self::ii(self::g($v, 'notBefore')), self::ii(self::g($v, 'notAfter')), self::ii(self::g($v, 'maxIdle'))];
    }

    private static function encDeleg(mixed $d): array
    {
        return array_merge([self::kk(461), self::ii(self::g($d, 'maxDepth'))], self::b(self::g($d, 'narrowOnly')), self::strs(self::g($d, 'mayTouch')));
    }

    private static function encHole(mixed $h): array
    {
        return array_merge([self::kk(470), self::ss(self::g($h, 'hid')), self::ss(self::g($h, 'q'))], self::strs(self::g($h, 'domain')),
            self::strs(self::g($h, 'affects')), self::b(self::g($h, 'global')));
    }

    /** The goal as a token tape. @return list<array{0:string,1:mixed}> */
    public static function encodeGoal(mixed $g): array
    {
        return array_merge(
            [self::kk(480), self::ii(self::g($g, 'v')), self::ss(self::g($g, 'principal')), self::ss(self::g($g, 'ontDigest')), self::ss(self::g($g, 'nlDigest'))],
            self::strs(self::g($g, 'sources')),
            self::lst(self::g($g, 'grants'), fn($x) => self::encGrant($x)),
            self::lst(self::g($g, 'prohibits'), fn($x) => self::encProhibit($x)),
            self::lst(self::g($g, 'bounds'), fn($x) => self::encBound($x)),
            self::encValidity(self::g($g, 'validity')),
            self::encDeleg(self::g($g, 'deleg')),
            self::lst(self::g($g, 'escalateOn'), fn($x) => self::encCond($x)),
            self::strs(self::g($g, 'wildcardAck')),
            self::lst(self::g($g, 'holes'), fn($x) => self::encHole($x)),
        );
    }

    private static function encParamDecl(mixed $p): array
    {
        return array_merge([self::kk(500), self::ss(self::g($p, 'path'))], self::encTy(self::g($p, 'ty')));
    }

    private static function encVerbDecl(mixed $v): array
    {
        return array_merge([self::kk(501), self::ss(self::g($v, 'verb')), self::ss(self::g($v, 'cls'))], self::lst(self::g($v, 'params'), fn($p) => self::encParamDecl($p)));
    }

    private static function encRelDecl(mixed $r): array
    {
        return array_merge([self::kk(502), self::ss(self::g($r, 'rel')), self::ss(self::g($r, 'anchor'))], self::strs(self::g($r, 'members')));
    }

    public static function encodeOntology(mixed $o): array
    {
        return array_merge([self::kk(510)], self::lst(self::g($o, 'verbs'), fn($v) => self::encVerbDecl($v)),
            self::lst(self::g($o, 'rels'), fn($r) => self::encRelDecl($r)));
    }

    /** Object.keys(o) in JavaScript's default sort order. @return list<string> */
    private static function sortedKeys(mixed $o): array
    {
        $keys = GoalJs::okeys($o);
        usort($keys, fn($a, $b) => AnalyzerJs::u16cmp($a, $b));
        return $keys;
    }

    private static function encAct(mixed $a): array
    {
        $params = self::g($a, 'params');
        $keys = self::sortedKeys($params);
        return array_merge([self::kk(530), self::ss(self::g($a, 'verb')), self::ss(self::g($a, 'res'))],
            self::lst($keys, fn($k) => array_merge([self::kk(520), self::ss($k)], self::encV(GoalJs::kget($params, $k)))),
            [self::ii(self::g($a, 't')), self::ss(self::g($a, 'sess')), self::ss(self::g($a, 'prin')), self::ss(self::g($a, 'org')),
                self::ss(self::g($a, 'agent')), self::ii(self::g($a, 'depth'))]);
    }

    public static function encodeAct(mixed $a): array
    {
        return self::encAct($a);
    }

    private static function encAdm(mixed $a): array
    {
        return array_merge([self::kk(531), self::ss(self::g($a, 'gid'))], self::encAct(self::g($a, 'act')));
    }

    public static function encodeHist(mixed $h): array
    {
        $aggs = self::g($h, 'aggs');
        $keys = self::sortedKeys($aggs);
        return array_merge([self::kk(541)], self::lst(self::g($h, 'adms'), fn($a) => self::encAdm($a)), [self::ii(self::g($h, 'last'))],
            self::lst($keys, fn($k) => array_merge([self::kk(540), self::ss($k)], self::encQ(GoalJs::kget($aggs, $k)))));
    }

    // ---- decoding

    private static function dUnit(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 300) {
            return Obj::of(['k' => 'money', 'ccy' => $r->str()]);
        }
        if (!isset(self::UNIT_TAGS[$k])) {
            throw new GoalIrError("bad unit tag $k");
        }
        return Obj::of(['k' => self::UNIT_TAGS[$k]]);
    }

    private static function dQ(GoalTapeReader $r): Obj
    {
        $u = self::dUnit($r);
        return Obj::of(['u' => $u, 'n' => $r->int()]);
    }

    private static function dTy(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 310) {
            return Obj::of(['k' => 'q', 'u' => self::dUnit($r)]);
        }
        if ($k === 311) {
            return Obj::of(['k' => 's']);
        }
        throw new GoalIrError("bad type tag $k");
    }

    private static function dAtom(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 320) {
            return Obj::of(['k' => 'q', 'q' => self::dQ($r)]);
        }
        if ($k === 321) {
            return Obj::of(['k' => 's', 's' => $r->str()]);
        }
        throw new GoalIrError("bad atom tag $k");
    }

    private static function dV(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 330) {
            return Obj::of(['k' => 'q', 'q' => self::dQ($r)]);
        }
        if ($k === 331) {
            return Obj::of(['k' => 's', 's' => $r->str()]);
        }
        if ($k === 332) {
            return Obj::of(['k' => 'set', 'items' => $r->lst(fn() => self::dAtom($r))]);
        }
        throw new GoalIrError("bad value tag $k");
    }

    private static function dTerm(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 340) {
            $path = $r->str();
            return Obj::of(['k' => 'param', 'path' => $path, 'ty' => self::dTy($r)]);
        }
        if ($k === 341) {
            return Obj::of(['k' => 'lit', 'v' => self::dV($r)]);
        }
        if ($k === 342) {
            $bid = $r->str();
            return Obj::of(['k' => 'hist', 'bid' => $bid, 'u' => self::dUnit($r)]);
        }
        throw new GoalIrError("bad term tag $k");
    }

    private static function dOp(GoalTapeReader $r): string
    {
        $i = $r->k() - 350;
        if ($i >= 0 && $i < count(self::OPS)) {
            return self::OPS[$i];
        }
        throw new GoalIrError('bad operator');
    }

    private static function dN(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        switch ($k) {
            case 600:
                return Obj::of(['k' => 'true']);
            case 601:
                return Obj::of(['k' => 'false']);
            case 602:
                $op = self::dOp($r);
                $l = self::dTerm($r);
                return Obj::of(['k' => 'atom', 'op' => $op, 'l' => $l, 'r' => self::dTerm($r)]);
            case 603:
                $a = self::dN($r);
                return Obj::of(['k' => 'and', 'a' => $a, 'b' => self::dN($r)]);
            case 604:
                $a = self::dN($r);
                return Obj::of(['k' => 'or', 'a' => $a, 'b' => self::dN($r)]);
            default:
                throw new GoalIrError("bad condition tag $k");
        }
    }

    private static function dResPat(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 630) {
            return Obj::of(['k' => 'star']);
        }
        if ($k === 631) {
            return Obj::of(['k' => 'set', 'ids' => $r->strs()]);
        }
        throw new GoalIrError("bad resource pattern tag $k");
    }

    private static function dWindow(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        switch ($k) {
            case 420:
                return Obj::of(['k' => 'task']);
            case 421:
                return Obj::of(['k' => 'sliding', 'ms' => $r->int()]);
            case 422:
                $ms = $r->int();
                return Obj::of(['k' => 'period', 'ms' => $ms, 't0' => $r->int()]);
            case 423:
                return Obj::of(['k' => 'lifetime']);
            default:
                throw new GoalIrError("bad window tag $k");
        }
    }

    private static function dScope(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        switch ($k) {
            case 430:
                return Obj::of(['k' => 'session']);
            case 431:
                return Obj::of(['k' => 'principal']);
            case 432:
                return Obj::of(['k' => 'org']);
            case 433:
                return Obj::of(['k' => 'fleet', 'agents' => $r->strs()]);
            default:
                throw new GoalIrError("bad scope tag $k");
        }
    }

    private static function dAgg(GoalTapeReader $r): string
    {
        $i = $r->k() - 400;
        if ($i >= 0 && $i < count(self::AGGS)) {
            return self::AGGS[$i];
        }
        throw new GoalIrError('bad aggregate');
    }

    private static function dOnExceed(GoalTapeReader $r): string
    {
        $oe = $r->k();
        if ($oe !== 440 && $oe !== 441) {
            throw new GoalIrError('bad on_exceed');
        }
        return $oe === 440 ? 'deny' : 'escalate';
    }

    private static function dCeil(GoalTapeReader $r): Obj
    {
        if ($r->k() !== 610) {
            throw new GoalIrError('ceiling expected');
        }
        $bid = $r->str();
        $selGids = $r->strs();
        $selVerbs = $r->strs();
        if ($r->k() !== 450) {
            throw new GoalIrError('bound core expected');
        }
        $agg = self::dAgg($r);
        $value = self::dTerm($r);
        $key = $r->str();
        $window = self::dWindow($r);
        $scope = self::dScope($r);
        $cap = self::dQ($r);
        return Obj::of(['bid' => $bid, 'selGids' => $selGids, 'selVerbs' => $selVerbs, 'agg' => $agg, 'value' => $value, 'key' => $key,
            'window' => $window, 'scope' => $scope, 'cap' => $cap, 'onExceed' => self::dOnExceed($r)]);
    }

    /** Decode the compiler's policy tape (after its leading status token); throws GoalIrError unless the whole tape is one policy. */
    public static function decodePolicy(mixed $t): Obj
    {
        $r = new GoalTapeReader($t);
        if ($r->k() !== 650) {
            throw new GoalIrError('policy expected');
        }
        $preds = $r->lst(function () use ($r) {
            if ($r->k() !== 620) {
                throw new GoalIrError('pred');
            }
            $gid = $r->str();
            $verb = $r->str();
            $res = self::dResPat($r);
            return Obj::of(['gid' => $gid, 'verb' => $verb, 'res' => $res, 'cond' => self::dN($r)]);
        });
        $prohs = $r->lst(function () use ($r) {
            if ($r->k() !== 640) {
                throw new GoalIrError('prohibition');
            }
            $pid = $r->str();
            $verbs = $r->strs();
            $res = self::dResPat($r);
            return Obj::of(['pid' => $pid, 'verbs' => $verbs, 'res' => $res, 'cond' => self::dN($r)]);
        });
        $ceils = $r->lst(fn() => self::dCeil($r));
        $escs = $r->lst(fn() => self::dN($r));
        if ($r->k() !== 460) {
            throw new GoalIrError('validity');
        }
        $nb = $r->int();
        $na = $r->int();
        $validity = Obj::of(['notBefore' => $nb, 'notAfter' => $na, 'maxIdle' => $r->int()]);
        if ($r->k() !== 461) {
            throw new GoalIrError('delegation');
        }
        $md = $r->int();
        $nrw = $r->int() === 1;
        $deleg = Obj::of(['maxDepth' => $md, 'narrowOnly' => $nrw, 'mayTouch' => $r->strs()]);
        if (!$r->done()) {
            throw new GoalIrError('trailing tokens after policy');
        }
        return Obj::of(['preds' => $preds, 'prohs' => $prohs, 'ceils' => $ceils, 'escs' => $escs, 'validity' => $validity, 'deleg' => $deleg]);
    }

    private static function dCond(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        switch ($k) {
            case 360:
                return Obj::of(['k' => 'true']);
            case 361:
                $op = self::dOp($r);
                $l = self::dTerm($r);
                return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => $l, 'r' => self::dTerm($r)]);
            case 362:
                $a = self::dCond($r);
                return Obj::of(['k' => 'and', 'a' => $a, 'b' => self::dCond($r)]);
            case 363:
                $a = self::dCond($r);
                return Obj::of(['k' => 'or', 'a' => $a, 'b' => self::dCond($r)]);
            case 364:
                return Obj::of(['k' => 'not', 'c' => self::dCond($r)]);
            default:
                throw new GoalIrError("bad condition tag $k");
        }
    }

    private static function dPart(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        if ($k === 375) {
            return Obj::of(['k' => 'exact', 'id' => $r->str()]);
        }
        if ($k === 376) {
            return Obj::of(['k' => 'oneof', 'ids' => $r->strs()]);
        }
        if ($k === 377) {
            $rel = $r->str();
            return Obj::of(['k' => 'related', 'rel' => $rel, 'anchor' => $r->str()]);
        }
        throw new GoalIrError("bad resource part tag $k");
    }

    private static function dRes(GoalTapeReader $r): Obj
    {
        $k = $r->k();
        switch ($k) {
            case 370:
                return Obj::of(['k' => 'exact', 'id' => $r->str()]);
            case 371:
                return Obj::of(['k' => 'oneof', 'ids' => $r->strs()]);
            case 372:
                $rel = $r->str();
                return Obj::of(['k' => 'related', 'rel' => $rel, 'anchor' => $r->str()]);
            case 373:
                return Obj::of(['k' => 'any', 'reason' => $r->str()]);
            case 374:
                return Obj::of(['k' => 'all_of', 'parts' => $r->lst(fn() => self::dPart($r))]);
            default:
                throw new GoalIrError("bad resource selector tag $k");
        }
    }

    private static function expect(GoalTapeReader $r, int $k, string $what): void
    {
        if ($r->k() !== $k) {
            throw new GoalIrError("$what expected");
        }
    }

    /** Parse a goal tape; throws GoalIrError unless the whole tape is exactly one goal. */
    public static function decodeGoal(mixed $t): Obj
    {
        $r = new GoalTapeReader($t);
        self::expect($r, 480, 'goal');
        $v = $r->int();
        $principal = $r->str();
        $ontDigest = $r->str();
        $nlDigest = $r->str();
        $sources = $r->strs();
        $grants = $r->lst(function () use ($r) {
            self::expect($r, 380, 'grant');
            $gid = $r->str();
            $verb = $r->str();
            $res = self::dRes($r);
            return Obj::of(['gid' => $gid, 'verb' => $verb, 'res' => $res, 'cond' => self::dCond($r)]);
        });
        $prohibits = $r->lst(function () use ($r) {
            self::expect($r, 392, 'prohibit');
            $pid = $r->str();
            $tk = $r->k();
            if ($tk === 390) {
                $target = Obj::of(['k' => 'verb', 'verb' => $r->str()]);
            } elseif ($tk === 391) {
                $target = Obj::of(['k' => 'effect', 'cls' => $r->str()]);
            } else {
                throw new GoalIrError('bad prohibit target');
            }
            $res = self::dRes($r);
            return Obj::of(['pid' => $pid, 'target' => $target, 'res' => $res, 'cond' => self::dCond($r)]);
        });
        $bounds = $r->lst(function () use ($r) {
            self::expect($r, 451, 'bound');
            $bid = $r->str();
            $sk = $r->k();
            if ($sk === 410) {
                $sel = Obj::of(['k' => 'gids', 'gids' => $r->strs()]);
            } elseif ($sk === 411) {
                $sel = Obj::of(['k' => 'effect', 'cls' => $r->str()]);
            } else {
                throw new GoalIrError('bad selection');
            }
            self::expect($r, 450, 'bound core');
            $agg = self::dAgg($r);
            $value = self::dTerm($r);
            $key = $r->str();
            $window = self::dWindow($r);
            $scope = self::dScope($r);
            $cap = self::dQ($r);
            return Obj::of(['bid' => $bid, 'sel' => $sel, 'agg' => $agg, 'value' => $value, 'key' => $key, 'window' => $window,
                'scope' => $scope, 'cap' => $cap, 'onExceed' => self::dOnExceed($r)]);
        });
        self::expect($r, 460, 'validity');
        $nb = $r->int();
        $na = $r->int();
        $validity = Obj::of(['notBefore' => $nb, 'notAfter' => $na, 'maxIdle' => $r->int()]);
        self::expect($r, 461, 'delegation');
        $md = $r->int();
        $nrw = $r->int() === 1;
        $deleg = Obj::of(['maxDepth' => $md, 'narrowOnly' => $nrw, 'mayTouch' => $r->strs()]);
        $escalateOn = $r->lst(fn() => self::dCond($r));
        $wildcardAck = $r->strs();
        $holes = $r->lst(function () use ($r) {
            self::expect($r, 470, 'hole');
            $hid = $r->str();
            $q = $r->str();
            $domain = $r->strs();
            $affects = $r->strs();
            return Obj::of(['hid' => $hid, 'q' => $q, 'domain' => $domain, 'affects' => $affects, 'global' => $r->int() === 1]);
        });
        if (!$r->done()) {
            throw new GoalIrError('trailing tokens after goal');
        }
        return Obj::of(['v' => $v, 'principal' => $principal, 'ontDigest' => $ontDigest, 'nlDigest' => $nlDigest, 'sources' => $sources,
            'grants' => $grants, 'prohibits' => $prohibits, 'bounds' => $bounds, 'validity' => $validity, 'deleg' => $deleg,
            'escalateOn' => $escalateOn, 'wildcardAck' => $wildcardAck, 'holes' => $holes]);
    }
}

/** Sequential reader over a token tape; every shape error is a GoalIrError. */
final class GoalTapeReader
{
    private int $i = 0;

    public function __construct(private readonly mixed $t)
    {
    }

    /** @return array{0:mixed,1:mixed} */
    private function nextTok(): array
    {
        if (!is_array($this->t) || !array_is_list($this->t) || $this->i >= count($this->t)) {
            throw new GoalIrError('truncated tape');
        }
        $x = $this->t[$this->i];
        $this->i++;
        if (!is_array($x) || !array_is_list($x) || count($x) < 2) {
            throw new GoalIrError('malformed token');
        }
        return $x;
    }

    public function k(): int
    {
        $x = $this->nextTok();
        if ($x[0] !== 'k' || !GoalCodec::safeInt($x[1])) {
            throw new GoalIrError('keyword expected');
        }
        return (int)Js::num($x[1]);
    }

    public function int(): int
    {
        $x = $this->nextTok();
        if ($x[0] !== 'i' || !GoalCodec::safeInt($x[1])) {
            throw new GoalIrError('integer expected');
        }
        return (int)Js::num($x[1]);
    }

    public function str(): string
    {
        $x = $this->nextTok();
        if ($x[0] !== 's' || !is_string($x[1])) {
            throw new GoalIrError('string expected');
        }
        return $x[1];
    }

    public function done(): bool
    {
        return $this->i >= count($this->t);
    }

    /** @return list<mixed> */
    public function lst(callable $f): array
    {
        $n = $this->int();
        if ($n < 0) {
            throw new GoalIrError('negative length');
        }
        $out = [];
        for ($j = 0; $j < $n; $j++) {
            $out[] = $f();
        }
        return $out;
    }

    /** @return list<string> */
    public function strs(): array
    {
        return $this->lst(fn() => $this->str());
    }
}
