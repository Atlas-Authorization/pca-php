<?php
declare(strict_types=1);

// `fresh_at` through Authorize::authorize and FreshAt::withSideCarried, on the shared fresh-at vectors.
// No PHPUnit, no Composer: php tests/fresh-at-authorize.php   (exit 1 on any failure; FreshAtAuthorizeTest wraps it)
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\FreshAt;

/** @return list<string> failures */
function freshAtAuthorizeRun(): array
{
    $rows = [];
    foreach (Json::parseLax(file_get_contents(__DIR__ . '/../conformance/fresh-at-vectors.json'))->get('vectors') as $v) {
        $rows[$v->get('name')] = $v;
    }
    $fails = [];
    $run = static function (string $name, ?Obj $policy) use ($rows): array {
        $v = $rows[$name];
        $c = $v->get('context');
        $a = $v->get('pcactn')->get('action');
        $r = Authorize::authorize($v->get('pcactn'), ['verb' => $a->get('verb'), 'resource' => $a->get('resource'), 'params' => new Obj()],
            $c->get('aud'), static fn ($ref) => $v->get('grant'), new MemoryStateStore(), static fn () => false, $c->get('now')->int(),
            'single-step', null, null, null, null, [], freshAt: $policy);
        return [$r->checks['fresh_at'] ?? 'absent', implode(' | ', $r->reasons)];
    };
    $policy = static fn (string $n): ?Obj => $rows[$n]->get('context')->has('fresh_at') ? $rows[$n]->get('context')->get('fresh_at') : null;
    $want = static function (string $what, mixed $got, mixed $exp) use (&$fails): void {
        $got === $exp || $fails[] = "$what: got " . json_encode($got) . ', want ' . json_encode($exp);
    };

    // ok / stale / no policy (the three vectors also pin the same outcomes at the core)
    $want('ok', $run('member-equal-state', $policy('member-equal-state'))[0], 'pass');
    [$st, $why] = $run('member-stale-revocation_epoch', $policy('member-stale-revocation_epoch'));
    $want('stale check', $st, 'fail');
    $want('stale escalates', str_contains($why, 'escalate: stale_state'), true);
    $want('no policy, member present', $run('member-without-policy', null)[0], 'fail');
    $want('no policy, no member (default null)', $run('no-member-no-policy', null)[0], 'absent');

    // side-carried: the middleware helper puts the `pca-fresh-at` header token into the policy, only without a member
    $side = static function (string $name, string $header) use ($rows, $policy, $run): array {
        $p = $policy($name)->without('side_carried');
        $q = FreshAt::withSideCarried($p, $rows[$name]->get('pcactn'), $header);
        return [$q, $run($name, $q)[0]];
    };
    foreach (['side-carried-ok' => 'pass', 'side-carried-stale' => 'fail', 'side-carried-garbage' => 'fail'] as $n => $exp) {
        $tok = $policy($n)->get('side_carried');
        $hdr = $n === 'side-carried-garbage' ? '{not json' : Json::canonicalizeLenient($tok);
        [$q, $st] = $side($n, $hdr);
        $want("header $n", $st, $exp);
    }
    [$q] = $side('side-carried-garbage', '{not json');
    $want('unparseable header is a null token', $q->has('side_carried') && $q->get('side_carried') === null, true);
    $want('no header leaves the policy alone', FreshAt::withSideCarried($policy('no-member-required'), $rows['no-member-required']->get('pcactn'), '')->has('side_carried'), false);
    $want('no policy, header ignored', FreshAt::withSideCarried(null, $rows['side-carried-ok']->get('pcactn'), '{}'), null);
    $p = $policy('member-equal-state');
    $want('member wins over header', FreshAt::withSideCarried($p, $rows['member-equal-state']->get('pcactn'), '{}')->has('side_carried'), false);
    return $fails;
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $f = freshAtAuthorizeRun();
    foreach ($f as $m) {
        fwrite(STDERR, "FAIL: $m\n");
    }
    echo count($f) === 0 ? "fresh-at authorize: ok\n" : '';
    exit($f === [] ? 0 : 1);
}
