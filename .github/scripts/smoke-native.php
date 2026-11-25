<?php
// smoke-native.php <module,module,...>: run from a clean directory against a composer-installed package; loads each packaged native
// library through the SDK's own loaders and makes one call.
require __DIR__ . '/vendor/autoload.php';

use Atlas\Pca\{AdaUrl, FheSeal, FndsaNative, LessFfi, MpcLweLattice, NativeDir, OpensslPq, SandboxWasmHost, Bls12, ZkNative};

$checks = [
    'pairing' => fn() => NativeDir::lib('blst') !== null && Bls12::isInf(1, Bls12::identity(1)),
    'fhe' => fn() => NativeDir::lib('sealc') !== null && FheSeal::available(),
    'lwe-ot' => fn() => NativeDir::lib('lweot') !== null && MpcLweLattice::available(),
    'fndsa' => fn() => NativeDir::lib('fndsa') !== null && FndsaNative::available(),
    'zk' => fn() => NativeDir::lib('pcazk') !== null && ZkNative::available(),
    'ada' => fn() => NativeDir::lib('ada') !== null && AdaUrl::available(),
    'less' => fn() => NativeDir::lib('atlas_less') !== null && LessFfi::available(),
    'openssl' => fn() => NativeDir::lib('crypto') !== null && OpensslPq::available('ML-DSA-65'),
    'sandbox' => fn() => SandboxWasmHost::packaged()?->verify() === null && SandboxWasmHost::packaged() !== null,
];
$bad = 0;
foreach (explode(',', $argv[1] ?? '') as $m) {
    $ok = isset($checks[$m]) && $checks[$m]();
    echo ($ok ? 'ok   ' : 'FAIL ') . $m . "\n";
    $bad += $ok ? 0 : 1;
}
exit($bad === 0 ? 0 : 1);
