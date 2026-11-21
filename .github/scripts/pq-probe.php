<?php
// Fails fast, with a clear message, when this runner is meant to have ML-DSA (PCA_REQUIRE_PQ=1) and the lane's probe cannot reach it.
// Run from the SDK directory (the working directory holds vendor/autoload.php).
require getcwd() . '/vendor/autoload.php';
echo 'php ', PHP_VERSION, ' ', PHP_OS_FAMILY, ' ffi=', extension_loaded('ffi') ? 'loaded' : 'NOT loaded', ' ffi.enable=', var_export(ini_get('ffi.enable'), true), "\n";
echo 'libcrypto candidates:', "\n";
foreach (Atlas\Pca\OpensslPq::candidates() as $c) {
    echo '  ', $c, is_file($c) ? '' : ' (missing)', "\n";
}
$ok = Atlas\Pca\Mldsa::available();
echo 'ML-DSA-65 via OpenSSL over FFI: ', $ok ? 'available' : 'NOT available', "\n";
if (!$ok && getenv('PCA_REQUIRE_PQ') === '1') {
    echo "::error::PCA_REQUIRE_PQ=1 but ML-DSA-65 is not reachable: need ext-ffi with ffi.enable=1 and an OpenSSL >= 3.5 libcrypto (see the candidates above)\n";
    exit(1);
}
exit(0);
