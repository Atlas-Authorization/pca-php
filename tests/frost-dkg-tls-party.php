<?php
declare(strict_types=1);

// One DKG participant as its own process, driven by FrostDkgTlsTest: `php frost-dkg-tls-party.php <config.json>`.
// stdout: `PORT <n>`; then it reads one JSON line of peer addresses from stdin, connects, runs the DKG (unless link-only) and prints `RESULT {json}` or `ERROR <message>`.
require __DIR__ . '/../vendor/autoload.php';

use Atlas\Pca\FrostDkgChannel;
use Atlas\Pca\FrostDkgTls;
use Atlas\Pca\Pca;

$cfg = json_decode((string)file_get_contents($argv[1]), true, 16, JSON_THROW_ON_ERROR);
try {
    $node = FrostDkgTls::startTlsDkgNode(['self' => $cfg['self'], 'sessionId' => Pca::unb64u($cfg['sessionId']), 'keyPem' => $cfg['keyPem'], 'certPem' => $cfg['certPem'],
        'peerCerts' => $cfg['peerCerts']]);
    fwrite(STDOUT, 'PORT ' . $node->port . "\n");
    fflush(STDOUT);
    $addresses = json_decode((string)fgets(STDIN), true, 16, JSON_THROW_ON_ERROR);
    $ch = $node->connect($addresses, $cfg['connectTimeoutMs'] ?? 20000);
    if (($cfg['mode'] ?? 'dkg') === 'link-only') {
        fwrite(STDOUT, "RESULT {\"linked\":true}\n");
        $node->close();
        exit(0);
    }
    $r = FrostDkgChannel::run($ch, ['t' => $cfg['t'], 'participants' => $cfg['participants'], 'sessionId' => Pca::unb64u($cfg['sessionId']), 'timeoutMs' => 30000]);
    $kp = $r['keyPackage'];
    $gpk = $kp->get('groupPublicKey');
    fwrite(STDOUT, 'RESULT ' . json_encode(['id' => $cfg['self'], 'gpk' => Pca::b64u($gpk), 'qualified' => count($r['qualified'])]) . "\n");
    $node->close();
} catch (Throwable $e) {
    fwrite(STDOUT, 'ERROR ' . $e->getMessage() . "\n");
    exit(1);
}
