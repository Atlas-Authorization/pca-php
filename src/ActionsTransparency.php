<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/ActionsRegistry.php';
require_once __DIR__ . '/Scitt.php';
require_once __DIR__ . '/ScittLog.php';

/**
 * Append a signed action pack to a SCITT transparency log (RFC 9943) and verify the receipt (native port of transparency.ts of the reference
 * actions package). The statement is a COSE Signed Statement over {ns, version, digest, root, prev}; the receipt is the log's signed inclusion
 * proof. Keys are the scitt module's native key forms (Ed25519 raw seed / public key, or a P-256 JWK).
 */
final class ActionsTransparency
{
    public const PACK_STATEMENT_CONTENT_TYPE = 'application/pca-action-pack+json';

    /** The payload the registry signs into the log (small: the digest, not the pack). */
    public static function packStatementPayload(Obj $p): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-action-pack-statement', 'ns' => $p->get('ns'), 'version' => $p->get('version'),
            'digest' => ActionsRegistry::packDigest($p), 'root' => $p->get('root'), 'prev' => $p->get('prev')]);
    }

    /**
     * Sign the pack's statement with the registry's COSE key ($signer: {alg, key, issuer}) and register it: {statement, receipt, index, root}.
     *
     * @param array<string,mixed> $signer
     * @return array{statement:string,receipt:string,index:int,root:string}
     */
    public static function appendPackToLog(Obj $pack, object $service, array $signer): array
    {
        foreach (['ns', 'version', 'root', 'prev'] as $k) {
            if (!$pack->has($k)) { // an undefined member makes the payload un-canonicalizable
                throw new JsonError('canonicalize: unsupported type undefined');
            }
        }
        $statement = Scitt::signStatement(self::packStatementPayload($pack), ['alg' => $signer['alg'], 'key' => $signer['key'], 'issuer' => $signer['issuer'],
            'subject' => $pack->get('ns') . '@' . $pack->get('version'), 'contentType' => self::PACK_STATEMENT_CONTENT_TYPE]);
        $r = ScittLog::registerStatement($statement, $service);
        return ['statement' => $statement, 'receipt' => $r['receipt'], 'index' => $r['index'], 'root' => $r['root']];
    }

    /**
     * Does $entry prove $pack is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never throws.
     *
     * @param array{statement:string,receipt:string} $entry
     * @param array{log:mixed,registry:mixed} $keys
     */
    public static function verifyPackLogEntry(Obj $pack, array $entry, array $keys, ?string $treeRoot = null): bool
    {
        try {
            $opts = ['verificationKey' => $keys['log'], 'statementKey' => $keys['registry']];
            if ($treeRoot !== null) {
                $opts['treeRoot'] = $treeRoot;
            }
            return Scitt::verifyReceipt($entry['receipt'], $entry['statement'], $opts)
                && Scitt::statementPayload($entry['statement']) === Json::canonicalizeNative(self::packStatementPayload($pack));
        } catch (\Throwable) {
            return false;
        }
    }
}
