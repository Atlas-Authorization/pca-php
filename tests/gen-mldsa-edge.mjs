// Generates test-data/mldsa65-edge.json: ML-DSA-65 signatures (TS reference, deterministic seed) over an EMPTY message and
// a 1-byte message, for the Mldsa::verify buffer edges (a zero-length message still needs a 1-byte FFI buffer).
//   node sdks/php-pca/tests/gen-mldsa-edge.mjs        (needs packages/pca/dist)
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as pca from '../../../packages/pca/dist/index.js';
const kp = pca.mlDsa65Keygen(new Uint8Array(createHash('sha256').update('atlas-pca-php/mldsa-edge').digest()));
const sign = (m) => pca.b64u(pca.mlDsa65Sign(kp.secretKey, m));
const out = { pq_pk: pca.encodeMlDsaPublicKey(kp.publicKey), empty_sig: sign(new Uint8Array(0)), one_byte_msg: pca.b64u(new Uint8Array([0x61])), one_byte_sig: sign(new Uint8Array([0x61])) };
for (const [m, s] of [[new Uint8Array(0), out.empty_sig], [new Uint8Array([0x61]), out.one_byte_sig]]) if (!pca.mlDsa65Verify(kp.publicKey, m, pca.unb64u(s))) throw new Error('self-check failed');
writeFileSync(new URL('../test-data/mldsa65-edge.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log('ok');
