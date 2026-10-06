# pca-php

Proof-Carrying Authority (PCA) verifier for PHP. **Preview.**

PCA is authF: instead of verifying a token, you verify a proof-carrying action (a PCActn) - the capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. This is a reference verifier that passes the shared conformance vectors.

> Preview: the wire format and API may change before 1.0.

## Install

Preview: `composer require atlas-authorization/pca-php` once listed on Packagist; until then add this repo as a VCS repository in `composer.json`, or copy `src/` (namespace `Atlas\Pca`).

## Verify

```php
use Atlas\Pca\Pca;

$v = Pca::verifyPcactnCore($pcactn, $grant); // decoded JSON (see Atlas\Pca\Json)
if ($v['allow']) {
    // chain, plan_inclusion, leaf_signature, counter all passed
} else {
    echo $v['reason'];
}
```

## Conformance tests

The shared golden vectors are vendored in `conformance/` (synced from the hub). Run:

```
php conformance.php
```

The reference verifier must produce the same `allow` and the same pass/fail for each of the four checks on every vector.

## Links

- Hub (spec, other languages): https://github.com/Atlas-Authorization/pca
- Live docs: https://atlasauth.net/pca
- TypeScript reference: npm `@atlasauth/pca`

## License

MIT
