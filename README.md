# pca-php — Proof-Carrying Authority verifier for PHP

An **offline verifier for Proof-Carrying Actions (PCActns)** in PHP. A PCActn is the credential an
autonomous agent presents with *every* action it takes: a self-contained, cryptographically-checkable
object proving the action is a faithful execution of authority its principal actually granted. Your
resource server verifies it locally — no token introspection, no network call on the hot path.

This library is the PHP member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

## Install

The verifier is a small source package under `src/` (namespace `Atlas\Pca`). Vendor it into your project
or clone the repo and autoload it. It relies on PHP's built-in `sodium` extension for Ed25519.

```php
use Atlas\Pca\Pca;
```

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (raw JSON via `verifyJson`, or a parsed value via
`verifyPcactnCore`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check
results.

```php
<?php
use Atlas\Pca\Pca;

// `$raw` is the PCActn as received (strict canonical JSON, wire version 2).
// `$grant` is the Root Intent Grant the action's capability chain roots in.
$verdict = Pca::verifyJson(
    $raw,
    $grant,
    (int) (microtime(true) * 1000),
    'https://api.example.com'
);

if ($verdict['allow']) {
    // every core check passed — execute the action
} else {
    error_log('denied: ' . json_encode($verdict['checks']));
}
```

The verdict reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter_format`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Authorize an operation

`Authorize::authorize` is the full decision for one operation. It runs the core checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
  and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
  refused);
- checks revocation with your `isRevoked` (only `false` passes);
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without an audience, grant resolver, state store or revocation check, or without the
operation, the call is refused and `$result->missing` names what is absent. `authorize` never throws: an internal error
is a denial.

```php
use Atlas\Pca\Authorize;
use Atlas\Pca\Obj;
use Atlas\Pca\PdoStateStore;

$store = new PdoStateStore(new PDO('sqlite:pca-replay.db')); // SQLite or PostgreSQL; $store->createTable() once
$result = Authorize::authorize(
    $pcactn,
    ['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => $body], // what you will execute; $body is an Obj
    'payments-rs',
    fn (string $grantRef) => $grants[$grantRef] ?? null,          // grant_ref -> grant, from your own store
    $store,
    fn (Obj $pcactn, Obj $grant) => in_array($grant->get('id'), $revokedGrantIds, true),
    plan: Authorize::SINGLE_STEP,
);
if (!$result->allow) {
    throw new RuntimeException($result->reason); // e.g. "policy: caveat(s) not satisfied: max_spend"
}
sendPayment($body);
```

- `plan: Authorize::SINGLE_STEP` accepts a proof whose plan is this one operation. For a multi-step plan, pass
  `context: fn (Obj $pcactn) => ['plan' => $nodes, 'plan_authorized' => true]` with the plan the principal authorized.
- `$result->status` is 200, 401 (no proof, or one that fails authentication) or 403. `$result->checks` maps every check
  to `pass`, `fail` or `not-enforced`, and `$result->reason` is the decisive failure. On success `$result->operation`
  is the bound operation (verb, resource, params digest, and an `id` for the proof), and
  `Authorize::isAuthorizedFor($result, $operation)` re-checks it where the side effect runs.
- The operation comes from your own routing and parsed request, never from the proof. Its params must be an `Obj`.
- `MemoryStateStore` lives for one request under PHP-FPM, so it never refuses a replay across requests: use
  `PdoStateStore` (one atomic `INSERT ... ON CONFLICT DO UPDATE ... WHERE` statement) or your own store with an atomic
  `claim(string $key, int $counter): ClaimResult`.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

`PcaMiddleware` runs this pipeline by default; the `authorize:` option (an `AuthorizeOptions` with the store, the
revocation check and an `operation` callback that maps the request to the operation) carries its components. Without
`authorize:` (and without `signatureOnly: true`) the options are empty and every request is refused with a 403
`authorize_config` whose `missing` list names the absent components. A denial is a 401 or 403 JSON response before your
handler runs; on success the request carries `pca.operation` and `pca.authorization` attributes.

To verify the signature and chain only, opt in explicitly with `signatureOnly: true`. It cannot be combined with
`authorize:` (the constructor throws `InvalidArgumentException`).

```php
$mw = new PcaMiddleware('payments-rs', $resolveGrant, signatureOnly: true);
```

### Check names

The core verifier reports the counter's format as `counter_format`. `authorize` reports the stateful check as `replay`,
with the reasons `replay: N is not greater than last seen M (replay)`, `replay: N was already claimed (replay)` and
`replay: the replay store failed (fail closed)`. `replay` is required, like `counter_format`, `revocation`,
`plan_root_authorized`, `audience`, `validity`, `grant_ref_bound`, `operation`, `params_digest` and `policy`. In
`require`, the name `counter` is an alias of `replay`.

### Limit-naming denial reasons

When an action's verb and resource are covered by an envelope predicate but one of its `where` limits is not met, the
reason names the limit instead of the generic text:

```
policy: amount <= 100 not satisfied for payments.send on payments/acme
```

A condition renders as `name op operand` (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`, `starts with`, `like`,
`matches`, `is a`, `member of`, `present`, `absent`); a `field` loses its `action.params.` prefix; an `all_of` shows its
first unmet child. Operands are shown only when they are safe integers, booleans, null, short plain strings or short
lists of those; anything else prints as `<value>`. When no predicate covers the verb and resource the text stays
`no predicate permits <verb> on <resource>`, and an empty list stays `envelope grants no predicates`.

### Upgrading to 0.5

- `PcaMiddleware` now runs `authorize` by default. Pass `authorize: new AuthorizeOptions(stateStore: ..., isRevoked: ...,
  operation: ...)`, or `signatureOnly: true` to keep the old signature-only behaviour.
- The core `counter` check is now `counter_format`; the stateful check in `authorize` is `replay`.
- A `require` entry `counter` still works and means `replay`.

## Caveats (policy layer)

The verifier above checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats. A resource server that enforces caveats evaluates them with its own action
parameters: `Pca::evaluateCaveats(Pca::policyCaveats($grant, $chain), $ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`Pca::decodePcaHeader($value)` (null when invalid)).

## What a passing result does not cover

`counter_format: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
Verification is stateless and this package has no replay store, so the resource server must persist, per grant and
agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its processes.

With `signatureOnly: true`, the PSR-15 `PcaMiddleware` runs the core verifier only. It does not check replay, revocation, caveats, envelope predicates, plan
authorization, risk or thresholds, and it does not compare the request body with the signed `params_digest`. Do those
checks in your handler (the caveat helpers above, the params digest of the body you will execute, your replay and
revocation stores), or use the default (`authorize:`), which does them.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): 676 golden and adversarial PCActns with their expected verdicts,
plus canonical-JSON, strict-base64url, and Merkle primitive vectors. `php conformance.php` runs the
verifier against every vector; it must reproduce `allow` and every listed check exactly.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and post-quantum public key are part of the signed body, so a suite downgrade or key swap
invalidates the action.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered. The broader
framework surface is implemented and tested in the reference implementation: threshold/step-up co-signing
(a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM allow),
TEE/hardware and model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof),
optimistic bonds and the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs
with abort). A few rungs carry a remaining production requirement, stated plainly rather than hidden
behind a label: a live TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested
against real-crypto mock reports); unforgeable FROST guardian custody needs each share in a separate trust
domain / HSM with a network signing protocol (the reference runs the signing round in-process); the MPC
Policy VM's offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and
the zero-knowledge circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller
policy coverage ongoing. See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the
full model.

## License

See `LICENSE`.
