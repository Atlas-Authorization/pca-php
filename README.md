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
  `risk_policy`, and liveness beacons (signed revocation epochs are covered by `revocationStaleness`, below). A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

`PcaMiddleware` runs this pipeline by default; the `authorize:` option (an `AuthorizeOptions` with the store, the
revocation check and an `operation` callback that maps the request to the operation) carries its components. Without
`authorize:` (and without `signatureOnly: true`) the options are empty and every request is refused with a 403
`authorize_config` whose `missing` list names the absent components. The options also carry `approvedGoal`, `revocationStaleness`, `requireAssurance`, `plans` and `executor` (described below). A denial is a 401 or 403 JSON response before your
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
- With `revocationStaleness`, every capability id in the proof's chain now needs a non-membership proof by default; pass `ids: fn () => []` to check freshness only.
- With `requireAssurance` set, a denial can name the new `assurance` check.

### Approved goal binding

An intent policy can commit to a goal the principal approved. `approved_goal` is a closed object of exactly `goal_digest`
and `policy_digest`, each canonical unpadded base64url of 32 bytes. Pass it in the intent policy you already give
`Authorize::authorize` or `Pca::verifyPcactn`, or as `approvedGoal` on the middleware options:

```php
$policy = Obj::of(['approved_goal' => Obj::of(['goal_digest' => $goalDigest, 'policy_digest' => $policyDigest])]);
```

The root grant's goal commitment then opens only against that approved goal: a grant committed the older way does not open
under it, and a grant committed to an approved goal does not open under a verifier without `approved_goal`. An extra member
or a short, padded or empty digest is a misconfiguration and denies. `approved_goal` alone switches the intent check on; the
fidelity and risk thresholds still apply. `Pca::intentGoalCommitV3($ref, $salt)` builds the commitment a grant should carry
and `Pca::isApprovedGoalRef($value)` validates a reference.

### Revocation staleness

A signed revocation epoch carries an expiry chosen by the signer. `RevocationStalenessPolicy` lets the verifier cap how old
the revocation state may be, with a tighter window for actions that cannot be undone. The action's class is the stricter of
your own class (the `reversibility_class` member of the `context` you return) and the class the proof signed; a missing or
unknown class counts as irreversible.

```php
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStalenessPolicy;

$policy = new RevocationStalenessPolicy(
    maxRevocationAgeMs: 300000.0,                       // any action (default 5 minutes)
    staleness: ['irreversible' => 60000.0],             // per class (defaults: irreversible 2 minutes, costly = the maximum)
    proofs: fn (string $capabilityId, Obj $pcactn) => $proofs[$capabilityId] ?? null, // non-membership proof per capability
);

$result = Authorize::authorize(
    $pcactn, $operation, 'payments-rs', $resolveGrant, $store, $isRevoked,
    revocationStaleness: $policy,
    revocationState: fn (Obj $pcactn, Obj $grant) => new RevocationState(epoch: $signedEpoch), // or new RevocationState(null, $root, $issuedAtMs)
    guardianPublic: $guardianKey,                       // the pinned key a signed epoch must verify under
);
```

- `revocationState` returns the state your trusted source holds: a guardian-signed `epoch` (signature, grant binding,
  expiry, rollback and the proof's own epoch are checked, then the age cap), or a bare `root` with the time it was issued.
  An unsigned root is refused for an irreversible action unless `allowUnsignedRootForIrreversible` is set, and an unknown
  issue time denies. A post-quantum guardian needs `guardianPins`.
- A state that is too old, from the future, unverifiable or missing for an irreversible action fails the `freshness` check.
  Your `isRevoked` callback keeps deciding revocation itself.
- **Per-capability proofs.** Alongside the age check, every capability id in the proof's chain needs a valid
  non-membership proof against the state's root. The `ids` argument (`fn (Obj $pcactn): array`) overrides which ids are
  proven; the default is every id in the chain, so a revoked ancestor kills its descendants. `proofs` is a
  `fn (string $id, Obj $pcactn)` callable or an array keyed by id. A missing proof source or proof denies
  (`no non-membership proof for <id>`), and so does a revoked id or an invalid proof
  (`capability <id> is revoked or proof invalid`). To check freshness only, pass `ids: fn () => []`.
  `RevocationStaleness::verifyNonMembership($root, $proof, $id)` checks one proof on its own.
- The helpers are public: `RevocationStaleness::gate`, `checkAge`, `checkEpoch`, `maxAgeMs`, `effectiveReversibility`
  and `signEpoch` (for an Ed25519 guardian). `PcaMiddleware` takes the same options through `AuthorizeOptions`.

### Operation records and the executor

`authorize` consumes the proof's counter, but a crash, a client retry or two workers can still run the side effect twice or
lose track of it. `Operations::executeAuthorized` runs an authorized operation at most once and keeps a durable record per
operation id (the digest of the presented proof):

```php
use Atlas\Pca\ExecuteOptions;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\Operations;
use Atlas\Pca\RecheckResult;

$ops = new MemoryOperationStore(); // one process only; use PdoOperationStore in production

$outcome = Operations::executeAuthorized($result, // an allowing AuthorizeResult
    fn (ExecutionHandle $h) => charge($body, idempotencyKey: $h->idempotencyKey), // pass the key to the downstream call
    new ExecuteOptions(
        store: $ops,
        operation: ['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => $body],
        recheck: fn ($h) => isRevoked($h->pcactn) ? RecheckResult::refuse('revoked') : RecheckResult::ok(),
    ));

$outcome->status; // committed, failed, aborted, pending, uncertain or refused
```

- The record is created `pending` before anything runs (one atomic create, so of N concurrent executions exactly one runs
  the callback), moves to `executing`, then `committed` (with the callback's result) or `failed` (with its error). A second
  call with the same id is answered from the record (`$outcome->replayed`) and never runs the callback again; a throw from
  it is recorded, not rethrown. The result must be a JSON value.
- An irreversible operation (your `reversibilityClass` or the signed one; unknown counts as irreversible) needs a
  `recheck`, called immediately before the callback; the proof's own expiry is always checked. A refusal records `aborted`.
- `Operations::recoverOperations($store, $olderThanMs)` (needs a store with `listOpen`) and `recoverOperation($store, $id)`
  settle stale records: a `pending` one becomes `aborted` (the side effect never started), an `executing` one `uncertain`
  (it may or may not have happened). Reconcile an uncertain record with the downstream system, using the idempotency key,
  then settle it with `Operations::resolveOperation($store, $id, ['state' => 'committed', 'result' => ...])` or
  `['state' => 'failed', 'error' => '...']`.
- Stores: `MemoryOperationStore`, and `PdoOperationStore` over SQLite or PostgreSQL (`createTable()` once; a unique-key
  insert and a conditional update). Your own store implements `create`, `get` and `transition` (a compare-and-set on the
  state), each atomic across everything that shares it.

`Executor` combines `authorize` and `executeAuthorized`, so a retry of the same proof is answered from its record instead of
a bare replay denial:

```php
use Atlas\Pca\Executor;

$executor = new Executor($ops, [
    'audience' => 'payments-rs', 'resolveGrant' => $resolveGrant, 'stateStore' => $store, 'isRevoked' => $isRevoked,
], reversibilityClassOf: fn ($operation) => catalogClass($operation));

$outcome = $executor->run($pcactn, $operation, fn (ExecutionHandle $h) => charge($body, idempotencyKey: $h->idempotencyKey));
```

The executor re-runs `isRevoked`, checks the proof's expiry and, with `plans`, that a registered plan is still executable,
right before the callback. A denial comes back as `$outcome->status === 'denied'` with the `AuthorizeResult` in
`$outcome->authorization`.

`PcaMiddleware` takes the same thing as the `executor` option (an `ExecutorOptions` with the store): the handler runs at
most once per authorization, its response is recorded, and a retry is answered from the record with a `PCA-Replayed: true`
header. An execution that failed answers 500, one still in flight or uncertain answers 409, and a refused re-check 409.

### Plan lifecycle

A plan is the list of steps an agent commits to; its Merkle root is signed into every proof. `PlanRegistry` gives the
principal's approval of a plan an explicit lifecycle (draft, validated, committed, authorized, revoked), and `authorize`
consults it:

```php
use Atlas\Pca\PlanRegistry;

$registry = new PlanRegistry(); // or new PlanRegistry(new PdoAtomicKv($pdo)) for a shared, durable registry

$draft = $registry->draft($grantRef, [['id' => 'pay', 'verb' => 'payments.send', 'resource' => 'payments/acme']]);
$root  = $draft['record']->get('root');   // computed from the nodes, never taken from the caller
$registry->validate($grantRef, $root);    // structural checks, then your optional validator
$registry->commit($grantRef, $root);      // the root is fixed; still not executable
$registry->authorize($grantRef, $root, ['by' => 'principal', 'expiresAt' => $expiresMs]); // after verifying the principal's consent

Authorize::authorize($pcactn, $operation, 'payments-rs', $resolveGrant, $store, $isRevoked, plans: $registry);
```

Each call returns an array with `ok`, the `state` and a `reason` when refused. A plan is executable only while it is
authorized, the approval has not expired and its stored nodes still hash to the root; that is evaluated at the moment of
use, not stored. `revoke($grantRef, $root, $reason)` is terminal. `status`, `check` and `isPlanAuthorized` answer questions
about a plan. With `plans`, an unregistered root is refused, and a denial names the plan's state in the `plan_state` check.
Concurrent transitions are atomic: of N racing callers exactly one moves the plan.

### Assurance labels

A check's status says whether it held; the assurance report says what a pass rests on: software or hardware attestation, a
SNARK or an attested-VM statement, a post-quantum or an Ed25519 signature, independent shares or a preview aggregate. Labels
come from your configuration, never from presented evidence. `authorize` verifies no attestation, zk proof or threshold
co-signature itself, so there the report rests on the signature suites and on what the proof carries (a carried feature
this SDK does not verify is reported `unsupported`). When you run your own verifiers, label them and build the report with
them:

```php
use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceRequirement;

$quoteCheck = Assurance::setLabel(fn ($evidence) => checkQuote($evidence), new AssuranceLabel('hardware', vendor: 'amd-sev-snp'));
$report = Assurance::report($checks, $pcactn, ['attestation' => $quoteCheck]);
Assurance::unmet($report, new AssuranceRequirement(attestation: 'hardware')); // null when met, else an "assurance: ..." reason

$result = Authorize::authorize($pcactn, $operation, 'payments-rs', $resolveGrant, $store, $isRevoked,
    requireAssurance: new AssuranceRequirement(signature: 'pq'));
$result->assurance; // what every check rests on (present with or without a requirement)
```

An unlabelled hook is `unknown` and satisfies no requirement. `requireAssurance` turns the report into a gate: evidence that
is weaker, missing, failed, unlabelled, preview, degraded or unsupported fails the `assurance` check, and the request is
denied before any replay state is written, so the counter is not consumed. Requirement members: `attestation` (`software` <
`hardware` < `multi_root`), `zk` (`attested_vm`, `attested_vm_hardware`, `proof`, `snark`), `signature` (`pq`), `threshold`
(a list of schemes) and `allowPreview`. Features this SDK does not verify, such as a carried `bond_ref`, are reported
`unsupported` and never count as a pass. `Assurance::signatureLevel` and `multiRootLevel` are public for custom gates.

### Step-up client

When an action needs more than the agent's signature, a step-up asks the principal's device for a co-signature.
`StepUpClient` lists pending step-ups and approves or denies them with an Ed25519 device key:

```php
use Atlas\Pca\MemorySecretStore;
use Atlas\Pca\PrincipalDeviceKey;
use Atlas\Pca\StepUpClient;

$key = new PrincipalDeviceKey($secretStore); // implement SecretStore over your platform keystore; MemorySecretStore is for tests
if (!$key->exists()) {
    $key->generate();
}
$client = new StepUpClient($dashboardUrl, $instanceUrl, $accountId, $instanceId, $key, fn () => $dashboardToken);

foreach ($client->pending() as $stepUp) {      // not-yet-expired step-ups
    $result = $client->approve($stepUp);       // signs the threshold message with the device key
    echo $result->anchored ? 'anchored' : 'waiting for more roles';
}
$client->deny($other, 'not expected');
```

The dashboard token is a callable, read per request. A threshold message that is not canonical base64url is never signed,
and a step-up id that could rewrite the request path is refused before any request. Failures are a `StepUpException` whose
`kind` is one of `no_device_key`, `invalid_secret`, `invalid_threshold_message`, `invalid_step_up`, `principal_mismatch`
(the server refused this key), `api` and `transport`. The key is a software key: for a phone or desktop app back the secret
store with the platform keystore and gate approvals behind user presence.

### Store conformance

If you write your own replay store or operation store, run the contract against it from a test, with a factory that opens a
new handle onto the same backend each call (one handle is one verifier instance's connection):

```php
use Atlas\Pca\StoreConformance;

$report = StoreConformance::runStateStore(['name' => 'postgres', 'open' => fn () => new MyStateStore(connect()), 'shared' => true, 'durable' => true]);
self::assertTrue($report->ok(), (string)$report);

$opsReport = StoreConformance::runOperationStore(['name' => 'ops', 'open' => fn () => new MyOperationStore(connect())]);
```

The state-store profile checks `claim` over strictly increasing counters, N copies of one counter racing (exactly one is
admitted, every round), durability across dropping every handle (and `restart` when given), a crash after the claim, and a
lost answer followed by a retry. The operation-store profile checks create-once, compare-and-set transitions, wrong-state
refusals, sharing and durability. With `processes: true` the races run in forked processes (needs `ext-pcntl`). A store that
declares itself not durable or not shared skips those checks (reported as skipped, never passed); any other failure is
reported. `(string)$report` prints every result.

## Acting as an agent (producing proofs)

The package also produces the proofs it verifies, so an agent written in PHP needs no other runtime. The principal mints a root grant
for the agent's public key; the agent signs one PCActn per action and sends it in the `PCA-Action` header (`Agent` keeps the replay
counter, picks the nonce and builds the headers).

```php
use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Sign;

$principal = KeyPair::generate(); // the principal's key stays with the principal
$agentKey = KeyPair::generate();

$minted = Sign::mintGrant($principal, $agentKey->public, [
    'predicates' => [['verb' => 'refund', 'resource' => 'orders/*']],
    'caveats' => [['type' => 'max_spend', 'usd' => 50]],
    'risk_policy' => Sign::defaultRiskPolicy(),
], 'refund order 1');

$agent = new Agent($agentKey, $minted['grant'], 'https://api.example.com');
$action = $agent->act('refund', 'orders/1', ['amount_cents' => 500]);
// any HTTP client: send $action->headers
```

`$agent->delegate($subKey, [Sign::sealedCaveat()])` returns a sub-agent holding the chain plus one narrower hop (caveats are only ever
appended). Third-party and approval artifacts: `Sign::signDischarge`, `signNarrow`, `signEscalationAnswer`, `signPassport`,
`signWorkflow` / `signStepReceipt`, `signReadGrant`, `signFreshAt`. Ed25519 outputs are byte-exact against the shared producer vectors.
ML-DSA and SLH-DSA suites sign through OpenSSL >= 3.5 libcrypto over FFI (`new PqKeyPair('ML-DSA-65')`, then
`new Agent(..., alg: 'hybrid-ed25519-ml-dsa-65', pq: $pq)`); without FFI or OpenSSL 3.5, and for FN-DSA and LESS, signing throws
`UnsupportedSigner`. Persist the counter (`onCounter:`) if the process can restart: a lower counter is refused as a replay.

## Caveats (policy layer)

The verifier above checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats. A resource server that enforces caveats evaluates them with its own action
parameters: `Pca::evaluateCaveats(Pca::policyCaveats($grant, $chain), $ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`Pca::decodePcaHeader($value)` (null when invalid)).

## One call: `Protect::protect`, and explaining a refusal

```php
$p = \Atlas\Pca\Protect::protect([
    'audience'  => 'payments-rs',
    'grants'    => [$grant],   // a list of grants looked up by id, or fn(string $ref): ?Obj. Never from the request.
    'operation' => fn ($req) => ['verb' => 'payments.send', 'resource' => 'payments/acme', 'params' => paramsOf($req)],
]);
$p->middleware;                 // a PSR-15 PcaMiddleware (also has Laravel-style handle($request, $next))
$p->revoke($grant->get('id'));  // later: every action under that grant is refused
```

`protect` fills in an in-memory replay store (pass a `PdoStateStore` under PHP-FPM), a revocation source and
`plan: 'single-step'`. Any option you pass wins, and an unknown key is an error. This SDK has no connector catalog, so risk is
not priced for you.

`Refusals::explainRefusal($reason)` returns the check, what it means, the fix and the docs page, and never throws. Every refusal
body carries a `doc` member; the reason strings are unchanged. A runnable Laravel server is in `examples/laravel-server`.

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
