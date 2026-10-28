<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

/**
 * Step-up client for the principal's device: list the pending step-ups of an instance, approve one with the principal's Ed25519
 * device key, or deny it. The device signature over the step-up's threshold message is the credential of the cosign call, so no
 * session is needed to approve; listing and denying go through the dashboard API with a bearer token.
 *
 *  - `dashboardUrl` + a dashboard bearer token (a service key or console session token) serve the list and deny calls (deny needs an
 *    owner or admin role).
 *  - `instanceUrl` (the host the agent talks to) serves the public, self-authenticating cosign call.
 */

/** Where the 32-byte Ed25519 seed is persisted. `load` returns null when nothing is stored. */
interface SecretStore
{
    public function load(): ?string;

    public function save(string $secret): void;

    public function delete(): void;
}

/** Keeps the seed in memory, for tests and demos only. */
final class MemorySecretStore implements SecretStore
{
    private ?string $value = null;

    public function load(): ?string
    {
        return $this->value;
    }

    public function save(string $secret): void
    {
        $this->value = $secret;
    }

    public function delete(): void
    {
        $this->value = null;
    }
}

/**
 * Everything the step-up client throws. `kind` is one of the constants; `status` the HTTP status for PRINCIPAL_MISMATCH and API.
 */
final class StepUpException extends \RuntimeException
{
    /** No principal key is stored yet; call `generate` or `importSecret`. */
    public const NO_DEVICE_KEY = 'no_device_key';
    /** The principal secret is not a base64url 32-byte Ed25519 seed. */
    public const INVALID_SECRET = 'invalid_secret';
    /** The server's threshold_message is not valid base64url. */
    public const INVALID_THRESHOLD_MESSAGE = 'invalid_threshold_message';
    /** The step-up id is not a plain URL segment. */
    public const INVALID_STEP_UP = 'invalid_step_up';
    /** HTTP 403: this device key is not the grant's principal key; the message is the server's guidance. */
    public const PRINCIPAL_MISMATCH = 'principal_mismatch';
    /** Any other non-2xx answer (409 already approved, denied or expired, 401, 404, 422, ...). */
    public const API = 'api';
    /** A network failure or an unreadable body. */
    public const TRANSPORT = 'transport';

    public function __construct(public readonly string $kind, string $message, public readonly int $status = 0, ?\Throwable $previous = null)
    {
        parent::__construct($kind === self::API ? "HTTP $status: $message" : $message, 0, $previous);
    }
}

/**
 * The principal's Ed25519 device key. Honest caveat: the PCA principal key MUST be Ed25519, and hardware key stores rarely offer a
 * portable Ed25519 key, so this is a software key: the 32-byte seed lives in the {@see SecretStore} you provide (put it in your
 * platform's secure store). Once loaded it is in process memory. Gate approvals behind a user-presence check in your application.
 */
final class PrincipalDeviceKey
{
    public function __construct(private readonly SecretStore $store)
    {
    }

    public function exists(): bool
    {
        $s = $this->store->load();
        return $s !== null && $s !== '';
    }

    private function save(string $seed): string
    {
        $this->store->save($seed);
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)));
    }

    /** Create a fresh key (replacing any existing one); returns its public key (base64url) to register as the grant's principal. */
    public function generate(): string
    {
        return $this->save(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));
    }

    /** Import an existing principal secret (a base64url 32-byte seed). The key MUST match the grant's principal. Returns the public key. */
    public function importSecret(string $secretB64u): string
    {
        $raw = Pca::unb64u($secretB64u, SODIUM_CRYPTO_SIGN_SEEDBYTES);
        if ($raw === null) {
            throw new StepUpException(StepUpException::INVALID_SECRET, 'The principal secret must be a base64url-encoded 32-byte Ed25519 seed.');
        }
        return $this->save($raw);
    }

    private function seed(): string
    {
        $seed = $this->store->load();
        if ($seed === null || $seed === '') {
            throw new StepUpException(StepUpException::NO_DEVICE_KEY, 'No principal device key is stored on this device.');
        }
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new StepUpException(StepUpException::INVALID_SECRET, 'The principal secret must be a base64url-encoded 32-byte Ed25519 seed.');
        }
        return $seed;
    }

    /** The secret (base64url seed) for backup or migration. Treat it like a password. */
    public function exportSecret(): string
    {
        return Pca::b64u($this->seed());
    }

    /** The public key (base64url), as registered on the grant. */
    public function publicKey(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($this->seed())));
    }

    /** Ed25519-sign `$message`; the signature as base64url. */
    public function sign(string $message): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($this->seed()))));
    }

    public function delete(): void
    {
        $this->store->delete();
    }
}

/** An action waiting for the principal's device signature. `expiresAt` is epoch milliseconds. */
final class PendingStepUp
{
    public function __construct(
        public readonly string $id,
        public readonly string $grantRef,
        public readonly string $actionVerb,
        public readonly string $actionResource,
        public readonly int $requiredT,
        /** the base64url of the exact bytes the principal key must sign */
        public readonly string $thresholdMessageB64u,
        public readonly int $expiresAt,
    ) {
    }

    /** A human summary for a confirmation sheet, for example `payments.refund on order/1234`. */
    public function summary(): string
    {
        return $this->actionVerb . ' on ' . $this->actionResource;
    }
}

/** The result of an approval. `anchored` is true once enough roles signed and the action was released. */
final class ApproveResult
{
    public function __construct(public readonly string $status, public readonly bool $anchored, public readonly int $httpStatus)
    {
    }
}

final class StepUpClient
{
    private const MAX_BODY = 1048576;

    /** @var \Closure(string,string,array<string,string>,?string):array{0:int,1:string} */
    private readonly \Closure $http;
    /** @var \Closure():string */
    private readonly \Closure $token;
    /** @var \Closure():int */
    private readonly \Closure $now;
    private readonly string $dashboard;
    private readonly string $instance;

    /**
     * @param callable():string $token the dashboard bearer token
     * @param callable|null $http `(string $method, string $url, array $headers, ?string $body): array{0:int,1:string}` returns
     *        [HTTP status, body]; default: PHP streams with a 30 second timeout (a body over 1 MiB is cut)
     * @param callable|null $now `(): int` epoch milliseconds (default: the wall clock); expired step-ups are dropped from `pending`
     */
    public function __construct(string $dashboardUrl, string $instanceUrl, private readonly string $accountId, private readonly string $instanceId,
                                private readonly PrincipalDeviceKey $key, callable $token, ?callable $http = null, ?callable $now = null)
    {
        foreach (['dashboardUrl' => $dashboardUrl, 'instanceUrl' => $instanceUrl] as $what => $raw) {
            $u = parse_url($raw);
            if ($u === false || !in_array($u['scheme'] ?? '', ['http', 'https'], true) || ($u['host'] ?? '') === '') {
                throw new \InvalidArgumentException("StepUpClient: $what must be an http(s) URL");
            }
        }
        if (!self::validId($accountId) || !self::validId($instanceId)) {
            throw new \InvalidArgumentException('StepUpClient needs a valid accountId and instanceId');
        }
        $this->dashboard = rtrim($dashboardUrl, '/');
        $this->instance = rtrim($instanceUrl, '/');
        $this->token = \Closure::fromCallable($token);
        $this->http = $http !== null ? \Closure::fromCallable($http) : self::streamHttp(...);
        $this->now = $now !== null ? \Closure::fromCallable($now) : static fn(): int => (int)(microtime(true) * 1000);
    }

    /** A path segment the client may put in a URL: letters, digits, `_`, `-` and `.`, not `.` or `..`. */
    private static function validId(string $id): bool
    {
        return $id !== '' && $id !== '.' && $id !== '..' && strlen($id) <= 200 && preg_match('/\A[A-Za-z0-9_.-]+\z/D', $id) === 1;
    }

    /** @return array{0:int,1:string} */
    private static function streamHttp(string $method, string $url, array $headers, ?string $body): array
    {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[] = "$k: $v";
        }
        $ctx = stream_context_create(['http' => ['method' => $method, 'header' => implode("\r\n", $h), 'content' => $body ?? '',
            'timeout' => 30, 'ignore_errors' => true, 'follow_location' => 0]]);
        $fp = @fopen($url, 'rb', false, $ctx);
        if ($fp === false) {
            throw new \RuntimeException('could not reach ' . parse_url($url, PHP_URL_HOST));
        }
        $data = (string)stream_get_contents($fp, self::MAX_BODY);
        $meta = stream_get_meta_data($fp);
        fclose($fp);
        $status = 0;
        foreach ($meta['wrapper_data'] ?? [] as $line) {
            if (is_string($line) && preg_match('#\AHTTP/\S+ (\d{3})#', $line, $m) === 1) {
                $status = (int)$m[1];
            }
        }
        return [$status, $data];
    }

    private function stepupsUrl(string ...$parts): string
    {
        return $this->dashboard . '/v1/dashboard/accounts/' . implode('/', array_merge([$this->accountId, 'instances', $this->instanceId, 'pca/stepups'], $parts));
    }

    /** @return array{0:int,1:string} */
    private function call(string $method, string $url, string $bearer, ?string $body): array
    {
        $headers = [];
        if ($bearer !== '') {
            $headers['Authorization'] = "Bearer $bearer";
        }
        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
        }
        try {
            [$status, $data] = ($this->http)($method, $url, $headers, $body);
        } catch (\Throwable $e) {
            throw new StepUpException(StepUpException::TRANSPORT, $e->getMessage(), 0, $e);
        }
        $data = substr((string)$data, 0, self::MAX_BODY);
        if ($status < 200 || $status > 299) {
            $msg = 'The request failed.';
            $env = json_decode($data, true);
            $m = is_array($env) && is_array($env['errors'] ?? null) ? ($env['errors'][0]['message'] ?? null) : null;
            if (is_string($m) && $m !== '') {
                $msg = $m;
            }
            throw new StepUpException($status === 403 ? StepUpException::PRINCIPAL_MISMATCH : StepUpException::API, $msg, $status);
        }
        return [$status, $data];
    }

    private function bearer(): string
    {
        try {
            return (string)($this->token)();
        } catch (\Throwable $e) {
            throw new StepUpException(StepUpException::TRANSPORT, 'Could not get the dashboard token.', 0, $e);
        }
    }

    /**
     * The pending, not-yet-expired step-ups.
     * @return list<PendingStepUp>
     */
    public function pending(): array
    {
        [, $body] = $this->call('GET', $this->stepupsUrl() . '?status=pending', $this->bearer(), null);
        $list = json_decode($body, true);
        if (!is_array($list) || !is_array($list['stepups'] ?? null)) {
            throw new StepUpException(StepUpException::TRANSPORT, 'Unreadable step-up list.');
        }
        $now = ($this->now)();
        $out = [];
        foreach ($list['stepups'] as $s) {
            $exp = null;
            if (is_array($s) && is_string($s['expires_at'] ?? null)) {
                try {
                    $d = new \DateTimeImmutable($s['expires_at']);
                    $exp = $d->getTimestamp() * 1000 + (int)$d->format('v');
                } catch (\Throwable) {
                    $exp = null;
                }
            }
            if ($exp === null || !is_string($s['id'] ?? null) || $s['id'] === '' || !is_string($s['grant_ref'] ?? null) || $s['grant_ref'] === ''
                || !is_string($s['threshold_message'] ?? null) || $s['threshold_message'] === '') {
                throw new StepUpException(StepUpException::TRANSPORT, 'Unreadable step-up entry.');
            }
            if ($exp <= $now) {
                continue;
            }
            $a = is_array($s['action'] ?? null) ? $s['action'] : [];
            $out[] = new PendingStepUp($s['id'], $s['grant_ref'], is_string($a['verb'] ?? null) ? $a['verb'] : '',
                is_string($a['resource'] ?? null) ? $a['resource'] : '', is_int($s['required_t'] ?? null) ? $s['required_t'] : 0,
                $s['threshold_message'], $exp);
        }
        return $out;
    }

    /**
     * Sign the step-up's threshold message with the device key and submit it. Throws a {@see StepUpException} of kind
     * PRINCIPAL_MISMATCH (server 403) when this key is not the grant's principal.
     */
    public function approve(PendingStepUp $stepUp): ApproveResult
    {
        $message = Pca::unb64u($stepUp->thresholdMessageB64u);
        if ($message === null || $message === '') {
            throw new StepUpException(StepUpException::INVALID_THRESHOLD_MESSAGE, "The step-up's threshold message is not valid base64url.");
        }
        if (!self::validId($stepUp->id)) {
            throw new StepUpException(StepUpException::INVALID_STEP_UP, 'The step-up id is not valid.');
        }
        $payload = json_encode(['role' => 'principal', 'publicKey' => $this->key->publicKey(), 'sig' => $this->key->sign($message)], JSON_THROW_ON_ERROR);
        [$status, $body] = $this->call('POST', $this->instance . '/v1/pca/stepups/' . $stepUp->id . '/cosign', '', $payload);
        // 200 + allow:true = anchored; 202 = more roles still required
        $r = json_decode($body, true);
        return new ApproveResult(is_array($r) && is_string($r['status'] ?? null) ? $r['status'] : '', is_array($r) && ($r['allow'] ?? false) === true, $status);
    }

    /** Deny a pending step-up (dashboard endpoint; audited; owner or admin). `$reason` may be empty. */
    public function deny(PendingStepUp $stepUp, string $reason = ''): void
    {
        if (!self::validId($stepUp->id)) {
            throw new StepUpException(StepUpException::INVALID_STEP_UP, 'The step-up id is not valid.');
        }
        $payload = $reason === '' ? '{}' : json_encode(['reason' => $reason], JSON_THROW_ON_ERROR);
        $this->call('POST', $this->stepupsUrl($stepUp->id, 'deny'), $this->bearer(), $payload);
    }
}
