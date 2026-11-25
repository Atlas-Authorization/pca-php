<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Siem.php';

/** The scrubbed copy of a guard failure recorded on a span: a fresh message, no cause, a sanitised class name. */
final class TelemetryError extends \Exception
{
    public function __construct(string $message, public readonly string $name = 'Error')
    {
        parent::__construct($message);
    }
}

/**
 * OpenTelemetry instrumentation for PCA: wrap a verification guard so every decision emits a span and two metrics (the reference's
 * pca-otel). Nothing from OpenTelemetry is imported: pass any tracer-like object (startSpan(name) -> span with setAttribute /
 * setStatus / recordException / end) and meter-like object (createCounter(name)->add(n, attrs), createHistogram(name)->record(n,
 * attrs)). setStatus receives a plain ['code' => int, 'message'? => string] array (UNSET 0, OK 1, ERROR 2); wrap it if your SDK wants a
 * Status object. This observes, it never decides: a tracer, meter or redactor that throws never changes what the guard returned.
 */
final class Otel
{
    public const STATUS_OK = 1;
    public const STATUS_ERROR = 2;
    public const MAX_TEXT = 256;

    /** @return list<array{0:string,1:string}> pattern, replacement */
    private static function rules(): array
    {
        $ws = Siem::WS;
        $nw = '(?:(?!' . $ws . ')[^/@])*';
        return [
            ['%\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*%', '[redacted]'],
            ['%\b(authorization["\']?' . $ws . '*[:=]' . $ws . '*)[^\n"\']*%i', '${1}[redacted]'],
            ['%\b(Bearer|Basic|Token)' . $ws . '+[\w.~+/=-]{6,}%i', '${1} [redacted]'],
            ['%([a-z][a-z0-9+.-]*://)' . $nw . ':' . $nw . '@%i', '${1}[redacted]@'],
        ];
    }

    private static function kvPattern(): string
    {
        $ws = Siem::WS;
        return '%\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)["\']?' . $ws . '*[:=]' . $ws . '*)'
            . '("[^"]*"|\'[^\']*\'|(?:(?!' . $ws . ')[^"\'&,;])+)%i';
    }

    /**
     * Remove what looks like a credential from text bound for telemetry (JWTs, Bearer / Basic credentials, URL userinfo, name=value
     * pairs for secret-like names, 32+ character base64url / hex runs) and cut the result to 256 characters.
     */
    public static function redactSecrets(mixed $text): string
    {
        $t = is_string($text) ? $text : Jsx::str($text);
        foreach (self::rules() as [$rx, $rep]) {
            $r = preg_replace($rx, $rep, $t);
            if ($r === null) { // a pattern gave up: nothing unredacted leaves
                return '[redacted]';
            }
            $t = $r;
        }
        $r = preg_replace_callback(self::kvPattern(), static function (array $m): string {
            $q = ($m[2] !== '' && ($m[2][0] === '"' || $m[2][0] === "'")) ? $m[2][0] : '';
            return $m[1] . $q . '[redacted]' . $q;
        }, $t);
        $r = $r === null ? null : preg_replace('%[A-Za-z0-9_-]{32,}%', '[redacted]', $r);
        if ($r === null) {
            return '[redacted]';
        }
        return Js::len($r) > self::MAX_TEXT ? Siem::u16slice($r, self::MAX_TEXT) . '...' : $r;
    }

    private static function g(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null;
    }

    private static function isNum(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f);
    }

    /** result?.verdict?.reasons?.[0], including JavaScript indexing into a string or an object keyed "0". */
    private static function firstReason(mixed $result): mixed
    {
        $rs = self::g(self::g($result, 'verdict'), 'reasons');
        if (is_array($rs) && array_is_list($rs)) {
            return $rs[0] ?? null;
        }
        if (is_string($rs)) {
            return $rs !== '' ? Siem::u16slice($rs, 1) : null;
        }
        return self::g($rs, '0');
    }

    /**
     * Span attributes for a guard result; absent fields are omitted and pca.reason is added on deny only. Anything but an explicit
     * ok is reported as a deny.
     * @return array<string,mixed>
     */
    public static function pcaSpanAttributes(mixed $result, ?callable $redact = null): array
    {
        $red = $redact ?? self::redactSecrets(...);
        $ok = self::g($result, 'ok') === true;
        $attrs = ['pca.decision' => $ok ? 'allow' : 'deny'];
        $status = self::g($result, 'status');
        if (self::isNum($status)) {
            $attrs['pca.status'] = $status;
        }
        $verdict = self::g($result, 'verdict');
        $tier = self::g(self::g($verdict, 'requiredThreshold'), 't');
        if (self::isNum($tier)) {
            $attrs['pca.tier'] = $tier;
        }
        $risk = self::g($verdict, 'r');
        if (self::isNum($risk)) {
            $attrs['pca.risk'] = $risk;
        }
        $action = self::g(self::g($result, 'pcactn'), 'action');
        $verb = self::g($action, 'verb');
        if (is_string($verb)) {
            $attrs['pca.verb'] = $red($verb);
        }
        $resource = self::g($action, 'resource');
        if (is_string($resource)) {
            $attrs['pca.resource'] = $red($resource);
        }
        if (!$ok) {
            $reason = self::firstReason($result);
            if (is_string($reason)) {
                $attrs['pca.reason'] = $red($reason);
            }
        }
        return $attrs;
    }

    private static function safe(callable $f): void
    {
        try {
            $f();
        } catch (\Throwable) { // the decision is the guard's, not the exporter's
        }
    }

    /**
     * Wrap a guard so each decision emits a span (default name pca.verify) and metrics (a pca.verifications counter and a
     * pca.verify.risk histogram, created once). The wrapper returns the guard's result unchanged and rethrows its exceptions after
     * recording a scrubbed copy on the span. With no tracer and no meter it is a transparent pass-through.
     * Options (an Obj or an assoc array): tracer, meter, spanName, redact.
     */
    public static function instrumentGuard(callable $guard, mixed $options = null): \Closure
    {
        $tracer = Js::opt($options, 'tracer');
        $meter = Js::opt($options, 'meter');
        $spanName = Js::opt($options, 'spanName');
        $redact = Js::opt($options, 'redact');
        $name = $spanName ?? 'pca.verify';
        $counter = $meter !== null ? $meter->createCounter('pca.verifications') : null;
        $histogram = $meter !== null ? $meter->createHistogram('pca.verify.risk') : null;
        $red = $redact ?? self::redactSecrets(...);

        $start = static function () use ($tracer, $name): mixed {
            $span = null;
            self::safe(static function () use (&$span, $tracer, $name): void {
                $span = $tracer !== null ? $tracer->startSpan($name) : null;
            });
            return $span;
        };
        $okPath = static function (mixed $span, mixed $result) use ($red, $counter, $histogram): void {
            if ($span !== null) {
                self::safe(static function () use ($span, $result, $red): void {
                    foreach (self::pcaSpanAttributes($result, $red) as $k => $v) {
                        $span->setAttribute((string)$k, $v);
                    }
                    $reason = self::g($result, 'ok') === true ? null : self::firstReason($result);
                    if (self::g($result, 'ok') === true) {
                        $span->setStatus(['code' => self::STATUS_OK]);
                    } elseif (is_string($reason)) {
                        $span->setStatus(['code' => self::STATUS_ERROR, 'message' => $red($reason)]);
                    } else {
                        $span->setStatus(['code' => self::STATUS_ERROR]);
                    }
                });
            }
            $decision = self::g($result, 'ok') === true ? 'allow' : 'deny';
            if ($counter !== null) {
                self::safe(static fn() => $counter->add(1, ['decision' => $decision]));
            }
            $risk = self::g(self::g($result, 'verdict'), 'r');
            if ($histogram !== null && self::isNum($risk)) {
                self::safe(static fn() => $histogram->record($risk, ['decision' => $decision]));
            }
        };
        $errPath = static function (mixed $span, \Throwable $e) use ($red): void {
            if ($span === null) {
                return;
            }
            self::safe(static function () use ($span, $e, $red): void {
                // a fresh error: the original may carry credentials in its message, cause or trace
                $nm = (new \ReflectionClass($e))->getShortName();
                $clean = new TelemetryError($red($e->getMessage()), preg_match('/\A\w{1,64}\z/', $nm) === 1 ? $nm : 'Error');
                $span->recordException($clean);
                $span->setStatus(['code' => self::STATUS_ERROR, 'message' => $clean->getMessage()]);
            });
        };
        $end = static function (mixed $span): void {
            if ($span !== null) {
                self::safe(static fn() => $span->end());
            }
        };
        return static function (mixed ...$args) use ($guard, $start, $okPath, $errPath, $end): mixed {
            $span = $start();
            try {
                $result = $guard(...$args);
                $okPath($span, $result);
                return $result;
            } catch (\Throwable $e) {
                $errPath($span, $e);
                throw $e;
            } finally {
                $end($span);
            }
        };
    }
}
