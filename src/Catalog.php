<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Actions.php';

/**
 * The 21 built-in connector actions the agent facade compiles permissions against ({@see Facade}): verb, effective reversibility,
 * blast radius, amount field, aliases and traits. Generated from the reference catalog: do not edit by hand (a test compares it
 * with the reference when the reference sources are present).
 *
 * A spec is a plain array `{connector, action, verb, reversibility, blastRadius, amountField?, resource?, description, aliases?, traits?}`.
 * The default catalog (the reference's DEFAULT_CATALOG) is {@see defaultCatalog}. A verb the catalog does not know resolves to the
 * most cautious spec ({@see uncataloguedSpec}): fail closed, never null.
 */
final class Catalog
{
    /** Blast radius by kind of action, in [0, 1]. */
    public const BLAST = ['read' => 0.05, 'reversibleWrite' => 0.2, 'rateLimitedWrite' => 0.5, 'irreversibleWrite' => 0.8, 'moneyMovement' => 0.9];
    private const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];
    /** ECMAScript white space and line terminators (the reference's `\s`), and the dot. */
    private const SPACE_OR_DOT = '/[\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}.]/u';

    public const BUILTIN_ACTIONS = [
        ['connector' => 'stripe', 'action' => 'charge', 'verb' => 'stripe.charge', 'reversibility' => 'irreversible', 'blastRadius' => 0.9, 'amountField' => 'amount', 'description' => 'Charge a customer. Refundable in practice, but a charge is treated as final.', 'aliases' => ['bill', 'charge_customer'], 'traits' => ['pca.irreversible', 'pca.money_moving']],
        ['connector' => 'stripe', 'action' => 'refund', 'verb' => 'stripe.refund', 'reversibility' => 'irreversible', 'blastRadius' => 0.9, 'amountField' => 'amount', 'description' => 'Returns money for a charge to the customer.', 'aliases' => ['issue_refund', 'refund', 'refund_charge', 'reimburse'], 'traits' => ['pca.irreversible', 'pca.money_moving']],
        ['connector' => 'stripe', 'action' => 'payout', 'verb' => 'stripe.payout', 'reversibility' => 'irreversible', 'blastRadius' => 0.9, 'amountField' => 'amount', 'description' => 'Moves funds from a Stripe balance to a bank account.', 'aliases' => ['pay_out', 'payout'], 'traits' => ['pca.irreversible', 'pca.money_moving']],
        ['connector' => 'stripe', 'action' => 'create_customer', 'verb' => 'stripe.create_customer', 'reversibility' => 'rate_limited', 'blastRadius' => 0.2, 'description' => 'Creates a customer record.', 'traits' => ['pca.pii_access']],
        ['connector' => 'gmail', 'action' => 'send', 'verb' => 'gmail.send', 'reversibility' => 'irreversible', 'blastRadius' => 0.8, 'description' => 'Sends an email to people outside your organisation.', 'aliases' => ['send_email'], 'traits' => ['pca.external_communication', 'pca.irreversible', 'pca.pii_access']],
        ['connector' => 'gmail', 'action' => 'draft', 'verb' => 'gmail.draft', 'reversibility' => 'reversible', 'blastRadius' => 0.2, 'description' => 'Saves an email draft without sending it.', 'traits' => ['pca.pii_access']],
        ['connector' => 'gmail', 'action' => 'delete', 'verb' => 'gmail.delete', 'reversibility' => 'irreversible', 'blastRadius' => 0.8, 'description' => 'Permanently deletes a message.', 'traits' => ['pca.destructive', 'pca.irreversible']],
        ['connector' => 'github', 'action' => 'read', 'verb' => 'github.read', 'reversibility' => 'reversible', 'blastRadius' => 0.05, 'description' => 'Reads files from a repository.', 'traits' => []],
        ['connector' => 'github', 'action' => 'create_pr', 'verb' => 'github.create_pr', 'reversibility' => 'irreversible', 'blastRadius' => 0.2, 'description' => 'Opens a pull request, which is visible to everyone with access to the repository.', 'traits' => ['pca.external_communication', 'pca.irreversible']],
        ['connector' => 'github', 'action' => 'comment', 'verb' => 'github.comment', 'reversibility' => 'irreversible', 'blastRadius' => 0.2, 'description' => 'Posts a comment, visible to everyone with access to the repository.', 'traits' => ['pca.external_communication', 'pca.irreversible']],
        ['connector' => 'github', 'action' => 'merge_pr', 'verb' => 'github.merge_pr', 'reversibility' => 'irreversible', 'blastRadius' => 0.5, 'description' => 'Merges a pull request, which can trigger deploys and other downstream effects.', 'traits' => ['pca.irreversible']],
        ['connector' => 'github', 'action' => 'delete_repo', 'verb' => 'github.delete_repo', 'reversibility' => 'irreversible', 'blastRadius' => 0.8, 'description' => 'Deletes a repository and everything in it.', 'traits' => ['pca.destructive', 'pca.irreversible']],
        ['connector' => 'slack', 'action' => 'post_message', 'verb' => 'slack.post_message', 'reversibility' => 'irreversible', 'blastRadius' => 0.5, 'description' => 'Posts a message that members of the channel can read.', 'traits' => ['pca.bulk', 'pca.external_communication', 'pca.irreversible']],
        ['connector' => 'slack', 'action' => 'read', 'verb' => 'slack.read', 'reversibility' => 'reversible', 'blastRadius' => 0.05, 'description' => 'Reads the message history of a channel.', 'traits' => []],
        ['connector' => 'calendar', 'action' => 'create_event', 'verb' => 'calendar.create_event', 'reversibility' => 'irreversible', 'blastRadius' => 0.2, 'description' => 'Creates an event and sends invitations to its attendees.', 'traits' => ['pca.external_communication', 'pca.irreversible', 'pca.pii_access']],
        ['connector' => 'calendar', 'action' => 'delete_event', 'verb' => 'calendar.delete_event', 'reversibility' => 'rate_limited', 'blastRadius' => 0.5, 'description' => 'Deletes a calendar event.', 'traits' => ['pca.destructive']],
        ['connector' => 'files', 'action' => 'read', 'verb' => 'files.read', 'reversibility' => 'reversible', 'blastRadius' => 0.05, 'description' => 'Reads files.', 'traits' => ['pca.bulk']],
        ['connector' => 'files', 'action' => 'write', 'verb' => 'files.write', 'reversibility' => 'rate_limited', 'blastRadius' => 0.5, 'description' => 'Writes or overwrites files.', 'traits' => ['pca.bulk']],
        ['connector' => 'files', 'action' => 'delete', 'verb' => 'files.delete', 'reversibility' => 'irreversible', 'blastRadius' => 0.8, 'description' => 'Deletes files.', 'traits' => ['pca.bulk', 'pca.destructive', 'pca.irreversible']],
        ['connector' => 'http', 'action' => 'get', 'verb' => 'http.get', 'reversibility' => 'reversible', 'blastRadius' => 0.05, 'description' => 'Fetches a URL.', 'traits' => ['pca.bulk', 'pca.network_egress']],
        ['connector' => 'http', 'action' => 'post', 'verb' => 'http.post', 'reversibility' => 'rate_limited', 'blastRadius' => 0.5, 'description' => 'Posts a body to a URL.', 'traits' => ['pca.bulk', 'pca.network_egress']],
    ];

    /** @var array<string, array<string,mixed>> verb => spec (a later spec overrides an earlier one) */
    private array $byVerb = [];

    /** @param list<array<string,mixed>>|null $actions the action specs (null: the built-in ones) */
    public function __construct(?array $actions = null)
    {
        foreach ($actions ?? self::BUILTIN_ACTIONS as $a) {
            $this->byVerb[$a['verb']] = $a;
        }
    }

    /** @return array<string,mixed>|null the spec of an exact verb */
    public function get(string $verb): ?array
    {
        return $this->byVerb[$verb] ?? null;
    }

    /** @return array<string,mixed>|null the exact `connector.action`, else the ONE action of the connector that has `$action` as an alias */
    public function resolve(string $connector, string $action): ?array
    {
        $exact = $this->get("$connector.$action");
        if ($exact !== null) {
            return $exact;
        }
        $hits = array_values(array_filter($this->byVerb, static fn(array $a): bool => ($a['connector'] ?? null) === $connector
            && in_array($action, $a['aliases'] ?? [], true)));
        return count($hits) === 1 ? $hits[0] : null;
    }

    /** @return list<array<string,mixed>> the specs of one connector, in catalog order */
    public function forConnector(string $connector): array
    {
        return array_values(array_filter($this->byVerb, static fn(array $a): bool => ($a['connector'] ?? null) === $connector));
    }

    /** @return list<array<string,mixed>> every spec, in order of first appearance by verb (a later spec replaced the earlier one in place) */
    public function all(): array
    {
        return array_values($this->byVerb);
    }

    /** @param list<array<string,mixed>>|null $actions the action specs, taken as given (null: the built-in ones) */
    public static function buildCatalog(?array $actions = null): self
    {
        return new self($actions);
    }

    /** The catalog of the built-in actions (the reference's DEFAULT_CATALOG). */
    public static function defaultCatalog(): self
    {
        return new self();
    }

    /**
     * Validate an action spec and default its verb to `connector.action`; every other member is kept. Throws on a missing connector
     * or action, a connector with white space or a dot, an empty or non-string `amountField`, an unknown reversibility class, or a
     * blast radius outside [0, 1].
     *
     * @param array<string,mixed> $s
     * @return array<string,mixed>
     */
    public static function defineAction(array $s): array
    {
        $connector = $s['connector'] ?? null;
        $action = $s['action'] ?? null;
        if (!is_string($connector) || !is_string($action) || $connector === '' || $action === '') {
            throw new \InvalidArgumentException('defineAction: connector and action are required');
        }
        if (preg_match(self::SPACE_OR_DOT, $connector) !== 0) { // a connector that is not UTF-8 is refused as well
            throw new \InvalidArgumentException('defineAction: connector must not contain whitespace or a dot');
        }
        if (array_key_exists('amountField', $s) && (!is_string($s['amountField']) || $s['amountField'] === '')) {
            throw new \InvalidArgumentException('defineAction: amountField must be a non-empty string');
        }
        if (!in_array($s['reversibility'] ?? null, self::REVERSIBILITY_ORDER, true)) {
            throw new \InvalidArgumentException('defineAction: bad reversibility');
        }
        $blast = $s['blastRadius'] ?? null;
        if (!(is_int($blast) || is_float($blast)) || !($blast >= 0 && $blast <= 1)) {
            throw new \InvalidArgumentException('defineAction: blastRadius must be in [0,1]');
        }
        $s['verb'] = $s['verb'] ?? "$connector.$action";
        return $s;
    }

    /** The spec of a verb no catalog row covers: irreversible, blast radius 1. @return array<string,mixed> */
    public static function uncataloguedSpec(string $verb): array
    {
        $dot = strpos($verb, '.');
        $rest = $dot === false ? '' : substr($verb, $dot + 1);
        return ['connector' => $dot === false ? $verb : substr($verb, 0, $dot), 'action' => $rest === '' ? $verb : $rest, 'verb' => $verb,
            'reversibility' => 'irreversible', 'blastRadius' => 1, 'description' => "(uncatalogued) $verb"];
    }

    /** The catalog's spec of a verb, or the uncatalogued one. @return array{spec: array<string,mixed>, catalogued: bool} */
    public static function resolveAction(self $catalog, string $verb): array
    {
        $spec = $catalog->get($verb);
        return $spec !== null ? ['spec' => $spec, 'catalogued' => true] : ['spec' => self::uncataloguedSpec($verb), 'catalogued' => false];
    }

    /** The content address of a catalog: the canonical hash of its specs sorted by verb (UTF-16 code unit order). Independent of insertion order. */
    public static function catalogDigest(self $catalog): string
    {
        $specs = $catalog->all();
        usort($specs, static fn(array $a, array $b): int => Actions::u16Order((string)($a['verb'] ?? ''), (string)($b['verb'] ?? '')));
        return Pca::hashCanonical(Sign::n($specs));
    }

    /** Throws unless the catalog's digest is exactly `$expected`. */
    public static function assertCatalogPinned(self $catalog, string $expected): void
    {
        if (self::catalogDigest($catalog) !== $expected) {
            throw new \RuntimeException('catalog does not match the pinned digest');
        }
    }

    /**
     * A catalog of `$base` plus `$extra`. An extension may only tighten: it throws when an extra spec replaces a verb with a lower
     * reversibility class or a lower blast radius.
     *
     * @param list<array<string,mixed>> $extra
     */
    public static function extendCatalog(self $base, array $extra): self
    {
        $sev = static fn(mixed $c): int => ($i = array_search($c, self::REVERSIBILITY_ORDER, true)) === false ? -1 : $i;
        foreach ($extra as $e) {
            $old = $base->get((string)($e['verb'] ?? ''));
            if ($old !== null && ($sev($e['reversibility'] ?? null) < $sev($old['reversibility'] ?? null) || ($e['blastRadius'] ?? NAN) < ($old['blastRadius'] ?? NAN))) {
                throw new \InvalidArgumentException("extendCatalog: '" . ($e['verb'] ?? '') . "' would be less cautious than the existing entry");
            }
        }
        return new self([...$base->all(), ...$extra]);
    }
}
