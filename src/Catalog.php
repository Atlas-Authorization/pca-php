<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The 21 built-in connector actions the agent facade compiles permissions against ({@see Facade}): verb, effective reversibility,
 * blast radius, amount field, aliases and traits. Generated from the reference catalog: do not edit by hand (a test compares it
 * with the reference when the reference sources are present).
 */
final class Catalog
{
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
}
