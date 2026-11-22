<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsRegistry.php';

use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for ActionsRegistry: evolutionDiffDigest refusal, reapproval catch, the verifyPack catch, rule22Integrity on a non-object. */
final class K05KillActionsRegistryTest extends TestCase
{
    /** [pack, keys (reg-1 only), shards] of the k05 oracle case verifyPack/sharded (a valid, signed, sharded pack). */
    private const SHARDED = <<<'JSON'
[{"v":1,"kind":"pca-action-pack","ns":"stripe","version":"1.0.0","stability":"stable","traits_digest":"W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM","roles_digest":"I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU","rules_digest":"UH2GMZ7KB7LkjbUIM-UScWH8QPRtBNvjgv_6Jgtag1Y","root":"PSYzR3QvecPIrxygifQIGzP4l1qeME-NmxYZRkrNLYE","defs":{"shards":[{"name":"stripe-1","digest":"c7n16kAW5hY1YYv3zP4elOr8PhK8nZJOznYAtpFeKNQ","uri":"shards/stripe-1.json"},{"name":"stripe-2","digest":"bCxxUclTXjZ5vIysz9wgUvkBYlEyNriKzESXzklI6fE","uri":"shards/stripe-2.json"}]},"source":{"kind":"hand","uri":"internal://k05","spec_digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","licence":"Apache-2.0","licence_notes":"k05 oracle"},"prev":null,"evolution":[{"v":1,"kind":"pca-evolution-record","ns":"stripe","verb":"stripe.charge","from":null,"to":"i1CwI1aoB7Ye_-MCLlvLi6_9XUZZmpKA7GTskyyvYPk","class":"added","reasons":[],"sig":{"alg":"ed25519","kid":"reg-1","value":"0_AfE2qG4Y6BqllLyYdv6sgewaLtKvht6BpQ7Sqt0f6zMLg7xYk1rmpqjxfSh8MXb4CCV2OLV8vXnODIxItUCg"}},{"v":1,"kind":"pca-evolution-record","ns":"stripe","verb":"stripe.create_customer","from":null,"to":"22aGta738fnn88IzCDgmVi3RVESCuMxy3e5idFgp_zw","class":"added","reasons":[],"sig":{"alg":"ed25519","kid":"reg-1","value":"AHgREAKcLjkKNOL8DKQtU5JL-G0sOFrBdPuEFKuXrSbK4fnZ00KyoyRU4bpDm1rE-KRd3IEmIQPiz7hZf1UyDA"}},{"v":1,"kind":"pca-evolution-record","ns":"stripe","verb":"stripe.payout","from":null,"to":"U4doUSxJs36ujvmxnTa8xDfhd4hUZWbE4A0C7z6vRL4","class":"added","reasons":[],"sig":{"alg":"ed25519","kid":"reg-1","value":"nkBp2A6qMOHJ0VvOrh7BeD5039hBrWL5F0y2QxoWMUhNAHCbxhGfyFsUeqkbf0CdH9nWkUmRSntcvSM3Sm2hCA"}},{"v":1,"kind":"pca-evolution-record","ns":"stripe","verb":"stripe.refund","from":null,"to":"Xo7ApENRzJyi5iakmamfXyLK2S7-jBcDWk2dwARzONE","class":"added","reasons":[],"sig":{"alg":"ed25519","kid":"reg-1","value":"CTprSNFj5JdNLGaOe-zrx-0FmhzZyVymHW4Nmif79DDBe34dKKACHE5LwEa8iJyv9EE2FImngILiSq8GWKLFBg"}}],"sig":{"alg":"ed25519","kid":"reg-1","value":"5u-ppVtW35Gt8Y77U0tNR5WQZLfJvFExBLL0GLHo8ryxfsoeKuFTt8BTW9j26J3lRYsbJp3H5Z8vJ5NyMKmHCg"}},[{"kid":"reg-1","alg":"ed25519","pk":"WuDZ4k35r3D1FJzlTfw11qZ4vV8TjUaYQTpWoUJGdSI"}],{"stripe-1":{"v":1,"kind":"pca-action-pack-shard","ns":"stripe","version":"1.0.0","name":"stripe-1","defs":[{"v":1,"kind":"pca-action-def","verb":"stripe.charge","aliases":["charge_customer","bill"],"title":"Charge a customer","description":"Charge a customer. Refundable in practice, but a charge is treated as final.","effects":["pay"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":10000000000,"unit":{"kind":"money","ccy":"USD","exp":2},"provenance_min":"first_party"},"customer":{"type":"string","max_len":128,"role":"id.stripe.customer"},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"examples":[{"params":{"customer":"cus_12345678","amount":2500,"idempotency_key":"k_1"},"expect":"escalate"}],"review":{"state":"authored"},"since":"0.5.0"},{"v":1,"kind":"pca-action-def","verb":"stripe.create_customer","title":"Create a customer record","description":"Creates a customer record.","effects":["create"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"email":{"type":"string","role":"contact.email","format":"email","max_len":254,"tags":["pii"],"required":false},"name":{"type":"string","max_len":200,"role":"person.name","required":false,"tags":["pii"]}},"reversibility":"rate_limited","blast":{"radius":"one","ppm":200000},"review":{"state":"authored"},"since":"0.5.0"}]},"stripe-2":{"v":1,"kind":"pca-action-pack-shard","ns":"stripe","version":"1.0.0","name":"stripe-2","defs":[{"v":1,"kind":"pca-action-def","verb":"stripe.payout","aliases":["payout","pay_out"],"title":"Pay out funds to a bank account","description":"Moves funds from a Stripe balance to a bank account.","effects":["pay"],"resource":{"type":"stripe.account","id":{"prefix":"acct_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":10000000000,"unit":{"kind":"money","ccy":"USD","exp":2},"provenance_min":"first_party"},"account":{"type":"string","max_len":128,"role":"id.stripe.account"},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"examples":[{"params":{"account":"acct_12345678","amount":100000,"idempotency_key":"k_1"},"expect":"escalate"}],"review":{"state":"authored"},"since":"0.5.0"},{"v":1,"kind":"pca-action-def","verb":"stripe.refund","aliases":["refund","issue_refund","reimburse","refund_charge"],"title":"Refund a charge","description":"Returns money for a charge to the customer.","effects":["pay"],"resource":{"type":"stripe.charge","id":{"prefix":"ch_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":10000000000,"unit":{"kind":"money","ccy":"USD","exp":2},"provenance_min":"first_party"},"charge":{"type":"string","max_len":128,"role":"id.stripe.charge"},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"examples":[{"params":{"charge":"ch_12345678","amount":2500,"idempotency_key":"k_1"},"expect":"escalate"}],"review":{"state":"authored"},"since":"0.5.0"}]}}]
JSON;

    public function testEvolutionDiffDigestNamesTheMissingMember(): void
    {
        $r = Obj::of(['ns' => 'a', 'verb' => 'a.b', 'from' => null, 'to' => null, 'class' => 'added']);
        try {
            ActionsRegistry::evolutionDiffDigest($r);
            self::fail('expected a throw');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('missing reasons', $e->getMessage());
        }
    }

    public function testReapprovalThatCannotBeCanonicalizedIsInvalid(): void
    {
        $lone = "\xED\xA0\x80";
        $r = Obj::of(['v' => new Num('1'), 'kind' => ActionsRegistry::REAPPROVAL_KIND, 'grant' => $lone, 'verb' => 'a.b', 'diff' => 'd',
            'sig' => Obj::of(['alg' => 'ed25519', 'value' => 'x'])]);
        self::assertFalse(ActionsRegistry::reapprovalValid($r, $lone, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'a.b', 'd'));
    }

    public function testAShardThatCannotBeHashedIsAVerificationError(): void
    {
        [$pack, $keys, $shards] = (new Parser(self::SHARDED, PHP_INT_MAX))->run();
        self::assertTrue(ActionsRegistry::verifyPack($pack, $keys, $shards)['ok']);
        $bad = new Obj();
        foreach ($shards->keys() as $k) {
            $bad->set($k, "\xED\xA0\x80");
        }
        self::assertSame(['ok' => false, 'reason' => 'pack verification error: canonicalize: lone surrogate in string'],
            ActionsRegistry::verifyPack($pack, $keys, $bad));
    }

    public function testRule22OfANonObjectIsABadRegistry(): void
    {
        self::assertSame(['ok' => false, 'code' => 'bad_registry'], ActionsRegistry::rule22Integrity('x'));
        self::assertSame(['ok' => false, 'code' => 'bad_registry'], ActionsRegistry::rule22Integrity(null));
    }

    public function testRule22FailsClosedOnAThrowAndOnAnUnknownCode(): void
    {
        try {
            ActionsRegistry::$rule22Hook = static function (?string $e): ?string {
                throw new \RuntimeException('boom');
            };
            self::assertSame(['ok' => false, 'code' => 'schema_floor_forged'], ActionsRegistry::rule22Integrity('x'));
            ActionsRegistry::$rule22Hook = static fn(?string $e): ?string => 'something else';
            self::assertSame(['ok' => false, 'code' => 'unknown'], ActionsRegistry::rule22Integrity('x'));
            ActionsRegistry::$rule22Hook = static fn(?string $e): ?string => null;
            self::assertSame(['ok' => true], ActionsRegistry::rule22Integrity('x'));
        } finally {
            ActionsRegistry::$rule22Hook = null;
        }
        self::assertSame(['ok' => false, 'code' => 'bad_registry'], ActionsRegistry::rule22Integrity('x'));
    }

    /** A throw while evaluating the pin is a bad_pin refusal that carries the error's message after the fixed prefix. */
    public function testAPinEvaluationErrorCarriesTheMessage(): void
    {
        $a = str_repeat('A', 43);
        $pin = Json::parseLax('{"pack":{"ns":"stripe","root":"' . $a . '"},"defs":{"stripe.charge":"' . $a . '"},"on_new_action":"deny"}');
        $doc = Json::parseLax('{"pack":{"ns":"stripe"},"verbs":[{"verb":"stripe.charge","def":"' . str_repeat('B', 43) . '"}]}');
        $i = ['pin' => $pin, 'doc' => $doc, 'verb' => 'stripe.charge', 'grant' => null];
        // control: no records, so no chain to the presented digest
        self::assertSame('def_changed', ActionsRegistry::decidePin($i + ['records' => []])['code']);
        self::assertSame(['ok' => false, 'code' => 'bad_pin', 'escalate' => false,
            'reason' => 'pin evaluation error (fail closed): i.records is not iterable'], ActionsRegistry::decidePin($i + ['records' => 5]));
    }
}
