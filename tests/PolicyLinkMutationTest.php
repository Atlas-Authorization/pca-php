<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/PolicyLink.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PolicyLink;
use PHPUnit\Framework\TestCase;

/** verifyLinkedPolicy: exact results for every branch, including a linked template that carries caveats. */
final class PolicyLinkMutationTest extends TestCase
{
    private static function o(array $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    private static function kp(): KeyPair
    {
        return new KeyPair(str_repeat("\x09", 32));
    }

    /** @return array{0: Obj, 1: Obj, 2: string} [ref, registry, digest] for a template with one predicate and one caveat */
    private static function link(): array
    {
        $def = self::o(['v' => 1, 'kind' => 'pca-policy-template', 'id' => 't', 'version' => '1', 'slots' => ['a' => ['type' => 'string']],
            'body' => ['predicates' => [['verb' => 'x', 'resource' => 'r', 'where' => [['field' => 'f', 'op' => 'eq', 'value' => ['$slot' => 'a']]]]],
                'caveats' => [['k' => 'c']]]]);
        $dg = PolicyLink::templateDigest($def);
        $msg = PolicyLink::SIG_DOMAIN_TEMPLATE . hash('sha256', $dg, true);
        $t = Obj::of(['def' => $def, 'signer' => self::kp()->public, 'sig' => Pca::b64u(self::kp()->sign($msg))]);
        $ref = Obj::of(['template_id' => 't', 'version_digest' => $dg, 'slots' => Obj::of(['a' => 'x'])]);
        return [$ref, Obj::of(['templates' => Obj::of([$dg => $t]), 'trusted' => [self::kp()->public]]), $dg];
    }

    public function testVerifyLinkedPolicyBranches(): void
    {
        [$ref, $reg, $dg] = self::link();
        $r = PolicyLink::resolveLink($ref, $reg);
        self::assertTrue($r['ok']);
        $preds = $r['policy']->get('predicates');
        $cavs = $r['policy']->get('caveats');
        self::assertCount(1, $cavs);

        // no link: nothing to verify here
        self::assertSame(['ok' => true], PolicyLink::verifyLinkedPolicy(Obj::of(['predicates' => [], 'caveats' => []]), $reg));
        // an exact instantiation, caveats included
        self::assertSame(['ok' => true, 'template' => $dg],
            PolicyLink::verifyLinkedPolicy(Obj::of(['template_ref' => $ref, 'predicates' => $preds, 'caveats' => $cavs]), $reg));
        // predicates differ, caveats equal
        $other = self::o([['verb' => 'y', 'resource' => 'r', 'where' => []]]);
        $differs = ['ok' => false, 'reason' => 'grant policy differs from the linked template instantiation'];
        self::assertSame($differs, PolicyLink::verifyLinkedPolicy(Obj::of(['template_ref' => $ref, 'predicates' => $other, 'caveats' => $cavs]), $reg));
        // caveats differ, predicates equal
        self::assertSame($differs, PolicyLink::verifyLinkedPolicy(Obj::of(['template_ref' => $ref, 'predicates' => $preds, 'caveats' => []]), $reg));
        // the link does not resolve: its reason is passed through
        $missing = Obj::of(['template_id' => 't', 'version_digest' => 'nope', 'slots' => Obj::of(['a' => 'x'])]);
        self::assertSame(['ok' => false, 'reason' => 'template version is not in the registry'],
            PolicyLink::verifyLinkedPolicy(Obj::of(['template_ref' => $missing, 'predicates' => $preds, 'caveats' => $cavs]), $reg));
        // a policy that cannot be canonicalised fails closed
        self::assertSame(['ok' => false, 'reason' => 'link verification error (fail closed)'],
            PolicyLink::verifyLinkedPolicy(Obj::of(['template_ref' => $ref, 'predicates' => new \stdClass(), 'caveats' => $cavs]), $reg));
    }
}
