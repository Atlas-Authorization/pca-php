<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicyLink.php';

use Atlas\Pca\Json;
use Atlas\Pca\Pca;
use Atlas\Pca\PolicyLink;
use PHPUnit\Framework\TestCase;

/** createLink / slotsDigest (policy-link.ts). */
final class PolicyLinkCreateTest extends TestCase
{
    private function def(): \Atlas\Pca\Obj
    {
        return Json::parseLax('{"v":1,"kind":"pca-policy-template","id":"t","version":"1","slots":{"a":{"type":"string"}},'
            . '"body":{"predicates":[{"verb":"x","resource":"r","where":[{"field":"f","op":"eq","value":{"$slot":"a"}}]}]}}');
    }

    public function testCreateLinkEmbedsOrBindsTheSlots(): void
    {
        $slots = Json::parseLax('{"a":"v"}');
        $ref = PolicyLink::createLink($this->def(), $slots);
        self::assertSame(['template_id', 'version_digest', 'slots'], $ref->keys());
        self::assertSame('t', $ref->get('template_id'));
        self::assertSame(PolicyLink::templateDigest($this->def()), $ref->get('version_digest'));
        self::assertNull(PolicyLink::templateRefError($ref));
        $bound = PolicyLink::createLink($this->def(), $slots, true);
        self::assertSame(['template_id', 'version_digest', 'bind_params_digest'], $bound->keys());
        self::assertSame(PolicyLink::slotsDigest($slots), $bound->get('bind_params_digest'));
        self::assertSame(Pca::hashCanonical($slots), PolicyLink::slotsDigest($slots));
        self::assertNull(PolicyLink::templateRefError($bound));
    }

    public function testCreateLinkRefusesBadSlots(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("createLink: slot 'b' is not declared by the template");
        PolicyLink::createLink($this->def(), Json::parseLax('{"a":"v","b":"x"}'));
    }
}
