<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ForbidCertificate.php';
require_once __DIR__ . '/../src/CaveatLang.php';

use Atlas\Pca\CaveatLang;
use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for ForbidCertificate (precedence ranking and tie-break, host objects that only look like Obj, the
 * fail-closed catch) and CaveatLang's number reader (nv) behind the discharge `v` check.
 */
final class K05KillForbidCertificateTest extends TestCase
{
    private static function o(array $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** A host object that answers keys / has / get like an Obj but is not one. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    private static function cert(array $clauses, string $decision, string $kind, ?string $id, array $shadowed): Obj
    {
        return self::o(['v' => 1, 'kind' => 'forbid-wins', 'clauses' => $clauses, 'decision' => $decision,
            'winner' => ['kind' => $kind, 'id' => $id], 'shadowed' => $shadowed]);
    }

    private static function emptyDeny(): Obj
    {
        return self::cert([], 'deny', 'none', null, []);
    }

    public function testCertificateMustBeAnObj(): void
    {
        $this->assertTrue(ForbidCertificate::consistent(self::emptyDeny()));
        $this->assertFalse(ForbidCertificate::consistent(self::lookalike(['v' => new Num('1'), 'kind' => 'forbid-wins', 'clauses' => [],
            'decision' => 'deny', 'winner' => Obj::of(['kind' => 'none', 'id' => null]), 'shadowed' => []])));
    }

    public function testVersionMustBeANumOne(): void
    {
        $fake = new \stdClass();
        $fake->lexeme = '1'; // a lexeme without being a Num
        $c = self::emptyDeny();
        $c->set('v', $fake);
        $this->assertFalse(ForbidCertificate::consistent($c));
    }

    public function testWinnerMustBeAnObj(): void
    {
        $c = self::emptyDeny();
        $c->set('winner', self::lookalike(['kind' => 'none', 'id' => null]));
        $this->assertFalse(ForbidCertificate::consistent($c));
        $c->set('winner', null);
        $this->assertFalse(ForbidCertificate::consistent($c));
    }

    public function testRowWithoutAStringIdIsUnreadable(): void
    {
        $this->assertTrue(ForbidCertificate::consistent(self::cert([['id' => 'p', 'kind' => 'permit', 'value' => 'true']], 'allow', 'permit', 'p', [])));
        $this->assertFalse(ForbidCertificate::consistent(self::cert([['kind' => 'permit', 'value' => 'true']], 'allow', 'permit', null, [])));
    }

    public function testRowWithAnUnknownKindIsUnreadable(): void
    {
        $this->assertFalse(ForbidCertificate::consistent(self::cert([['id' => 'p', 'kind' => 'bogus', 'value' => 'true']], 'deny', 'none', null, [])));
    }

    /** The listed signer outranks the unlisted one even though its id sorts later and it comes second in the table. */
    public function testPrecedenceRanksBeforeTheIdTieBreak(): void
    {
        $rows = [['id' => 'a', 'kind' => 'forbid', 'value' => 'true'], ['id' => 'z', 'kind' => 'forbid', 'value' => 'true', 'signer' => 'A']];
        $this->assertTrue(ForbidCertificate::consistent(self::cert($rows, 'deny', 'forbid', 'z', ['a']), ['A']));
        $this->assertFalse(ForbidCertificate::consistent(self::cert($rows, 'deny', 'forbid', 'a', ['z']), ['A']));
        // with no precedence both rank last and the smaller id wins
        $this->assertTrue(ForbidCertificate::consistent(self::cert($rows, 'deny', 'forbid', 'a', ['z'])));
    }

    public function testANonListPrecedenceFailsClosed(): void
    {
        $rows = [['id' => 'a', 'kind' => 'forbid', 'value' => 'true'], ['id' => 'z', 'kind' => 'forbid', 'value' => 'true', 'signer' => 'A']];
        // array_search returns the string key 'k': the int-typed rank throws and the certificate is not consistent
        $this->assertFalse(ForbidCertificate::consistent(self::cert($rows, 'deny', 'forbid', 'z', ['a']), ['k' => 'A']));
    }

    public function testCaveatLangVersionNeedsANumOne(): void
    {
        $d = static fn (string $v) => Json::parseLax('{"v":' . $v . ',"kind":"pca-discharge","caveat_id":"nd","issuer":"iss","cap_hash":"c",'
            . '"bind":"chain_hop","claims":{},"iat":1,"not_after":2,"nonce":"n","sig":"x"}');
        $this->assertSame('not a pca-discharge v1', CaveatLang::dischargeShapeError($d('2')));
        $this->assertSame('not a pca-discharge v1', CaveatLang::dischargeShapeError($d('null')));
    }
}
