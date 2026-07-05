<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Token;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Token\ValidatedToken;

final class ValidatedTokenTest extends TestCase
{
    public function testHoldsClaims(): void
    {
        $vt = new ValidatedToken('sub-1', ['it-client'], 'http://kc:8080/realms/it-realm', 2000, 1000, ['sub' => 'sub-1']);
        self::assertSame('sub-1', $vt->subject);
        self::assertContains('it-client', $vt->audience);
    }
}
