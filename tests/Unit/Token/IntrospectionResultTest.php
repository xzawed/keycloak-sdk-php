<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Token;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Token\IntrospectionResult;

final class IntrospectionResultTest extends TestCase
{
    public function testFromArrayActive(): void
    {
        $ir = IntrospectionResult::fromArray(['active' => true, 'username' => 'alice', 'client_id' => 'it-client']);
        self::assertTrue($ir->active);
        self::assertSame('alice', $ir->username);
        self::assertSame('it-client', $ir->clientId);
    }

    public function testInactiveDefaults(): void
    {
        $ir = IntrospectionResult::fromArray(['active' => false]);
        self::assertFalse($ir->active);
        self::assertNull($ir->username);
    }
}
