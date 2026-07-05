<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Token;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Token\TokenSet;

final class TokenSetTest extends TestCase
{
    public function testFromArrayParsesAndComputesExpiresAt(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 300, 'refresh_token' => 'rt'], now: 1000);
        self::assertSame('at', $ts->accessToken);
        self::assertSame(300, $ts->expiresIn);
        self::assertSame(1300, $ts->expiresAt);
    }

    public function testIsExpired(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'at', 'expires_in' => 300], now: 1000);
        self::assertFalse($ts->isExpired(now: 1200, skew: 30));
        self::assertTrue($ts->isExpired(now: 1290, skew: 30));   // 1290 >= 1300-30
    }

    public function testToStringMasksTokens(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'secret-at', 'refresh_token' => 'secret-rt', 'expires_in' => 60]);
        $s = (string) $ts;
        self::assertStringNotContainsString('secret-at', $s);
        self::assertStringNotContainsString('secret-rt', $s);
    }
}
