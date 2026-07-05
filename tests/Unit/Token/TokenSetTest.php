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

    public function testFromArrayParsesIdTokenScopeAndTokenType(): void
    {
        $ts = TokenSet::fromArray([
            'access_token' => 'at',
            'token_type' => 'Bearer',
            'id_token' => 'idt',
            'scope' => 'openid profile',
            'expires_in' => 60,
        ], now: 1000);
        self::assertSame('Bearer', $ts->tokenType);
        self::assertSame('idt', $ts->idToken);
        self::assertSame('openid profile', $ts->scope);
    }

    public function testFromArrayWithoutExpiresInLeavesExpiresAtNullAndNeverExpired(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'at']);
        self::assertNull($ts->expiresAt);
        self::assertSame(0, $ts->expiresIn);
        self::assertFalse($ts->isExpired());
    }

    public function testFromArrayCoercesNonStringAndNonIntScalarValues(): void
    {
        // toStr()의 int/float/bool 분기 + toInt()의 float/numeric-string 분기를 노출한다
        // (신뢰된 응답이라도 일부 IdP 구현이 숫자형을 문자열이 아닌 그대로 내려보낼 수 있음).
        $ts = TokenSet::fromArray(['access_token' => 'at', 'token_type' => 1, 'expires_in' => 60.0], now: 1000);
        self::assertSame('1', $ts->tokenType);
        self::assertSame(60, $ts->expiresIn);

        $ts2 = TokenSet::fromArray(['access_token' => 'at', 'expires_in' => '60'], now: 1000);
        self::assertSame(60, $ts2->expiresIn);
    }
}
