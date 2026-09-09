<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Token;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\KeycloakConfig;
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

    /**
     * ⚠️ **`isExpired` 의 `$skew` 기본값이 `KeycloakConfig::clockSkew` 와 같은지 아무도 안 봤다.**
     * 교차언어 가드의 코드 축은 언어당 파일 하나만 읽고 php 는 `KeycloakConfig.php` 라, 이 자리의
     * `= 30` 은 어느 축에도 안 걸린다. 위 `testIsExpired` 도 못 잡는다 — `skew:` 를 **넘겨서**
     * 재기 때문이다. 기본값을 실제로 타는 유일한 기존 테스트는 `expiresAt === null` 경로라
     * skew 가 평가조차 되지 않는다(실측 2026-09-09).
     *
     * ⚠️ **여기에 `30` 을 다시 적지 않는다** — `KeycloakConfig` 에서 **파생**한다. 상수를 또 적으면
     * 두 번째 정의 자리를 한 층 위에 만드는 것이다. 정책값 30 자체는 `KeycloakConfigTest` 의 몫이다.
     */
    public function testIsExpiredDefaultSkewMatchesConfigClockSkew(): void
    {
        $skew = (new KeycloakConfig('https://kc.example', 'r', 'c'))->clockSkew;
        $ts = TokenSet::fromArray(['access_token' => 'at', 'expires_in' => 300], now: 1000);
        // expiresAt = 1300. 경계는 1300 - skew.
        self::assertTrue(
            $ts->isExpired(now: 1300 - $skew),
            "기본 skew 가 config.clockSkew({$skew}) 보다 작다 — 사용처 기본값이 갈렸다",
        );
        self::assertFalse(
            $ts->isExpired(now: 1300 - $skew - 1),
            "기본 skew 가 config.clockSkew({$skew}) 보다 크다 — 사용처 기본값이 갈렸다",
        );
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

    /**
     * ⚠️ 이 테스트는 한때 `assertFalse($ts->isExpired())` 였다 — **결함을 고정하고 있었다.**
     * 만료 시각 미상을 "안 만료됨"으로 읽으면 provider 캐시가 죽은 토큰을 영원히 재사용한다.
     * 자매 여덟(java·python·node·go·dotnet·kotlin·rust·ruby)은 전부 "만료됨"으로 읽는다.
     */
    public function testFromArrayWithoutExpiresInLeavesExpiresAtNullAndIsExpiredFailSafe(): void
    {
        $ts = TokenSet::fromArray(['access_token' => 'at']);
        self::assertNull($ts->expiresAt);
        self::assertSame(0, $ts->expiresIn);
        self::assertTrue($ts->isExpired(), '만료 시각 미상은 fail-safe 하게 "만료됨"이어야 한다');
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
