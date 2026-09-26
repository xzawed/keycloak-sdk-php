<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Exception\KeycloakConfigError;

final class KeycloakConfigTest extends TestCase
{
    public function testValidConfigAndDefaults(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080/', realm: 'it-realm', clientId: 'it-client', clientSecret: 'sec');
        self::assertSame('http://kc:8080', $c->serverUrl);   // 후행 슬래시 제거
        self::assertSame(['openid'], $c->scopes);
        self::assertSame(30, $c->clockSkew);
        self::assertSame(5.0, $c->connectTimeout);
        self::assertSame(30, $c->jwksMinRefetchSeconds);
        self::assertNull($c->expectedAudience);              // 미설정 = 기대 aud는 clientId
    }
    public function testJwksMinRefetchCustom(): void
    {
        $c = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'r', clientId: 'c', jwksMinRefetchSeconds: 120);
        self::assertSame(120, $c->jwksMinRefetchSeconds);
    }
    public function testNegativeJwksMinRefetchThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        // 화살표 함수로 감싸 즉시 호출 — bare `new`(S1848) 없이 생성자 예외를 발생시킨다.
        (static fn (): KeycloakConfig => new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'r', clientId: 'c', jwksMinRefetchSeconds: -1))();
    }
    public function testMissingServerUrlThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        new KeycloakConfig(serverUrl: '', realm: 'r', clientId: 'c');
    }
    public function testMissingRealmThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        new KeycloakConfig(serverUrl: 'http://kc:8080', realm: '', clientId: 'c');
    }
    public function testMissingClientIdThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: '');
    }
    public function testScopesNormalizedToList(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', scopes: [0 => 'openid', 2 => 'email']);
        self::assertSame(['openid', 'email'], $c->scopes);   // array_values reindexes to a list
    }
    public function testSignatureAlgorithmsDefault(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c');
        self::assertSame(['RS256'], $c->signatureAlgorithms);
    }
    public function testSignatureAlgorithmsCustom(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', signatureAlgorithms: ['ES256', 'RS256']);
        self::assertSame(['ES256', 'RS256'], $c->signatureAlgorithms);
    }
    public function testEmptySignatureAlgorithmsThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', signatureAlgorithms: []);
    }
    public function testToStringMasksSecret(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', clientSecret: 'super-secret');
        self::assertStringNotContainsString('super-secret', (string) $c);
        self::assertStringContainsString('***', (string) $c);
    }
    /**
     * expectExceptionMessage 는 부분 일치라, 앵커로 메시지 전체를 고정한다.
     *
     * @return iterable<string, array{float}>
     */
    public static function rejectedTimeouts(): iterable
    {
        yield '0.0' => [0.0];
        yield '-1.0' => [-1.0];
        yield 'NAN' => [\NAN];
        yield 'INF' => [\INF];
    }
    #[DataProvider('rejectedTimeouts')]
    public function testRejectedConnectTimeoutThrows(float $connectTimeout): void
    {
        $this->expectException(KeycloakConfigError::class);
        $this->expectExceptionMessageMatches('/\AconnectTimeout must be > 0\z/');
        // 화살표 함수로 감싸 즉시 호출 — bare `new`(S1848) 없이 생성자 예외를 발생시킨다.
        (static fn (): KeycloakConfig => new KeycloakConfig(
            serverUrl: 'http://kc:8080',
            realm: 'r',
            clientId: 'c',
            connectTimeout: $connectTimeout,
        ))();
    }
    #[DataProvider('rejectedTimeouts')]
    public function testRejectedReadTimeoutThrows(float $readTimeout): void
    {
        $this->expectException(KeycloakConfigError::class);
        $this->expectExceptionMessageMatches('/\AreadTimeout must be > 0\z/');
        (static fn (): KeycloakConfig => new KeycloakConfig(
            serverUrl: 'http://kc:8080',
            realm: 'r',
            clientId: 'c',
            readTimeout: $readTimeout,
        ))();
    }
    public function testNegativeClockSkewThrows(): void
    {
        $this->expectException(KeycloakConfigError::class);
        $this->expectExceptionMessageMatches('/\AclockSkew must be >= 0\z/');
        (static fn (): KeycloakConfig => new KeycloakConfig(
            serverUrl: 'http://kc:8080',
            realm: 'r',
            clientId: 'c',
            clockSkew: -1,
        ))();
    }
    public function testTimeoutAndClockSkewBoundariesConstruct(): void
    {
        $c = new KeycloakConfig(
            serverUrl: 'http://kc:8080',
            realm: 'r',
            clientId: 'c',
            connectTimeout: 0.001,
            readTimeout: 0.001,
            clockSkew: 0,
        );
        self::assertSame(0.001, $c->connectTimeout);
        self::assertSame(0.001, $c->readTimeout);
        self::assertSame(0, $c->clockSkew);
    }
}
