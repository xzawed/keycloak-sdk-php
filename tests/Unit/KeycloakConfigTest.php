<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

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
        self::assertSame(60, $c->jwksMinRefetchSeconds);
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
}
