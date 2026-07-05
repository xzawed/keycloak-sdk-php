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
    public function testToStringMasksSecret(): void
    {
        $c = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', clientSecret: 'super-secret');
        self::assertStringNotContainsString('super-secret', (string) $c);
        self::assertStringContainsString('***', (string) $c);
    }
}
