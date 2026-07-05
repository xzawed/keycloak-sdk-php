<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

final class OidcEndpointsTest extends TestCase
{
    public function testAssembly(): void
    {
        $e = new OidcEndpoints(new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'it-realm', clientId: 'c'));
        self::assertSame('http://kc:8080/realms/it-realm', $e->issuer());
        self::assertSame('http://kc:8080/realms/it-realm/protocol/openid-connect/token', $e->token());
        self::assertSame('http://kc:8080/realms/it-realm/protocol/openid-connect/token/introspect', $e->introspection());
        self::assertSame('http://kc:8080/realms/it-realm/protocol/openid-connect/logout', $e->endSession());
        self::assertSame('http://kc:8080/realms/it-realm/protocol/openid-connect/certs', $e->jwks());
    }
}
