<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Exception\{KeycloakException, KeycloakConfigError, KeycloakAuthError,
    KeycloakTransportError, KeycloakAdminError, KeycloakNotFoundError, KeycloakConflictError,
    KeycloakForbiddenError, TokenValidationError};

final class ExceptionHierarchyTest extends TestCase
{
    public function testAllExtendBase(): void
    {
        foreach ([KeycloakConfigError::class, KeycloakAuthError::class, KeycloakTransportError::class,
            KeycloakAdminError::class, KeycloakNotFoundError::class, KeycloakConflictError::class,
            KeycloakForbiddenError::class, TokenValidationError::class] as $cls) {
            self::assertTrue(is_a($cls, KeycloakException::class, true), "$cls should extend KeycloakException");
        }
    }
    public function testAdminSubtypesExtendAdminError(): void
    {
        self::assertTrue(is_a(KeycloakNotFoundError::class, KeycloakAdminError::class, true));
        self::assertTrue(is_a(KeycloakConflictError::class, KeycloakAdminError::class, true));
        self::assertTrue(is_a(KeycloakForbiddenError::class, KeycloakAdminError::class, true));
    }
    public function testAdminErrorCarriesStatus(): void
    {
        $e = new KeycloakNotFoundError('nope', 404);
        self::assertSame(404, $e->getStatusCode());
    }
}
