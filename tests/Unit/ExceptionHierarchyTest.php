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
            $parents = class_parents($cls);
            self::assertIsArray($parents, "$cls should be a loadable class");
            self::assertArrayHasKey(KeycloakException::class, $parents, "$cls should extend KeycloakException");
        }
    }

    public function testAdminSubtypesExtendAdminError(): void
    {
        foreach ([KeycloakNotFoundError::class, KeycloakConflictError::class, KeycloakForbiddenError::class] as $cls) {
            $parents = class_parents($cls);
            self::assertIsArray($parents, "$cls should be a loadable class");
            self::assertArrayHasKey(KeycloakAdminError::class, $parents, "$cls should extend KeycloakAdminError");
        }
    }
    public function testAdminErrorCarriesStatus(): void
    {
        $e = new KeycloakNotFoundError('nope', 404);
        self::assertSame(404, $e->getStatusCode());
    }
}
