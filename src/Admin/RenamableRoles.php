<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Http\Command;
use Fschmtt\Keycloak\Http\Method;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Resource\Resource as FschmttResource;

/**
 * A role update that sends the path (current name) and the body (new name) **separately**.
 *
 * ⚠️ fschmtt `Roles::update` builds the path from `$role->getName()`
 * (`'roleName' => $role->getName()` in `Resource/Roles.php`). Since the path and the body come from the same
 * value, **a rename cannot be expressed** — measured, the PUT goes to `/roles/{new name}` and
 * the current name appears nowhere in the request. Keycloak renames with `PUT /roles/{current name}` + the new name in
 * the body, so that request is not a rename but an update of a role that does not exist.
 *
 * Standing this class up through fschmtt's public escape hatch `Keycloak::resource()` **reuses the token, the HTTP
 * client and the serializer as they are**. A raw Guzzle PUT would have needed a bearer obtained separately, but
 * that is locked inside fschmtt, and running a fresh grant breaks the §4 token-cache invariant.
 *
 * ⚠️ `CommandExecutor` is a type fschmtt marks `@internal`. The only ground for using it here is the
 * **exact pin `0.44.0`** in `composer.json` — when the pin is raised, `RolesRenameTest` drives the
 * real fschmtt stack to confirm this assembly still holds.
 *
 * @internal §4 — this type does not leave the facade.
 */
final class RenamableRoles extends FschmttResource
{
    public function updateByName(string $realm, string $currentName, Role $role): void
    {
        $this->commandExecutor->executeCommand(new Command(
            '/admin/realms/{realm}/roles/{roleName}',
            Method::PUT,
            [
                'realm' => $realm,
                'roleName' => $currentName,
            ],
            $role,
        ));
    }
}
