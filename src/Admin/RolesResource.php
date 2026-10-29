<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Collection\RoleCollection;

final class RolesResource
{
    public function __construct(private readonly Keycloak $kc, private readonly string $realm) {}

    /**
     * ⚠️ The fschmtt client holds the credentials, so a dump printed the client secret verbatim (measured 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }

    /** ⚠️ The representation being sent is hidden (update too) — so it is not printed as a trace argument of a failure error (the same rule as `UsersResource::create`). */
    public function create(#[\SensitiveParameter] Role $role): void
    {
        ErrorTranslation::call(fn () => $this->kc->roles()->create($this->realm, $role));
    }

    public function get(string $roleName): Role
    {
        return ErrorTranslation::call(fn (): Role => $this->kc->roles()->get($this->realm, $roleName));
    }

    public function all(): RoleCollection
    {
        return ErrorTranslation::call(fn (): RoleCollection => $this->kc->roles()->all($this->realm));
    }

    public function delete(string $roleName): void
    {
        ErrorTranslation::call(fn () => $this->kc->roles()->delete($this->realm, $roleName));
    }

    /**
     * Updates the role, addressing it by its current name. Giving `$role` a new name makes it a rename.
     *
     * ⚠️ **It does not use fschmtt `Roles::update`** — that one builds the path from `$role->getName()`, so
     * the path and the body come from one value, and therefore a rename cannot be expressed. The 8 sister languages
     * all take two arguments (name, representation), so under §4 isomorphism, too, this side is right. For the background and the
     * replacement path, see {@see RenamableRoles}.
     */
    public function update(string $name, #[\SensitiveParameter] Role $role): void
    {
        ErrorTranslation::call(
            fn () => $this->kc->resource(RenamableRoles::class)->updateByName($this->realm, $name, $role),
        );
    }
}
