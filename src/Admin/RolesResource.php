<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Collection\RoleCollection;

final class RolesResource
{
    public function __construct(private readonly Keycloak $kc, private readonly string $realm) {}

    public function create(Role $role): void
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
     * fschmtt Roles::update 는 역할 이름을 $role->getName() 에서 읽는다
     * (별도 id 인자 없음). void — 자매 언어와 동형.
     */
    public function update(Role $role): void
    {
        ErrorTranslation::call(fn () => $this->kc->roles()->update($this->realm, $role));
    }
}
