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
     * 현재 이름으로 주소를 잡아 롤을 갱신한다. `$role` 의 name 에 새 이름을 주면 rename 이다.
     *
     * ⚠️ **fschmtt `Roles::update` 를 쓰지 않는다** — 그쪽은 경로를 `$role->getName()` 에서
     * 만들어 경로와 body 가 한 값에서 나오고, 그래서 rename 을 표현할 수 없다. 자매 8개 언어는
     * 전부 (이름, representation) 두 인자를 받으므로 §4 동형도 이쪽이 맞다. 경위와 대체 경로는
     * {@see RenamableRoles}.
     */
    public function update(string $name, Role $role): void
    {
        ErrorTranslation::call(
            fn () => $this->kc->resource(RenamableRoles::class)->updateByName($this->realm, $name, $role),
        );
    }
}
