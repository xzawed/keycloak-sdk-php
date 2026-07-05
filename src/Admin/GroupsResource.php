<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Group;
use Fschmtt\Keycloak\Collection\GroupCollection;

final class GroupsResource
{
    public function __construct(private readonly Keycloak $kc, private readonly string $realm) {}

    public function create(Group $group): void
    {
        ErrorTranslation::call(fn () => $this->kc->groups()->create($this->realm, $group));
    }

    public function get(string $groupId): Group
    {
        return ErrorTranslation::call(fn (): Group => $this->kc->groups()->get($this->realm, $groupId));
    }

    public function all(): GroupCollection
    {
        return ErrorTranslation::call(fn (): GroupCollection => $this->kc->groups()->all($this->realm));
    }

    public function delete(string $groupId): void
    {
        ErrorTranslation::call(fn () => $this->kc->groups()->delete($this->realm, $groupId));
    }
}
