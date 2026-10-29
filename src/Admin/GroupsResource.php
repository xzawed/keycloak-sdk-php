<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Group;
use Fschmtt\Keycloak\Collection\GroupCollection;

final class GroupsResource
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
    public function create(#[\SensitiveParameter] Group $group): void
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

    /** void — fschmtt Groups::update is void too. Isomorphic with the sister languages. */
    public function update(string $groupId, #[\SensitiveParameter] Group $group): void
    {
        ErrorTranslation::call(fn () => $this->kc->groups()->update($this->realm, $groupId, $group));
    }
}
