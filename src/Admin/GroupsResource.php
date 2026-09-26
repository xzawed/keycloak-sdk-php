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
     * ⚠️ fschmtt 클라이언트가 자격증명을 쥐고 있어 덤프가 클라이언트 시크릿을 원문으로 찍었다(실측 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }

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

    /** void — fschmtt Groups::update 도 void. 자매 언어와 동형. */
    public function update(string $groupId, Group $group): void
    {
        ErrorTranslation::call(fn () => $this->kc->groups()->update($this->realm, $groupId, $group));
    }
}
