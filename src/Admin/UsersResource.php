<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Http\Criteria;
use Fschmtt\Keycloak\Representation\User;
use Fschmtt\Keycloak\Collection\UserCollection;

final class UsersResource
{
    public function __construct(private readonly Keycloak $kc, private readonly string $realm) {}

    /** 생성 후 id를 얻으려면 search 후속(fschmtt create는 void). */
    public function create(User $user): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->create($this->realm, $user));
    }

    public function get(string $userId): User
    {
        return ErrorTranslation::call(fn (): User => $this->kc->users()->get($this->realm, $userId));
    }

    public function search(?Criteria $criteria = null): UserCollection
    {
        return ErrorTranslation::call(fn (): UserCollection => $this->kc->users()->search($this->realm, $criteria));
    }

    public function delete(string $userId): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->delete($this->realm, $userId));
    }

    /** 편의: username으로 생성된 사용자 id 조회(create가 void라 필요). */
    public function findIdByUsername(string $username): ?string
    {
        $found = $this->search(new Criteria(['username' => $username, 'exact' => true]));

        return $found->first()?->getId();
    }
}
