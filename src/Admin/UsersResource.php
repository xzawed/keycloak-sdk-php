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

    /**
     * ⚠️ fschmtt 클라이언트가 자격증명을 쥐고 있어 덤프가 클라이언트 시크릿을 원문으로 찍었다(실측 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }

    /**
     * 생성 후 id를 얻으려면 search 후속(fschmtt create는 void).
     *
     * ⚠️ 보내는 representation 은 비밀(credentials)을 쥘 수 있다 — 실패 오류의 트레이스 인자로 찍히지 않게 가린다(update 도).
     */
    public function create(#[\SensitiveParameter] User $user): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->create($this->realm, $user));
    }

    public function get(string $userId): User
    {
        return ErrorTranslation::call(fn (): User => $this->kc->users()->get($this->realm, $userId));
    }

    /**
     * void — 자매 언어(Java/Kotlin/Python/Node/Go/Ruby/.NET)가 전부 값을 안 돌린다.
     * fschmtt Users::update 도 void 라 버릴 것도 없다.
     */
    public function update(string $userId, #[\SensitiveParameter] User $user): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->update($this->realm, $userId, $user));
    }

    /** ⚠️ 검색 조건은 쿼리로 간다 — 원인 사본이 URL 의 쿼리를 빼듯 실패 오류의 트레이스 인자에서도 가린다(findIdByUsername 도). */
    public function search(#[\SensitiveParameter] ?Criteria $criteria = null): UserCollection
    {
        return ErrorTranslation::call(fn (): UserCollection => $this->kc->users()->search($this->realm, $criteria));
    }

    public function delete(string $userId): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->delete($this->realm, $userId));
    }

    /** 편의: username으로 생성된 사용자 id 조회(create가 void라 필요). */
    public function findIdByUsername(#[\SensitiveParameter] string $username): ?string
    {
        $found = $this->search(new Criteria(['username' => $username, 'exact' => true]));

        return $found->first()?->getId();
    }
}
