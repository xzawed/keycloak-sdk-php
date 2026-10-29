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
     * ⚠️ The fschmtt client holds the credentials, so a dump printed the client secret verbatim (measured 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }

    /**
     * To get the id after creating, follow up with a search (fschmtt create is void).
     *
     * ⚠️ The representation being sent can hold secrets (credentials) — it is hidden so it is not printed as a trace
     * argument of a failure error (update too).
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
     * void — the sister languages (Java/Kotlin/Python/Node/Go/Ruby/.NET) all return no value.
     * fschmtt Users::update is void too, so there is nothing to discard.
     */
    public function update(string $userId, #[\SensitiveParameter] User $user): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->update($this->realm, $userId, $user));
    }

    /** ⚠️ The search criteria go into the query — just as the cause copy strips the URL's query, they are hidden from a failure error's trace arguments too (findIdByUsername as well). */
    public function search(#[\SensitiveParameter] ?Criteria $criteria = null): UserCollection
    {
        return ErrorTranslation::call(fn (): UserCollection => $this->kc->users()->search($this->realm, $criteria));
    }

    public function delete(string $userId): void
    {
        ErrorTranslation::call(fn () => $this->kc->users()->delete($this->realm, $userId));
    }

    /** Convenience: looks up a created user's id by username (needed because create is void). */
    public function findIdByUsername(#[\SensitiveParameter] string $username): ?string
    {
        $found = $this->search(new Criteria(['username' => $username, 'exact' => true]));

        return $found->first()?->getId();
    }
}
