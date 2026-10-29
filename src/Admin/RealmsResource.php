<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Collection\RealmCollection;
use Fschmtt\Keycloak\Http\Criteria;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Realm;

final class RealmsResource
{
    public function __construct(private readonly Keycloak $kc) {}

    /**
     * ⚠️ The fschmtt client holds the credentials, so a dump printed the client secret verbatim (measured 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [];
    }

    public function get(string $realm): Realm
    {
        return ErrorTranslation::call(fn (): Realm => $this->kc->realms()->get($realm));
    }

    /** Isomorphic with ClientsResource::all() — named all, returns *Collection, optional Criteria (it goes into the query, so it is hidden too). */
    public function all(#[\SensitiveParameter] ?Criteria $criteria = null): RealmCollection
    {
        return ErrorTranslation::call(fn (): RealmCollection => $this->kc->realms()->all($criteria));
    }

    /**
     * import (not create) — internal re-GET by realm name.
     *
     * ⚠️ The representation being sent can hold secrets (client, user and SMTP credentials) — it is hidden so it is not
     * printed as a trace argument of a failure error (update too).
     */
    public function import(#[\SensitiveParameter] Realm $realm): Realm
    {
        return ErrorTranslation::call(fn (): Realm => $this->kc->realms()->import($realm));
    }

    public function delete(string $realm): void
    {
        ErrorTranslation::call(fn () => $this->kc->realms()->delete($realm));
    }

    /**
     * void — fschmtt Realms::update re-GETs the Realm and returns it, but
     * the facade discards it (the same decision as ClientsResource::update). import is
     * POST + re-fetch (create) and this one is a PUT, so it is named update.
     */
    public function update(string $realm, #[\SensitiveParameter] Realm $updated): void
    {
        ErrorTranslation::call(fn () => $this->kc->realms()->update($realm, $updated));
    }
}
