<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Http\Criteria;
use Fschmtt\Keycloak\Representation\Client;
use Fschmtt\Keycloak\Collection\ClientCollection;

final class ClientsResource
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
     * fschmtt uses import (not create) — the id has to be set for the internal re-GET to work.
     *
     * ⚠️ The representation being sent can hold a client secret — it is hidden so it is not printed as a trace argument of
     * a failure error (update too).
     */
    public function import(#[\SensitiveParameter] Client $client): Client
    {
        return ErrorTranslation::call(fn (): Client => $this->kc->clients()->import($this->realm, $client));
    }

    public function get(string $clientUuid): Client
    {
        return ErrorTranslation::call(fn (): Client => $this->kc->clients()->get($this->realm, $clientUuid));
    }

    /** ⚠️ The search criteria go into the query — just as the cause copy strips the URL's query, they are hidden from a failure error's trace arguments too. */
    public function all(#[\SensitiveParameter] ?Criteria $criteria = null): ClientCollection
    {
        return ErrorTranslation::call(fn (): ClientCollection => $this->kc->clients()->all($this->realm, $criteria));
    }

    public function delete(string $clientUuid): void
    {
        ErrorTranslation::call(fn () => $this->kc->clients()->delete($this->realm, $clientUuid));
    }

    /**
     * void — fschmtt Clients::update re-GETs the Client and returns it, but
     * the facade discards it. The sister languages' update is void/None/nil/Task/error in every case
     * (§4 isomorphism). import is POST + re-fetch (create), so it keeps its name; this one is a
     * PUT, so it is update, as in fschmtt.
     */
    public function update(string $clientUuid, #[\SensitiveParameter] Client $client): void
    {
        ErrorTranslation::call(fn () => $this->kc->clients()->update($this->realm, $clientUuid, $client));
    }
}
