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

    /** fschmtt는 import(create 아님) — id를 세팅해야 내부 re-GET이 성립. */
    public function import(Client $client): Client
    {
        return ErrorTranslation::call(fn (): Client => $this->kc->clients()->import($this->realm, $client));
    }

    public function get(string $clientUuid): Client
    {
        return ErrorTranslation::call(fn (): Client => $this->kc->clients()->get($this->realm, $clientUuid));
    }

    public function all(?Criteria $criteria = null): ClientCollection
    {
        return ErrorTranslation::call(fn (): ClientCollection => $this->kc->clients()->all($this->realm, $criteria));
    }

    public function delete(string $clientUuid): void
    {
        ErrorTranslation::call(fn () => $this->kc->clients()->delete($this->realm, $clientUuid));
    }
}
