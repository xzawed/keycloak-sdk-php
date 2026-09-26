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
     * ⚠️ fschmtt 클라이언트가 자격증명을 쥐고 있어 덤프가 클라이언트 시크릿을 원문으로 찍었다(실측 2026-09-26).
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
    }

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

    /**
     * void — fschmtt Clients::update 는 Client 를 재-GET 해 돌려주지만
     * 파사드는 버린다. 자매 언어 update 는 전부 void/None/nil/Task/error
     * (§4 동형). import 는 POST+재조회(생성)라 이름을 유지하고, 여기는
     * PUT 이라 fschmtt 그대로 update 다.
     */
    public function update(string $clientUuid, Client $client): void
    {
        ErrorTranslation::call(fn () => $this->kc->clients()->update($this->realm, $clientUuid, $client));
    }
}
