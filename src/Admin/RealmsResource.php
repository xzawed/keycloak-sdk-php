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

    public function get(string $realm): Realm
    {
        return ErrorTranslation::call(fn (): Realm => $this->kc->realms()->get($realm));
    }

    /** ClientsResource::all() 과 동형 — 이름 all, 반환 *Collection, 선택 Criteria. */
    public function all(?Criteria $criteria = null): RealmCollection
    {
        return ErrorTranslation::call(fn (): RealmCollection => $this->kc->realms()->all($criteria));
    }

    /** import(create 아님) — realm 이름으로 내부 re-GET. */
    public function import(Realm $realm): Realm
    {
        return ErrorTranslation::call(fn (): Realm => $this->kc->realms()->import($realm));
    }

    public function delete(string $realm): void
    {
        ErrorTranslation::call(fn () => $this->kc->realms()->delete($realm));
    }

    /**
     * void — fschmtt Realms::update 는 Realm 을 재-GET 해 돌려주지만
     * 파사드는 버린다(ClientsResource::update 와 같은 결정). import 는
     * POST+재조회(생성)이고 여기는 PUT 이라 이름을 update 로 둔다.
     */
    public function update(string $realm, Realm $updated): void
    {
        ErrorTranslation::call(fn () => $this->kc->realms()->update($realm, $updated));
    }
}
