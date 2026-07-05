<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Realm;

final class RealmsResource
{
    public function __construct(private readonly Keycloak $kc) {}

    public function get(string $realm): Realm
    {
        return ErrorTranslation::call(fn (): Realm => $this->kc->realms()->get($realm));
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
}
