<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Http\Command;
use Fschmtt\Keycloak\Http\Method;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Resource\Resource as FschmttResource;

/**
 * 경로(현재 이름)와 body(새 이름)를 **분리해서** 내는 롤 update.
 *
 * ⚠️ fschmtt `Roles::update` 는 경로를 `$role->getName()` 에서 만든다
 * (`Resource/Roles.php` 의 `'roleName' => $role->getName()`). 경로와 body 가 같은 값에서
 * 나오므로 **rename 을 표현할 수 없다** — 실측하면 PUT 이 `/roles/{새 이름}` 으로 나가고
 * 현재 이름은 요청 어디에도 없다. Keycloak 은 `PUT /roles/{현재 이름}` + body 의 새 이름으로
 * rename 하므로, 그 요청은 rename 이 아니라 존재하지 않는 롤에 대한 갱신이다.
 *
 * fschmtt 의 공개 탈출구 `Keycloak::resource()` 로 이 클래스를 세우면 토큰·HTTP 클라이언트·
 * 직렬화기를 **그대로 재사용**한다. raw Guzzle PUT 이었다면 베어러를 따로 구해야 하는데
 * 그것은 fschmtt 안에 잠겨 있고, 새로 grant 를 태우면 §4 토큰 캐시 불변식이 깨진다.
 *
 * ⚠️ `CommandExecutor` 는 fschmtt 가 `@internal` 로 표시한 타입이다. 그것을 여기서 쓰는 근거는
 * `composer.json` 의 **정확 핀 `0.42.0`** 하나뿐이다 — 핀을 올릴 때 `RolesRenameTest` 가
 * 실제 fschmtt 스택을 태워 이 조립이 아직 성립하는지 확인한다.
 *
 * @internal §4 — 이 타입은 파사드 밖으로 나가지 않는다.
 */
final class RenamableRoles extends FschmttResource
{
    public function updateByName(string $realm, string $currentName, Role $role): void
    {
        $this->commandExecutor->executeCommand(new Command(
            '/admin/realms/{realm}/roles/{roleName}',
            Method::PUT,
            [
                'realm' => $realm,
                'roleName' => $currentName,
            ],
            $role,
        ));
    }
}
