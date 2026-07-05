<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\{KeycloakClient, KeycloakConfig, AuthClient};
use Xzawed\Keycloak\Admin\AdminClient;

final class KeycloakClientTest extends TestCase
{
    private function cfg(): KeycloakConfig
    {
        return new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', clientSecret: 's');
    }

    public function testAuthEagerAdminLazyCached(): void
    {
        $client = KeycloakClient::create($this->cfg());
        // auth()/admin()의 반환 타입은 이미 AuthClient/AdminClient로 선언되어 있어(final class)
        // assertInstanceOf(및 ::class/get_debug_type 비교)는 PHPStan(level max)이 "always true"로
        // 지적한다(alreadyNarrowedType) — new \ReflectionObject(...)->getName()은 PHPStan이 리터럴로
        // 특수화하지 않으므로 실제 런타임 클래스명 검증을 유지하면서 이 규칙을 피한다
        // (ExceptionHierarchyTest의 class_parents와 동형 대응).
        self::assertSame(AuthClient::class, (new \ReflectionObject($client->auth()))->getName());
        $a1 = $client->admin();
        $a2 = $client->admin();
        self::assertSame(AdminClient::class, (new \ReflectionObject($a1))->getName());
        self::assertSame($a1, $a2);   // 캐시
    }
}
