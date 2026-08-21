<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Collection\RealmCollection;
use Fschmtt\Keycloak\Http\Criteria;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Client as ClientRepresentation;
use Fschmtt\Keycloak\Representation\Group;
use Fschmtt\Keycloak\Representation\Realm;
use Fschmtt\Keycloak\Representation\User;
use Fschmtt\Keycloak\Resource\Clients;
use Fschmtt\Keycloak\Resource\Groups;
use Fschmtt\Keycloak\Resource\Realms;
use Fschmtt\Keycloak\Resource\Users;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Admin\ClientsResource;
use Xzawed\Keycloak\Admin\GroupsResource;
use Xzawed\Keycloak\Admin\RealmsResource;
use Xzawed\Keycloak\Admin\RolesResource;
use Xzawed\Keycloak\Admin\UsersResource;
use Xzawed\Keycloak\Exception\KeycloakConflictError;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;

/**
 * update() 다섯 리소스 + realms.all() 위임·경계 변환.
 *
 * 반환 타입은 전부 void — 자매 언어 실측:
 *   Java void · Kotlin Unit · Python None · Node Promise<void> ·
 *   Go error · Ruby nil · .NET Task.
 * fschmtt Clients::update / Realms::update 가 representation을 돌려줘도
 * 파사드는 버린다(§4 동형). Users/Roles/Groups 는 원래 void.
 */
final class AdminResourceUpdateTest extends TestCase
{
    private const REALM = 'test-realm';

    private function clientEx(int $status): ClientException
    {
        return new ClientException("HTTP $status", new Request('PUT', '/'), new Response($status));
    }

    /**
     * Keycloak 스텁 — 접근자만 연결. PHPUnit 12 는 기대 없는 createMock 을 notice 한다.
     *
     * @param 'users'|'clients'|'realms'|'roles'|'groups' $accessor
     */
    private function kcReturning(string $accessor, object $inner): Keycloak
    {
        $kc = self::createStub(Keycloak::class);
        $kc->method($accessor)->willReturn($inner);

        return $kc;
    }

    /**
     * @return list<array{0: class-string, 1: 'update'}>
     */
    public static function updateMethods(): array
    {
        return [
            [UsersResource::class, 'update'],
            [ClientsResource::class, 'update'],
            [RealmsResource::class, 'update'],
            [RolesResource::class, 'update'],
            [GroupsResource::class, 'update'],
        ];
    }

    #[DataProvider('updateMethods')]
    public function testUpdateReturnTypeIsVoid(string $class, string $method): void
    {
        $type = (new \ReflectionMethod($class, $method))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $type, "$class::$method must declare a named return type");
        self::assertSame('void', $type->getName(), "$class::$method must be void (sister-language isomorphism)");
    }

    public function testUsersUpdateDelegates(): void
    {
        $user = new User(username: 'alice');
        $inner = self::createMock(Users::class);
        $inner->expects($this->once())->method('update')->with(self::REALM, 'u1', $user);

        (new UsersResource($this->kcReturning('users', $inner), self::REALM))->update('u1', $user);
    }

    public function testUsersUpdate404BecomesNotFound(): void
    {
        $inner = self::createStub(Users::class);
        $inner->method('update')->willThrowException($this->clientEx(404));

        $this->expectException(KeycloakNotFoundError::class);
        (new UsersResource($this->kcReturning('users', $inner), self::REALM))->update('missing', new User(username: 'x'));
    }

    public function testUsersUpdate409BecomesConflict(): void
    {
        $inner = self::createStub(Users::class);
        $inner->method('update')->willThrowException($this->clientEx(409));

        $this->expectException(KeycloakConflictError::class);
        (new UsersResource($this->kcReturning('users', $inner), self::REALM))->update('u1', new User(username: 'x'));
    }

    public function testClientsUpdateDelegatesAndDiscardsReturn(): void
    {
        $client = new ClientRepresentation(id: 'c1', clientId: 'app');
        $inner = self::createMock(Clients::class);
        $inner->expects($this->once())
            ->method('update')
            ->with(self::REALM, 'c1', $client)
            ->willReturn($client);

        (new ClientsResource($this->kcReturning('clients', $inner), self::REALM))->update('c1', $client);
    }

    public function testClientsUpdate404BecomesNotFound(): void
    {
        $inner = self::createStub(Clients::class);
        $inner->method('update')->willThrowException($this->clientEx(404));

        $this->expectException(KeycloakNotFoundError::class);
        (new ClientsResource($this->kcReturning('clients', $inner), self::REALM))->update('missing', new ClientRepresentation(id: 'x'));
    }

    public function testRealmsUpdateDelegatesAndDiscardsReturn(): void
    {
        $realm = new Realm(realm: 'r1', displayName: 'R');
        $inner = self::createMock(Realms::class);
        $inner->expects($this->once())
            ->method('update')
            ->with('r1', $realm)
            ->willReturn($realm);

        (new RealmsResource($this->kcReturning('realms', $inner)))->update('r1', $realm);
    }

    public function testRealmsUpdate404BecomesNotFound(): void
    {
        $inner = self::createStub(Realms::class);
        $inner->method('update')->willThrowException($this->clientEx(404));

        $this->expectException(KeycloakNotFoundError::class);
        (new RealmsResource($this->kcReturning('realms', $inner)))->update('missing', new Realm(realm: 'missing'));
    }

    public function testRealmsAllDelegates(): void
    {
        $criteria = new Criteria();
        $collection = new RealmCollection();
        $inner = self::createMock(Realms::class);
        $inner->expects($this->once())->method('all')->with($criteria)->willReturn($collection);

        $result = (new RealmsResource($this->kcReturning('realms', $inner)))->all($criteria);
        self::assertSame($collection, $result);
    }

    public function testRealmsAllWithoutCriteriaPassesNull(): void
    {
        $collection = new RealmCollection();
        $inner = self::createMock(Realms::class);
        $inner->expects($this->once())->method('all')->with(null)->willReturn($collection);

        self::assertSame($collection, (new RealmsResource($this->kcReturning('realms', $inner)))->all());
    }

    public function testRealmsAll404BecomesNotFound(): void
    {
        $inner = self::createStub(Realms::class);
        $inner->method('all')->willThrowException($this->clientEx(404));

        $this->expectException(KeycloakNotFoundError::class);
        (new RealmsResource($this->kcReturning('realms', $inner)))->all();
    }

    // 롤의 update 위임·404 변환은 여기에 없다 — RolesRenameTest 로 옮겼다.
    // 이 파일은 fschmtt Resource 를 목으로 뜨는데, 롤만은 그 경계에서 목을 뜨면
    // **경로가 어떻게 조립되는지 볼 수 없다**. fschmtt Roles::update 는 경로를
    // $role->getName() 에서 만들어 rename 을 표현하지 못하고, 목은 그것을 통과시킨다.
    // 그래서 롤은 실제 HTTP 스택을 태워 경로와 body 를 함께 본다.

    public function testGroupsUpdateDelegates(): void
    {
        $group = new Group(id: 'g1', name: 'staff');
        $inner = self::createMock(Groups::class);
        $inner->expects($this->once())->method('update')->with(self::REALM, 'g1', $group);

        (new GroupsResource($this->kcReturning('groups', $inner), self::REALM))->update('g1', $group);
    }

    public function testGroupsUpdate404BecomesNotFound(): void
    {
        $inner = self::createStub(Groups::class);
        $inner->method('update')->willThrowException($this->clientEx(404));

        $this->expectException(KeycloakNotFoundError::class);
        (new GroupsResource($this->kcReturning('groups', $inner), self::REALM))->update('missing', new Group(name: 'x'));
    }

    public function testGroupsUpdate409BecomesConflict(): void
    {
        $inner = self::createStub(Groups::class);
        $inner->method('update')->willThrowException($this->clientEx(409));

        $this->expectException(KeycloakConflictError::class);
        (new GroupsResource($this->kcReturning('groups', $inner), self::REALM))->update('g1', new Group(name: 'x'));
    }
}
