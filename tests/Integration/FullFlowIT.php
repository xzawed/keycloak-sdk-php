<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Integration;

use Fschmtt\Keycloak\Representation\Client as ClientRepresentation;
use Fschmtt\Keycloak\Representation\User;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;

/**
 * E2E — 실제 Keycloak 26.6 컨테이너(realm import)로 전 흐름 검증:
 * client-credentials 토큰 → validate(다중 aud) → introspect → user CRUD → delete 후 NotFound →
 * client import/get/delete → raw() 탈출구 스모크.
 *
 * 컨테이너 라이프사이클은 {@see KeycloakContainerTrait}(docker CLI 폴백) 참고.
 */
final class FullFlowIT extends TestCase
{
    use KeycloakContainerTrait;

    private static KeycloakClient $client;

    public static function setUpBeforeClass(): void
    {
        self::startKeycloak();
        self::$client = KeycloakClient::create(new KeycloakConfig(
            serverUrl: self::$baseUrl,
            realm: 'it-realm',
            clientId: 'it-client',
            clientSecret: 'it-secret',
        ));
    }

    public static function tearDownAfterClass(): void
    {
        self::stopKeycloak();
    }

    public function testFullFlow(): void
    {
        // 1) client-credentials 토큰
        $token = self::$client->auth()->clientCredentialsToken();
        self::assertNotSame('', $token->accessToken);
        self::assertGreaterThan(0, $token->expiresIn);

        // 2) validate(자체강화 RS256 검증 — 실제 KC JWKS 조회, 다중 aud 수용, it-client 포함)
        $validated = self::$client->auth()->validate($token->accessToken);
        self::assertContains('it-client', $validated->audience);
        self::assertStringEndsWith('/realms/it-realm', $validated->issuer);

        // 3) introspect(RFC 7662)
        $introspected = self::$client->auth()->introspect($token->accessToken);
        self::assertTrue($introspected->active);

        // 4) user CRUD
        $users = self::$client->admin()->users();
        $username = 'php-it-' . bin2hex(random_bytes(4));
        $users->create(new User(username: $username, email: "{$username}@example.com", enabled: true));

        $userId = $users->findIdByUsername($username);
        self::assertNotNull($userId);
        self::assertSame($username, $users->get($userId)->getUsername());

        $users->delete($userId);

        // 5) delete 후 조회 → NotFound
        $this->expectException(KeycloakNotFoundError::class);
        $users->get($userId);
    }

    public function testAdminClientCrud(): void
    {
        $clients = self::$client->admin()->clients();
        $clientUuid = self::uuidV4();
        $clientId = 'php-it-client-' . bin2hex(random_bytes(4));

        // fschmtt의 import()는 POST 후 $client->getId()로 재-GET한다(Location 헤더 미사용) —
        // 따라서 id를 미리 생성해 넘겨야 한다(ClientsResource 문서화된 제약, Task 9와 동형).
        $imported = $clients->import(new ClientRepresentation(
            id: $clientUuid,
            clientId: $clientId,
            enabled: true,
            publicClient: true,
            protocol: 'openid-connect',
        ));
        self::assertSame($clientUuid, $imported->getId());
        self::assertSame($clientId, $imported->getClientId());

        $fetched = $clients->get($clientUuid);
        self::assertSame($clientId, $fetched->getClientId());

        $clients->delete($clientUuid);

        $this->expectException(KeycloakNotFoundError::class);
        $clients->get($clientUuid);
    }

    public function testRawEscapeHatch(): void
    {
        // raw() 탈출구 스모크 — 하위 fschmtt 클라이언트가 실제로 살아있는지 확인
        self::assertNotSame('', self::$client->admin()->raw()->getBaseUrl());
    }

    private static function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        $hex = bin2hex($data);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }
}
