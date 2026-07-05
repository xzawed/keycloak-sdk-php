<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\GrantType;
use GuzzleHttp\Client as GuzzleClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Exception\KeycloakConfigError;

/**
 * fschmtt(admin REST client)를 감싸는 관리 파사드. 네트워크 경계 모듈 — 커버리지 게이트 omit(phpunit.xml).
 * 실제 CRUD는 Task 11 통합테스트로 검증.
 */
final class AdminClient
{
    private readonly Keycloak $kc;
    private readonly string $realm;

    public function __construct(KeycloakConfig $config)
    {
        if ($config->clientSecret === null || $config->clientSecret === '') {
            throw new KeycloakConfigError('admin requires clientSecret (client-credentials)');
        }
        $this->realm = $config->realm;
        $guzzle = new GuzzleClient([
            'connect_timeout' => $config->connectTimeout,
            'timeout' => $config->readTimeout,
            'verify' => true,
            'http_errors' => true,
        ]);
        $this->kc = ErrorTranslation::call(fn (): Keycloak => (new Builder())
            ->withBaseUrl($config->serverUrl)
            ->withGrantType(GrantType::clientCredentials(
                clientId: $config->clientId,
                clientSecret: $config->clientSecret,
                realm: $config->realm,
            ))
            ->withHttpClient($guzzle)
            ->build());
    }

    public function users(): UsersResource
    {
        return new UsersResource($this->kc, $this->realm);
    }

    public function clients(): ClientsResource
    {
        return new ClientsResource($this->kc, $this->realm);
    }

    public function realms(): RealmsResource
    {
        return new RealmsResource($this->kc);
    }

    public function roles(): RolesResource
    {
        return new RolesResource($this->kc, $this->realm);
    }

    public function groups(): GroupsResource
    {
        return new GroupsResource($this->kc, $this->realm);
    }

    /** 탈출구 — 하위 fschmtt 클라이언트(문서화된 은닉성 예외). */
    public function raw(): Keycloak
    {
        return $this->kc;
    }
}
