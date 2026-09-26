<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\GrantType;
use GuzzleHttp\Client as GuzzleClient;
use Xzawed\Keycloak\Http\HttpOptions;
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
        $guzzle = new GuzzleClient(HttpOptions::guzzle($config));
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

    /**
     * ⚠️ fschmtt 클라이언트는 자격증명을 쥐고 있어 덤프가 클라이언트 시크릿을 원문으로 찍었다(실측 2026-09-26).
     * 그 객체는 내보이지 않는다 — 필요하면 `raw()` 로 꺼낸다.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm];
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
