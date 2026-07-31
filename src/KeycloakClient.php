<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Xzawed\Keycloak\Admin\AdminClient;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\Jwks\JwksStore;

/**
 * 통합 진입점: auth 즉시 조립(네트워크 없음), admin은 첫 admin() 호출 시 지연 생성(secret 필요) + 캐시.
 *
 * 네트워크 경계 모듈 — 커버리지 게이트 omit(phpunit.xml). 전체 흐름은 Task 11 통합테스트로 검증.
 */
final class KeycloakClient
{
    private ?AdminClient $adminClient = null;

    private function __construct(
        private readonly KeycloakConfig $config,
        private readonly AuthClient $authClient,
    ) {}

    public static function create(KeycloakConfig $config): self
    {
        $endpoints = new OidcEndpoints($config);
        $guzzle = new GuzzleClient(HttpOptions::guzzle($config));
        $factory = new HttpFactory();
        $jwks = new JwksStore($endpoints->jwks(), $guzzle, $factory, $config->jwksMinRefetchSeconds);
        $validator = new JwtValidator($config, $endpoints, $jwks);
        $auth = new AuthClient($config, $endpoints, $validator, $guzzle);

        return new self($config, $auth);
    }

    public function auth(): AuthClient
    {
        return $this->authClient;
    }

    public function admin(): AdminClient
    {
        return $this->adminClient ??= new AdminClient($this->config);
    }

    public function close(): void
    {
        // Guzzle/PSR-18은 명시적 커넥션 풀 close가 필요 없다(소켓은 GC/keep-alive 관리).
        // 대칭성/미래대비로 제공 — admin 캐시 해제.
        $this->adminClient = null;
    }
}
