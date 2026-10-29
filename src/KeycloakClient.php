<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use Xzawed\Keycloak\Admin\AdminClient;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\Jwks\JwksStore;

/**
 * Unified entry point: auth is assembled eagerly (no network); admin is created lazily on the first admin() call
 * (needs the secret) and cached.
 *
 * Network-boundary module — omitted from the coverage gate (phpunit.xml). The full flow is verified by the Task 11
 * integration tests.
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
