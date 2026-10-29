<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\GrantType;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\Internal\AdminResponseBody;
use Xzawed\Keycloak\Internal\BearerToken;
use Xzawed\Keycloak\Internal\TokenResponseCap;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Exception\KeycloakConfigError;

/**
 * Admin facade wrapping fschmtt (the admin REST client). Network-boundary module — omitted from the coverage gate
 * (phpunit.xml). The actual CRUD is verified by the Task 11 integration tests.
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
        // 토큰 응답 상한(`TokenResponseCap`) — fschmtt 가 토큰을 받는 요청에만 걸고 admin REST 응답(사용자 목록 등)은 건드리지 않는다.
        // admin REST 응답 본문(`AdminResponseBody`)은 그 나머지 요청에 — 읽지 않는 2xx 본문은 받지 않고 오류 본문은 상한에서 자른다.
        // 둘 다 맨 안쪽(`push`)이라 http_errors 보다 먼저 본문을 받는다 — 오류 상태의 본문도 상한을 지난다.
        // Bearer 문법(`BearerToken`)은 그 바깥 — 상한이 판정한 토큰 응답에서 fschmtt 가 받아 두기 전에 access token 을 거부한다.
        $stack = HandlerStack::create();
        $stack->push(BearerToken::grantMiddleware(self::isTokenGrant(...)), 'bearer_grammar');
        $stack->push(TokenResponseCap::middleware(self::isTokenGrant(...), 'admin token response'), 'token_response_cap');
        $stack->push(AdminResponseBody::middleware(self::isTokenGrant(...)), 'admin_response_body');
        $guzzle = new GuzzleClient(['handler' => $stack] + HttpOptions::guzzle($config));
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
     * ⚠️ The fschmtt client holds the credentials, so a dump printed the client secret verbatim (measured 2026-09-26).
     * That object is not shown — take it out with `raw()` if you need it.
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

    /** Escape hatch — the underlying fschmtt client (a documented hiding exception). */
    public function raw(): Keycloak
    {
        return $this->kc;
    }

    /**
     * fschmtt 의 토큰 부여(client_credentials 와 그 refresh_token) — Bearer 없이 토큰 경로로 가는 요청. admin REST 요청은 전부 Bearer 를
     * 싣는다. `ErrorTranslation::failed()` 와 같은 규칙이다(꼬리만으로는 못 가른다 — 그 상수의 docblock).
     */
    private static function isTokenGrant(RequestInterface $request): bool
    {
        return !$request->hasHeader('Authorization') && str_ends_with($request->getUri()->getPath(), ErrorTranslation::TOKEN_PATH);
    }
}
