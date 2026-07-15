<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\KeycloakException;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Internal\PkceKeycloakProvider;
use Xzawed\Keycloak\Token\AuthorizationRequest;
use Xzawed\Keycloak\Token\IntrospectionResult;
use Xzawed\Keycloak\Token\TokenSet;
use Xzawed\Keycloak\Token\ValidatedToken;

/**
 * 인증 파사드 — league/oauth2-client + stevenmaguire/oauth2-keycloak을 감싸고
 * introspect/logout(RFC 7662 + 백채널)은 손수 구현한다. validate()는 T7 JwtValidator에 위임.
 *
 * 네트워크 경계 모듈 — 커버리지 게이트 omit(phpunit.xml). 전체 흐름은 Task 11 통합테스트로 검증.
 */
final class AuthClient
{
    private PkceKeycloakProvider $provider;

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly OidcEndpoints $endpoints,
        private readonly JwtValidator $validator,
        private readonly GuzzleClientInterface $http,
    ) {
        $this->provider = new PkceKeycloakProvider([
            'authServerUrl' => $config->serverUrl,
            'realm' => $config->realm,
            'clientId' => $config->clientId,
            'clientSecret' => $config->clientSecret ?? '',
            'redirectUri' => $config->redirectUri ?? '',
            'version' => '26.0.0',   // >=20 → openid 스코프, >=18 → logout id_token_hint
        ], ['httpClient' => $http]);
    }

    public function createAuthorizationRequest(): AuthorizationRequest
    {
        $url = $this->provider->getAuthorizationUrl(['scope' => implode(' ', $this->config->scopes)]);
        $verifier = $this->provider->getPkceCode();

        return new AuthorizationRequest(url: $url, state: $this->provider->getState(), codeVerifier: (string) $verifier);
    }

    /**
     * Authorization-code + PKCE 토큰 교환. 콜백에서 OAuth `state`를 createAuthorizationRequest()가 발급한
     * 값과 대조하는 것은 호출자 책임이다(SDK는 무상태라 state를 검증하지 않는다 — Node/Go/C# SDK와 동형).
     */
    public function exchangeCode(string $code, string $codeVerifier): TokenSet
    {
        $this->provider->setPkceCode($codeVerifier);

        return $this->toTokenSet($this->getAccessToken('authorization_code', ['code' => $code]));
    }

    public function clientCredentialsToken(): TokenSet
    {
        // config.scopes를 client-credentials 요청에 전달한다(authz-url과 동형). 누락 시 커스텀 스코프가
        // 무시돼 언더스코프 토큰이 발급된다(다른 SDK는 모두 threading — Node/Rust token-provider 동형).
        $options = $this->config->scopes === [] ? [] : ['scope' => implode(' ', $this->config->scopes)];

        return $this->toTokenSet($this->getAccessToken('client_credentials', $options));
    }

    public function refresh(string $refreshToken): TokenSet
    {
        return $this->toTokenSet($this->getAccessToken('refresh_token', ['refresh_token' => $refreshToken]));
    }

    public function validate(string $accessToken): ValidatedToken
    {
        return $this->validator->validate($accessToken);
    }

    public function introspect(string $token): IntrospectionResult
    {
        // RFC 7662 — league/stevenmaguire 미제공, 손수 POST(client_secret_basic)
        // RFC 6749 §2.3.1: Basic 자격증명은 각 구성요소를 먼저 percent-encode한다
        // (secret에 ':'/예약문자가 있어도 자격증명이 깨지지 않도록).
        $basic = base64_encode(rawurlencode($this->config->clientId) . ':' . rawurlencode($this->config->clientSecret ?? ''));
        try {
            $response = $this->http->request('POST', $this->endpoints->introspection(), [
                'headers' => ['Authorization' => 'Basic ' . $basic, 'Content-Type' => 'application/x-www-form-urlencoded'],
                'form_params' => ['token' => $token, 'token_type_hint' => 'access_token'],
            ]);
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('introspection unreachable', previous: $e);
        } catch (GuzzleException $e) {
            throw new KeycloakAuthError('introspection failed', previous: $e);
        } catch (KeycloakException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new KeycloakTransportError('introspection failed unexpectedly', previous: $e);
        }
        $json = json_decode((string) $response->getBody(), true);
        if (!is_array($json)) {
            throw new KeycloakAuthError('introspection returned non-JSON');
        }

        return IntrospectionResult::fromArray(self::stringKeyed($json));
    }

    public function logoutUrl(TokenSet $tokens): string
    {
        $token = new AccessToken(['access_token' => $tokens->accessToken, 'id_token' => $tokens->idToken]);

        return $this->provider->getLogoutUrl(['access_token' => $token]);
    }

    public function logout(string $refreshToken): void
    {
        // 백채널 end_session POST(refresh_token + client creds) — league/stevenmaguire 미제공
        try {
            $this->http->request('POST', $this->endpoints->endSession(), [
                'form_params' => [
                    'client_id' => $this->config->clientId,
                    'client_secret' => $this->config->clientSecret ?? '',
                    'refresh_token' => $refreshToken,
                ],
            ]);
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('logout unreachable', previous: $e);
        } catch (GuzzleException $e) {
            throw new KeycloakAuthError('logout failed', previous: $e);
        } catch (KeycloakException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new KeycloakTransportError('logout failed unexpectedly', previous: $e);
        }
    }

    /** @param array<string,mixed> $options */
    private function getAccessToken(string $grant, array $options = []): AccessToken
    {
        try {
            $token = $this->provider->getAccessToken($grant, $options);
        } catch (IdentityProviderException $e) {
            $body = $e->getResponseBody();
            $oauth = is_array($body) && isset($body['error']) ? self::toStr($body['error']) : null;

            throw new KeycloakAuthError('token request rejected: ' . $e->getMessage(), oauthError: $oauth, previous: $e);
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('token endpoint unreachable', previous: $e);
        } catch (GuzzleException $e) {
            throw new KeycloakTransportError('token request failed', previous: $e);
        } catch (\UnexpectedValueException $e) {
            // league는 토큰 엔드포인트가 비-JSON/파싱불가 응답을 줄 때 SPL \UnexpectedValueException을
            // 던진다(IdentityProviderException이 아님 — OAuth 에러 바디가 아니라 응답 자체가 깨진 경우).
            // JwksStore가 동일 상황(비-JSON 응답)을 KeycloakTransportError로 매핑하는 것과 동형.
            throw new KeycloakTransportError('token endpoint returned unexpected response', previous: $e);
        } catch (\Throwable $e) {
            // league/oauth2-client 및 그 하위 의존성이 던질 수 있는 그 밖의 미분류 예외까지 전부
            // 여기로 수렴시켜 "getAccessToken을 벗어나는 미분류 하위 예외는 없다" 경계를 보장한다.
            // (KeycloakException pass-through 분기는 넣지 않는다 — $this->provider->getAccessToken()은
            // league의 완전히 타입드된 메서드라 PHPStan이 우리 자신의 예외가 여기서 절대 던져지지 않음을
            // 증명하므로 그 분기는 도달불가 dead catch로 확정 보고된다: catch.neverThrown.)
            throw new KeycloakTransportError('token request failed', previous: $e);
        }
        if (!$token instanceof AccessToken) {
            throw new KeycloakAuthError('unexpected access token implementation');
        }

        return $token;
    }

    private function toTokenSet(AccessToken $t): TokenSet
    {
        $values = self::stringKeyed($t->getValues());

        return new TokenSet(
            accessToken: $t->getToken(),
            tokenType: isset($values['token_type']) ? self::toStr($values['token_type']) : 'Bearer',
            expiresIn: $t->getExpires() !== null ? max(0, $t->getExpires() - \time()) : 0,
            refreshToken: $t->getRefreshToken(),
            idToken: isset($values['id_token']) ? self::toStr($values['id_token']) : null,
            scope: isset($values['scope']) ? self::toStr($values['scope']) : null,
            expiresAt: $t->getExpires(),
        );
    }

    /** mixed 값을 문자열로 안전하게 좁힌다(신뢰된 OAuth 응답의 스칼라 값만 통과). */
    private static function toStr(mixed $v, string $default = ''): string
    {
        return match (true) {
            \is_string($v) => $v,
            \is_int($v), \is_float($v), \is_bool($v) => (string) $v,
            default => $default,
        };
    }

    /**
     * json_decode(..., true)/league getValues()의 배열은 키 타입이 array-key(int|string)로만 추론된다.
     * 신뢰된 OAuth/introspection 응답의 키는 항상 문자열이므로 정수 키(있다면)를 걸러 string-keyed로 좁힌다
     * (JwtValidator/JwksStore의 stringKeyed와 동일 패턴 — 로컬 헬퍼로 중복 유지, 공용화는 범위 밖).
     *
     * @param array<array-key, mixed> $a
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $a): array
    {
        $out = [];
        foreach ($a as $k => $v) {
            if (is_string($k)) {
                $out[$k] = $v;
            }
        }

        return $out;
    }
}
