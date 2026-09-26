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
use Xzawed\Keycloak\Exception\SanitizedCause;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\Internal\OAuthErrorCode;
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

    /**
     * @param string|null $redirectUri 이 요청에만 쓸 콜백 URL. null이면 config 값.
     *   ⚠️ 콜백이 여럿인 앱(멀티테넌트·환경별)이 클라이언트 하나로 그것을 섬기기 위한 자리다 —
     *   나머지 여덟 SDK와 동형. **`exchangeCode()`에 같은 값을 넘겨야 한다**(RFC 6749 §4.1.3).
     */
    public function createAuthorizationRequest(?string $redirectUri = null): AuthorizationRequest
    {
        // league/oauth2-client getAuthorizationUrl(['nonce' => $n])는 쿼리에 nonce=를 그대로 싣는다
        // (실측 2026-08-15: HAS_NONCE_KEY=yes MATCHES=yes). pkceMethod 생성자 옵션의 no-op과 다른 부류.
        $nonce = self::randomUrlSafe();
        $options = [
            'scope' => implode(' ', $this->config->scopes),
            'nonce' => $nonce,
        ];
        // ⚠️ 키가 비어 있으면 상류가 생성자 값으로 채운다(`AbstractProvider::getAuthorizationParameters`).
        // 그래서 null일 때는 **키 자체를 넣지 않는다** — 빈 문자열을 넣으면 config 폴백이 죽는다.
        if ($redirectUri !== null) {
            $options['redirect_uri'] = $redirectUri;
        }
        $url = $this->provider->getAuthorizationUrl($options);
        $verifier = $this->provider->getPkceCode();

        return new AuthorizationRequest(
            url: $url,
            state: $this->provider->getState(),
            codeVerifier: (string) $verifier,
            nonce: $nonce,
        );
    }

    /**
     * Authorization-code + PKCE 토큰 교환. 콜백에서 OAuth `state`를 createAuthorizationRequest()가 발급한
     * 값과 대조하는 것은 호출자 책임이다(SDK는 무상태라 state를 검증하지 않는다 — Node/Go/C# SDK와 동형).
     *
     * `$expectedNonce`가 주어지면(createAuthorizationRequest()가 돌려준 nonce) 응답 id_token을
     * JwtValidator로 서명·iss·aud·exp까지 검증한 뒤 nonce 클레임을 대조한다 — OIDC nonce 재생
     * 방지. 불일치·부재·검증실패는 모두 거부(fail-closed). null이면 id_token 검증을 건너뛴다
     * (여덟 언어 공통 패턴 — 필수로 만들지 않는다).
     */
    public function exchangeCode(
        #[\SensitiveParameter] string $code,
        #[\SensitiveParameter] string $codeVerifier,
        ?string $expectedNonce = null,
        ?string $redirectUri = null,
    ): TokenSet {
        $this->provider->setPkceCode($codeVerifier);
        $options = ['code' => $code];
        // ⚠️ 인가 때 쓴 값과 **같아야** 한다(RFC 6749 §4.1.3) — 다르면 Keycloak이 거부한다.
        // null일 때 키를 넣지 않는 이유는 createAuthorizationRequest()와 같다(상류 폴백 보존).
        if ($redirectUri !== null) {
            $options['redirect_uri'] = $redirectUri;
        }
        $tokens = $this->toTokenSet($this->getAccessToken('authorization_code', $options));
        if ($expectedNonce !== null) {
            $this->requireValidNonce($tokens->idToken, $expectedNonce);
        }

        return $tokens;
    }

    /**
     * id_token의 nonce 클레임을 대조하기 전에 강화 JwtValidator로 서명·iss·aud·exp까지 검증한다.
     * 거부는 자매 언어와 같이 Auth 계급(KeycloakAuthError)이다 — TokenValidationError는
     * validator가 던지고 여기서 감싼다(Ruby AuthError 동형).
     */
    private function requireValidNonce(#[\SensitiveParameter] ?string $idToken, string $expectedNonce): void
    {
        if ($idToken === null || $idToken === '') {
            throw new KeycloakAuthError('authorization code exchange failed: missing id_token for nonce validation');
        }
        try {
            $validated = $this->validator->validate($idToken);
        } catch (TokenValidationError $e) {
            throw new KeycloakAuthError('authorization code exchange failed: invalid id_token: ' . $e->getMessage(), previous: $e);
        }
        $actual = $validated->claims['nonce'] ?? null;
        if (!is_string($actual) || $actual !== $expectedNonce) {
            throw new KeycloakAuthError('authorization code exchange failed: unexpected nonce');
        }
    }

    /** state/PKCE와 같은 강도의 URL-safe 난수(base64url, 패딩 없음). */
    private static function randomUrlSafe(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    }

    public function clientCredentialsToken(): TokenSet
    {
        // config.scopes를 client-credentials 요청에 전달한다(authz-url과 동형). 누락 시 커스텀 스코프가
        // 무시돼 언더스코프 토큰이 발급된다(다른 SDK는 모두 threading — Node/Rust token-provider 동형).
        $options = $this->config->scopes === [] ? [] : ['scope' => implode(' ', $this->config->scopes)];

        return $this->toTokenSet($this->getAccessToken('client_credentials', $options));
    }

    public function refresh(#[\SensitiveParameter] string $refreshToken): TokenSet
    {
        return $this->toTokenSet($this->getAccessToken('refresh_token', ['refresh_token' => $refreshToken]));
    }

    public function validate(#[\SensitiveParameter] string $accessToken): ValidatedToken
    {
        return $this->validator->validate($accessToken);
    }

    public function introspect(#[\SensitiveParameter] string $token): IntrospectionResult
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
            throw new KeycloakTransportError('introspection unreachable', previous: SanitizedCause::of($e));
        } catch (GuzzleException $e) {
            throw new KeycloakAuthError('introspection failed', previous: SanitizedCause::of($e));
        } catch (KeycloakException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new KeycloakTransportError('introspection failed unexpectedly', previous: SanitizedCause::of($e));
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

    public function logout(#[\SensitiveParameter] string $refreshToken): void
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
            throw new KeycloakTransportError('logout unreachable', previous: SanitizedCause::of($e));
        } catch (GuzzleException $e) {
            throw new KeycloakAuthError('logout failed', previous: SanitizedCause::of($e));
        } catch (KeycloakException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new KeycloakTransportError('logout failed unexpectedly', previous: SanitizedCause::of($e));
        }
    }

    /**
     * ⚠️ `$options` 는 refresh_token·authorization code 를 쥔다 — 이 프레임이 SDK 예외 트레이스의 #0 이다.
     * ⚠️ 하위 예외는 원본이 아니라 `SanitizedCause` 사본으로 단다(그 클래스의 docblock).
     *
     * @param array<string,mixed> $options
     */
    private function getAccessToken(string $grant, #[\SensitiveParameter] array $options = []): AccessToken
    {
        try {
            $token = $this->provider->getAccessToken($grant, $options);
        } catch (IdentityProviderException $e) {
            $body = $e->getResponseBody();
            // ⚠️ league 의 메시지는 `error: error_description` 이다 — 설명은 응답 본문이라 IdP 가 토큰을 되울리면
            // 그대로 찍혔다(실측). 메시지에는 OAuth `error` 코드만 싣고(`oauthError` 와 같은 값), 그 코드도 코드
            // 모양일 때만 받는다 — `error` 자리에 토큰을 실어 보내면 공개 프로퍼티째 찍혔다(Grok 레그 실측).
            $oauth = OAuthErrorCode::of(is_array($body) ? ($body['error'] ?? null) : null);

            throw new KeycloakAuthError('token request rejected' . ($oauth === null ? '' : ': ' . $oauth), oauthError: $oauth, previous: SanitizedCause::of($e));
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('token endpoint unreachable', previous: SanitizedCause::of($e));
        } catch (GuzzleException $e) {
            throw new KeycloakTransportError('token request failed', previous: SanitizedCause::of($e));
        } catch (\UnexpectedValueException $e) {
            // league는 토큰 엔드포인트가 비-JSON/파싱불가 응답을 줄 때 SPL \UnexpectedValueException을
            // 던진다(IdentityProviderException이 아님 — OAuth 에러 바디가 아니라 응답 자체가 깨진 경우).
            // JwksStore가 동일 상황(비-JSON 응답)을 KeycloakTransportError로 매핑하는 것과 동형.
            throw new KeycloakTransportError('token endpoint returned unexpected response', previous: SanitizedCause::of($e));
        } catch (\Throwable $e) {
            // league/oauth2-client 및 그 하위 의존성이 던질 수 있는 그 밖의 미분류 예외까지 전부
            // 여기로 수렴시켜 "getAccessToken을 벗어나는 미분류 하위 예외는 없다" 경계를 보장한다.
            // (KeycloakException pass-through 분기는 넣지 않는다 — $this->provider->getAccessToken()은
            // league의 완전히 타입드된 메서드라 PHPStan이 우리 자신의 예외가 여기서 절대 던져지지 않음을
            // 증명하므로 그 분기는 도달불가 dead catch로 확정 보고된다: catch.neverThrown.)
            throw new KeycloakTransportError('token request failed', previous: SanitizedCause::of($e));
        }
        if (!$token instanceof AccessToken) {
            throw new KeycloakAuthError('unexpected access token implementation');
        }

        return $token;
    }

    /**
     * ⚠️ league 는 `access_token`·`refresh_token` 의 **존재**만 보고(`empty`) 타입은 안 본다 — 숫자·객체가 그대로
     * 실려 `strict_types` 의 `\TypeError` 가 공개 API 로 샜고, 그 트레이스 인자(`$t`)가 토큰 응답 전체를 쥐었다
     * (실측 2026-09-26). `expires_in` 이 소수면 만료 시각도 float 이라 같은 길로 샜다. `TokenSet::fromArray` 와
     * 같은 규칙으로 좁힌다 — access_token 은 강제변환하지 않는다(#481).
     */
    private function toTokenSet(#[\SensitiveParameter] AccessToken $t): TokenSet
    {
        $values = self::stringKeyed($t->getValues());
        $access = self::usableToken($t->getToken());
        if ($access === null) {
            throw new KeycloakAuthError('token response has no usable access_token');
        }
        $refresh = $t->getRefreshToken();
        $expires = self::toIntOrNull($t->getExpires());

        return new TokenSet(
            accessToken: $access,
            tokenType: isset($values['token_type']) ? self::toStr($values['token_type']) : 'Bearer',
            expiresIn: $expires !== null ? max(0, $expires - \time()) : 0,
            refreshToken: $refresh === null ? null : self::toStr($refresh),
            idToken: isset($values['id_token']) ? self::toStr($values['id_token']) : null,
            scope: isset($values['scope']) ? self::toStr($values['scope']) : null,
            expiresAt: $expires,
        );
    }

    /** 비어 있지 않은 문자열만 — `toStr` 처럼 숫자를 문자열로 바꾸지 않는다(쓸 수 없는 토큰이 된다). */
    private static function usableToken(#[\SensitiveParameter] mixed $v): ?string
    {
        return \is_string($v) && $v !== '' ? $v : null;
    }

    private static function toIntOrNull(mixed $v): ?int
    {
        return match (true) {
            \is_int($v) => $v,
            \is_float($v) => (int) $v,
            default => null,
        };
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
