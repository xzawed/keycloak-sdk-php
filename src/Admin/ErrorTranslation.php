<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Exception\BuilderException;
use Fschmtt\Keycloak\Exception\VersionDetectionException;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Message;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakConfigError;
use Xzawed\Keycloak\Exception\KeycloakConflictError;
use Xzawed\Keycloak\Exception\KeycloakException;
use Xzawed\Keycloak\Exception\KeycloakForbiddenError;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\SanitizedCause;
use Xzawed\Keycloak\Internal\BearerToken;
use Xzawed\Keycloak\Internal\OAuthErrorCode;
use Xzawed\Keycloak\Internal\TokenResponseCap;

/**
 * fschmtt does not translate Guzzle exceptions (404/409/403 are all a raw ClientException), so they are translated here,
 * at the boundary.
 *
 * ⚠️ The underlying exception is attached not as the original but as a `SanitizedCause` copy, and the message is built here
 * (the same rule as `AuthClient` — the rationale is in `SanitizedCause`'s docblock). With the original attached, when admin's
 * token grant (fschmtt performs it) or an admin request failed, the response-body summary in Guzzle's message and the
 * arguments of the underlying frames — the token response body, the `client_secret` form, the `Bearer` header, the
 * representation sent — were printed through `getMessage()` · `(string)$e` · `var_dump` · `print_r` (measured 2026-10-02).
 * What is kept: the type · the HTTP status (`getStatusCode()`) · the OAuth `error` code of a token-grant error (only when
 * it has the `OAuthErrorCode` shape). The input the facade sends (representations, search criteria) is hidden by each
 * resource method with `#[\SensitiveParameter]` — identifiers that go into the path remain visible, as the cause's URL does.
 *
 * ⚠️ fschmtt 0.44 wraps **every** failure of the version detection it runs first on each resource access made before the
 * version is known (`GET /admin/serverinfo` — the first admin token grant happens there) in a
 * `VersionDetectionException` and attaches it as the cause (`Keycloak::fetchVersion`). While wrapped, a token-grant 401,
 * a transport failure and a cap rejection fell through to the bottom net (#750: "admin request failed unexpectedly",
 * status null). So the cause is taken out and thrown down the same ladder again —
 * it is the very object 0.43 threw as is, so the type, status, message and cause copy are the same. Without a cause (a
 * serverinfo that hides systemInfo) the wrapper goes to the net as it is — in 0.43 the `\Error` raised by a call on null
 * went to the same net (the two serverinfo cells of `AdminFacadeErrorLeakTest`).
 */
final class ErrorTranslation
{
    /**
     * Where fschmtt gets the admin token — the tail after `{base}/realms/{realm}`. ⚠️ The tail alone cannot tell them apart —
     * an identifier that goes into the path can make an admin REST path end with this too (fschmtt does not encode path
     * values). What tells them apart is the Bearer (`failed()`). The token response cap in `AdminClient` also picks out the
     * token grant by the same rule.
     */
    public const TOKEN_PATH = '/protocol/openid-connect/token';

    /** OAuth 오류 응답은 작다 — 이보다 긴 본문에서는 코드를 찾지 않는다(적대적 IdP 의 큰 본문을 통째로 디코드하지 않는다). */
    private const MAX_ERROR_BODY = 8192;

    /**
     * ⚠️ `$fn` is a closure that captures the representation being sent (password, client secret) — it is an argument of
     * the #0 frame in the SDK exception's trace.
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function call(#[\SensitiveParameter] callable $fn): mixed
    {
        try {
            try {
                return $fn();
            } catch (VersionDetectionException $e) {
                throw $e->getPrevious() ?? $e;   // fschmtt 0.44 의 감싸기를 벗긴다 — 클래스 docblock.
            }
        } catch (ClientException $e) {
            $status = $e->getResponse()->getStatusCode();
            $message = self::failed($e);
            $cause = SanitizedCause::of($e);
            throw match ($status) {
                404 => new KeycloakNotFoundError($message, 404, $cause),
                409 => new KeycloakConflictError($message, 409, $cause),
                403 => new KeycloakForbiddenError($message, 403, $cause),
                default => new KeycloakAdminError($message, $status, $cause),
            };
        } catch (ServerException $e) {
            throw new KeycloakAdminError(self::failed($e), $e->getResponse()->getStatusCode(), SanitizedCause::of($e));
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('admin request unreachable', previous: SanitizedCause::of($e));
        } catch (RequestException $e) {
            if (TokenResponseCap::isRejection($e)) {
                // admin 의 토큰 응답이 상한을 넘었거나 끝을 알리기 전에 막혔다(`AdminClient` 의 미들웨어) — 토큰 부여에서 끝나 admin
                // REST 요청은 나가지 않았다. 메시지는 그 미들웨어가 만든 문구다. ⚠️ 원인을 달지 않는다 — 그 예외의 트레이스는 Guzzle `request()` 의
                // `form_params`(client_secret) 프레임 인자를 쥔다.
                throw new KeycloakTransportError($e->getMessage());
            }
            if (BearerToken::isRejection($e)) {
                // admin 의 토큰 부여가 Bearer 문법 밖의 access token 을 줬다(`AdminClient` 의 미들웨어) — fschmtt 가 받아 두기 전에 거부해
                // 캐시되지 않았고 admin REST 요청은 나가지 않았다. 타입은 쓸 수 없는 부여가 내던 것(상태 없는 `KeycloakAdminError`)이다.
                // ⚠️ 원인을 달지 않는다 — 위와 같은 이유.
                throw new KeycloakAdminError($e->getMessage());
            }
            throw new KeycloakTransportError('admin request failed', previous: SanitizedCause::of($e));
        } catch (BuilderException $e) {
            // fschmtt Builder 의 고정 문구 둘(`Base URL is not set`·`Grant type is not set`) — 네트워크 앞이라 응답·토큰이 없다.
            throw new KeycloakConfigError($e->getMessage(), previous: SanitizedCause::of($e));
        } catch (KeycloakException $e) {
            throw $e;   // 우리 자신의 SDK 예외 — 재래핑하지 않는다.
        } catch (\Throwable $e) {
            // fschmtt SerializerException(역직렬화 실패)·토큰 응답 파싱 실패(JsonException·lcobucci 예외·TypeError) 및 그 밖의
            // 미분류 하위 라이브러리 예외를 전부 여기로 수렴시켜 admin 파사드 밖으로 새지 않게 한다(JwtValidator의 \Throwable net과
            // 동형). ⚠️ 메시지는 옮기지 않는다 — 감사하지 않은 라이브러리가 만든 것이다(원본 클래스명은 원인에 남는다).
            throw new KeycloakAdminError('admin request failed unexpectedly', null, SanitizedCause::of($e));
        }
    }

    /** HTTP 오류 응답의 메시지 — 상태만, admin 의 토큰 부여면 코드 모양의 OAuth `error` 도. 본문의 나머지는 싣지 않는다. */
    private static function failed(BadResponseException $e): string
    {
        $status = $e->getResponse()->getStatusCode();
        $request = $e->getRequest();
        // admin 의 토큰 부여는 Bearer 없이 나가는 요청 하나뿐이다(fschmtt `Client::fetchTokens`) — admin 요청은 전부 Bearer 를
        // 싣는다. 꼬리만 보면 `users()->get('x/protocol/openid-connect/token')` 이 admin 오류 본문의 코드 모양 `error` 를 실었다.
        if ($request->hasHeader('Authorization') || !str_ends_with($request->getUri()->getPath(), self::TOKEN_PATH)) {
            return "admin request failed: HTTP $status";
        }
        try {
            // 감사한 하위 라이브러리(psr7)의 요약 — 시크·되감기를 맡고, 상한을 넘으면 꼬리표가 붙어 JSON 이 아니게 된다.
            $error = json_decode(Message::bodySummary($e->getResponse(), self::MAX_ERROR_BODY) ?? '', true);
        } catch (\Throwable) {
            $error = null;   // 읽을 수 없는 본문 — 코드 없이 상태만 싣는다(읽기 오류가 경계를 넘지 않게).
        }
        $code = OAuthErrorCode::of(\is_array($error) ? ($error['error'] ?? null) : null);

        return "admin token request failed: HTTP $status" . ($code === null ? '' : " ($code)");
    }
}
