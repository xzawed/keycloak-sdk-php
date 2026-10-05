<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Exception\BuilderException;
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
use Xzawed\Keycloak\Internal\OAuthErrorCode;
use Xzawed\Keycloak\Internal\TokenResponseCap;

/**
 * fschmtt는 Guzzle 예외를 변환하지 않으므로(404/409/403 전부 raw ClientException) 경계에서 여기로 변환한다.
 *
 * ⚠️ 하위 예외는 원본이 아니라 `SanitizedCause` 사본으로 달고, 메시지는 여기서 만든다(`AuthClient` 와 같은 규칙 — 근거는
 * `SanitizedCause` 의 docblock). 원본을 달면 admin 의 토큰 부여(fschmtt 가 한다)나 admin 요청이 실패할 때 Guzzle 메시지의
 * 응답 본문 요약과 하위 프레임의 인자 — 토큰 응답 본문·`client_secret` 폼·`Bearer` 헤더·보낸 representation — 가
 * `getMessage()`·`(string)$e`·`var_dump`·`print_r` 로 찍혔다(실측 2026-10-02). 남기는 것: 타입 · HTTP 상태(`getStatusCode()`) ·
 * 토큰 부여 오류의 OAuth `error` 코드(`OAuthErrorCode` 모양일 때만). 파사드가 보내는 입력(representation·검색 조건)은 각
 * 자원 메서드가 `#[\SensitiveParameter]` 로 가린다 — 경로로 가는 식별자는 원인의 URL 처럼 남는다.
 */
final class ErrorTranslation
{
    /**
     * fschmtt 가 admin 토큰을 받는 자리 — `{base}/realms/{realm}` 뒤의 꼬리. ⚠️ 꼬리만으로는 못 가른다 — 경로로 가는 식별자가
     * admin REST 경로도 이것으로 끝나게 만든다(fschmtt 는 경로 값을 인코딩하지 않는다). 가르는 것은 Bearer 다(`failed()`).
     * `AdminClient` 의 토큰 응답 상한도 같은 규칙으로 토큰 부여를 고른다.
     */
    public const TOKEN_PATH = '/protocol/openid-connect/token';

    /** OAuth 오류 응답은 작다 — 이보다 긴 본문에서는 코드를 찾지 않는다(적대적 IdP 의 큰 본문을 통째로 디코드하지 않는다). */
    private const MAX_ERROR_BODY = 8192;

    /**
     * ⚠️ `$fn` 은 보내는 representation(비밀번호·client secret)을 붙잡은 클로저다 — SDK 예외 트레이스의 #0 프레임 인자다.
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function call(#[\SensitiveParameter] callable $fn): mixed
    {
        try {
            return $fn();
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
                // admin 의 토큰 응답이 상한을 넘었다(`AdminClient` 의 미들웨어) — 토큰 부여에서 끝나 admin REST 요청은 나가지 않았다.
                // 메시지는 그 미들웨어가 만든 상한 문구다. ⚠️ 원인을 달지 않는다 — 그 예외의 트레이스는 Guzzle `request()` 의
                // `form_params`(client_secret) 프레임 인자를 쥔다.
                throw new KeycloakTransportError($e->getMessage());
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
