<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * IdP 오류 응답의 `error` 값을 **OAuth 오류 코드일 때만** 받아들인다. @internal
 *
 * ⚠️ `error` 도 응답 본문이다 — 토큰을 되울리면 `KeycloakAuthError` 의 메시지와 공개 프로퍼티 `oauthError` 가
 * 그대로 찍었다(Grok 레그 실측 2026-09-26, `var_dump`·`print_r` 까지). RFC 6749·6750·8628·OIDC 와 Keycloak 의
 * 코드는 전부 소문자·밑줄이라(`invalid_grant`·`login_required`·`authorization_pending` …) 그 모양만 통과시킨다 —
 * JWT·base64url·hex 토큰은 대문자·숫자·`-`·`.` 를 품어 걸러진다. python 레그와 같은 모양이다.
 */
final class OAuthErrorCode
{
    public static function of(mixed $error): ?string
    {
        return \is_string($error) && preg_match('/^[a-z_]{1,64}$/', $error) === 1 ? $error : null;
    }
}
