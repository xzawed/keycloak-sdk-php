<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Http;

use Xzawed\Keycloak\KeycloakConfig;

/**
 * Common options for every Guzzle client the SDK creates. Two places (KeycloakClient · Admin\AdminClient) each held
 * the same array, and if even one hardening item drifts apart, only that path silently becomes vulnerable —
 * gathering them in one place removes that possibility and also lets tests inspect the SDK's settings directly.
 *
 * @internal Not a consumer API. It depends on the underlying library's option shape, so it is not kept as a public contract.
 */
final class HttpOptions
{
    /**
     * @return array<string, mixed>
     */
    public static function guzzle(KeycloakConfig $config): array
    {
        return [
            'connect_timeout' => $config->connectTimeout,
            'timeout' => $config->readTimeout,
            'verify' => true,
            'http_errors' => true,
            // SSRF 하드닝: back-channel 요청은 3xx를 따라가지 않는다.
            // ⚠️ Guzzle은 진입점마다 기본값이 다르다 — PSR-18 `sendRequest()`는 미추종이지만
            // `request()`는 **추종**한다(RedirectMiddleware::$defaultSettings). 이 SDK는 둘 다
            // 쓰므로 명시하지 않으면 `request()` 경로(introspect·logout·token 그랜트·admin REST)만
            // 뚫린다. 실측: `client_secret_basic` 헤더가 리다이렉트 대상으로 재전송됐고, logout은
            // 302를 따라간 뒤 **정상 반환**했다(세션이 살아 있는데 폐기됐다고 믿게 된다).
            // Java·Kotlin·Go·.NET·Rust·Ruby와 동형. authorization-code의 redirect_uri와는 무관하다.
            'allow_redirects' => false,
        ];
    }
}
