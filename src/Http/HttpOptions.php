<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Http;

use Xzawed\Keycloak\KeycloakConfig;

/**
 * SDK가 만드는 모든 Guzzle 클라이언트의 공통 옵션. 두 곳(KeycloakClient·Admin\AdminClient)이
 * 같은 배열을 각자 들고 있었는데, 하드닝 항목이 하나라도 어긋나면 그쪽 경로만 조용히 취약해진다 —
 * 한 곳으로 모아 그 가능성을 없애고, 동시에 테스트가 SDK의 설정을 직접 검사할 수 있게 한다.
 *
 * @internal 소비자용 API가 아니다. 하위 라이브러리 옵션 형태에 종속적이라 공개 계약으로 두지 않는다.
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
