<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\KeycloakConfig;

/**
 * SSRF 하드닝 — SDK가 **스스로 보내는** back-channel 요청(token·introspect·logout·admin REST)은
 * 3xx를 따라가면 안 된다.
 *
 * ⚠️ Guzzle은 두 진입점의 기본값이 다르다: PSR-18 `sendRequest()`는 미추종이지만
 * `request()`는 **추종한다**(`Client.php`가 `RedirectMiddleware::$defaultSettings`를 기본값으로
 * 넣는다). 이 SDK는 두 경로를 모두 쓰므로 `request()` 쪽이 뚫려 있었다 — 실측에서
 * `client_secret_basic` 헤더가 리다이렉트 대상 경로로 재전송됐고, `logout`은 302를 따라가
 * 무관한 200을 받고 **정상 반환**했다(호출자는 세션이 폐기됐다고 믿지만 살아 있다).
 *
 * ⚠️ OIDC authorization-code의 redirect_uri는 브라우저 front-channel 개념이라 무관하다.
 */
final class HttpOptionsTest extends TestCase
{
    public function testGuzzleOptionsDisableRedirects(): void
    {
        $config = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'r', clientId: 'c');
        $opts = HttpOptions::guzzle($config);

        self::assertArrayHasKey('allow_redirects', $opts);
        self::assertFalse($opts['allow_redirects'], 'back-channel 요청은 3xx를 따라가면 안 된다');
        // 기존 하드닝이 함께 살아 있어야 한다 — 옵션을 팩토리로 옮기며 잃어버리지 않았는지 확인.
        self::assertTrue($opts['verify'], 'TLS 검증은 계속 켜져 있어야 한다');
        self::assertSame($config->connectTimeout, $opts['connect_timeout']);
        self::assertSame($config->readTimeout, $opts['timeout']);
    }

    /**
     * 위 단언은 설정값만 본다. 이 테스트는 그 설정이 **실제로 리다이렉트를 막는지**를
     * 네트워크 없이 증명한다 — MockHandler에 [302, 200]을 넣어두고, 추종하면 큐가 비고
     * 추종하지 않으면 200이 큐에 남는다. 대조군이 없으면 "설정을 읽었다"만 증명하는 셈이다.
     */
    public function testConfiguredOptionsActuallyStopTheRedirect(): void
    {
        $config = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'r', clientId: 'c');
        $mock = new MockHandler([
            new Response(302, ['Location' => 'https://evil.internal/x']),
            new Response(200, [], 'FOLLOWED'),
        ]);
        $client = new GuzzleClient(HttpOptions::guzzle($config) + ['handler' => HandlerStack::create($mock)]);

        $res = $client->request('POST', 'https://kc:8080/realms/r/protocol/openid-connect/logout', [
            'http_errors' => false,
        ]);

        self::assertSame(302, $res->getStatusCode(), '302가 호출자에게 그대로 표면화되어야 한다');
        self::assertCount(1, $mock, '리다이렉트를 따라가지 않았으므로 큐의 200은 소비되지 않아야 한다');
    }
}
