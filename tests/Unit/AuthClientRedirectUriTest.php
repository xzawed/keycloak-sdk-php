<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * 인가요청·토큰교환의 `redirect_uri`를 **호출당** 받는가 — 나머지 여덟 SDK와 동형.
 *
 * 왜 필요한가: 콜백 URL이 여럿인 앱(멀티테넌트·환경별 콜백)은 클라이언트 하나로 그것을
 * 섬길 수 있어야 한다. php와 rust만 생성 시 config 값에 묶여 있어 **클라이언트를 다시
 * 만들어야** 했고, 하네스 conformance가 그 비대칭을 php 25/26으로 내고 있었다.
 *
 * ⚠️ **둘을 함께 봐야 한다.** OAuth는 토큰 교환의 `redirect_uri`가 인가 때 쓴 값과 **같기를**
 * 요구한다(RFC 6749 §4.1.3). 인가 URL만 고치면 교환이 config 값을 보내 Keycloak이 거부한다.
 */
final class AuthClientRedirectUriTest extends TestCase
{
    private const CONFIG_URI = 'https://app/cb';
    private const PER_CALL_URI = 'https://tenant-b.app/callback';

    /** 토큰 엔드포인트로 실제로 나간 요청 — 아래 핸들러가 채운다. */
    private ?RequestInterface $sent = null;

    public function testAuthorizationUrlUsesPerCallRedirectUri(): void
    {
        $req = $this->auth()->createAuthorizationRequest(self::PER_CALL_URI);
        self::assertSame(self::PER_CALL_URI, $this->queryParam($req->url, 'redirect_uri'));
    }

    /** 인자를 안 주면 config 값 — 기존 소비자가 그대로 돈다(가산적 변경). */
    public function testAuthorizationUrlFallsBackToConfigRedirectUri(): void
    {
        $req = $this->auth()->createAuthorizationRequest();
        self::assertSame(self::CONFIG_URI, $this->queryParam($req->url, 'redirect_uri'));
    }

    public function testExchangeCodeSendsPerCallRedirectUri(): void
    {
        $this->auth()->exchangeCode('the-code', 'the-verifier', null, self::PER_CALL_URI);
        self::assertSame(self::PER_CALL_URI, $this->bodyParam('redirect_uri'));
    }

    public function testExchangeCodeFallsBackToConfigRedirectUri(): void
    {
        $this->auth()->exchangeCode('the-code', 'the-verifier');
        self::assertSame(self::CONFIG_URI, $this->bodyParam('redirect_uri'));
    }

    private function queryParam(string $url, string $name): string
    {
        $qs = parse_url($url, PHP_URL_QUERY);
        self::assertIsString($qs);
        parse_str($qs, $params);
        self::assertArrayHasKey($name, $params);
        self::assertIsString($params[$name]);

        return $params[$name];
    }

    private function bodyParam(string $name): string
    {
        self::assertInstanceOf(RequestInterface::class, $this->sent, '토큰 요청이 나가지 않았다');
        parse_str((string) $this->sent->getBody(), $params);
        self::assertArrayHasKey($name, $params, '토큰 요청 본문에 ' . $name . ' 이 없다');
        self::assertIsString($params[$name]);

        return $params[$name];
    }

    /**
     * ⚠️ Guzzle의 history 미들웨어를 쓰지 않는다 — 그 컨테이너 타입이 `array|ArrayAccess<int, array>`
     * 라 by-ref로도 `ArrayObject`로도 phpstan(level max + strict)을 통과시키기 어렵다.
     * 요청을 그대로 잡는 핸들러가 타입이 정확하고 읽기도 쉽다.
     */
    private function auth(): AuthClient
    {
        $cfg = new KeycloakConfig(
            serverUrl: 'https://kc:8080',
            realm: 'it-realm',
            clientId: 'it-client',
            clientSecret: 's',
            redirectUri: self::CONFIG_URI,
        );
        $endpoints = new OidcEndpoints($cfg);
        $capture = function (RequestInterface $request): object {
            $this->sent = $request;

            return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 60,
            ], JSON_THROW_ON_ERROR)));
        };
        $tokenHttp = new Client(['handler' => HandlerStack::create($capture)]);

        $jwksHttp = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                throw new \RuntimeException('JWKS must not be fetched here');
            }
        };
        $validator = new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $jwksHttp, new HttpFactory()));

        return new AuthClient($cfg, $endpoints, $validator, $tokenHttp);
    }
}
