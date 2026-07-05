<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface, StreamInterface};
use GuzzleHttp\Psr7\{HttpFactory, Response};
use Xzawed\Keycloak\{KeycloakConfig, OidcEndpoints, ClientCredentialsTokenProvider};
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;

final class ClientCredentialsTokenProviderTest extends TestCase
{
    private function config(): KeycloakConfig
    {
        return new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', clientSecret: 's');
    }

    public function testFetchesAndCachesToken(): void
    {
        $calls = 0;
        $http = new class ($calls) implements ClientInterface {
            public function __construct(public int &$calls) {}
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(
                    200,
                    ['Content-Type' => 'application/json'],
                    json_encode(['access_token' => 'AT', 'token_type' => 'Bearer', 'expires_in' => 300], JSON_THROW_ON_ERROR),
                );
            }
        };
        $f = new HttpFactory();
        $p = new ClientCredentialsTokenProvider($this->config(), new OidcEndpoints($this->config()), $http, $f, $f);
        self::assertSame('AT', $p->getToken());
        self::assertSame('AT', $p->getToken());   // 캐시 재사용
        self::assertSame(1, $calls);              // 두 번째는 네트워크 없음
    }

    public function testOauthErrorMapped(): void
    {
        $http = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(
                    401,
                    ['Content-Type' => 'application/json'],
                    json_encode(['error' => 'invalid_client', 'error_description' => 'bad'], JSON_THROW_ON_ERROR),
                );
            }
        };
        $f = new HttpFactory();
        $p = new ClientCredentialsTokenProvider($this->config(), new OidcEndpoints($this->config()), $http, $f, $f);
        $this->expectException(KeycloakAuthError::class);
        $p->getToken();
    }

    public function testClientExceptionMappedToTransport(): void
    {
        $http = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('connection failed') extends \RuntimeException implements ClientExceptionInterface {};
            }
        };
        $f = new HttpFactory();
        $p = new ClientCredentialsTokenProvider($this->config(), new OidcEndpoints($this->config()), $http, $f, $f);
        $this->expectException(KeycloakTransportError::class);
        $p->getToken();
    }

    public function testNetworkExceptionMappedToTransport(): void
    {
        $http = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('unreachable', $request) extends \RuntimeException implements NetworkExceptionInterface {
                    public function __construct(string $message, private readonly RequestInterface $request)
                    {
                        parent::__construct($message);
                    }
                    public function getRequest(): RequestInterface
                    {
                        return $this->request;
                    }
                };
            }
        };
        $f = new HttpFactory();
        $p = new ClientCredentialsTokenProvider($this->config(), new OidcEndpoints($this->config()), $http, $f, $f);
        $this->expectException(KeycloakTransportError::class);
        $p->getToken();
    }
}
