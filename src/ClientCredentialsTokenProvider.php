<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Xzawed\Keycloak\Token\TokenSet;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;

final class ClientCredentialsTokenProvider implements TokenProvider
{
    private ?TokenSet $cached = null;

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly OidcEndpoints $endpoints,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function getToken(): string
    {
        if ($this->cached !== null && !$this->cached->isExpired(skew: $this->config->clockSkew)) {
            return $this->cached->accessToken;
        }
        $this->cached = $this->fetch();
        return $this->cached->accessToken;
    }

    private function fetch(): TokenSet
    {
        $body = http_build_query([
            'grant_type' => 'client_credentials',
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret ?? '',
            'scope' => implode(' ', $this->config->scopes),
        ]);
        $request = $this->requestFactory->createRequest('POST', $this->endpoints->token())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streamFactory->createStream($body));
        try {
            $response = $this->http->sendRequest($request);
        } catch (NetworkExceptionInterface $e) {
            throw new KeycloakTransportError('token endpoint unreachable', previous: $e);
        } catch (ClientExceptionInterface $e) {
            throw new KeycloakTransportError('token request failed', previous: $e);
        }
        $json = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || !is_array($json) || !isset($json['access_token'])) {
            $oauth = null;
            if (is_array($json) && isset($json['error']) && is_string($json['error'])) {
                $oauth = $json['error'];
            }
            throw new KeycloakAuthError('client-credentials failed', oauthError: $oauth);
        }
        return TokenSet::fromArray(self::stringKeyed($json));
    }

    /**
     * json_decode(..., true)의 배열은 키 타입이 array-key(int|string)로만 추론된다.
     * 신뢰된 OAuth 토큰 응답은 항상 문자열 키이므로 정수 키(있다면)를 걸러 string-keyed로 좁힌다.
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
