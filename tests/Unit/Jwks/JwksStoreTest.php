<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Jwks;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface};
use GuzzleHttp\Psr7\{HttpFactory, Response};
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\TokenValidationError;

final class JwksStoreTest extends TestCase
{
    /** @param list<array<string,mixed>> $keys */
    private function http(array $keys, int &$calls): ClientInterface
    {
        return new class ($keys, $calls) implements ClientInterface {
            /** @param list<array<string,mixed>> $keys */
            public function __construct(private array $keys, public int &$calls) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(200, [], json_encode(['keys' => $this->keys], JSON_THROW_ON_ERROR));
            }
        };
    }

    public function testCacheHitNoNetworkAfterFirst(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $store = new JwksStore('http://kc/certs', $this->http([['kid' => 'k1', 'kty' => 'RSA']], $calls), $f);
        self::assertSame('k1', $store->getKeyByKid('k1')['kid']);
        self::assertSame('k1', $store->getKeyByKid('k1')['kid']);
        self::assertSame(1, $calls);   // 두 번째는 캐시
    }

    public function testUnresolvedKidRefetchesOnceThenRateLimited(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $store = new JwksStore('http://kc/certs', $this->http([['kid' => 'k1', 'kty' => 'RSA']], $calls), $f, minRefetchIntervalSeconds: 60);
        $store->getKeyByKid('k1');            // fetch #1
        try {
            $store->getKeyByKid('k2');
        } catch (TokenValidationError) {
            // unresolved → refetch #2
        }
        try {
            $store->getKeyByKid('k3');
        } catch (TokenValidationError) {
            // rate-limited → NO refetch
        }
        self::assertSame(2, $calls);          // 위조 kid 스팸이 IdP를 때리지 않음
    }

    public function testNetworkFailureMappedToTransportError(): void
    {
        $f = new HttpFactory();
        $http = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('connection failed') extends \RuntimeException implements ClientExceptionInterface {};
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        $this->expectException(KeycloakTransportError::class);
        $store->getKeyByKid('k1');
    }

    public function testUnknownKidAfterSuccessfulRefetchThrowsTokenValidationError(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        // JWKS never contains the requested kid, even after refetch.
        $store = new JwksStore('http://kc/certs', $this->http([['kid' => 'other', 'kty' => 'RSA']], $calls), $f, minRefetchIntervalSeconds: 0);
        $this->expectException(TokenValidationError::class);
        $store->getKeyByKid('missing');
    }

    public function testKeyRotationPickedUpAfterRefetch(): void
    {
        $f = new HttpFactory();
        // First fetch only has k1; a rotated JWKS (fetched on refetch) adds k2.
        $responses = [
            json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR),
            json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA'], ['kid' => 'k2', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR),
        ];
        $http = new class ($responses) implements ClientInterface {
            private int $call = 0;

            /** @param non-empty-list<string> $responses */
            public function __construct(private readonly array $responses) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $index = min($this->call, count($this->responses) - 1);
                $body = $this->responses[$index];
                $this->call++;
                return new Response(200, [], $body);
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f, minRefetchIntervalSeconds: 0);
        $store->getKeyByKid('k1');   // initial load
        self::assertSame('k2', $store->getKeyByKid('k2')['kid']);   // rotated key picked up via refetch
    }

    public function testInvalidJwksResponseShapeMappedToTransportError(): void
    {
        $f = new HttpFactory();
        $http = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                // 200 OK but missing the required "keys" field.
                return new Response(200, [], json_encode(['not_keys' => []], JSON_THROW_ON_ERROR));
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        $this->expectException(KeycloakTransportError::class);
        $store->getKeyByKid('k1');
    }

    public function testMalformedKeyEntrySkippedButValidEntryResolves(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $http = new class ($calls) implements ClientInterface {
            public function __construct(public int &$calls) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;
                // A non-array entry mixed in with a valid JWK — must be skipped, not crash.
                return new Response(200, [], json_encode(['keys' => ['not-an-object', ['kid' => 'k1', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR));
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        self::assertSame('k1', $store->getKeyByKid('k1')['kid']);
        self::assertSame(1, $calls);
    }

    public function testFetchFailureStillStampsRateLimitGate(): void
    {
        // 실패한 fetch(IdP 장애)도 rate-limit 게이트를 소모해야 한다. stamp-after-fetch면 fetch가
        // 예외로 죽어 lastRefetchAt이 갱신되지 않아, 위조 kid 스팸이 IdP를 무제한 때린다(미인증 DoS 증폭).
        // Rust/Go/Python/Ruby 동형: 재조회 *결정 시점*에 stamp한다.
        $calls = 0;
        $f = new HttpFactory();
        // 첫 fetch만 성공(k1), 이후는 전부 실패(장애창).
        $http = new class ($calls) implements ClientInterface {
            public function __construct(public int &$calls) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;
                if ($this->calls === 1) {
                    return new Response(200, [], json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR));
                }
                throw new class ('IdP down') extends \RuntimeException implements ClientExceptionInterface {};
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f, minRefetchIntervalSeconds: 60);
        $store->getKeyByKid('k1'); // fetch #1 (성공)
        // forged-1: 미해결 kid → 재조회 #2가 IdP 장애로 실패(transport error).
        try {
            $store->getKeyByKid('forged-1');
        } catch (\Throwable) {
        }
        // forged-2: 창 내 → rate-limited여야 한다(재조회 #3 없음). stamp-after-fetch면 재조회한다.
        try {
            $store->getKeyByKid('forged-2');
        } catch (\Throwable) {
        }
        self::assertSame(2, $calls, '실패한 fetch도 게이트를 소모 — forged-2는 재조회 없이 rate-limited');
    }
}
