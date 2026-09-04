<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Jwks;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface};
use GuzzleHttp\Psr7\{HttpFactory, Response};
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Jwks\FailureBackoff;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\TokenValidationError;

/** 프로브가 IdP 도달 횟수를 **메서드로** 읽게 하는 이음매(참조 카운터를 쓰면 phpstan 이 좁힌다). */
interface CallCounting
{
    public function callCount(): int;
}

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

    /**
     * ⚠️ **2차 정의 자리 금지**(Task D1). `JwksStore`는 `final class`에 public 생성자라 소비자가
     * 파사드를 거치지 않고 직접 생성할 수 있다. 예전에는 그 경로의 기본값이 60이라 config·문서가
     * 말하는 30과 어긋났다. 이 테스트는 "생략했을 때의 값"을 config 상수에 고정한다 — 리터럴을
     * 다시 적으면 실패한다.
     */
    public function testOmittedMinRefetchUsesConfigDefault(): void
    {
        $f = new HttpFactory();
        $calls = 0;
        $store = new JwksStore('http://kc/certs', $this->http([['kid' => 'k1', 'kty' => 'RSA']], $calls), $f);
        $ref = new \ReflectionProperty($store, 'minRefetchIntervalSeconds');
        self::assertSame(KeycloakConfig::DEFAULT_JWKS_MIN_REFETCH_SECONDS, $ref->getValue($store));
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

    // ⚠️ 여기부터가 콜드 캐시 + IdP 장애 축이다. 위 30초 게이트는 *캐시가 찬 뒤*에만 걸린다 —
    // 캐시가 비어 있고 fetch 가 계속 실패하면 그 게이트에 닿지도 못한다. 실측(2026-09-04):
    // 20회 조회 → IdP 요청 **20건**, 7개 언어 동일.

    /**
     * 항상 503 을 내는 클라이언트.
     *
     * ⚠️ 카운터를 참조 인자(`int &$calls`)로 노출하지 않고 **메서드**로 읽는다 — phpstan 은 지역
     * 스칼라를 좁혀서, 같은 변수에 대한 두 번째 `assertSame` 을 「항상 참/항상 거짓」으로 판정한다
     * (실측: `staticMethod.alreadyNarrowedType` + `impossibleType`). 이 부류의 테스트는 창 안과
     * 창 밖에서 **각각** 세어야 하므로 참조 카운터로는 쓸 수 없다.
     */
    private function failingHttp(): ClientInterface&CallCounting
    {
        return new class () implements ClientInterface, CallCounting {
            private int $calls = 0;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;

                return new Response(503, [], '{"error":"service unavailable"}');
            }

            public function callCount(): int
            {
                return $this->calls;
            }
        };
    }

    public function testColdCacheFailingIdpCollapsesToOneRequest(): void
    {
        $http = $this->failingHttp();
        $store = new JwksStore('http://kc/certs', $http, new HttpFactory(), minRefetchIntervalSeconds: 30);

        for ($i = 0; $i < 20; $i++) {
            try {
                $store->getKeyByKid('k1');
                self::fail('IdP 가 죽어 있는 동안 조회가 성공해서는 안 된다');
            } catch (KeycloakTransportError) {
            }
        }

        self::assertSame(1, $http->callCount(), '콜드 캐시 + IdP 장애: 20회 조회가 요청 1건이어야 한다');
    }

    /**
     * ⚠️ 대조군 — IdP 가 복구되면 다시 나가야 한다. 「한 번 실패하면 영원히 차단」은 원래 결함보다
     * 나쁘고, 위 단언만으로는 그것도 통과한다. 창 만료 자체는 `FailureBackoffTest` 가 시계를
     * 주입해 재고, 여기서는 **성공이 스토어의 백오프를 실제로 되돌리는가**(배선)를 본다.
     */
    public function testRecoveredIdpResetsTheBackoff(): void
    {
        $http = new class () implements ClientInterface, CallCounting {
            private int $calls = 0;
            public bool $down = true;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;
                if ($this->down) {
                    return new Response(503, [], '{"error":"down"}');
                }

                return new Response(200, [], json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR));
            }

            public function callCount(): int
            {
                return $this->calls;
            }
        };
        $store = new JwksStore('http://kc/certs', $http, new HttpFactory(), minRefetchIntervalSeconds: 30);

        try {
            $store->getKeyByKid('k1');
            self::fail('IdP 가 죽어 있는 동안 조회가 성공해서는 안 된다');
        } catch (KeycloakTransportError) {
        }
        $backoff = (new \ReflectionProperty($store, 'backoff'))->getValue($store);
        self::assertInstanceOf(FailureBackoff::class, $backoff);
        self::assertSame(1, $backoff->failures(), '실패한 fetch 는 카운터를 올려야 한다');

        // 창을 넘긴다(상한 5초보다 크게) — sleep 대신 백오프의 시계를 지나가게 만든다.
        $http->down = false;
        (new \ReflectionProperty($backoff, 'lastFailureAt'))->setValue($backoff, null);
        self::assertSame('k1', $store->getKeyByKid('k1')['kid']);
        self::assertSame(0, $backoff->failures(), '성공은 카운터를 0으로 되돌려야 한다');
        self::assertSame(2, $http->callCount());
    }
}
