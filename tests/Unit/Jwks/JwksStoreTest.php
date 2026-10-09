<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Jwks;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface, StreamInterface};
use GuzzleHttp\Psr7\{FnStream, HttpFactory, Response, Utils};
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Jwks\FailureBackoff;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\OidcEndpoints;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\SanitizedCause;
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

    /**
     * ⚠️ **크기 상한 축.** go·rust·java·kotlin 은 51200(Nimbus `RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT`)
     * 을 가지고 있었고 php 만 없었다. 게다가 php 는 상태 검사보다 **먼저** `(string) getBody()` 로
     * 본문을 통째로 슬러프했다 — 500 의 거대 본문도 그대로 메모리에 올렸다.
     */
    public function testOversizedJwksBodyRejected(): void
    {
        $f = new HttpFactory();
        $big = str_repeat('x', JwksStore::JWKS_MAX_BYTES + 1);
        $http = new class ($big) implements ClientInterface {
            public function __construct(private string $big) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(200, [], $this->big);
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        $this->expectException(KeycloakTransportError::class);
        $this->expectExceptionMessageMatches('/exceeds/');
        $store->getKeyByKid('k1');
    }

    /** ⚠️ **대조군을 지우지 말 것** — 위 단언만 두면 「어떤 본문이든 거부한다」로도 통과한다. */
    public function testUnderSizedJwksBodyStillResolves(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $store = new JwksStore('http://kc/certs', $this->http([['kid' => 'k1', 'kty' => 'RSA']], $calls), $f);
        self::assertSame('k1', $store->getKeyByKid('k1')['kid']);
    }

    /**
     * ⚠️ 상한은 **상태와 무관하게** 걸려야 한다. 200 만 겨누면 오류 응답의 거대 본문이 그대로
     * 들어온다 — 그게 수정 전 php 의 순서였다.
     */
    public function testOversizedErrorResponseBodyAlsoRejected(): void
    {
        $f = new HttpFactory();
        $big = str_repeat('x', JwksStore::JWKS_MAX_BYTES + 1);
        $http = new class ($big) implements ClientInterface {
            public function __construct(private string $big) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(500, [], $this->big);
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        $this->expectException(KeycloakTransportError::class);
        $store->getKeyByKid('k1');
    }

    /**
     * ⚠️ **예외를 던지는 것만으로는 「슬러프하지 않는다」의 증거가 못 된다** — 다 읽고 나서
     * 길이를 재도 그 단언은 참이다. 스트림이 실제로 생산한 바이트를 세어, 상한 + 청크 하나
     * 안에서 읽기가 끊겼음을 본다.
     */
    public function testOversizedBodyIsNotFullySlurped(): void
    {
        $f = new HttpFactory();
        $produced = 0;
        // 상한의 100 배를 흘리는 스트림. 끊지 않으면 5MB 를 전부 생산한다.
        $stream = new \GuzzleHttp\Psr7\PumpStream(
            function (int $length) use (&$produced): string {
                $produced += $length;
                return str_repeat('x', $length);
            },
            ['size' => JwksStore::JWKS_MAX_BYTES * 100],
        );
        $http = new class ($stream) implements ClientInterface {
            public function __construct(private \Psr\Http\Message\StreamInterface $stream) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(200, [], $this->stream);
            }
        };
        $store = new JwksStore('http://kc/certs', $http, $f);
        try {
            $store->getKeyByKid('k1');
            self::fail('oversized body should have been rejected');
        } catch (KeycloakTransportError) {
            // expected
        }
        self::assertLessThanOrEqual(
            JwksStore::JWKS_MAX_BYTES + JwksStore::JWKS_READ_CHUNK_BYTES,
            $produced,
            'read must abort at the cap, not after slurping the whole stream',
        );
    }

    /** 주어진 본문 하나를 200 으로 돌려주는 클라이언트. */
    private static function serving(StreamInterface $body): ClientInterface
    {
        return new class ($body) implements ClientInterface {
            public function __construct(private readonly StreamInterface $body) {}

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(200, ['Content-Type' => 'application/json'], $this->body);
            }
        };
    }

    /** 조회 한 번의 결과 — 받아들였으면 `kid <kid>`, 아니면 `<예외 클래스>: <메시지>`. */
    private static function outcome(JwksStore $store): string
    {
        try {
            $kid = $store->getKeyByKid('k1')['kid'] ?? null;

            return 'kid ' . (is_string($kid) ? $kid : '?');
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
    }

    /** kid `k1` 하나를 담은 JWKS 를 JSON 공백으로 `$size` 바이트에 맞춘다 — 상한 근처에서도 받아들일 수 있는 문서다. */
    private static function document(int $size): string
    {
        $doc = '{"keys":[{"kid":"k1","kty":"RSA"}]}';

        return $doc . str_repeat(' ', $size - strlen($doc));
    }

    /**
     * 판독기가 스트림에서 **가져오는** 바이트는 많아야 상한+1 이고(넘었음을 아는 한 바이트까지), 한 번의 청은 많아야
     * min(청크, 상한+1 − 이미 가져온 바이트)다 — `TokenResponseCap::read` 와 같은 꼴이다. 수정 전에는 청을 8,192 바이트로 고정해
     * 3×상한 본문에서 57,344 바이트(상한 +6,144)를 가져갔고, 남은 자리가 2,049 바이트일 때도 8,192 바이트를 청했다(실측 2026-10-09).
     *
     * 상한 이하인 문서는 전과 같이 받아들인다(⚠️ 받아들이는 문서 집합을 바꾸지 않는다). 청한 만큼 주는 스트림 · 한 번에 1 바이트씩
     * 주는 스트림 · 상한 −16 까지 주고 그 뒤로 1 바이트씩 주는 스트림(청이 남은 자리까지 줄어드는지)을 함께 돈다.
     * ⚠️ 청한 바이트의 **합**은 묶이지 않는다 — 적게 주는 스트림이면 다시 청한다. 묶이는 것은 가져온 바이트와 한 번의 청이다.
     */
    public function testTheReaderTakesAtMostTheCapPlusOneAndEachRequestFitsTheRoomLeft(): void
    {
        $cap = JwksStore::JWKS_MAX_BYTES;
        $exceeds = KeycloakTransportError::class . ": JWKS response exceeds $cap bytes";
        // 스트림이 한 번에 주는 바이트 — (청한 바이트, 이미 내준 바이트) → 줄 바이트
        $asAsked = static fn (int $asked, int $taken): int => $asked;
        $oneByte = static fn (int $asked, int $taken): int => min(1, $asked);
        $oneByteNearTheCap = static fn (int $asked, int $taken): int => $taken >= $cap - 16 ? min(1, $asked) : min($asked, $cap - 16 - $taken);
        /** @var array<string, array{string, \Closure(int, int): int, string}> 칸 => [본문, 주는 규칙, 기대 결과] */
        $cases = [
            'as asked, cap' => [self::document($cap), $asAsked, 'kid k1'],
            'as asked, cap+1' => [self::document($cap + 1), $asAsked, $exceeds],
            'as asked, 3×cap' => [self::document(3 * $cap), $asAsked, $exceeds],
            'as asked, 100' => [self::document(100), $asAsked, 'kid k1'],
            '1 byte per read, 2,048' => [self::document(2048), $oneByte, 'kid k1'],
            '1 byte per read from cap−16, cap' => [self::document($cap), $oneByteNearTheCap, 'kid k1'],
            '1 byte per read from cap−16, cap+1' => [self::document($cap + 1), $oneByteNearTheCap, $exceeds],
            '1 byte per read from cap−16, 3×cap' => [self::document(3 * $cap), $oneByteNearTheCap, $exceeds],
        ];
        foreach ($cases as $name => [$content, $give, $want]) {
            $taken = 0;
            $reads = 0;
            $tooBig = [];
            $inner = Utils::streamFor($content);
            $spy = FnStream::decorate($inner, [
                'read' => static function (int $length) use ($inner, $give, $cap, &$taken, &$reads, &$tooBig): string {
                    $room = min(JwksStore::JWKS_READ_CHUNK_BYTES, $cap + 1 - $taken);
                    if ($length > $room) {
                        $tooBig[] = "청 $length > 남은 자리 $room (가져간 $taken)";
                    }
                    $reads++;
                    $got = $inner->read($give($length, $taken));
                    $taken += strlen($got);

                    return $got;
                },
            ]);
            $store = new JwksStore('http://kc/certs', self::serving($spy), new HttpFactory());
            self::assertSame($want, self::outcome($store), "$name: 결과");
            self::assertLessThanOrEqual($cap + 1, $taken, "$name: 스트림에서 가져온 바이트");
            self::assertSame([], array_slice($tooBig, 0, 3), "$name: 한 번의 청이 min(청크, 상한+1 − 가져온 바이트) 를 넘었다");
            if ($give === $oneByte) {
                self::assertGreaterThan(2048, $reads, "$name: 1 바이트씩 읽히지 않았다(공허)");
            }
        }
    }

    /**
     * 끝(EOF)이 아닌 빈 읽기에서 멈추고 실패한다 — EOF 를 알리지 않는 본문(막힌 논블로킹 소켓 · 소비자가 주입한 PSR-18 클라이언트의
     * 지연 본문)에서 `eof()` 만 기다리며 돌지 않는다. 수정 전 실측(2026-10-09): 합성 스트림에서 20 만 번 읽어도 멈추지 않았고(70 ms),
     * Guzzle `stream => true` 본문을 논블로킹으로 둔 소켓에서는 서버가 연결을 닫을 때까지 3.04 초 동안 빈 읽기 1,651,136 번을 돌았다.
     *
     * ⚠️ 실패로 닫는다 — 그때까지 읽은 바이트로 판정하지 않는다(`TokenResponseCap::read` 도 같다). 그렇게 판정하면 끝을 보지 못한 본문의
     * 앞부분이 받아들여진다: 60,000 바이트 문서가 40,960 바이트에서 한 번 막혔다가 이어지면 예전 판독기는 (돈 끝에) 상한 초과였는데 앞부분
     * 판정은 `kid k1` 을 받아들였다(Grok 레그가 찾고 실측). 끝을 찾은 빈 읽기 — PHP 소켓은 그 읽기 뒤에야 `feof()` 가 참이다 — 는 정상
     * 끝이다. 그래서 받아들이는 문서는 예전에 받아들이던 것의 부분집합이다.
     */
    public function testAnEmptyReadThatIsNotTheEndFailsInsteadOfSpinning(): void
    {
        $doc = self::document(64);
        $stalled = KeycloakTransportError::class . ': JWKS response stalled before its end';
        /** @var array<string, array{string, ?int, bool, string}> 칸 => [본문, 막히는 바이트(null = 막히지 않음), 막힘이 계속되는가, 기대 결과] */
        $cases = [
            'nothing, then stalls' => [$doc, 0, true, $stalled],
            'half a document, then stalls' => [$doc, 9, true, $stalled],
            'the whole document, then stalls' => [$doc, strlen($doc), true, $stalled],
            'a 60,000-byte document stalls once at 40,000, then goes on' => [self::document(60000), 40000, false, $stalled],
            'the whole document, then the empty read that finds its end' => [$doc, null, false, 'kid k1'],
        ];
        foreach ($cases as $name => [$content, $stallAt, $forever, $want]) {
            $reads = 0;
            $empties = 0;
            $ended = false;
            $stalledOnce = false;
            $inner = Utils::streamFor($content);
            $spy = FnStream::decorate($inner, [
                'read' => static function (int $length) use ($inner, $stallAt, $forever, &$reads, &$empties, &$ended, &$stalledOnce): string {
                    if (++$reads > 1000) {
                        throw new \LogicException('1,000 번을 읽고도 멈추지 않았다');   // 수정 전 판독기를 끝내는 안전핀
                    }
                    $at = $inner->tell();
                    if ($stallAt !== null && $at >= $stallAt && ($forever || !$stalledOnce)) {
                        $stalledOnce = true;
                        $empties++;

                        return '';   // 막혔다 — 줄 것이 없는데 끝도 아니다
                    }
                    $got = $inner->read($stallAt !== null && $at < $stallAt ? min($length, $stallAt - $at) : $length);
                    if ($got === '') {
                        $empties++;
                        $ended = true;   // 끝을 찾은 빈 읽기 — 이 뒤로 eof() 가 참이다
                    }

                    return $got;
                },
                'eof' => static function () use (&$ended): bool {
                    return $ended;   // 끝을 찾은 빈 읽기 전에는 EOF 를 알리지 않는다
                },
            ]);
            $store = new JwksStore('http://kc/certs', self::serving($spy), new HttpFactory());
            self::assertSame($want, self::outcome($store), "$name: 결과");
            self::assertSame(1, $empties, "$name: 빈 읽기는 한 번이면 끝나야 한다");
        }
    }

    /**
     * 본문을 읽다 난 오류도 SDK 오류다 — 수정 전에는 하위 `\RuntimeException` 이 `getKeyByKid()` 와 공개 경계
     * `JwtValidator::validate()` 밖으로 그대로 나갔다(§4 · 실측 2026-10-09: Guzzle `stream => true` 본문을 막힌 소켓에서 읽으면
     * psr7 의 `Unable to read from stream`). 다른 레인의 `… response could not be read` 와 같은 꼴이고 원인은 정화된 사본이다.
     */
    public function testABodyThatFailsToReadIsATransportErrorAtTheValidatorBoundary(): void
    {
        $failing = static function (): FnStream {
            $fail = static fn (): never => throw new \RuntimeException('tc read failure');

            return new FnStream([
                '__toString' => $fail, 'getContents' => $fail, 'read' => $fail, 'eof' => static fn (): bool => false,
                'isSeekable' => static fn (): bool => false, 'isReadable' => static fn (): bool => true, 'getSize' => static fn (): ?int => null,
                'close' => static fn (): null => null, 'getMetadata' => static fn (): mixed => null,
            ]);
        };
        $cfg = new KeycloakConfig('https://kc.test', 'r', 'c', 'tc-client-secret');
        $ep = new OidcEndpoints($cfg);
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        $jwt = $b64('{"alg":"RS256","kid":"k1"}') . '.' . $b64('{"sub":"u1"}') . '.' . $b64('sig');
        $calls = [
            'getKeyByKid' => static fn (): mixed => (new JwksStore($ep->jwks(), self::serving($failing()), new HttpFactory()))->getKeyByKid('k1'),
            'validate' => static fn (): mixed => (new JwtValidator($cfg, $ep, new JwksStore($ep->jwks(), self::serving($failing()), new HttpFactory())))->validate($jwt),
        ];
        foreach ($calls as $name => $call) {
            try {
                $call();
                self::fail("$name: 읽을 수 없는 본문을 받아들였다");
            } catch (\Throwable $e) {
                self::assertInstanceOf(KeycloakTransportError::class, $e, "$name: " . $e::class . ': ' . $e->getMessage());
                self::assertSame('JWKS response could not be read', $e->getMessage(), $name);
                self::assertInstanceOf(SanitizedCause::class, $e->getPrevious(), "$name: 원인은 정화된 사본이다");
            }
        }
    }

    // ⚠️ **「상한이 51200 이다」를 여기서 단언하지 않는다** — php 에서는 상수 대 리터럴 비교가
    // 컴파일 시점에 참으로 확정돼 정보를 담지 않는다(phpstan `staticMethod.alreadyNarrowedType`
    // 이 그것을 지적했다). 값이 자매 언어와 같은지는 교차언어 축이 본다:
    // `sh scripts/test/test-security-defaults.sh` 의 「JWKS 응답 크기 상한」.

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

    /**
     * ⚠️ **빈 키셋 200 은 좋은 캐시를 덮어서는 안 된다.** go 의 #380 픽스는 절반이 상태코드,
     * 나머지 절반이 `len(ks.Keys) == 0` 거부였는데 자매 SDK 로는 앞 절반만 복제됐다. `[]` 는
     * 배열이라 위의 shape 검사를 그대로 통과한다. 프록시·WAF·반쯤 뜬 realm 이 200 +
     * `{"keys":[]}` 를 주면 검증기가 눈이 멀고 refetch 게이트가 복구까지 막는다(실측 재현).
     */
    public function testEmptyKeySetOnColdStartIsTransportError(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $store = new JwksStore('http://kc/certs', $this->http([], $calls), $f, minRefetchIntervalSeconds: 0);
        $this->expectException(KeycloakTransportError::class);
        $this->expectExceptionMessageMatches('/no keys/');
        $store->getKeyByKid('k1');
    }

    public function testEmptyKeySetDoesNotClobberAGoodCache(): void
    {
        $f = new HttpFactory();
        $responses = [
            json_encode(['keys' => [['kid' => 'k1', 'kty' => 'RSA']]], JSON_THROW_ON_ERROR),
            json_encode(['keys' => []], JSON_THROW_ON_ERROR),
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
        self::assertSame('k1', $store->getKeyByKid('k1')['kid'], '사전조건: 좋은 캐시');

        // 미해결 kid 재조회가 빈 200 을 받는다 — 실패해야 한다.
        try {
            $store->getKeyByKid('k2');
            self::fail('빈 키셋 재조회는 실패해야 한다');
        } catch (KeycloakTransportError | TokenValidationError) {
            // 어느 쪽이든 「성공」이 아니면 된다.
        }

        // 핵심: 방금 검증되던 k1 이 살아 있어야 한다.
        self::assertSame('k1', $store->getKeyByKid('k1')['kid'], '빈 200 이 좋은 캐시를 덮었다');
    }

    /**
     * kid 가 없는 항목만 담긴 **비어 있지 않은** 배열도 저장되는 맵은 빈 맵이다 —
     * 「실제로 올릴 집합이 0 개면 거부」라는 같은 규칙이 이것도 잡아야 한다.
     */
    public function testNonEmptyArrayWithNoUsableKidIsAlsoRejected(): void
    {
        $calls = 0;
        $f = new HttpFactory();
        $store = new JwksStore('http://kc/certs', $this->http([['kty' => 'RSA']], $calls), $f, minRefetchIntervalSeconds: 0);
        $this->expectException(KeycloakTransportError::class);
        $this->expectExceptionMessageMatches('/no keys/');
        $store->getKeyByKid('k1');
    }
}
