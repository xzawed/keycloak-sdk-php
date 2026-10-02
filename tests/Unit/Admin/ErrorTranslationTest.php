<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Fschmtt\Keycloak\Exception\BuilderException;
use Fschmtt\Keycloak\Exception\SerializerException;
use GuzzleHttp\Exception\{ClientException, ConnectException, RequestException, ServerException};
use GuzzleHttp\Psr7\{FnStream, Request, Response};
use Xzawed\Keycloak\Admin\ErrorTranslation;
use Xzawed\Keycloak\Exception\{KeycloakNotFoundError, KeycloakConflictError, KeycloakForbiddenError, KeycloakAdminError, KeycloakConfigError, KeycloakTransportError, SanitizedCause};

/**
 * 분기별 변환 — 타입·상태·메시지·원인의 모양. 보낸 비밀(client secret·Bearer·representation)이 트레이스 인자로 새지 않는지는
 * 실제 fschmtt·Guzzle 스택을 태우는 `AdminFacadeErrorLeakTest` 가 잰다(여기서 손으로 만든 예외는 트레이스에 그 프레임이 없다).
 */
final class ErrorTranslationTest extends TestCase
{
    private const TOKEN_URL = 'http://kc.test/realms/r/protocol/openid-connect/token';
    private const ADMIN_URL = 'http://kc.test/admin/realms/r/users/u1';

    private function clientEx(int $status): ClientException
    {
        return new ClientException("HTTP $status", new Request('GET', '/'), new Response($status));
    }

    public function testMaps404(): void
    {
        $this->expectException(KeycloakNotFoundError::class);
        ErrorTranslation::call(fn () => throw $this->clientEx(404));
    }
    public function testMaps409(): void
    {
        $this->expectException(KeycloakConflictError::class);
        ErrorTranslation::call(fn () => throw $this->clientEx(409));
    }
    public function testMaps403(): void
    {
        $this->expectException(KeycloakForbiddenError::class);
        ErrorTranslation::call(fn () => throw $this->clientEx(403));
    }
    public function testMaps5xx(): void
    {
        $this->expectException(KeycloakAdminError::class);
        ErrorTranslation::call(fn () => throw new ServerException('boom', new Request('GET', '/'), new Response(500)));
    }
    public function testMapsConnect(): void
    {
        $this->expectException(KeycloakTransportError::class);
        ErrorTranslation::call(fn () => throw new ConnectException('refused', new Request('GET', '/')));
    }
    public function testBuilderExceptionMappedToConfig(): void
    {
        $this->expectException(KeycloakConfigError::class);
        ErrorTranslation::call(fn () => throw new BuilderException('missing base url'));
    }
    public function testBaseRequestExceptionMappedToTransport(): void
    {
        $this->expectException(KeycloakTransportError::class);
        ErrorTranslation::call(fn () => throw new RequestException('cURL error 60: SSL certificate problem', new Request('GET', 'https://kc/')));
    }
    public function testSerializerExceptionMappedToAdminError(): void
    {
        // fschmtt는 역직렬화 실패 시 Guzzle 예외가 아닌 자체 SerializerException을 던진다 —
        // ErrorTranslation의 \Throwable 총망라 net이 이를 KeycloakAdminError로 잡아야 한다(경계 누출 차단).
        $this->expectException(KeycloakAdminError::class);
        ErrorTranslation::call(fn () => throw new SerializerException('bad json'));
    }
    /**
     * 404/409/403 밖의 4xx 는 `default` 팔로 간다. ⚠️ 하위 타입(NotFound 등)도 `KeycloakAdminError` 라
     * `expectException(KeycloakAdminError::class)` 로는 팔을 잘못 고른 것을 못 잡는다 — 정확한 클래스를 본다.
     * 이 테스트가 없을 때 `default` 를 NotFound 로 바꿔도 단위 스위트 전부가 통과했다(변이 실측).
     */
    public function testMapsOther4xxToExactAdminError(): void
    {
        foreach ([400, 401] as $status) {
            $e = self::thrownBy(fn () => ErrorTranslation::call(fn () => throw $this->clientEx($status)));
            self::assertSame(KeycloakAdminError::class, $e::class, "HTTP $status");
            self::assertSame($status, $e->getStatusCode(), "HTTP $status");
        }
    }

    /**
     * 우리 자신의 SDK 예외는 재래핑하지 않고 **그 객체 그대로** 나간다. 이 분기가 없으면 `\Throwable` 그물이
     * 받아 새 `KeycloakAdminError` 로 감싸 타입(NotFound → AdminError)을 잃는다 — 그래도 단위 스위트는
     * 전부 통과했다(변이 실측).
     */
    public function testPassesThroughOwnSdkExceptionUnwrapped(): void
    {
        $own = new KeycloakNotFoundError('already translated', 404);
        self::assertSame($own, self::thrownBy(fn () => ErrorTranslation::call(fn () => throw $own)));
    }

    /**
     * 던져진 것을 돌려준다. `ErrorTranslation::call(fn () => throw …)` 을 직접 try 로 감싸면 PHPStan 이
     * never 로 좁혀 그 뒤의 `fail()` 을 죽은 코드로 본다 — 그렇다고 `fail()` 을 지우면 **안 던져도 통과**한다.
     */
    private static function thrownBy(callable $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('예외가 던져지지 않았다');
    }

    /**
     * 메시지는 SDK 가 만든다 — HTTP 상태, 그리고 admin 의 **토큰 부여**면 코드 모양의 OAuth `error` 만(`AuthClient` 와
     * 같은 규칙, `OAuthErrorCode`). 본문의 나머지와 코드 모양이 아닌 `error`(토큰을 되울린 자리)는 싣지 않는다. admin REST 의
     * 오류 본문은 OAuth 응답이 아니라 코드 모양이어도 싣지 않는다. 8 KiB 를 넘는 본문은 코드를 찾지 않는다.
     *
     * @return array<string, array{0: string, 1: int, 2: string, 3: string}>
     */
    public static function httpErrors(): array
    {
        $json = static fn (array $a): string => (string) json_encode($a);

        return [
            'token 400 · code + echoed description' => [self::TOKEN_URL, 400,
                $json(['error' => 'invalid_grant', 'error_description' => 'ETecho0-description']), 'admin token request failed: HTTP 400 (invalid_grant)'],
            'token 400 · error carries a token' => [self::TOKEN_URL, 400,
                $json(['error' => 'ETerr00-Token-In-Error-Code']), 'admin token request failed: HTTP 400'],
            'token 401 · non-JSON body' => [self::TOKEN_URL, 401, 'ETbody0-not-json', 'admin token request failed: HTTP 401'],
            'token 400 · JSON without error' => [self::TOKEN_URL, 400, $json(['message' => 'x']), 'admin token request failed: HTTP 400'],
            'token 400 · body over 8 KiB' => [self::TOKEN_URL, 400,
                $json(['error' => 'invalid_grant', 'pad' => str_repeat('x', 9000)]), 'admin token request failed: HTTP 400'],
            'token 503 · code' => [self::TOKEN_URL, 503, $json(['error' => 'temporarily_unavailable']), 'admin token request failed: HTTP 503 (temporarily_unavailable)'],
            'admin 404 · code-shaped error is not an OAuth code' => [self::ADMIN_URL, 404, $json(['error' => 'not_found']), 'admin request failed: HTTP 404'],
            'admin 409 · errorMessage echo' => [self::ADMIN_URL, 409, $json(['errorMessage' => 'ETecho1-admin-body']), 'admin request failed: HTTP 409'],
            'admin 500 · HTML' => [self::ADMIN_URL, 500, '<p>ETecho2-html</p>', 'admin request failed: HTTP 500'],
        ];
    }

    #[DataProvider('httpErrors')]
    public function testHttpErrorMessageCarriesStatusAndOnlyACodeShapedOAuthError(string $url, int $status, string $body, string $message): void
    {
        $method = str_ends_with($url, '/token') ? 'POST' : 'GET';
        $req = new Request($method, $url . '?q=ETquery0');
        $res = new Response($status, ['Content-Type' => 'application/json'], $body);
        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw ($status >= 500
            ? new ServerException('Guzzle message ' . $body, $req, $res)
            : new ClientException('Guzzle message ' . $body, $req, $res))));

        self::assertInstanceOf(KeycloakAdminError::class, $e);
        self::assertSame($status, $e->getStatusCode());
        self::assertSame($message, $e->getMessage());
        $cause = $e->getPrevious();
        self::assertInstanceOf(SanitizedCause::class, $cause);
        // 원인은 상태·메서드·URL(쿼리 제외)만 — #622 의 같은 사본이다.
        self::assertSame(
            ($status >= 500 ? ServerException::class : ClientException::class) . ": HTTP $status from $method $url (response body withheld)",
            $cause->getMessage(),
        );
    }

    /**
     * admin 의 토큰 부여는 Bearer 없이 나가는 요청 하나뿐이다(fschmtt `Client::fetchTokens`) — admin 요청은 전부 Bearer 를 싣는다.
     * 경로 꼬리만 보면 경로로 가는 식별자(`users()->get('x/protocol/openid-connect/token')` — fschmtt 는 경로 값을 인코딩하지 않는다)가
     * admin 요청을 토큰 부여로 바꿔, admin 오류 본문의 코드 모양 `error` 를 메시지에 실었다. 진짜 스택으로 다섯 자원의 식별자 메서드
     * 전부를 재는 것은 `AdminFacadeErrorLeakTest` 의 'admin 404 · path identifier ends in the token path' 칸이다.
     */
    public function testAdminRequestWhosePathEndsInTheTokenPathIsNotTheTokenGrant(): void
    {
        $req = new Request('GET', 'http://kc.test/admin/realms/r/users/x/protocol/openid-connect/token', ['Authorization' => 'Bearer ETbearer0']);
        $json = ['Content-Type' => 'application/json'];
        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw new ClientException('x', $req, new Response(404, $json, '{"error":"invalid_client"}'))));
        self::assertSame(KeycloakNotFoundError::class, $e::class);
        self::assertSame('admin request failed: HTTP 404', $e->getMessage());

        // 5xx 갈래도 같은 판정을 탄다 — Keycloak 의 500 본문은 코드 모양이다(`unknown_error`).
        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw new ServerException('x', $req, new Response(500, $json, '{"error":"unknown_error"}'))));
        self::assertSame(KeycloakAdminError::class, $e::class);
        self::assertSame('admin request failed: HTTP 500', $e->getMessage());
    }

    /** 본문을 못 읽어도 변환은 끝난다 — 읽기 오류가 하위 예외 원본으로 경계를 넘지 않는다(코드만 빠진다). */
    public function testUnreadableTokenErrorBodyStillTranslates(): void
    {
        $body = FnStream::decorate(\GuzzleHttp\Psr7\Utils::streamFor('{"error":"invalid_grant"}'), [
            'read' => static fn (): string => throw new \RuntimeException('stream read failed'),
        ]);
        $res = new Response(400, [], $body);
        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw new ClientException('x', new Request('POST', self::TOKEN_URL), $res)));

        self::assertSame(KeycloakAdminError::class, $e::class);
        self::assertSame('admin token request failed: HTTP 400', $e->getMessage());
    }

    /**
     * 모든 갈래가 하위 예외를 원본이 아니라 `SanitizedCause` 사본으로 단다(§4 — 원인 사슬에도 하위 타입이 없다).
     *
     * @return array<string, array{0: \Throwable, 1: class-string<\Throwable>, 2: string}>
     */
    public static function lowerExceptions(): array
    {
        $req = new Request('GET', self::ADMIN_URL);

        return [
            'ClientException' => [new ClientException('c', $req, new Response(404)), KeycloakNotFoundError::class, 'admin request failed: HTTP 404'],
            'ServerException' => [new ServerException('s', $req, new Response(502)), KeycloakAdminError::class, 'admin request failed: HTTP 502'],
            'ConnectException' => [new ConnectException('refused', $req), KeycloakTransportError::class, 'admin request unreachable'],
            'RequestException without response' => [new RequestException('TLS handshake failed', $req), KeycloakTransportError::class, 'admin request failed'],
            // fschmtt Builder 의 고정 문구 — 네트워크 앞이라 응답·토큰을 쥘 수 없어 메시지를 옮긴다.
            'BuilderException' => [new BuilderException('Base URL is not set'), KeycloakConfigError::class, 'Base URL is not set'],
            // 분류 밖 예외의 메시지는 옮기지 않는다 — 감사하지 않은 라이브러리(fschmtt·lcobucci·json_decode)의 메시지다.
            'unclassified Throwable' => [new \RuntimeException('ETmsg00-quoted-token'), KeycloakAdminError::class, 'admin request failed unexpectedly'],
            'TypeError' => [new \TypeError('Parser::parse(): Argument #1 must be of type string, array given'), KeycloakAdminError::class, 'admin request failed unexpectedly'],
        ];
    }

    /** @param class-string<\Throwable> $sdkClass */
    #[DataProvider('lowerExceptions')]
    public function testLowerExceptionIsAttachedAsSanitizedCopy(\Throwable $lower, string $sdkClass, string $message): void
    {
        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw $lower));

        self::assertSame($sdkClass, $e::class);
        self::assertSame($message, $e->getMessage());
        $cause = $e->getPrevious();
        self::assertInstanceOf(SanitizedCause::class, $cause);
        self::assertSame($lower::class, $cause->originalClass);
        for ($l = $e; $l !== null; $l = $l->getPrevious()) {
            self::assertStringStartsWith('Xzawed\\Keycloak\\', $l::class, '원인 사슬에 하위 예외 원본이 있다(§4)');
        }
    }

    /**
     * Guzzle 의 전송 실패 메시지는 요청 URL 을 **쿼리째** 인용한다(admin 검색의 쿼리는 소비자의 검색어·username). 원인 사본은 URL 을
     * 남기되 쿼리·사용자정보·조각을 빼고, 다른 꼴로 인용돼(호스트를 IP 로 바꾼 URL · 디코드한 쿼리) 바꾸지 못한 쿼리가 남으면 메시지를
     * 거둔다 — 감싼 사슬(stream 핸들러의 fopen 경고)도 같은 URL 로 본다. 진짜 핸들러로 재는 것은
     * `AdminFacadeErrorLeakTest::testRealTransportFailureCauseKeepsTheUrlButNotItsQuery` 이고, 여기서는 그 꼴들을 Guzzle 파일에서 난
     * 것처럼 세워(원인 사본은 파일로 감사한 라이브러리를 가린다) 가지마다 고정한다.
     *
     * @return array<string, array{0: class-string<ConnectException|RequestException>, 1: string, 2: ?string, 3: list<string>}>
     */
    public static function quotedRequestUrls(): array
    {
        $url = 'http://u:p@kc.test/admin/realms/r/users?search=ETq%2B0+x&exact=true#f';
        $redacted = 'http://u:***@kc.test/admin/realms/r/users?search=ETq%2B0+x&exact=true#f';
        $safe = 'http://kc.test/admin/realms/r/users';
        $withheld = '(message withheld: it quotes the request query)';
        $see = '(see https://curl.se/libcurl/c/libcurl-errors.html)';

        return [
            'curl · … for <URL>' => [ConnectException::class, "cURL error 28: Operation timed out $see for $redacted", null,
                ["cURL error 28: Operation timed out $see for $safe"]],
            'stream · Connection refused for URI <URL>' => [ConnectException::class, "Connection refused for URI $redacted", null,
                ["Connection refused for URI $safe"]],
            'curl · other errno, no response' => [RequestException::class, "cURL error 56: Recv failure $see for $redacted", null,
                ["cURL error 56: Recv failure $see for $safe"]],
            'host rewritten to an IP' => [ConnectException::class, 'Connection refused for URI http://127.0.0.1/admin/realms/r/users?search=ETq%2B0+x&exact=true', null,
                [$withheld]],
            'query quoted decoded' => [ConnectException::class, 'request failed: search=ETq+0 x&exact=true', null, [$withheld]],
            'stream · wrapped fopen warning' => [ConnectException::class, "Connection refused for URI $redacted",
                "Error creating resource: [message] fopen($url): Failed to open stream", ["Connection refused for URI $safe", "Error creating resource: [message] fopen($safe): Failed to open stream"]],
        ];
    }

    /**
     * @param class-string<ConnectException|RequestException> $class
     * @param list<string> $causes
     */
    #[DataProvider('quotedRequestUrls')]
    public function testTransportFailureCauseKeepsTheUrlButNotItsQuery(string $class, string $message, ?string $wrapped, array $causes): void
    {
        $guzzle = (new \ReflectionClass(\GuzzleHttp\Client::class))->getFileName();
        self::assertIsString($guzzle);
        $file = new \ReflectionProperty(\Exception::class, 'file');
        $req = new Request('GET', 'http://u:p@kc.test/admin/realms/r/users?search=ETq%2B0+x&exact=true#f');
        $previous = $wrapped === null ? null : new \RuntimeException($wrapped);
        $lower = $class === ConnectException::class ? new ConnectException($message, $req, $previous) : new RequestException($message, $req, null, $previous);
        foreach ([$lower, $previous] as $thrown) {
            if ($thrown !== null) {
                $file->setValue($thrown, $guzzle);   // Guzzle 핸들러 안에서 난 것처럼 — 감사한 라이브러리의 메시지
            }
        }

        $e = self::thrownBy(fn () => ErrorTranslation::call(static fn () => throw $lower));

        self::assertSame(KeycloakTransportError::class, $e::class);
        $chain = [];
        for ($l = $e->getPrevious(); $l !== null; $l = $l->getPrevious()) {
            self::assertInstanceOf(SanitizedCause::class, $l);
            $chain[] = substr($l->getMessage(), \strlen($l->originalClass) + 2);
        }
        self::assertSame($causes, $chain);
    }

    public function testPassesThroughReturn(): void
    {
        // 리터럴 'ok' 대신 런타임 생성 문자열 사용 — PHPStan이 @template T를 리터럴 타입으로 좁혀
        // assertSame을 "항상 참"으로 오판(staticMethod.alreadyNarrowedType)하는 것을 피한다.
        $expected = bin2hex(random_bytes(4));
        self::assertSame($expected, ErrorTranslation::call(fn (): string => $expected));
    }
}
