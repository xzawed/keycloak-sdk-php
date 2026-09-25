<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;
use Fschmtt\Keycloak\Exception\BuilderException;
use Fschmtt\Keycloak\Exception\SerializerException;
use GuzzleHttp\Exception\{ClientException, ConnectException, RequestException, ServerException};
use GuzzleHttp\Psr7\{Request, Response};
use Xzawed\Keycloak\Admin\ErrorTranslation;
use Xzawed\Keycloak\Exception\{KeycloakNotFoundError, KeycloakConflictError, KeycloakForbiddenError, KeycloakAdminError, KeycloakConfigError, KeycloakTransportError};

final class ErrorTranslationTest extends TestCase
{
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

    public function testPassesThroughReturn(): void
    {
        // 리터럴 'ok' 대신 런타임 생성 문자열 사용 — PHPStan이 @template T를 리터럴 타입으로 좁혀
        // assertSame을 "항상 참"으로 오판(staticMethod.alreadyNarrowedType)하는 것을 피한다.
        $expected = bin2hex(random_bytes(4));
        self::assertSame($expected, ErrorTranslation::call(fn (): string => $expected));
    }
}
