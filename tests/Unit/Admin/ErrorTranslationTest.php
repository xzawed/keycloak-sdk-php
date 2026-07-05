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
    public function testPassesThroughReturn(): void
    {
        // 리터럴 'ok' 대신 런타임 생성 문자열 사용 — PHPStan이 @template T를 리터럴 타입으로 좁혀
        // assertSame을 "항상 참"으로 오판(staticMethod.alreadyNarrowedType)하는 것을 피한다.
        $expected = bin2hex(random_bytes(4));
        self::assertSame($expected, ErrorTranslation::call(fn (): string => $expected));
    }
}
