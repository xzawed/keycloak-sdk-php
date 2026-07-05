<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Token;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Token\IntrospectionResult;

final class IntrospectionResultTest extends TestCase
{
    public function testFromArrayActive(): void
    {
        $ir = IntrospectionResult::fromArray(['active' => true, 'username' => 'alice', 'client_id' => 'it-client']);
        self::assertTrue($ir->active);
        self::assertSame('alice', $ir->username);
        self::assertSame('it-client', $ir->clientId);
    }

    public function testInactiveDefaults(): void
    {
        $ir = IntrospectionResult::fromArray(['active' => false]);
        self::assertFalse($ir->active);
        self::assertNull($ir->username);
        self::assertNull($ir->clientId);
    }

    public function testDirectConstructorDefaults(): void
    {
        // fromArray()가 아닌 직접 생성자 경로 — username/clientId/claims 기본값(null/[])을 검증한다.
        $ir = new IntrospectionResult(active: true);
        self::assertTrue($ir->active);
        self::assertNull($ir->username);
        self::assertNull($ir->clientId);
        self::assertSame([], $ir->claims);
    }

    public function testFromArrayCoercesNonStringScalarUsername(): void
    {
        // toStr()의 int/float/bool 분기 노출 — 일부 IdP는 username/client_id를 문자열이 아닌
        // 그대로 내려보낼 수 있다(신뢰된 응답이라도 스칼라 타입 전제가 항상 문자열은 아님).
        $ir = IntrospectionResult::fromArray(['active' => true, 'username' => 42]);
        self::assertSame('42', $ir->username);
    }
}
