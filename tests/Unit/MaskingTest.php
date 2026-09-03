<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Masking;

final class MaskingTest extends TestCase
{
    public function testMasksNonEmptyFully(): void
    {
        self::assertSame('***', Masking::mask('super-secret-token'));
    }
    public function testEmptyAndNull(): void
    {
        self::assertSame('***', Masking::mask(''));   // 존재 여부도 노출 안 함
        self::assertSame('***', Masking::mask(null));
    }
    public function testNoPrefixLeak(): void
    {
        self::assertStringNotContainsString('super', Masking::mask('super-secret'));
    }

    /**
     * 마스킹을 __toString 에만 걸면 PHP 의 **기본 직렬화기**가 그것을 우회한다 — 승격된
     * 프로퍼티가 public 이라 json_encode() 가 원문을 그대로 뱉는다. 세 타입이 같은 구멍을
     * 갖고 있었다. .NET·Node 는 직렬화 경로를 따로 막는데 PHP 만 무보호였다.
     */
    public function testJsonEncodeMasksTokenSet(): void
    {
        $ts = new \Xzawed\Keycloak\Token\TokenSet(
            accessToken: 'SECRETat',
            tokenType: 'Bearer',
            expiresIn: 60,
            refreshToken: 'SECRETrt',
            idToken: 'SECRETid',
        );
        $json = (string) \json_encode($ts);

        self::assertStringNotContainsString('SECRETat', $json);
        self::assertStringNotContainsString('SECRETrt', $json);
        self::assertStringNotContainsString('SECRETid', $json);
        self::assertStringContainsString('Bearer', $json); // 진단 가치는 남는다
    }

    public function testJsonEncodeMasksConfigClientSecret(): void
    {
        $cfg = new \Xzawed\Keycloak\KeycloakConfig(
            serverUrl: 'https://kc.example.com',
            realm: 'demo',
            clientId: 'app',
            clientSecret: 'SECRETcs',
        );
        $json = (string) \json_encode($cfg);

        self::assertStringNotContainsString('SECRETcs', $json);
        self::assertStringContainsString('demo', $json);
    }

    /** codeVerifier 는 코드 교환의 소유 증명 비밀이다 — url/state/nonce 는 비밀이 아니다. */
    public function testJsonEncodeAndStringMaskAuthorizationRequest(): void
    {
        $req = new \Xzawed\Keycloak\Token\AuthorizationRequest(
            url: 'https://kc.example/auth?x=1',
            state: 'st4te',
            codeVerifier: 'SECRETverifier',
            nonce: 'n0nce',
        );

        $json = (string) \json_encode($req);
        self::assertStringNotContainsString('SECRETverifier', $json);
        self::assertStringContainsString('st4te', $json);

        $str = (string) $req;
        self::assertStringNotContainsString('SECRETverifier', $str);
        self::assertStringContainsString('***', $str);
    }
}
