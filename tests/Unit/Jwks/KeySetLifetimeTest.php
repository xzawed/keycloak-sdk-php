<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Jwks;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/** 가짜 IdP — 내주는 kid 와 상태를 바꿀 수 있고, 받은 요청을 **메서드로** 센다(참조 카운터는 phpstan 이 좁힌다). */
final class LifetimeIdp implements ClientInterface
{
    public int $status = 200;
    /** @var list<string> */
    public array $kids = ['k1'];
    private int $calls = 0;

    /** @param array<string, array<string, string>> $jwks kid → 공개 JWK */
    public function __construct(private readonly array $jwks) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->calls++;
        if ($this->status !== 200) {
            return new Response($this->status, [], '{"error":"temporarily_unavailable"}');
        }
        $keys = array_map(fn (string $kid): array => $this->jwks[$kid], $this->kids);

        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => $keys], JSON_THROW_ON_ERROR));
    }

    public function calls(): int
    {
        return $this->calls;
    }
}

/**
 * 키 집합의 수명(아홉 언어 공통 · 판정 2026-10-29). 성공한 적재로 얻은 집합은 그 적재가 끝난 때부터 300 초만 쓴다 — 그 뒤는
 * **콜드 캐시와 같다**: 다음 검증이 같은 실패 백오프로 다시 받고, 그 적재가 실패하면 거부한다(낡은 키 폴백 없음). 수명 전에는
 * 예전처럼 미해결 kid 의 강제 재조회만 받고, 그것이 성공하면 수명이 다시 시작한다.
 *
 * 시계는 스토어의 단조 시계 이음매(`clock`)를 리플렉션으로 바꿔 끼운다 — 실패 백오프도 같은 시계를 읽는다. 30 초 재조회
 * 게이트(`time()`)와 토큰의 exp(벽시계)는 움직이지 않는다.
 */
final class KeySetLifetimeTest extends TestCase
{
    /** @var array<string, array{priv: string, jwk: array<string, string>}> */
    private static array $keys = [];
    private float $now = 1000.0;

    public static function setUpBeforeClass(): void
    {
        foreach (['k1', 'k2'] as $kid) {
            $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            self::assertNotFalse($res);
            self::assertTrue(openssl_pkey_export($res, $priv));
            self::assertIsString($priv);
            $details = openssl_pkey_get_details($res);
            self::assertIsArray($details);
            $rsa = $details['rsa'];
            self::assertIsArray($rsa);
            self::assertIsString($rsa['n']);
            self::assertIsString($rsa['e']);
            $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
            self::$keys[$kid] = ['priv' => $priv, 'jwk' => [
                'kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e']),
            ]];
        }
    }

    private function idp(): LifetimeIdp
    {
        return new LifetimeIdp(array_map(static fn (array $k): array => $k['jwk'], self::$keys));
    }

    private function validator(LifetimeIdp $idp): JwtValidator
    {
        $cfg = new KeycloakConfig(serverUrl: 'https://kc.test', realm: 'r', clientId: 'c');
        $store = new JwksStore('https://kc.test/realms/r/protocol/openid-connect/certs', $idp, new HttpFactory());
        (new \ReflectionProperty($store, 'clock'))->setValue($store, fn (): float => $this->now);

        return new JwtValidator($cfg, new OidcEndpoints($cfg), $store);
    }

    private function token(string $kid): string
    {
        $claims = ['sub' => "u-$kid", 'iss' => 'https://kc.test/realms/r', 'aud' => 'c', 'exp' => time() + 600];

        return FbJwt::encode($claims, self::$keys[$kid]['priv'], 'RS256', $kid);
    }

    /** @param class-string<\Throwable> $type */
    private function assertRejected(JwtValidator $v, string $kid, string $type, string $message): void
    {
        try {
            $v->validate($this->token($kid));
        } catch (\Throwable $e) {
            self::assertInstanceOf($type, $e, $e::class . ': ' . $e->getMessage());
            self::assertStringContainsString($message, $e->getMessage());

            return;
        }
        self::fail("$kid: 받아들였다");
    }

    public function testT1AHealthyIdpIsNotAskedAt299sAndIsAskedOnceAt301s(): void
    {
        $idp = $this->idp();
        $v = $this->validator($idp);
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject); // 적재 — t0
        $this->now += 299;
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject);
        self::assertSame(1, $idp->calls());
        $this->now += 2; // t0 + 301
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject);
        self::assertSame(2, $idp->calls());
    }

    public function testT2AnOutageAfterTheLifetimeIsRejectedBackedOffAndRecovers(): void
    {
        $idp = $this->idp();
        $v = $this->validator($idp);
        $v->validate($this->token('k1')); // t0
        $idp->status = 503;
        $this->now += 301;
        $this->assertRejected($v, 'k1', KeycloakTransportError::class, 'JWKS response invalid');
        self::assertSame(2, $idp->calls()); // 적재 + 시도 한 번
        for ($i = 0; $i < 3; $i++) {
            $this->assertRejected($v, 'k1', KeycloakTransportError::class, 'backing off');
        }
        self::assertSame(2, $idp->calls());
        $idp->status = 200;
        $this->now += 10; // 백오프 상한(5 초) 너머
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject);
        self::assertSame(3, $idp->calls());
    }

    public function testT3AKeyTheIdpWithdrewIsRejectedAfterTheRefetchWhileTheOtherValidates(): void
    {
        $idp = $this->idp();
        $idp->kids = ['k1', 'k2'];
        $v = $this->validator($idp);
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject); // t0 — 두 키
        $idp->kids = ['k2']; // IdP 가 k1 을 거뒀다
        $this->now += 301;
        $this->assertRejected($v, 'k1', TokenValidationError::class, 'unknown kid "k1"');
        self::assertSame('u-k2', $v->validate($this->token('k2'))->subject);
    }

    public function testT4AForcedRefetchRestartsTheLifetime(): void
    {
        $idp = $this->idp();
        $v = $this->validator($idp);
        $v->validate($this->token('k1')); // t0
        $idp->kids = ['k1', 'k2']; // k2 가 회전해 들어왔다
        $this->now += 100;
        self::assertSame('u-k2', $v->validate($this->token('k2'))->subject); // 미해결 kid → 강제 재조회
        self::assertSame(2, $idp->calls());
        $this->now += 250; // t0 + 350 — 재조회로부터 250 초
        self::assertSame('u-k1', $v->validate($this->token('k1'))->subject);
        self::assertSame(2, $idp->calls());
        $this->now += 51; // 재조회로부터 301 초
        self::assertSame('u-k2', $v->validate($this->token('k2'))->subject);
        self::assertSame(3, $idp->calls());
    }
}
