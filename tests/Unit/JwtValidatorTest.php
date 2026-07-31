<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

final class JwtValidatorTest extends TestCase
{
    /** @var array{priv:string,jwk:array<string,mixed>} */
    private array $key;
    private string $iss = 'https://kc:8080/realms/it-realm';

    protected function setUp(): void
    {
        // RSA 키쌍 생성 + JWKS 엔트리(n,e) 구성
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        self::assertTrue(openssl_pkey_export($res, $priv));
        self::assertIsString($priv);
        $details = openssl_pkey_get_details($res);
        self::assertIsArray($details);
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        $n = $rsa['n'];
        $e = $rsa['e'];
        self::assertIsString($n);
        self::assertIsString($e);
        $jwk = [
            'kty' => 'RSA', 'kid' => 'test-kid', 'use' => 'sig', 'alg' => 'RS256',
            'n' => rtrim(strtr(base64_encode($n), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($e), '+/', '-_'), '='),
        ];
        $this->key = ['priv' => $priv, 'jwk' => $jwk];
    }

    private function validator(?string $expectedAudience = null): JwtValidator
    {
        $cfg = new KeycloakConfig(
            serverUrl: 'https://kc:8080',
            realm: 'it-realm',
            clientId: 'it-client',
            expectedAudience: $expectedAudience,
        );
        $f = new HttpFactory();
        $jwk = $this->key['jwk'];
        $http = new class ($jwk) implements ClientInterface {
            /** @param array<string,mixed> $jwk */
            public function __construct(private array $jwk) {}

            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
            }
        };
        $store = new JwksStore('https://kc:8080/realms/it-realm/protocol/openid-connect/certs', $http, $f);

        return new JwtValidator($cfg, new OidcEndpoints($cfg), $store);
    }

    /** @param array<string,mixed> $claims */
    private function sign(array $claims, string $alg = 'RS256', ?string $kid = 'test-kid'): string
    {
        return FbJwt::encode($claims, $this->key['priv'], $alg, $kid);
    }

    /** @return array<string,mixed> */
    private function goodClaims(): array
    {
        return ['sub' => 's1', 'iss' => $this->iss, 'aud' => ['it-client', 'account'], 'exp' => time() + 300, 'iat' => time()];
    }

    public function testValidTokenPasses(): void
    {
        $vt = $this->validator()->validate($this->sign($this->goodClaims()));
        self::assertSame('s1', $vt->subject);
        self::assertContains('it-client', $vt->audience);
        self::assertSame($this->iss, $vt->issuer);
    }

    public function testRejectsNoneAlg(): void
    {
        // alg=none 토큰을 수동 구성(header.alg=none, 서명 빈값)
        $h = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT'], JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $p = rtrim(strtr(base64_encode(json_encode($this->goodClaims(), JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate("$h.$p.");
    }

    public function testRejectsWrongIssuer(): void
    {
        $c = $this->goodClaims();
        $c['iss'] = 'http://evil/realms/it-realm';
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($c));
    }

    public function testRejectsAudienceNotContainingClient(): void
    {
        $c = $this->goodClaims();
        $c['aud'] = ['other-client'];
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($c));
    }

    public function testExpectedAudienceUnsetFallsBackToClientId(): void
    {
        // 미설정이면 종전 동작 그대로 — clientId를 담은 aud는 통과, 담지 않은 aud는 거부.
        $vt = $this->validator()->validate($this->sign($this->goodClaims()));
        self::assertContains('it-client', $vt->audience);

        $c = $this->goodClaims();
        $c['aud'] = ['my-api'];
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($c));
    }

    public function testExpectedAudienceReplacesClientId(): void
    {
        // 설정하면 기대 aud가 그 값으로 바뀐다 — clientId만 담은 토큰은 더 이상 통과하지 않는다.
        $c = $this->goodClaims();
        $c['aud'] = ['my-api', 'account'];
        $vt = $this->validator('my-api')->validate($this->sign($c));
        self::assertContains('my-api', $vt->audience);

        $this->expectException(TokenValidationError::class);
        $this->validator('my-api')->validate($this->sign($this->goodClaims()));
    }

    public function testRejectsExpired(): void
    {
        $c = $this->goodClaims();
        $c['exp'] = time() - 100;
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($c));
    }

    public function testRejectsMissingExp(): void
    {
        $c = $this->goodClaims();
        unset($c['exp']);
        $this->expectException(TokenValidationError::class);   // exp 필수
        $this->validator()->validate($this->sign($c));
    }

    public function testRejectsUnknownKid(): void
    {
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($this->goodClaims(), kid: 'other-kid'));
    }

    // ── 릴리스 전 감사 후속: 구현만 있고 테스트가 없던 2건 ──

    /**
     * 클록 스큐 경계 — 스큐(기본 30초) 안에서 만료된 토큰은 통과하고, 밖에서 만료된 토큰은 거부된다.
     * 두 단언이 쌍이어야 의미가 있다: 통과 케이스만으로는 스큐가 무한대여도, 거부 케이스만으로는
     * 스큐가 0이어도 통과한다. 쌍이어야 `FbJwt::$leeway = config->clockSkew` 배선이 증명된다.
     * (⚠️ firebase/php-jwt의 `$leeway`는 프로세스 전역 static이라 JwtValidator가 매 검증마다
     * 재설정한다 — 다른 테스트가 남긴 값에 의존하지 않도록 두 케이스를 같은 테스트에 둔다.)
     */
    public function testClockSkewBoundaryWithinPassesBeyondRejected(): void
    {
        $within = $this->goodClaims();
        $within['exp'] = time() - 10;   // 스큐 30초 안
        self::assertSame('s1', $this->validator()->validate($this->sign($within))->subject);

        $beyond = $this->goodClaims();
        $beyond['exp'] = time() - 60;   // 스큐 30초 밖
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($beyond));
    }

    /**
     * HS256/RS256 혼동 공격 — 공격자가 공개된 RSA 공개키를 HMAC 비밀로 삼아 HS256 토큰을 위조한다.
     * 검증기가 헤더의 alg를 믿고 키를 고르면 "공개키를 아는 사람 = 토큰을 발급할 수 있는 사람"이 된다.
     * 우리 검증기는 JWKS의 RS256 키로만 검증하므로 거부해야 한다.
     */
    public function testRejectsHs256ForgedWithRsaPublicKey(): void
    {
        $privateKey = openssl_pkey_get_private($this->key['priv']);
        self::assertNotFalse($privateKey);
        $details = openssl_pkey_get_details($privateKey);
        self::assertIsArray($details);
        $publicPem = $details['key'];
        self::assertIsString($publicPem);

        // 공개키 텍스트를 HMAC 비밀로 사용해 위조(고전 공격 벡터).
        $forged = FbJwt::encode($this->goodClaims(), $publicPem, 'HS256', 'test-kid');

        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($forged);
    }

    public function testRejectsTamperedSignature(): void
    {
        // 다른 키쌍으로 서명하되 kid는 진짜 kid를 사칭 — JWKS는 진짜 공개키를 돌려주므로
        // firebase의 openssl_verify가 실패해 SignatureInvalidException(→TokenValidationError)이어야 한다.
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        self::assertTrue(openssl_pkey_export($other, $otherPriv));
        self::assertIsString($otherPriv);
        $jwt = FbJwt::encode($this->goodClaims(), $otherPriv, 'RS256', 'test-kid');
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($jwt);
    }

    public function testRejectsMissingKid(): void
    {
        $jwt = $this->sign($this->goodClaims(), kid: null);
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($jwt);
    }

    public function testRejectsMalformedJwtFormat(): void
    {
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate('not-a-jwt');
    }

    public function testRejectsInvalidHeaderEncoding(): void
    {
        $h = rtrim(strtr(base64_encode('not-json'), '+/', '-_'), '=');
        $p = rtrim(strtr(base64_encode(json_encode($this->goodClaims(), JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate("$h.$p.sig");
    }

    public function testRejectsMissingAudienceClaim(): void
    {
        $c = $this->goodClaims();
        unset($c['aud']);
        $this->expectException(TokenValidationError::class);
        $this->validator()->validate($this->sign($c));
    }

    public function testAcceptsStringAudienceContainingClient(): void
    {
        $c = $this->goodClaims();
        $c['aud'] = 'it-client'; // 단일-문자열 aud(흔한 OIDC 모양) — 정규화해 list로 담아야 한다
        $vt = $this->validator()->validate($this->sign($c));
        self::assertSame(['it-client'], $vt->audience);
    }

    public function testAcceptsNonStringScalarClaims(): void
    {
        // 일부 IdP/버전은 sub를 int, iat를 float, exp를 숫자문자열로 실어보내기도 한다 —
        // toStr/toInt의 int·float·numeric-string 강제변환 분기를 실제로 행사한다.
        $c = $this->goodClaims();
        $c['sub'] = 12345;
        $c['iat'] = (float) time();
        $c['exp'] = (string) (time() + 300);
        $vt = $this->validator()->validate($this->sign($c));
        self::assertSame('12345', $vt->subject);
        self::assertIsInt($vt->issuedAt);
        self::assertIsInt($vt->expiresAt);
    }

    public function testRejectsUnsupportedJwksKeyKty(): void
    {
        $cfg = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'it-realm', clientId: 'it-client');
        $jwk = ['kty' => 'weird', 'kid' => 'test-kid', 'alg' => 'RS256'];
        $http = new class ($jwk) implements ClientInterface {
            /** @param array<string,mixed> $jwk */
            public function __construct(private array $jwk) {}

            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
            }
        };
        $f = new HttpFactory();
        $store = new JwksStore('https://kc:8080/realms/it-realm/protocol/openid-connect/certs', $http, $f);
        $validator = new JwtValidator($cfg, new OidcEndpoints($cfg), $store);
        $this->expectException(TokenValidationError::class);
        $validator->validate($this->sign($this->goodClaims()));
    }

    public function testMalformedJwksModulusMappedToTokenValidationError(): void
    {
        // JWKS 엔트리의 "n"이 배열(비-스칼라)이면 Firebase\JWT\JWK::parseKey가
        // createPemFromModulusAndExponent(string $n, ...)에 array를 넘겨 \TypeError를 던진다
        // (\TypeError는 \Error 상속이지 \Exception이 아니다). validate()는 이를 TokenValidationError로
        // 반드시 변환해야 한다(경계 불변식) — 진짜 키쌍으로 서명한 문법적으로 유효한 토큰을 사용해
        // 서명 검증 이전에 파싱 단계에서 \TypeError가 나는 경로를 정확히 행사한다.
        $cfg = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'it-realm', clientId: 'it-client');
        $jwk = $this->key['jwk'];
        $jwk['n'] = ['x']; // 비-스칼라 n — string 타입힌트 위반
        $http = new class ($jwk) implements ClientInterface {
            /** @param array<string,mixed> $jwk */
            public function __construct(private array $jwk) {}

            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
            }
        };
        $f = new HttpFactory();
        $store = new JwksStore('https://kc:8080/realms/it-realm/protocol/openid-connect/certs', $http, $f);
        $validator = new JwtValidator($cfg, new OidcEndpoints($cfg), $store);
        $this->expectException(TokenValidationError::class);
        $validator->validate($this->sign($this->goodClaims()));
    }
}
