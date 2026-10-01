<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\Exception\KeycloakConfigError;
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

    /** @param array<string,mixed> $claims */
    private function signAs(string $signer, array $claims, ?string $kid): string
    {
        $b64 = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');

        return match ($signer) {
            'rs256' => $this->sign($claims, kid: $kid),
            'none' => $b64(json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => $kid], JSON_THROW_ON_ERROR)) . '.'
                . $b64(json_encode($claims, JSON_THROW_ON_ERROR)) . '.',
            'hs256-public-key' => FbJwt::encode($claims, $this->publicPem(), 'HS256', $kid),
            'foreign-key' => FbJwt::encode($claims, self::otherPrivateKey(), 'RS256', $kid),
            default => throw new \LogicException("unknown signer {$signer}"),
        };
    }

    private function publicPem(): string
    {
        $privateKey = openssl_pkey_get_private($this->key['priv']);
        self::assertNotFalse($privateKey);
        $details = openssl_pkey_get_details($privateKey);
        self::assertIsArray($details);
        $publicPem = $details['key'];
        self::assertIsString($publicPem);

        return $publicPem;
    }

    private static function otherPrivateKey(): string
    {
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        self::assertTrue(openssl_pkey_export($other, $otherPriv));
        self::assertIsString($otherPriv);

        return $otherPriv;
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

    // ── validateIdToken — id_token 의 aud 는 client id 다(OIDC Core §2·§3.1.3.7). expectedAudience 는 보지 않는다 ──

    public function testValidateIdTokenChecksTheClientIdNotTheExpectedAudience(): void
    {
        $v = $this->validator('my-api');
        $vt = $v->validateIdToken($this->sign($this->goodClaims()), 'it-client');   // aud [it-client, account]
        self::assertSame(['it-client', 'account'], $vt->audience);

        $c = $this->goodClaims();
        $c['aud'] = ['my-api'];   // 재정의 값만 — 액세스 토큰이라면 통과했을 aud
        $this->expectException(TokenValidationError::class);
        $this->expectExceptionMessage('audience does not contain it-client');
        $v->validateIdToken($this->sign($c), 'it-client');
    }

    /** 대조는 넘겨받은 client id 다 — 교환을 한 클라이언트(`AuthClient` 의 설정)가 그 값을 준다. */
    public function testValidateIdTokenChecksTheClientIdItIsGiven(): void
    {
        $c = $this->goodClaims();
        $c['aud'] = 'web-client';
        self::assertSame(['web-client'], $this->validator()->validateIdToken($this->sign($c), 'web-client')->audience);

        $this->expectException(TokenValidationError::class);
        $this->expectExceptionMessage('audience does not contain web-client');
        $this->validator()->validateIdToken($this->sign($this->goodClaims()), 'web-client');
    }

    public function testValidateIdTokenRefusesAnEmptyClientId(): void
    {
        $c = $this->goodClaims();
        $c['aud'] = [''];
        $this->expectException(KeycloakConfigError::class);
        $this->validator()->validateIdToken($this->sign($c), ' ');
    }

    /**
     * aud 만 바뀐다 — 나머지 검사는 validate() 와 같은 경로다.
     *
     * @return iterable<string, array{array<string,mixed>, string, ?string, non-empty-string}>
     */
    public static function idTokenDefects(): iterable
    {
        // [바꿀 클레임(null 은 제거 · exp 는 지금부터의 초), 서명 방식, kid, 거부 메시지 접두]
        yield 'a foreign issuer' => [['iss' => 'http://evil/realms/it-realm'], 'rs256', 'test-kid', 'issuer mismatch'];
        yield 'expired beyond the skew' => [['exp' => -60], 'rs256', 'test-kid', 'token verification failed: Expired token'];
        yield 'no exp' => [['exp' => null], 'rs256', 'test-kid', 'exp claim is required'];
        yield 'alg none' => [[], 'none', 'test-kid', 'algorithm not allowed: none'];
        yield 'HS256 forged with the RSA public key' => [[], 'hs256-public-key', 'test-kid', 'algorithm not allowed: HS256'];
        yield 'no kid' => [[], 'rs256', null, 'missing kid'];
        yield 'a key outside the JWKS' => [[], 'foreign-key', 'test-kid', 'token verification failed: Signature verification failed'];
    }

    /** @param array<string,mixed> $changes */
    #[DataProvider('idTokenDefects')]
    public function testValidateIdTokenKeepsEveryOtherCheck(array $changes, string $signer, ?string $kid, string $message): void
    {
        $claims = $this->goodClaims();
        foreach ($changes as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
            } else {
                $claims[$name] = $name === 'exp' && \is_int($value) ? time() + $value : $value;
            }
        }
        $this->expectException(TokenValidationError::class);
        $this->expectExceptionMessage($message);
        $this->validator('my-api')->validateIdToken($this->signAs($signer, $claims, $kid), 'it-client');
    }

    public function testValidateIdTokenAllowsTheClockSkew(): void
    {
        $within = $this->goodClaims();
        $within['exp'] = time() - 10;   // 스큐 30초 안 — 위 「expired beyond the skew」와 쌍
        self::assertSame('s1', $this->validator('my-api')->validateIdToken($this->sign($within), 'it-client')->subject);
    }

    /**
     * id_token 과 액세스 토큰이 **한** JwksStore 를 쓴다 — 캐시·재조회 게이트·백오프가 하나다.
     * 대조군이 같은 http 위에 저장소를 하나 더 세워, 둘째 저장소라면 이 카운터가 셈을 보인다.
     */
    public function testValidateIdTokenAndValidateShareOneKeyStore(): void
    {
        $cfg = new KeycloakConfig(serverUrl: 'https://kc:8080', realm: 'it-realm', clientId: 'it-client', expectedAudience: 'my-api');
        $jwk = $this->key['jwk'];
        $http = new class ($jwk) implements ClientInterface {
            public int $hits = 0;

            /** @param array<string,mixed> $jwk */
            public function __construct(private array $jwk) {}

            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                ++$this->hits;

                return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
            }
        };
        $endpoints = new OidcEndpoints($cfg);
        $v = new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $http, new HttpFactory()));
        $access = $this->goodClaims();
        $access['aud'] = ['my-api'];

        $v->validateIdToken($this->sign($this->goodClaims()), 'it-client');
        self::assertSame(1, $http->hits);
        $v->validate($this->sign($access));
        self::assertSame(1, $http->hits, 'validate() must reuse the key store validateIdToken() warmed');

        (new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $http, new HttpFactory())))->validate($this->sign($access));
        self::assertSame(2, $http->hits, 'a second key store fetches again, and this counter sees it');
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
