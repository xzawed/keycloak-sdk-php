<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT as FbJwt;
use Xzawed\Keycloak\Exception\KeycloakConfigError;
use Xzawed\Keycloak\Exception\SanitizedCause;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\Token\ValidatedToken;

/**
 * 자체강화 JWT 검증기: RS256 알고리즘 핀(헤더 불신)·none/미서명 거부·iss 정확일치·aud 포함검사·
 * exp 필수·nbf·클록 스큐·DoS-safe JWKS(JwksStore)를 강제한다.
 * firebase/php-jwt는 서명·exp·nbf 검증 프리미티브로만 사용하고, alg 사전 핀·iss·aud는 이 클래스가 강제한다.
 */
final class JwtValidator
{
    /**
     * 받는 JWT 의 바이트 상한 — 넘으면 **어떤 분해·디코드보다 먼저** 거부한다.
     *
     * 이 경로는 서명을 보기 전에 토큰을 쪼개고 헤더·페이로드를 json_decode 한다. 상한이 없을 때 깊게 중첩한 JSON 배열을
     * 실은 헤더는 토큰 바이트당 약 167 B 를 할당했고, 768 KiB 토큰 하나가 기본 `memory_limit` 128M 에서 치명 OOM 으로
     * 요청을 끝냈다(넓은 배열이면 약 95 B · 1.5 MiB, 실측). 공격자가 일으키는 OOM 치명 오류는 PHP2Shell(CVE-2026-109618 · CVE-2026-109619)의 트리거이고, 패치된
     * PHP 에서도 요청을 죽이는 DoS 다. 256000 은 .NET SDK 가 쓰는 Microsoft.IdentityModel 의 `DefaultMaximumTokenSizeInBytes`
     * 와 같고, Keycloak 26.6 이 기본 설정으로 받는 가장 긴 Bearer(65,459 B)의 약 3.9 배다. 이 길이에서 잰 가장 비싼 모양
     * (깊이 500 으로 중첩한 배열, 바이트당 약 86 B)은 22 MB 남짓이다 — `JwtValidatorTest` 가 기본 한도의 1/4 아래를
     * 단언하므로 상한을 올리면 그 시험이 먼저 빨개진다.
     */
    public const JWT_MAX_BYTES = 256000;

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly OidcEndpoints $endpoints,
        private readonly JwksStore $jwks,
    ) {}

    /**
     * 액세스 토큰 검증 — 기대 aud 는 `expectedAudience`(설정 시), 미설정이면 `clientId`.
     */
    public function validate(#[\SensitiveParameter] string $jwt): ValidatedToken
    {
        return $this->verify($jwt, $this->config->expectedAudience ?? $this->config->clientId);
    }

    /**
     * id_token 검증 — aud 는 `$clientId` 를 담아야 한다(OIDC Core §2·§3.1.3.7: id_token 의 aud 는 그것을 요청한
     * 클라이언트다). `expectedAudience` 는 **보지 않는다** — 그것은 액세스 토큰의 리소스 서버 제한이다(RFC 9700
     * §2.3). 나머지(alg 핀·kid·서명·exp 필수·클록 스큐·iss)는 validate() 와 같은 경로이고 JWKS 저장소도 같은 것이다.
     * nonce 대조는 호출자 몫이다 — `AuthClient::exchangeCode()` 가 이것을 부르고 대조한다.
     *
     * @throws KeycloakConfigError  `$clientId` 가 비었을 때
     * @throws TokenValidationError 검증 실패
     */
    public function validateIdToken(#[\SensitiveParameter] string $idToken, string $clientId): ValidatedToken
    {
        if (trim($clientId) === '') {
            // 빈 기대값은 aud [""] 인 토큰을 통과시킨다 — 비교를 무력화하는 입력은 거부한다.
            throw new KeycloakConfigError('clientId is required');
        }

        return $this->verify($idToken, $clientId);
    }

    /**
     * 검증 본문 — 두 공개 진입점은 기대 aud 만 다르다.
     *
     * ⚠️ `#[\SensitiveParameter]` 를 떼지 말 것 — 이 프레임은 원문 JWT 를 인자로 쥐고, 여기서 난 예외의 트레이스가 그것을
     * 찍는다(`zend.exception_ignore_args=0` · `CodeExchangeIT::assertLeaksNothing`).
     */
    private function verify(#[\SensitiveParameter] string $jwt, string $expectedAud): ValidatedToken
    {
        // (0) 길이 상한 — 아래 어느 단계든 토큰 길이에 비례해 할당하기 전에(`JWT_MAX_BYTES`).
        if (\strlen($jwt) > self::JWT_MAX_BYTES) {
            throw new TokenValidationError(sprintf('token exceeds %d bytes', self::JWT_MAX_BYTES));
        }

        // (1) 헤더 사전 게이트 — firebase 디코드 이전에 우리가 직접 첫 세그먼트를 파싱해 alg를
        // RS256로 핀하고 none/미서명/다른 alg를 즉시 거부한다. firebase의 &$headers out-param은
        // 디코드가 *성공한 후에만* 채워지므로 사전 게이트로 쓸 수 없다(순서 함정).
        $header = $this->decodeHeader($jwt);
        $alg = isset($header['alg']) && is_string($header['alg']) ? $header['alg'] : null;
        if ($alg === null || !in_array($alg, $this->config->signatureAlgorithms, true)) {
            throw new TokenValidationError(sprintf('algorithm not allowed: %s', $alg ?? '(none)'));
        }
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
        if ($kid === null) {
            throw new TokenValidationError('missing kid');
        }
        // ⚠️ 헤더 배열은 여기서 놓는다 — firebase 가 헤더를 다시 디코드하는 동안 둘이 함께 살면 할당이 두 배다
        // (깊이 500 중첩 배열 헤더가 상한 길이에서 42 MB → 21 MB, 실측).
        unset($header);

        // (2) JWKS에서 kid로 키 조회(DoS-safe, JwksStore) → firebase Key → 서명/exp/nbf 검증(클록 스큐 적용)
        $jwk = $this->jwks->getKeyByKid($kid);
        $prevLeeway = FbJwt::$leeway;
        FbJwt::$leeway = $this->config->clockSkew;
        try {
            try {
                $key = JWK::parseKey($jwk, $alg);
                if ($key === null) {
                    throw new TokenValidationError('unusable JWKS key');
                }
                $payload = FbJwt::decode($jwt, $key);
            } catch (TokenValidationError $e) {
                throw $e; // 우리 자신의 예외 — 재래핑하지 않는다.
            } catch (\Throwable $e) {
                // firebase SignatureInvalidException/ExpiredException/BeforeValidException(모두
                // \UnexpectedValueException 상속) + SPL 예외(미지원 alg·손상된 JWKS 키 등) +
                // \Error/\TypeError(예: JWK::parseKey가 배열/객체 n·e를 만나 createPemFromModulusAndExponent에
                // string 아닌 값을 넘길 때) 전부 여기로 수렴 — \Throwable 전체를 잡아야
                // "validate()를 벗어나는 firebase/SPL/Error 예외는 없다" 경계 불변식이 유지된다.
                // ⚠️ 원본을 달지 않는다 — 그 트레이스의 `JWT::decode(<원문 JWT>, …)` 인자가 토큰 전체다(실측:
                // 위조 서명 id_token 이 exchangeCode 오류의 var_dump 에 그대로 찍혔다). firebase 메시지는 입력을 인용하지 않는다.
                throw new TokenValidationError('token verification failed: ' . $e->getMessage(), previous: SanitizedCause::of($e));
            }
        } finally {
            FbJwt::$leeway = $prevLeeway;
        }

        // (3) firebase는 서명·exp(있으면)·nbf만 검증한다 — exp 필수·iss 정확일치·aud 포함은 우리가 강제.
        $claims = self::stringKeyed((array) $payload);
        if (!isset($claims['exp'])) {
            throw new TokenValidationError('exp claim is required');
        }
        $iss = isset($claims['iss']) ? self::toStr($claims['iss']) : '';
        if ($iss !== $this->endpoints->issuer()) {
            throw new TokenValidationError(sprintf('issuer mismatch: %s', $iss));
        }
        $aud = $this->normalizeAudience($claims['aud'] ?? null);
        if (!in_array($expectedAud, $aud, true)) {
            throw new TokenValidationError(sprintf('audience does not contain %s', $expectedAud));
        }

        // (4) 매핑 — 'exp'는 위에서 존재를 이미 강제했으므로(재차 isset하면 PHPStan이 "always exists"로
        // 지적) 바로 접근한다. 'iat'는 선택 클레임이라 isset로 방어한다.
        return new ValidatedToken(
            subject: isset($claims['sub']) ? self::toStr($claims['sub']) : '',
            audience: $aud,
            issuer: $iss,
            expiresAt: self::toInt($claims['exp']),
            issuedAt: isset($claims['iat']) ? self::toInt($claims['iat']) : null,
            claims: $claims,
        );
    }

    /** @return array<string,mixed> */
    private function decodeHeader(#[\SensitiveParameter] string $jwt): array
    {
        // 점을 먼저 센다 — explode 는 조각마다 값을 하나씩 만들어, 점만으로 된 토큰이 길이의 약 25 배를 썼다(실측).
        if (substr_count($jwt, '.') !== 2) {
            throw new TokenValidationError('malformed JWT');
        }
        $parts = explode('.', $jwt);
        $decoded = json_decode(FbJwt::urlsafeB64Decode($parts[0]), true);
        if (!is_array($decoded)) {
            throw new TokenValidationError('invalid JWT header');
        }

        return self::stringKeyed($decoded);
    }

    /** @return list<string> */
    private function normalizeAudience(mixed $aud): array
    {
        if (is_string($aud)) {
            return [$aud];
        }
        if (is_array($aud)) {
            return array_values(array_map(static fn (mixed $a): string => self::toStr($a), $aud));
        }

        return [];
    }

    /** mixed 값을 문자열로 안전하게 좁힌다(신뢰된 클레임의 스칼라 값만 통과). */
    private static function toStr(mixed $v, string $default = ''): string
    {
        return match (true) {
            \is_string($v) => $v,
            \is_int($v), \is_float($v), \is_bool($v) => (string) $v,
            default => $default,
        };
    }

    /** mixed 값을 정수로 안전하게 좁힌다(신뢰할 수 없는 클레임 값은 null). */
    private static function toInt(mixed $v): ?int
    {
        return match (true) {
            \is_int($v) => $v,
            \is_float($v) => (int) $v,
            \is_string($v) && \is_numeric($v) => (int) $v,
            default => null,
        };
    }

    /**
     * json_decode(..., true)의 배열은 키 타입이 array-key(int|string)로만 추론된다(숫자문자열 키는
     * PHP가 배열 키를 int로 강제 변환하는 관용 때문). JWT 헤더/클레임의 키는 항상 문자열이므로
     * 정수 키(있다면, 비표준 클레임명)를 걸러 string-keyed로 좁힌다(T5/T6의 stringKeyed와 동일 패턴 —
     * 로컬 헬퍼로 중복 유지, 공용화는 범위 밖).
     *
     * @param array<array-key, mixed> $a
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $a): array
    {
        $out = [];
        foreach ($a as $k => $v) {
            if (is_string($k)) {
                $out[$k] = $v;
            }
        }

        return $out;
    }
}
