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
 * Self-hardened JWT validator: enforces the RS256 algorithm pin (the header is not trusted) · none/unsigned rejection ·
 * exact iss match · aud membership check · required exp · nbf · clock skew · DoS-safe JWKS (JwksStore).
 * firebase/php-jwt is used only as the signature/exp/nbf verification primitive; the up-front alg pin, iss and aud are
 * enforced by this class.
 */
final class JwtValidator
{
    /**
     * Byte cap on an incoming JWT — past it, the token is rejected **before any splitting or decoding**.
     *
     * This path splits the token and json_decodes the header and payload before it looks at the signature. Without a cap, a
     * header carrying a deeply nested JSON array allocated about 167 B per token byte, and a single 768 KiB token ended the
     * request with a fatal OOM under the default `memory_limit` of 128M (a wide array: about 95 B · 1.5 MiB, measured). An
     * attacker-triggered fatal OOM error is the trigger of PHP2Shell (CVE-2026-109618 · CVE-2026-109619), and even on a patched
     * PHP it is a DoS that kills the request. 256000 equals Microsoft.IdentityModel's `DefaultMaximumTokenSizeInBytes`, which the
     * .NET SDK uses, and is about 3.9 times the longest Bearer Keycloak 26.6 accepts with its default settings (65,459 B). The
     * most expensive shape measured at this length (an array nested 500 deep, about 86 B per byte) is a little over 22 MB —
     * `JwtValidatorTest` asserts it stays below 1/4 of the default limit, so raising the cap turns that test red first.
     */
    public const JWT_MAX_BYTES = 256000;

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly OidcEndpoints $endpoints,
        private readonly JwksStore $jwks,
    ) {}

    /**
     * Validates an access token — the expected aud is `expectedAudience` (when set), otherwise `clientId`.
     */
    public function validate(#[\SensitiveParameter] string $jwt): ValidatedToken
    {
        return $this->verify($jwt, $this->config->expectedAudience ?? $this->config->clientId);
    }

    /**
     * Validates an id_token — its aud must contain `$clientId` (OIDC Core §2 · §3.1.3.7: an id_token's aud is the client
     * that requested it). `expectedAudience` is **not consulted** — that is an access token's resource-server restriction
     * (RFC 9700 §2.3). The rest (alg pin · kid · signature · required exp · clock skew · iss) is the same path as validate(),
     * and the JWKS store is the same one too. Comparing the nonce is the caller's job — `AuthClient::exchangeCode()` calls
     * this and compares it.
     *
     * @throws KeycloakConfigError  when `$clientId` is empty
     * @throws TokenValidationError on a validation failure
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
