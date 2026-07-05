<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT as FbJwt;
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
    private const PINNED_ALG = 'RS256';

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly OidcEndpoints $endpoints,
        private readonly JwksStore $jwks,
    ) {}

    public function validate(string $jwt): ValidatedToken
    {
        // (1) 헤더 사전 게이트 — firebase 디코드 이전에 우리가 직접 첫 세그먼트를 파싱해 alg를
        // RS256로 핀하고 none/미서명/다른 alg를 즉시 거부한다. firebase의 &$headers out-param은
        // 디코드가 *성공한 후에만* 채워지므로 사전 게이트로 쓸 수 없다(순서 함정).
        $header = $this->decodeHeader($jwt);
        $alg = isset($header['alg']) && is_string($header['alg']) ? $header['alg'] : null;
        if ($alg !== self::PINNED_ALG) {
            throw new TokenValidationError(sprintf('algorithm not allowed: %s', $alg ?? '(none)'));
        }
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
        if ($kid === null) {
            throw new TokenValidationError('missing kid');
        }

        // (2) JWKS에서 kid로 키 조회(DoS-safe, JwksStore) → firebase Key → 서명/exp/nbf 검증(클록 스큐 적용)
        $jwk = $this->jwks->getKeyByKid($kid);
        $prevLeeway = FbJwt::$leeway;
        FbJwt::$leeway = $this->config->clockSkew;
        try {
            try {
                $key = JWK::parseKey($jwk, self::PINNED_ALG);
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
                throw new TokenValidationError('token verification failed: ' . $e->getMessage(), previous: $e);
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
        if (!in_array($this->config->clientId, $aud, true)) {
            throw new TokenValidationError('audience does not contain clientId');
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
    private function decodeHeader(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new TokenValidationError('malformed JWT');
        }
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
