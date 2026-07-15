<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Xzawed\Keycloak\Exception\KeycloakConfigError;

/**
 * 불변 설정. 시크릿은 PHP 관용상 string이며 마스킹으로 심층방어(char[] 소거는 PHP에서 불가 — 과대광고 금지).
 */
final readonly class KeycloakConfig
{
    public string $serverUrl;

    /** @var list<string> */
    public array $scopes;

    /** @var list<string> JWT 서명 검증 허용 알고리즘 핀(기본 RS256, ES256/PS256 realm용 설정 가능). */
    public array $signatureAlgorithms;

    /**
     * @param array<int, string> $scopes
     * @param array<int, string> $signatureAlgorithms
     */
    public function __construct(
        string $serverUrl,
        public string $realm,
        public string $clientId,
        #[\SensitiveParameter] public ?string $clientSecret = null,
        array $scopes = ['openid'],
        public float $connectTimeout = 5.0,
        public float $readTimeout = 10.0,
        public int $clockSkew = 30,
        public ?string $redirectUri = null,
        array $signatureAlgorithms = ['RS256'],
        /** 미해결 kid로 인한 JWKS 재조회의 최소 간격(초, 기본 60) — DoS 증폭 상한. */
        public int $jwksMinRefetchSeconds = 60,
    ) {
        if (trim($serverUrl) === '') {
            throw new KeycloakConfigError('serverUrl is required');
        }
        if (trim($this->realm) === '') {
            throw new KeycloakConfigError('realm is required');
        }
        if (trim($this->clientId) === '') {
            throw new KeycloakConfigError('clientId is required');
        }
        if ($signatureAlgorithms === []) {
            // 빈 집합은 alg 핀을 무력화한다(핀 없이는 alg 혼동에 노출) — 거부한다.
            throw new KeycloakConfigError('signatureAlgorithms must be non-empty');
        }
        if ($this->jwksMinRefetchSeconds < 0) {
            throw new KeycloakConfigError('jwksMinRefetchSeconds must be >= 0');
        }
        // 후행 슬래시 제거(엔드포인트 조립 규약)
        $this->serverUrl = rtrim($serverUrl, '/');
        $this->scopes = array_values($scopes);
        $this->signatureAlgorithms = array_values($signatureAlgorithms);
    }

    public function __toString(): string
    {
        return sprintf(
            'KeycloakConfig(serverUrl=%s, realm=%s, clientId=%s, clientSecret=%s)',
            $this->serverUrl,
            $this->realm,
            $this->clientId,
            Masking::mask($this->clientSecret),
        );
    }
}
