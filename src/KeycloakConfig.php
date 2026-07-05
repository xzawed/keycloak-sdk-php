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

    /**
     * @param array<int, string> $scopes
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
        // 후행 슬래시 제거(엔드포인트 조립 규약)
        $this->serverUrl = rtrim($serverUrl, '/');
        $this->scopes = array_values($scopes);
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
