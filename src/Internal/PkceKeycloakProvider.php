<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Xzawed\Keycloak\Masking;

/**
 * stevenmaguire Keycloak 프로바이더는 pkceMethod 옵션을 무시한다(getPkceMethod()가 null 반환).
 * 이 서브클래스가 S256 PKCE를 강제한다. @internal
 */
final class PkceKeycloakProvider extends Keycloak
{
    protected function getPkceMethod(): string
    {
        return self::PKCE_METHOD_S256;
    }

    /**
     * ⚠️ 덤프 계열은 league 의 프로퍼티를 그대로 찍는다 — 이 훅이 없을 때 `var_dump` 가 클라이언트 시크릿과
     * **살아 있는 PKCE verifier**(`pkceCode`, `createAuthorizationRequest()` 가 채운다)를 원문으로 찍었다
     * (실측 2026-09-26). `encryptionKey` 는 암호화 토큰용 개인키라 함께 가린다.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'authServerUrl' => $this->authServerUrl,
            'realm' => $this->realm,
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret === null || $this->clientSecret === '' ? $this->clientSecret : Masking::mask($this->clientSecret),
            'redirectUri' => $this->redirectUri,
            'pkceCode' => $this->pkceCode === null ? null : Masking::mask($this->pkceCode),
            'encryptionKey' => $this->encryptionKey === null ? null : Masking::mask($this->encryptionKey),
        ];
    }
}
