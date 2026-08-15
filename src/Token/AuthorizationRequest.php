<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

final readonly class AuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $state,
        #[\SensitiveParameter] public string $codeVerifier,
        // nonce는 인가 URL 쿼리에 실리는 재생 방지 값이라 비밀이 아니다
        // (state와 동급 — Kotlin/Python은 inspect에 그대로 노출, code_verifier만 마스킹).
        public string $nonce,
    ) {}
}
