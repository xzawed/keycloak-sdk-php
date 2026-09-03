<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

use Xzawed\Keycloak\Masking;

/**
 * ⚠️ codeVerifier 는 코드 교환의 **소유 증명 비밀**이다 — 인가 코드를 훔친 공격자가 로그에서
 * 이 값을 얻으면 흐름을 완성한다. 그래서 __toString 과 JsonSerializable 을 함께 둔다(형제
 * TokenSet 과 같은 규약). url/state/nonce 는 가리지 않는다 — Rust 의 Debug impl 과 동형이다.
 * 한계: var_dump()/print_r() 는 여전히 프로퍼티를 직접 읽는다.
 */
final readonly class AuthorizationRequest implements \JsonSerializable
{
    public function __construct(
        public string $url,
        public string $state,
        #[\SensitiveParameter] public string $codeVerifier,
        // nonce는 인가 URL 쿼리에 실리는 재생 방지 값이라 비밀이 아니다
        // (state와 동급 — Kotlin/Python은 inspect에 그대로 노출, code_verifier만 마스킹).
        public string $nonce,
    ) {}

    public function __toString(): string
    {
        return \sprintf(
            'AuthorizationRequest(url=%s, state=%s, nonce=%s, codeVerifier=%s)',
            $this->url,
            $this->state,
            $this->nonce,
            Masking::mask($this->codeVerifier),
        );
    }

    /** @return array<string,mixed> */
    public function jsonSerialize(): array
    {
        return [
            'url' => $this->url,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'codeVerifier' => Masking::mask($this->codeVerifier),
        ];
    }
}
