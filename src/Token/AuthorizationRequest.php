<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

use Xzawed\Keycloak\Masking;

/**
 * ⚠️ codeVerifier is the code exchange's **proof-of-possession secret** — an attacker who stole the authorization code
 * and gets this value from a log completes the flow. So __toString and JsonSerializable are both provided (the same
 * convention as the sibling TokenSet). url/state/nonce are not hidden — isomorphic with Rust's Debug impl.
 * Limit: __debugInfo() covers var_dump()/print_r()/debug_zval_dump() but **cannot cover
 * var_export()** (measured on PHP 8.3.32 — it prints even private properties verbatim). get_object_vars(),
 * an (array) cast, foreach and reading the public properties are also outside the boundary. Do not oversell this — it is
 * defence in depth against accidental logging, not a confidentiality boundary.
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

    /**
     * ⚠️ The dump family (`var_dump` · `print_r` · `debug_zval_dump`) **bypasses `__toString` and `jsonSerialize` and
     * reads the properties directly**. This hook covers that path (measured on PHP 8.3.32 — `print_r` honors this hook
     * too. ⚠️ **`var_export` does not honor it and prints even the private ones verbatim** — that is a boundary no hook
     * can close).
     *
     * The masking is not defined in two places — this delegates to `jsonSerialize()`, which is already masked.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }
}
