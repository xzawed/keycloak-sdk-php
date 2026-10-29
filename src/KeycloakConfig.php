<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Xzawed\Keycloak\Exception\KeycloakConfigError;

/**
 * 불변 설정. 시크릿은 PHP 관용상 string이며 마스킹으로 심층방어(char[] 소거는 PHP에서 불가 — 과대광고 금지).
 */
/**
 * ⚠️ __toString alone is not enough — the promoted properties are public, so json_encode() emits clientSecret
 * verbatim. That is why JsonSerializable is implemented as well.
 * Limit: __debugInfo() covers var_dump()/print_r()/debug_zval_dump() but **cannot cover
 * var_export()** (measured on PHP 8.3.32 — it prints even private properties verbatim). get_object_vars(),
 * an (array) cast, foreach and reading the public properties are also outside the boundary. Do not oversell this — it is
 * defence in depth against accidental logging, not a confidentiality boundary.
 */
final readonly class KeycloakConfig implements \JsonSerializable
{
    /**
     * The **single definition site** of the default JWKS minimum refetch interval (seconds). It is the DoS amplification cap,
     * and all nine languages are aligned on the same value — `scripts/test/test-security-defaults.sh` checks the nine
     * languages' code and the consumer docs together.
     *
     * ⚠️ Do not write this number anywhere else. It used to be written **twice** — 30 here and 60 in the `Jwks\JwksStore`
     * constructor — and since `JwksStore` is a `final class` with a public constructor, a consumer who constructed it
     * directly (not through the facade) got 60, not the 30 the docs state.
     */
    public const DEFAULT_JWKS_MIN_REFETCH_SECONDS = 30;

    public string $serverUrl;

    /** @var list<string> */
    public array $scopes;

    /** @var list<string> Pin of the algorithms allowed for JWT signature verification (default RS256; configurable for ES256/PS256 realms). */
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
        /** Minimum interval (seconds) between JWKS refetches caused by an unresolved kid — the DoS amplification cap. The default is the constant above. */
        public int $jwksMinRefetchSeconds = self::DEFAULT_JWKS_MIN_REFETCH_SECONDS,
        /**
         * The value the token's aud must contain (default null = clientId). A stock realm does not put clientId in a
         * client-credentials token's aud, so either set the resource/audience the realm actually issues, or add an
         * audience mapper to the Keycloak client. It applies only to access tokens (`validate()`) — the id_token aud in
         * `exchangeCode()` is always checked against clientId (OIDC Core §3.1.3.7).
         */
        public ?string $expectedAudience = null,
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
        // 실측(3초 지연 스텁): 0.0 은 Guzzle 이 타임아웃 없이 지연 전체를 기다리고, -1.0 은 호출이
        // 즉시 실패한다. 둘 다 쓸 수 없는 설정인데 생성이 조용히 됐다 — 유한하고 0보다 커야 한다.
        // clockSkew 음수도 거부한다.
        if (!is_finite($this->connectTimeout) || $this->connectTimeout <= 0.0) {
            throw new KeycloakConfigError('connectTimeout must be > 0');
        }
        if (!is_finite($this->readTimeout) || $this->readTimeout <= 0.0) {
            throw new KeycloakConfigError('readTimeout must be > 0');
        }
        if ($this->clockSkew < 0) {
            throw new KeycloakConfigError('clockSkew must be >= 0');
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

    /** @return array<string,mixed> */
    public function jsonSerialize(): array
    {
        return [
            'serverUrl' => $this->serverUrl,
            'realm' => $this->realm,
            'clientId' => $this->clientId,
            'scopes' => $this->scopes,
            'signatureAlgorithms' => $this->signatureAlgorithms,
            'connectTimeout' => $this->connectTimeout,
            'readTimeout' => $this->readTimeout,
            'clockSkew' => $this->clockSkew,
            'redirectUri' => $this->redirectUri,
            'jwksMinRefetchSeconds' => $this->jwksMinRefetchSeconds,
            'expectedAudience' => $this->expectedAudience,
            'clientSecret' => Masking::mask($this->clientSecret),
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
