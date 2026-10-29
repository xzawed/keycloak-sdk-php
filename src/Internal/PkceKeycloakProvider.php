<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Xzawed\Keycloak\Masking;

/**
 * The stevenmaguire Keycloak provider ignores the pkceMethod option (getPkceMethod() returns null).
 * This subclass enforces S256 PKCE. @internal
 *
 * The cap on token responses (the three grants client_credentials · refresh_token · authorization_code) is applied here too —
 * the two places where league sends the request and parses the body (`getResponse` · `parseResponse`) belong to this class.
 * The cap and its rationale are owned by `TokenResponseCap`.
 */
final class PkceKeycloakProvider extends Keycloak
{
    protected function getPkceMethod(): string
    {
        return self::PKCE_METHOD_S256;
    }

    /**
     * Attaches the capped sink (`TokenResponseCap::sink()`) to league's `send($request)` — curl cuts the transfer at the chunk
     * that passes cap+1 bytes. A request that ends that way goes out as `ResponseTooLarge`, not as a Guzzle exception
     * (`AuthClient` turns it into `KeycloakTransportError`). The body of an error status (4xx · 5xx) passes through the same
     * sink too — league reads that body with `parseResponse()`.
     */
    public function getResponse(RequestInterface $request): ResponseInterface
    {
        $sink = TokenResponseCap::sink();
        try {
            return $this->getHttpClient()->send($request, ['sink' => $sink]);
        } catch (\Throwable $e) {
            if (TokenResponseCap::overflowed($sink)) {
                throw new ResponseTooLarge('token response');
            }
            throw $e;
        }
    }

    /**
     * Reads the body **once, only up to the cap** (`TokenResponseCap::read`) and produces the same value as upstream
     * (stevenmaguire `Keycloak::parseResponse` → league `AbstractProvider::parseResponse`). ⚠️ Upstream read the body **twice**
     * with `(string)` and held two copies (measured: with a 32 MiB body, at Keycloak.php:394 and AbstractProvider.php:786 —
     * the league lane's peak was twice that of the other lanes).
     *
     * The shape of a token or OAuth error response — a content type that is not `jwt` · `urlencoded` and a body that is a JSON
     * object with string keys — is parsed right here (the same `json_decode($content, true)` as upstream's branch for it).
     * Anything else (the rare branches: jwt · urlencoded · a body that is not JSON or not an object) hands the read body to
     * upstream as is and lets upstream parse it — to keep upstream's exceptions, its weak-mode return type coercion (scalar →
     * string, null → TypeError) and even integer keys the same (only in those branches are two copies within the cap
     * accepted). Differential test against upstream: `PkceKeycloakProviderParseTest`.
     *
     * @return string|array<string, mixed>
     */
    protected function parseResponse(ResponseInterface $response): string|array
    {
        $content = TokenResponseCap::read($response->getBody());
        if ($content === null) {
            throw new ResponseTooLarge('token response');
        }
        $type = $this->getContentType($response);
        if (!str_contains($type, 'jwt') && !str_contains($type, 'urlencoded')) {
            $parsed = json_decode($content, true);
            if (\is_array($parsed)) {
                $object = self::stringKeyed($parsed);
                if ($object !== null) {
                    return $object;
                }
            }
        }

        return parent::parseResponse($response->withBody(Utils::streamFor($content)));
    }

    /**
     * 키가 전부 문자열인 배열(JSON 객체)이면 같은 순서·같은 값의 배열, 아니면 null.
     *
     * @param array<mixed> $a
     * @return array<string, mixed>|null
     */
    private static function stringKeyed(array $a): ?array
    {
        $out = [];
        foreach ($a as $k => $v) {
            if (!\is_string($k)) {
                return null;
            }
            $out[$k] = $v;
        }

        return $out;
    }

    /**
     * ⚠️ The dump family prints league's properties as they are — without this hook, `var_dump` printed the client secret and
     * the **live PKCE verifier** (`pkceCode`, filled by `createAuthorizationRequest()`) verbatim
     * (measured 2026-09-26). `encryptionKey` is the private key for encrypted tokens, so it is hidden as well.
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
