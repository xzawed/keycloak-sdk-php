<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Xzawed\Keycloak\Masking;

/**
 * stevenmaguire Keycloak 프로바이더는 pkceMethod 옵션을 무시한다(getPkceMethod()가 null 반환).
 * 이 서브클래스가 S256 PKCE를 강제한다. @internal
 *
 * 토큰 응답(client_credentials·refresh_token·authorization_code 세 grant)의 상한도 여기서 건다 — league 가 요청을 보내고 본문을
 * 해석하는 두 자리(`getResponse`·`parseResponse`)가 이 클래스의 것이다. 상한과 그 근거는 `TokenResponseCap` 이 소유한다.
 */
final class PkceKeycloakProvider extends Keycloak
{
    protected function getPkceMethod(): string
    {
        return self::PKCE_METHOD_S256;
    }

    /**
     * league 의 `send($request)` 에 상한 싱크를 단다(`TokenResponseCap::sink()`) — curl 은 상한+1 바이트를 넘기는 청크에서 전송을 끊는다.
     * 그렇게 끝난 요청은 Guzzle 예외가 아니라 `ResponseTooLarge` 로 나간다(`AuthClient` 가 `KeycloakTransportError` 로 바꾼다).
     * 오류 상태(4xx·5xx)의 본문도 같은 싱크를 지난다 — league 는 그 본문을 `parseResponse()` 로 읽는다.
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
     * 본문을 **한 번, 상한까지만** 읽고(`TokenResponseCap::read`) 상류(stevenmaguire `Keycloak::parseResponse` → league
     * `AbstractProvider::parseResponse`)와 같은 값을 낸다. ⚠️ 상류는 본문을 `(string)` 으로 **두 번** 읽어 사본 둘을 쥐었다(실측: 32 MiB
     * 본문에 Keycloak.php:394 와 AbstractProvider.php:786 — league 레인의 피크가 다른 레인의 두 배였다).
     *
     * 토큰·OAuth 오류 응답의 꼴 — 내용 타입이 `jwt`·`urlencoded` 가 아니고 본문이 문자열 키의 JSON 객체 — 은 여기서 바로 해석한다(상류의
     * 그 갈래와 같은 `json_decode($content, true)`). 그 밖(드문 갈래: jwt · urlencoded · JSON 이 아니거나 객체가 아닌 본문)은 읽은 본문을
     * 상류에 그대로 넘겨 상류가 해석하게 한다 — 상류의 예외·약한 모드 반환형 강제(스칼라 → 문자열, null → TypeError)·정수 키까지 같게
     * 두려는 것이다(그 갈래에서만 상한 안의 사본 둘을 감수한다). 상류와의 차등 검사: `PkceKeycloakProviderParseTest`.
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
