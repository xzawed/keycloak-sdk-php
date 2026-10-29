<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Bearer 의 문법 — 아홉 언어가 같은 규칙. 양끝의 SP·HTAB·CR·LF 만(NBSP·U+3000·VT·FF 는 아니다) 다듬고, 나머지가 RFC 6750
 * `b64token`(`1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`, ASCII)이어야 한다. @internal
 *
 * 두 자리가 이 술어 하나를 쓴다. (1) admin 레인(`grantMiddleware`) — fschmtt 가 토큰을 스스로 받아 자기 저장소에 두고 헤더도 스스로
 * 만들어, SDK 는 보내는 값을 고쳐 쓸 수 없다(psr7 은 `new Request()` 에서 — 핸들러 스택보다 먼저 — 헤더 값을 검증하고 양끝 SP·HTAB 을
 * 다듬는다). 그래서 토큰 응답에서 **다듬을 필요가 없는** b64token 만 받는다. (2) `ClientCredentialsTokenProvider` — 자기 캐시라 다듬은
 * 값을 캐시한다.
 *
 * ⚠️ 이 술어 전에는 lcobucci 의 base64url 해석이 우연히 그 자리를 막았고, 그것은 sodium 확장에 달렸다 — sodium 이 없으면 lcobucci 가
 * 공백을 건너뛰어 앞이나 가운데에 SP·HTAB 을 실은 JWT 가 그대로 나갔다(실측 2026-10-29 — `Admin\AdminBearerGrammarTest`).
 */
final class BearerToken
{
    public const GRANT_REFUSED = 'admin token request failed: the access token is not a valid RFC 6750 bearer token (b64token)';

    public const PROVIDER_REFUSED = 'client-credentials failed: the access token is not a valid RFC 6750 bearer token (b64token)';

    /** 이 미들웨어의 거부를 다른 `RequestException` 과 가르는 Guzzle handler context 키 — `isRejection`. */
    private const REJECTION = 'xzawed_keycloak_bearer_grammar';

    /**
     * Bearer 뒤에 실을 값(다듬은 토큰), 또는 실을 수 없으면 null. ⚠️ 기본 `trim()` 은 NUL·VT 도 다듬는다 — 집합을 적는다. 끝은
     * `\z` 다 — `$` 는 끝 LF 앞에서도 맞는다.
     */
    public static function sendable(#[\SensitiveParameter] string $token): ?string
    {
        $t = trim($token, " \t\r\n");

        return preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/', $t) === 1 ? $t : null;
    }

    /**
     * admin 핸들러 스택 미들웨어 — `$isTokenGrant` 가 고르는 요청(fschmtt 의 토큰 부여)의 2xx 응답에서 문자열 `access_token` 이 다듬을
     * 필요 없는 b64token 이 아니면 그 부여를 Guzzle `RequestException`(메시지 `GRANT_REFUSED` · 응답·원인 없음)으로 거부한다. fschmtt 가
     * 받아 두기 전이라 캐시되지 않고(다음 호출이 다시 묻는다) admin REST 요청은 나가지 않는다. Guzzle 의 것인 이유는
     * `TokenResponseCap::middleware` 와 같다 — `raw()` 소비자에게 그대로 닿는다. 문자열이 아닌 `access_token`·JSON 이 아닌 본문은 오늘처럼
     * fschmtt 가 거부한다.
     *
     * ⚠️ 스택에서 `TokenResponseCap::middleware` 의 **바깥**에 둔다 — 상한이 판정한 본문을 본다.
     *
     * @param \Closure(RequestInterface): bool $isTokenGrant
     * @return \Closure(callable(RequestInterface, array<string, mixed>): PromiseInterface): (\Closure(RequestInterface, array<string, mixed>): PromiseInterface)
     */
    public static function grantMiddleware(\Closure $isTokenGrant): \Closure
    {
        return static fn (callable $handler): \Closure => static function (RequestInterface $request, array $options) use ($handler, $isTokenGrant): PromiseInterface {
            $result = $handler($request, $options);
            $promise = $result instanceof PromiseInterface ? $result : Create::promiseFor($result);
            if (!$isTokenGrant($request)) {
                return $promise;
            }

            return $promise->then(static function (ResponseInterface $response) use ($request): ResponseInterface {
                $status = $response->getStatusCode();
                if ($status < 200 || $status >= 300) {
                    return $response;   // 오류 응답은 http_errors 와 `Admin\ErrorTranslation` 의 몫이다
                }
                $raw = (string) $response->getBody();
                // 잘못된 UTF-8 은 U+FFFD 로 읽는다 — 그 바이트를 담은 토큰도 문법 밖이다(fschmtt 의 json_decode 는 본문째 거부한다).
                $json = json_decode($raw, true, 512, JSON_INVALID_UTF8_SUBSTITUTE);
                $token = \is_array($json) ? ($json['access_token'] ?? null) : null;
                if (\is_string($token) && self::sendable($token) !== $token) {
                    throw new RequestException(self::GRANT_REFUSED, $request, null, null, [self::REJECTION => true]);
                }

                return $response->withBody(Utils::streamFor($raw));   // 위에서 끝까지 읽었다 — fschmtt 는 처음부터 읽는다
            });
        };
    }

    /** 이 미들웨어의 거부인가 — `Admin\ErrorTranslation` 이 다른 `RequestException`(전송 실패)과 가른다. */
    public static function isRejection(\Throwable $e): bool
    {
        return $e instanceof RequestException && ($e->getHandlerContext()[self::REJECTION] ?? null) === true;
    }
}
