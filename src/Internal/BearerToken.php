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
 * The Bearer grammar — the same rule in all nine languages. Only SP · HTAB · CR · LF are trimmed from both ends (not NBSP ·
 * U+3000 · VT · FF), and the rest must be an RFC 6750 `b64token` (`1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`,
 * ASCII). @internal
 *
 * Two places use this one predicate. (1) The admin lane (`grantMiddleware`) — fschmtt gets the token itself, keeps it in its
 * own store and builds the header itself, so the SDK cannot rewrite the value sent (psr7 validates the header value in
 * `new Request()` — before the handler stack — and trims SP · HTAB from both ends). So from a token response it accepts only
 * a b64token that **needs no trimming**. (2) `ClientCredentialsTokenProvider` — it is its own cache, so it caches the trimmed
 * value.
 *
 * ⚠️ Before this predicate, lcobucci's base64url parsing happened to block that spot, and that depended on the sodium
 * extension — without sodium, lcobucci skipped whitespace, so a JWT carrying SP · HTAB at the front or in the middle went
 * out as is (measured 2026-10-29 — `Admin\AdminBearerGrammarTest`).
 */
final class BearerToken
{
    public const GRANT_REFUSED = 'admin token request failed: the access token is not a valid RFC 6750 bearer token (b64token)';

    public const PROVIDER_REFUSED = 'client-credentials failed: the access token is not a valid RFC 6750 bearer token (b64token)';

    /** 이 미들웨어의 거부를 다른 `RequestException` 과 가르는 Guzzle handler context 키 — `isRejection`. */
    private const REJECTION = 'xzawed_keycloak_bearer_grammar';

    /**
     * The value to put after Bearer (the trimmed token), or null if it cannot be sent. ⚠️ `trim()` with its default set also
     * trims NUL · VT — so the set is spelled out. The end is `\z` — `$` also matches before a trailing LF.
     */
    public static function sendable(#[\SensitiveParameter] string $token): ?string
    {
        $t = trim($token, " \t\r\n");

        return preg_match('/\A[A-Za-z0-9\-._~+\/]+=*\z/', $t) === 1 ? $t : null;
    }

    /**
     * Admin handler-stack middleware — in the 2xx response to a request picked by `$isTokenGrant` (fschmtt's token grant), if
     * the string `access_token` is not a b64token that needs no trimming, it rejects that grant with a Guzzle `RequestException`
     * (message `GRANT_REFUSED` · no response or cause). This is before fschmtt stores it, so nothing is cached (the next call
     * asks again) and no admin REST request goes out. Why it is Guzzle's: the same as `TokenResponseCap::middleware` — it
     * reaches a `raw()` consumer as is. A non-string `access_token` or a non-JSON body is rejected by fschmtt, as today.
     *
     * ⚠️ It goes **outside** `TokenResponseCap::middleware` in the stack — it sees the body the cap has judged.
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

    /** Whether this is this middleware's rejection — `Admin\ErrorTranslation` tells it apart from other `RequestException`s (transport failures). */
    public static function isRejection(\Throwable $e): bool
    {
        return $e instanceof RequestException && ($e->getHandlerContext()[self::REJECTION] ?? null) === true;
    }
}
