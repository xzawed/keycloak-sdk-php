<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * How much of an admin response body is received — registry admin-response-body-unbounded. A body fschmtt does not read is
 * not received (the 2xx of a request other than GET·HEAD — commands discard the response and lookups are GET only: the
 * premise pin in `AdminResponseBodyTest`), and an error body (300 and up) is cut at the token response cap — requests
 * from `AdminClient::raw()` too. A GET's 2xx is received to the end, as now (user lists are legitimately large). The
 * token grant is not touched (that is `TokenResponseCap`'s job).
 *
 * curl hands over the response only once the transfer ends (the body flows into the sink before that), so the decision is
 * made **during** the transfer: `on_headers` looks at the final response's status — if a non-GET 2xx has a body it ends the
 * transfer (a body whose framing was announced, at the head; any other, at the first body byte), and at 300 or above it
 * receives the body with `TokenResponseCap::sink()` (it answers short on the write that holds cap + 1 bytes, so curl ends
 * the transfer and the stream handler ends the copy). Only the rejection of a transfer it ended **itself** that way is
 * revived, by attaching the kept body to the response received as the head — so that the outer `http_errors` and
 * `Admin\ErrorTranslation` choose by status. Any other rejection (a transport failure) is passed on as is.
 *
 * ⚠️ curl calls `on_headers` for heads that are not the final response too — an interim response (`100 Continue` —
 * Guzzle adds `Expect` to a request body of 1 MiB or more) and a proxy tunnel's `200 Connection established`
 * (`HTTPS_PROXY` for an https target). Taking that as the write's response and cutting returns the request as a success
 * without it ever reaching the server (measured — the version before both fixes did that). So 1xx is skipped (including
 * one framed in violation of the spec), a 2xx without framing (`framed`) is not cut at the head (a spec-conforming CONNECT
 * 200 has no framing — RFC 9110 §9.3.6), and a request a proxy can step into is never cut at the head at all
 * (`mayUseProxy`) — the head of a proxy that violates the spec and frames that 200 cannot be told apart from the origin
 * server's (flagged by Grok leg 2 — it returned 200 as a success without even sending the PUT past the tunnel). A 2xx not
 * cut at the head is cut at the first byte when body bytes arrive (so an unframed 204 does not lose the connection) — a
 * CONNECT's response passes no bytes to the sink. The price: behind a proxy, a 2xx that stalls without body bytes holds on
 * until the read timeout, as before the fix.
 * ⚠️ `CURLOPT_SUPPRESS_CONNECT_HEADERS`, which hides the CONNECT head, is not used — it is outside Guzzle's curl option
 * allow list, so it raises E_USER_DEPRECATED on every request and guzzlehttp/guzzle 8 rejects it (flagged by Grok leg 3 ·
 * measured). With the stream handler, PHP's http wrapper reads and discards the CONNECT head (php-src
 * `ext/standard/http_fopen_wrapper.c`).
 * ⚠️ A 2xx without a body (Keycloak's write responses — an unframed 204 · a 201 with `Content-Length: 0`) is not cut at
 * the head — there is nothing to cut, and cutting only makes curl lose the connection it would use for the next request.
 * ⚠️ The sink does not throw — curl received the body to the end even with that exception (measured). The stream handler
 * stops copying on the sink's short write (cap · first-byte refusal) from guzzlehttp/psr7 2.11 on (`copyToStream`, which
 * retries a short write) — older versions read a body that announced its Content-Length to the end, and only the
 * amount held is capped.
 *
 * @internal
 */
final class AdminResponseBody
{
    /**
     * Admin handler-stack middleware — requests picked by `$isTokenRequest` (fschmtt's token grant) are sent as they are.
     *
     * @param \Closure(RequestInterface): bool $isTokenRequest
     * @return \Closure(callable(RequestInterface, array<string, mixed>): PromiseInterface): (\Closure(RequestInterface, array<string, mixed>): PromiseInterface)
     */
    public static function middleware(\Closure $isTokenRequest): \Closure
    {
        return static fn (callable $handler): \Closure => static function (RequestInterface $request, array $options) use ($handler, $isTokenRequest): PromiseInterface {
            if ($isTokenRequest($request)) {
                return self::promise($handler($request, $options));
            }
            $direct = !self::mayUseProxy($options);   // 프록시가 끼어들 수 있으면 머리에서 끊지 않는다 — 클래스 docblock
            $head = null;     // 최종 응답의 머리
            $error = false;   // 300 이상 — 본문을 상한에서 자른다
            $unread = false;  // fschmtt 가 읽지 않는 2xx 본문 — 받지 않는다
            $cut = false;     // 이 미들웨어가 2xx 의 전송을 끊었다 — 그 거부만 머리로 되살린다
            // 2xx 본문을 받는 요청 — fschmtt 의 조회(GET)와, 본문이 없는 HEAD(RFC 9110 §9.3.2 — `raw()->resource()` 의 명령이 보낸다).
            $reads = \in_array($request->getMethod(), ['GET', 'HEAD'], true);
            $options['on_headers'] = static function (ResponseInterface $response) use (&$head, &$error, &$unread, &$cut, $reads, $direct): void {
                if ($response->getStatusCode() < 200) {
                    return;   // 중간 응답 — 클래스 docblock
                }
                $head = $response;
                $error = $response->getStatusCode() >= 300;
                // 본문 없다는 2xx 도 싱크는 바이트를 받지 않는다 — 스트림 처리기는 `Content-Length: 0` 을 길이 미상으로 보고 EOF 까지
                // 복사한다(Guzzle `StreamHandler::drain`). 머리에서 끊는 것은 틀을 알린 본문뿐이다.
                $unread = !$error && !$reads;
                if ($unread && $direct && !self::bodiless($response) && self::framed($response)) {
                    $cut = true;
                    throw new \RuntimeException('admin response body left unread');   // 본문 전에 전송을 끝낸다
                }
            };
            $plain = Utils::streamFor(Utils::tryFopen('php://temp', 'r+'));   // Guzzle 의 기본 싱크와 같다
            $capped = TokenResponseCap::sink();
            $options['sink'] = FnStream::decorate($plain, [
                // ⚠️ 화살표 함수로 바꾸지 말 것 — 그것은 `$error`·`$unread` 를 만들 때의 값(거짓)으로 잡는다.
                'write' => static function (string $data) use (&$error, &$unread, &$cut, $capped, $plain): int {
                    if ($unread) {
                        $cut = true;
                        return 0;   // GET·HEAD 가 아닌 요청의 2xx 본문 바이트(틀이 없는 본문 · 본문 없다는 응답 뒤) — 받지 않고 끝낸다
                    }

                    return $error ? $capped->write($data) : $plain->write($data);
                },
            ]);

            return self::promise($handler($request, $options))->then(
                static function (ResponseInterface $response) use (&$error, $capped): ResponseInterface {
                    return $error ? self::withKept($response, $capped) : $response;
                },
                static function (mixed $reason) use (&$head, &$error, &$cut, $capped): ResponseInterface|PromiseInterface {
                    if ($head instanceof ResponseInterface && $cut) {
                        return $head->withBody(Utils::streamFor(''));
                    }
                    if ($head instanceof ResponseInterface && $error && TokenResponseCap::overflowed($capped)) {
                        return self::withKept($head, $capped);   // 싱크의 짧은 쓰기에 curl 이 끊은 전송
                    }

                    return Create::rejectionFor($reason);
                },
            );
        };
    }

    /**
     * 본문이 없다고 머리가 말하는 응답 — `Content-Length: 0`. 204 는 따로 가르지 않는다: 규격대로면 204 에는 틀이 없어(`framed`)
     * 머리에서 끊기지 않고, 규격을 어겨 길이를 단 204 는 끊어도 결과가 같다(실측: 어느 쪽이든 다음 요청은 새 연결로 간다).
     */
    private static function bodiless(ResponseInterface $response): bool
    {
        return $response->getHeaderLine('Content-Length') === '0';
    }

    /**
     * 이 요청에 프록시가 끼어들 수 있는가 — 요청 옵션 `proxy` 의 프록시(Guzzle `Client` 가 `HTTPS_PROXY`·CLI 의 `HTTP_PROXY` 를 거기로
     * 옮긴다 · `no` 목록만으로는 프록시가 아니다)나, 그 옵션이 정하지 않을 때 Guzzle·libcurl 이 읽는 환경변수. 넓게 본다 — 이 요청에
     * 쓰이지 않을 프록시(다른 스킴 · `no` 목록에 든 호스트)도 「끼어들 수 있다」: 틀리게 「없다」고 하면 머리에서 끊어 규격을 어긴
     * 프록시의 CONNECT 200 에 속고, 틀리게 「있다」고 하면 첫 바이트에서 끊을 뿐이다.
     *
     * @param array<mixed> $options
     */
    private static function mayUseProxy(array $options): bool
    {
        $proxy = $options['proxy'] ?? null;
        if (\is_string($proxy) && $proxy !== '') {
            return true;
        }
        if (\is_array($proxy)) {
            foreach ($proxy as $url) {   // 스킴별 프록시 URL — `no` 는 호스트 배열이라 여기서 걸러진다
                if (\is_string($url) && $url !== '') {
                    return true;
                }
            }
        }
        foreach (['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'] as $name) {
            $value = \getenv($name);
            if (\is_string($value) && $value !== '') {
                return true;
            }
        }

        return false;
    }

    /**
     * 본문의 틀을 머리가 알리는 응답 — 본문이 온다고 알렸으니 머리에서 끊는다(프록시가 끼어들 수 없을 때만 — `mayUseProxy`).
     * 규격대로인 204 에는 틀이 없다(RFC 9110 §8.6 —
     * Keycloak 26.6 의 쓰기 204 도 그렇다). Guzzle 은 압축을 풀 때 Content-Length 를 `X-Encoded-Content-Length` 로 옮긴다.
     * ⚠️ PHP 의 http 래퍼(스트림 처리기)는 청크를 풀며 `Transfer-Encoding` 을 머리에 남기지 않는다 — 그 응답은 여기서 틀이 없다고
     * 보여 첫 본문 바이트에서 끊는다(`AdminResponseBodyTest::headStallRows`).
     */
    private static function framed(ResponseInterface $response): bool
    {
        return $response->hasHeader('Content-Length') || $response->hasHeader('Transfer-Encoding') || $response->hasHeader('X-Encoded-Content-Length');
    }

    /**
     * 오류 응답에 남긴 본문(상한 싱크의 앞 `TOKEN_RESPONSE_MAX_BYTES` 바이트)을 단다 — `Content-Length` 가 있으면 남긴 길이로 맞춘다.
     * 서버가 알린 길이를 그대로 두면 `raw()` 소비자가 그 응답을 다시 내보낼 때 상대가 오지 않을 바이트를 기다리거나 잘린 전송으로
     * 실패한다(연결이 살아 있으면 상대의 타임아웃까지 · 닫히면 그 자리에서). 없으면(청크 ·
     * Guzzle 이 압축을 풀며 뗀 것) 더하지 않는다.
     */
    private static function withKept(ResponseInterface $response, StreamInterface $capped): ResponseInterface
    {
        $capped->rewind();
        $kept = substr($capped->getContents(), 0, TokenResponseCap::TOKEN_RESPONSE_MAX_BYTES);
        $response = $response->withBody(Utils::streamFor($kept));

        return $response->hasHeader('Content-Length') ? $response->withHeader('Content-Length', (string) \strlen($kept)) : $response;
    }

    /** `TokenResponseCap::promise` 와 같은 정규화 — 핸들러의 반환을 약속으로 세운다. */
    private static function promise(mixed $result): PromiseInterface
    {
        return $result instanceof PromiseInterface ? $result : Create::promiseFor($result);
    }
}
