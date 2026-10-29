<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Cap on the response bodies of the token endpoint (every grant — the auth lane, and the admin lane's own token),
 * introspection and logout. However many lanes there are, it is this one constant (`PkceKeycloakProvider` ·
 * `AuthClient::introspect` · `logout` · `ClientCredentialsTokenProvider` · `Admin\AdminClient`). @internal
 *
 * ⚠️ There used to be no cap — all six lanes accepted a response with 32 MiB of JSON whitespace appended after a usable
 * token (zend peak: league 75 MB · the rest 40 MB), and a body larger than memory_limit ended the process with an
 * uncatchable fatal error (exit 255) (measured 2026-10-03).
 *
 * Two layers. (1) The **sink** (`sink()`) — it stops the stream Guzzle writes the response body into at cap+1 bytes. curl
 * cuts the transfer on the short write (CURLE_WRITE_ERROR) and psr7's copy (the stream handler) stops (psr7 2.11 and up —
 * `AdminResponseBody`'s docblock) — not just memory but the **transfer** ends near the cap.
 * curl passes decompressed bytes in chunks of at most 16,384 bytes (CURL_MAX_WRITE_SIZE), so what is received before the
 * cut is up to the one chunk that passes cap+1 (the sink stores only up to cap+1 bytes of that chunk). (2) The **reader**
 * (`read()`) — it reads that body once, at most up to cap+1 bytes; it returns null if the body went over, and it fails if it stalls
 * before signaling its end (`ResponseStalled`). Only the reader decides — the paths that do not use the sink (PSR-18
 * `sendRequest()`, a handler the consumer passed in) also go through here.
 *
 * ⚠️ Why not switch to `'stream' => true`: Guzzle then sends the request with PHP's stream handler instead of curl — the
 * connection time limit (`connect_timeout`) is ignored (measured: an unreachable address with `connect_timeout` 1 s ·
 * `timeout` 4 s — curl 1,018 ms, stream 4,004 ms), and the zlib filter decompressed gzip ahead, past the cap (measured: for
 * 32 MiB of gzip a process zend peak of 14 MB, with the sink 4.4 MB). The source of the TLS trust store also changes from
 * `curl.cainfo` to PHP OpenSSL (`openssl.cafile`) (source: `StreamHandler::add_verify` turns on verification only, without
 * a cafile). A body within the cap has to ride the same transfer as today.
 *
 * ⚠️ Do not borrow 51200 (the JWKS cap, `JwksStore::JWKS_MAX_BYTES`) — the longest Bearer Keycloak 26.6 accepts with its
 * default settings is 65,459 bytes (a service-account token grows with every realm it manages). 1 MiB is 16 times that, so
 * no token the server accepts is refused.
 */
final class TokenResponseCap
{
    /** ⚠️ A cross-language guard extracts this value — keep it a bare decimal literal, not an expression (`1 << 20`). All nine languages use the same value. */
    public const TOKEN_RESPONSE_MAX_BYTES = 1048576;

    /** 판독기가 한 번에 청하는 바이트 — PHP `fread` 는 청한 길이만큼 미리 잡으므로 상한을 한 번에 청하지 않는다. */
    private const READ_CHUNK_BYTES = 8192;

    /** admin 미들웨어의 상한 거부를 다른 `RequestException` 과 가르는 Guzzle handler context 키 — 그 미들웨어만 단다(`isRejection`). */
    private const REJECTION = 'xzawed_keycloak_token_response_cap';

    /**
     * Reads the body from the start and returns its bytes if it is within the cap, or null if it is over. The bytes **taken**
     * from the stream are at most cap+1 (up to the one byte that shows it went over — PSR-7 `read()` never gives more than
     * requested), and a single request is at most min(8 KiB, cap+1 − bytes already taken). The string grows only by what
     * was taken. If the stream is seekable it reads from the start (the same as `(string) $body`). It closes the stream once
     * read — an over-cap body is not drained to the end.
     *
     * ⚠️ The **sum** of bytes requested is not bounded — a stream that gives less than requested is asked again, so the sum
     * goes past cap+1 (measured: a 2,048-byte body that gives 1 byte at a time was asked 2,049 times, a sum of 16,785,408 ·
     * 2,048 taken). What is bounded is the bytes taken and a single request.
     *
     * ⚠️ It stops at an empty read that is not the end (EOF) and **fails** (`ResponseStalled`) — it does not judge by the
     * bytes read so far (the same rule as `JwksStore::readCapped`). It used to stop at that empty read and return the front
     * part, so when a body that does not signal EOF (a delayed body from a transport the consumer injected) stalled once,
     * the front part of a response whose end was never seen was accepted (measured 2026-10-09: a 2 MiB token response that
     * stalled once at 1,000,000 bytes — over the cap without the stall — was accepted by all five lanes). An empty read that
     * finds the end (a PHP stream's `eof()` is true only after that read) is a normal end. A request is always at least
     * 1 byte, so an empty read cannot be the reader's fault.
     *
     * ⚠️ A read error from the stream is thrown as is — the receiving side turns it into an SDK error at its own boundary (so
     * the exception's trace arguments are not carried out). A stall, for the same reason, is a carrier rather than an SDK
     * exception — unlike `JwksStore::readCapped`, this reader is also called **inside** league's and Guzzle's frames (whose
     * arguments hold refresh_token · code · client_secret), and `SanitizedCause` leaves SDK exceptions as they are instead of
     * turning them into copies.
     *
     * @throws ResponseStalled an empty read that is not the end
     */
    public static function read(StreamInterface $body): ?string
    {
        try {
            if ($body->isSeekable()) {
                $body->rewind();
            }
            $buf = '';
            $empty = false;
            while (!$body->eof()) {
                if ($empty) {
                    throw new ResponseStalled();   // 빈 읽기 뒤에도 끝이 아니다 — 끝을 찾은 빈 읽기였다면 위 조건이 루프를 끝냈다
                }
                $chunk = $body->read(min(self::READ_CHUNK_BYTES, self::TOKEN_RESPONSE_MAX_BYTES + 1 - \strlen($buf)));
                $empty = $chunk === '';
                $buf .= $chunk;
                if (\strlen($buf) > self::TOKEN_RESPONSE_MAX_BYTES) {
                    return null;
                }
            }

            return $buf;
        } finally {
            try {
                $body->close();
            } catch (\Throwable) {
                // 닫기는 정리일 뿐이다 — 판정(또는 원래 오류)을 덮지 않는다.
            }
        }
    }

    /**
     * The body stream passed to Guzzle's `sink` request option — it stores only up to cap+1 bytes, and the write that stores
     * that byte returns one less than it stored (short). Writes after that return 0. Storing the (cap+1)th byte is the point —
     * that is how the reader knows "it went over".
     *
     * ⚠️ Why the write that stored that byte returns short: if it reported everything as taken, the short write would only
     * happen on receiving the **next** byte — in front of a server that sent exactly cap+1 bytes and stopped, both transports
     * were held until the read timeout (the token cells of `AdminResponseBodyTest`).
     */
    public static function sink(): StreamInterface
    {
        $buffer = Utils::streamFor(Utils::tryFopen('php://memory', 'r+'));

        return FnStream::decorate($buffer, [
            'write' => static function (string $data) use ($buffer): int {
                $room = self::TOKEN_RESPONSE_MAX_BYTES + 1 - (int) $buffer->getSize();
                if ($room <= 0) {
                    return 0;
                }
                $written = $buffer->write(\strlen($data) <= $room ? $data : substr($data, 0, $room));

                return self::overflowed($buffer) ? $written - 1 : $written;
            },
        ]);
    }

    /** Whether the sink received a body over the cap — for a request that ended in an exception because its transfer was cut, it tells the reason apart. */
    public static function overflowed(StreamInterface $sink): bool
    {
        return (int) $sink->getSize() > self::TOKEN_RESPONSE_MAX_BYTES;
    }

    /**
     * The admin lane's handler-stack middleware — it attaches the sink only to requests picked by `$isTokenRequest` (fschmtt's
     * token grant), reads the received body once with the reader and passes it on as a new body of the same bytes. If it is
     * over, it rejects that request with a Guzzle `RequestException` (message `"$what exceeds 1048576
     * bytes"`), and if the reader stalls before seeing the end, in the same form (`"$what stalled before its end"`) — the
     * request ends here and no admin REST request goes out. Other requests (legitimately large admin responses such as user
     * lists) are not touched.
     *
     * ⚠️ Why the rejection is Guzzle's rather than an SDK exception: this stack belongs to the fschmtt client that
     * `AdminClient::raw()` exposes, so what is thrown here reaches a consumer using the escape hatch **as is** (§4(b) — raw()
     * exposes the underlying client and the errors it raises). So it has to be of the underlying family that consumer catches
     * (`GuzzleException`); the message is only the cap wording, and neither the response (the received body — it holds the
     * token) nor a cause is attached. On the facade side, `Admin\ErrorTranslation` picks it out with `isRejection()` and turns
     * it into a `KeycloakTransportError` without a cause.
     *
     * ⚠️ It goes at the **innermost** position of the stack (`push`) — it has to receive the response before http_errors so
     * that a 4xx error body also goes through the cap, and that middleware and `Admin\ErrorTranslation` see a rewindable body.
     *
     * @param \Closure(RequestInterface): bool $isTokenRequest
     * @return \Closure(callable(RequestInterface, array<string, mixed>): PromiseInterface): (\Closure(RequestInterface, array<string, mixed>): PromiseInterface)
     */
    public static function middleware(\Closure $isTokenRequest, string $what): \Closure
    {
        return static fn (callable $handler): \Closure => static function (RequestInterface $request, array $options) use ($handler, $isTokenRequest, $what): PromiseInterface {
            if (!$isTokenRequest($request)) {
                return self::promise($handler($request, $options));
            }
            $sink = self::sink();
            $options['sink'] = $sink;

            $exceeds = sprintf('%s exceeds %d bytes', $what, self::TOKEN_RESPONSE_MAX_BYTES);   // `ResponseTooLarge` 와 같은 꼴

            return self::promise($handler($request, $options))->then(
                static function (ResponseInterface $response) use ($request, $what, $exceeds): ResponseInterface {
                    try {
                        $body = self::read($response->getBody());
                    } catch (ResponseStalled) {
                        throw self::rejection($request, "$what stalled before its end");   // 운반체를 raw() 로 내보내지 않는다
                    }
                    if ($body === null) {
                        throw self::rejection($request, $exceeds);
                    }

                    return $response->withBody(Utils::streamFor($body));
                },
                static function (mixed $reason) use ($request, $sink, $exceeds): PromiseInterface {
                    if (self::overflowed($sink)) {
                        throw self::rejection($request, $exceeds);   // curl 이 짧은 쓰기에 끊은 전송(CURLE_WRITE_ERROR)
                    }

                    return Create::rejectionFor($reason);
                },
            );
        };
    }

    /** Whether this is the middleware's rejection (over the cap · stalled) — `Admin\ErrorTranslation` tells it apart from other `RequestException`s (transport failures). */
    public static function isRejection(\Throwable $e): bool
    {
        return $e instanceof RequestException && ($e->getHandlerContext()[self::REJECTION] ?? null) === true;
    }

    /** 미들웨어의 거부 — 요청만 달고(응답·원인 없음) 표시를 handler context 에 둔다. 메시지는 SDK 가 만든 문구뿐이다. */
    private static function rejection(RequestInterface $request, string $message): RequestException
    {
        return new RequestException($message, $request, null, null, [self::REJECTION => true]);
    }

    /**
     * 미들웨어가 받는 핸들러는 이름 없는 `callable` 이다 — 그 반환을 약속으로 세운다. Guzzle `Client::transfer` 가 핸들러의 반환에
     * 하는 것과 같은 정규화(`Create::promiseFor`)라 약속은 그대로 지나간다.
     */
    private static function promise(mixed $result): PromiseInterface
    {
        return $result instanceof PromiseInterface ? $result : Create::promiseFor($result);
    }
}
