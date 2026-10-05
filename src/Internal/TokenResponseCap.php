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
 * 토큰 엔드포인트(모든 grant — auth 레인과 admin 레인의 자기 토큰)·introspection·logout 응답 본문의 상한. 레인이 몇이든 이 상수
 * 하나다(`PkceKeycloakProvider` · `AuthClient::introspect`·`logout` · `ClientCredentialsTokenProvider` · `Admin\AdminClient`). @internal
 *
 * ⚠️ 예전에는 상한이 없었다 — 쓸 수 있는 토큰 뒤에 JSON 공백 32 MiB 를 붙인 응답을 여섯 레인이 전부 받아들였고(zend 피크 league
 * 75 MB · 그 밖 40 MB), memory_limit 보다 큰 본문은 잡을 수 없는 치명 오류(exit 255)로 프로세스를 끝냈다(실측 2026-10-03).
 *
 * 두 겹이다. (1) **싱크**(`sink()`) — Guzzle 이 응답 본문을 받아 적는 스트림을 상한+1 바이트에서 막는다. curl 은 짧은 쓰기에
 * 전송을 끊고(CURLE_WRITE_ERROR) psr7 의 복사(스트림 핸들러)는 멈춘다 — 메모리뿐 아니라 **전송**이 상한 근처에서 끝난다.
 * curl 은 푼 바이트를 많아야 16,384 바이트(CURL_MAX_WRITE_SIZE) 청크로 넘기므로 끊기 전에 받은 것은 상한+1 을 넘는 청크 하나까지다
 * (싱크는 그 청크에서 상한+1 바이트까지만 담는다). (2) **판독기**(`read()`) — 그 본문을 한 번만, 많아야 상한+1 바이트까지 읽어
 * 넘었으면 null 이다. 판독기만이 판정한다 — 싱크를 쓰지 않는 길(PSR-18 `sendRequest()`, 소비자가 넘긴 핸들러)도 여기를 지난다.
 *
 * ⚠️ `'stream' => true` 로 바꾸지 않은 이유: Guzzle 은 그 요청을 curl 이 아니라 PHP 스트림 핸들러로 보낸다 — 연결 시간 제한
 * (`connect_timeout`)이 무시되고(실측: `connect_timeout` 1 초 · `timeout` 4 초에 닿지 않는 주소 — curl 1,018 ms, 스트림 4,004 ms),
 * gzip 은 zlib 필터가 상한 너머까지 미리 풀었다(실측: 32 MiB gzip 에 프로세스 zend 피크 14 MB, 싱크는 4.4 MB). TLS 신뢰 저장소의
 * 출처도 `curl.cainfo` 에서 PHP OpenSSL(`openssl.cafile`)로 바뀐다(소스: `StreamHandler::add_verify` 는 cafile 없이 검증만 켠다).
 * 상한 안의 본문은 오늘과 같은 전송을 타야 한다.
 *
 * ⚠️ 51200(JWKS 상한 `JwksStore::JWKS_MAX_BYTES`)을 빌리지 말 것 — Keycloak 26.6 이 기본 설정으로 받아들이는 가장 긴 Bearer 가
 * 65,459 바이트다(서비스 계정 토큰은 관리하는 realm 마다 자란다). 1 MiB 는 그 16 배라 서버가 받는 토큰은 거부하지 않는다.
 */
final class TokenResponseCap
{
    /** ⚠️ 교차언어 가드가 이 값을 뽑는다 — 식(`1 << 20`)이 아니라 맨 십진 리터럴로 둔다. 아홉 언어가 같은 값이다. */
    public const TOKEN_RESPONSE_MAX_BYTES = 1048576;

    /** 판독기가 한 번에 청하는 바이트 — PHP `fread` 는 청한 길이만큼 미리 잡으므로 상한을 한 번에 청하지 않는다. */
    private const READ_CHUNK_BYTES = 8192;

    /** admin 미들웨어의 상한 거부를 다른 `RequestException` 과 가르는 Guzzle handler context 키 — 그 미들웨어만 단다(`isRejection`). */
    private const REJECTION = 'xzawed_keycloak_token_response_cap';

    /**
     * 본문을 처음부터 읽어 상한 이하면 그 바이트를, 넘으면 null 을 돌려준다. 스트림에서 **가져오는** 바이트는 많아야 상한+1 이고(넘었음을
     * 아는 한 바이트까지 — PSR-7 `read()` 는 청한 것보다 많이 주지 않는다), 한 번의 청은 많아야 min(8 KiB, 상한+1 − 이미 가져온 바이트)다.
     * 문자열은 가져온 만큼만 자란다. 되감을 수 있으면 처음부터 읽는다(`(string) $body` 와 같다). 다 읽으면 닫는다 — 넘은 본문을 끝까지
     * 비우지 않는다.
     *
     * ⚠️ 청한 바이트의 **합**은 묶이지 않는다 — 청한 것보다 적게 주는 스트림이면 다시 청하므로 합이 상한+1 을 넘는다(실측: 한 번에 1 바이트씩
     * 주는 2,048 바이트 본문에 2,049 번 청해 합 16,785,408 · 가져온 2,048). 묶이는 것은 가져온 바이트와 한 번의 청이다.
     *
     * ⚠️ 스트림의 읽기 오류는 그대로 던진다 — 받는 쪽이 자기 경계에서 SDK 오류로 바꾼다(그 예외의 트레이스 인자를 실어 내보내지 않게).
     */
    public static function read(StreamInterface $body): ?string
    {
        try {
            if ($body->isSeekable()) {
                $body->rewind();
            }
            $buf = '';
            while (!$body->eof()) {
                $chunk = $body->read(min(self::READ_CHUNK_BYTES, self::TOKEN_RESPONSE_MAX_BYTES + 1 - \strlen($buf)));
                if ($chunk === '') {
                    break;   // 더 줄 것이 없다(Guzzle `Utils::copyToString` 과 같다) — 막힌 스트림에서 돌지 않는다
                }
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
     * Guzzle `sink` 요청 옵션에 넘기는 본문 스트림 — 상한+1 바이트까지만 담고, 그 경계를 넘기는 쓰기는 담은 만큼만 받았다고(짧게)
     * 돌려준다. 그 뒤의 쓰기는 0 이다. 상한+1 번째 바이트를 담는 것이 요점이다 — 판독기가 그것으로 「넘었다」를 안다.
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

                return $buffer->write(\strlen($data) <= $room ? $data : substr($data, 0, $room));
            },
        ]);
    }

    /** 싱크가 상한을 넘는 본문을 받았는가 — 전송이 끊겨 예외로 끝난 요청에서 그 까닭을 가른다. */
    public static function overflowed(StreamInterface $sink): bool
    {
        return (int) $sink->getSize() > self::TOKEN_RESPONSE_MAX_BYTES;
    }

    /**
     * admin 레인의 핸들러 스택 미들웨어 — `$isTokenRequest` 가 고르는 요청(fschmtt 의 토큰 부여)에만 싱크를 달고, 받은 본문을 판독기로
     * 한 번 읽어 같은 바이트의 새 본문으로 바꿔 넘긴다. 넘으면 그 요청을 Guzzle `RequestException`(메시지 `"$what exceeds 1048576
     * bytes"`)으로 거부한다 — 요청은 여기서 끝나고 admin REST 요청은 나가지 않는다. 그 밖의 요청(사용자 목록처럼 정당하게 큰 admin
     * 응답)은 건드리지 않는다.
     *
     * ⚠️ 거부가 SDK 예외가 아니라 Guzzle 의 것인 이유: 이 스택은 `AdminClient::raw()` 가 내보내는 fschmtt 클라이언트의 것이라, 여기서
     * 던진 것은 탈출구를 쓰는 소비자에게 **그대로** 닿는다(§4(b) — raw() 는 하위 클라이언트와 그것이 내는 오류를 내보낸다). 그래서
     * 그 소비자가 잡는 하위 계열(`GuzzleException`)이어야 하고, 메시지는 상한 문구뿐이며 응답(받은 본문 — 토큰을 담는다)과 원인을 달지
     * 않는다. 파사드 쪽은 `Admin\ErrorTranslation` 이 `isRejection()` 으로 가려 원인 없는 `KeycloakTransportError` 로 바꾼다.
     *
     * ⚠️ 스택의 **맨 안쪽**(`push`)에 둔다 — http_errors 보다 먼저 응답을 받아야 4xx 의 오류 본문도 상한을 지나고, 그 미들웨어와
     * `Admin\ErrorTranslation` 이 되감을 수 있는 본문을 본다.
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

            return self::promise($handler($request, $options))->then(
                static function (ResponseInterface $response) use ($request, $what): ResponseInterface {
                    $body = self::read($response->getBody());
                    if ($body === null) {
                        throw self::rejection($request, $what);
                    }

                    return $response->withBody(Utils::streamFor($body));
                },
                static function (mixed $reason) use ($request, $sink, $what): PromiseInterface {
                    if (self::overflowed($sink)) {
                        throw self::rejection($request, $what);   // curl 이 짧은 쓰기에 끊은 전송(CURLE_WRITE_ERROR)
                    }

                    return Create::rejectionFor($reason);
                },
            );
        };
    }

    /** 미들웨어의 상한 거부인가 — `Admin\ErrorTranslation` 이 다른 `RequestException`(전송 실패)과 가른다. */
    public static function isRejection(\Throwable $e): bool
    {
        return $e instanceof RequestException && ($e->getHandlerContext()[self::REJECTION] ?? null) === true;
    }

    /** 상한 거부 — 요청만 달고(응답·원인 없음) 표시를 handler context 에 둔다. 메시지는 `ResponseTooLarge` 와 같은 꼴이다. */
    private static function rejection(RequestInterface $request, string $what): RequestException
    {
        return new RequestException(sprintf('%s exceeds %d bytes', $what, self::TOKEN_RESPONSE_MAX_BYTES), $request, null, null, [self::REJECTION => true]);
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
