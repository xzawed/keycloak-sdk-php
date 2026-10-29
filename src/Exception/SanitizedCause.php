<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\MessageTrait;
use GuzzleHttp\Psr7\Utils;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\UriInterface;
use Xzawed\Keycloak\Internal\OAuthErrorCode;

/**
 * A sanitized copy attached in an SDK exception's `getPrevious()` slot **instead of the original** underlying library
 * exception (§4 — underlying types do not leak into the public API). It is never thrown directly.
 *
 * ⚠️ Attaching the original as is leaks a malformed or hostile IdP response into the cause chain (measured 2026-09-26):
 * league's `IdentityProviderException` holds the whole error response body and puts `error_description` in its message,
 * Guzzle's `BadResponseException` puts the start of the response body in its message, and the underlying exception's
 * **trace arguments** hold the token response array, the call options (refresh_token · code · Basic header) and the raw
 * JWT — `(string)$e` · `var_dump` · `print_r` follow that chain. `#[\SensitiveParameter]` does not reach third-party
 * frames, so replacing the original with a copy is the only way to stop this at the boundary.
 *
 * What the copy keeps: the original class name (`originalClass`, also at the head of the message) · code · file · line ·
 * the trace **without arguments** · the cause chain sanitized by the same rules. The message is split three ways — an
 * HTTP error response keeps only the status, method and URL (without query and user info), an OAuth error response only
 * the `error` code (when it has the `OAuthErrorCode` shape), and anything else carries over **only messages built inside
 * the audited underlying libraries** (those libraries' messages do not quote their input — ⚠️ two exceptions: Guzzle's
 * transport failure quotes the request URL including its query, which `withoutQuery()` trims to the same extent, and
 * psr7's header validation quotes the rejected header value whole, which `quotesAHeader()` withholds). The message of
 * an exception raised outside them, such as in a consumer handler or middleware, is not carried over, since there is no
 * knowing what it quotes (measured by the Grok leg: a secret quoted by a handler exception was printed through the chain).
 */
final class SanitizedCause extends \RuntimeException
{
    private const MAX_DEPTH = 8;

    /** 메시지를 믿는 하위 라이브러리 — 클래스 => 그 파일에서 소스 뿌리(`src`)까지 올라갈 단계. */
    private const AUDITED = [
        \GuzzleHttp\Client::class => 1,
        \GuzzleHttp\Psr7\Message::class => 1,
        \GuzzleHttp\Promise\Promise::class => 1,
        \League\OAuth2\Client\Provider\AbstractProvider::class => 2,
        \Stevenmaguire\OAuth2\Client\Provider\Keycloak::class => 2,
        \Firebase\JWT\JWT::class => 1,
    ];

    /** @var list<string>|null */
    private static ?array $auditedRoots = null;

    /** psr7 의 헤더 검증이 사는 파일(`quotesAHeader`). */
    private static ?string $headerValidation = null;

    /** @param class-string $originalClass */
    private function __construct(public readonly string $originalClass, string $message, int $code, ?\Throwable $previous)
    {
        parent::__construct($originalClass . ': ' . $message, $code, $previous);
    }

    /**
     * Turns an underlying exception into a copy that can be attached as an SDK exception's `previous`. The SDK's own
     * exceptions have already crossed the boundary, so they are left as they are.
     */
    public static function of(#[\SensitiveParameter] \Throwable $e): \Throwable
    {
        return self::copy($e, 0);
    }

    /** @param UriInterface|null $sent 바깥 HTTP 예외가 보낸 요청의 URL — 이 메시지가 인용할 수 있다(`withoutQuery`). */
    private static function copy(#[\SensitiveParameter] \Throwable $e, int $depth, ?UriInterface $sent = null): \Throwable
    {
        if ($e instanceof KeycloakException || $e instanceof self) {
            return $e;
        }
        if ($e instanceof RequestExceptionInterface || $e instanceof NetworkExceptionInterface) {
            $sent = $e->getRequest()->getUri();   // 이 예외와 그것이 감싼 사슬(stream 핸들러의 fopen 경고)이 인용하는 URL
        }
        $previous = $e->getPrevious();
        $code = $e->getCode();
        $copy = new self(
            $e::class,
            self::safeMessage($e, $sent),
            \is_int($code) ? $code : 0,
            $previous === null || $depth >= self::MAX_DEPTH ? null : self::copy($previous, $depth + 1, $sent),
        );
        $copy->file = $e->getFile();
        $copy->line = $e->getLine();
        // 인자만 뺀 원본 프레임 — 어디서 났는지는 남기고, 무엇을 쥐고 있었는지는 버린다.
        $frames = array_map(static function (array $frame): array {
            unset($frame['args']);

            return $frame;
        }, $e->getTrace());
        (new \ReflectionProperty(\Exception::class, 'trace'))->setValue($copy, $frames);

        return $copy;
    }

    private static function safeMessage(\Throwable $e, ?UriInterface $sent): string
    {
        if ($e instanceof IdentityProviderException) {
            $body = $e->getResponseBody();
            $error = OAuthErrorCode::of(\is_array($body) ? ($body['error'] ?? null) : null);

            return $error === null ? 'OAuth error response (body withheld)' : "OAuth error response: $error (description withheld)";
        }
        if ($e instanceof RequestException) {
            $response = $e->getResponse();
            if ($response !== null) {
                $request = $e->getRequest();
                $uri = $request->getUri()->withUserInfo('')->withQuery('')->withFragment('');

                return sprintf('HTTP %d from %s %s (response body withheld)', $response->getStatusCode(), $request->getMethod(), (string) $uri);
            }
        }

        if (!self::fromAuditedLibrary($e)) {
            return '(message withheld: thrown outside the audited libraries)';
        }
        if (self::quotesAHeader($e)) {
            return '(message withheld: it quotes a header value)';
        }

        return $sent === null ? $e->getMessage() : self::withoutQuery($e->getMessage(), $sent);
    }

    /**
     * ⚠️ psr7 의 헤더 검증(`MessageTrait` — 헤더 이름·값)은 거부한 것을 **통째로** 메시지에 인용한다 — `"Bearer <토큰>" is not valid
     * header value.` admin 의 Bearer 에 CR·LF 가 든 토큰이 이 메시지로 원인의 `getMessage()`·`(string)$e`·`var_dump`·`print_r` 에
     * 찍혔다(실측 2026-10-05: sodium 확장이 없는 PHP 에서 lcobucci 가 base64 의 공백을 건너뛰어 그 토큰을 받아들이고, fschmtt 가
     * 그것을 Bearer 로 실으려다 터졌다 — `Admin/AdminBearerHeaderLeakTest`). 그 파일에서 난 예외는 메시지를 옮기지 않는다 — 원본
     * 클래스명·파일·줄은 남는다. 값을 고쳐 쓰지 않는다(요청은 원래대로 나가지 않는다).
     */
    private static function quotesAHeader(\Throwable $e): bool
    {
        self::$headerValidation ??= (string) (new \ReflectionClass(MessageTrait::class))->getFileName();

        return $e->getFile() === self::$headerValidation;
    }

    /**
     * ⚠️ 감사한 라이브러리도 전송 실패에는 요청 URL 을 **쿼리째** 인용한다 — curl `cURL error 28: … for <URL>`, stream `Connection
     * refused for URI <URL>`(실측 2026-10-02 — admin 검색의 쿼리는 소비자의 검색어·username 이다). HTTP 갈래와 같은 선으로 URL 은
     * 남기되 쿼리·사용자정보·조각을 빼고, 다른 꼴로 인용돼(호스트를 IP 로 바꾼 URL · 디코드한 쿼리) 바꾸지 못한 쿼리가 남으면
     * 메시지를 통째로 거둔다.
     */
    private static function withoutQuery(string $message, UriInterface $uri): string
    {
        $safe = (string) $uri->withUserInfo('')->withQuery('')->withFragment('');
        $message = str_replace([(string) $uri, (string) Utils::redactUserInfo($uri)], $safe, $message);
        $query = $uri->getQuery();
        foreach ($query === '' ? [] : [$query, rawurldecode($query), urldecode($query)] as $quoted) {
            if (str_contains($message, $quoted)) {
                return '(message withheld: it quotes the request query)';
            }
        }

        return $message;
    }

    private static function fromAuditedLibrary(\Throwable $e): bool
    {
        if (self::$auditedRoots === null) {
            self::$auditedRoots = [];
            foreach (self::AUDITED as $class => $up) {
                $file = (new \ReflectionClass($class))->getFileName();
                if ($file !== false) {
                    self::$auditedRoots[] = \dirname($file, $up) . \DIRECTORY_SEPARATOR;
                }
            }
        }
        foreach (self::$auditedRoots as $root) {
            if (str_starts_with($e->getFile(), $root)) {
                return true;
            }
        }

        return false;
    }
}
