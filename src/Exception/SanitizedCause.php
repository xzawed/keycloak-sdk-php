<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

use GuzzleHttp\Exception\RequestException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Xzawed\Keycloak\Internal\OAuthErrorCode;

/**
 * SDK 예외의 `getPrevious()` 자리에 하위 라이브러리 예외 **원본 대신** 달리는 정화된 사본이다(§4 — 하위
 * 타입은 공개 API 로 새지 않는다). 직접 던지지 않는다.
 *
 * ⚠️ 원본을 그대로 달면 형식이 틀린·적대적인 IdP 응답이 원인 사슬로 샌다(실측 2026-09-26): league 의
 * `IdentityProviderException` 은 오류 응답 본문 전체를 쥐고 메시지에 `error_description` 을 싣고, Guzzle 의
 * `BadResponseException` 은 메시지에 응답 본문 앞부분을 싣고, 하위 예외의 **트레이스 인자**는 토큰 응답 배열·
 * 호출 옵션(refresh_token·code·Basic 헤더)·원문 JWT 를 쥔다 — `(string)$e`·`var_dump`·`print_r` 가 그 사슬을
 * 따라간다. `#[\SensitiveParameter]` 는 제3자 프레임에 닿지 않으므로 사본으로 바꾸는 것만이 경계에서 막는 길이다.
 *
 * 사본이 남기는 것: 원본 클래스명(`originalClass`, 메시지 머리에도)·코드·파일·줄·**인자를 뺀** 트레이스·같은 규칙으로
 * 정화된 원인 사슬. 메시지는 셋으로 가른다 — HTTP 오류 응답은 상태·메서드·URL(쿼리·사용자정보 제외)만, OAuth 오류
 * 응답은 `error` 코드(`OAuthErrorCode` 모양일 때)만, 그 밖은 **감사한 하위 라이브러리 안에서 만든 메시지만** 옮긴다
 * (그 라이브러리들의 메시지는 입력을 인용하지 않는다). 소비자 핸들러·미들웨어처럼 그 밖에서 난 예외의 메시지는
 * 무엇을 인용할지 모르므로 옮기지 않는다(Grok 레그 실측: 핸들러 예외가 인용한 시크릿이 사슬로 찍혔다).
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

    /** @param class-string $originalClass */
    private function __construct(public readonly string $originalClass, string $message, int $code, ?\Throwable $previous)
    {
        parent::__construct($originalClass . ': ' . $message, $code, $previous);
    }

    /**
     * 하위 예외를 SDK 예외의 `previous` 로 달 수 있는 사본으로 바꾼다. SDK 자신의 예외는 이미 경계를 지났으므로 그대로 둔다.
     */
    public static function of(#[\SensitiveParameter] \Throwable $e): \Throwable
    {
        return self::copy($e, 0);
    }

    private static function copy(#[\SensitiveParameter] \Throwable $e, int $depth): \Throwable
    {
        if ($e instanceof KeycloakException || $e instanceof self) {
            return $e;
        }
        $previous = $e->getPrevious();
        $code = $e->getCode();
        $copy = new self(
            $e::class,
            self::safeMessage($e),
            \is_int($code) ? $code : 0,
            $previous === null || $depth >= self::MAX_DEPTH ? null : self::copy($previous, $depth + 1),
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

    private static function safeMessage(\Throwable $e): string
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

        return self::fromAuditedLibrary($e) ? $e->getMessage() : '(message withheld: thrown outside the audited libraries)';
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
