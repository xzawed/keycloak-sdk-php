<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\OAuth\GrantType;
use Fschmtt\Keycloak\OAuth\TokenStorageInterface;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\Admin\UsersResource;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\SanitizedCause;

/**
 * 헤더에 실을 수 없는 admin Bearer 가 SDK 오류에 **토큰을 찍지 않는다**(헤더 칸 — wave 4 item 3, 등록부 `php-admin-bearer-header-quote`).
 *
 * admin 레인은 이 SDK 에서 토큰을 **헤더**에 싣는 유일한 자리다(fschmtt 가 `Authorization: Bearer <토큰>` 을 만든다 — introspect·
 * refresh·logout 은 토큰을 폼 본문에 percent-encode 해 싣는다). psr7 은 CR·LF·NUL 같은 제어 문자를 담은 헤더 값을 거부하며 그 값을
 * **통째로** 메시지에 인용한다 — `"Bearer <토큰>" is not valid header value.` 그 예외를 `SanitizedCause` 가 감사한 라이브러리의
 * 메시지로 옮기면 토큰이 원인의 메시지·`(string)$e`·`var_dump`·`print_r` 에 찍혔다.
 *
 * 실제 경로(실측 2026-10-05, scratchpad `probe3h.php`): sodium 확장이 **없는** PHP 에서 lcobucci 는 base64 를
 * `base64_decode(…, true)` 로 풀고 그것은 공백(CR·LF)을 건너뛴다 — 가짜 토큰 엔드포인트가 서명 조각에 LF·CR·CRLF 를 품은 토큰을 주면
 * fschmtt 가 그것을 받아 두고 Bearer 로 실으려다 psr7 에서 터졌다(LF·CR·CRLF 셋 다 원인 메시지에 토큰 원문). sodium 이 있으면 lcobucci 가
 * 먼저 거부한다(`CannotDecodeContent`, 메시지 보류). 그래서 여기서는 lcobucci 의 해석을 건너뛴 토큰을 저장소에 직접 넣어 **그 자리**를
 * 확장과 무관하게 잰다. NUL 은 lcobucci 가 어디서나 거부하지만 psr7 도 거부하는 글자라 같은 칸에 둔다.
 *
 * ⚠️ 하네스 상태는 정적이다 — 토큰은 인자로도 인스턴스 프로퍼티로도 넘기지 않는다(트레이스 인자에 실려 `var_dump` 가 따라간다).
 */
final class AdminBearerHeaderLeakTest extends TestCase
{
    private const MARK_A = 'HDRcanaryAAAA';
    private const MARK_B = 'HDRcanaryBBBB';

    private static string $sentAuth = '';

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
        self::$sentAuth = '';
    }

    /** @return array<string, array{string, bool}> 이름 => [서명 조각의 두 표지 사이에 넣는 글자, psr7 이 그 헤더 값을 거부하는가] */
    public static function oddCharacters(): array
    {
        return [
            'LF' => ["\n", true],
            'CR' => ["\r", true],
            'CRLF' => ["\r\n", true],
            'NUL' => ["\0", true],
            // psr7 은 0x80–0xFF 바이트를 헤더 값에 허용한다 — 거부가 없으니 오류도 없다(대조군).
            'U+0100' => ["\u{0100}", false],
        ];
    }

    #[DataProvider('oddCharacters')]
    public function testABearerAHeaderCannotCarryIsNotPrintedByTheSdkError(string $odd, bool $rejected): void
    {
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        $storage = new class () implements TokenStorageInterface {
            private ?Token $access = null;

            public function storeAccessToken(Token $accessToken): void
            {
                $this->access = $accessToken;
            }

            public function storeRefreshToken(Token $refreshToken): void {}

            public function retrieveAccessToken(): ?Token
            {
                return $this->access;
            }

            public function retrieveRefreshToken(): ?Token
            {
                return null;
            }
        };
        // lcobucci 의 해석을 건너뛴 토큰 — `toString()` 은 인코딩된 세 조각을 그대로 잇는다(서명 조각에 그 글자가 남는다).
        $storage->storeAccessToken(new Plain(
            new DataSet(['alg' => 'RS256', 'typ' => 'JWT'], $b64('{"alg":"RS256","typ":"JWT"}')),
            new DataSet(['exp' => new \DateTimeImmutable('+5 minutes')], $b64('{"exp":1}')),
            new Signature('sig', self::MARK_A . $odd . self::MARK_B),
        ));
        $handler = static function (RequestInterface $req): PromiseInterface {
            self::$sentAuth = $req->getHeaderLine('Authorization');
            $body = $req->getUri()->getPath() === '/admin/serverinfo' ? '{"systemInfo":{"version":"26.0.0"}}' : '[]';

            return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], $body));
        };
        $kc = (new Builder())
            ->withBaseUrl('http://kc.test')
            ->withGrantType(GrantType::clientCredentials(clientId: 'c', clientSecret: 'ADMHDR-client-secret', realm: 'r'))
            ->withTokenStorage($storage)
            ->withHttpClient(new GuzzleClient(['handler' => HandlerStack::create($handler)]))
            ->build();

        $thrown = null;
        try {
            (new UsersResource($kc, 'r'))->search();
        } catch (\Throwable $e) {
            $thrown = $e;
        }
        if (!$rejected) {
            self::assertNull($thrown, '대조군 — psr7 이 받아들이는 헤더 값이면 요청이 나간다');
            self::assertStringContainsString(self::MARK_A, self::$sentAuth);

            return;
        }
        self::assertSame('', self::$sentAuth, '헤더를 만들지 못해 요청은 나가지 않았다');
        self::assertInstanceOf(KeycloakAdminError::class, $thrown);
        self::assertSame('admin request failed unexpectedly', $thrown->getMessage());
        $cause = $thrown->getPrevious();
        self::assertInstanceOf(SanitizedCause::class, $cause);
        self::assertSame(\InvalidArgumentException::class, $cause->originalClass, '원본 클래스명은 남는다(디버깅 정보)');
        ob_start();
        var_dump($thrown);
        $dump = (string) ob_get_clean();
        foreach (['getMessage' => $thrown->getMessage(), 'cause' => $cause->getMessage(), '(string)' => (string) $thrown, 'var_dump' => $dump, 'print_r' => print_r($thrown, true)] as $how => $out) {
            self::assertStringNotContainsString(self::MARK_A, $out, "$how 가 Bearer 토큰을 찍는다");
            self::assertStringNotContainsString(self::MARK_B, $out, "$how 가 Bearer 토큰을 찍는다");
            self::assertStringNotContainsString('ADMHDR-client-secret', $out, "$how 가 client secret 을 찍는다");
        }
    }
}
