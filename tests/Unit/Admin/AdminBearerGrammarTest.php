<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Exception\VersionDetectionException;
use Fschmtt\Keycloak\Representation\Role;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Internal\BearerToken;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * admin Bearer 의 문법 — 아홉 언어가 같은 규칙(등록부 `bearer-token-grammar-divergent`): 양끝의 SP·HTAB·CR·LF 만(그 밖은 아니다)
 * 다듬고, 나머지가 RFC 6750 `b64token`(`[A-Za-z0-9-._~+/]+=*`, ASCII)이면 `Authorization: Bearer <나머지>` 로 보내고, 아니면 요청을
 * 보내지 않는다. 술어는 하나다(`Internal\BearerToken::sendable`).
 *
 * PHP 의 admin 레인은 **부여 시점에 받거나 거부하는** 갈래다 — fschmtt 가 토큰을 스스로 받아(`Client::fetchTokens`) 자기 저장소에
 * 두고 헤더를 스스로 만든다. SDK 는 보내는 값을 고쳐 쓸 수 없다: 저장소는 fschmtt 의 것이고, 헤더 값은 psr7 이 `new Request()`
 * 에서 — 핸들러 스택의 어떤 미들웨어보다 먼저 — 검증한다(CR·LF·NUL 이 든 값은 거기서 던지고, 양끝 SP·HTAB 은 거기서 다듬는다).
 * 그래서 토큰 응답을 보는 미들웨어(`BearerToken::grantMiddleware`)가 **다듬을 필요가 없는** b64token 만 받는다 — lf·crlf·lead-tab 도
 * 거부 칸이다. 소비자는 admin 레인에 토큰을 넣을 수 없고, IdP 는 그런 토큰을 주지 않는다. `ClientCredentialsTokenProvider` 는 자기
 * 캐시를 가지므로 다듬은 값을 캐시한다.
 *
 * ⚠️ fschmtt 는 access token 을 lcobucci 로 **JWT 로 파싱**한다 — 점 둘로 가른 base64url 세 조각이 아니면(plain·pad) 문법과 무관하게
 * 거기서 실패한다(`admin request failed unexpectedly`). 그래서 다듬기·가운데 공백 칸을 fschmtt 가 받아들일 JWT 에도 다시 잰다(`jwt-*`).
 *
 * 수정 전 실측(2026-10-29, 이 파일을 수정 전 코드에서 돌림): sodium 이 있으면 표준 표의 거부 칸과 `jwt-*` 는 전부 lcobucci 가 파싱에서
 * 거부했다 — 파사드는 `admin request failed unexpectedly`(원인 `InvalidTokenStructure`·`CannotDecodeContent`, 잘못된 UTF-8 은 fschmtt
 * 의 `JsonException`)이고 admin 요청은 없었다. sodium 이 없으면 lcobucci 가 base64url 안의 공백을 건너뛰어 `jwt-lead-tab` 이
 * `Bearer  \t<JWT>` 로, `jwt-inner-sp`·`jwt-inner-tab` 이 가운데 공백째 나갔다 — 판정이 SDK 가 아니라 확장에 달려 있었다.
 *
 * ⚠️ 하네스 상태는 정적이다 — 토큰은 시험 인자로 넘기지 않는다(트레이스 인자에 실려 `(string) $e` 가 따라간다 — `AdminBearerHeaderLeakTest`).
 */
final class AdminBearerGrammarTest extends TestCase
{
    private const GRANT_REFUSED = 'admin token request failed: the access token is not a valid RFC 6750 bearer token (b64token)';
    private const PROVIDER_REFUSED = 'client-credentials failed: the access token is not a valid RFC 6750 bearer token (b64token)';
    /** fschmtt(lcobucci)가 JWT 가 아닌 access token 을 거부할 때 오늘의 파사드 오류 — 문법과 무관하다. */
    private const NOT_A_JWT = 'admin request failed unexpectedly';
    private const TOKEN_SUFFIX = '/protocol/openid-connect/token';

    private static string $dir = '';
    private static int $port = 0;
    /** @var resource|null */
    private static $proc = null;
    /** @var array<string, array{string, string, ?string}>|null */
    private static ?array $table = null;

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
    }

    public static function setUpBeforeClass(): void
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($sock, "빈 포트를 못 얻었다: $errstr");
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, (int) strrpos($name, ':') + 1);
        self::$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bg-idp-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir(self::$dir));
        self::serve('');
        $env = getenv();
        $env['BG_STATE'] = self::$dir;
        $pipes = [];
        $proc = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . self::$port, __DIR__ . '/../Fixtures/bearer-idp-router.php'],
            [0 => ['pipe', 'r'], 1 => ['file', self::$dir . '/server.out', 'a'], 2 => ['file', self::$dir . '/server.err', 'a']],
            $pipes,
            self::$dir,
            $env,
        );
        self::assertIsResource($proc, '가짜 IdP 프로세스를 못 띄웠다');
        self::$proc = $proc;
        // ⚠️ 치명 오류·exit 는 tearDownAfterClass 를 건너뛴다 — `php -S` 가 고아로 남아 포트를 쥐지 않게(TokenResponseCapTest 와 같다).
        register_shutdown_function(static function (): void {
            self::stopIdp();
        });
        for ($i = 0; $i < 500; $i++) {
            $c = @fsockopen('127.0.0.1', self::$port, $en, $es, 0.2);
            if ($c !== false) {
                fclose($c);

                return;
            }
            usleep(20_000);
        }
        self::fail('가짜 IdP 가 뜨지 않았다');
    }

    public static function tearDownAfterClass(): void
    {
        self::stopIdp();
    }

    private static function stopIdp(): void
    {
        if (self::$proc !== null) {
            proc_terminate(self::$proc);
            proc_close(self::$proc);
            self::$proc = null;
        }
        foreach (['state.json', 'requests.log', 'server.out', 'server.err'] as $f) {
            @unlink(self::$dir . '/' . $f);
        }
        @rmdir(self::$dir);
    }

    /**
     * id => [토큰, admin 레인의 기대, 술어(`sendable`)의 값]. admin 의 기대: `sent`(그대로 나간다) · `grammar`(문법이 부여를 거부한다)
     * · `jwt`(fschmtt 가 JWT 가 아니라 거부한다). 표준 표, 그다음 PHP 의 덧붙임 — 문자열이 바이트라 잘못된 UTF-8 한 바이트, 그리고 fschmtt
     * 가 받아들일 JWT 위의 다듬기·가운데 공백.
     *
     * @return array<string, array{string, string, ?string}>
     */
    private static function table(): array
    {
        if (self::$table !== null) {
            return self::$table;
        }
        $jwt = self::jwt();
        $sig = (int) strrpos($jwt, '.') + 1;
        $inner = static fn (string $c): string => substr($jwt, 0, $sig + 8) . $c . substr($jwt, $sig + 8);

        return self::$table = [
            'plain' => ['abc.DEF-ghi_jkl~mno+pqr/stu', 'jwt', 'abc.DEF-ghi_jkl~mno+pqr/stu'],
            'pad' => ['abc==', 'jwt', 'abc=='],
            'jwt' => [$jwt, 'sent', $jwt],
            'lf' => ["abc\n", 'grammar', 'abc'],
            'crlf' => ["abc\r\n", 'grammar', 'abc'],
            'lead-tab' => [" \tabc\t ", 'grammar', 'abc'],
            'inner-sp' => ['a bc', 'grammar', null],
            'inner-tab' => ["a\tbc", 'grammar', null],
            'inner-crlf' => ["a\r\nX-Evil: 1", 'grammar', null],
            'mid-pad' => ['a=bc', 'grammar', null],
            'empty' => ['', 'grammar', null],
            'blank' => [" \t\r\n", 'grammar', null],
            'latin1' => ["abc\u{00E9}", 'grammar', null],
            'above-ff' => ["abc\u{0100}", 'grammar', null],
            'c1' => ["abc\u{0085}", 'grammar', null],
            'nul' => ["abc\0", 'grammar', null],
            'del' => ["abc\x7F", 'grammar', null],
            'nbsp' => ["abc\u{00A0}", 'grammar', null],
            'ideographic' => ["\u{3000}abc", 'grammar', null],
            'vt' => ["abc\x0B", 'grammar', null],
            'invalid-utf8' => ["abc\xFF", 'grammar', null],
            'jwt-lf' => [$jwt . "\n", 'grammar', $jwt],
            'jwt-crlf' => [$jwt . "\r\n", 'grammar', $jwt],
            'jwt-lead-tab' => [" \t" . $jwt . "\t ", 'grammar', $jwt],
            'jwt-inner-sp' => [$inner(' '), 'grammar', null],
            'jwt-inner-tab' => [$inner("\t"), 'grammar', null],
        ];
    }

    /** @return array<string, array{string}> */
    public static function ids(): array
    {
        $out = [];
        foreach (array_keys(self::table()) as $id) {
            $out[$id] = [$id];
        }

        return $out;
    }

    /**
     * (a) 파사드 — 토큰 부여는 첫 자원 접근의 버전 탐지에서 난다. 문법 밖이면 부여가 거부되고 캐시되지 않아 다음 호출이 IdP 에 다시
     * 묻고, admin 요청은 나가지 않는다. 문법 안이면 캐시되고 모든 admin 요청이 그 토큰 그대로를 싣는다. `roles()->update` 는 fschmtt 의
     * `Roles` 가 아니라 `RenamableRoles` 를 거치는 다른 길이다.
     */
    #[DataProvider('ids')]
    public function testTheFacadeTakesOnlyAGrantUnderTheGrammarAndCachesNoOther(string $id): void
    {
        [, $expect] = self::table()[$id];
        self::serve($id);
        $admin = KeycloakClient::create(self::config())->admin();
        $first = self::thrown(static fn (): int => count($admin->users()->search()));
        $second = self::thrown(static fn (): int => count($admin->users()->search()));
        $grants = self::tokenRequests();
        $sent = self::adminRequests();
        self::serve($id);
        $roles = KeycloakClient::create(self::config())->admin()->roles();
        $rename = self::thrown(static function () use ($roles): void {
            $roles->update('n', new Role(name: 'n'));
        });
        $sent = array_merge($sent, self::adminRequests());

        if ($expect === 'sent') {
            foreach (['search' => $first, 'search again' => $second, 'roles update' => $rename] as $call => $e) {
                self::assertNull($e, "$id $call: " . self::describe($e));
            }
            self::assertSame(1, $grants, "$id: 쓸 수 있는 토큰은 캐시된다");
            self::assertNotSame([], $sent);
            foreach ($sent as [$method, $path, $auth]) {
                self::assertSame('Bearer ' . self::table()[$id][0], $auth, "$id $method $path");
            }

            return;
        }
        foreach (['search' => $first, 'search again' => $second, 'roles update' => $rename] as $call => $e) {
            self::assertInstanceOf(KeycloakAdminError::class, $e, "$id $call: " . self::describe($e));
            self::assertSame($expect === 'grammar' ? self::GRANT_REFUSED : self::NOT_A_JWT, $e->getMessage(), "$id $call");
            self::assertNull($e->getStatusCode(), "$id $call");
            self::assertQuotesNoToken($id, $e, true);
        }
        self::assertSame(2, $grants, "$id: 거부한 부여는 캐시되지 않는다 — 다음 호출이 IdP 에 다시 묻는다");
        self::assertSame([], $sent, "$id: admin 요청은 나가지 않는다");
    }

    /**
     * (b) 탈출구 `raw()` 는 하위 fschmtt 클라이언트와 그것이 내는 오류를 내보낸다(§4(b)) — 문법이 거부한 부여는 Guzzle 의
     * `RequestException`(SDK 문구, 응답·원인 없음)이고, fschmtt 의 버전 탐지가 그것을 감싼다(`TokenResponseCap` 의 거부와 같은 꼴).
     */
    #[DataProvider('ids')]
    public function testRawGetsTheLowerLibraryErrorForARefusedGrant(string $id): void
    {
        [, $expect] = self::table()[$id];
        self::serve($id);
        $raw = KeycloakClient::create(self::config())->admin()->raw();
        $e = self::thrown(static fn (): int => count($raw->users()->all('r')));
        $sent = self::adminRequests();

        if ($expect === 'sent') {
            self::assertNull($e, "$id: " . self::describe($e));
            self::assertNotSame([], $sent);
            foreach ($sent as [$method, $path, $auth]) {
                self::assertSame('Bearer ' . self::table()[$id][0], $auth, "$id $method $path");
            }

            return;
        }
        self::assertInstanceOf(VersionDetectionException::class, $e, "$id: " . self::describe($e));
        $cause = $e->getPrevious();
        if ($expect === 'grammar') {
            self::assertInstanceOf(RequestException::class, $cause, "$id: " . self::describe($cause));
            self::assertSame(self::GRANT_REFUSED, $cause->getMessage(), $id);
            self::assertFalse($cause->hasResponse(), "$id: 받은 본문(토큰을 담는다)을 달지 않는다");
            self::assertNull($cause->getPrevious(), $id);
        }
        self::assertInstanceOf(\Throwable::class, $cause, $id);
        self::assertQuotesNoToken($id, $e, false);
        self::assertSame([], $sent, "$id: admin 요청은 나가지 않는다");
    }

    /** (c) 술어 자체 — 다듬은 값 또는 null. */
    #[DataProvider('ids')]
    public function testThePredicate(string $id): void
    {
        [$token, , $want] = self::table()[$id];
        self::assertSame($want, BearerToken::sendable($token), $id);
    }

    /**
     * (c) `ClientCredentialsTokenProvider` 는 자기 캐시를 가진다 — 문법 밖 토큰은 캐시 전에 거부하고(`KeycloakAuthError`, 다음 호출이
     * 다시 묻는다), 문법 안 토큰은 다듬은 값으로 캐시해 돌려준다. 이 레인은 JWT 를 파싱하지 않는다(plain·pad 도 그대로 나간다).
     */
    #[DataProvider('ids')]
    public function testTheTokenProviderCachesOnlyATokenUnderTheGrammar(string $id): void
    {
        [, , $want] = self::table()[$id];
        $http = new class () implements ClientInterface {
            public int $calls = 0;
            public string $body = '';

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->calls++;

                return new Response(200, ['Content-Type' => 'application/json'], $this->body);
            }
        };
        $http->body = self::body($id);
        $f = new HttpFactory();
        $cfg = new KeycloakConfig(serverUrl: 'http://kc.test', realm: 'r', clientId: 'c', clientSecret: 'bg-client-secret');
        $provider = new ClientCredentialsTokenProvider($cfg, new OidcEndpoints($cfg), $http, $f, $f);

        foreach (['first', 'second'] as $attempt) {
            $got = null;
            $e = self::thrown(static function () use ($provider, &$got): void {
                $got = $provider->getToken();
            });
            if ($want !== null) {
                self::assertNull($e, "$id $attempt: " . self::describe($e));
                self::assertSame($want, $got, "$id $attempt");
                continue;
            }
            self::assertInstanceOf(KeycloakAuthError::class, $e, "$id $attempt: " . self::describe($e));
            $message = match ($id) {
                'empty' => 'token response has no usable access_token',   // TokenSet 이 먼저 거부한다(오늘의 계약)
                'invalid-utf8' => 'client-credentials failed',             // json_decode 가 먼저 거부한다(오늘의 계약)
                default => self::PROVIDER_REFUSED,
            };
            self::assertSame($message, $e->getMessage(), "$id $attempt");
            self::assertQuotesNoToken($id, $e, true);
        }
        self::assertSame($want === null ? 2 : 1, $http->calls, "$id: 거부한 토큰은 캐시되지 않는다 · 받은 토큰은 캐시된다");
    }

    private static function config(): KeycloakConfig
    {
        return new KeycloakConfig('http://127.0.0.1:' . self::$port, 'r', 'c', 'bg-client-secret', readTimeout: 10.0);
    }

    /** 가짜 IdP 의 토큰 응답을 그 칸의 본문으로 바꾸고 요청 기록을 비운다. */
    private static function serve(string $id): void
    {
        file_put_contents(self::$dir . '/state.json', json_encode(['body_hex' => bin2hex($id === '' ? '{}' : self::body($id))], JSON_THROW_ON_ERROR));
        @unlink(self::$dir . '/requests.log');
    }

    /** 그 칸의 토큰을 그대로 담은 토큰 응답 — 제어 문자·`"`·`\` 만 이스케이프하고 나머지 바이트(잘못된 UTF-8 포함)는 날것이다. */
    private static function body(string $id): string
    {
        $escaped = preg_replace_callback('/[\x00-\x1F"\\\\]/', static fn (array $m): string => sprintf('\u%04x', ord($m[0])), self::table()[$id][0]);
        self::assertIsString($escaped);

        return '{"access_token":"' . $escaped . '","token_type":"Bearer","expires_in":300}';
    }

    /** 실제 HS256 JWS — fschmtt 는 서명은 보지 않고 exp 로 만료를 본다. */
    private static function jwt(): string
    {
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        $head = $b64('{"alg":"HS256","typ":"JWT"}');
        $claims = $b64((string) json_encode(['sub' => 'svc', 'azp' => 'c', 'exp' => time() + 3600]));

        return "$head.$claims." . $b64(hash_hmac('sha256', "$head.$claims", 'bg-signing-key', true));
    }

    /** @return list<array{string, string, ?string}> 가짜 IdP 가 받은 [메서드, 경로, Authorization 값] */
    private static function requests(): array
    {
        $out = [];
        $log = @file(self::$dir . '/requests.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($log === false ? [] : $log as $line) {
            $r = json_decode($line, true);
            if (is_array($r) && is_string($r[0] ?? null) && is_string($r[1] ?? null)) {
                $auth = is_string($r[2] ?? null) ? hex2bin($r[2]) : null;
                $out[] = [$r[0], $r[1], $auth === false ? null : $auth];
            }
        }

        return $out;
    }

    /** @return list<array{string, string, ?string}> admin REST 로 나간 요청 — 토큰 부여는 빼고 */
    private static function adminRequests(): array
    {
        return array_values(array_filter(self::requests(), static fn (array $r): bool => str_starts_with($r[1], '/admin/')));
    }

    private static function tokenRequests(): int
    {
        return count(array_filter(self::requests(), static fn (array $r): bool => str_ends_with($r[1], self::TOKEN_SUFFIX)));
    }

    /**
     * 거부 오류가 토큰을 찍지 않는다 — 전체 토큰·`abc`·주입한 헤더 이름. `$dumps` 면 `(string)`(트레이스 인자 포함)도 본다(SDK 오류).
     * ⚠️ `print_r` 은 보지 않는다 — 트레이스 인자를 따라 PHPUnit 의 객체 그래프를 걸어, 실패가 쌓인 실행에서 메모리 상한을 넘었다(실측).
     */
    private static function assertQuotesNoToken(string $id, \Throwable $e, bool $dumps): void
    {
        $token = trim(self::table()[$id][0], " \t\r\n");
        $needles = array_filter(['abc', 'X-Evil', $token], static fn (string $n): bool => strlen($n) > 1);
        $texts = [];
        for ($x = $e; $x !== null; $x = $x->getPrevious()) {
            $texts[$x::class . ' message'] = $x->getMessage();
        }
        if ($dumps) {
            $texts['(string)'] = (string) $e;
        }
        foreach ($texts as $how => $text) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $text, "$id: $how 가 토큰을 찍는다");
            }
        }
    }

    private static function thrown(callable $fn): ?\Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }

        return null;
    }

    private static function describe(?\Throwable $e): string
    {
        return $e === null ? 'no exception' : $e::class . ': ' . $e->getMessage();
    }
}
