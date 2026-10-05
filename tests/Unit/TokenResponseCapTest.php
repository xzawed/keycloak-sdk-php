<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\SanitizedCause;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\Internal\TokenResponseCap;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * 토큰 엔드포인트·introspection·logout 응답 본문의 상한 1,048,576 바이트(등록부 `token-response-size-unbounded`)를 **공개 API 의
 * 일곱 레인**에 건다 — client_credentials · refresh · 코드 교환(셋 다 league) · `ClientCredentialsTokenProvider` · introspect ·
 * logout · admin 의 자기 토큰 부여(fschmtt). 수정 전 실측(가짜 IdP · 32 MiB 공백 패딩): 여섯 레인 전부 수락, league 레인은 본문 사본
 * 둘(zend 피크 75 MB), memory_limit 보다 큰 본문은 잡을 수 없는 치명 오류(exit 255). logout 은 Guzzle 기본 싱크(php://temp)가
 * 16 MiB 본문을 끝까지 받아 2 MB 를 넘는 순간부터 임시 파일에 통째로 옮겨 썼다(200·400 모두 — 서버가 16,777,216 바이트를 다 썼고
 * 임시 파일이 16,777,216 바이트까지 자랐다).
 *
 * 가짜 IdP 는 진짜 HTTP 다(`Fixtures/token-cap-router.php`) — 상한이 전송(curl 이 싱크에 넘기는 청크·끊기·gzip 디코딩)과
 * 맞물리기 때문이다. 길이를 아는 본문(`cl`)·모르는 본문(`close`, `php -S` 는 청크 인코딩을 쓰지 않는다)·gzip(푼 바이트로
 * 센다) 셋을 돈다.
 *
 * 할당은 `memory_reset_peak_usage()` 뒤의 zend 피크로 잰다. 수신자(클라이언트·admin 파사드)는 재기 **전에** 만든다 — 클래스
 * 적재·조립은 본문 판정의 몫이 아니다.
 */
final class TokenResponseCapTest extends TestCase
{
    /** ⚠️ SDK 상수와 따로 적는다 — 상수가 바뀌면 `testTheCapIsOneMebibyte` 가 운다. */
    private const CAP = 1048576;

    /** Keycloak 26.6 이 기본 설정으로 받아들이는 가장 긴 Bearer(실측 2026-10-03: 65,459 = 401 · 65,460 = 431). */
    private const LARGEST_BEARER = 65459;

    /** 상한을 넘긴 판정이 쥐어도 되는 zend 메모리 — 본문 크기와 무관해야 한다(수정 전 32 MiB 본문: league 75 MB · 그 밖 40 MB). */
    private const BOUND_OVER = 4 * self::CAP;

    /** 2 KiB 남짓한 본문의 호출이 쥐어도 되는 zend 메모리 — 상한 근처를 미리 잡으면 여기서 운다. */
    private const BOUND_SMALL = self::CAP / 4;

    /** @var array<string, string> 레인 => 상한을 넘긴 본문의 메시지 */
    private const OVER = [
        'cc' => 'token response exceeds 1048576 bytes',
        'refresh' => 'token response exceeds 1048576 bytes',
        'code' => 'token response exceeds 1048576 bytes',
        'cctp' => 'token response exceeds 1048576 bytes',
        'introspect' => 'introspection response exceeds 1048576 bytes',
        'logout' => 'logout response exceeds 1048576 bytes',
        'admin' => 'admin token response exceeds 1048576 bytes',
    ];

    private static string $dir = '';
    private static int $port = 0;
    /** 마지막 `serve()` 가 상태에 쓴 nonce — `sentTo()` 는 이 상태를 읽은 요청의 기록만 본다. */
    private static string $nonce = '';
    /** @var resource|null */
    private static $proc = null;

    public static function setUpBeforeClass(): void
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($sock, "빈 포트를 못 얻었다: $errstr");
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, (int) strrpos($name, ':') + 1);
        self::$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'tc-idp-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir(self::$dir));
        self::serve('token', []);
        $env = getenv();
        $env['TC_STATE'] = self::$dir;
        $pipes = [];
        $proc = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . self::$port, __DIR__ . '/Fixtures/token-cap-router.php'],
            [0 => ['pipe', 'r'], 1 => ['file', self::$dir . '/server.out', 'a'], 2 => ['file', self::$dir . '/server.err', 'a']],
            $pipes,
            self::$dir,
            $env,
        );
        self::assertIsResource($proc, '가짜 IdP 프로세스를 못 띄웠다');
        self::$proc = $proc;
        // ⚠️ 치명 오류·exit 는 tearDownAfterClass 를 건너뛴다 — `php -S` 가 고아로 남아 포트를 쥐지 않게(HostilePathMatrixTest 와 같다).
        register_shutdown_function(static function (): void {
            self::stopIdp();
        });
        for ($i = 0; $i < 500; $i++) {   // 기동 대기 — 판정에 시간을 쓰지 않는다
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
        foreach (['state.json', 'requests.log', 'sent.log', 'server.out', 'server.err'] as $f) {
            @unlink(self::$dir . '/' . $f);
        }
        @rmdir(self::$dir);
    }

    /**
     * 가짜 IdP 상태 — 겨눈 엔드포인트의 본문 명세만 바꾸고 요청 기록을 비운다.
     *
     * @param array{access?: int, size?: int, framing?: string, gzip?: bool, status?: int} $spec
     */
    private static function serve(string $endpoint, array $spec): void
    {
        $state = [
            'token' => ['access' => 1000, 'size' => 0, 'framing' => 'cl', 'gzip' => false],
            'introspect' => ['size' => 0, 'framing' => 'cl', 'gzip' => false],
            'logout' => ['size' => 0, 'framing' => 'cl', 'gzip' => false],
        ];
        $state[$endpoint] = $spec + $state[$endpoint];
        self::$nonce = bin2hex(random_bytes(6));
        $state['nonce'] = self::$nonce;
        file_put_contents(self::$dir . '/state.json', json_encode($state, JSON_THROW_ON_ERROR));
        @unlink(self::$dir . '/requests.log');
        @unlink(self::$dir . '/sent.log');
    }

    /**
     * 경로가 `$suffix` 로 끝나고 마지막 `serve()` 의 상태를 읽은 응답에서 가짜 IdP 가 내보낸 본문 바이트(gzip 이면 압축 전). 서버
     * 스크립트가 끝나야 남는다 — 끊긴 전송은 서버가 다음 쓰기에서 알아채므로 호출이 돌아온 뒤 잠시 기다린다. 남지 않으면 null.
     */
    private static function sentTo(string $suffix): ?int
    {
        for ($i = 0; $i < 250; $i++) {
            $log = @file(self::$dir . '/sent.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($log === false ? [] : $log as $line) {
                $r = json_decode($line, true);
                if (is_array($r) && is_string($r[0] ?? null) && is_int($r[1] ?? null) && ($r[2] ?? null) === self::$nonce && str_ends_with($r[0], $suffix)) {
                    return $r[1];
                }
            }
            usleep(20_000);
        }

        return null;
    }

    /** @return list<array{0: string, 1: string, 2: int}> 가짜 IdP 가 받은 [메서드, 경로, Authorization 길이] */
    private static function requests(): array
    {
        $out = [];
        $log = @file(self::$dir . '/requests.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($log === false ? [] : $log as $line) {
            $r = json_decode($line, true);
            if (is_array($r) && is_string($r[0] ?? null) && is_string($r[1] ?? null) && is_int($r[2] ?? null)) {
                $out[] = [$r[0], $r[1], $r[2]];
            }
        }

        return $out;
    }

    /** @return list<string> admin REST 로 나간 요청의 경로 — 토큰 부여는 빼고 */
    private static function adminRequests(): array
    {
        return array_values(array_map(
            static fn (array $r): string => $r[1],
            array_filter(self::requests(), static fn (array $r): bool => str_starts_with($r[1], '/admin/')),
        ));
    }

    /** 레인의 본문이 나오는 엔드포인트. */
    private static function endpoint(string $lane): string
    {
        return match ($lane) {
            'introspect', 'logout' => $lane,
            default => 'token',
        };
    }

    /**
     * 레인의 공개 호출 하나 — 수신자는 여기서 만들고(재기 전), 돌려주는 클로저가 그 호출이다. 결과는 판정에 쓰는 스칼라 하나:
     * 토큰 레인은 access token 의 길이, introspect 는 `active`, logout 은 돌아왔으면 true, admin 은 돌려받은 사용자 수.
     *
     * @return \Closure(): (int|bool)
     */
    private static function lane(string $lane): \Closure
    {
        $cfg = new KeycloakConfig('http://127.0.0.1:' . self::$port, 'r', 'c', 'tc-client-secret', readTimeout: 30.0);
        $auth = KeycloakClient::create($cfg)->auth();
        if ($lane === 'cctp') {
            $f = new HttpFactory();
            $provider = new ClientCredentialsTokenProvider($cfg, new OidcEndpoints($cfg), new GuzzleClient(HttpOptions::guzzle($cfg)), $f, $f);

            return static fn (): int => strlen($provider->getToken());
        }
        if ($lane === 'admin') {
            $users = KeycloakClient::create($cfg)->admin()->users();

            return static fn (): int => count($users->search());
        }

        return match ($lane) {
            'cc' => static fn (): int => strlen($auth->clientCredentialsToken()->accessToken),
            'refresh' => static fn (): int => strlen($auth->refresh('tc-refresh-token')->accessToken),
            'code' => static fn (): int => strlen($auth->exchangeCode('tc-code', str_repeat('v', 64))->accessToken),
            'introspect' => static fn (): bool => $auth->introspect('tc-introspected-token')->active,
            'logout' => static function () use ($auth): bool {
                $auth->logout('tc-refresh-token');

                return true;
            },
            default => throw new \LogicException("모르는 레인 $lane"),
        };
    }

    /**
     * 호출 하나와 그동안의 zend 피크(호출 직전 사용량 대비).
     *
     * @param \Closure(): (int|bool) $call
     * @return array{0: int|bool|\Throwable, 1: int}
     */
    private static function measure(\Closure $call): array
    {
        gc_collect_cycles();
        memory_reset_peak_usage();
        $before = memory_get_usage();
        try {
            $result = $call();
        } catch (\Throwable $e) {
            $result = $e;
        }
        $peak = memory_get_peak_usage() - $before;
        if (getenv('TC_PRINT') === '1') {   // 재는 명령: TC_PRINT=1 vendor/bin/phpunit --filter TokenResponseCapTest
            fwrite(STDERR, sprintf("%-34s peak=%9d  %s\n", self::$current, $peak, $result instanceof \Throwable ? $result->getMessage() : var_export($result, true)));
        }

        return [$result, $peak];
    }

    /** 찍을 때 쓰는 이름 — 데이터 제공자 이름. */
    private static string $current = '';

    protected function setUp(): void
    {
        self::$current = $this->dataName() === '' ? $this->name() : (string) $this->dataName();
    }

    /** @return array<string, array{string}> */
    public static function lanes(): array
    {
        $out = [];
        foreach (array_keys(self::OVER) as $lane) {
            $out[$lane] = [$lane];
        }

        return $out;
    }

    /** @return array<string, array{string, string, bool}> 레인 × 본문 틀(`cl` 길이를 안다 · `close` 모른다 · `gzip` 푼 바이트) */
    public static function lanesByFraming(): array
    {
        $out = [];
        foreach (array_keys(self::OVER) as $lane) {
            foreach (['cl' => false, 'close' => false, 'gzip' => true] as $framing => $gzip) {
                $out["$lane $framing"] = [$lane, $framing === 'gzip' ? 'close' : $framing, $gzip];
            }
        }

        return $out;
    }

    /** @return array<string, array{string, int, string, bool}> 레인 × 거대 본문(16 MiB 길이 앎 · 32 MiB 모름 · 32 MiB gzip) */
    public static function lanesByHugeBody(): array
    {
        $out = [];
        foreach (array_keys(self::OVER) as $lane) {
            $out["$lane 16 MiB cl"] = [$lane, 16 * self::CAP, 'cl', false];
            $out["$lane 32 MiB close"] = [$lane, 32 * self::CAP, 'close', false];
            $out["$lane 32 MiB gzip"] = [$lane, 32 * self::CAP, 'close', true];
        }

        return $out;
    }

    /**
     * 상한은 1 MiB 이고 **맨 십진 리터럴**로 한 자리에 선언된다 — 교차언어 가드가 그 줄을 뽑는다(식 `1 << 20` 이면 못 뽑는다).
     */
    public function testTheCapIsOneMebibyteDeclaredAsAPlainDecimalLiteral(): void
    {
        self::assertSame(self::CAP, (new \ReflectionClassConstant(TokenResponseCap::class, 'TOKEN_RESPONSE_MAX_BYTES'))->getValue());
        $file = (string) (new \ReflectionClass(TokenResponseCap::class))->getFileName();
        self::assertSame(1, preg_match_all('/\bconst TOKEN_RESPONSE_MAX_BYTES = (\S+);/', (string) file_get_contents($file), $m));
        self::assertSame('1048576', $m[1][0]);
    }

    /**
     * Keycloak 이 받아들이는 가장 긴 Bearer 는 어느 레인에서도 상한에 걸리지 않는다 — admin 은 그것을 Bearer 로 실어 보낸다.
     * introspect·logout 의 응답은 토큰을 싣지 않는다 — 그 둘은 평범한 응답이 지나가는지만 본다.
     */
    #[DataProvider('lanes')]
    public function testTheLargestBearerKeycloakAcceptsPassesOnEveryLane(string $lane): void
    {
        self::serve('token', ['access' => self::LARGEST_BEARER]);
        $call = self::lane($lane);
        [$result] = self::measure($call);
        if ($result instanceof \Throwable) {
            self::fail("$lane: 받아들여야 한다 — " . $result::class . ': ' . $result->getMessage());
        }
        match ($lane) {
            'introspect', 'logout' => self::assertTrue($result),
            'admin' => self::assertSame(['/admin/serverinfo', '/admin/realms/r/users'], self::adminRequests()),
            default => self::assertSame(self::LARGEST_BEARER, $result),
        };
        if ($lane === 'admin') {
            foreach (self::requests() as [, $path, $authLen]) {
                if (str_starts_with($path, '/admin/')) {
                    self::assertSame(strlen('Bearer ') + self::LARGEST_BEARER, $authLen, "$path 의 Authorization 길이");
                }
            }
        }
    }

    #[DataProvider('lanesByFraming')]
    public function testABodyOfExactlyTheCapPasses(string $lane, string $framing, bool $gzip): void
    {
        self::serve(self::endpoint($lane), ['size' => self::CAP, 'framing' => $framing, 'gzip' => $gzip]);
        [$result] = self::measure(self::lane($lane));
        if ($result instanceof \Throwable) {
            self::fail("$lane: 정확히 상한인 본문은 받아들여야 한다 — " . $result::class . ': ' . $result->getMessage());
        }
        self::assertNotFalse($result);
    }

    #[DataProvider('lanesByFraming')]
    public function testABodyOneByteOverTheCapFails(string $lane, string $framing, bool $gzip): void
    {
        self::serve(self::endpoint($lane), ['size' => self::CAP + 1, 'framing' => $framing, 'gzip' => $gzip]);
        [$result] = self::measure(self::lane($lane));
        self::assertInstanceOf(KeycloakTransportError::class, $result, "$lane: 상한+1 바이트 본문은 KeycloakTransportError 여야 한다 — "
            . (is_object($result) ? $result::class : 'success'));
        self::assertSame(self::OVER[$lane], $result->getMessage());
        self::assertNull($result->getPrevious(), '하위 프레임을 쥔 원인을 달지 않는다 — 메시지가 전부다');
        if ($lane === 'admin') {
            self::assertSame([], self::adminRequests(), 'admin 은 토큰 부여가 실패하면 admin REST 요청을 보내지 않는다');
        }
    }

    #[DataProvider('lanesByHugeBody')]
    public function testAHugeBodyFailsWithAnAllocationThatDoesNotGrowWithIt(string $lane, int $size, string $framing, bool $gzip): void
    {
        self::serve(self::endpoint($lane), ['size' => $size, 'framing' => $framing, 'gzip' => $gzip]);
        [$result, $peak] = self::measure(self::lane($lane));
        self::assertInstanceOf(KeycloakTransportError::class, $result, "$lane: " . (is_object($result) ? $result::class : 'success'));
        self::assertSame(self::OVER[$lane], $result->getMessage());
        self::assertLessThan(self::BOUND_OVER, $peak, "$lane: {$size} 바이트 본문을 거부하며 zend 메모리를 $peak 바이트 잡았다");
        if ($lane === 'admin') {
            self::assertSame([], self::adminRequests());
        }
        // 전송도 상한 근처에서 끊긴다(싱크) — 판독기만으로는 거부는 같아도 서버가 본문을 끝까지 보낸다(logout 수정 전: 16 MiB 를 다 받아
        // 임시 파일에 썼다). ⚠️ cctp 는 뺀다 — PSR-18 `sendRequest()` 에는 요청별 싱크가 없어 주입 클라이언트가 끝까지 받는다(문서화된
        // 한계). gzip 도 뺀다 — 압축된 본문 전체가 소켓 버퍼에 들어가 끊어도 서버는 다 보낸다.
        if ($lane !== 'cctp' && !$gzip) {
            $sent = self::sentTo('/' . self::endpoint($lane));
            self::assertNotNull($sent, "$lane: 가짜 IdP 가 내보낸 바이트를 남기지 않았다");
            if (getenv('TC_PRINT') === '1') {
                fwrite(STDERR, sprintf("%-34s sent=%9d of %d\n", self::$current, $sent, $size));
            }
            self::assertLessThan(intdiv($size, 2), $sent, "$lane: 서버가 {$size} 바이트 본문 중 $sent 바이트를 보냈다 — 전송이 끊기지 않았다");
        }
    }

    /** @return array<string, array{int, string, int}> 상한을 넘는 admin 토큰 응답 — [본문 바이트, 틀, 상태] */
    public static function overCapAdminTokenBodies(): array
    {
        return [
            '200 cap+1 cl' => [self::CAP + 1, 'cl', 200],        // 끝까지 받은 응답을 판독기가 거부한다(미들웨어의 이행 갈래)
            '200 16 MiB cl' => [16 * self::CAP, 'cl', 200],      // curl 이 짧은 쓰기에 끊은 전송(거부 갈래)
            '400 32 MiB close' => [32 * self::CAP, 'close', 400], // 오류 상태도 같은 거부 갈래
        ];
    }

    /** 호출이 던진 것 — 던지지 않았으면 null(PHPUnit 의 실패 예외를 삼키지 않으려고 `try` 밖에서 판정한다). */
    private static function thrown(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Throwable $e) {
            return $e;
        }

        return null;
    }

    /**
     * admin 의 탈출구 `raw()` 는 하위 fschmtt 클라이언트와 **그것이 내는 오류**를 내보낸다(§4(b)). 그 길에서 상한을 넘은 토큰 응답은
     * 하위 라이브러리 계열 — Guzzle 의 `RequestException` — 로 나가야 한다. SDK 내부 클래스가 나가면 `GuzzleException` 을 잡는 소비자가
     * 놓친다(실측: 이 시험 전에는 `\UnexpectedValueException` 을 잇는 `Internal\ResponseTooLarge` 가 나왔다 — 그 전 ff40a07 은 그
     * 응답을 받아들였다). 메시지는 상한 문구뿐이고(토큰·시크릿 없음) 응답과 원인을 달지 않는다 — 받은 본문은 토큰을 담는다. 같은 본문을
     * 파사드로 부르면 오늘의 `KeycloakTransportError`(원인 없음)다. 어느 길이든 admin REST 요청은 나가지 않는다.
     */
    #[DataProvider('overCapAdminTokenBodies')]
    public function testAdminRawGetsAGuzzleExceptionWhileTheFacadeKeepsItsError(int $size, string $framing, int $status): void
    {
        $cfg = new KeycloakConfig('http://127.0.0.1:' . self::$port, 'r', 'c', 'tc-client-secret', readTimeout: 30.0);
        $spec = ['size' => $size, 'framing' => $framing, 'status' => $status];

        self::serve('token', $spec);
        $raw = KeycloakClient::create($cfg)->admin()->raw();
        $e = self::thrown(static fn (): int => count($raw->users()->all('r')));
        self::assertInstanceOf(GuzzleException::class, $e, 'raw(): ' . ($e === null ? 'success' : $e::class . ': ' . $e->getMessage()));
        self::assertInstanceOf(RequestException::class, $e);
        self::assertStringStartsWith('GuzzleHttp\\Exception\\', $e::class, 'raw() 가 내보내는 것은 하위 라이브러리의 클래스다');
        self::assertSame('admin token response exceeds 1048576 bytes', $e->getMessage());
        foreach (['tc-client-secret', 'eyJ', str_repeat('A', 32)] as $secret) {   // 시크릿 · 가짜 IdP 토큰의 머리와 서명 조각
            self::assertStringNotContainsString($secret, $e->getMessage());
        }
        self::assertFalse($e->hasResponse(), '받은 본문(토큰을 담는다)을 달지 않는다');
        self::assertNull($e->getPrevious());
        self::assertSame([], self::adminRequests(), 'raw(): 토큰 부여가 실패하면 admin REST 요청은 없다');

        self::serve('token', $spec);
        $facade = self::thrown(static fn (): int => count(KeycloakClient::create($cfg)->admin()->users()->search()));
        self::assertInstanceOf(KeycloakTransportError::class, $facade, '파사드: ' . ($facade === null ? 'success' : $facade::class));
        self::assertSame('admin token response exceeds 1048576 bytes', $facade->getMessage());
        self::assertNull($facade->getPrevious());
        self::assertSame([], self::adminRequests(), '파사드: 토큰 부여가 실패하면 admin REST 요청은 없다');
    }

    /**
     * 오류 상태(400)의 본문도 상한을 지난다 — league 는 그 본문을 읽어 OAuth 오류를 만들고, admin 은 그 본문에서 오류 코드를 찾는다.
     * 상한 안이면 그 레인이 오늘 내는 오류 그대로(`KeycloakAuthError` · admin 은 상태를 지킨 `KeycloakAdminError`), 넘으면 상한 오류다.
     */
    #[DataProvider('lanes')]
    public function testAnErrorStatusBodyIsCappedToo(string $lane): void
    {
        $sizes = [self::CAP => false, self::CAP + 1 => true, 32 * self::CAP => true];
        foreach ($sizes as $size => $over) {
            self::serve(self::endpoint($lane), ['size' => $size, 'framing' => 'close', 'status' => 400]);
            [$result, $peak] = self::measure(self::lane($lane));
            self::assertInstanceOf(\Throwable::class, $result, "$lane $size: 400 은 실패여야 한다");
            if ($over) {
                self::assertInstanceOf(KeycloakTransportError::class, $result, "$lane $size: " . $result::class . ': ' . $result->getMessage());
                self::assertSame(self::OVER[$lane], $result->getMessage(), "$lane $size");
                self::assertLessThan(self::BOUND_OVER, $peak, "$lane $size: 거부하며 zend 메모리를 $peak 바이트 잡았다");
            } elseif ($lane === 'admin') {
                self::assertInstanceOf(KeycloakAdminError::class, $result, "$lane $size: " . $result::class . ': ' . $result->getMessage());
                self::assertSame(400, $result->getStatusCode());
            } else {
                self::assertInstanceOf(KeycloakAuthError::class, $result, "$lane $size: " . $result::class . ': ' . $result->getMessage());
                if ($lane === 'logout') {
                    self::assertSame('logout failed', $result->getMessage(), "$lane $size: 상한 안의 오류 상태는 오늘의 오류 그대로다");
                }
            }
            if ($lane === 'admin') {
                self::assertSame([], self::adminRequests(), "$lane $size: 토큰 부여가 실패하면 admin REST 요청은 없다");
            }
        }
    }

    /** 2 KiB 남짓한 본문의 판정이 상한 근처를 미리 잡지 않는다 — 읽은 만큼만 자란다. */
    #[DataProvider('lanes')]
    public function testASmallBodyAllocatesFarLessThanTheCap(string $lane): void
    {
        self::serve(self::endpoint($lane), ['size' => 2048]);
        (self::lane($lane))();   // 데우기 — 처음 쓰는 클래스의 적재를 재지 않는다
        // ⚠️ 재는 호출은 **새 수신자**다 — `ClientCredentialsTokenProvider` 와 admin(fschmtt)은 받은 토큰을 캐시해, 데운 수신자를 다시
        // 부르면 토큰 요청 없이 끝난다(실측: 그렇게 쟀을 때 cctp 0 바이트 — 상한을 한 번에 청하는 변이를 그 두 레인이 놓쳤다).
        $call = self::lane($lane);
        @unlink(self::$dir . '/requests.log');
        [$result, $peak] = self::measure($call);
        $suffix = '/' . self::endpoint($lane);
        self::assertNotSame([], array_filter(self::requests(), static fn (array $r): bool => str_ends_with($r[1], $suffix)), "$lane: 잰 호출이 그 엔드포인트에 닿지 않았다(공허)");
        if ($result instanceof \Throwable) {
            self::fail("$lane: " . $result::class . ': ' . $result->getMessage());
        }
        self::assertLessThan(self::BOUND_SMALL, $peak, "$lane: 2 KiB 본문의 호출이 zend 메모리를 $peak 바이트 잡았다");
    }

    /**
     * 판독기가 스트림에서 **가져오는** 바이트는 많아야 상한+1 이고(넘었음을 아는 한 바이트까지), 한 번의 청은 많아야 min(8 KiB, 상한+1 −
     * 이미 가져온 바이트)다(PHP `fread` 는 청한 길이를 미리 잡는다). 정확히 상한인 본문은 그대로 돌려준다.
     *
     * ⚠️ 청한 바이트의 **합**은 묶이지 않는다 — 청한 것보다 적게 주는 스트림이면 판독기가 다시 청해 합이 상한+1 을 넘는다(실측: 한 번에
     * 1 바이트씩 주는 2,048 바이트 본문에 청한 합 16,785,408). 이 시험의 옛 이름(`testTheReaderNeverAsksForMoreThanTheCapPlusOne`)과
     * 「청한 합 ≤ 상한+1」 단언은 청한 만큼 주는 스트림에서만 참이었다. 그래서 청한 만큼 주는 스트림 · 한 번에 1 바이트씩 주는 스트림 ·
     * 상한 바로 앞부터 1 바이트씩 주는 스트림(청이 남은 자리까지 줄어드는지)을 함께 돈다.
     */
    public function testTheReaderTakesAtMostTheCapPlusOneAndEachRequestFitsTheRoomLeft(): void
    {
        // 스트림이 한 번에 주는 바이트 — (청한 바이트, 이미 내준 바이트) → 줄 바이트
        $asAsked = static fn (int $asked, int $taken): int => $asked;
        $oneByte = static fn (int $asked, int $taken): int => min(1, $asked);
        $oneByteNearTheCap = static fn (int $asked, int $taken): int => $taken >= self::CAP - 16 ? min(1, $asked) : $asked;
        /** @var array<string, array{int, \Closure(int, int): int, ?int}> 칸 => [본문 바이트, 주는 규칙, 기대 길이(null = 넘었다)] */
        $cases = [
            'as asked, cap' => [self::CAP, $asAsked, self::CAP],
            'as asked, cap+1' => [self::CAP + 1, $asAsked, null],
            'as asked, 3×cap' => [3 * self::CAP, $asAsked, null],
            'as asked, 10' => [10, $asAsked, 10],
            '1 byte per read, 2,048' => [2048, $oneByte, 2048],
            '1 byte per read from cap−16, cap' => [self::CAP, $oneByteNearTheCap, self::CAP],
            '1 byte per read from cap−16, cap+1' => [self::CAP + 1, $oneByteNearTheCap, null],
            '1 byte per read from cap−16, 3×cap' => [3 * self::CAP, $oneByteNearTheCap, null],
        ];
        foreach ($cases as $name => [$size, $give, $want]) {
            $taken = 0;
            $reads = 0;
            $tooBig = [];
            $inner = Utils::streamFor(str_repeat('a', $size));
            $spy = FnStream::decorate($inner, [
                'read' => static function (int $length) use ($inner, $give, &$taken, &$reads, &$tooBig): string {
                    $room = min(8192, self::CAP + 1 - $taken);
                    if ($length > $room) {
                        $tooBig[] = "청 $length > 남은 자리 $room (가져간 $taken)";
                    }
                    $reads++;
                    $got = $inner->read($give($length, $taken));
                    $taken += strlen($got);

                    return $got;
                },
            ]);
            $got = TokenResponseCap::read($spy);
            self::assertSame($want, $got === null ? null : strlen($got), "$name: 결과");
            self::assertLessThanOrEqual(self::CAP + 1, $taken, "$name: 스트림에서 가져온 바이트");
            self::assertSame([], array_slice($tooBig, 0, 3), "$name: 한 번의 청이 min(8192, 상한+1 − 가져온 바이트) 를 넘었다");
            if ($give === $oneByte) {
                self::assertGreaterThan($size, $reads, "$name: 1 바이트씩 읽히지 않았다(공허)");
            }
        }
    }

    /**
     * 본문을 읽다 실패하면 SDK 오류다 — 상한을 걸며 본문 읽기가 SDK 코드로 나왔고, 그 읽기는 지연 본문(소비자가 넘긴 클라이언트 ·
     * `stream` 옵션)에서 실패할 수 있다. 수정 전에는 `(string) $body` 의 raw `\RuntimeException` 이 introspect 와
     * `ClientCredentialsTokenProvider::getToken()` 밖으로 나갔다(§4). league 레인은 원래부터 `token request failed` 였다.
     * logout 은 전에 본문을 읽지 않아 2xx 면 돌아왔다 — 이제 상한을 판정하려고 읽으므로 읽을 수 없는 본문은 introspect 와 같은
     * 부류의 `KeycloakTransportError` 다(SDK 가 만든 클라이언트의 본문은 메모리 싱크라 이 갈래에 닿지 않는다).
     */
    public function testABodyThatFailsToReadIsAnSdkError(): void
    {
        $failing = static function (): FnStream {
            $fail = static fn (): never => throw new \RuntimeException('tc read failure');

            return new FnStream([
                '__toString' => $fail, 'getContents' => $fail, 'read' => $fail, 'eof' => static fn (): bool => false,
                'isSeekable' => static fn (): bool => false, 'isReadable' => static fn (): bool => true, 'getSize' => static fn (): ?int => null,
                'close' => static fn (): null => null, 'getMetadata' => static fn (): mixed => null,
            ]);
        };
        $handler = static fn (): PromiseInterface => Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], $failing()));
        $cfg = new KeycloakConfig('https://kc.test', 'r', 'c', 'tc-client-secret');
        $http = new GuzzleClient(['handler' => HandlerStack::create($handler)] + HttpOptions::guzzle($cfg));
        $ep = new OidcEndpoints($cfg);
        $f = new HttpFactory();
        $auth = new AuthClient($cfg, $ep, new JwtValidator($cfg, $ep, new JwksStore($ep->jwks(), $http, $f)), $http);
        $calls = [
            'introspect' => [static fn (): mixed => $auth->introspect('tc-token'), 'introspection response could not be read'],
            'logout' => [static function () use ($auth): void {
                $auth->logout('tc-refresh-token');
            }, 'logout response could not be read'],
            'cctp' => [static fn (): mixed => (new ClientCredentialsTokenProvider($cfg, $ep, $http, $f, $f))->getToken(), 'token response could not be read'],
            'cc' => [static fn (): mixed => $auth->clientCredentialsToken(), 'token request failed'],
        ];
        foreach ($calls as $lane => [$call, $message]) {
            try {
                $call();
                self::fail("$lane: 읽을 수 없는 본문을 받아들였다");
            } catch (\Throwable $e) {
                self::assertInstanceOf(KeycloakTransportError::class, $e, "$lane: " . $e::class . ': ' . $e->getMessage());
                self::assertSame($message, $e->getMessage(), $lane);
                self::assertInstanceOf(SanitizedCause::class, $e->getPrevious(), "$lane: 원인은 정화된 사본이다");
            }
        }
    }

    /**
     * 싱크는 상한+1 바이트까지만 담고 그 경계를 넘기는 청크에서 짧게 쓴다 — curl 은 짧은 쓰기에 전송을 끊고(CURLE_WRITE_ERROR),
     * psr7 의 복사는 멈춘다. 그 뒤의 쓰기는 0 이다. 상한+1 번째 바이트를 담아 두는 것이 요점이다 — 판독기가 그것으로 「넘었다」를 안다.
     */
    public function testTheSinkHoldsAtMostTheCapPlusOneAndRefusesTheRest(): void
    {
        $sink = TokenResponseCap::sink();
        $chunk = str_repeat('b', 16384);   // curl 의 CURL_MAX_WRITE_SIZE
        $accepted = 0;
        for ($i = 0; $i < 70; $i++) {
            $n = $sink->write($chunk);
            $accepted += $n;
            if ($n < strlen($chunk)) {
                break;
            }
        }
        self::assertSame(self::CAP + 1, $sink->getSize(), '싱크가 담은 바이트');
        self::assertSame(self::CAP + 1, $accepted, '받아들였다고 돌려준 바이트');
        self::assertSame(0, $sink->write($chunk), '넘은 뒤의 쓰기');
        self::assertTrue(TokenResponseCap::overflowed($sink));
        self::assertNull(TokenResponseCap::read($sink));

        $exact = TokenResponseCap::sink();
        self::assertSame(self::CAP, $exact->write(str_repeat('c', self::CAP)));
        self::assertFalse(TokenResponseCap::overflowed($exact));
        self::assertSame(self::CAP, strlen((string) TokenResponseCap::read($exact)));
    }
}
