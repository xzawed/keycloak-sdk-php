<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Http\Command;
use Fschmtt\Keycloak\Http\CommandExecutor;
use Fschmtt\Keycloak\Http\Method;
use Fschmtt\Keycloak\Http\Query;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\Representation\Client;
use Fschmtt\Keycloak\Representation\Group;
use Fschmtt\Keycloak\Representation\Realm;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Representation\User;
use Fschmtt\Keycloak\Resource\Resource as FschmttResource;   // 별칭 — 아니면 docblock 의 `resource` 타입이 이 클래스가 된다
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Handler\CurlVersion;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Utils as GuzzleUtils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\Admin\AdminClient;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakConflictError;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Internal\AdminResponseBody;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;

/**
 * admin 이 쓰지 않는 응답 본문과 오류 본문을 끝까지 읽지 않는다 — 등록부 admin-response-body-unbounded(php). fschmtt 가 읽지 않는
 * 본문(GET 이 아닌 요청의 2xx)은 받지 않고, 오류 본문(300 이상)은 1,048,576 바이트에서 자른다 — `raw()` 의 요청도. GET 의 2xx 는
 * 지금처럼 끝까지 읽는다.
 *
 * 가짜 Keycloak 은 원시 소켓 서버(`Fixtures/admin-body-server.php`)다 — 본문 중간에서 멈춘 응답과 서버가 써 보낸 바이트를 잴 수 있어야 해서.
 * 전송은 curl 과 스트림 처리기(ext-curl 없는 설치) 둘 다 돈다(`TokenResponseCapTest` 와 같은 `useTransport`).
 */
final class AdminResponseBodyTest extends TestCase
{
    /** 시험의 신탁 — SDK 상수와 따로 쓴다. */
    private const CAP = 1048576;
    /** 소켓 버퍼가 다 담지 못하는 본문. */
    private const HUGE = 64 * 1048576;
    /** 재스캔(2026-10-25)의 읽기 타임아웃. */
    private const STALL_TIMEOUT = 4.0;
    private const BASE = '/admin/realms/r';
    private const ERROR_HEAD = '{"error":"HTTP 404 Not Found"}';
    /** 프록시 환경변수 — 있으면 `AdminResponseBody` 가 머리에서 끊지 않는다(`mayUseProxy`). 시험마다 비우고 되돌린다. */
    private const PROXY_ENV = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'];

    private static string $dir = '';
    private static int $port = 0;
    private static string $nonce = '';
    /** @var resource|null */
    private static $proc = null;
    /** @var array{0: \ReflectionProperty, 1: mixed}|null */
    private ?array $curlInfo = null;
    /** @var array<string, string|false> 시험 앞의 프록시 환경변수 — `tearDown` 이 되돌린다 */
    private array $proxyEnv = [];

    public static function setUpBeforeClass(): void
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($sock, "빈 포트를 못 얻었다: $errstr");
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, (int) strrpos($name, ':') + 1);
        self::$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'arb-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir(self::$dir));
        self::route([]);
        $pipes = [];
        $proc = proc_open(
            [PHP_BINARY, __DIR__ . '/../Fixtures/admin-body-server.php', (string) self::$port, self::$dir],
            [0 => ['pipe', 'r'], 1 => ['file', self::$dir . '/server.out', 'a'], 2 => ['file', self::$dir . '/server.err', 'a']],
            $pipes,
        );
        self::assertIsResource($proc, '가짜 Keycloak 프로세스를 못 띄웠다');
        self::$proc = $proc;
        register_shutdown_function(static function (): void {
            self::stopServer();
        });
        for ($i = 0; $i < 500; $i++) {
            $c = @fsockopen('127.0.0.1', self::$port, $en, $es, 0.2);
            if ($c !== false) {
                fclose($c);

                return;
            }
            usleep(20_000);
        }
        self::fail('가짜 Keycloak 이 뜨지 않았다');
    }

    public static function tearDownAfterClass(): void
    {
        self::stopServer();
    }

    private static function stopServer(): void
    {
        if (self::$proc !== null) {
            proc_terminate(self::$proc);
            proc_close(self::$proc);
            self::$proc = null;
        }
        foreach (['state.json', 'sent.log', 'server.out', 'server.err'] as $f) {
            @unlink(self::$dir . '/' . $f);
        }
        @rmdir(self::$dir);
    }

    protected function setUp(): void
    {
        foreach (self::PROXY_ENV as $name) {
            $this->proxyEnv[$name] = getenv($name);
            putenv($name);
        }
    }

    protected function tearDown(): void
    {
        if ($this->curlInfo !== null) {
            [$property, $before] = $this->curlInfo;
            $property->setValue(null, $before);
            $this->curlInfo = null;
        }
        foreach ($this->proxyEnv as $name => $value) {
            putenv($value === false ? $name : "$name=$value");
        }
        $this->proxyEnv = [];
        gc_collect_cycles();   // 끊긴 응답의 소켓을 놓는다 — 한 번에 연결 하나를 받는 가짜 서버가 다음 시험에서 기다리지 않게
    }

    /**
     * 경로마다의 응답 명세 — `"METHOD /path" => [status, head, pad, stall?, extra]`. 기록(sent.log)을 비우고 새 nonce 를 둔다.
     *
     * @param array<string, array<string, mixed>> $routes
     */
    private static function route(array $routes): void
    {
        self::$nonce = bin2hex(random_bytes(6));
        file_put_contents(self::$dir . '/state.json', json_encode(['nonce' => self::$nonce, 'routes' => $routes === [] ? new \stdClass() : $routes], JSON_THROW_ON_ERROR));
        @unlink(self::$dir . '/sent.log');
    }

    /**
     * 이 nonce 의 `METHOD path` 요청 기록 — 응답이 끝나거나 클라이언트가 닫은 뒤 남는다(필드는 `Fixtures/admin-body-server.php` 머리말).
     *
     * @return array{written: int, got: int, declared: int, continued: bool, conn: int, tunneled: bool}|null
     */
    private static function record(string $method, string $path): ?array
    {
        for ($i = 0; $i < 500; $i++) {
            $lines = @file(self::$dir . '/sent.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines === false ? [] : $lines as $line) {
                $r = json_decode($line, true);
                if (!is_array($r) || ($r['method'] ?? null) !== $method || ($r['path'] ?? null) !== $path || ($r['nonce'] ?? null) !== self::$nonce) {
                    continue;
                }
                $int = static fn (string $key): int => is_int($r[$key] ?? null) ? $r[$key] : -1;

                return ['written' => $int('written'), 'got' => $int('got'), 'declared' => $int('declared'),
                    'continued' => ($r['continued'] ?? null) === true, 'conn' => $int('conn'), 'tunneled' => ($r['tunneled'] ?? null) === true];
            }
            usleep(20_000);
        }

        return null;
    }

    /** 이 nonce 의 응답에서 서버가 `METHOD path` 에 써 보낸 본문 바이트. */
    private static function sent(string $method, string $path): ?int
    {
        return self::record($method, $path)['written'] ?? null;
    }

    private static function config(float $readTimeout = 30.0): KeycloakConfig
    {
        return new KeycloakConfig('http://127.0.0.1:' . self::$port, 'r', 'c', 'arb-client-secret', readTimeout: $readTimeout);
    }

    /**
     * 호출 하나 — 결과(값 또는 예외)와 걸린 ms.
     *
     * @return array{0: mixed, 1: int}
     */
    private static function timed(\Closure $call): array
    {
        $t = hrtime(true);
        try {
            $result = $call();
        } catch (\Throwable $e) {
            $result = $e;
        }
        $ms = intdiv(hrtime(true) - $t, 1_000_000);

        return [$result, $ms];
    }

    private static function note(string $line): void
    {
        if (getenv('TC_PRINT') === '1') {   // 재는 명령: TC_PRINT=1 vendor/bin/phpunit --filter AdminResponseBodyTest
            fwrite(STDERR, $line . "\n");
        }
    }

    private static function describe(mixed $result): string
    {
        if ($result instanceof \Throwable) {
            $status = $result instanceof KeycloakAdminError ? ' ' . var_export($result->getStatusCode(), true) : '';

            return $result::class . $status . ': ' . substr($result->getMessage(), 0, 60);
        }

        return 'ok';
    }

    /** `TokenResponseCapTest::useTransport` 와 같다 — 수신자를 만들기 전에 부른다. */
    private function useTransport(string $transport): void
    {
        if ($transport === 'stream') {
            $property = new \ReflectionProperty(CurlVersion::class, 'versionInfo');
            $this->curlInfo = [$property, $property->getValue()];
            $property->setValue(null, false);
        }
        $chosen = GuzzleUtils::chooseHandler();
        if ($transport === 'stream') {
            self::assertInstanceOf(StreamHandler::class, $chosen, 'ext-curl 없는 설치를 흉내 내지 못했다');
        } else {
            self::assertNotInstanceOf(StreamHandler::class, $chosen, 'curl 칸인데 Guzzle 이 StreamHandler 를 골랐다');
        }
    }

    /**
     * 파사드 쓰기 열다섯 — [메서드, 경로, 부르는 법, 뒤따르는 GET(fschmtt 가 되읽는 것) 의 경로와 본문].
     *
     * @return array<string, array{0: string, 1: string, 2: \Closure(AdminClient): mixed, 3: array<string, string>}>
     */
    private static function writes(): array
    {
        $clientBack = ['GET ' . self::BASE . '/clients/c1' => '{"id":"c1","clientId":"c"}'];
        $realmBack = ['GET /admin/realms/x' => '{"realm":"x"}'];

        return [
            'users.create' => ['POST', self::BASE . '/users', static fn (AdminClient $a) => $a->users()->create(new User(username: 'u')), []],
            'users.update' => ['PUT', self::BASE . '/users/u1', static fn (AdminClient $a) => $a->users()->update('u1', new User(username: 'u')), []],
            'users.delete' => ['DELETE', self::BASE . '/users/u1', static fn (AdminClient $a) => $a->users()->delete('u1'), []],
            'clients.import' => ['POST', self::BASE . '/clients', static fn (AdminClient $a) => $a->clients()->import(new Client(id: 'c1', clientId: 'c')), $clientBack],
            'clients.update' => ['PUT', self::BASE . '/clients/c1', static fn (AdminClient $a) => $a->clients()->update('c1', new Client(id: 'c1', clientId: 'c')), $clientBack],
            'clients.delete' => ['DELETE', self::BASE . '/clients/c1', static fn (AdminClient $a) => $a->clients()->delete('c1'), []],
            'realms.import' => ['POST', '/admin/realms', static fn (AdminClient $a) => $a->realms()->import(new Realm(realm: 'x')), $realmBack],
            'realms.update' => ['PUT', '/admin/realms/x', static fn (AdminClient $a) => $a->realms()->update('x', new Realm(realm: 'x')), $realmBack],
            'realms.delete' => ['DELETE', '/admin/realms/x', static fn (AdminClient $a) => $a->realms()->delete('x'), []],
            'roles.create' => ['POST', self::BASE . '/roles', static fn (AdminClient $a) => $a->roles()->create(new Role(name: 'n')), []],
            'roles.update' => ['PUT', self::BASE . '/roles/n', static fn (AdminClient $a) => $a->roles()->update('n', new Role(name: 'n')), []],
            'roles.delete' => ['DELETE', self::BASE . '/roles/n', static fn (AdminClient $a) => $a->roles()->delete('n'), []],
            'groups.create' => ['POST', self::BASE . '/groups', static fn (AdminClient $a) => $a->groups()->create(new Group(name: 'g')), []],
            'groups.update' => ['PUT', self::BASE . '/groups/g1', static fn (AdminClient $a) => $a->groups()->update('g1', new Group(name: 'g')), []],
            'groups.delete' => ['DELETE', self::BASE . '/groups/g1', static fn (AdminClient $a) => $a->groups()->delete('g1'), []],
        ];
    }

    /** @return array<string, array{string, string}> 쓰기 × 전송 */
    public static function writeRows(): array
    {
        $rows = [];
        foreach (array_keys(self::writes()) as $name) {
            foreach (['curl', 'stream'] as $transport) {
                $rows[$transport === 'curl' ? $name : "$name · stream"] = [$name, $transport];
            }
        }

        return $rows;
    }

    /**
     * 오류 본문을 저마다 읽는 호출 — 조회(GET) · 쓰기(PUT) · 가져오기(POST).
     *
     * @return array<string, array{0: string, 1: string, 2: \Closure(AdminClient): mixed}>
     */
    private static function errorCalls(): array
    {
        return [
            'users.get' => ['GET', self::BASE . '/users/u1', static fn (AdminClient $a) => $a->users()->get('u1')],
            'users.update' => ['PUT', self::BASE . '/users/u1', static fn (AdminClient $a) => $a->users()->update('u1', new User(username: 'u'))],
            'clients.import' => ['POST', self::BASE . '/clients', static fn (AdminClient $a) => $a->clients()->import(new Client(id: 'c1', clientId: 'c'))],
        ];
    }

    /** @return array<string, array{string, int, string}> 호출 × 상태 × 전송 */
    public static function errorRows(): array
    {
        $rows = [];
        foreach (array_keys(self::errorCalls()) as $name) {
            foreach ([404, 500] as $status) {
                foreach (['curl', 'stream'] as $transport) {
                    $rows["$name $status" . ($transport === 'curl' ? '' : ' · stream')] = [$name, $status, $transport];
                }
            }
        }

        return $rows;
    }

    /** @return array<string, array{string, string}> 오류 호출 × 전송 */
    public static function errorCallRows(): array
    {
        $rows = [];
        foreach (array_keys(self::errorCalls()) as $name) {
            foreach (['curl', 'stream'] as $transport) {
                $rows[$transport === 'curl' ? $name : "$name · stream"] = [$name, $transport];
            }
        }

        return $rows;
    }

    /** @return array<string, array{string}> */
    public static function transports(): array
    {
        return ['curl' => ['curl'], 'stream' => ['stream']];
    }

    /** 쓰기의 2xx 와 그 본문 — 받지 않는다: 서버는 64 MiB 를 다 쓰지 못한다. */
    #[DataProvider('writeRows')]
    public function testAWritesSuccessBodyIsNotRead(string $name, string $transport): void
    {
        [$method, $path, $call, $back] = self::writes()[$name];
        $routes = [$method . ' ' . $path => ['status' => $method === 'POST' ? 201 : 200, 'head' => '{}', 'pad' => self::HUGE - 2]];
        foreach ($back as $key => $body) {
            $routes[$key] = ['head' => $body];
        }
        self::route($routes);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $call($admin));
        $sent = self::sent($method, $path);

        self::note(sprintf('[%s] %s: %d ms · server wrote %s · %s', $transport, $name, $ms, var_export($sent, true), self::describe($result)));
        self::assertNotInstanceOf(\Throwable::class, $result, "$name: " . self::describe($result));
        self::assertNotNull($sent, "$name: 서버 기록이 없다");
        self::assertLessThan(self::HUGE, $sent, "$name: 서버가 $sent 바이트를 다 썼다 — 쓰지 않는 본문을 읽었다");
    }

    /** 2xx 의 머리 뒤에서 멈춘 본문이 쓰기를 붙들지 않는다 — 곧바로 돌아온다. */
    #[DataProvider('writeRows')]
    public function testAWriteReturnsWithoutWaitingForAStalledBody(string $name, string $transport): void
    {
        [$method, $path, $call, $back] = self::writes()[$name];
        $routes = [$method . ' ' . $path => ['status' => $method === 'POST' ? 201 : 200, 'head' => '{}', 'pad' => self::CAP - 2, 'stall' => 2]];
        foreach ($back as $key => $body) {
            $routes[$key] = ['head' => $body];
        }
        self::route($routes);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config(self::STALL_TIMEOUT));

        [$result, $ms] = self::timed(static fn () => $call($admin));

        self::note(sprintf('[%s] %s stalled: %d ms · %s', $transport, $name, $ms, self::describe($result)));
        self::assertNotInstanceOf(\Throwable::class, $result, "$name: " . self::describe($result));
        self::assertLessThan(2000, $ms, "$name: {$ms} ms — 멈춘 본문을 기다렸다");
    }

    /**
     * 틀을 알린 2xx(Content-Length · chunked · gzip — Guzzle 이 푼 응답의 Content-Length 를 `X-Encoded-Content-Length` 로 옮긴다)는
     * 본문 첫 바이트 전에 멈춰도 기다리지 않는다 — 머리에서 끝낸다(재스캔 칸 A2: 201 + 알린 길이 뒤 멈춤 · #834). 스트림 처리기의 chunked 칸은
     * 없다 — PHP 의 http 래퍼가 청크를 풀며 `Transfer-Encoding` 을 머리에서 빼(`AdminResponseBody::framed` 의 docblock) 첫 바이트에서
     * 끊는 길로 가고, 바이트가 오지 않으면 고치기 전처럼 읽기 타임아웃까지 기다린다(실측 4,081 ms).
     *
     * @return array<string, array{string, array<string, mixed>}>
     */
    public static function headStallRows(): array
    {
        return [
            'Content-Length' => ['curl', []],
            'Content-Length · stream' => ['stream', []],
            'chunked' => ['curl', ['chunked' => true]],
            'gzip' => ['curl', ['gzip' => true]],
            'gzip · stream' => ['stream', ['gzip' => true]],
        ];
    }

    /** @param array<string, mixed> $spec */
    #[DataProvider('headStallRows')]
    public function testAWriteReturnsAtTheHeadOfAFramedBodyThatNeverComes(string $transport, array $spec): void
    {
        $users = self::BASE . '/users';
        self::route(["POST $users" => ['status' => 201, 'head' => '{"id":"x"}', 'pad' => self::CAP, 'stall' => 0] + $spec]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config(self::STALL_TIMEOUT));

        [$result, $ms] = self::timed(static fn () => $admin->users()->create(new User(username: 'u')));

        self::note(sprintf('[%s] create 201 %s stalled before its body: %d ms · %s', $transport, json_encode($spec), $ms, self::describe($result)));
        self::assertNotInstanceOf(\Throwable::class, $result, self::describe($result));
        self::assertLessThan(2000, $ms, "{$ms} ms — 오지 않는 본문을 기다렸다");
    }

    /**
     * 틀이 없는 2xx(닫힘으로 끝나는 본문)가 본문 바이트 없이 멈추면 끊을 자리가 없다 — 고치기 전처럼 읽기 타임아웃 끝에 전송
     * 오류다. 이 미들웨어는 **스스로** 끊은 전송만 되살린다(클래스 docblock — Grok 레그 1 의 205·200 무 Content-Length 칸).
     */
    public function testAnUnframedWriteResponseThatNeverEndsStaysATransportError(): void
    {
        $path = self::BASE . '/users/u1';
        self::route(["PUT $path" => ['status' => 200, 'length' => false, 'stall' => 0]]);
        $admin = new AdminClient(self::config(1.0));

        [$result, $ms] = self::timed(static fn () => $admin->users()->update('u1', new User(username: 'u')));

        self::note(sprintf('[curl] update 200 (no framing) stalled before its body: %d ms · %s', $ms, self::describe($result)));
        self::assertInstanceOf(KeycloakTransportError::class, $result, self::describe($result));
    }

    /**
     * 1 MiB 이상인 요청 본문에는 Guzzle 이 `Expect: 100-Continue` 를 단다 — curl 은 그 중간 응답에도 `on_headers` 를 부른다. 그것을
     * 최종 응답으로 보면 요청 본문을 보내기도 전에 끝내고 쓰기가 성공한 듯 돌아온다. 서버가 본문을 다 받아야 한다. 스트림 처리기는
     * `Expect` 를 떼고 보내므로(`StreamHandler::__invoke`) 그 칸은 큰 본문이 그대로 가는지만 잰다.
     */
    #[DataProvider('transports')]
    public function testALargeWriteIsSentWhole(string $transport): void
    {
        self::route(['POST /admin/realms' => ['status' => 201], 'GET /admin/realms/x' => ['head' => '{"realm":"x"}']]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $admin->realms()->import(new Realm(realm: 'x', displayName: str_repeat('d', self::CAP))));
        $record = self::record('POST', '/admin/realms');

        self::note(sprintf('[%s] large write: %d ms · %s · %s', $transport, $ms, json_encode($record), self::describe($result)));
        self::assertNotInstanceOf(\Throwable::class, $result, self::describe($result));
        self::assertNotNull($record);
        self::assertSame($transport === 'curl', $record['continued'], 'curl 칸이 100-continue 를 청하지 않았다면 이 시험이 뜻을 갖지 못한다');
        self::assertGreaterThan(self::CAP, $record['declared']);
        self::assertSame($record['declared'], $record['got'], '서버가 요청 본문을 다 받지 못했다');
    }

    /**
     * 중간 응답(1xx)은 답이 아니다 — curl 은 그것에도 `on_headers` 를 부른다. 규격을 어겨 Content-Length 를 단 1xx(RFC 9110 §8.6)를
     * 틀을 알린 2xx 처럼 보고 끊으면, 뒤따르는 최종 응답(409)을 읽지 않은 채 쓰기가 성공으로 돌아온다.
     */
    #[DataProvider('transports')]
    public function testAnInterimResponseIsNotTheAnswer(string $transport): void
    {
        $path = self::BASE . '/users/u1';
        self::route(["PUT $path" => ['status' => 409, 'head' => '{"errorMessage":"conflict"}', 'interim' => ['status' => 103, 'headers' => ['Content-Length' => '2']]]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $admin->users()->update('u1', new User(username: 'u')));

        self::note(sprintf('[%s] update 103 (Content-Length: 2) then 409: %d ms · %s', $transport, $ms, self::describe($result)));
        self::assertInstanceOf(KeycloakConflictError::class, $result, self::describe($result));
    }

    /**
     * 본문이 없다는 2xx 뒤에 바이트를 더 보내는 서버(규격 위반) — 스트림 처리기는 `Content-Length: 0` 을 길이 미상으로 보고 EOF 까지
     * 복사한다(Guzzle `StreamHandler::drain`). GET 이 아닌 요청의 2xx 는 본문 바이트를 받지 않는다 — 서버는 64 MiB 를 다 쓰지 못한다.
     *
     * @return array<string, array{string, array<string, mixed>}>
     */
    public static function trailingRows(): array
    {
        $rows = [];
        foreach (['204' => ['status' => 204], '200 Content-Length: 0' => ['status' => 200, 'cl' => 0]] as $case => $spec) {
            foreach (['curl', 'stream'] as $transport) {
                $rows[$transport === 'curl' ? "$case + 64 MiB" : "$case + 64 MiB · stream"] = [$transport, $spec];
            }
        }

        return $rows;
    }

    /** @param array<string, mixed> $spec */
    #[DataProvider('trailingRows')]
    public function testBytesAfterABodilessWriteResponseAreNotRead(string $transport, array $spec): void
    {
        $path = self::BASE . '/users/u1';
        self::route(["PUT $path" => $spec + ['head' => '{}', 'pad' => self::HUGE - 2]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $admin->users()->update('u1', new User(username: 'u')));
        $sent = self::sent('PUT', $path);

        self::note(sprintf('[%s] update %s + 64 MiB after it: %d ms · server wrote %s · %s', $transport, json_encode($spec), $ms, var_export($sent, true), self::describe($result)));
        self::assertNotInstanceOf(\Throwable::class, $result, self::describe($result));
        self::assertNotNull($sent);
        self::assertLessThan(self::HUGE, $sent, "서버가 $sent 바이트를 다 썼다 — 본문 없다는 응답 뒤의 바이트를 읽었다");
    }

    /**
     * HEAD 의 응답에는 본문이 없다(RFC 9110 §9.3.2) — 끊을 것이 없고, 끊으면 curl 이 다음 요청에 쓸 연결만 잃는다. 파사드는 HEAD 를
     * 보내지 않지만 `raw()->resource()` 의 자원은 fschmtt `Command` 에 `Method::HEAD` 를 실을 수 있다(Grok 레그 지목).
     */
    public function testAHeadResponseKeepsTheConnection(): void
    {
        $this->useTransport('curl');
        $path = self::BASE . '/users/u1';
        self::route(["HEAD $path" => ['status' => 200, 'cl' => 24, 'keep' => true], "GET $path" => ['head' => '{"id":"u1","username":"u"}', 'keep' => true]]);
        $kc = (new AdminClient(self::config()))->raw();

        $kc->resource(AdminResponseBodyHeadResource::class)->head('r', 'u1');
        $kc->users()->get('r', 'u1');
        $conns = [self::record('HEAD', $path)['conn'] ?? null, self::record('GET', $path)['conn'] ?? null];

        self::note('HEAD then GET conns: ' . json_encode($conns));
        self::assertNotNull($conns[0]);
        self::assertSame($conns[0], $conns[1], 'HEAD 뒤에 연결을 잃었다');
    }

    /**
     * 프록시 터널(https 대상에 `HTTPS_PROXY` 면 curl 이 CONNECT 한다) — curl 은 프록시의 `200 Connection established` 에도
     * `on_headers` 를 부른다. 그것을 쓰기의 2xx 로 보고 끊으면 요청은 서버에 닿지 않은 채 성공으로 돌아온다(실측: 고치기 전 판이
     * 그랬다). 평문으로 재려고 미들웨어를 직접 단 Guzzle 클라이언트에 `CURLOPT_HTTPPROXYTUNNEL` 로 터널을 강제한다(가짜 서버가
     * 프록시 노릇도 한다). 원서버에 닿지 못한 터널은 성공이 아니라 전송 오류다. 규격(RFC 9110 §9.3.6)을 어겨 그 200 에 틀을 다는
     * 프록시도 있다 — 틀로는 가를 수 없으니 프록시가 끼어들 수 있는 요청은 머리에서 끊지 않는다(Grok 레그 2 지목 ·
     * `testAFramedWriteResponseIsCutAtTheHeadOnlyWhenNoProxyCanBeInPlay`).
     *
     * @return array<string, array{array<string, mixed>, int|null}> [PUT 의 명세(`tunnel` = 터널을 닫는다 · `connect` = 프록시의 200 에
     *     더할 머리 줄), 돌려받을 상태(null = 예외)]
     */
    public static function tunnelRows(): array
    {
        return [
            '204 No Content' => [['status' => 204], 204],
            '204 behind a CONNECT 200 with Content-Length' => [['status' => 204, 'connect' => "Content-Length: 10\r\n"], 204],
            '204 behind a chunked CONNECT 200' => [['status' => 204, 'connect' => "Transfer-Encoding: chunked\r\n"], 204],
            '201 Content-Length: 0' => [['status' => 201], 201],
            '200 + 64 MiB (Content-Length)' => [['status' => 200, 'head' => '{}', 'pad' => self::HUGE - 2], 200],
            '200 + 64 MiB (close-delimited)' => [['status' => 200, 'head' => '{}', 'pad' => self::HUGE - 2, 'length' => false], 200],
            '404 + 64 MiB' => [['status' => 404, 'head' => self::ERROR_HEAD, 'pad' => self::HUGE - strlen(self::ERROR_HEAD)], 404],
            'tunnel closed before the server' => [['tunnel' => 'close'], null],
        ];
    }

    /** @param array<string, mixed> $put */
    #[DataProvider('tunnelRows')]
    public function testAWriteThroughAProxyTunnelReachesTheServer(array $put, ?int $want): void
    {
        $path = self::BASE . '/users/u1';
        self::route(isset($put['tunnel']) ? ['CONNECT' => ['close' => true]] : ["PUT $path" => $put, 'CONNECT' => ['headers' => $put['connect'] ?? '']]);
        $this->useTransport('curl');
        $stack = HandlerStack::create();
        $stack->push(AdminResponseBody::middleware(static fn (): bool => false), 'admin_response_body');
        $client = new GuzzleClient(['handler' => $stack, 'http_errors' => false, 'allow_redirects' => false, 'timeout' => self::STALL_TIMEOUT]);
        $body = '{"username":"u"}';

        [$result, $ms] = self::timed(static fn () => $client->request('PUT', 'http://origin.test' . $path, [
            'proxy' => 'http://127.0.0.1:' . self::$port,
            'curl' => [\CURLOPT_HTTPPROXYTUNNEL => true],
            'body' => $body,
            'headers' => ['Authorization' => 'Bearer t', 'Content-Type' => 'application/json'],
        ]));
        $record = self::record($want === null ? 'CONNECT' : 'PUT', $want === null ? '/' : $path);

        $seen = $result instanceof ResponseInterface ? $result->getStatusCode() . ' ' . $result->getReasonPhrase() : self::describe($result);
        self::note(sprintf('[curl] tunnel %s: %d ms · %s · %s', json_encode($put), $ms, json_encode($record), $seen));
        self::assertNotNull($record, '가짜 프록시 기록이 없다');
        if ($want === null) {
            self::assertInstanceOf(TransferException::class, $result, "원서버에 닿지 못한 터널이 성공으로 돌아왔다: $seen");

            return;
        }
        self::assertInstanceOf(ResponseInterface::class, $result, $seen);
        self::assertSame($want, $result->getStatusCode(), $seen);
        self::assertTrue($record['tunneled']);
        self::assertSame(strlen($body), $record['got'], '서버가 요청 본문을 다 받지 못했다');
        self::assertLessThan(self::HUGE, $record['written']);
        self::assertSame($want >= 300 ? self::CAP : 0, strlen((string) $result->getBody()), '남긴 본문 — 오류는 상한까지, 2xx 는 비운다');
    }

    /**
     * 머리에서 끊는 것은 프록시가 끼어들 수 없을 때뿐이다(`AdminResponseBody::mayUseProxy`) — 이 요청에 쓰이지 않을 프록시(다른
     * 스킴의 옵션 · 환경변수)도 끼어들 수 있다고 본다. 그때 본문 바이트 없이 멈춘 틀 있는 201 은 고치기 전처럼 읽기 타임아웃 끝에
     * 전송 오류다. `no` 목록만 있는 `proxy` 옵션(Guzzle `Client` 가 `NO_PROXY` 를 옮긴 것)은 프록시가 아니다 — 머리에서 끊는다.
     * `https_proxy` 행은 Linux 에서는 환경변수 갈래를 재고, Windows 에서는(대소문자를 가리지 않아 Guzzle `Client` 가 `HTTPS_PROXY` 로
     * 읽어 옵션에 옮긴다) 옵션 갈래를 잰다. `all_proxy` 는 `Client` 가 옮기지 않는다 — 두 OS 다 환경변수 갈래만 본다. 그 요청은
     * 실제로 그 프록시(가짜 서버 — 절대형 대상을 받는다)를 지난다.
     *
     * @return array<string, array{array<string, mixed>, array<string, string>, bool}> [요청 옵션 `proxy`, 환경변수(`FIXTURE` = 가짜
     *     서버), 머리에서 끊는가]
     */
    public static function proxyRows(): array
    {
        return [
            'no proxy' => [[], [], true],
            'proxy option with only a no-list' => [['no' => ['127.0.0.1']], [], true],
            'proxy option for https only' => [['https' => 'http://127.0.0.1:9'], [], false],
            'https_proxy in the environment' => [[], ['https_proxy' => 'http://127.0.0.1:9'], false],
            'all_proxy in the environment (the request goes through it)' => [[], ['all_proxy' => 'FIXTURE'], false],
        ];
    }

    /**
     * @param array<string, mixed> $proxy
     * @param array<string, string> $env
     */
    #[DataProvider('proxyRows')]
    public function testAFramedWriteResponseIsCutAtTheHeadOnlyWhenNoProxyCanBeInPlay(array $proxy, array $env, bool $cutAtHead): void
    {
        $path = self::BASE . '/users/u1';
        self::route(["PUT $path" => ['status' => 201, 'head' => '{"id":"x"}', 'pad' => self::CAP, 'stall' => 0]]);
        foreach ($env as $name => $value) {
            putenv($name . '=' . ($value === 'FIXTURE' ? 'http://127.0.0.1:' . self::$port : $value));   // tearDown 이 되돌린다
        }
        $this->useTransport('curl');
        $stack = HandlerStack::create();
        $stack->push(AdminResponseBody::middleware(static fn (): bool => false), 'admin_response_body');
        $client = new GuzzleClient(['handler' => $stack, 'http_errors' => false, 'allow_redirects' => false, 'timeout' => 1.0] + ($proxy === [] ? [] : ['proxy' => $proxy]));

        [$result, $ms] = self::timed(static fn () => $client->request('PUT', 'http://127.0.0.1:' . self::$port . $path, ['body' => '{}']));

        $seen = $result instanceof ResponseInterface ? (string) $result->getStatusCode() : self::describe($result);
        self::note(sprintf('[curl] create 201 stalled before its body · proxy %s · env %s: %d ms · %s', json_encode($proxy), json_encode($env), $ms, $seen));
        self::assertNotNull(self::record('PUT', $path), '요청이 서버에 닿지 않았다');
        if ($cutAtHead) {
            self::assertInstanceOf(ResponseInterface::class, $result, $seen);
            self::assertSame(201, $result->getStatusCode());
            self::assertLessThan(900, $ms, "{$ms} ms — 머리에서 끊지 않았다");
        } else {
            self::assertInstanceOf(TransferException::class, $result, "프록시가 끼어들 수 있는데 머리에서 끊었다: $seen");
        }
    }

    /**
     * 본문 없는 2xx(Keycloak 의 쓰기 응답 — 201 `Content-Length: 0` · Content-Length 없는 204)는 끊지 않는다: 다음 요청이 같은 연결로
     * 간다. 대조 — 본문 있는 2xx 는 끊으므로 다음 요청이 새 연결로 간다(이 시험이 연결이 바뀌는 것을 본다는 증거). 스트림 처리기는
     * 요청마다 연결을 닫으므로 curl 만 잰다.
     */
    public function testAnEmptyWriteResponseKeepsTheConnection(): void
    {
        $this->useTransport('curl');
        $users = self::BASE . '/users';
        $user = "$users/u1";
        $conns = [];
        foreach (['empty' => ['status' => 204, 'keep' => true], 'body' => ['status' => 200, 'head' => '{}', 'pad' => 1022, 'keep' => true]] as $case => $put) {
            self::route(["POST $users" => ['status' => 201, 'keep' => true], "PUT $user" => $put, "DELETE $user" => ['status' => 204, 'keep' => true]]);
            $admin = new AdminClient(self::config());

            $admin->users()->create(new User(username: 'u'));
            $admin->users()->update('u1', new User(username: 'u'));
            $admin->users()->delete('u1');
            $conns[$case] = array_map(static fn (array $r): ?int => self::record($r[0], $r[1])['conn'] ?? null, [['POST', $users], ['PUT', $user], ['DELETE', $user]]);
            unset($admin);
            gc_collect_cycles();
        }

        self::note('keep-alive: ' . json_encode($conns));
        [$create, $update, $delete] = $conns['empty'];
        self::assertNotNull($create);
        self::assertSame($create, $update, '본문 없는 201(Content-Length: 0) 뒤에 연결을 잃었다');
        self::assertSame($update, $delete, '본문 없는 204(Content-Length 없음) 뒤에 연결을 잃었다');
        self::assertSame($conns['body'][0], $conns['body'][1]);
        self::assertNotSame($conns['body'][1], $conns['body'][2], '대조: 본문 있는 2xx 를 끊었다면 다음 요청은 새 연결이어야 한다');
    }

    /** 오류 본문은 상한에서 잘린다 — 클래스와 상태는 그대로, 서버는 64 MiB 를 다 쓰지 못한다. */
    #[DataProvider('errorRows')]
    public function testAnErrorBodyIsCutAtTheCap(string $name, int $status, string $transport): void
    {
        [$method, $path, $call] = self::errorCalls()[$name];
        self::route([$method . ' ' . $path => ['status' => $status, 'head' => self::ERROR_HEAD, 'pad' => self::HUGE - strlen(self::ERROR_HEAD)]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        gc_collect_cycles();
        memory_reset_peak_usage();
        $before = memory_get_usage();
        [$result, $ms] = self::timed(static fn () => $call($admin));
        $peak = memory_get_peak_usage() - $before;
        $sent = self::sent($method, $path);

        self::note(sprintf('[%s] %s %d: %d ms · peak %d · server wrote %s · %s', $transport, $name, $status, $ms, $peak, var_export($sent, true), self::describe($result)));
        self::assertInstanceOf($status === 404 ? KeycloakNotFoundError::class : KeycloakAdminError::class, $result, self::describe($result));
        self::assertSame($status, $result->getStatusCode());
        self::assertNotNull($sent);
        self::assertLessThan(self::HUGE, $sent, "서버가 $sent 바이트를 다 썼다 — 오류 본문을 끝까지 읽었다");
    }

    /**
     * 3xx 본문도 오류 본문처럼 상한에서 잘린다(`allow_redirects` 가 꺼져 따라가지 않는다). ⚠️ 3xx 를 성공으로 읽는 것은 따로 열린
     * 항목이다(등록부 go-admin-3xx-read-as-success) — 여기서는 받는 양만 잰다.
     */
    #[DataProvider('transports')]
    public function testARedirectBodyIsCutAtTheCap(string $transport): void
    {
        $path = self::BASE . '/users/u1';
        $head = '{"id":"u1","username":"u"}';
        self::route(["GET $path" => ['status' => 302, 'head' => $head, 'pad' => self::HUGE - strlen($head)]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $admin->users()->get('u1'));
        $sent = self::sent('GET', $path);

        self::note(sprintf('[%s] users.get 302: %d ms · server wrote %s · %s', $transport, $ms, var_export($sent, true), self::describe($result)));
        self::assertNotNull($sent);
        self::assertLessThan(self::HUGE, $sent, "서버가 $sent 바이트를 다 썼다 — 3xx 본문을 끝까지 읽었다");
    }

    /**
     * 상한을 넘긴 뒤 멈춘 오류 본문 — 나머지를 기다리지 않고 그 상태로 끝난다. 클래스만으로는 모자란다: 읽기 타임아웃 끝에도 상태로
     * 고른 같은 클래스가 나온다(psr7 2.11 아래의 스트림 처리기 실측 4,045–4,065 ms) — 그래서 시간을 함께 본다.
     */
    #[DataProvider('errorCallRows')]
    public function testAnErrorBodyPastTheCapThatStallsEndsWithoutWaiting(string $name, string $transport): void
    {
        [$method, $path, $call] = self::errorCalls()[$name];
        self::route([$method . ' ' . $path => ['status' => 404, 'head' => self::ERROR_HEAD, 'pad' => 2 * self::CAP, 'stall' => self::CAP + 1]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config(self::STALL_TIMEOUT));

        [$result, $ms] = self::timed(static fn () => $call($admin));

        self::note(sprintf('[%s] %s past the cap, stalled: %d ms · %s', $transport, $name, $ms, self::describe($result)));
        self::assertInstanceOf(KeycloakNotFoundError::class, $result, self::describe($result));
        self::assertLessThan(2000, $ms, "$name: 상한을 넘은 뒤에도 {$ms} ms 를 기다렸다 — 읽기 타임아웃까지 붙들렸다");
    }

    /**
     * 본문 중간에 끊긴 전송 — 미들웨어는 자기가 끊지 않은 거부를 그대로 넘긴다(`KeycloakTransportError`). 상한 아래에서 끊긴 오류
     * 본문도 그렇다(curl). 스트림 처리기는 Content-Length 보다 일찍 끝난 본문을 끝으로 받으므로(Guzzle `StreamHandler::drain`) 그 칸은
     * 상태로 고른다. 쓰기의 2xx 는 본문을 받지 않으므로 끊겨도 성공이다 — 예전에는 curl 칸만 전송 오류였다.
     *
     * @return array<string, array{string, int, string, class-string<\Throwable>|null}>
     */
    public static function brokenRows(): array
    {
        return [
            'users.get 200' => ['users.get', 200, 'curl', KeycloakTransportError::class],
            'users.get 404' => ['users.get', 404, 'curl', KeycloakTransportError::class],
            'users.get 404 · stream' => ['users.get', 404, 'stream', KeycloakNotFoundError::class],
            'users.update 404' => ['users.update', 404, 'curl', KeycloakTransportError::class],
            'users.update 404 · stream' => ['users.update', 404, 'stream', KeycloakNotFoundError::class],
            'users.update 200' => ['users.update', 200, 'curl', null],
            'users.update 200 · stream' => ['users.update', 200, 'stream', null],
        ];
    }

    /** @param class-string<\Throwable>|null $want */
    #[DataProvider('brokenRows')]
    public function testATransferThatBreaksMidBodyKeepsItsClass(string $name, int $status, string $transport, ?string $want): void
    {
        [$method, $path, $call] = self::errorCalls()[$name];
        $head = $status === 200 ? '{"id":"u1","username":"u"' : self::ERROR_HEAD;
        self::route([$method . ' ' . $path => ['status' => $status, 'head' => $head, 'pad' => 4096, 'stall' => 100, 'close' => true]]);
        $this->useTransport($transport);
        $admin = new AdminClient(self::config());

        [$result, $ms] = self::timed(static fn () => $call($admin));

        self::note(sprintf('[%s] %s %d broken mid-body: %d ms · %s', $transport, $name, $status, $ms, self::describe($result)));
        if ($want === null) {
            self::assertNotInstanceOf(\Throwable::class, $result, self::describe($result));
        } else {
            self::assertInstanceOf($want, $result, self::describe($result));
        }
    }

    /**
     * `raw()` 의 오류 본문도 상한에서 잘린다 — 탈출구는 Guzzle 의 예외를 그대로 넘기고, 그 응답의 본문이 상한이다. 그 응답의
     * `Content-Length` 는 남긴 길이다 — 서버가 알린 64 MiB 를 그대로 두면 그 응답을 다시 내보내는 소비자(PSR-7 그대로 흘리는 프록시)의
     * 상대가 오지 않을 바이트를 기다리거나 잘린 전송으로 실패한다.
     */
    public function testARawErrorBodyIsCutAtTheCap(): void
    {
        self::route(['GET ' . self::BASE . '/users/u1' => ['status' => 404, 'head' => self::ERROR_HEAD, 'pad' => self::HUGE - strlen(self::ERROR_HEAD)]]);
        $raw = (new AdminClient(self::config()))->raw();

        try {
            $raw->users()->get('r', 'u1');
            self::fail('404 인데 돌아왔다');
        } catch (ClientException $e) {
            self::assertSame(404, $e->getResponse()->getStatusCode());
            self::assertSame(self::CAP, strlen((string) $e->getResponse()->getBody()));
            self::assertSame((string) self::CAP, $e->getResponse()->getHeaderLine('Content-Length'), '남긴 본문과 다른 길이를 알린다');
        }
        self::assertLessThan(self::HUGE, self::sent('GET', self::BASE . '/users/u1'));
    }

    /**
     * gzip 오류 본문도 **푼** 바이트로 상한에서 잘린다 — 푸는 것은 싱크 아래(curl · psr7 `InflateStream`)다. 소비자는 Accept-Encoding 을
     * 정할 수 없다(fschmtt 가 요청 머리를 받지 않는다). 64 MiB 공백을 압축한 본문.
     */
    #[DataProvider('transports')]
    public function testAGzipErrorBodyIsCutAtTheCapDecoded(string $transport): void
    {
        self::route(['GET ' . self::BASE . '/users/u1' => ['status' => 404, 'head' => self::ERROR_HEAD, 'pad' => self::HUGE - strlen(self::ERROR_HEAD), 'gzip' => true]]);
        $this->useTransport($transport);
        $raw = (new AdminClient(self::config()))->raw();

        gc_collect_cycles();
        memory_reset_peak_usage();
        $before = memory_get_usage();
        [$result, $ms] = self::timed(static fn () => $raw->users()->get('r', 'u1'));
        $peak = memory_get_peak_usage() - $before;

        $body = $result instanceof ClientException ? (string) $result->getResponse()->getBody() : '';
        self::note(sprintf('[%s] gzip 404: %d ms · peak %d · body %d · %s', $transport, $ms, $peak, strlen($body), self::describe($result)));
        self::assertInstanceOf(ClientException::class, $result, self::describe($result));
        self::assertSame(404, $result->getResponse()->getStatusCode());
        self::assertSame(self::CAP, strlen($body));
        self::assertStringStartsWith(self::ERROR_HEAD, $body, '푼 바이트가 아니다');
        self::assertFalse($result->getResponse()->hasHeader('Content-Length'), 'Guzzle 이 압축을 풀며 뗀 Content-Length 를 되살렸다');
    }

    /** GET 의 2xx 는 상한 없이 끝까지 읽는다 — 사용자 목록은 정당하게 크다. */
    public function testASuccessBodyAGetUsesIsReadWhole(): void
    {
        $users = [];
        for ($i = 0; strlen((string) json_encode($users)) <= self::CAP + 4096; $i++) {
            $users[] = ['id' => sprintf('%012d', $i), 'username' => sprintf('user-%012d', $i)];
        }
        self::route(['GET ' . self::BASE . '/users' => ['head' => (string) json_encode($users)]]);

        $found = (new AdminClient(self::config()))->users()->search();

        self::assertGreaterThan(self::CAP, strlen((string) json_encode($users)), '본문이 상한을 넘어야 이 시험이 뜻을 갖는다');
        self::assertCount(count($users), $found);
    }

    /**
     * 토큰 응답이 상한 + 1 바이트를 보내고 멈추면 곧바로 거부한다 — 그 바이트를 담은 쓰기에서 전송을 끊는다(재스캔 칸 T2: 상한 + 1 뒤
     * 멈춘 토큰 응답 · #834 · php 만 읽기 타임아웃까지 기다렸다).
     *
     * @return array<string, array{string, string}>
     */
    public static function tokenLanes(): array
    {
        $rows = [];
        foreach (['client credentials', 'admin token'] as $lane) {
            foreach (['curl', 'stream'] as $transport) {
                $rows[$transport === 'curl' ? $lane : "$lane · stream"] = [$lane, $transport];
            }
        }

        return $rows;
    }

    #[DataProvider('tokenLanes')]
    public function testATokenResponsePastTheCapThatStallsIsRefusedAtOnce(string $lane, string $transport): void
    {
        $token = '/realms/r/protocol/openid-connect/token';
        self::route(['POST ' . $token => ['head' => '{"access_token":"x","token_type":"Bearer","expires_in":300}', 'pad' => 2 * self::CAP, 'stall' => self::CAP + 1]]);
        $this->useTransport($transport);
        $cfg = self::config(self::STALL_TIMEOUT);
        $call = $lane === 'admin token'
            ? static fn () => (new AdminClient($cfg))->users()->search()
            : static fn () => KeycloakClient::create($cfg)->auth()->clientCredentialsToken();

        [$result, $ms] = self::timed($call);

        self::note(sprintf('[%s] %s past the cap, stalled: %d ms · %s', $transport, $lane, $ms, self::describe($result)));
        self::assertInstanceOf(KeycloakTransportError::class, $result, self::describe($result));
        self::assertLessThan(2000, $ms, "$lane: 상한을 넘은 뒤에도 {$ms} ms 를 기다렸다 — 읽기 타임아웃까지 붙들렸다");
    }

    /**
     * fschmtt 가 GET 이 아닌 요청의 응답 본문을 읽지 않는다는 전제 — 이 SDK 가 그 본문을 받지 않는 근거다(파사드 표시 없이 HTTP 층에서
     * 고른다). 명령은 응답을 버리고(`CommandExecutor::executeCommand(): void`), 조회는 GET 뿐이며, `Keycloak` 은 HTTP 클라이언트를
     * 내보이지 않는다(`raw()` 소비자도 그 본문에 닿지 못한다). ⚠️ fschmtt 핀(composer.json)이 움직이면 이 시험이 먼저 본다.
     */
    public function testFschmttNeverReadsTheBodyOfARequestThatIsNotAGet(): void
    {
        $execute = new \ReflectionMethod(CommandExecutor::class, 'executeCommand');
        self::assertSame('void', (string) $execute->getReturnType());
        self::assertSame(Method::GET, (new \ReflectionClass(Query::class))->newInstanceWithoutConstructor()->getMethod());
        foreach ((new \ReflectionClass(Keycloak::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
            $type = (string) $m->getReturnType();
            self::assertStringNotContainsString('Http\\Client', $type, "Keycloak::{$m->getName()} 가 HTTP 클라이언트를 내보인다");
            self::assertStringNotContainsString('ClientInterface', $type, "Keycloak::{$m->getName()} 가 HTTP 클라이언트를 내보인다");
        }
    }
}

/** `raw()->resource()` 의 자원 — 파사드에 없는 HEAD 를 fschmtt 명령으로 보낸다(`AdminResponseBodyTest::testAHeadResponseKeepsTheConnection`). */
final class AdminResponseBodyHeadResource extends FschmttResource
{
    public function head(string $realm, string $userId): void
    {
        $this->commandExecutor->executeCommand(new Command('/admin/realms/{realm}/users/{userId}', Method::HEAD, ['realm' => $realm, 'userId' => $userId]));
    }
}
