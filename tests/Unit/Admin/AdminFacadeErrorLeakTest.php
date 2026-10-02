<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\Collection\CredentialCollection;
use Fschmtt\Keycloak\Http\Criteria;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\GrantType;
use Fschmtt\Keycloak\Representation\Client;
use Fschmtt\Keycloak\Representation\Credential;
use Fschmtt\Keycloak\Representation\Group;
use Fschmtt\Keycloak\Representation\Realm;
use Fschmtt\Keycloak\Representation\Role;
use Fschmtt\Keycloak\Representation\User;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\Admin\AdminClient;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakConflictError;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\SanitizedCause;

/**
 * admin 파사드가 던지는 오류가 **보낸 것**(client secret · Bearer · representation)과 **받은 오류 본문**을 찍지 않는다 —
 * admin 의 자기 토큰 부여(fschmtt 가 한다)와 admin 요청이 실패할 때.
 *
 * `HostilePathMatrixTest` 는 토큰 **응답** 변형을 계급에 붙이고, 그 칸의 카나리아는 응답 속 값뿐이다. 여기서는 요청 쪽을
 * 잰다: client_credentials 폼의 `client_secret` · admin 요청의 `Authorization: Bearer` · admin REST 오류 본문 · 보낸
 * representation(비밀번호·client secret) · 전송 실패. 실제 스택(fschmtt Builder → Client → Guzzle, 핸들러만 가짜 —
 * `RolesRenameTest` 와 같은 조립)을 태워 Guzzle 이 **미들웨어 안에서** 만든 예외를 그대로 받는다. 손으로 만든
 * `ClientException` 은 트레이스에 Guzzle·fschmtt 프레임이 없어 이 누출을 못 본다(`ErrorTranslationTest` 의 한계).
 *
 * 메서드는 손 목록이 아니다 — `AdminClient` 가 내주는 자원 클래스마다 공개 메서드 전부를 리플렉션으로 뽑고, 인자는 타입으로
 * 합성한다(모르는 타입이면 실패한다). 새 파사드 메서드는 저절로 들어온다. representation 과 검색 조건(`Criteria`)은 카나리아를
 * 품는다. 문자열 인자는 **어디로 가는지를 재서** 가른다(`hiddenStrings`): 쿼리·본문으로 가면 카나리아이고, 경로로 가는 식별자는
 * 원인 사본의 URL(`HTTP … from GET <경로>`)처럼 일부러 남는다 — `SanitizedCause` 가 쿼리를 빼고 경로를 남기는 것과 같은 선이다.
 *
 * 디버깅 정보는 지운 만큼만 지웠는지 함께 본다(`modes()`): 예외 타입 · `getStatusCode()` · 토큰 부여의 OAuth `error` 코드
 * (`OAuthErrorCode` 모양일 때) · 원인의 원본 클래스명.
 *
 * ⚠️ 하네스 상태는 정적이고, 인자를 넘기는 하네스 프레임(`invoke`)은 `#[\SensitiveParameter]` 로 가린다 — 그래야 찍힌 것이
 * SDK 프레임의 것이다. 트레이스 인자는 `zend.exception_ignore_args=0` 에서 잰다(운영 php.ini 는 1 이라 안 모은다).
 *
 * ⚠️ `modes()` 의 unreachable 두 칸은 가짜 핸들러가 `ConnectException` 을 만든다 — Guzzle 의 진짜 전송 실패 메시지(요청 URL 을
 * **쿼리째** 인용한다)는 거기 없다. 그 메시지는 진짜 curl·stream 핸들러를 붙인 `testRealTransportFailure…` 가 잰다.
 */
final class AdminFacadeErrorLeakTest extends TestCase
{
    private const SERVER = 'http://kc.test';
    private const REALM = 'r';
    private const TOKEN_PATH = '/realms/r/protocol/openid-connect/token';
    // 카나리아 — 앞 10 자가 서로 달라 접두 적중이 어느 것인지 가린다.
    private const SECRET = 'ADMsecret-client-secret-canary';
    private const BODY = 'ADMbody0-echoed-error-body-canary';
    private const INPUT = 'ADMinput-sent-representation-canary';

    private static string $mode = '';
    private static string $bearer = '';
    /** @var list<string> 가짜 IdP 가 받은 요청 `메서드 경로` */
    private static array $sent = [];
    /** @var list<string> 같은 요청의 `쿼리 본문` — 문자열 인자가 경로가 아닌 곳으로 가는지 가른다(`hiddenStrings`) */
    private static array $rest = [];
    /** @var list<string> 같은 요청의 쿼리만 — 소비자 입력을 쿼리로 보내는 메서드를 가른다(`queriesInput`) */
    private static array $queries = [];
    /**
     * 진짜 전송 핸들러 — 있으면 토큰 부여·serverinfo 밖의 요청은 가짜 응답 대신 이리로 간다(`testRealTransportFailure…`).
     *
     * @var (\Closure(RequestInterface, array<mixed>): PromiseInterface)|null
     */
    private static ?\Closure $transport = null;
    private static string $server = self::SERVER;

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
        // fschmtt 는 access_token 을 lcobucci 로 파싱하고(서명은 검증 안 한다) exp 로 만료를 본다 — 형태만 맞춘 JWT.
        self::$bearer = $b64('{"alg":"RS256","typ":"JWT"}') . '.'
            . $b64((string) json_encode(['exp' => time() + 300, 'iat' => time(), 'jti' => 'ADMbearer-jti-canary'])) . '.'
            . $b64('ADMbearer-signature-canary');
    }

    /**
     * 실패 방식 => 기대. `status` 는 `KeycloakAdminError::getStatusCode()`, `cause` 는 첫 원인의 [원본 클래스, 메시지 머리,
     * 메시지 꼬리] — 원인은 하위 예외 원본이 아니라 `SanitizedCause` 사본이다. `reach` 는 실패가 난 자리(공허성 검사). `id` 는
     * 경로로 가는 문자열 인자의 값(없으면 `id-1`).
     *
     * @return array<string, array{class: class-string<\Throwable>, status: ?int, message: string, cause: array{0: class-string<\Throwable>, 1: string, 2: string}, reach: string, id?: string}>
     */
    private static function modes(): array
    {
        $tokenUrl = self::SERVER . self::TOKEN_PATH;
        $withheld = '(message withheld: thrown outside the audited libraries)';

        return [
            // 오류 본문이 토큰·설명을 되울린다 — 메시지에는 상태와 코드 모양의 error 만.
            'token 401 · error body echoes' => ['class' => KeycloakAdminError::class, 'status' => 401,
                'message' => 'admin token request failed: HTTP 401 (invalid_client)',
                'cause' => [ClientException::class, "HTTP 401 from POST $tokenUrl (response body withheld)", ''], 'reach' => 'token'],
            // 200 인데 JSON 이 아니다 — fschmtt 의 json_decode 가 본문을 인자로 쥔 채 던진다.
            'token 200 · non-JSON body' => ['class' => KeycloakAdminError::class, 'status' => null,
                'message' => 'admin request failed unexpectedly',
                'cause' => [\JsonException::class, $withheld, ''], 'reach' => 'token'],
            'token unreachable' => ['class' => KeycloakTransportError::class, 'status' => null,
                'message' => 'admin request unreachable',
                'cause' => [ConnectException::class, $withheld, ''], 'reach' => 'token'],
            // admin REST 의 오류 본문은 OAuth 응답이 아니다 — 코드 모양의 error 가 있어도 싣지 않는다.
            'admin 409 · error body echoes' => ['class' => KeycloakConflictError::class, 'status' => 409,
                'message' => 'admin request failed: HTTP 409',
                'cause' => [ClientException::class, 'HTTP 409 from ', ' (response body withheld)'], 'reach' => 'admin'],
            'admin 500 · HTML body' => ['class' => KeycloakAdminError::class, 'status' => 500,
                'message' => 'admin request failed: HTTP 500',
                'cause' => [ServerException::class, 'HTTP 500 from ', ' (response body withheld)'], 'reach' => 'admin'],
            'admin unreachable' => ['class' => KeycloakTransportError::class, 'status' => null,
                'message' => 'admin request unreachable',
                'cause' => [ConnectException::class, $withheld, ''], 'reach' => 'admin'],
            // 경로로 가는 식별자가 admin 경로를 토큰 부여의 꼬리로 끝나게 해도 admin 요청이다(fschmtt 는 경로 값을 인코딩하지
            // 않는다) — 코드 모양의 error 가 있어도 싣지 않는다. 식별자 없는 메서드는 이 칸에서 보통 404 의 대조군이다.
            'admin 404 · path identifier ends in the token path' => ['class' => KeycloakNotFoundError::class, 'status' => 404,
                'message' => 'admin request failed: HTTP 404',
                'cause' => [ClientException::class, 'HTTP 404 from ', ' (response body withheld)'], 'reach' => 'admin',
                'id' => 'id-1/protocol/openid-connect/token'],
            // 같은 것의 5xx 갈래 — Keycloak 의 500 본문은 코드 모양이다(`unknown_error`).
            'admin 500 · path identifier ends in the token path' => ['class' => KeycloakAdminError::class, 'status' => 500,
                'message' => 'admin request failed: HTTP 500',
                'cause' => [ServerException::class, 'HTTP 500 from ', ' (response body withheld)'], 'reach' => 'admin',
                'id' => 'id-1/protocol/openid-connect/token'],
        ];
    }

    /**
     * 실제 fschmtt 스택 — 핸들러만 가짜다(`$transport` 가 있으면 admin 요청은 진짜 핸들러로 간다). ⚠️ 핸들러는 아무것도
     * 캡처하지 않는다(정적 상태와 상수만 읽는다).
     */
    private static function keycloak(): Keycloak
    {
        $handler = static function (RequestInterface $req, array $options): PromiseInterface {
            $path = $req->getUri()->getPath();
            self::$sent[] = $req->getMethod() . ' ' . $path;
            self::$rest[] = $req->getUri()->getQuery() . ' ' . $req->getBody();
            self::$queries[] = $req->getUri()->getQuery();
            $json = ['Content-Type' => 'application/json'];
            if ($path === self::TOKEN_PATH) {
                return match (self::$mode) {
                    'token 401 · error body echoes' => Create::promiseFor(new Response(401, $json, (string) json_encode([
                        'error' => 'invalid_client', 'error_description' => self::BODY, 'access_token' => self::BODY,
                    ]))),
                    'token 200 · non-JSON body' => Create::promiseFor(new Response(200, $json, self::BODY)),
                    'token unreachable' => Create::rejectionFor(new ConnectException('connection refused', $req)),
                    default => Create::promiseFor(new Response(200, $json, (string) json_encode([
                        'access_token' => self::$bearer, 'expires_in' => 300, 'token_type' => 'Bearer',
                    ]))),
                };
            }
            if ($path === '/admin/serverinfo') {
                // fschmtt 는 첫 자원 접근 전에 서버 버전을 묻는다 — 여기서 실패하면 자원 엔드포인트에 못 닿는다.
                return Create::promiseFor(new Response(200, $json, '{"systemInfo":{"version":"26.0.0"}}'));
            }
            if (self::$transport !== null) {
                return (self::$transport)($req, $options);
            }

            return match (self::$mode) {
                'admin 409 · error body echoes' => Create::promiseFor(new Response(409, $json, (string) json_encode([
                    'error' => 'conflict_code', 'errorMessage' => self::BODY,
                ]))),
                'admin 500 · HTML body' => Create::promiseFor(new Response(500, ['Content-Type' => 'text/html'], '<p>' . self::BODY . '</p>')),
                'admin unreachable' => Create::rejectionFor(new ConnectException('connection refused', $req)),
                'admin 404 · path identifier ends in the token path' => Create::promiseFor(new Response(404, $json, (string) json_encode([
                    'error' => 'invalid_client', 'error_description' => self::BODY,
                ]))),
                'admin 500 · path identifier ends in the token path' => Create::promiseFor(new Response(500, $json, (string) json_encode([
                    'error' => 'unknown_error', 'error_description' => self::BODY,
                ]))),
                default => Create::promiseFor(new Response(204)),
            };
        };

        return (new Builder())
            ->withBaseUrl(self::$server)
            ->withGrantType(GrantType::clientCredentials(clientId: 'c', clientSecret: self::SECRET, realm: self::REALM))
            // 시간 제한은 진짜 핸들러에만 뜻이 있다(응답하지 않는 소켓 — `testRealTransportFailure…`).
            ->withHttpClient(new GuzzleClient(['handler' => HandlerStack::create($handler), 'timeout' => 0.25, 'connect_timeout' => 0.25]))
            ->build();
    }

    /**
     * `AdminClient` 가 내주는 자원 클래스의 공개 메서드 전부 — `짧은클래스::메서드 => [클래스, 메서드]`.
     *
     * @return array<string, array{0: class-string, 1: string}>
     */
    private static function facadeMethods(): array
    {
        $out = [];
        foreach ((new \ReflectionClass(AdminClient::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $accessor) {
            $type = $accessor->getReturnType();
            if (!$type instanceof \ReflectionNamedType || !str_starts_with($type->getName(), 'Xzawed\\Keycloak\\Admin\\')) {
                continue;   // raw() 는 fschmtt 를 그대로 내준다(§4(b) 탈출구) — 파사드가 아니다.
            }
            $class = $type->getName();
            self::assertTrue(class_exists($class));
            $rc = new \ReflectionClass($class);
            foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                if (!$m->isStatic() && !str_starts_with($m->getName(), '__') && $m->getDeclaringClass()->getName() === $class) {
                    $out[$rc->getShortName() . '::' . $m->getName()] = [$class, $m->getName()];
                }
            }
        }
        ksort($out);

        return $out;
    }

    /**
     * 타입으로 합성한 인자 — representation 과 검색 조건은 카나리아를 품는다(소비자가 보내는 비밀번호·client secret·검색어 자리).
     * `$str` 는 문자열 자리의 값이다(생성자는 realm, 메서드는 `hiddenStrings` 가 가른 값).
     */
    private static function arg(\ReflectionParameter $p, Keycloak $kc, string $str): mixed
    {
        $type = $p->getType();
        $name = $type instanceof \ReflectionNamedType ? $type->getName() : '(union)';

        return match ($name) {
            Keycloak::class => $kc,
            'string' => $str,
            Criteria::class => new Criteria(['search' => self::INPUT]),
            User::class => new User(username: 'u1', credentials: new CredentialCollection([new Credential(type: 'password', value: self::INPUT)])),
            Client::class => new Client(id: 'c-uuid', clientId: 'c2', secret: self::INPUT),
            Realm::class => new Realm(realm: 'r2', displayName: self::INPUT),
            Group::class => new Group(name: self::INPUT),
            Role::class => new Role(name: 'role-1', description: self::INPUT),
            default => self::fail("{$p->getDeclaringClass()?->getName()}::{$p->getDeclaringFunction()->getName()} 의 인자 \${$p->getName()}: 합성할 줄 모르는 타입 $name — 여기 더하라"),
        };
    }

    /**
     * ⚠️ 인자를 가린다 — 가리지 않으면 이 프레임이 representation 을 쥐고 SDK 와 무관한 누출이 잡힌다. `$call` 은
     * `ReflectionMethod::getClosure()` 라 그 호출 프레임이 곧 파사드 메서드의 프레임이다(사이에 리플렉션 프레임이 없다).
     *
     * @param list<mixed> $args
     */
    private static function invoke(\Closure $call, #[\SensitiveParameter] array $args): ?\Throwable
    {
        try {
            $call(...$args);
        } catch (\Throwable $e) {
            return $e;
        }

        return null;
    }

    /** @return list<string> 정적 상태를 함수로 읽는다 — 핸들러가 바꾸는 것을 정적 분석이 「항상 빈 배열」로 좁히지 않게. */
    private static function sent(): array
    {
        return self::$sent;
    }

    /** @return list<string> `sent()` 와 같은 이유로 함수로 읽는다. */
    private static function rest(): array
    {
        return self::$rest;
    }

    /**
     * 수신자와 인자를 만든다. 문자열 인자는 `$str($p)` 가 정한다.
     *
     * @param array{0: class-string, 1: string} $target
     * @param \Closure(\ReflectionParameter): string $str
     * @return array{0: \Closure, 1: list<mixed>}
     */
    private static function build(array $target, \Closure $str): array
    {
        [$class, $method] = $target;
        $kc = self::keycloak();
        $ctor = (new \ReflectionClass($class))->getConstructor();
        $receiver = new $class(...array_map(static fn (\ReflectionParameter $p): mixed => self::arg($p, $kc, self::REALM), $ctor?->getParameters() ?? []));
        $m = new \ReflectionMethod($class, $method);

        return [$m->getClosure($receiver), array_map(static fn (\ReflectionParameter $p): mixed => self::arg($p, $kc, $str($p)), $m->getParameters())];
    }

    /**
     * 문자열 인자 중 **경로가 아닌 곳**(쿼리·본문)으로 가는 것 — 정상 IdP 위에서 인자마다 다른 표지를 넣고 한 번 불러, 표지가
     * 요청 경로에 나타나는지 잰다. 경로에 없으면 가려야 할 입력이고, 쿼리·본문에도 없으면(어디에도 안 실림) 실패한다.
     *
     * @param array{0: class-string, 1: string} $target
     * @return list<string> 파라미터 이름
     */
    private static function hiddenStrings(array $target): array
    {
        self::$mode = '';
        self::$sent = [];
        self::$rest = [];
        [$call, $args] = self::build($target, static fn (\ReflectionParameter $p): string => 'ADMstr' . $p->getPosition() . 'x' . $p->getName());
        self::invoke($call, $args);
        $paths = implode("\n", self::sent());
        $rest = implode("\n", self::rest());
        $hidden = [];
        foreach ((new \ReflectionMethod($target[0], $target[1]))->getParameters() as $p) {
            $marker = 'ADMstr' . $p->getPosition() . 'x' . $p->getName();
            $type = $p->getType();
            if ($type instanceof \ReflectionNamedType && $type->getName() === 'string' && !str_contains($paths, $marker)) {
                // 공허 방지 — 경로에 없다면 쿼리·본문에는 실렸어야 한다(어디에도 없으면 이 재기 자체를 의심한다).
                self::assertStringContainsString($marker, $rest, "{$target[1]}(\${$p->getName()}): 표지가 요청 어디에도 없다");
                $hidden[] = $p->getName();
            }
        }

        return $hidden;
    }

    /** @return array<string, string> 찍는 길 => 출력. `(string)` 은 원인 사슬 전부의 메시지·트레이스를 담는다. */
    private static function renderings(\Throwable $e): array
    {
        ob_start();
        var_dump($e);
        $out = ['getMessage' => $e->getMessage(), '(string)' => (string) $e, 'getTraceAsString' => $e->getTraceAsString(),
            'var_dump' => (string) ob_get_clean(), 'print_r' => print_r($e, true)];
        for ($l = $e->getPrevious(), $i = 1; $l !== null; $l = $l->getPrevious(), $i++) {
            $out["cause[$i]"] = $l::class . ': ' . $l->getMessage() . "\n" . $l->getTraceAsString();
        }

        return $out;
    }

    /**
     * 한 칸(메서드 × 실패 방식)의 위반 — 비면 통과.
     *
     * @param array{0: class-string, 1: string} $target
     * @param array{class: class-string<\Throwable>, status: ?int, message: string, cause: array{0: class-string<\Throwable>, 1: string, 2: string}, reach: string, id?: string} $want
     * @return list<string>
     */
    private static function cell(array $target, string $mode, array $want): array
    {
        $hidden = self::hiddenStrings($target);
        self::$mode = $mode;
        self::$sent = [];
        self::$rest = [];
        $id = $want['id'] ?? 'id-1';
        [$call, $args] = self::build($target, static fn (\ReflectionParameter $p): string => in_array($p->getName(), $hidden, true) ? self::INPUT : $id);
        $e = self::invoke($call, $args);

        $why = [];
        $reached = array_filter(self::sent(), static fn (string $s): bool => $want['reach'] === 'token'
            ? $s === 'POST ' . self::TOKEN_PATH
            : !str_ends_with($s, self::TOKEN_PATH) && $s !== 'GET /admin/serverinfo');
        if ($reached === []) {
            $why[] = '실패를 낼 자리에 안 닿았다(공허): ' . implode(', ', self::sent());
        }
        if ($e === null) {
            return [...$why, '오류 없이 끝났다'];
        }
        if ($e::class !== $want['class']) {
            $why[] = 'SDK 타입이 ' . $e::class . " — 기대 {$want['class']}";
        }
        if ($e instanceof KeycloakAdminError && $e->getStatusCode() !== $want['status']) {
            $why[] = 'getStatusCode() ' . var_export($e->getStatusCode(), true) . ' — 기대 ' . var_export($want['status'], true);
        }
        if ($e->getMessage() !== $want['message']) {
            $why[] = 'getMessage() ' . json_encode($e->getMessage()) . ' — 기대 ' . json_encode($want['message']);
        }
        for ($l = $e, $d = 0; $l !== null; $l = $l->getPrevious(), $d++) {
            if (!str_starts_with($l::class, 'Xzawed\\Keycloak\\')) {
                $why[] = "원인 사슬 [$d] 이 하위 예외 원본 " . $l::class . '(§4)';
            }
        }
        $cause = $e->getPrevious();
        [$origin, $head, $tail] = $want['cause'];
        if (!$cause instanceof SanitizedCause || $cause->originalClass !== $origin) {
            $why[] = '첫 원인이 ' . ($cause === null ? 'null' : $cause::class) . " — 기대 $origin 의 SanitizedCause";
        } elseif (!str_starts_with($cause->getMessage(), "$origin: $head") || !str_ends_with($cause->getMessage(), $tail)) {
            $why[] = '원인 메시지 ' . json_encode($cause->getMessage()) . ' — 기대 ' . json_encode("{$origin}: {$head}…{$tail}");
        }

        return [...$why, ...self::printed($e)];
    }

    /** @return list<string> 카나리아가 찍힌 자리 — 원문, 또는 (JWT 가 아닌 값은) 앞 10 자. */
    private static function printed(\Throwable $e): array
    {
        $why = [];
        $canaries = ['SECRET' => [self::SECRET, true], 'BODY' => [self::BODY, true], 'INPUT' => [self::INPUT, true], 'BEARER' => [self::$bearer, false]];
        foreach (self::renderings($e) as $how => $out) {
            foreach ($canaries as $name => [$value, $prefix]) {
                if (str_contains($out, $value)) {
                    $why[] = "$name 가 $how 에 원문으로 찍혔다";
                } elseif ($prefix && str_contains($out, substr($value, 0, 10))) {
                    $why[] = "$name 가 $how 에 앞 10 자로 찍혔다";
                }
            }
        }

        return $why;
    }

    public function testAdminFailuresDoNotPrintSecretsBearerBodiesOrInputs(): void
    {
        $methods = self::facadeMethods();
        // 공허성 — 걷기가 다섯 자원을 다 찾았는가(0 이면 아래 루프는 아무것도 안 재며 통과한다).
        self::assertGreaterThanOrEqual(5, count(array_unique(array_column($methods, 0))), '자원 클래스를 못 찾았다');
        $fails = [];
        $cells = 0;
        foreach ($methods as $label => $target) {
            foreach (self::modes() as $mode => $want) {
                $cells++;
                foreach (self::cell($target, $mode, $want) as $why) {
                    $fails[] = "$label / $mode: $why";
                }
            }
        }
        self::assertGreaterThan(0, $cells);
        self::assertSame([], $fails, sprintf("admin 오류 %d 칸 중 위반 %d 건:\n%s", $cells, count($fails), implode("\n", $fails)));
    }

    /** @return list<string> `sent()` 와 같은 이유로 함수로 읽는다. */
    private static function queries(): array
    {
        return self::$queries;
    }

    /**
     * 소비자 입력(검색 조건·숨김 문자열)을 **쿼리로** 보내는 메서드인가 — 정상 IdP 위에서 카나리아를 넣어 한 번 불러 잰다.
     *
     * @param array{0: class-string, 1: string} $target
     * @param list<string> $hidden
     */
    private static function queriesInput(array $target, array $hidden): bool
    {
        self::$mode = '';
        self::$queries = [];
        [$call, $args] = self::build($target, static fn (\ReflectionParameter $p): string => in_array($p->getName(), $hidden, true) ? self::INPUT : 'id-1');
        self::invoke($call, $args);

        return str_contains(implode("\n", self::queries()), self::INPUT);
    }

    /**
     * 진짜 전송 핸들러로 admin 요청이 시간 초과된 한 칸의 위반 — 비면 통과.
     *
     * @param array{0: class-string, 1: string} $target
     * @param list<string> $hidden
     * @return list<string>
     */
    private static function transportCell(array $target, array $hidden): array
    {
        self::$sent = [];
        [$call, $args] = self::build($target, static fn (\ReflectionParameter $p): string => in_array($p->getName(), $hidden, true) ? self::INPUT : 'id-1');
        $e = self::invoke($call, $args);
        $admin = array_values(array_filter(self::sent(), static fn (string $s): bool => !str_ends_with($s, self::TOKEN_PATH) && $s !== 'GET /admin/serverinfo'));
        if ($admin === []) {
            return ['admin 요청에 안 닿았다(공허): ' . implode(', ', self::sent())];
        }
        if (!$e instanceof KeycloakTransportError) {
            return ['SDK 타입이 ' . ($e === null ? '(오류 없음)' : $e::class) . ' — 기대 ' . KeycloakTransportError::class];
        }
        $why = [];
        $cause = $e->getPrevious();
        $messages = [ConnectException::class => 'admin request unreachable', RequestException::class => 'admin request failed'];
        if (!$cause instanceof SanitizedCause || !isset($messages[$cause->originalClass])) {
            $why[] = '첫 원인이 ' . ($cause === null ? 'null' : $cause::class) . ' — 기대 Guzzle 전송 예외의 SanitizedCause';
        } else {
            if ($e->getMessage() !== $messages[$cause->originalClass]) {
                $why[] = 'getMessage() ' . json_encode($e->getMessage()) . ' — 기대 ' . json_encode($messages[$cause->originalClass]);
            }
            // 진단은 남는다 — 쿼리를 뺀 URL(경로까지)은 원인 메시지에 있다(메시지를 통째로 거두면 이 칸이 실패한다).
            $last = $admin[count($admin) - 1];
            $url = self::$server . substr($last, (int) strpos($last, ' ') + 1);
            if (!str_contains($cause->getMessage(), $url)) {
                $why[] = '원인 메시지에 쿼리를 뺀 URL ' . $url . ' 이 없다: ' . json_encode($cause->getMessage());
            }
        }

        return [...$why, ...self::printed($e)];
    }

    /**
     * Guzzle 의 진짜 전송 실패는 요청 URL 을 **쿼리째** 메시지에 싣는다 — curl `cURL error 28: … for <URL>`, stream `Connection
     * refused for URI <URL>`(실측 2026-10-02). admin 검색의 쿼리는 소비자의 검색어·username 이라 원인 사본이 그대로 옮기면 `(string)`·
     * `var_dump`·`print_r` 에 찍혔다 — 토큰을 캐시한 뒤 Keycloak 이 느려지거나 끊기면 나는 흔한 실패다. 응답하지 않는 소켓에 진짜
     * 핸들러를 붙여(토큰 부여·serverinfo 만 가짜) 시간 초과를 낸다. 쿼리로 입력을 보내는 메서드는 손 목록이 아니라 잰다(`queriesInput`).
     */
    public function testRealTransportFailureCauseKeepsTheUrlButNotItsQuery(): void
    {
        $handlers = [];
        if (\function_exists('curl_exec') && \function_exists('curl_multi_exec')) {
            $handlers['curl'] = (new CurlHandler())(...);
        }
        if (filter_var(\ini_get('allow_url_fopen'), \FILTER_VALIDATE_BOOL)) {
            $handlers['stream'] = (new StreamHandler())(...);
        }
        self::assertNotSame([], $handlers, '전송 핸들러가 하나도 없다');
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);   // 받기만 하고 답하지 않는다
        self::assertNotFalse($socket, (string) $errstr);
        $queried = [];
        $fails = [];
        try {
            $address = stream_socket_get_name($socket, false);
            self::assertIsString($address);
            self::$server = "http://$address";
            foreach (self::facadeMethods() as $label => $target) {
                $hidden = self::hiddenStrings($target);
                if (!self::queriesInput($target, $hidden)) {
                    continue;
                }
                $queried[] = $label;
                foreach ($handlers as $name => $transport) {
                    self::$transport = $transport;
                    foreach (self::transportCell($target, $hidden) as $why) {
                        $fails[] = "$label / $name: $why";
                    }
                    self::$transport = null;
                }
            }
        } finally {
            self::$transport = null;
            self::$server = self::SERVER;
            fclose($socket);
        }
        self::assertNotSame([], $queried, '쿼리로 입력을 보내는 메서드를 못 찾았다(공허)');
        $cells = count($queried) * count($handlers);
        self::assertSame([], $fails, sprintf("진짜 전송 실패 %d 칸(%s × %s) 중 위반 %d 건:\n%s", $cells, implode('·', $queried), implode('·', array_keys($handlers)), count($fails), implode("\n", $fails)));
    }
}
