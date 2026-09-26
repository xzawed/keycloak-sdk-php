<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\Admin\ErrorTranslation;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * 바닥 계약(기본 표현이 비밀을 찍지 않는다)을 **손으로 고른 값 타입이 아니라 도달 가능한 객체 전부**에
 * 건다. `DumpMaskingTest` 는 값 타입 넷을 재는데, 실측(2026-09-26)으로 그 밖의 **파사드**가 새고 있었다:
 * `KeycloakClient`·`AuthClient` 의 `var_dump`·`print_r` 가 클라이언트 시크릿과 살아 있는 PKCE verifier 를,
 * `AdminClient` 가 시크릿을 원문으로 찍었다(중첩된 하위 라이브러리 객체를 덤프가 그대로 따라간다).
 *
 * ⚠️ **새 자리를 스스로 찾는 것이 요점이다**(등록부 `guard-detection-surface-hand-narrowed`). 검사 대상은
 * (1) 공개 API 로 만든 뿌리에서 리플렉션으로 **닿는 이 SDK 의 객체 전부**이고, (2) `php/src` 를 훑어 얻은
 * **클래스 선언 전수**가 그 걷기에 걸렸는지 대조한다. 인스턴스 상태가 없는 클래스(정적 도우미)는 규칙으로
 * 빠지고, 그 밖의 면제는 이유와 함께 아래 표에 적는다. Go 의 `facade_dump_test.go` 와 같은 모양이다.
 *
 * ⚠️ 예외는 `var_dump` 가 **트레이스 인자까지** 찍는다 — `#[\SensitiveParameter]` 가 빠진 자리가 여기서도
 * 드러난다(`zend.exception_ignore_args=0` 에서 잰다. 운영 php.ini 는 1 이라 인자를 안 모은다).
 *
 * ⚠️ 한계: 카나리아는 뿌리를 만드는 호출이 흘려 넣은 비밀뿐이다. `var_export` 는 `__debugInfo` 를 타지 않아
 * 여기서 재지 않는다(`php/README.md` 가 그 경계를 적는다).
 */
final class FacadeDumpTest extends TestCase
{
    private const SECRET = 'CANARY-DUMP-CLIENT-SECRET';
    private const ACCESS = 'CANARY-DUMP-ACCESS-TOKEN';
    private const REFRESH = 'CANARY-DUMP-REFRESH-TOKEN';
    private const ID = 'CANARY-DUMP-ID-TOKEN';
    private const GARBAGE = 'CANARY-DUMP-GARBAGE-TOKEN';
    private const PASSWORD = 'CANARY-DUMP-ADMIN-PASSWORD';
    private const SERVER = 'https://kc.test';

    /** 걷기에 안 닿아도 되는 클래스와 그 이유. ⚠️ 이유 없는 면제는 넣지 않는다. */
    private const EXEMPT = [
        \Xzawed\Keycloak\Admin\RenamableRoles::class => 'RolesResource::update 안에서 만들어 곧바로 버린다 — 반환·보관되지 않아 '
            . '소비자가 쥘 수 없다. 직접 만드는 길은 raw() 경유 fschmtt 표면이다(§4(b) 탈출구).',
    ];

    /**
     * 알려진 누출 — `"뿌리|카나리아"` 와 등록부 항목. ⚠️ 고쳐져 더 안 새면 **여기서 지워야 통과한다**(낡은 항목 검사).
     *
     * 비었다 — 전송 오류 뿌리 넷(introspect·logout 의 Guzzle 프레임 인자)은 SDK 가 하위 예외 원본 대신
     * `SanitizedCause`(인자를 뺀 트레이스)를 달면서 닫혔다(`php-exception-trace-third-party-args`). 적대적 응답
     * 쪽은 `MalformedTokenResponseTest` 가 잰다.
     *
     * @var array<string, string>
     */
    private const KNOWN_LEAKS = [];

    /** @return array<string, string> 비어 있어도 표다 — 상수의 리터럴 타입(`array{}`)으로 읽으면 조회가 「항상 거짓」이 된다. */
    private static function knownLeaks(): array
    {
        return self::KNOWN_LEAKS;
    }

    /** @var array<string, true> */
    private static array $knownSeen = [];

    // ⚠️ 하네스 상태는 **정적**으로 둔다 — 예외의 트레이스 인자에 PHPUnit 러너 프레임이 테스트 객체를 싣고,
    // `var_dump` 가 그 인스턴스 프로퍼티를 찍는다. 인스턴스에 카나리아를 두면 SDK 와 무관한 누출이 잡힌다
    // (실측: 예외 뿌리 전부가 카나리아 여덟을 다 찍었다). 정적 프로퍼티는 덤프에 안 나온다.
    /** @var array<string, string> 이름 => 값 */
    private static array $canaries = [];
    /** @var array<string, true> */
    private static array $visited = [];
    /** @var list<string> */
    private static array $leaks = [];

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
        self::$canaries = [];
        self::$knownSeen = [];
        self::$visited = [];
        self::$leaks = [];
    }

    /** @return array{priv:string,jwk:array<string,mixed>} */
    private static function rsaKey(): array
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        self::assertTrue(openssl_pkey_export($res, $priv));
        self::assertIsString($priv);
        $details = openssl_pkey_get_details($res);
        self::assertIsArray($details);
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        self::assertIsString($rsa['n']);
        self::assertIsString($rsa['e']);
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return ['priv' => $priv, 'jwk' => [
            'kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'alg' => 'RS256',
            'n' => $b64($rsa['n']), 'e' => $b64($rsa['e']),
        ]];
    }

    /**
     * 가짜 IdP — 경로로 응답을 고른다(순서 큐가 아니라서 호출 순서가 바뀌어도 안 깨진다).
     *
     * @param array<string, mixed> $jwk
     */
    private static function idp(array $jwk): GuzzleClient
    {
        $json = ['Content-Type' => 'application/json'];
        $handler = static function (RequestInterface $req) use ($json, $jwk): PromiseInterface {
            $path = $req->getUri()->getPath();
            return Create::promiseFor(match (true) {
                str_ends_with($path, '/realms/bad/protocol/openid-connect/token') => new Response(401, $json, '{"error":"invalid_client"}'),
                str_ends_with($path, '/token/introspect') => new Response(200, $json, '{"active":true,"username":"svc","client_id":"c","sub":"u1"}'),
                str_ends_with($path, '/token') => new Response(200, $json, json_encode([
                    'access_token' => self::ACCESS, 'token_type' => 'Bearer', 'expires_in' => 300,
                    'refresh_token' => self::REFRESH, 'id_token' => self::ID,
                ], JSON_THROW_ON_ERROR)),
                str_ends_with($path, '/certs') => new Response(200, $json, json_encode(['keys' => [$jwk]], JSON_THROW_ON_ERROR)),
                default => new Response(404),
            });
        };

        return new GuzzleClient(['handler' => HandlerStack::create($handler), 'http_errors' => true]);
    }

    private static function authClient(KeycloakConfig $cfg, GuzzleClient $http): AuthClient
    {
        $ep = new OidcEndpoints($cfg);

        return new AuthClient($cfg, $ep, new JwtValidator($cfg, $ep, new JwksStore($ep->jwks(), $http, new HttpFactory())), $http);
    }

    /** @return \Throwable */
    private static function caught(callable $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('실패 뿌리를 못 만들었다 — 가짜 IdP 가 실패를 안 냈다');
    }

    /**
     * 공개 API 로 뿌리를 만들고, 그 과정이 흘려 넣은 비밀 전부를 카나리아로 남긴다.
     *
     * @return array<string, object>
     */
    private function roots(): array
    {
        $key = self::rsaKey();
        $http = self::idp($key['jwk']);
        $cfg = new KeycloakConfig(self::SERVER, 'r', 'c', self::SECRET);

        $kc = KeycloakClient::create($cfg);
        $admin = $kc->admin();
        $ar = $kc->auth()->createAuthorizationRequest('https://app/cb');

        $auth = self::authClient($cfg, $http);
        $ts = $auth->clientCredentialsToken();
        $ir = $auth->introspect(self::ACCESS);
        $jwt = FbJwt::encode([
            'iss' => self::SERVER . '/realms/r', 'sub' => 'u1', 'aud' => 'c',
            'exp' => time() + 60, 'iat' => time(),
        ], $key['priv'], 'RS256', 'k1');
        $vt = $auth->validate($jwt);

        $provider = new ClientCredentialsTokenProvider($cfg, new OidcEndpoints($cfg), $http, new HttpFactory(), new HttpFactory());
        $provider->getToken();

        // ⚠️ 카나리아가 실제로 흘러 들어갔는가 — 안 흘렀으면 아래 누출 검사는 없는 것을 찾으며 통과한다.
        self::assertSame([self::ACCESS, self::REFRESH, self::ID], [$ts->accessToken, $ts->refreshToken, $ts->idToken]);
        self::assertNotSame('', $ar->codeVerifier);

        $adminBody = json_encode(['credentials' => [['type' => 'password', 'value' => self::PASSWORD]]], JSON_THROW_ON_ERROR);
        $adminReq = new Request('POST', self::SERVER . '/admin/realms/r/users', [], $adminBody);
        $down = self::authClient($cfg, new GuzzleClient(['handler' => HandlerStack::create(
            static fn (RequestInterface $r): PromiseInterface => Create::rejectionFor(new ConnectException('refused', $r)),
        )]));

        self::$canaries = [
            'SECRET' => self::SECRET, 'ACCESS' => self::ACCESS, 'REFRESH' => self::REFRESH, 'ID' => self::ID,
            'GARBAGE' => self::GARBAGE, 'PASSWORD' => self::PASSWORD, 'VERIFIER' => $ar->codeVerifier, 'JWT' => $jwt,
            // introspect 의 Basic 헤더 값 — 시크릿의 인코딩된 형태도 비밀이다.
            'BASIC' => base64_encode(rawurlencode('c') . ':' . rawurlencode(self::SECRET)),
        ];

        return [
            'KeycloakClient::create' => $kc,
            'admin()' => $admin,
            'users()' => $admin->users(), 'clients()' => $admin->clients(), 'realms()' => $admin->realms(),
            'roles()' => $admin->roles(), 'groups()' => $admin->groups(),
            'createAuthorizationRequest' => $ar,
            'AuthClient' => $auth, 'clientCredentialsToken' => $ts, 'introspect' => $ir, 'validate' => $vt,
            'ClientCredentialsTokenProvider' => $provider,
            'auth error' => self::caught(static fn () => self::authClient(new KeycloakConfig(self::SERVER, 'bad', 'c', self::SECRET), $http)->clientCredentialsToken()),
            'validation error' => self::caught(static fn () => $auth->validate(self::GARBAGE)),
            'introspect transport error' => self::caught(static fn () => $down->introspect(self::ACCESS)),
            'logout transport error' => self::caught(static fn () => $down->logout(self::REFRESH)),
            'config error' => self::caught(static fn () => new KeycloakConfig('', 'r', 'c', self::SECRET)),
            'admin 404' => self::caught(static fn () => ErrorTranslation::call(static fn () => throw new ClientException('HTTP 404', $adminReq, new Response(404)))),
            'admin 409' => self::caught(static fn () => ErrorTranslation::call(static fn () => throw new ClientException('HTTP 409', $adminReq, new Response(409)))),
            'admin 403' => self::caught(static fn () => ErrorTranslation::call(static fn () => throw new ClientException('HTTP 403', $adminReq, new Response(403)))),
            'admin 500' => self::caught(static fn () => ErrorTranslation::call(static fn () => throw new ServerException('HTTP 500', $adminReq, new Response(500)))),
        ];
    }

    private static function isOwn(object $o): bool
    {
        return str_starts_with($o::class, 'Xzawed\\Keycloak\\');
    }

    /** @param \SplObjectStorage<object, mixed> $seen */
    private function walk(mixed $v, string $path, \SplObjectStorage $seen): void
    {
        if (is_array($v)) {
            foreach ($v as $k => $x) {
                $this->walk($x, $path . '[' . $k . ']', $seen);
            }
            return;
        }
        if (!is_object($v) || $seen->contains($v)) {
            return;
        }
        $seen->attach($v);
        if (!self::isOwn($v)) {
            return;
        }
        for ($c = new \ReflectionClass($v); $c !== false; $c = $c->getParentClass()) {
            self::$visited[$c->getName()] = true;
        }
        $this->render($v, $path);
        // 부모의 private 까지 — ReflectionObject 는 자기 클래스의 private 만 준다.
        for ($c = new \ReflectionClass($v); $c !== false; $c = $c->getParentClass()) {
            foreach ($c->getProperties() as $p) {
                if ($p->isStatic() || $p->getDeclaringClass()->getName() !== $c->getName() || !$p->isInitialized($v)) {
                    continue;
                }
                $this->walk($p->getValue($v), $path . '->' . $p->getName(), $seen);
            }
        }
    }

    private function render(object $o, string $path): void
    {
        $outs = [];
        ob_start();
        var_dump($o);
        $outs['var_dump'] = (string) ob_get_clean();
        $outs['print_r'] = print_r($o, true);
        if ($o instanceof \Stringable) {
            $outs['(string)'] = (string) $o;
        }
        if ($o instanceof \JsonSerializable) {
            $outs['json_encode'] = (string) json_encode($o);
        }
        foreach ($outs as $how => $out) {
            foreach (self::$canaries as $name => $c) {
                if (str_contains($out, $c)) {
                    $key = strtok($path, '-[') . '|' . $name;
                    if (array_key_exists($key, self::knownLeaks())) {
                        self::$knownSeen[$key] = true;
                        continue;
                    }
                    self::$leaks[] = sprintf('%s [%s] %s: 비밀 %s 가 원문으로 찍혔다', $path, $o::class, $how, $name);
                }
            }
        }
    }

    /** @return list<class-string> `php/src` 의 클래스 선언 전수 — 손 목록이 아니라 트리에서 파생한다. */
    private static function declaredClasses(): array
    {
        $found = [];
        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(\dirname(__DIR__, 2) . '/src')) as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $src = (string) file_get_contents($file->getPathname());
            if (
                preg_match('/^namespace\s+([^;]+);/m', $src, $ns) === 1
                && preg_match('/^(?:final\s+|abstract\s+|readonly\s+)*class\s+(\w+)/m', $src, $cls) === 1
            ) {
                $fqcn = trim($ns[1]) . '\\' . $cls[1];
                if (class_exists($fqcn)) {
                    $found[] = $fqcn;
                }
            }
        }
        sort($found);

        return $found;
    }

    public function testReachableObjectsDoNotDumpSecrets(): void
    {
        $roots = $this->roots();
        $seen = new \SplObjectStorage();
        foreach ($roots as $name => $obj) {
            $this->walk($obj, $name, $seen);
        }
        self::assertSame([], self::$leaks, "기본 표현이 비밀을 찍는다:\n" . implode("\n", self::$leaks));
        self::assertSame(
            [],
            array_keys(array_diff_key(self::knownLeaks(), self::$knownSeen)),
            '알려진 누출이 더 안 난다 — 고쳐졌으면 KNOWN_LEAKS 와 등록부 항목을 함께 닫아라',
        );

        $declared = self::declaredClasses();
        self::assertGreaterThanOrEqual(20, count($declared), 'php/src 반사가 클래스를 거의 못 찾았다 — 파생이 공허하다');
        $problems = [];
        foreach ($declared as $class) {
            $stateless = (new \ReflectionClass($class))->getProperties() === []
                || array_filter((new \ReflectionClass($class))->getProperties(), static fn (\ReflectionProperty $p): bool => !$p->isStatic()) === [];
            $reached = isset(self::$visited[$class]);
            $exempt = array_key_exists($class, self::EXEMPT);
            if ($reached && $exempt) {
                $problems[] = "$class: 걷기에 닿는데 면제 표에도 있다 — 면제를 지워라";
            } elseif (!$reached && !$exempt && !$stateless) {
                $problems[] = "$class: 공개 API 뿌리에서 닿지 않는 상태 있는 클래스다 — 만드는 경로를 뿌리에 더하거나, 이유와 함께 면제하라";
            }
        }
        foreach (array_keys(self::EXEMPT) as $class) {
            if (!in_array($class, $declared, true)) {
                $problems[] = "$class: 면제 표에 있지만 선언이 없다 — 낡은 면제다";
            }
        }
        self::assertSame([], $problems, implode("\n", $problems));
    }
}
