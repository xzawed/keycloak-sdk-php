<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Token\AuthorizationRequest;

/**
 * 인가 코드 교환 E2E — 실제 Keycloak 26.6 이 발급한 코드·id_token 으로.
 *
 * `exchangeCode()` 의 nonce 대조와 id_token 서명 검증은 지금까지 목 토큰으로만 돌았다. 여기서는 {@see BrowserLogin} 으로
 * 실제 로그인해 받은 코드를 교환하고, **서버가 서명한** 토큰에 대고 거부 경로까지 돈다(python 파일럿
 * `test_code_exchange_it.py` 와 같은 모양). realm 의 `it-web`(RS256 · PKCE S256 강제 · aud 매퍼)·`it-web-hs256`
 * (id_token 을 HS256 서명)과 짝이다. 서명만 틀린 RS256 id_token 은 실서버가 만들 수 없다 — 그 거부는 단위
 * `AuthClientNonceTest::testExchangeCodeRejectsUntrustedIdToken` 이 고정한다.
 *
 * ⚠️ 교환은 인가 요청을 만든 인스턴스가 아니라 **새 클라이언트**로 한다. `AuthClient` 는 league 프로바이더에 PKCE
 * verifier 를 쥐고 있어, 같은 인스턴스로 교환하면 `exchangeCode()` 가 넘겨받은 verifier 를 무시해도 초록이다(실측:
 * 인스턴스를 공유하게 바꾸면 그 변이 앞에서 6 중 5 가 침묵). `exchangeCode()` 는 무상태라고 약속하고(docblock),
 * PHP-FPM 에서 콜백은 실제로 새 프로세스다.
 *
 * ⚠️ 거부는 전부 `try`/`catch` 로 이 본문에서 직접 받는다 — 비밀을 인자로도 클로저 캡처로도 넘기지 않는다. 예외
 * 트레이스 인자에 이 프레임 위의 호출이 실리고 `var_dump`·`print_r` 가 클로저의 캡처까지 따라가, SDK 가 아니라
 * 테스트가 흘린 값이 잡힌다(`MalformedTokenResponseTest` 의 실측). 트레이스 인자는 `zend.exception_ignore_args=0`
 * 에서 잰다(운영 php.ini 는 1 이라 안 모은다).
 */
final class CodeExchangeIT extends TestCase
{
    use KeycloakContainerTrait;

    private const REDIRECT_URI = 'http://localhost/it-callback';
    private const WEB_CLIENT_SECRETS = ['it-web' => 'it-web-secret', 'it-web-hs256' => 'it-web-hs256-secret'];
    private const USERNAME = 'alice';
    private const PASSWORD = 'alice-password';
    private const UNEXPECTED_NONCE = 'authorization code exchange failed: unexpected nonce';
    /** 이름을 모르는 토큰까지 — 거부 경로가 id_token 을 사슬에 달면 테스트는 그 값을 손에 넣지 못한다. */
    private const JWT = '/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./';

    private string|false $ignoreArgs = false;

    public static function setUpBeforeClass(): void
    {
        self::startKeycloak();
    }

    public static function tearDownAfterClass(): void
    {
        self::stopKeycloak();
    }

    protected function setUp(): void
    {
        $this->ignoreArgs = ini_set('zend.exception_ignore_args', '0');
    }

    protected function tearDown(): void
    {
        if ($this->ignoreArgs !== false) {
            ini_set('zend.exception_ignore_args', $this->ignoreArgs);
        }
    }

    public function testExchangeCodeBindsTokensToTheNonceAndUser(): void
    {
        [$request, $code] = self::login();
        $auth = self::web()->auth();
        $tokens = $auth->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
        self::assertNotNull($tokens->refreshToken);
        self::assertNotNull($tokens->idToken);
        $aliceId = self::aliceId();
        $id = $auth->validate($tokens->idToken);
        self::assertSame($request->nonce, $id->claims['nonce'] ?? null);
        self::assertSame($aliceId, $id->subject);
        // 교환이 돌려준 접근 토큰 자체가 그 사용자의 활성 토큰이다(가짜로 바꿔 끼워도 아래 refresh 는 초록이다).
        $issued = $auth->introspect($tokens->accessToken);
        self::assertTrue($issued->active);
        self::assertSame(self::USERNAME, $issued->username);

        // refresh: 새 접근 토큰을 준다 — 같은 사용자의 활성 토큰이다.
        $refreshed = $auth->refresh($tokens->refreshToken);
        self::assertNotSame($tokens->accessToken, $refreshed->accessToken);
        self::assertNotNull($refreshed->refreshToken);
        $active = $auth->introspect($refreshed->accessToken);
        self::assertTrue($active->active);
        self::assertSame(self::USERNAME, $active->username);

        // logout: 세션을 끝낸다 — 그 refresh token 은 더는 갱신되지 않고 접근 토큰은 비활성이 된다.
        $auth->logout($refreshed->refreshToken);
        try {
            $auth->refresh($refreshed->refreshToken);
            self::fail('a refresh token of a logged-out session must be refused');
        } catch (KeycloakAuthError $ended) {
        }
        self::assertSame('invalid_grant', $ended->oauthError);
        self::assertLeaksNothing($ended, [
            'refresh_token' => $refreshed->refreshToken,
            'client_secret' => self::WEB_CLIENT_SECRETS['it-web'],
        ]);
        self::assertFalse($auth->introspect($refreshed->accessToken)->active);
    }

    public function testExchangeCodeRefusesANonceTheServerDidNotSign(): void
    {
        [$request, $code] = self::login();
        try {
            self::web()->auth()->exchangeCode($code, $request->codeVerifier, 'x' . $request->nonce, self::REDIRECT_URI);
            self::fail('a nonce the server did not sign must be refused');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertSame(self::UNEXPECTED_NONCE, $refused->getMessage());
        self::assertNull($refused->oauthError); // 서버가 아니라 SDK 가 거부했다
        self::assertLeaksNothing($refused, self::inputs($request, $code, 'it-web'));
    }

    /** nonce 를 빼고 인가받은 코드 — 서버는 nonce 없는 id_token 을 낸다. 부재도 거부다. */
    public function testExchangeCodeRefusesAnIdTokenThatCarriesNoNonce(): void
    {
        $request = self::stripNonce(self::web()->auth()->createAuthorizationRequest(self::REDIRECT_URI));
        // 전제: 서버가 정말 nonce 없이 서명한다(아니면 아래는 부재가 아니라 불일치를 잰다).
        $code = BrowserLogin::login($request, self::REDIRECT_URI, self::USERNAME, self::PASSWORD);
        $auth = self::web()->auth();
        $unchecked = $auth->exchangeCode($code, $request->codeVerifier, null, self::REDIRECT_URI);
        self::assertNotNull($unchecked->idToken);
        self::assertArrayNotHasKey('nonce', $auth->validate($unchecked->idToken)->claims);

        $code = BrowserLogin::login($request, self::REDIRECT_URI, self::USERNAME, self::PASSWORD);
        try {
            self::web()->auth()->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
            self::fail('an id_token without a nonce must be refused when a nonce is expected');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertSame(self::UNEXPECTED_NONCE, $refused->getMessage());
        self::assertLeaksNothing($refused, self::inputs($request, $code, 'it-web'));
    }

    /** 인가 범위에 `openid` 가 없으면 서버는 id_token 을 내지 않는다 — nonce 를 기대하면 그 부재도 거부다. */
    public function testExchangeCodeRefusesATokenResponseWithoutAnIdToken(): void
    {
        $request = self::web(scopes: ['profile'])->auth()->createAuthorizationRequest(self::REDIRECT_URI);
        // 전제: 서버가 정말 id_token 없이 답한다(아니면 아래는 부재가 아니라 다른 거부를 잰다).
        $code = BrowserLogin::login($request, self::REDIRECT_URI, self::USERNAME, self::PASSWORD);
        $unchecked = self::web()->auth()->exchangeCode($code, $request->codeVerifier, null, self::REDIRECT_URI);
        self::assertNull($unchecked->idToken);

        $code = BrowserLogin::login($request, self::REDIRECT_URI, self::USERNAME, self::PASSWORD);
        try {
            self::web()->auth()->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
            self::fail('a token response without an id_token must be refused when a nonce is expected');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertSame('authorization code exchange failed: missing id_token for nonce validation', $refused->getMessage());
        self::assertLeaksNothing($refused, self::inputs($request, $code, 'it-web'));
    }

    public function testReusedCodeIsRefusedWithoutLeakingIt(): void
    {
        [$request, $code] = self::login();
        $auth = self::web()->auth();
        // 로그인 자체(콜백 URL 에 코드가 실린다)는 SDK 의 누출이 아니다 — 여기서부터 잰다.
        $log = tempnam(sys_get_temp_dir(), 'kc-php-it-');
        self::assertIsString($log);
        $errorLog = ini_set('error_log', $log);
        $reused = null;
        ob_start();
        try {
            $tokens = $auth->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
            try {
                $auth->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
            } catch (KeycloakAuthError $e) {
                $reused = $e;
            }
        } finally {
            $printed = (string) ob_get_clean();
            ini_set('error_log', $errorLog === false ? '' : $errorLog);
            $printed .= (string) file_get_contents($log);
            unlink($log);
        }
        self::assertInstanceOf(KeycloakAuthError::class, $reused, 'a reused code must be refused');
        self::assertSame('invalid_grant', $reused->oauthError);
        self::assertLeaksNothing($reused, self::inputs($request, $code, 'it-web') + [
            'access_token' => $tokens->accessToken,
            'refresh_token' => $tokens->refreshToken,
            'id_token' => $tokens->idToken,
        ], $printed);
    }

    /** @return iterable<string, array{list<string>, non-empty-string}> */
    public static function hs256Pins(): iterable
    {
        // 알고리즘 핀이 먼저 거부한다.
        yield 'pinned to RS256' => [['RS256'], 'algorithm not allowed: HS256'];
        // 핀을 열어도 그 키(realm 의 HMAC 비밀)는 JWKS 에 없다.
        yield 'HS256 allowed' => [['RS256', 'HS256'], 'unknown kid'];
    }

    /**
     * `it-web-hs256` 의 id_token 은 realm 의 HMAC 키로 서명된다 — 대칭키는 JWKS 에 없다.
     *
     * @param list<string>     $algorithms
     * @param non-empty-string $reason
     */
    #[DataProvider('hs256Pins')]
    public function testIdTokenSignedByAKeyOutsideTheJwksIsRefused(array $algorithms, string $reason): void
    {
        [$request, $code] = self::login('it-web-hs256');
        try {
            self::web('it-web-hs256', $algorithms)->auth()
                ->exchangeCode($code, $request->codeVerifier, $request->nonce, self::REDIRECT_URI);
            self::fail('an id_token signed by a key outside the JWKS must be refused');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertStringStartsWith('authorization code exchange failed: invalid id_token: ', $refused->getMessage());
        $cause = $refused->getPrevious();
        self::assertInstanceOf(TokenValidationError::class, $cause);
        self::assertStringStartsWith($reason, $cause->getMessage());
        self::assertLeaksNothing($refused, self::inputs($request, $code, 'it-web-hs256'));
    }

    /**
     * 사슬 전부가 SDK 계급이고(§4 — 하위 예외 원본은 공개 API 로 새지 않는다), 어떤 찍는 길에도 비밀·JWT 가 없다.
     * `(string)` 은 사슬 전부의 메시지·트레이스를, `var_dump`·`print_r` 는 트레이스 인자와 `previous` 까지 찍는다.
     *
     * @param array<string, string|null> $hidden
     */
    private static function assertLeaksNothing(KeycloakAuthError $refused, array $hidden, string $printed = ''): void
    {
        for ($link = $refused; $link !== null; $link = $link->getPrevious()) {
            self::assertStringStartsWith('Xzawed\\Keycloak\\', $link::class);
        }
        ob_start();
        var_dump($refused);
        $renderings = [
            'getMessage' => $refused->getMessage(),
            '(string)' => (string) $refused,
            'var_dump' => (string) ob_get_clean(),
            'print_r' => print_r($refused, true),
            'stdout+error_log' => $printed,
        ];
        foreach ($renderings as $how => $out) {
            self::assertSame(0, preg_match(self::JWT, $out), "{$how} carries a JWT");
            foreach ($hidden as $name => $secret) {
                self::assertNotNull($secret, $name);
                self::assertNotSame('', $secret, $name);
                // assertStringNotContainsString 은 실패하면 건초더미(그리고 비밀)를 통째로 찍는다 — 위치만 말한다.
                self::assertFalse(str_contains($out, $secret), "{$how} carries the {$name}");
            }
        }
    }

    /** @return array<string, string> 교환이 IdP 로 흘려 보내는 비밀 */
    private static function inputs(AuthorizationRequest $request, string $code, string $clientId): array
    {
        return [
            'code' => $code,
            'code_verifier' => $request->codeVerifier,
            'client_secret' => self::WEB_CLIENT_SECRETS[$clientId],
        ];
    }

    /**
     * @param list<string> $algorithms
     * @param list<string> $scopes
     */
    private static function web(string $clientId = 'it-web', array $algorithms = ['RS256'], array $scopes = ['openid']): KeycloakClient
    {
        return KeycloakClient::create(new KeycloakConfig(
            serverUrl: self::$baseUrl,
            realm: 'it-realm',
            clientId: $clientId,
            clientSecret: self::WEB_CLIENT_SECRETS[$clientId],
            scopes: $scopes,
            signatureAlgorithms: $algorithms,
        ));
    }

    /**
     * 인가 요청은 이 인스턴스가, 교환은 호출자가 **새 인스턴스로** 한다(클래스 docblock).
     *
     * @return array{AuthorizationRequest, string}
     */
    private static function login(string $clientId = 'it-web'): array
    {
        $request = self::web($clientId)->auth()->createAuthorizationRequest(self::REDIRECT_URI);

        return [$request, BrowserLogin::login($request, self::REDIRECT_URI, self::USERNAME, self::PASSWORD)];
    }

    /** 인가 URL 에서 `nonce` 만 뺀다 — 서버가 nonce 클레임 **없는** id_token 을 서명하게 한다. */
    private static function stripNonce(AuthorizationRequest $request): AuthorizationRequest
    {
        [$base, $query] = explode('?', $request->url, 2) + [1 => ''];
        $pairs = explode('&', $query);
        $kept = array_values(array_filter($pairs, static fn (string $pair): bool => !str_starts_with($pair, 'nonce=')));
        self::assertCount(\count($pairs) - 1, $kept, 'the authorization URL must carry exactly one nonce');

        return new AuthorizationRequest(
            url: $base . '?' . implode('&', $kept),
            state: $request->state,
            codeVerifier: $request->codeVerifier,
            nonce: $request->nonce,
        );
    }

    /** `alice` 의 사용자 id — 토큰의 `sub` 와 대조할 **독립 원천**(admin API)에서 읽는다. */
    private static function aliceId(): string
    {
        $admin = KeycloakClient::create(new KeycloakConfig(
            serverUrl: self::$baseUrl,
            realm: 'it-realm',
            clientId: 'it-client',
            clientSecret: 'it-secret',
        ));
        $id = $admin->admin()->users()->findIdByUsername(self::USERNAME);
        self::assertNotNull($id);

        return $id;
    }
}
