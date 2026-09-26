<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * ⚠️ 적대적·형식이 틀린 IdP 응답에서 난 SDK 오류가 **그 응답의 토큰·본문과 호출 입력의 비밀을 찍지 않는다.**
 *
 * `FacadeDumpTest` 는 정상 응답과 전송 실패만 뿌리로 세운다. 여기서는 토큰·introspect·logout 엔드포인트가
 * 적대적 응답을 줄 때 공개 auth 호출 전부를 돌려, 그 오류를 **`(string)$e`**(원인 사슬 전부의 메시지·트레이스)·
 * **`var_dump`**·**`print_r`**·**`getMessage()`** 로 찍고 카나리아(원문 또는 앞 10 자)를 찾는다.
 * Node #603 의 `auth-malformed-token-response.test.ts` 와 같은 부류다. 수정 전 실측(2026-09-26, 처음 27 변형):
 * 원문 적중 231 · 앞 10 자만 적중 0 · 원인 사슬의 하위 예외 원본 66(그중 16 은 던져진 것 자체가 `\TypeError`).
 * e3·w2·x·x2·x3 과 핸들러 메시지의 카나리아는 Grok 레그가 찾은 자리다. 원인과 수정은 `SanitizedCause` 의
 * docblock 이 소유한다.
 *
 * ⚠️ 하네스 상태는 전부 **정적**이다 — 예외 트레이스 인자에 러너·클로저 프레임이 실리고 `var_dump` 가 그것을
 * 따라간다(FacadeDumpTest 의 실측). 그래서 카나리아는 인자로도, 클로저 캡처로도 넘기지 않는다.
 * 트레이스 인자는 `zend.exception_ignore_args=0` 에서 잰다(운영 php.ini 는 1 이라 안 모은다).
 */
final class MalformedTokenResponseTest extends TestCase
{
    private const SERVER = 'https://kc.test';
    private const NONCE = 'nonce-not-secret';

    // 입력 비밀 — 호출이 IdP 로 흘려 보내는 값. 앞 10 자가 서로 달라 접두 적중이 어느 것인지 가린다.
    private const SECRET = 'LKin0SECRET-client-secret-value';
    private const IN_REFRESH = 'LKin1REFRESH-input-refresh-token';
    private const IN_CODE = 'LKin2CODE-input-authorization-code';
    private const IN_VERIFIER = 'LKin3VERIFIER-input-pkce-code-verifier';
    private const IN_TOKEN = 'LKin4TOKEN-input-introspected-token';
    // 핸들러(소비자 미들웨어 자리)가 던지는 예외의 메시지 — SDK 는 그 메시지가 무엇을 인용하는지 모른다.
    private const HANDLER_ECHO = 'LKh1HANDLER-message-echo';

    /**
     * 알려진 누출 — `"변형|호출|찍는 길|카나리아"` 와 이유. ⚠️ 고쳐져 더 안 새면 **여기서 지워야 통과한다**.
     *
     * @var array<string, string>
     */
    private const KNOWN_LEAKS = [];

    /** @return array<string, string> 비어 있어도 표다 — 상수의 리터럴 타입(`array{}`)으로 읽으면 조회가 「항상 거짓」이 된다. */
    private static function knownLeaks(): array
    {
        return self::KNOWN_LEAKS;
    }

    /**
     * 흐름 검사 — 변형마다 호출이 **실제로 실패했는가**와 그 SDK 분류(`auth`·`transport`). `ok` 는 SDK 가 그 응답을
     * 받아들였다는 뜻이다(누출 검사 대상이 아니다). ⚠️ 대조군: 가짜 IdP 가 변형을 안 주면 실패가 `ok` 로 바뀌어 여기서
     * 잡힌다. 분류는 수정 전과 같다 — 바뀐 것은 원래 `\TypeError` 가 새던 자리(b·b2 → `auth`, b3·c3 → 수용)뿐이다.
     *
     * @var array<string, array<string, string>>
     */
    private const EXPECTED = [
        'a id_token not a JWT' => ['clientCredentialsToken' => 'ok', 'refresh' => 'ok', 'exchangeCode' => 'ok', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'ok'],
        'a2 id_token forged JWT' => ['clientCredentialsToken' => 'ok', 'refresh' => 'ok', 'exchangeCode' => 'ok', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'ok'],
        'b access_token int' => ['clientCredentialsToken' => 'auth', 'refresh' => 'auth', 'exchangeCode' => 'auth', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'auth'],
        'b2 access_token object' => ['clientCredentialsToken' => 'auth', 'refresh' => 'auth', 'exchangeCode' => 'auth', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'auth'],
        'b3 refresh_token int' => ['clientCredentialsToken' => 'ok', 'refresh' => 'ok', 'exchangeCode' => 'ok', 'provider.getToken' => 'ok'],
        'c expires_in string' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'ok'],
        'c2 token_type array' => ['clientCredentialsToken' => 'ok', 'refresh' => 'ok', 'exchangeCode' => 'ok', 'provider.getToken' => 'ok'],
        'c3 expires_in float' => ['clientCredentialsToken' => 'ok', 'refresh' => 'ok', 'exchangeCode' => 'ok', 'provider.getToken' => 'ok'],
        'd short non-JSON body' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'auth'],
        'd2 long non-JSON body' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'auth'],
        'd3 non-JSON body text/plain' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'auth'],
        'd4 500 non-JSON body text/html' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'auth'],
        'e 400 error_description echo' => ['clientCredentialsToken' => 'auth', 'refresh' => 'auth', 'exchangeCode' => 'auth', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'auth'],
        'e2 401 error body carrying tokens' => ['clientCredentialsToken' => 'auth', 'refresh' => 'auth', 'exchangeCode' => 'auth', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'auth'],
        'e3 error code carries a token' => ['clientCredentialsToken' => 'auth', 'refresh' => 'auth', 'exchangeCode' => 'auth', 'exchangeCode+nonce' => 'auth', 'provider.getToken' => 'auth'],
        'f short non-JSON body' => ['introspect' => 'auth'],
        'f2 long non-JSON body' => ['introspect' => 'auth'],
        'f3 401 error_description echo' => ['introspect' => 'auth'],
        'f4 500 body echo' => ['introspect' => 'auth'],
        'f5 200 JSON wrong types' => ['introspect' => 'ok'],
        'g 400 error_description echo' => ['logout' => 'auth'],
        't token endpoint unreachable' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'transport'],
        't2 token handler RuntimeException' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'transport'],
        'u introspect unreachable' => ['introspect' => 'transport'],
        'u2 introspect handler RuntimeException' => ['introspect' => 'transport'],
        'v logout unreachable' => ['logout' => 'transport'],
        'v2 logout handler RuntimeException' => ['logout' => 'transport'],
        'w JWKS unreachable' => ['exchangeCode+nonce' => 'transport'],
        'w2 JWKS handler RuntimeException' => ['exchangeCode+nonce' => 'transport'],
        'x token TLS failure' => ['clientCredentialsToken' => 'transport', 'refresh' => 'transport', 'exchangeCode' => 'transport', 'exchangeCode+nonce' => 'transport', 'provider.getToken' => 'transport'],
        'x2 introspect TLS failure' => ['introspect' => 'auth'],
        'x3 logout TLS failure' => ['logout' => 'auth'],
    ];

    /**
     * 정화가 **디버깅 정보까지 지우지 않는가** — `"변형|호출"` => [SDK 메시지, oauthError, 원인 메시지]. 감사한 하위
     * 라이브러리가 만든 메시지·OAuth 오류 코드(`[a-z_]` 모양)·HTTP 상태는 남고, 그 밖은 원본 클래스명만 남는다.
     *
     * @var array<string, array{0:string,1:?string,2:?string}>
     */
    private const DEBUG_INFO = [
        'd short non-JSON body|clientCredentialsToken' => ['token endpoint returned unexpected response', null,
            'UnexpectedValueException: Failed to parse JSON response: Syntax error'],
        'e 400 error_description echo|clientCredentialsToken' => ['token request rejected: invalid_grant', 'invalid_grant',
            'League\OAuth2\Client\Provider\Exception\IdentityProviderException: OAuth error response: invalid_grant (description withheld)'],
        'e 400 error_description echo|provider.getToken' => ['client-credentials failed', 'invalid_grant', null],
        'e3 error code carries a token|clientCredentialsToken' => ['token request rejected', null,
            'League\OAuth2\Client\Provider\Exception\IdentityProviderException: OAuth error response (body withheld)'],
        'e3 error code carries a token|provider.getToken' => ['client-credentials failed', null, null],
        'f3 401 error_description echo|introspect' => ['introspection failed', null,
            'GuzzleHttp\Exception\ClientException: HTTP 401 from POST https://kc.test/realms/r/protocol/openid-connect/token/introspect (response body withheld)'],
        'u2 introspect handler RuntimeException|introspect' => ['introspection failed unexpectedly', null,
            'RuntimeException: (message withheld: thrown outside the audited libraries)'],
    ];

    /**
     * SDK 가 **받아들이는** 변형 — 오류가 없으니 누출 검사 대상도 없다. 그 밖의 변형은 적어도 한 호출을 실패시켜야 한다
     * (전부 `ok` 인 표는 아무것도 재지 않으면서 초록이다). b3·c3 은 수정 전 `\TypeError` 였다(`TokenSet::fromArray` 와 같은 규칙).
     */
    private const ACCEPTED = ['b3 refresh_token int', 'c2 token_type array', 'c3 expires_in float', 'f5 200 JSON wrong types'];

    /** @var array<string, array{0:string,1:bool}> 이름 => [값, 앞 10 자도 찾는가] */
    private static array $canaries = [];
    /** @var array{ep:string,status:int,type:string,body:string,fail:?string} */
    private static array $reply = ['ep' => '', 'status' => 200, 'type' => '', 'body' => '', 'fail' => null];
    /** @var array<string, mixed> */
    private static array $jwk = [];
    private static ?AuthClient $auth = null;
    private static ?ClientCredentialsTokenProvider $provider = null;
    /** @var array<string, array<string, string>> */
    private static array $outcomes = [];
    /** @var list<string> */
    private static array $leaks = [];
    /** @var array<string, true> */
    private static array $knownSeen = [];
    /** @var list<string> */
    private static array $foreign = [];
    /** @var array<string, array{0:string,1:?string,2:?string}> */
    private static array $debug = [];

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
        self::$outcomes = [];
        self::$leaks = [];
        self::$knownSeen = [];
        self::$foreign = [];
        self::$debug = [];
    }

    protected function tearDown(): void
    {
        self::$auth = null;
        self::$provider = null;
    }

    /** base64url(JSON) — 가짜 JWT 조각. */
    private static function seg(string $json): string
    {
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    }

    /**
     * 적대적 응답 표. 본문 속 카나리아는 이름으로 등록해 찾는다. `fail` 은 응답 대신 거부, `calls` 는 호출 부분집합.
     *
     * @return array<string, array{ep:string,status:int,type:string,body:string,canaries:array<string, array{0:string,1:bool}>,fail?:string,calls?:list<string>}>
     */
    private static function variants(): array
    {
        $json = 'application/json';
        $none = ['status' => 0, 'type' => '', 'body' => '', 'canaries' => []];
        // 넌스 검증은 id_token 이 JWT 가 아니거나 없으면 그 이유로 실패한다 — 그 길은 (a) 변형이 소유하므로 여기서는 뺀다.
        $noNonce = ['clientCredentialsToken', 'refresh', 'exchangeCode', 'provider.getToken'];
        $enc = static fn (array $a): string => json_encode($a, JSON_THROW_ON_ERROR);
        $forgedSig = 'LKa2SIGforgedSignatureSegment';
        $forged = self::seg('{"alg":"RS256","kid":"k1","typ":"JWT"}') . '.'
            . self::seg($enc(['iss' => self::SERVER . '/realms/r', 'aud' => 'c', 'sub' => 'u1', 'exp' => time() + 60, 'nonce' => self::NONCE]))
            . '.' . $forgedSig;
        $long = 'LKd2LONGbody-canary-that-starts-a-long-body';

        return [
            // (a) id_token 이 JWT 가 아니다.
            'a id_token not a JWT' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKa1AT-access-token-canary', 'token_type' => 'Bearer', 'expires_in' => 300,
                'refresh_token' => 'LKa1RT-refresh-token-canary', 'id_token' => 'LKa1ID-not-a-jwt-id-token',
            ]), 'canaries' => [
                'a.AT' => ['LKa1AT-access-token-canary', true], 'a.RT' => ['LKa1RT-refresh-token-canary', true],
                'a.ID' => ['LKa1ID-not-a-jwt-id-token', true],
            ]],
            // (a') id_token 이 JWT 모양이지만 서명이 위조됐다 — firebase 까지 간다. ⚠️ 앞 10 자는 공개 헤더라 원문만 찾는다.
            'a2 id_token forged JWT' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKa2AT-access-token-canary', 'token_type' => 'Bearer', 'expires_in' => 300,
                'refresh_token' => 'LKa2RT-refresh-token-canary', 'id_token' => $forged,
            ]), 'canaries' => [
                'a2.AT' => ['LKa2AT-access-token-canary', true], 'a2.RT' => ['LKa2RT-refresh-token-canary', true],
                'a2.ID' => [$forged, false], 'a2.SIG' => [$forgedSig, true],
            ]],
            // (b) access_token 이 문자열이 아니다 — refresh_token 은 카나리아.
            'b access_token int' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 12345, 'token_type' => 'Bearer', 'expires_in' => 300,
                'refresh_token' => 'LKb1RT-refresh-token-canary', 'id_token' => 'LKb1ID-id-token-canary',
            ]), 'canaries' => [
                'b.RT' => ['LKb1RT-refresh-token-canary', true], 'b.ID' => ['LKb1ID-id-token-canary', true],
            ]],
            'b2 access_token object' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => ['v' => 'LKb2AT-nested-access-token'], 'token_type' => 'Bearer', 'expires_in' => 300,
                'refresh_token' => 'LKb2RT-refresh-token-canary',
            ]), 'canaries' => [
                'b2.AT' => ['LKb2AT-nested-access-token', true], 'b2.RT' => ['LKb2RT-refresh-token-canary', true],
            ]],
            // refresh_token 이 문자열이 아니다 — access_token 은 카나리아. league 는 비어 있지 않으면 그대로 싣는다.
            'b3 refresh_token int' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKb3AT-access-token-canary', 'token_type' => 'Bearer', 'expires_in' => 300,
                'refresh_token' => 777, 'id_token' => 'LKb3ID-id-token-canary',
            ]), 'canaries' => [
                'b3.AT' => ['LKb3AT-access-token-canary', true], 'b3.ID' => ['LKb3ID-id-token-canary', true],
            ], 'calls' => $noNonce],
            // (c) expires_in · token_type 의 타입이 틀렸다.
            'c expires_in string' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKc1AT-access-token-canary', 'token_type' => 'Bearer', 'expires_in' => 'soon',
                'refresh_token' => 'LKc1RT-refresh-token-canary',
            ]), 'canaries' => [
                'c.AT' => ['LKc1AT-access-token-canary', true], 'c.RT' => ['LKc1RT-refresh-token-canary', true],
            ]],
            'c2 token_type array' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKc2AT-access-token-canary', 'token_type' => ['Bearer'], 'expires_in' => 300,
                'refresh_token' => 'LKc2RT-refresh-token-canary',
            ]), 'canaries' => [
                'c2.AT' => ['LKc2AT-access-token-canary', true], 'c2.RT' => ['LKc2RT-refresh-token-canary', true],
            ], 'calls' => $noNonce],
            'c3 expires_in float' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $enc([
                'access_token' => 'LKc3AT-access-token-canary', 'token_type' => 'Bearer', 'expires_in' => 300.5,
                'refresh_token' => 'LKc3RT-refresh-token-canary',
            ]), 'canaries' => [
                'c3.AT' => ['LKc3AT-access-token-canary', true], 'c3.RT' => ['LKc3RT-refresh-token-canary', true],
            ], 'calls' => $noNonce],
            // (d) 200 에 JSON 이 아닌 본문 — 짧은 카나리아(≤ 20 자) 하나, 카나리아로 시작하는 긴 본문 하나.
            'd short non-JSON body' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => 'LKd1SHORTbody',
                'canaries' => ['d.SHORT' => ['LKd1SHORTbody', true]]],
            'd2 long non-JSON body' => ['ep' => 'token', 'status' => 200, 'type' => $json, 'body' => $long . str_repeat('x', 400),
                'canaries' => ['d2.LONG' => [$long, true]]],
            'd3 non-JSON body text/plain' => ['ep' => 'token', 'status' => 200, 'type' => 'text/plain', 'body' => 'LKd3PLAINbody',
                'canaries' => ['d3.PLAIN' => ['LKd3PLAINbody', true]]],
            'd4 500 non-JSON body text/html' => ['ep' => 'token', 'status' => 500, 'type' => 'text/html', 'body' => 'LKd4HTMLbody-500-page',
                'canaries' => ['d4.HTML' => ['LKd4HTMLbody-500-page', true]]],
            // (e) 오류 본문의 error_description 이 토큰을 되울린다.
            'e 400 error_description echo' => ['ep' => 'token', 'status' => 400, 'type' => $json, 'body' => $enc([
                'error' => 'invalid_grant', 'error_description' => 'token LKe1ECHO-echoed-refresh-token is not active',
            ]), 'canaries' => ['e.ECHO' => ['LKe1ECHO-echoed-refresh-token', true]]],
            'e2 401 error body carrying tokens' => ['ep' => 'token', 'status' => 401, 'type' => $json, 'body' => $enc([
                'error' => 'invalid_client', 'error_description' => 'LKe2DESC-echoed-client-secret',
                'access_token' => 'LKe2AT-access-token-in-error', 'refresh_token' => 'LKe2RT-refresh-token-in-error',
            ]), 'canaries' => [
                'e2.DESC' => ['LKe2DESC-echoed-client-secret', true], 'e2.AT' => ['LKe2AT-access-token-in-error', true],
                'e2.RT' => ['LKe2RT-refresh-token-in-error', true],
            ]],
            // `error` 자리 자체가 토큰을 되울린다 — OAuth 오류 코드 모양(`[a-z_]`)이 아니면 코드로 싣지 않는다(Grok 레그).
            'e3 error code carries a token' => ['ep' => 'token', 'status' => 400, 'type' => $json, 'body' => $enc([
                'error' => 'LKe3ERR-Token-In-Error-Code', 'error_description' => 'x',
            ]), 'canaries' => ['e3.ERR' => ['LKe3ERR-Token-In-Error-Code', true]]],
            // (f) introspect 의 같은 모양.
            'f short non-JSON body' => ['ep' => 'introspect', 'status' => 200, 'type' => $json, 'body' => 'LKf1SHORTbody',
                'canaries' => ['f.SHORT' => ['LKf1SHORTbody', true]]],
            'f2 long non-JSON body' => ['ep' => 'introspect', 'status' => 200, 'type' => $json, 'body' => 'LKf2LONGbody-canary-long' . str_repeat('x', 400),
                'canaries' => ['f2.LONG' => ['LKf2LONGbody-canary-long', true]]],
            'f3 401 error_description echo' => ['ep' => 'introspect', 'status' => 401, 'type' => $json, 'body' => $enc([
                'error' => 'invalid_client', 'error_description' => 'LKf3ECHO-echoed-token',
            ]), 'canaries' => ['f3.ECHO' => ['LKf3ECHO-echoed-token', true]]],
            'f4 500 body echo' => ['ep' => 'introspect', 'status' => 500, 'type' => 'text/plain', 'body' => 'LKf4ECHO-500-body-echo',
                'canaries' => ['f4.ECHO' => ['LKf4ECHO-500-body-echo', true]]],
            'f5 200 JSON wrong types' => ['ep' => 'introspect', 'status' => 200, 'type' => $json, 'body' => $enc([
                'active' => 'yes', 'username' => ['LKf5USER-nested'], 'client_id' => 7,
            ]), 'canaries' => ['f5.USER' => ['LKf5USER-nested', true]]],
            // logout(백채널 end_session)의 같은 모양.
            'g 400 error_description echo' => ['ep' => 'logout', 'status' => 400, 'type' => $json, 'body' => $enc([
                'error' => 'invalid_grant', 'error_description' => 'LKg1ECHO-echoed-refresh-token',
            ]), 'canaries' => ['g.ECHO' => ['LKg1ECHO-echoed-refresh-token', true]]],
            // 전송 실패 — 응답은 없지만 하위 예외의 **트레이스 인자**가 호출 입력(refresh·code·Basic·시크릿)을 쥔다.
            // 감싸는 자리마다 하나씩: connect = ConnectException 갈래, runtime = Guzzle 밖 예외(`\Throwable` 갈래),
            // tls = 응답 없는 RequestException(연결 아닌 GuzzleException · PSR-18 비-네트워크 갈래). 핸들러 예외의
            // 메시지는 HANDLER_ECHO 를 싣는다 — 감사한 라이브러리 밖에서 난 메시지는 옮기지 않아야 한다.
            't token endpoint unreachable' => ['ep' => 'token', 'fail' => 'connect'] + $none,
            't2 token handler RuntimeException' => ['ep' => 'token', 'fail' => 'runtime'] + $none,
            'u introspect unreachable' => ['ep' => 'introspect', 'fail' => 'connect'] + $none,
            'u2 introspect handler RuntimeException' => ['ep' => 'introspect', 'fail' => 'runtime'] + $none,
            'v logout unreachable' => ['ep' => 'logout', 'fail' => 'connect'] + $none,
            'v2 logout handler RuntimeException' => ['ep' => 'logout', 'fail' => 'runtime'] + $none,
            'w JWKS unreachable' => ['ep' => 'certs', 'fail' => 'connect'] + $none,
            'w2 JWKS handler RuntimeException' => ['ep' => 'certs', 'fail' => 'runtime'] + $none,
            'x token TLS failure' => ['ep' => 'token', 'fail' => 'tls'] + $none,
            'x2 introspect TLS failure' => ['ep' => 'introspect', 'fail' => 'tls'] + $none,
            'x3 logout TLS failure' => ['ep' => 'logout', 'fail' => 'tls'] + $none,
        ];
    }

    /** 가짜 IdP — 겨냥한 엔드포인트만 적대적 응답을 주고, 나머지는 정상이다. */
    private static function http(KeycloakConfig $cfg): GuzzleClient
    {
        $handler = static function (RequestInterface $req): PromiseInterface {
            $path = $req->getUri()->getPath();
            $ep = match (true) {
                str_ends_with($path, '/token/introspect') => 'introspect',
                str_ends_with($path, '/token') => 'token',
                str_ends_with($path, '/logout') => 'logout',
                str_ends_with($path, '/certs') => 'certs',
                default => 'other',
            };
            if ($ep === self::$reply['ep']) {
                return match (self::$reply['fail']) {
                    'connect' => Create::rejectionFor(new ConnectException('connection refused ' . self::HANDLER_ECHO, $req)),
                    'runtime' => Create::rejectionFor(new \RuntimeException('handler failed ' . self::HANDLER_ECHO)),
                    'tls' => Create::rejectionFor(new RequestException('TLS handshake failed ' . self::HANDLER_ECHO, $req)),
                    default => Create::promiseFor(new Response(self::$reply['status'], ['Content-Type' => self::$reply['type']], self::$reply['body'])),
                };
            }
            $json = ['Content-Type' => 'application/json'];

            return Create::promiseFor(match ($ep) {
                'certs' => new Response(200, $json, json_encode(['keys' => [self::$jwk]], JSON_THROW_ON_ERROR)),
                'introspect' => new Response(200, $json, '{"active":false}'),
                'logout' => new Response(204),
                // id_token 은 JWT 모양(kid k1) — 넌스 검증이 JWKS 까지 가야 JWKS 변형이 닿는다. 서명은 가짜다(비밀 아님).
                'token' => new Response(200, $json, json_encode([
                    'access_token' => 'ok', 'token_type' => 'Bearer', 'expires_in' => 300,
                    'id_token' => self::seg('{"alg":"RS256","kid":"k1"}') . '.' . self::seg('{"sub":"u1"}') . '.c2ln',
                ], JSON_THROW_ON_ERROR)),
                default => new Response(404),
            });
        };

        return new GuzzleClient(['handler' => HandlerStack::create($handler)] + HttpOptions::guzzle($cfg));
    }

    /** @return array<string, mixed> */
    private static function rsaJwk(): array
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        $details = openssl_pkey_get_details($res);
        self::assertIsArray($details);
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        self::assertIsString($rsa['n']);
        self::assertIsString($rsa['e']);
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return ['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'alg' => 'RS256', 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])];
    }

    /** 새 클라이언트 — 변형 사이에 캐시(JWKS·provider)가 이어지지 않는다. */
    private static function fresh(): void
    {
        $cfg = new KeycloakConfig(self::SERVER, 'r', 'c', self::SECRET);
        $http = self::http($cfg);
        $ep = new OidcEndpoints($cfg);
        self::$auth = new AuthClient($cfg, $ep, new JwtValidator($cfg, $ep, new JwksStore($ep->jwks(), $http, new HttpFactory())), $http);
        self::$provider = new ClientCredentialsTokenProvider($cfg, $ep, $http, new HttpFactory(), new HttpFactory());
    }

    /**
     * 엔드포인트별 공개 호출. ⚠️ 클로저는 아무것도 캡처하지 않는다(정적 상태와 상수만 읽는다).
     *
     * @return array<string, array<string, \Closure>>
     */
    private static function calls(): array
    {
        return [
            'token' => [
                'clientCredentialsToken' => static fn () => self::$auth?->clientCredentialsToken(),
                'refresh' => static fn () => self::$auth?->refresh(self::IN_REFRESH),
                'exchangeCode' => static fn () => self::$auth?->exchangeCode(self::IN_CODE, self::IN_VERIFIER),
                'exchangeCode+nonce' => static fn () => self::$auth?->exchangeCode(self::IN_CODE, self::IN_VERIFIER, self::NONCE),
                'provider.getToken' => static fn () => self::$provider?->getToken(),
            ],
            'introspect' => ['introspect' => static fn () => self::$auth?->introspect(self::IN_TOKEN)],
            'logout' => ['logout' => static fn () => self::$auth?->logout(self::IN_REFRESH)],
            'certs' => ['exchangeCode+nonce' => static fn () => self::$auth?->exchangeCode(self::IN_CODE, self::IN_VERIFIER, self::NONCE)],
        ];
    }

    private static function attempt(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Throwable $e) {
            return $e;
        }

        return null;
    }

    private static function outcome(?\Throwable $e): string
    {
        return match (true) {
            $e === null => 'ok',
            $e instanceof KeycloakAuthError => 'auth',
            $e instanceof KeycloakTransportError => 'transport',
            default => $e::class,
        };
    }

    /** §4 — 공개 API 로 나오는 오류와 그 원인 사슬의 고리는 전부 SDK 타입이다(하위 예외 원본이 아니라). */
    private static function checkChain(string $key, \Throwable $e): void
    {
        for ($link = $e, $depth = 0; $link !== null; $link = $link->getPrevious(), $depth++) {
            if (!str_starts_with($link::class, 'Xzawed\\Keycloak\\')) {
                self::$foreign[] = "$key: 사슬 [$depth] 이 " . $link::class;
            }
        }
    }

    /** @return array<string, string> 찍는 길 => 출력. `(string)` 은 원인 사슬 전부의 메시지·트레이스를 담는다. */
    private static function renderings(\Throwable $e): array
    {
        ob_start();
        var_dump($e);
        $dump = (string) ob_get_clean();

        return ['getMessage' => $e->getMessage(), '(string)' => (string) $e, 'var_dump' => $dump, 'print_r' => print_r($e, true)];
    }

    /** 원문이면 FULL, (그 카나리아가 허용하면) 앞 10 자만 보여도 PREFIX. */
    private static function hit(string $out, string $value, bool $prefix): ?string
    {
        if (str_contains($out, $value)) {
            return 'FULL';
        }

        return $prefix && str_contains($out, substr($value, 0, 10)) ? 'PREFIX' : null;
    }

    private static function inspect(string $key, \Throwable $e): void
    {
        self::checkChain($key, $e);
        foreach (self::renderings($e) as $how => $out) {
            foreach (self::$canaries as $name => [$value, $prefix]) {
                $hit = self::hit($out, $value, $prefix);
                $id = "$key|$how|$name";
                if ($hit === null) {
                    continue;
                }
                if (array_key_exists($id, self::knownLeaks())) {
                    self::$knownSeen[$id] = true;
                    continue;
                }
                self::$leaks[] = "$id ($hit)";
            }
        }
    }

    /**
     * ⚠️ 변형 배열을 인자로 받지 않는다 — 이 프레임이 예외 트레이스에 실려 본문·카나리아를 `var_dump` 에 흘린다
     * (실측: 넘겼더니 160 건이 하네스에서 났다). 받는 것은 호출 이름 부분집합뿐이다.
     *
     * @param list<string>|null $only
     */
    private static function drive(string $name, ?array $only, \Closure $call, string $callName): void
    {
        if ($only !== null && !in_array($callName, $only, true)) {
            return;
        }
        self::fresh();
        $e = self::attempt($call);
        self::$outcomes[$name][$callName] = self::outcome($e);
        if ($e !== null) {
            self::inspect("$name|$callName", $e);
            if (array_key_exists("$name|$callName", self::DEBUG_INFO)) {
                self::$debug["$name|$callName"] = [
                    $e->getMessage(),
                    $e instanceof KeycloakAuthError ? $e->oauthError : null,
                    $e->getPrevious()?->getMessage(),
                ];
            }
        }
    }

    public function testHostileResponsesDoNotLeakThroughSdkErrors(): void
    {
        self::$jwk = self::rsaJwk();
        $variants = self::variants();
        $calls = self::calls();
        self::$canaries = [
            'SECRET' => [self::SECRET, true], 'IN_REFRESH' => [self::IN_REFRESH, true], 'IN_CODE' => [self::IN_CODE, true],
            'IN_VERIFIER' => [self::IN_VERIFIER, true], 'IN_TOKEN' => [self::IN_TOKEN, true],
            'BASIC' => [base64_encode(rawurlencode('c') . ':' . rawurlencode(self::SECRET)), true],
            'HANDLER' => [self::HANDLER_ECHO, true],
        ];
        foreach ($variants as $v) {
            self::$canaries += $v['canaries'];
        }
        foreach ($variants as $name => $v) {
            self::$reply = ['ep' => $v['ep'], 'status' => $v['status'], 'type' => $v['type'], 'body' => $v['body'], 'fail' => $v['fail'] ?? null];
            foreach ($calls[$v['ep']] as $callName => $call) {
                self::drive($name, $v['calls'] ?? null, $call, $callName);
            }
        }

        // 표 자체의 공허성 — 받아들이는 변형은 실패가 없어야 하고, 그 밖의 변형은 적어도 한 호출을 실패시켜야 한다.
        $vacuous = array_keys(array_filter(
            self::EXPECTED,
            static fn (array $byCall, string $name): bool => (array_diff($byCall, ['ok']) === []) !== in_array($name, self::ACCEPTED, true),
            ARRAY_FILTER_USE_BOTH,
        ));
        self::assertSame([], $vacuous, '흐름 표가 ACCEPTED 와 어긋난다(전부 ok 인 변형은 아무것도 안 잰다)');
        self::assertSame(self::EXPECTED, self::$outcomes, '흐름 검사 — 적대적 응답이 기대한 실패(또는 수용)를 내지 않았다');
        self::assertSame([], self::$foreign, "하위 예외가 공개 API 로 샜다(§4):\n" . implode("\n", self::$foreign));
        self::assertSame([], self::$leaks, "SDK 오류가 비밀을 찍는다:\n" . implode("\n", self::$leaks));
        self::assertSame(
            [],
            array_keys(array_diff_key(self::knownLeaks(), self::$knownSeen)),
            '알려진 누출이 더 안 난다 — 고쳐졌으면 KNOWN_LEAKS 에서 지워라',
        );
        self::assertSame(self::DEBUG_INFO, self::$debug, '정화가 디버깅 정보(라이브러리 메시지·OAuth 코드·HTTP 상태)까지 지웠다');
    }
}
