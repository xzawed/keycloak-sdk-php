<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Exception\TokenValidationError;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

/**
 * OIDC nonce 재생 방지 — Java AuthClientNonceTest / Ruby auth_client_spec 동형.
 * createAuthorizationRequest는 항상 nonce를 만들어 URL에 싣고, exchangeCode는
 * expectedNonce가 주어지면 id_token을 완전 검증한 뒤 nonce 클레임을 대조한다.
 */
final class AuthClientNonceTest extends TestCase
{
    /** 리소스 서버 audience — client id(`it-client`)가 아닌 재정의 값. */
    private const OVERRIDE = 'my-api';
    private const AUD_REFUSED = 'authorization code exchange failed: invalid id_token: audience does not contain it-client';

    /** @var array{priv:string,jwk:array<string,mixed>} */
    private array $key;
    private string $iss = 'https://kc:8080/realms/it-realm';

    protected function setUp(): void
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        self::assertTrue(openssl_pkey_export($res, $priv));
        self::assertIsString($priv);
        $details = openssl_pkey_get_details($res);
        self::assertIsArray($details);
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        $n = $rsa['n'];
        $e = $rsa['e'];
        self::assertIsString($n);
        self::assertIsString($e);
        $jwk = [
            'kty' => 'RSA', 'kid' => 'test-kid', 'use' => 'sig', 'alg' => 'RS256',
            'n' => rtrim(strtr(base64_encode($n), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($e), '+/', '-_'), '='),
        ];
        $this->key = ['priv' => $priv, 'jwk' => $jwk];
    }

    public function testCreateAuthorizationRequestPutsNonceOnUrlAndObject(): void
    {
        $auth = $this->authWithTokenBody([]);
        $req = $auth->createAuthorizationRequest();
        self::assertNotSame('', $req->nonce);
        $qs = parse_url($req->url, PHP_URL_QUERY);
        self::assertIsString($qs);
        parse_str($qs, $params);
        self::assertArrayHasKey('nonce', $params);
        self::assertSame($req->nonce, $params['nonce']);
    }

    public function testCreateAuthorizationRequestNonceDiffersPerCall(): void
    {
        $auth = $this->authWithTokenBody([]);
        $a = $auth->createAuthorizationRequest();
        $b = $auth->createAuthorizationRequest();
        self::assertNotSame($a->nonce, $b->nonce);
        self::assertNotSame($a->state, $b->state);
        self::assertNotSame($a->codeVerifier, $b->codeVerifier);
    }

    public function testExchangeCodeAcceptsMatchingNonce(): void
    {
        $hits = new JwksHitCounter();
        $idToken = $this->signIdToken('server-nonce');
        $ts = $this->authWithTokenBody($this->tokenBody($idToken), jwksHits: $hits)
            ->exchangeCode('code', 'verifier', 'server-nonce');
        self::assertSame('AT', $ts->accessToken);
        self::assertSame($idToken, $ts->idToken);
        self::assertGreaterThan(0, $hits->n, 'matching nonce must fully validate id_token (JWKS fetch)');
    }

    public function testExchangeCodeRejectsMismatchedNonce(): void
    {
        $idToken = $this->signIdToken('server-nonce');
        $this->expectException(KeycloakAuthError::class);
        $this->expectExceptionMessageMatches('/nonce/');
        $this->authWithTokenBody($this->tokenBody($idToken))
            ->exchangeCode('code', 'verifier', 'attacker-nonce');
    }

    public function testExchangeCodeRejectsMissingIdTokenWhenNonceExpected(): void
    {
        $this->expectException(KeycloakAuthError::class);
        $this->expectExceptionMessageMatches('/id_token/');
        $this->authWithTokenBody($this->tokenBody(null))
            ->exchangeCode('code', 'verifier', 'server-nonce');
    }

    public function testExchangeCodeRejectsUntrustedIdToken(): void
    {
        $attacker = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($attacker);
        self::assertTrue(openssl_pkey_export($attacker, $attackerPriv));
        self::assertIsString($attackerPriv);
        $forged = $this->signIdToken('server-nonce', $attackerPriv);
        $this->expectException(KeycloakAuthError::class);
        $this->authWithTokenBody($this->tokenBody($forged))
            ->exchangeCode('code', 'verifier', 'server-nonce');
    }

    public function testExchangeCodeSkipsIdTokenValidationWithoutNonce(): void
    {
        $idToken = $this->signIdToken('server-nonce');
        $ts = $this->authWithTokenBody($this->tokenBody($idToken), forbidJwks: true)
            ->exchangeCode('code', 'verifier');
        self::assertSame('AT', $ts->accessToken);
        self::assertSame($idToken, $ts->idToken);
    }

    // ── id_token 의 aud 는 client id 다(OIDC Core §2·§3.1.3.7) — expectedAudience 는 액세스 토큰의 것이다 ──

    /** @return iterable<string, array{string|list<string>}> */
    public static function idTokenAudiencesNamingTheClient(): iterable
    {
        yield 'the client id alone' => ['it-client'];
        yield 'the client id in a list' => [['it-client']];
        yield 'the client id beside the override' => [[self::OVERRIDE, 'it-client']];
    }

    /**
     * (A1) 재정의해도 aud 에 client id 를 담은 id_token 의 교환은 통과한다 — 예전에는 재정의 값을 찾아 거부했다.
     *
     * @param string|list<string> $aud
     */
    #[DataProvider('idTokenAudiencesNamingTheClient')]
    public function testExchangeCodeUnderAnAudienceOverrideAcceptsAnIdTokenIssuedToTheClient(string|array $aud): void
    {
        $hits = new JwksHitCounter();
        $idToken = $this->sign($this->idTokenClaims('server-nonce', ['aud' => $aud]));
        $ts = $this->authWithTokenBody($this->tokenBody($idToken), jwksHits: $hits, expectedAudience: self::OVERRIDE)
            ->exchangeCode('code', 'verifier', 'server-nonce');
        self::assertSame($idToken, $ts->idToken);
        self::assertSame(1, $hits->n, 'the id_token must still be fully validated (one JWKS fetch)');
    }

    /** @return iterable<string, array{string|list<string>|null}> */
    public static function idTokenAudiencesWithoutTheClient(): iterable
    {
        yield 'only the override' => [self::OVERRIDE];
        yield 'only the override, in a list' => [[self::OVERRIDE]];
        yield 'another client' => [['account']];
        yield 'no aud claim' => [null];
    }

    /**
     * (A2) aud 에 client id 가 없는 id_token 은 거부한다 — 재정의 값과 같아도.
     *
     * @param string|list<string>|null $aud
     */
    #[DataProvider('idTokenAudiencesWithoutTheClient')]
    public function testExchangeCodeRejectsAnIdTokenNotIssuedToTheClientEvenUnderAnOverride(string|array|null $aud): void
    {
        $idToken = $this->sign($this->idTokenClaims('server-nonce', ['aud' => $aud]));
        try {
            $this->authWithTokenBody($this->tokenBody($idToken), expectedAudience: self::OVERRIDE)
                ->exchangeCode('code', 'verifier', 'server-nonce');
            self::fail('an id_token whose aud lacks the client id must be refused');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertSame(self::AUD_REFUSED, $refused->getMessage());
        self::assertInstanceOf(TokenValidationError::class, $refused->getPrevious());
    }

    /** (A3) 액세스 토큰 검증은 재정의를 계속 쓴다 — client id 만 담은 액세스 토큰은 거부한다. */
    public function testValidateKeepsCheckingAccessTokensAgainstTheOverride(): void
    {
        $auth = $this->authWithTokenBody([], expectedAudience: self::OVERRIDE);
        $vt = $auth->validate($this->sign($this->accessTokenClaims([self::OVERRIDE, 'account'])));
        self::assertSame([self::OVERRIDE, 'account'], $vt->audience);
        try {
            $auth->validate($this->sign($this->accessTokenClaims(['it-client'])));
            self::fail('an access token without the overriding audience must be refused');
        } catch (TokenValidationError $refused) {
        }
        self::assertSame('audience does not contain ' . self::OVERRIDE, $refused->getMessage());
    }

    /**
     * (A4) 재정의 아래서도 id_token 의 나머지 검사(iss·alg 핀·exp·kid·서명)와 nonce 대조는 그대로다.
     *
     * @return iterable<string, array{array<string,mixed>, string, string, non-empty-string}>
     */
    public static function idTokenDefectsUnderAnOverride(): iterable
    {
        // [바꿀 클레임(null 은 제거 · exp 는 지금부터의 초), 서명 방식, 넘기는 nonce, 거부 메시지]
        $invalid = 'authorization code exchange failed: invalid id_token: ';
        yield 'a foreign issuer' => [['iss' => 'https://evil/realms/it-realm'], 'rs256', 'server-nonce', $invalid . 'issuer mismatch: https://evil/realms/it-realm'];
        yield 'expired beyond the skew' => [['exp' => -60], 'rs256', 'server-nonce', $invalid . 'token verification failed: Expired token'];
        yield 'no exp' => [['exp' => null], 'rs256', 'server-nonce', $invalid . 'exp claim is required'];
        yield 'an algorithm outside the pin' => [[], 'hs256', 'server-nonce', $invalid . 'algorithm not allowed: HS256'];
        yield 'a key outside the JWKS' => [[], 'foreign-key', 'server-nonce', $invalid . 'token verification failed: Signature verification failed'];
        yield 'another nonce' => [[], 'rs256', 'attacker-nonce', 'authorization code exchange failed: unexpected nonce'];
    }

    /** @param array<string,mixed> $changes */
    #[DataProvider('idTokenDefectsUnderAnOverride')]
    public function testExchangeCodeUnderAnAudienceOverrideKeepsTheOtherIdTokenChecks(array $changes, string $signer, string $nonce, string $message): void
    {
        $idToken = $this->signAs($signer, $this->idTokenClaims('server-nonce', $changes));
        try {
            $this->authWithTokenBody($this->tokenBody($idToken), expectedAudience: self::OVERRIDE)
                ->exchangeCode('code', 'verifier', $nonce);
            self::fail('a defective id_token must be refused under an audience override too');
        } catch (KeycloakAuthError $refused) {
        }
        self::assertSame($message, $refused->getMessage());
    }

    /** (A4) 클록 스큐 쌍의 안쪽 — 위 「expired beyond the skew」와 짝이라 스큐가 0 이어도 무한이어도 하나가 빨개진다. */
    public function testExchangeCodeUnderAnAudienceOverrideAllowsTheClockSkew(): void
    {
        $idToken = $this->sign($this->idTokenClaims('server-nonce', ['exp' => -10]));
        $ts = $this->authWithTokenBody($this->tokenBody($idToken), expectedAudience: self::OVERRIDE)
            ->exchangeCode('code', 'verifier', 'server-nonce');
        self::assertSame($idToken, $ts->idToken);
    }

    /**
     * (A5) 교환의 id_token 검증과 액세스 토큰 검증은 **한** JWKS 저장소를 쓴다 — 캐시·재조회 게이트·백오프가 하나다.
     *
     * 토큰 엔드포인트와 JWKS 가 **한** HTTP 클라이언트를 쓴다(`KeycloakClient::create` 와 같은 배선) — 그래서 id_token
     * 쪽이 제 저장소를 따로 만들면, 그것이 어느 http 로 조회하든 이 카운터나 교환 자체가 그것을 본다.
     */
    public function testExchangeCodeAndValidateShareOneJwksStore(): void
    {
        $hits = new JwksHitCounter();
        [$auth, $cfg, $endpoints, $http] = $this->authOverOneClient(
            $hits,
            self::OVERRIDE,
            $this->signIdToken('server-nonce'),
            $this->sign($this->idTokenClaims('server-nonce'), kid: 'rotated-b'),
        );
        $auth->exchangeCode('code', 'verifier', 'server-nonce');
        self::assertSame(1, $hits->n, 'the exchange validates the id_token on a cold cache (one fetch)');
        $access = $this->sign($this->accessTokenClaims([self::OVERRIDE]));
        $auth->validate($access);
        self::assertSame(1, $hits->n, 'validate() after the exchange must reuse the key store the exchange warmed');

        // 재조회 게이트도 하나다 — validate() 가 미해결 kid 로 재조회를 쓰면, 곧이은 교환의 미해결 kid 는 조회 없이 막힌다.
        try {
            $auth->validate($this->sign($this->accessTokenClaims([self::OVERRIDE]), kid: 'rotated-a'));
            self::fail('an unresolved kid must be refused');
        } catch (TokenValidationError $unknown) {
        }
        self::assertSame('unknown kid "rotated-a"', $unknown->getMessage());
        self::assertSame(2, $hits->n, 'the first unresolved kid spends the refetch');
        try {
            $auth->exchangeCode('code', 'verifier', 'server-nonce');   // 토큰 응답 둘째 — kid 가 rotated-b 인 id_token
            self::fail('an unresolved kid inside the refetch window must be refused');
        } catch (KeycloakAuthError $limited) {
        }
        self::assertSame('authorization code exchange failed: invalid id_token: unknown kid "rotated-b" (refetch rate-limited)', $limited->getMessage());
        self::assertSame(2, $hits->n, 'the exchange must see the refetch validate() already spent');

        // 대조군: 저장소를 하나 더 만들면 같은 http 위에서 이 카운터가 그것을 센다 — 위의 1·2 는 공허하지 않다.
        (new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $http, new HttpFactory())))->validate($access);
        self::assertSame(3, $hits->n, 'a second key store fetches again, and this counter sees it');
    }

    /**
     * 토큰 엔드포인트와 JWKS 를 **한** Guzzle 클라이언트로 — `KeycloakClient::create` 의 배선과 같다.
     * 토큰 응답은 교환마다 `$idTokens` 를 차례로 싣는다.
     *
     * @return array{AuthClient, KeycloakConfig, OidcEndpoints, Client}
     */
    private function authOverOneClient(JwksHitCounter $hits, ?string $expectedAudience, string ...$idTokens): array
    {
        $cfg = $this->config($expectedAudience);
        $endpoints = new OidcEndpoints($cfg);
        $jwks = json_encode(['keys' => [$this->key['jwk']]], JSON_THROW_ON_ERROR);
        $tokens = array_map(fn (string $t): string => json_encode($this->tokenBody($t), JSON_THROW_ON_ERROR), $idTokens);
        $route = static function (RequestInterface $r) use ($hits, $jwks, &$tokens): PromiseInterface {
            if (str_ends_with($r->getUri()->getPath(), '/protocol/openid-connect/certs')) {
                ++$hits->n;

                return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], $jwks));
            }
            $body = array_shift($tokens);
            self::assertIsString($body, 'more token requests than queued token responses');

            return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], $body));
        };
        $http = new Client(['handler' => HandlerStack::create($route)]);
        $validator = new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $http, new HttpFactory()));

        return [new AuthClient($cfg, $endpoints, $validator, $http), $cfg, $endpoints, $http];
    }

    private function config(?string $expectedAudience = null): KeycloakConfig
    {
        return new KeycloakConfig(
            serverUrl: 'https://kc:8080',
            realm: 'it-realm',
            clientId: 'it-client',
            clientSecret: 's',
            redirectUri: 'https://app/cb',
            expectedAudience: $expectedAudience,
        );
    }

    /** @param array<string,mixed> $body */
    private function authWithTokenBody(array $body, bool $forbidJwks = false, ?JwksHitCounter $jwksHits = null, ?string $expectedAudience = null): AuthClient
    {
        $cfg = $this->config($expectedAudience);
        $endpoints = new OidcEndpoints($cfg);
        $tokenHttp = $body === []
            ? new Client()
            : new Client(['handler' => HandlerStack::create(new MockHandler([
                new Response(200, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR)),
            ]))]);
        $jwk = $this->key['jwk'];
        $jwksHttp = $forbidJwks
            ? new class () implements ClientInterface {
                public function sendRequest(RequestInterface $r): ResponseInterface
                {
                    throw new \RuntimeException('JWKS must not be fetched when expectedNonce is omitted');
                }
            }
        : new class ($jwk, $jwksHits) implements ClientInterface {
            /** @param array<string,mixed> $jwk */
            public function __construct(private array $jwk, private ?JwksHitCounter $hits) {}

            public function sendRequest(RequestInterface $r): ResponseInterface
            {
                if ($this->hits !== null) {
                    ++$this->hits->n;
                }

                return new Response(200, [], json_encode(['keys' => [$this->jwk]], JSON_THROW_ON_ERROR));
            }
        };
        $validator = new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $jwksHttp, new HttpFactory()));

        return new AuthClient($cfg, $endpoints, $validator, $tokenHttp);
    }

    /** @return array<string,mixed> */
    private function tokenBody(?string $idToken): array
    {
        $body = [
            'access_token' => 'AT',
            'token_type' => 'Bearer',
            'expires_in' => 300,
            'refresh_token' => 'RT',
            'scope' => 'openid',
        ];
        if ($idToken !== null) {
            $body['id_token'] = $idToken;
        }

        return $body;
    }

    private function signIdToken(string $nonce, ?string $priv = null): string
    {
        return $this->sign($this->idTokenClaims($nonce), $priv);
    }

    /**
     * Keycloak 이 내는 모양의 id_token 클레임. `$changes` 의 null 은 그 클레임을 빼고, `exp` 는 지금부터의 초다.
     *
     * @param array<string,mixed> $changes
     * @return array<string,mixed>
     */
    private function idTokenClaims(string $nonce, array $changes = []): array
    {
        $claims = ['sub' => 'u', 'iss' => $this->iss, 'aud' => 'it-client', 'nonce' => $nonce, 'exp' => time() + 300, 'iat' => time()];
        foreach ($changes as $name => $value) {
            if ($value === null) {
                unset($claims[$name]);
            } else {
                $claims[$name] = $name === 'exp' && \is_int($value) ? time() + $value : $value;
            }
        }

        return $claims;
    }

    /**
     * @param list<string> $aud
     * @return array<string,mixed>
     */
    private function accessTokenClaims(array $aud): array
    {
        return ['sub' => 'u', 'iss' => $this->iss, 'aud' => $aud, 'azp' => 'it-client', 'exp' => time() + 300, 'iat' => time()];
    }

    /** @param array<string,mixed> $claims */
    private function sign(array $claims, ?string $priv = null, string $kid = 'test-kid'): string
    {
        return FbJwt::encode($claims, $priv ?? $this->key['priv'], 'RS256', $kid);
    }

    /** @param array<string,mixed> $claims */
    private function signAs(string $signer, array $claims): string
    {
        return match ($signer) {
            'rs256' => $this->sign($claims),
            // 핀 밖 알고리즘 — 헤더 게이트가 먼저 거부하므로 키는 무엇이든 된다.
            'hs256' => FbJwt::encode($claims, str_repeat('k', 64), 'HS256', 'test-kid'),
            // JWKS 의 kid 를 사칭한 다른 키쌍 — 서명 검증이 거부한다.
            'foreign-key' => $this->sign($claims, self::foreignKey()),
            default => throw new \LogicException("unknown signer {$signer}"),
        };
    }

    private static function foreignKey(): string
    {
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        self::assertTrue(openssl_pkey_export($other, $priv));
        self::assertIsString($priv);

        return $priv;
    }
}

final class JwksHitCounter
{
    public int $n = 0;
}
