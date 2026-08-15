<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\Exception\KeycloakAuthError;
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

    /** @param array<string,mixed> $body */
    private function authWithTokenBody(array $body, bool $forbidJwks = false, ?JwksHitCounter $jwksHits = null): AuthClient
    {
        $cfg = new KeycloakConfig(
            serverUrl: 'https://kc:8080',
            realm: 'it-realm',
            clientId: 'it-client',
            clientSecret: 's',
            redirectUri: 'https://app/cb',
        );
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
        return FbJwt::encode(
            [
                'sub' => 'u',
                'iss' => $this->iss,
                'aud' => 'it-client',
                'nonce' => $nonce,
                'exp' => time() + 300,
                'iat' => time(),
            ],
            $priv ?? $this->key['priv'],
            'RS256',
            'test-kid',
        );
    }
}

final class JwksHitCounter
{
    public int $n = 0;
}
