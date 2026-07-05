<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\AuthClient;
use Xzawed\Keycloak\Jwks\JwksStore;
use Xzawed\Keycloak\JwtValidator;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;

final class AuthMappingTest extends TestCase
{
    public function testIntrospectMapsActive(): void
    {
        $cfg = new KeycloakConfig(serverUrl: 'http://kc:8080', realm: 'r', clientId: 'c', clientSecret: 's');
        $mock = new MockHandler([new Response(200, [], '{"active":true,"username":"alice","client_id":"c"}')]);
        $guzzle = new Client(['handler' => HandlerStack::create($mock)]);
        $endpoints = new OidcEndpoints($cfg);
        // JwtValidator는 introspect에 미사용 — 최소 구성
        $validator = new JwtValidator($cfg, $endpoints, new JwksStore($endpoints->jwks(), $guzzle, new HttpFactory()));
        $auth = new AuthClient($cfg, $endpoints, $validator, $guzzle);
        $ir = $auth->introspect('some-token');
        self::assertTrue($ir->active);
        self::assertSame('alice', $ir->username);
    }
}
