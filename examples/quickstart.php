<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Fschmtt\Keycloak\Representation\User;

$client = KeycloakClient::create(new KeycloakConfig(
    serverUrl: getenv('KC_SERVER_URL') ?: 'http://localhost:8080',
    realm: getenv('KC_REALM') ?: 'it-realm',
    clientId: getenv('KC_CLIENT_ID') ?: 'it-client',
    clientSecret: getenv('KC_CLIENT_SECRET') ?: 'it-secret',
));

// 1) client-credentials 그랜트로 토큰 발급. TokenSet의 __toString()은 자동 마스킹된다(accessToken=***).
$token = $client->auth()->clientCredentialsToken();
echo "token type: {$token->tokenType}, expires in: {$token->expiresIn}s\n";

// 2) 발급받은 액세스 토큰을 자체 강화 검증(RS256 핀·iss 정확일치·aud 포함검사·exp 필수·클록 스큐).
$validated = $client->auth()->validate($token->accessToken);
echo "subject: {$validated->subject}, issuer: {$validated->issuer}\n";

// 3) 관리 API — 사용자 생성. fschmtt의 create()는 void를 반환하므로 id가 필요하면 findIdByUsername()로 후속 조회한다.
$client->admin()->users()->create(new User(username: 'demo-user', email: 'demo@example.com', enabled: true));
echo "created demo-user\n";

$userId = $client->admin()->users()->findIdByUsername('demo-user');
echo "demo-user id: {$userId}\n";
