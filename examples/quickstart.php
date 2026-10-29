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

// 1) Get a token with the client-credentials grant. TokenSet's __toString() is masked automatically (accessToken=***).
$token = $client->auth()->clientCredentialsToken();
echo "token type: {$token->tokenType}, expires in: {$token->expiresIn}s\n";

// 2) Validate the issued access token with the self-hardened checks (RS256 pin · exact iss · aud membership · required exp ·
//    clock skew).
$validated = $client->auth()->validate($token->accessToken);
echo "subject: {$validated->subject}, issuer: {$validated->issuer}\n";

// 3) Admin API — create a user. fschmtt's create() returns void, so if you need the id, look it up afterwards with
//    findIdByUsername().
$client->admin()->users()->create(new User(username: 'demo-user', email: 'demo@example.com', enabled: true));
echo "created demo-user\n";

$userId = $client->admin()->users()->findIdByUsername('demo-user');
echo "demo-user id: {$userId}\n";
