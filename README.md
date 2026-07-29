# Keycloak SDK for PHP

An idiomatic PHP SDK for [Keycloak](https://www.keycloak.org/) covering both OIDC/OAuth2 authentication and the Admin REST API behind one consistent facade.

Part of a **nine-language polyglot SDK** (Java · Python · Node · Go · C# · PHP · Rust · Ruby · Kotlin) — one API shape, nine idioms: [github.com/xzawed/KeyCloakSDK](https://github.com/xzawed/KeyCloakSDK).

> **Pre-release** — not yet published to Packagist.

## Requirements

- PHP **8.3+** (`composer.json` requires `^8.3`)
- Keycloak server 26.6.x (verified by the integration suite)

## Install

The SDK is developed in the `php/` directory of a polyglot monorepo, and Packagist cannot install from a subdirectory. Releases are therefore subtree-split into the dedicated read-only repository [`xzawed/keycloak-sdk-php`](https://github.com/xzawed/keycloak-sdk-php), which is what Packagist reads — the package name stays `xzawed/keycloak-sdk`:

```bash
composer require xzawed/keycloak-sdk
```

```php
use Xzawed\Keycloak\{KeycloakClient, KeycloakConfig};   // admin lives under Xzawed\Keycloak\Admin
```

## Quickstart

`KeycloakClient::create()` assembles auth immediately (no network); `admin()` is created lazily on first call and needs a client secret. Value types are `final readonly class`, and failures throw the `KeycloakException` hierarchy.

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Fschmtt\Keycloak\Representation\User;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;

$client = KeycloakClient::create(new KeycloakConfig(
    serverUrl: 'https://kc.example.com',
    realm: 'myrealm',
    clientId: 'my-app',
    clientSecret: '…', // load from an env var / secret manager; __toString is auto-masked
));

// 1) client-credentials grant. TokenSet::__toString() masks the tokens (accessToken=***).
$token = $client->auth()->clientCredentialsToken();
echo "token type: {$token->tokenType}, expires in: {$token->expiresIn}s\n";

// 2) hardened verification (alg pinning · exact iss · aud containment · mandatory exp · clock skew).
$validated = $client->auth()->validate($token->accessToken);
echo "subject: {$validated->subject}, issuer: {$validated->issuer}\n";

// 3) admin API — create returns void, so look the id up afterwards with findIdByUsername().
$client->admin()->users()->create(new User(username: 'alice', enabled: true));
$userId = $client->admin()->users()->findIdByUsername('alice');
echo "created userId={$userId}\n";
```

Admin failures surface as `KeycloakNotFoundError` / `KeycloakConflictError` / `KeycloakForbiddenError` (all carrying `KeycloakAdminError::getStatusCode()`), network failures as `KeycloakTransportError`. `admin()->raw()` is the escape hatch to the underlying typed client.

## Secure by default

- **Algorithm pinning** — the accepted JWT signature algorithms are pinned (`RS256` by default, configurable via `signatureAlgorithms:`); the header-supplied `alg`, including `none`, is never trusted.
- **Hardened claims** — exact `iss` match, `aud` containment check, mandatory `exp` (a token without one is rejected), and a bounded clock skew (`clockSkew:`, default 30s).
- **DoS-safe JWKS** — a refetch happens only for an unresolved key ID (rotation), rate-limited by `jwksMinRefetchSeconds:` (default 60s), so forged random `kid`s cannot flood the IdP.
- **Secrets stay out of logs** — `KeycloakConfig` and `TokenSet` mask secrets and tokens fully (`***`, no prefix) in their `__toString()`; TLS verification is on by default and both connect and read timeouts are always applied.

## Documentation

- [Getting started](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/getting-started.md) — per-language install, quickstart, and compatibility matrix
- [Full PHP example](https://github.com/xzawed/KeyCloakSDK/blob/main/php/examples/quickstart.php)
- [Deploying a Keycloak server](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/deploying-keycloak-server.md)
- [Security policy](https://github.com/xzawed/KeyCloakSDK/blob/main/SECURITY.md)

## License

[Apache-2.0](https://github.com/xzawed/KeyCloakSDK/blob/main/php/LICENSE)
