# Keycloak SDK for PHP

An idiomatic PHP SDK for [Keycloak](https://www.keycloak.org/) covering both OIDC/OAuth2 authentication and the Admin REST API behind one consistent facade.

Part of a **nine-language polyglot SDK** (Java · Python · Node · Go · C# · PHP · Rust · Ruby · Kotlin) — one API shape, nine idioms: [github.com/xzawed/KeyCloakSDK](https://github.com/xzawed/KeyCloakSDK).

> **Pre-release** — the first release candidate (`v0.1.0-rc.1`) is on Packagist (`composer require "xzawed/keycloak-sdk:0.1.0-rc.1"`); there is no stable release yet.

## Requirements

- PHP **8.3+** (`composer.json` requires `^8.3`)
- Keycloak server 26.6.x (verified by the integration suite)

## Install

The SDK is developed in the `php/` directory of a polyglot monorepo, and Packagist cannot install from a subdirectory. Releases are therefore subtree-split into the dedicated read-only repository [`xzawed/keycloak-sdk-php`](https://github.com/xzawed/keycloak-sdk-php), which is what Packagist reads — the package name stays `xzawed/keycloak-sdk`:

```bash
composer require "xzawed/keycloak-sdk:0.1.0-rc.1"
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

// 3) admin API — create/update return void (sister-language isomorphism). Look the id up with findIdByUsername().
$users = $client->admin()->users();
$users->create(new User(username: 'alice', enabled: true));
$userId = $users->findIdByUsername('alice');
$users->update($userId, $users->get($userId)->withEmail('alice@example.com'));
echo "created userId={$userId}\n";
```

> **Audience:** validation requires the token's `aud` to contain `clientId`. A stock realm does *not* put the client id in a client-credentials token's `aud`, so on a default realm either pass `expectedAudience: 'my-api'` (the audience your realm actually issues), or add an *Audience* protocol mapper to the client in Keycloak.

Admin failures surface as `KeycloakNotFoundError` / `KeycloakConflictError` / `KeycloakForbiddenError` (all carrying `KeycloakAdminError::getStatusCode()`), network failures as `KeycloakTransportError`. `admin()->raw()` is the escape hatch to the underlying typed client.

## Security defaults

- **Algorithm pinning** — the accepted JWT signature algorithms are pinned (`RS256` by default, configurable via `signatureAlgorithms:`); the header-supplied `alg`, including `none`, is never trusted. The SDK decodes the raw header segment itself to gate on `alg` *before* verification, because `firebase/php-jwt` only fills its `&$headers` out-parameter after a successful decode.
- **Hardened claims** — exact `iss` match, `aud` containment check, mandatory `exp` (a token without one is rejected), and a bounded clock skew (`clockSkew:`, default 30s).
- **DoS-safe JWKS** — a refetch is triggered only by an unresolved key ID (rotation) and never by a bad signature, and is rate-limited by `jwksMinRefetchSeconds:` (default 30s) — so no volume of forged random `kid`s makes the SDK issue more than one JWKS request per interval.
- **OIDC nonce / `id_token` replay protection** — `createAuthorizationRequest()` always issues a cryptographic nonce, puts it on the authorization URL, and returns it on `AuthorizationRequest::$nonce`. Pass that value as the optional third argument to `exchangeCode()` and the SDK fully validates the `id_token` (signature · `iss` · `aud` · `exp`) before comparing the nonce claim. Omit it and id_token validation is skipped (same opt-out as the other eight languages).
- **Secret handling** — `KeycloakConfig` and `TokenSet` mask secrets and tokens fully (`***`, no prefix) in their `__toString()`; TLS verification is on by default and both connect and read timeouts are always applied.

Two scope limits worth knowing. The JWKS cache and its rate limit are per-`JwksStore` in-memory state, so their reach follows your deployment model: under a long-running worker (Swoole, RoadRunner) they span requests, but under classic PHP-FPM every request builds a fresh store and the limit only binds within that one request. And masking covers this SDK's own `__toString()` — PHP has no erasable string type, so the client secret lives in an ordinary `string` for its lifetime and masking is defence in depth, not a guarantee about your logs.

## Upgrading from `0.1.0-rc.1`

The next release will be `0.1.0-rc.2`. It adds OIDC `nonce` so `id_token` replay can be detected, which changes two signatures. **One of them can break your code:**

1. **`new AuthorizationRequest(...)` gains a required `string $nonce`.** If you construct this type by hand you will get a `TypeError` for the missing argument. Let the SDK build it instead — `$client->auth()->createAuthorizationRequest(...)` returns a fully populated instance. Reading fields off the returned object is unaffected (a field was *added*, none removed).
2. **`exchangeCode()` gains an optional third argument.** Two-argument calls keep working unchanged — but that path still does **not** verify the `id_token`. To get replay protection, pass the nonce you were given: `exchangeCode($code, $verifier, $req->nonce)`.

## Versioning and support

This SDK is **pre-1.0**. Under SemVer a `0.x` **minor** bump may carry breaking changes, so read the release notes before upgrading. Only the newest released version of each language SDK receives security fixes — there are no LTS lines, and older `0.x` releases are not backported to. Full policy: [SECURITY.md](https://github.com/xzawed/KeyCloakSDK/blob/main/SECURITY.md).

## Documentation

- [Getting started](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/getting-started.md) — per-language install, quickstart, and compatibility matrix
- [Full PHP example](https://github.com/xzawed/KeyCloakSDK/blob/main/php/examples/quickstart.php)
- [Deploying a Keycloak server](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/deploying-keycloak-server.md)
- [Security policy](https://github.com/xzawed/KeyCloakSDK/blob/main/SECURITY.md)

## License

[Apache-2.0](https://github.com/xzawed/KeyCloakSDK/blob/main/php/LICENSE)
