# Keycloak SDK for PHP

An idiomatic PHP SDK for [Keycloak](https://www.keycloak.org/) covering both OIDC/OAuth2 authentication and the Admin REST API behind one consistent facade.

Part of a **nine-language polyglot SDK** (Java · Python · Node · Go · C# · PHP · Rust · Ruby · Kotlin) — one API shape, nine idioms: [github.com/xzawed/KeyCloakSDK](https://github.com/xzawed/KeyCloakSDK).

> **`v0.2.0` is on Packagist** — `composer require xzawed/keycloak-sdk` resolves it under Composer's default `minimum-stability: stable`.
>
> ⚠️ **`0.2.0` restores a capability that `0.1.0` did not have: renaming a realm role.** `roles()->update()` now takes the current name as its first argument — `update(string $name, Role $role)` — because the old one-argument form **could not express a rename at all**. See [Upgrading from `0.1.0`](https://github.com/xzawed/KeyCloakSDK/blob/main/php/README.md#upgrading-from-010).

## Requirements

- PHP **8.3+** (`composer.json` requires `^8.3`)
- Keycloak server 26.6.x (verified by the integration suite)

## Install

The SDK is developed in the `php/` directory of a polyglot monorepo, and Packagist cannot install from a subdirectory. Releases are therefore subtree-split into the dedicated read-only repository [`xzawed/keycloak-sdk-php`](https://github.com/xzawed/keycloak-sdk-php), which is what Packagist reads — the package name stays `xzawed/keycloak-sdk`:

```bash
composer require "xzawed/keycloak-sdk:0.2.0"
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

## Upgrading from `0.1.0`

**One signature changed, and it is a fix rather than a rearrangement.**

`roles()->update(Role $role)` became **`roles()->update(string $name, Role $role)`**. The old form took only the representation, and the library underneath builds the request path out of `$role->getName()` — so the path and the body came from the same value and **a rename could not be expressed**. Measured on `0.1.0`: asking to rename `old-name` to `new-name` sent `PUT /roles/new-name` with body `{"name":"new-name"}`, and the current name appeared nowhere in the request. Keycloak renames with `PUT /{current name}` carrying the new name in the body, so that request was not a rename — it was an update aimed at a role that does not exist yet.

```php
// 0.1.0 — could only ever update a role in place
$admin->roles()->update(new Role(name: 'reporting'));

// 0.2.0 — address by the current name, put the new one in the body
$admin->roles()->update('reporting', new Role(name: 'analytics'));

// updating without renaming: repeat the name
$admin->roles()->update('reporting', new Role(name: 'reporting', description: 'Read-only'));
```

The other eight language SDKs always took `(name, representation)`; this brings PHP back in line with them. Nothing else changed — `users()`, `clients()`, `realms()` and `groups()` already took a separate identifier and are untouched.

## Upgrading from `0.1.0-rc.1`

`0.1.0-rc.2` adds OIDC `nonce` so `id_token` replay can be detected, which changes two signatures. **One of them can break your code:**

1. **`new AuthorizationRequest(...)` gains a required `string $nonce`.** If you construct this type by hand you will get a `TypeError` for the missing argument. Let the SDK build it instead — `$client->auth()->createAuthorizationRequest(...)` returns a fully populated instance. Reading fields off the returned object is unaffected (a field was *added*, none removed).
2. **`exchangeCode()` gains an optional third argument.** Two-argument calls keep working unchanged — but that path still does **not** verify the `id_token`. To get replay protection, pass the nonce you were given: `exchangeCode($code, $verifier, $req->nonce)`.

## Versioning and support

This SDK is **pre-1.0**. Under SemVer a `0.x` **minor** bump may carry breaking changes, so read the release notes before upgrading. Only the newest released version of each language SDK receives security fixes — there are no LTS lines, and older `0.x` releases are not backported to. Full policy: [SECURITY.md](https://github.com/xzawed/KeyCloakSDK/blob/main/SECURITY.md).

## Documentation

- [Project overview](https://github.com/xzawed/KeyCloakSDK) — all nine languages, what is identical and what is not
- [Changelog](https://github.com/xzawed/KeyCloakSDK/blob/main/CHANGELOG.md) — **read this before upgrading**; breaking changes are listed per language
- [Getting started](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/getting-started.md) — install and quickstart for this language
- [Compatibility](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/reference/compatibility.md) — which Keycloak server range and base libraries each published version shipped against
- [Full PHP example](https://github.com/xzawed/KeyCloakSDK/blob/main/php/examples/quickstart.php)
- [Deploying a Keycloak server](https://github.com/xzawed/KeyCloakSDK/blob/main/docs/guides/deploying-keycloak-server.md)
- [Security policy](https://github.com/xzawed/KeyCloakSDK/blob/main/SECURITY.md)

## License

[Apache-2.0](https://github.com/xzawed/KeyCloakSDK/blob/main/php/LICENSE)
