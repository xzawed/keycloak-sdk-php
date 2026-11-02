<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * A token response that is a JSON object but carries no usable `access_token` (absent, empty or not a string) — the carrier
 * that brings `PkceKeycloakProvider::createAccessToken`'s verdict to `AuthClient::getAccessToken`, which turns it into a
 * **new** `KeycloakAuthError` (`token response has no usable access_token`, no cause). @internal
 *
 * ⚠️ Without it league's `AccessToken` constructor threw an SPL `\InvalidArgumentException` that fell into the boundary's
 * catch-all and came out as `KeycloakTransportError`, while `ClientCredentialsTokenProvider` called the same response a
 * `KeycloakAuthError`. It is not attached as a cause and it extends `\UnexpectedValueException` for the same reasons as
 * `ResponseStalled` (it is thrown inside league's call stack, and it is the exception league declares on `getAccessToken()`).
 */
final class TokenResponseUnusable extends \UnexpectedValueException
{
    public function __construct()
    {
        parent::__construct('token response has no usable access_token');
    }
}
