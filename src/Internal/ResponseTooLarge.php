<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * A token response body league receives (client_credentials · refresh_token · authorization_code) exceeded the cap
 * (`TokenResponseCap::TOKEN_RESPONSE_MAX_BYTES`) — the carrier that brings a verdict made **inside** league's call stack
 * (`PkceKeycloakProvider`) to the SDK boundary. @internal
 *
 * ⚠️ It does not go out to the public API — the only place that throws it is `PkceKeycloakProvider`, and `AuthClient` holds
 * that provider only as a private (there is no escape hatch). `AuthClient::getAccessToken` catches this and turns it into a
 * **new** `KeycloakTransportError` (same message, no cause). This exception's trace holds the frame arguments of league's
 * `getAccessToken($grant, $options)` (refresh_token · code), so it must not be attached as a cause.
 * It extends `\UnexpectedValueException` because that is the exception league declares on `getAccessToken()` (the catch at
 * that boundary is not a dead branch).
 *
 * ⚠️ The admin lane does not use this — that stack is fschmtt's, which `AdminClient::raw()` exposes, so what is thrown there
 * reaches a consumer using the escape hatch as is (measured: it leaked when this class was used). That spot rejects with a
 * Guzzle `RequestException` (`TokenResponseCap::middleware`).
 */
final class ResponseTooLarge extends \UnexpectedValueException
{
    /** @param string $what name of the oversized body — `token response` */
    public function __construct(string $what)
    {
        parent::__construct(sprintf('%s exceeds %d bytes', $what, TokenResponseCap::TOKEN_RESPONSE_MAX_BYTES));
    }
}
