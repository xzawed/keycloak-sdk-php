<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * A token, introspection or logout response body gave an empty read before it signaled its end (EOF) — the carrier that
 * brings `TokenResponseCap::read`'s verdict to the SDK boundary. @internal
 *
 * ⚠️ It does not go out to the public API — every place that calls the reader catches and converts it. introspect · logout
 * (`AuthClient`) and `ClientCredentialsTokenProvider` on the spot, and the league lane (`PkceKeycloakProvider::parseResponse`)
 * in `AuthClient::getAccessToken`, turn it into a **new** `KeycloakTransportError` (`<body name> stalled before its end`, no
 * cause), and in the admin lane `TokenResponseCap::middleware` turns it into the same Guzzle `RequestException` as the cap
 * rejection (`AdminClient::raw()` exposes underlying errors). Why it is not attached as a cause: the same as
 * `ResponseTooLarge` — it is thrown **inside** league's and Guzzle's call stacks, so this exception's trace holds those
 * frame arguments (refresh_token · code · the client_secret in `form_params`). It extends `\UnexpectedValueException` for
 * the same reason as well (it is the exception league declares on `getAccessToken()`, so the catch at that boundary is not
 * a dead branch).
 */
final class ResponseStalled extends \UnexpectedValueException
{
    public function __construct()
    {
        parent::__construct('response stalled before its end');
    }
}
