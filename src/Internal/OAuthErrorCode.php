<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * Accepts the `error` value of an IdP error response **only when it is an OAuth error code**. @internal
 *
 * ⚠️ `error` is response body too — when it echoed a token back, `KeycloakAuthError`'s message and the public property
 * `oauthError` printed it as is (measured by the Grok leg 2026-09-26, through `var_dump` · `print_r`). The codes of
 * RFC 6749 · 6750 · 8628 · OIDC and Keycloak are all lowercase letters and underscores (`invalid_grant` · `login_required` ·
 * `authorization_pending` …), so only that shape is let through — JWT, base64url and hex tokens contain uppercase letters,
 * digits, `-` or `.` and are filtered out. It is the same shape as the python leg.
 *
 * ⚠️ The anchors are `\A` · `\z` — `$` (without `D`) and `\Z` also match **before one trailing newline**, so
 * `"invalid_client\n"` passed as a code and was put into the message and `oauthError` newline and all (it splits log lines,
 * measured 2026-10-02). Pinned by: `OAuthErrorCodeTest`.
 */
final class OAuthErrorCode
{
    public static function of(mixed $error): ?string
    {
        return \is_string($error) && preg_match('/\A[a-z_]{1,64}\z/', $error) === 1 ? $error : null;
    }
}
