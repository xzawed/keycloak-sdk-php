<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

/** Fully opaque masking of tokens/secrets (no prefix is exposed). */
final class Masking
{
    public static function mask(#[\SensitiveParameter] ?string $secret): string
    {
        return '***';
    }
}
