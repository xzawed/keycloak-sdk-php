<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

/** 토큰/시크릿을 완전 불투명 마스킹(접두 노출 없음). */
final class Masking
{
    public static function mask(?string $secret): string
    {
        return '***';
    }
}
