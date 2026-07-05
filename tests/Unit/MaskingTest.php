<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Masking;

final class MaskingTest extends TestCase
{
    public function testMasksNonEmptyFully(): void
    {
        self::assertSame('***', Masking::mask('super-secret-token'));
    }
    public function testEmptyAndNull(): void
    {
        self::assertSame('***', Masking::mask(''));   // 존재 여부도 노출 안 함
        self::assertSame('***', Masking::mask(null));
    }
    public function testNoPrefixLeak(): void
    {
        self::assertStringNotContainsString('super', Masking::mask('super-secret'));
    }
}
