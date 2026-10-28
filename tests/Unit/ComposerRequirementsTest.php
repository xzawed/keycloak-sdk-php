<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * 소비자 하한 핀 — `composer.json` 의 `require` 를 직접 읽는다. 상한 시험(`TokenResponseCapTest`·`AdminResponseBodyTest`)은
 * 잠긴 판(composer.lock)으로 돌아 하한이 내려가도 초록이다 — 소비자에게 닿는 것은 잠금이 아니라 이 범위다(ruby
 * `http_framing_pins_spec` 의 net-http 하한 핀과 같은 꼴). 바꾸려면 아래 이유를 다시 재고 이 표를 함께 고친다.
 *
 * - `ext-curl` — 없으면 Guzzle 이 PHP 스트림 래퍼(`StreamHandler`)로 떨어지고, 그 래퍼는 응답 헤더 한 줄을 길이 제한 없이 읽는다
 *   (실측: 16 MiB 한 줄을 이행 · 피크 +57 MB, curl 은 같은 줄을 `cURL error 100` 으로 거부). Composer 는 설치 때만 묻는다 —
 *   런타임 점검(`platform-check` 기본값)은 PHP 판뿐이라 `TokenResponseCapTest` 의 stream 칸은 남는다.
 * - `guzzlehttp/guzzle` — 7.15.2 아래에 GHSA-v5mv-p594-2x33(high)·GHSA-f7vp-7xgx-4w4r 가 걸린다(`composer audit` 의 출처).
 * - `guzzlehttp/psr7` — 2.12.3 아래에 GHSA-c2w2-prh8-qm98 이 걸리고, 2.11 아래의 `copyToStream` 은 Content-Length 를 아는
 *   본문에서 싱크의 짧은 쓰기를 무시해 스트림 처리기가 상한에서 멈추지 못한다(`AdminResponseBody` docblock).
 */
final class ComposerRequirementsTest extends TestCase
{
    /** @return array<string, array{string, string}> 좌표 · composer.json 이 적어야 할 제약 */
    public static function floors(): array
    {
        return [
            'ext-curl' => ['ext-curl', '*'],
            'guzzlehttp/guzzle' => ['guzzlehttp/guzzle', '^7.15.2'],
            'guzzlehttp/psr7' => ['guzzlehttp/psr7', '^2.12.3'],
        ];
    }

    #[DataProvider('floors')]
    public function testRequireDeclaresTheConsumerFloor(string $package, string $constraint): void
    {
        self::assertSame($constraint, self::requirements()[$package] ?? null, "composer.json require.$package");
    }

    /** @return array<mixed> */
    private static function requirements(): array
    {
        $json = file_get_contents(__DIR__ . '/../../composer.json');
        self::assertIsString($json, 'composer.json 을 읽지 못했다');
        $manifest = json_decode($json, true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($manifest);
        $require = $manifest['require'] ?? null;
        self::assertIsArray($require, 'composer.json 에 require 가 없다');

        return $require;
    }
}
