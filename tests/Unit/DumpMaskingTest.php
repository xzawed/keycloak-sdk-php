<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;
use Xzawed\Keycloak\Token\AuthorizationRequest;
use Xzawed\Keycloak\Token\TokenSet;

/**
 * **덤프 경로** 마스킹 — `var_dump`/`print_r` 이 비밀을 원문으로 찍지 않는가.
 *
 * ⚠️ 이것은 축의 **바닥(기본 문자열/디버그 표현)이 아니라 그 밖**이다. `__toString` 과
 * `jsonSerialize` 는 이미 마스킹하는데, PHP 의 덤프 계열은 그 둘을 **우회해 프로퍼티를 직접**
 * 읽는다(실측 2026-09-12: `var_dump($provider)` 가 캐시된 액세스 토큰과 중첩 config 의
 * `clientSecret` 을 둘 다 원문으로 찍었다).
 *
 * ⚠️ **`__debugInfo()` 가 덮는 범위는 실측으로 정했다**(PHP 8.3.32):
 *   var_dump ✓ · print_r ✓ · debug_zval_dump ✓ · **var_export ✗**(private 까지 원문으로 찍는다)
 * 저장소 주석이 `print_r` 을 `var_export` 와 같은 부류로 적고 있었는데 **틀렸다.**
 *
 * ⚠️ **이것은 기밀 경계가 아니다.** 공개 프로퍼티(`$ts->accessToken`)·`get_object_vars`·
 * `(array)` 캐스트·`foreach` 는 여전히 원문을 본다. 우발적 로깅에 대한 심층 방어다.
 */
final class DumpMaskingTest extends TestCase
{
    private const SECRET = 'SECRET-CENSUS';
    private const TOKEN = 'AT-CENSUS-TOKEN';

    /** @return list<array{0:string,1:object}> */
    public static function secretHolders(): array
    {
        $cfg = new KeycloakConfig(
            serverUrl: 'http://kc:8080',
            realm: 'r',
            clientId: 'c',
            clientSecret: self::SECRET,
        );
        $f = new HttpFactory();
        $provider = new ClientCredentialsTokenProvider(
            $cfg,
            new OidcEndpoints($cfg),
            new \GuzzleHttp\Client(),
            $f,
            $f,
        );
        $r = new \ReflectionObject($provider);
        $p = $r->getProperty('cached');
        $p->setAccessible(true);
        $p->setValue($provider, new TokenSet(accessToken: self::TOKEN, expiresIn: 60));

        return [
            ['TokenSet', new TokenSet(accessToken: self::TOKEN, expiresIn: 60, refreshToken: self::TOKEN)],
            ['AuthorizationRequest', new AuthorizationRequest(url: 'http://x', state: 's', codeVerifier: self::TOKEN, nonce: 'n')],
            ['KeycloakConfig', $cfg],
            ['ClientCredentialsTokenProvider', $provider],
        ];
    }

    #[DataProvider('secretHolders')]
    public function testVarDumpDoesNotLeak(string $label, object $obj): void
    {
        ob_start();
        var_dump($obj);
        $out = (string) ob_get_clean();
        self::assertStringNotContainsString(self::TOKEN, $out, "$label: var_dump 이 토큰을 원문으로 찍는다");
        self::assertStringNotContainsString(self::SECRET, $out, "$label: var_dump 이 시크릿을 원문으로 찍는다");
    }

    #[DataProvider('secretHolders')]
    public function testPrintRDoesNotLeak(string $label, object $obj): void
    {
        ob_start();
        print_r($obj);
        $out = (string) ob_get_clean();
        self::assertStringNotContainsString(self::TOKEN, $out, "$label: print_r 이 토큰을 원문으로 찍는다");
        self::assertStringNotContainsString(self::SECRET, $out, "$label: print_r 이 시크릿을 원문으로 찍는다");
    }

    /** ⚠️ 대조군 — 마스킹이 「전부 숨기기」가 아니라 **비밀만** 가리는지. 디버깅 가능해야 한다. */
    public function testDumpStillShowsNonSecretFields(): void
    {
        ob_start();
        var_dump(new TokenSet(accessToken: self::TOKEN, expiresIn: 60, scope: 'openid'));
        $out = (string) ob_get_clean();
        self::assertStringContainsString('openid', $out, '비밀이 아닌 필드까지 숨기면 디버깅이 불가능해진다');
        self::assertStringContainsString('***', $out);
    }
}
