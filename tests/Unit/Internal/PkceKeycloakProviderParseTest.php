<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Internal;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Xzawed\Keycloak\Internal\PkceKeycloakProvider;

/**
 * `PkceKeycloakProvider::parseResponse()` 는 상류(stevenmaguire `Keycloak` → league `AbstractProvider`)의 해석을 **한 번 읽은
 * 본문으로** 다시 쓴다 — 상류는 본문을 두 번 `(string)` 으로 읽어 사본 둘을 쥐었고(실측: 32 MiB 본문에 Keycloak.php:394 와
 * AbstractProvider.php:786 의 두 사본), 상한을 걸 자리도 없었다. 다시 쓴 해석이 상한 안의 본문에서 **상류와 같은 값·같은 예외**를
 * 내는지 상류 프로바이더와 나란히 돌려 잰다(차등). 내용 타입 갈래 넷(jwt · urlencoded · json · 그 밖)과 500 갈래를 덮는다.
 */
final class PkceKeycloakProviderParseTest extends TestCase
{
    /** @return array<string, array{int, string, string}> 상태 · Content-Type · 본문 */
    public static function responses(): array
    {
        return [
            'json token' => [200, 'application/json', '{"access_token":"a","token_type":"Bearer","expires_in":300}'],
            'json with charset' => [200, 'application/json;charset=UTF-8', '{"access_token":"a"}'],
            'json scalar' => [200, 'application/json', '"just a string"'],
            // 상류(stevenmaguire)는 strict_types 없는 파일이라 반환형 `string|array` 가 스칼라를 문자열로 바꾸고 null 에는 TypeError 다.
            'json integer' => [200, 'application/json', '123'],
            'json float' => [200, 'application/json', '1.5'],
            'json true' => [200, 'application/json', 'true'],
            'json false' => [200, 'application/json', 'false'],
            'json null' => [200, 'application/json', 'null'],
            'json list' => [200, 'application/json', '[1,2]'],
            'json empty object' => [200, 'application/json', '{}'],
            'json numeric key' => [200, 'application/json', '{"0":"a","access_token":"b"}'],
            'json nested object' => [200, 'application/json', '{"access_token":"a","x":{"0":1,"k":[1,2]}}'],
            'json malformed' => [200, 'application/json', '{"access_token":'],
            'json invalid utf-8' => [200, 'application/json', "{\"access_token\":\"a\xff\"}"],
            'json 400 error' => [400, 'application/json', '{"error":"invalid_grant","error_description":"x"}'],
            'json 400 malformed' => [400, 'application/json', 'not json'],
            'no content type json body' => [200, '', '{"access_token":"a"}'],
            'no content type text body' => [200, '', 'access denied'],
            'text/plain json body' => [200, 'text/plain', '{"access_token":"a"}'],
            'text/plain text body' => [200, 'text/plain', 'not json at all'],
            'text/html 500' => [500, 'text/html', '<p>oops</p>'],
            'text/html 502' => [502, 'text/html', '<p>bad gateway</p>'],
            'urlencoded' => [200, 'application/x-www-form-urlencoded', 'access_token=a&token_type=bearer&expires_in=300'],
            'urlencoded nested' => [200, 'application/x-www-form-urlencoded; charset=UTF-8', 'a[b]=1&c=2'],
            'urlencoded numeric keys' => [200, 'application/x-www-form-urlencoded', '0=a&1=b&access_token=c'],
            'jwt userinfo' => [200, 'application/jwt', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.'],
            'jwt with json body' => [200, 'application/jwt', '{"access_token":"a"}'],
            'empty json' => [200, 'application/json', ''],
            'empty text' => [200, 'text/plain', ''],
            'whitespace padded json' => [200, 'application/json', '{"access_token":"a"}' . str_repeat(' ', 4096)],
        ];
    }

    /** @return array{0: string, 1: mixed} 반환값이면 ['value', 값], 예외면 ['throws', [클래스, 메시지, 원인 클래스]] */
    private static function parse(object $provider, ResponseInterface $response): array
    {
        $m = new \ReflectionMethod($provider, 'parseResponse');
        try {
            return ['value', $m->invoke($provider, $response)];
        } catch (\Throwable $e) {
            return ['throws', [$e::class, $e->getMessage(), $e->getPrevious() === null ? null : $e->getPrevious()::class]];
        }
    }

    #[DataProvider('responses')]
    public function testParsesLikeTheUpstreamProvider(int $status, string $type, string $body): void
    {
        $options = ['authServerUrl' => 'https://kc.test', 'realm' => 'r', 'clientId' => 'c', 'clientSecret' => 's', 'version' => '26.0.0'];
        $headers = $type === '' ? [] : ['Content-Type' => $type];
        $upstream = self::parse(new Keycloak($options), new Response($status, $headers, $body));
        $ours = self::parse(new PkceKeycloakProvider($options), new Response($status, $headers, $body));
        self::assertSame($upstream, $ours);
    }
}
