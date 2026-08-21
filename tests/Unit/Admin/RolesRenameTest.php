<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Admin;

use Fschmtt\Keycloak\Builder;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\GrantType;
use Fschmtt\Keycloak\Representation\Role;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Xzawed\Keycloak\Admin\RolesResource;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;

/**
 * 롤 rename — **나가는 HTTP 요청의 모양**을 본다.
 *
 * ⚠️ 이 파일만 fschmtt 를 목으로 뜨지 않고 **실제 스택**(Builder → CommandExecutor → Guzzle)을
 * 태운다. 자매 테스트들처럼 `Fschmtt\…\Resource\Roles` 를 목으로 뜨면 경로가 어떻게 조립되는지
 * 볼 수 없고, 바로 그래서 이 결함이 오래 살아남았다 — fschmtt `Roles::update` 는 경로를
 * `$role->getName()` 에서 만들어 rename 을 표현하지 못하는데, 목은 그 사실을 통과시킨다.
 *
 * 부수 효과로 이 테스트는 **fschmtt 핀을 올릴 때의 드리프트 가드**이기도 하다. 우리 우회로는
 * `@internal` 인 `CommandExecutor` 위에 서 있으므로, 그 조립이 깨지면 여기서 먼저 터진다.
 */
final class RolesRenameTest extends TestCase
{
    private const REALM = 'test-realm';

    /**
     * 나간 요청. `Middleware::history()` 를 쓰지 않는 이유는 그쪽 컨테이너가 by-ref
     * `array|ArrayAccess` 라서 phpstan level max 가 프로퍼티 타입을 그만큼 넓히기 때문이다.
     *
     * @var list<RequestInterface>
     */
    private array $requests = [];

    /**
     * 형태만 갖춘 JWT. fschmtt 는 access_token 을 파싱하지만(점 두 개) 서명은 검증하지 않는다.
     */
    private function fakeJwt(): string
    {
        $b64 = static fn (array $o): string => rtrim(strtr(base64_encode((string) json_encode($o)), '+/', '-_'), '=');

        return $b64(['alg' => 'RS256', 'typ' => 'JWT'])
            . '.' . $b64(['exp' => time() + 300, 'iat' => time()])
            . '.' . rtrim(strtr(base64_encode('test-signature'), '+/', '-_'), '=');
    }

    /**
     * 토큰 grant 와 serverinfo 는 형태를 맞춰 답하고, 그 밖의 요청에는 $terminal 을 돌려준다.
     * 둘 중 하나라도 어긋나면 PUT 까지 도달하지 못하므로, 테스트는 요청을 못 찾고 실패한다.
     */
    private function keycloak(Response $terminal): Keycloak
    {
        $jwt = $this->fakeJwt();
        $json = static fn (array $o): Response => new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($o));

        $dispatch = static function (RequestInterface $request, array $options) use ($json, $jwt, $terminal) {
            $path = $request->getUri()->getPath();
            if (str_contains($path, '/protocol/openid-connect/token')) {
                return Create::promiseFor($json(['access_token' => $jwt, 'expires_in' => 300, 'token_type' => 'Bearer']));
            }
            if (str_contains($path, '/admin/serverinfo')) {
                return Create::promiseFor($json(['systemInfo' => ['version' => '26.0.0']]));
            }

            return Create::promiseFor($terminal);
        };

        $stack = HandlerStack::create($dispatch);
        $stack->push(function (callable $handler): callable {
            return function (RequestInterface $request, array $options) use ($handler) {
                $this->requests[] = $request;

                return $handler($request, $options);
            };
        });

        return (new Builder())
            ->withBaseUrl('http://kc.test')
            ->withGrantType(GrantType::clientCredentials(
                clientId: 'test-client',
                clientSecret: 'test-secret',
                realm: self::REALM,
            ))
            ->withHttpClient(new GuzzleClient(['handler' => $stack]))
            ->build();
    }

    private function lastPut(): RequestInterface
    {
        $puts = [];
        foreach ($this->requests as $request) {
            if ($request->getMethod() === 'PUT') {
                $puts[] = $request;
            }
        }
        // PUT 이 아예 안 나갔는데 통과시키면 이 테스트는 공허해진다. 정확히 하나여야 하는 것은
        // 자매 테스트들이 목으로 걸던 expects($this->once()) 에 해당한다 — 목을 걷어내면서
        // 그 단언까지 같이 잃지 않도록 여기서 요청 수로 센다.
        self::assertCount(1, $puts, 'PUT 은 정확히 한 번 — 0 이면 토큰/serverinfo 단계에서 멈춘 것이라 측정 무효다');

        return $puts[0];
    }

    public function testUpdateAddressesByCurrentNameAndCarriesNewNameInBody(): void
    {
        $roles = new RolesResource($this->keycloak(new Response(204)), self::REALM);

        // 소비자의 의도: 'old-name' 을 'new-name' 으로 rename 한다.
        $roles->update('old-name', new Role(name: 'new-name'));

        $put = $this->lastPut();

        // ⚠️ **이 줄이 이 테스트를 지탱한다.** 대조군 실측: 병합 구현을 되돌린 채 이 단언만
        // 무력화하면 나머지가 전부 통과한다(exit=0). fschmtt 의 병합은 경로를 $role->getName()
        // 에서 만들므로 **경로가 새 이름으로 어긋나고**, body 는 어차피 새 이름이라 멀쩡하다.
        // 자매 Go SDK 는 정확히 거울상이다 — gocloak 은 name 인자를 경로에 실어 경로가 항상
        // 맞고 body 가 깨지므로, 그쪽 테스트는 body 단언이 지탱한다. **부류가 같다고 단언
        // 위치를 복사하지 말 것.**
        self::assertSame('/admin/realms/' . self::REALM . '/roles/old-name', $put->getUri()->getPath());

        // body 는 새 이름이어야 한다. 이 단언은 현재 병합에 대해서는 공허하지만(위 대조군),
        // 경로만 옳고 body 가 옛 이름인 반대 방향의 회귀 — 자매 Go 에서 실제로 잡힌 것 — 를 막는다.
        $body = json_decode((string) $put->getBody(), true);
        self::assertIsArray($body);
        self::assertSame('new-name', $body['name'] ?? null, 'body 는 **새 이름**을 날라야 rename 이다');
    }

    public function testUpdateTakesOneTokenGrant(): void
    {
        $roles = new RolesResource($this->keycloak(new Response(204)), self::REALM);
        $roles->update('old-name', new Role(name: 'new-name'));

        $grants = 0;
        foreach ($this->requests as $request) {
            if (str_contains($request->getUri()->getPath(), '/protocol/openid-connect/token')) {
                ++$grants;
            }
        }

        // 우회로가 fschmtt 의 토큰을 재사용한다는 증거. raw Guzzle PUT 으로 갔다면 베어러를
        // 따로 구해야 했고, 새 grant 는 §4 토큰 캐시 불변식 위반이다.
        self::assertSame(1, $grants, 'admin 우회로가 토큰을 추가로 발급하면 §4 캐시 불변식이 깨진다');
    }

    public function testUpdate404BecomesNotFound(): void
    {
        $roles = new RolesResource($this->keycloak(new Response(404)), self::REALM);

        $this->expectException(KeycloakNotFoundError::class);
        $roles->update('missing', new Role(name: 'missing'));
    }
}
