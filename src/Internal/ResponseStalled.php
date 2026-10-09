<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * 토큰·introspection·logout 응답 본문이 끝(EOF)을 알리기 전에 빈 읽기를 냈다 — `TokenResponseCap::read` 의 판정을 SDK 경계까지
 * 나르는 운반체다. @internal
 *
 * ⚠️ 공개 API 로 나가지 않는다 — 판독기를 부르는 자리마다 받아 바꾼다. introspect·logout(`AuthClient`)과
 * `ClientCredentialsTokenProvider` 는 그 자리에서, league 레인(`PkceKeycloakProvider::parseResponse`)은 `AuthClient::getAccessToken`
 * 에서 **새** `KeycloakTransportError`(`<본문 이름> stalled before its end`, 원인 없음)로 바꾸고, admin 레인은
 * `TokenResponseCap::middleware` 가 상한 거부와 같은 Guzzle `RequestException` 으로 바꾼다(`AdminClient::raw()` 는 하위 오류를 내보낸다).
 * 원인으로 달지 않는 까닭은 `ResponseTooLarge` 와 같다 — league·Guzzle 의 호출 스택 **안에서** 던져지므로 이 예외의 트레이스가 그
 * 프레임 인자(refresh_token·code·`form_params` 의 client_secret)를 쥔다. `\UnexpectedValueException` 을 잇는 것도 같은 까닭이다(league
 * 가 `getAccessToken()` 에 선언한 예외라 그 경계의 catch 가 죽은 갈래가 아니다).
 */
final class ResponseStalled extends \UnexpectedValueException
{
    public function __construct()
    {
        parent::__construct('response stalled before its end');
    }
}
