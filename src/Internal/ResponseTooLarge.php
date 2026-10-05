<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

/**
 * league 가 받는 토큰 응답 본문(client_credentials·refresh_token·authorization_code)이 상한(`TokenResponseCap::TOKEN_RESPONSE_MAX_BYTES`)을
 * 넘었다 — league 의 호출 스택 **안에서**(`PkceKeycloakProvider`) 난 판정을 SDK 경계까지 나르는 운반체다. @internal
 *
 * ⚠️ 공개 API 로 나가지 않는다 — 던지는 곳은 `PkceKeycloakProvider` 뿐이고 그 프로바이더는 `AuthClient` 가 private 로만 쥔다(탈출구가
 * 없다). `AuthClient::getAccessToken` 이 이것을 받아 **새** `KeycloakTransportError`(같은 메시지, 원인 없음)로 바꾼다. 이 예외의
 * 트레이스는 league 의 `getAccessToken($grant, $options)` 프레임 인자(refresh_token·code)를 쥐므로 원인으로 달면 안 된다.
 * `\UnexpectedValueException` 을 잇는 것은 league 가 `getAccessToken()` 에 선언한 예외라서다(그 경계의 catch 가 죽은 갈래가 아니다).
 *
 * ⚠️ admin 레인은 이것을 쓰지 않는다 — 그 스택은 `AdminClient::raw()` 가 내보내는 fschmtt 의 것이라 거기서 던진 것은 탈출구를 쓰는
 * 소비자에게 그대로 닿는다(이 클래스를 썼을 때 실측으로 샜다). 그 자리는 Guzzle `RequestException` 으로 거부한다
 * (`TokenResponseCap::middleware`).
 */
final class ResponseTooLarge extends \UnexpectedValueException
{
    /** @param string $what 넘은 본문의 이름 — `token response` */
    public function __construct(string $what)
    {
        parent::__construct(sprintf('%s exceeds %d bytes', $what, TokenResponseCap::TOKEN_RESPONSE_MAX_BYTES));
    }
}
