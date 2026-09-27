<?php

declare(strict_types=1);

/*
 * 적대 경로 행렬(`HostilePathMatrixTest`)의 **기록하는 가짜 IdP** — `php -S` 라우터다.
 *
 * ⚠️ 왜 Guzzle 핸들러가 아니라 프로세스인가: `KeycloakClient::create()` 와 `AdminClient` 는 Guzzle 을 **스스로**
 * 만든다(`HttpOptions::guzzle()` — 핸들러를 넣을 자리가 없다). 공개 API 로 만든 클라이언트를 그대로 부르려면
 * 진짜 HTTP 가 필요하다. 핸들러를 주입하는 뿌리만 쓰면 admin 의 토큰 부여 경로가 행렬에서 통째로 빠진다.
 *
 * 상태는 `HP_IDP_STATE` 디렉터리의 `state.json` 이 정하고, 모든 요청을 라우팅 **앞**에서 `requests.log` 에
 * `[메서드, 경로, grant_type]` 한 줄로 남긴다 — 라우트가 없는 경로(admin 404 포함)도 남는다. 분류는 SDK 가
 * 무엇을 **시도했나**를 본다.
 */

$dir = getenv('HP_IDP_STATE');
if (!is_string($dir) || $dir === '') {
    http_response_code(500);

    return;
}
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url(is_string($uri) ? $uri : '/', PHP_URL_PATH);
$path = is_string($path) ? $path : '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$method = is_string($method) ? $method : 'GET';
$tokenSuffix = '/protocol/openid-connect/token';
$grant = '';
if ($method === 'POST' && str_ends_with($path, $tokenSuffix)) {
    // 폼이 표준(RFC 6749 §4.1.3)이지만 JSON 본문으로 보낸 교환도 CODE_EXCHANGE 로 읽는다 — 폼만 읽으면 그 교환이 TOKEN_GRANT 로
    // 떨어져 nonce 변형(W3b)이 안 붙는다(Grok 레그 지목, 실측 SILENT).
    $raw = (string) file_get_contents('php://input');
    parse_str($raw, $form);
    $g = $form['grant_type'] ?? null;
    if (!is_string($g)) {
        $json = json_decode($raw, true);
        $g = is_array($json) ? ($json['grant_type'] ?? null) : null;
    }
    $grant = is_string($g) ? $g : '';
}
file_put_contents($dir . '/requests.log', json_encode([$method, $path, $grant], JSON_THROW_ON_ERROR) . "\n", FILE_APPEND | LOCK_EX);

$state = json_decode((string) file_get_contents($dir . '/state.json'), true);
if (!is_array($state)) {
    http_response_code(500);

    return;
}

$reply = static function (int $status, string $type, string $body): void {
    http_response_code($status);
    if ($type !== '') {
        header('Content-Type: ' . $type);
    }
    echo $body;
};
$str = static fn (mixed $v): string => is_string($v) ? $v : '';

if (str_ends_with($path, $tokenSuffix)) {
    // tokenOverride 는 W3 변형이다 — 수신자를 정상 응답으로 만든 **뒤에** 건다.
    $o = $state['tokenOverride'] ?? null;
    if (is_array($o)) {
        $status = $o['status'] ?? 200;
        $reply(is_int($status) ? $status : 200, $str($o['type'] ?? ''), $str($o['body'] ?? ''));
    } else {
        $reply(200, 'application/json', $str($state['tokenDefault'] ?? ''));
    }
} elseif (str_ends_with($path, $tokenSuffix . '/introspect')) {
    $reply(200, 'application/json', '{"active":true,"username":"svc","client_id":"c","sub":"u1"}');
} elseif (str_ends_with($path, '/protocol/openid-connect/certs')) {
    if (($state['certsDown'] ?? false) === true) {
        $reply(503, 'application/json', '{"error":"unavailable"}');
    } else {
        $reply(200, 'application/json', $str($state['jwks'] ?? ''));
    }
} elseif (str_ends_with($path, '/protocol/openid-connect/logout')) {
    http_response_code(204);
} elseif (str_ends_with($path, '/admin/serverinfo')) {
    // fschmtt 는 첫 명령 전에 서버 버전을 묻는다 — 답하지 않으면 admin 행이 자기 자원 엔드포인트에 못 닿고 여기서 404 로 끝난다.
    $reply(200, 'application/json', '{"systemInfo":{"version":"26.0.0"}}');
} else {
    $reply(404, 'application/json', '{"error":"not found"}');
}
