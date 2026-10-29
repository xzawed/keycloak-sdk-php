<?php

declare(strict_types=1);

/*
 * bearer 문법 시험(`Admin/AdminBearerGrammarTest`)의 가짜 IdP — `php -S` 라우터다.
 *
 * ⚠️ 왜 Guzzle 핸들러가 아니라 프로세스인가: `KeycloakClient::create()`·`AdminClient` 는 Guzzle 을 스스로 만들어 핸들러를 넣을
 * 자리가 없다(`hostile-idp-router.php` 와 같은 이유).
 *
 * 상태는 `BG_STATE` 디렉터리의 `state.json` — `{"body_hex": 토큰 응답 본문의 hex}`. 토큰 엔드포인트는 그 바이트를 그대로 200 으로
 * 낸다(hex 인 까닭: 잘못된 UTF-8 바이트도 그대로 실어야 한다). 모든 요청은 라우팅 앞에서 `requests.log` 에
 * `[메서드, 경로, Authorization 값의 hex 또는 null]` 한 줄로 남는다(hex 인 까닭: 받은 바이트를 그대로 대조한다).
 */

$dir = getenv('BG_STATE');
if (!is_string($dir) || $dir === '') {
    http_response_code(500);

    return;
}
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url(is_string($uri) ? $uri : '/', PHP_URL_PATH);
$path = is_string($path) ? $path : '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$method = is_string($method) ? $method : 'GET';
$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
file_put_contents($dir . '/requests.log', json_encode([$method, $path, is_string($auth) ? bin2hex($auth) : null], JSON_THROW_ON_ERROR) . "\n", FILE_APPEND | LOCK_EX);

$state = json_decode((string) file_get_contents($dir . '/state.json'), true);
$body = is_array($state) && is_string($state['body_hex'] ?? null) ? hex2bin($state['body_hex']) : false;
if ($body === false) {
    http_response_code(500);

    return;
}

if (str_ends_with($path, '/protocol/openid-connect/token')) {
    header('Content-Type: application/json');
    echo $body;
} elseif ($path === '/admin/serverinfo') {
    // fschmtt 는 첫 자원 접근 전에 서버 버전을 묻는다 — 토큰 부여가 거기서 난다.
    header('Content-Type: application/json');
    echo '{"systemInfo":{"version":"26.6.0"}}';
} elseif (str_starts_with($path, '/admin/')) {
    if ($method === 'GET') {
        header('Content-Type: application/json');
        echo '[]';
    } else {
        http_response_code(204);
    }
} else {
    http_response_code(404);
}
