<?php

declare(strict_types=1);

/*
 * admin 응답 본문(`AdminResponseBodyTest`)의 가짜 Keycloak — 원시 소켓 HTTP/1.1 서버다(한 번에 연결 하나).
 *
 * ⚠️ 왜 `php -S` 라우터가 아닌가: 본문 중간에서 멈춘 응답을 만들어야 하는데, `php -S` 스크립트는 클라이언트가 끊어도 다음 쓰기
 * 전에는 그것을 모른다 — 멈춘 스크립트가 서버를 붙들어 다음 시험이 기다린다. 여기서는 멈춘 뒤 `stream_select` 로 클라이언트가
 * 닫는 것을 곧바로 본다.
 *
 * 실행: `php admin-body-server.php <포트> <상태 디렉터리>`. 상태는 `<디렉터리>/state.json` —
 * `{"nonce": 문자열, "routes": {"METHOD /path": 명세}}`, 명세는
 * `{"status": int, "headers": {이름: 값}, "head": 문자열, "pad": 공백 바이트, "stall": 쓰고 멈출 본문 바이트(없으면 끝까지),
 *   "close": bool(stall 에서 붙들지 않고 닫는다), "length": bool(Content-Length 를 단다 — 기본 참, 거짓이면 연결 종료로 끝),
 *   "gzip": bool(head + pad 를 gzip 으로 보낸다 — stall 은 압축된 바이트로 센다), "keep": bool(응답 뒤 연결을 닫지 않는다 — stall 이
 *   없을 때만), "chunked": bool(Content-Length 대신 Transfer-Encoding: chunked — stall 은 청크 안의 바이트로 센다),
 *   "cl": int(본문과 상관없이 이 Content-Length 를 단다 — 규격을 어기는 서버),
 *   "interim": {"status": 1xx, "headers": {이름: 값}}(최종 응답 앞에 중간 응답 하나를 보낸다)}`. 204 에는 Content-Length 를 달지 않는다.
 * 경로가 없으면: GET /admin/serverinfo 는 버전, `/protocol/openid-connect/token` 은 쓸 수 있는 토큰, 그 밖은 404.
 * `CONNECT` 는 프록시처럼 받는다 — 터널 너머 요청을 같은 연결에서 이 서버가 받는다(경로 "CONNECT" 의 {"close": true} 면 받지 않고 닫는다).
 * 요청마다 응답이 끝나거나 클라이언트가 닫은 뒤 `<디렉터리>/sent.log` 에 한 줄을 남긴다 — `{"method", "path", "nonce",
 * "written": 써 보낸 본문 바이트, "got": 받은 요청 본문 바이트, "declared": 요청의 Content-Length, "continued": 100 Continue 를
 * 보냈는가, "conn": 연결 번호(1 부터), "tunneled": CONNECT 터널 너머로 왔는가}`.
 */

$port = (int) ($argv[1] ?? 0);
$dir = $argv[2] ?? '';
$server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
if ($server === false || $dir === '') {
    fwrite(STDERR, "cannot listen: $errstr\n");
    exit(1);
}

$spaces = str_repeat(' ', 65536);
$b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
$token = static function () use ($b64): string {
    $claims = $b64((string) json_encode(['exp' => time() + 300, 'iat' => time(), 'sub' => 'svc']));

    return $b64('{"alg":"RS256","typ":"JWT"}') . '.' . $claims . '.' . str_repeat('A', 43);
};

/** @param array<mixed> $spec */
$int = static fn (array $spec, string $key, int $default): int => is_int($spec[$key] ?? null) ? $spec[$key] : $default;

/** head 뒤에 공백 pad 바이트를 붙인 본문의 gzip — 큰 pad 를 한꺼번에 만들지 않는다. */
$gzip = static function (string $head, int $pad) use ($spaces): string {
    $ctx = deflate_init(ZLIB_ENCODING_GZIP);
    if ($ctx === false) {
        return '';
    }
    $out = (string) deflate_add($ctx, $head, ZLIB_NO_FLUSH);
    for ($left = $pad; $left > 0; $left -= 65536) {
        $out .= (string) deflate_add($ctx, substr($spaces, 0, min($left, 65536)), ZLIB_NO_FLUSH);
    }

    return $out . deflate_add($ctx, '', ZLIB_FINISH);
};

// ⚠️ 소켓을 받는 것은 이름 있는 함수다 — phpstan 은 변수에 담은 클로저의 `@param resource` 를 읽지 않는다.

/**
 * 요청 머리와 본문을 읽는다 — 머리는 빈 줄까지, 본문은 Content-Length 만큼. 클라이언트가 닫았으면 null.
 *
 * @param resource $conn
 * @return array{0: string, 1: string, 2: int, 3: int, 4: bool}|null [메서드, 경로, 받은 본문 바이트, Content-Length, 100 Continue]
 */
function arb_read_request($conn): ?array
{
    $head = '';
    while (!str_contains($head, "\r\n\r\n")) {
        $chunk = fread($conn, 8192);
        if ($chunk === false || $chunk === '') {
            return null;
        }
        $head .= $chunk;
    }
    [$raw, $rest] = explode("\r\n\r\n", $head, 2);
    $lines = explode("\r\n", $raw);
    [$method, $target] = array_pad(explode(' ', array_shift($lines)), 2, '/');
    $headers = [];
    foreach ($lines as $line) {
        [$k, $v] = array_pad(explode(':', $line, 2), 2, '');
        $headers[strtolower(trim($k))] = trim($v);
    }
    $continued = str_contains(strtolower($headers['expect'] ?? ''), '100-continue');
    if ($continued) {
        fwrite($conn, "HTTP/1.1 100 Continue\r\n\r\n");
    }
    $declared = (int) ($headers['content-length'] ?? 0);
    $got = strlen($rest);
    while ($got < $declared) {
        $chunk = fread($conn, max(1, min($declared - $got, 65536)));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $got += strlen($chunk);
    }
    $path = parse_url($target, PHP_URL_PATH);

    return [$method, is_string($path) ? $path : '/', $got, $declared, $continued];
}

/**
 * 클라이언트가 닫을 때까지(많아야 10 초) 아무것도 쓰지 않고 붙든다.
 *
 * @param resource $conn
 */
function arb_hold($conn): void
{
    $deadline = microtime(true) + 10;
    while (microtime(true) < $deadline) {
        $r = [$conn];
        $w = $e = null;
        if (@stream_select($r, $w, $e, 1) > 0) {
            $chunk = @fread($conn, 1024);
            if ($chunk === false || $chunk === '') {
                return;
            }
        }
    }
}

/**
 * 본문 조각 하나를 쓴다 — chunked 면 청크 틀에 싸서. 돌려주는 것은 쓴 본문 바이트(실패하면 0). 청크는 다 쓰거나 실패한다.
 *
 * @param resource $conn
 */
function arb_send($conn, string $bytes, bool $chunked): int
{
    $frame = $chunked ? sprintf("%x\r\n", strlen($bytes)) . $bytes . "\r\n" : $bytes;
    for ($at = 0; $at < strlen($frame);) {
        $n = @fwrite($conn, substr($frame, $at));
        if ($n === false || $n === 0) {
            return $chunked ? 0 : $at;
        }
        $at += $n;
    }

    return strlen($bytes);
}

/**
 * 다음 요청을 받을 연결 — 붙든 연결(keep 응답 뒤)의 다음 요청(또는 닫힘)과 새 연결 중 먼저 오는 것. 새 연결이 오면 붙든 연결은
 * 버려진 것이라 닫는다.
 *
 * @param resource $server
 * @param array{0: resource, 1: int}|null $kept
 * @return array{0: resource, 1: int}|null [연결, 번호]
 */
function arb_next($server, ?array $kept, int &$conns): ?array
{
    if ($kept !== null) {
        $r = [$kept[0], $server];
        $w = $e = null;
        if (@stream_select($r, $w, $e, 3600) < 1) {
            return null;
        }
        if (in_array($kept[0], $r, true)) {
            return $kept;
        }
        @fclose($kept[0]);
    }
    $conn = @stream_socket_accept($server, $kept === null ? 3600 : 0);

    return $conn === false ? null : [$conn, ++$conns];
}

$conns = 0;
$kept = null;
for (;;) {
    $taken = arb_next($server, $kept, $conns);
    $kept = null;
    if ($taken === null) {
        continue;
    }
    [$conn, $id] = $taken;
    // 읽지도 닫지도 않는 클라이언트(끊긴 뒤 소켓을 늦게 놓는 스트림 처리기)에 쓰기가 끝없이 묶이지 않게.
    stream_set_timeout($conn, 5);
    $request = arb_read_request($conn);
    if ($request === null) {
        fclose($conn);
        continue;
    }
    [$method, $path, $got, $declared, $continued] = $request;
    $state = json_decode((string) @file_get_contents($dir . '/state.json'), true);
    $state = is_array($state) ? $state : [];
    $routes = is_array($state['routes'] ?? null) ? $state['routes'] : [];
    $tunneled = false;
    if ($method === 'CONNECT') {
        // 프록시 노릇 — 터널을 열었다고 답하고 같은 연결에서 터널 너머 요청을 이 서버가 받는다. 경로 "CONNECT" 의 명세
        // {"close": true} 면 터널 너머 요청을 받지 않고 닫는다(원서버에 닿지 못한 터널). {"headers": "…\r\n"} 는 그 200 에 머리 줄을
        // 더한다 — 규격(RFC 9110 §9.3.6)을 어기고 틀(Content-Length · Transfer-Encoding)을 다는 프록시.
        $tunnel = $routes['CONNECT'] ?? null;
        $tunnel = is_array($tunnel) ? $tunnel : [];
        fwrite($conn, "HTTP/1.1 200 Connection established\r\n" . (is_string($tunnel['headers'] ?? null) ? $tunnel['headers'] : '') . "\r\n");
        $request = ($tunnel['close'] ?? false) === true ? null : arb_read_request($conn);
        if ($request === null) {
            @fclose($conn);
            $record = ['method' => 'CONNECT', 'path' => $path, 'nonce' => is_string($state['nonce'] ?? null) ? $state['nonce'] : '', 'conn' => $id];
            file_put_contents($dir . '/sent.log', json_encode($record) . "\n", FILE_APPEND | LOCK_EX);
            continue;
        }
        [$method, $path, $got, $declared, $continued] = $request;
        $tunneled = true;
    }
    $spec = $routes["$method $path"] ?? null;
    if (!is_array($spec)) {
        $spec = match (true) {
            $method === 'GET' && $path === '/admin/serverinfo' => ['head' => '{"systemInfo":{"version":"26.6.0"}}'],
            str_ends_with($path, '/protocol/openid-connect/token') => [
                'head' => (string) json_encode(['access_token' => $token(), 'token_type' => 'Bearer', 'expires_in' => 300]),
            ],
            default => ['status' => 404, 'head' => '{"error":"not found"}'],
        };
    }
    $status = $int($spec, 'status', 200);
    $stall = $int($spec, 'stall', -1);
    $keep = ($spec['keep'] ?? false) === true && $stall < 0;
    $headers = [];
    foreach (is_array($spec['headers'] ?? null) ? $spec['headers'] : [] as $name => $value) {
        $headers[(string) $name] = is_scalar($value) ? (string) $value : '';
    }
    $head = is_string($spec['head'] ?? null) ? $spec['head'] : '';
    $pad = $int($spec, 'pad', 0);
    if (($spec['gzip'] ?? false) === true) {
        $headBody = $gzip($head, $pad);
        $total = strlen($headBody);
        $headers['Content-Encoding'] = 'gzip';
    } else {
        $headBody = $head;
        $total = strlen($head) + $pad;
    }
    $chunked = ($spec['chunked'] ?? false) === true;
    $out = "HTTP/1.1 $status X\r\nContent-Type: application/json\r\n" . ($keep ? '' : "Connection: close\r\n");
    foreach ($headers as $name => $value) {
        $out .= "$name: $value\r\n";
    }
    if (is_int($spec['cl'] ?? null)) {
        $out .= "Content-Length: {$spec['cl']}\r\n";   // 본문과 다른 길이를 알린다(규격을 어기는 서버)
    } elseif ($chunked) {
        $out .= "Transfer-Encoding: chunked\r\n";
    } elseif ($status !== 204 && ($keep || ($spec['length'] ?? true) === true)) {
        $out .= "Content-Length: $total\r\n";   // 204 에는 달지 않는다(RFC 9110 §8.6) — Keycloak 의 204 도 그렇다
    }
    $limit = $stall >= 0 ? $stall : $total;
    $interim = '';
    if (is_array($spec['interim'] ?? null)) {   // 최종 응답 앞의 중간 응답 하나 — {"status": 1xx, "headers": {이름: 값}}
        $interim = 'HTTP/1.1 ' . $int($spec['interim'], 'status', 103) . " X\r\n";
        foreach (is_array($spec['interim']['headers'] ?? null) ? $spec['interim']['headers'] : [] as $name => $value) {
            $interim .= $name . ': ' . (is_scalar($value) ? (string) $value : '') . "\r\n";
        }
        $interim .= "\r\n";
    }
    $ok = @fwrite($conn, $interim . $out . "\r\n") !== false;
    $first = substr($headBody, 0, $limit);
    $written = 0;
    while ($ok && $written < strlen($first)) {
        $n = arb_send($conn, substr($first, $written, 65536), $chunked);
        $ok = $n > 0;
        $written += $ok ? $n : 0;
    }
    while ($ok && $written < $limit) {
        $n = arb_send($conn, substr($spaces, 0, min($limit - $written, 65536)), $chunked);
        $ok = $n > 0;
        $written += $ok ? $n : 0;
    }
    if ($ok && $chunked && $stall < 0) {
        $ok = @fwrite($conn, "0\r\n\r\n") !== false;
    }
    if ($ok && $stall >= 0 && ($spec['close'] ?? false) !== true) {
        arb_hold($conn);
    }
    if ($ok && $keep) {
        $kept = [$conn, $id];
    } else {
        @fclose($conn);
    }
    $record = ['method' => $method, 'path' => $path, 'nonce' => is_string($state['nonce'] ?? null) ? $state['nonce'] : '',
        'written' => $written, 'got' => $got, 'declared' => $declared, 'continued' => $continued, 'conn' => $id, 'tunneled' => $tunneled];
    file_put_contents($dir . '/sent.log', json_encode($record) . "\n", FILE_APPEND | LOCK_EX);
}
