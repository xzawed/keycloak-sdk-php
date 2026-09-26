<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Integration;

use GuzzleHttp\Client;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\ResponseInterface;
use Xzawed\Keycloak\Token\AuthorizationRequest;

/**
 * 브라우저 없는 로그인 — 실제 Keycloak 로그인 폼을 HTTP 로 채워 인가 코드를 받는다.
 *
 * 세 걸음이고 `python/tests/integration/browser_login.py` 의 모양을 그대로 옮긴다:
 *
 * 1. SDK 가 만든 인가 URL(`createAuthorizationRequest()`)을 GET 한다(로그인 페이지 + 인증 세션 쿠키 —
 *    쿠키는 2 에서 직접 되싣는다).
 * 2. `<form id="kc-form-login">` 의 `action` 에 사용자명·비밀번호를 POST 하되 **리다이렉트는 따라가지 않는다** —
 *    redirect_uri 에는 아무것도 떠 있지 않다. 302 의 `Location` 이 곧 콜백이다.
 * 3. `Location` 에서 `code`·`state` 를 꺼내고, `state` 가 SDK 가 발급한 값인지 확인한다.
 *
 * 폼을 못 찾거나 상태 코드가 틀리면 받은 HTML 앞부분을 실어 실패한다 — 테마가 바뀌었을 때 원인이 바로 보이게.
 */
final class BrowserLogin
{
    private const LOGIN_FORM_ID = 'kc-form-login';

    /** `$request`(SDK 의 `createAuthorizationRequest()` 결과)로 로그인해 인가 코드를 돌려준다. */
    public static function login(
        AuthorizationRequest $request,
        string $redirectUri,
        string $username,
        #[\SensitiveParameter] string $password,
    ): string {
        $browser = new Client(['allow_redirects' => false, 'http_errors' => false, 'timeout' => 30]);
        $page = $browser->request('GET', $request->url);
        $html = (string) $page->getBody();
        if ($page->getStatusCode() !== 200) {
            Assert::fail("login page did not render:\n" . self::snippet($page, $request->url, $html));
        }
        $action = self::formAction($html);
        if ($action === null) {
            Assert::fail(\sprintf("no <form id=\"%s\"> in the login page:\n%s", self::LOGIN_FORM_ID, self::snippet($page, $request->url, $html)));
        }
        // ⚠️ Guzzle 의 CookieJar 에 맡기지 말고 **직접 되싣는다.** Keycloak 26 은 http 에서도 로그인 쿠키에 `Secure` 를
        // 단다. 브라우저는 localhost 를 안전한 출처로 봐서 보내지만, RFC 6265 대로 사는 저장소(Guzzle `SetCookie`
        // 는 https 가 아니면 Secure 쿠키를 싣지 않는다)는 http 요청에서 빼 POST 가 400 "Restart login cookie not
        // found" 로 끝난다(python 파일럿 실측 · php 에서 다시 잼: `'cookies' => true` 로 바꾸면 POST 가 400).
        $answer = $browser->request('POST', $action, [
            'form_params' => ['username' => $username, 'password' => $password],
            'headers' => ['Cookie' => self::cookieHeader($page)],
        ]);
        if ($answer->getStatusCode() !== 302) {
            Assert::fail("login POST did not redirect:\n" . self::snippet($answer, $action, (string) $answer->getBody()));
        }
        $location = $answer->getHeaderLine('Location');
        $callback = parse_url($location);
        $origin = \is_array($callback)
            ? ($callback['scheme'] ?? '') . '://' . ($callback['host'] ?? '') . (isset($callback['port']) ? ':' . $callback['port'] : '') . ($callback['path'] ?? '')
            : '';
        if ($origin !== $redirectUri) {
            Assert::fail("login redirected somewhere else: {$location}");
        }
        $query = self::queryParameters(\is_array($callback) ? ($callback['query'] ?? '') : '');
        // state 는 SDK 가 인가 URL 에 실은 CSRF 값이다 — 서버가 그대로 되돌려야 한다.
        if (($query['state'] ?? []) !== [$request->state]) {
            Assert::fail(\sprintf('state mismatch: sent %s, got %s', $request->state, implode(',', $query['state'] ?? ['(none)'])));
        }
        $codes = $query['code'] ?? [];
        if (\count($codes) !== 1 || $codes[0] === '') {
            Assert::fail("no single authorization code in the callback: {$location}");
        }

        return $codes[0];
    }

    /** `<form id="kc-form-login">` 의 action 만 집는다(속성 값의 `&amp;` 는 DOM 이 푼다). */
    private static function formAction(string $html): ?string
    {
        if ($html === '') {
            return null;
        }
        $dom = new \DOMDocument();
        $quiet = libxml_use_internal_errors(true);
        try {
            $dom->loadHTML($html);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($quiet);
        }
        $form = (new \DOMXPath($dom))->query(\sprintf('//form[@id="%s"]', self::LOGIN_FORM_ID));
        $node = $form === false ? null : $form->item(0);
        if (!$node instanceof \DOMElement) {
            return null;
        }
        $action = $node->getAttribute('action');

        return $action === '' ? null : $action;
    }

    /** 응답이 설정한 쿠키를 `Cookie` 헤더 한 줄로 — 이름=값만, 속성(`Secure`·`Path`…)은 버린다. 지운 쿠키(빈 값)는 싣지 않는다. */
    private static function cookieHeader(ResponseInterface $response): string
    {
        $pairs = [];
        foreach ($response->getHeader('Set-Cookie') as $header) {
            $pair = trim(explode(';', $header, 2)[0]);
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            if ($name !== '' && $value !== '') {
                $pairs[] = "{$name}={$value}";
            }
        }

        return implode('; ', $pairs);
    }

    /**
     * `parse_str` 대신 손으로 가른다 — 그것은 같은 키가 둘이면 뒤엣것만 남겨(「코드가 하나인가」를 못 잰다) 이름의 `.` 도 `_` 로 바꾼다.
     *
     * @return array<string, list<string>>
     */
    private static function queryParameters(string $query): array
    {
        $out = [];
        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $out[rawurldecode($name)][] = rawurldecode(str_replace('+', ' ', $value));
        }

        return $out;
    }

    private static function snippet(ResponseInterface $response, string $url, string $body): string
    {
        return \sprintf("HTTP %d %s\n%s", $response->getStatusCode(), $url, substr($body, 0, 1500));
    }
}
