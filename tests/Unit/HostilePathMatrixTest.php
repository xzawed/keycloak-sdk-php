<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use Firebase\JWT\JWT as FbJwt;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\ClientCredentialsTokenProvider;
use Xzawed\Keycloak\Exception\KeycloakException;
use Xzawed\Keycloak\Http\HttpOptions;
use Xzawed\Keycloak\KeycloakClient;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\OidcEndpoints;
use Xzawed\Keycloak\Tests\Unit\Token\TokenSetTest;

/**
 * 적대 경로 행렬 — 분류표를 세우고, 적대 변형을 **메서드 손 목록이 아니라 계급에** 붙인다
 * (등록부 `guard-detection-surface-hand-narrowed`, Go 파일럿 `go/hostile_path_matrix_test.go` 의 PHP 판).
 *
 * nonce·콜드캐시 백오프·토큰응답 타입검증 축은 `scripts/test/test-security-defaults.sh` 가 손으로 고른 자리에 앵커를
 * 건다. 그래서 **새 공개 교환 경로**가 생기면 세 축 모두 그것을 모른다. 여기서는 경로를 파생한다:
 *
 *   - 선언 집합: `FacadeDumpTest::roots()` 에서 `FacadeDumpTest::reach()` 가 닿는 이 SDK 클래스마다 공개 메서드 전부
 *     (정적·생성자 포함, 이 SDK 가 선언한 것 — 부모가 SDK 면 물려받은 것도 그 클래스의 행이다). 그리고 `php/src`
 *     에 선언된 공개 메서드 전수와 합친다. 걷기가 안 닿는 클래스의 인스턴스 메서드는 수신자가 없어 UNDETERMINED 다.
 *   - 호출: 메서드마다 **새** 클라이언트를 **기록하는 가짜 IdP**(`Fixtures/hostile-idp-router.php`, `php -S`) 위에
 *     만들어 리플렉션으로 부른다. 인자는 타입만 보고 합성한다.
 *   - 분류: 그 호출이 IdP 에 실제로 보낸 요청으로 가른다(`classify`).
 *
 * 단언은 Go 판과 같다 — (1) 이유 없는 UNDETERMINED 없음(낡은 면제는 실패) · (2) CODE_EXCHANGE·TOKEN_GRANT·JWKS_FETCH
 * 가 각각 비지 않음 · (W1) 손 테스트가 겨누는 메서드가 전부 기대 계급의 행이고 그 축의 파생 대상에 있음(표 자신도
 * 앵커와 대조) · (W3a) 토큰 부여·코드 교환 행마다 기존 테스트가 단언한 형식이 틀린 토큰 응답 · (W3b) nonce 파라미터가
 * 있는 코드 교환 행마다 id_token 변형 · (W3c) JWKS 를 조회한 행마다 콜드 캐시 + /certs 503.
 * 실패한 칸은 `KNOWN_GAP_GROUPS` 에 이유와 함께 있으면 GAP, 관측되지 않는 항목은 낡은 것이라 실패한다.
 *
 * Grok 레그가 「새 교환 메서드가 빠져나가는 길」로 지목하고 실측(변이 SILENT)이 맞다고 한 일곱을 받았다 — 제3자 부모 표면의
 * 면제를 SDK 클래스별로 두고 「내보내지 않는다」를 타입으로 잰다 · 동적 표면(`__call`·`__callStatic`·`__get`)은 UNDETERMINED ·
 * JSON 본문의 교환도 CODE_EXCHANGE(라우터) · bool 이 가른 경로는 true 로 한 번 더 · W3b 에 iss≠·aud≠·exp 지남·alg=none 과
 * 거부 오류의 id_token 누출 검사 · W3c 에 위조 서명 토큰. 기각한 둘: `php/src` 밖의 클래스(composer 자동로드가 `src/` 뿐이라
 * 배포되지 않는다) · 다른 호스트로 나가는 요청(기록하는 IdP 가 볼 수 없다 — 아래 한계).
 *
 * ⚠️ Go 와 다른 자리 넷(PHP 가 강제한다):
 *   - **가짜 IdP 가 프로세스다** — `KeycloakClient::create()`·`AdminClient` 는 Guzzle 을 스스로 만들어 핸들러를 넣을
 *     자리가 없다(라우터 머리 주석). 그래서 IdP 는 칸마다 새로 띄우지 않고 **상태를 비운다**(클라이언트는 칸마다 새것).
 *   - **정적 메서드·생성자도 행이다** — 수신자가 필요 없으니 걷기가 안 닿아도 부른다(Go 의 선언 집합엔 패키지 함수가
 *     없었다). 생성자는 `new` 로 부른다 — 생성 때 토큰을 받아 오는 새 클래스가 여기서 드러난다.
 *   - **제3자 부모의 공개 표면은 행이 아니라 면제표(`INHERITED_EXEMPT`)다** — league `AbstractProvider::authorize()` 는
 *     `exit` 를 부른다(리플렉션으로 막 부르면 테스트 프로세스가 죽는다). 표에 없는 물려받음은 실패한다.
 *   - **하네스 상태는 전부 정적이다**(`FacadeDumpTest`·`MalformedTokenResponseTest` 의 실측) — 예외 트레이스 인자에
 *     러너 프레임이 테스트 객체를 싣고 `var_dump` 가 따라간다. 변형 본문은 인자로 넘기지 않는다(코드 이름만 넘긴다).
 *
 * ⚠️ 한계(Go 판과 같은 부류 — 전부 NONE 으로 읽힌다): 기록된 요청도 오류도 없이 끝나는 교환 경로. bool 이 아닌 합성
 * 인자(정수·열거형·기본값)가 요청 앞에서 갈라 세우는 것, 이 IdP 가 아닌 호스트로 나가 오류를 버리는 것. 그리고 반환·
 * 프로퍼티 타입이 `mixed`·`object` 인 자리는 「내보내지 않는다」 검사가 못 가른다.
 *
 * 재는 명령: `HP_MATRIX_PRINT=1 vendor/bin/phpunit --filter HostilePathMatrixTest` — 분류표·판정표·요약을 stderr 로 찍는다.
 */
final class HostilePathMatrixTest extends TestCase
{
    private const CODE_EXCHANGE = 'CODE_EXCHANGE';
    private const TOKEN_GRANT = 'TOKEN_GRANT';
    private const JWKS_FETCH = 'JWKS_FETCH';
    private const OTHER = 'OTHER';
    private const NONE = 'NONE';
    private const UNDETERMINED = 'UNDETERMINED';
    private const CLASSES = [self::CODE_EXCHANGE, self::TOKEN_GRANT, self::JWKS_FETCH, self::OTHER, self::NONE, self::UNDETERMINED];

    private const NS = 'Xzawed\\Keycloak\\';
    private const BASE = '/realms/r/protocol/openid-connect';
    // 분류는 realm 과 무관하게 **꼬리**로 본다 — 인자로 받은 realm 의 엔드포인트도 교환이다(Go 판의 Grok 레그 실측).
    private const TOKEN_SUFFIX = '/protocol/openid-connect/token';
    private const CERTS_SUFFIX = '/protocol/openid-connect/certs';
    private const SECRET = 'hp-client-secret';
    // 콜드 캐시 칸의 호출 수 — 상한 k−1 이 백오프, 하한 1 이 콜드 경로 도달의 증명이다.
    private const COLD_K = 5;

    /** UNDETERMINED 여도 되는 행과 그 이유(`짧은클래스::메서드`). ⚠️ 이유 없는 면제는 넣지 않는다 — 낡은 면제는 실패한다. */
    private const UNDETERMINED_EXEMPT = [
        'Token\\TokenSet::fromArray' => '정적 파서 — 인자(배열)만 받고 HTTP 클라이언트를 쥐지 않아 요청을 낼 수 없다. '
            . '합성 인자 `[]` 는 access_token 이 없어 계약상 거부된다(TokenSetTest::testMissingAccessTokenIsRejected).',
        'Admin\\RenamableRoles::updateByName' => 'RolesResource::update 안에서 만들어 곧바로 버린다 — 소비자가 쥘 수 없어 걷기가 안 닿는다'
            . '(FacadeDumpTest::EXEMPT 와 같은 이유). 그 경로는 행 Admin\\RolesResource::update 가 TOKEN_GRANT 로 잰다.',
    ];

    /**
     * SDK 클래스가 물려받은 **제3자** 공개 메서드를 행으로 부르지 않는 이유 — `짧은 SDK 클래스 => [선언한 제3자 클래스들, 이유]`.
     * 키가 SDK 클래스인 것이 요점이다(부모로 키를 잡으면 그 부모를 물려받는 새 SDK 클래스가 조용히 빠진다). 예외 클래스가
     * `\Exception` 의 접근자를 물려받는 것은 규칙으로 뺀다(`checkInherited`). 이유 「내보내지 않는다」는 반환·프로퍼티 타입으로 잰다.
     * 표에 없는 물려받음은 실패하고, 더는 물려받지 않는 항목은 낡은 면제로 실패한다.
     */
    private const INHERITED_EXEMPT = [
        'Internal\\PkceKeycloakProvider' => [
            [\League\OAuth2\Client\Provider\AbstractProvider::class, \Stevenmaguire\OAuth2\Client\Provider\Keycloak::class],
            'AuthClient 의 private 프로퍼티로만 쥐고 내보내지 않는다(§4 은닉·@internal) — 그 교환은 AuthClient 의 행들이 잰다. '
                . '⚠️ AbstractProvider::authorize() 는 exit 를 불러 리플렉션으로 막 부를 수도 없다.',
        ],
        'Admin\\RenamableRoles' => [
            [\Fschmtt\Keycloak\Resource\Resource::class],
            'RolesResource::update 안에서 fschmtt Keycloak::resource() 로 만들어 곧바로 버린다(@internal) — 물려받는 것은 fschmtt 내부 '
                . '실행기를 받는 생성자뿐이고, 그 교환은 행 Admin\\RolesResource::update 가 TOKEN_GRANT 로 잰다.',
        ],
    ];

    /** W3b 에서 빠져도 되는 CODE_EXCHANGE 행과 그 이유. nonce 를 다른 이름으로 받는 새 교환 메서드가 조용히 빠지지 않게. 오늘은 비었다. */
    private const NONCE_DROP_EXEMPT = [];

    /**
     * 현재 main 에서 실패하는 칸 — `등록부 id => [이유, 축, 행 목록, 변형 목록]` 이고 `knownGaps()` 가 **행 × 변형의 칸마다**
     * `W3<축> 행/변형 => id: 이유` 로 펼친다. SDK 를 고치지 않고 드러내 둔다. 관측되지 않는(이제 통과하거나 칸이 없는) 칸은
     * 낡은 것이라 실패한다. ⚠️ 와일드카드는 없다 — 행을 이름으로 적으므로 **새 admin 메서드의 같은 누출은 GAP 이 아니라
     * FAIL** 이다(틈에 조용히 흡수되지 않는다). **이유 없는 항목은 넣지 않는다.**
     */
    private const KNOWN_GAP_GROUPS = [
        'php-admin-token-error-unsanitized' => [
            'reason' => 'admin 의 토큰 부여는 fschmtt 가 하고 Admin\\ErrorTranslation 이 그 예외를 SanitizedCause 없이 원본째 달며 '
                . '메시지도 그대로 옮긴다 — Guzzle 의 본문 요약(d4·e·e2·e3 → getMessage)과 하위 예외의 트레이스 인자(b2·d·d2·d3 → '
                . 'var_dump·print_r·(string))가 토큰 응답을 찍는다. #622 는 AuthClient·provider 에만 적용됐다.',
            'axis' => 'a',
            'rows' => [
                'Admin\\ClientsResource::all', 'Admin\\ClientsResource::delete', 'Admin\\ClientsResource::get',
                'Admin\\ClientsResource::import', 'Admin\\ClientsResource::update',
                'Admin\\GroupsResource::all', 'Admin\\GroupsResource::create', 'Admin\\GroupsResource::delete',
                'Admin\\GroupsResource::get', 'Admin\\GroupsResource::update',
                'Admin\\RealmsResource::all', 'Admin\\RealmsResource::delete', 'Admin\\RealmsResource::get',
                'Admin\\RealmsResource::import', 'Admin\\RealmsResource::update',
                'Admin\\RolesResource::all', 'Admin\\RolesResource::create', 'Admin\\RolesResource::delete',
                'Admin\\RolesResource::get', 'Admin\\RolesResource::update',
                'Admin\\UsersResource::create', 'Admin\\UsersResource::delete', 'Admin\\UsersResource::findIdByUsername',
                'Admin\\UsersResource::get', 'Admin\\UsersResource::search', 'Admin\\UsersResource::update',
            ],
            'variants' => ['b2', 'd', 'd2', 'd3', 'd4', 'e', 'e2', 'e3'],
        ],
    ];

    /**
     * W1 — 손으로 고른 PHP 테스트가 겨누는 메서드. [행, 계급, 축(a·b·c·row), 앵커(`tests/Unit 아래 파일|메서드`), 앵커가 부르는 이름].
     * 부르는 이름이 행의 메서드가 아니면(비공개·다른 클래스) 행의 소스가 — 같은 클래스의 비공개 메서드를 따라 — 그것을 부르는지 대조한다.
     */
    private const HAND = [
        ['AuthClient::clientCredentialsToken', self::TOKEN_GRANT, 'a', 'MalformedTokenResponseTest.php|calls', 'clientCredentialsToken'],
        ['AuthClient::refresh', self::TOKEN_GRANT, 'a', 'MalformedTokenResponseTest.php|calls', 'refresh'],
        ['AuthClient::exchangeCode', self::CODE_EXCHANGE, 'a', 'MalformedTokenResponseTest.php|calls', 'exchangeCode'],
        ['ClientCredentialsTokenProvider::getToken', self::TOKEN_GRANT, 'a', 'MalformedTokenResponseTest.php|calls', 'getToken'],
        ['AuthClient::introspect', self::OTHER, 'row', 'MalformedTokenResponseTest.php|calls', 'introspect'],
        ['AuthClient::logout', self::OTHER, 'row', 'MalformedTokenResponseTest.php|calls', 'logout'],
        // 보안 기본값 가드(scripts/test/test-security-defaults.sh)의 PHP 행위 앵커 — nonce · 백오프 · 토큰 타입 · 빈 키셋.
        ['AuthClient::exchangeCode', self::CODE_EXCHANGE, 'b', 'AuthClientNonceTest.php|testExchangeCodeRejectsMismatchedNonce', 'exchangeCode'],
        ['AuthClient::exchangeCode', self::CODE_EXCHANGE, 'b', 'AuthClientNonceTest.php|testExchangeCodeRejectsMissingIdTokenWhenNonceExpected', 'exchangeCode'],
        ['Jwks\\JwksStore::getKeyByKid', self::JWKS_FETCH, 'c', 'Jwks/JwksStoreTest.php|testColdCacheFailingIdpCollapsesToOneRequest', 'getKeyByKid'],
        ['Jwks\\JwksStore::getKeyByKid', self::JWKS_FETCH, 'c', 'Jwks/FailureBackoffTest.php|testWindowExpiresAndAllowsARetry', 'remaining'],
        ['Jwks\\JwksStore::getKeyByKid', self::JWKS_FETCH, 'c', 'Jwks/JwksStoreTest.php|testRecoveredIdpResetsTheBackoff', 'getKeyByKid'],
        ['ClientCredentialsTokenProvider::getToken', self::TOKEN_GRANT, 'a', 'Token/TokenSetTest.php|testNonStringAccessTokenIsRejected', 'fromArray'],
        ['Jwks\\JwksStore::getKeyByKid', self::JWKS_FETCH, 'c', 'Jwks/JwksStoreTest.php|testEmptyKeySetDoesNotClobberAGoodCache', 'getKeyByKid'],
    ];

    // 보안 기본값 가드가 PHP 행위 앵커를 적는 모양 둘 — `php/tests/Unit/<파일>|public function <이름>(` · `"php/tests/Unit/<파일>" "<이름>"`.
    private const SCRIPT_ANCHOR_RES = [
        '#php/tests/Unit/([A-Za-z0-9_/]+Test\.php)\|public function ([A-Za-z0-9_]+)\(#',
        '#"php/tests/Unit/([A-Za-z0-9_/]+Test\.php)"\s+"(test[A-Za-z0-9_]+)"#',
    ];

    // ⚠️ 하네스 상태는 전부 정적이다(클래스 머리 주석).
    private static string $dir = '';
    private static int $port = 0;
    /** @var resource|null */
    private static $proc = null;
    private static string $priv = '';
    private static string $otherPriv = '';
    /** @var array<string, string> */
    private static array $jwk = [];
    private static string $universal = '';
    private static string $idToken = '';
    private static string $access = '';
    private static string $refresh = '';
    /** @var array<string, array{from:string, measure:bool, status:int, type:string, body:string, canaries:array<string, array{0:string,1:bool}>}> */
    private static array $variants = [];
    /** @var list<string> 마지막 `invoke` 가 모은 PHP 경고 */
    private static array $lastWarnings = [];
    /** @var array<string, true> bool 자리를 true 로 불러야 요청을 내는 행(`runRow`) — W3 칸도 같은 인자로 부른다 */
    private static array $flipRows = [];
    /** 마지막 W3b 칸이 낸 id_token — 거부 오류의 렌더링에 원문이 없어야 한다(정적이라 덤프에 안 실린다) */
    private static string $lastIdToken = '';
    /** @var array<string, list<string>> 경고 => 그것을 낸 칸·행 */
    private static array $warned = [];

    protected function setUp(): void
    {
        ini_set('zend.exception_ignore_args', '0');
    }

    public function testHostilePathMatrix(): void
    {
        self::startIdp();
        try {
            self::matrix();
        } finally {
            self::stopIdp();
        }
    }

    private static function matrix(): void
    {
        self::$warned = [];
        self::$flipRows = [];
        $builderOf = self::probeBuilders();
        $decl = self::declared();
        $rows = [];
        foreach ($decl['rows'] as $m) {
            $rows[$m['label']] = $m['unreached'] !== '' ? self::unreachedRow($m) : self::runRow($m, $builderOf);
        }
        ksort($rows);
        $fails = $decl['fails'];
        $counts = array_fill_keys(self::CLASSES, 0);
        foreach ($rows as $r) {
            $counts[$r['cls']]++;
        }
        $called = count(array_filter($rows, static fn (array $r): bool => $r['recv'] !== 'none'));
        $out = [sprintf(
            '선언 집합 %d 메서드(부른 것 %d + 걷기가 안 닿아 수신자 없는 것 %d) — 경로의 %s 는 생략, {U} 는 보편 인자(서명된 JWS)',
            count($rows),
            $called,
            count($rows) - $called,
            self::BASE,
        )];
        foreach ($rows as $r) {
            $out[] = sprintf('%-52s → %-13s · %s  [수신자 %s · %s]%s', $r['label'], $r['cls'], $r['reqs'], $r['recv'], $r['outcome'], $r['note']);
        }
        $classLine = '계급별: ' . implode(' · ', array_map(static fn (string $c): string => "$c {$counts[$c]}", self::CLASSES));
        $out[] = $classLine;
        $out[] = $decl['inheritedLine'];

        // (1) UNDETERMINED 없음 — 면제는 이유와 함께, 낡은 면제는 실패.
        foreach ($rows as $r) {
            if ($r['cls'] === self::UNDETERMINED && !array_key_exists($r['label'], self::UNDETERMINED_EXEMPT)) {
                $fails[] = "{$r['label']}: 분류하지 못했다(UNDETERMINED) — 인자 합성·수신자를 고치거나 이유와 함께 면제하라{$r['note']}";
            }
        }
        foreach (self::UNDETERMINED_EXEMPT as $label => $reason) {
            if (($rows[$label]['cls'] ?? null) !== self::UNDETERMINED) {
                $fails[] = "UNDETERMINED_EXEMPT[$label]: 낡은 면제다 — 선언 집합에 없거나 더는 UNDETERMINED 가 아니다($reason)";
            }
        }
        // (2) 세 교환 계급이 각각 비지 않는다 — 비면 분류기·가짜 IdP·인자 합성 중 하나가 공허해진 것이다.
        foreach ([self::CODE_EXCHANGE, self::TOKEN_GRANT, self::JWKS_FETCH] as $c) {
            if ($counts[$c] === 0) {
                $fails[] = "$c 계급이 비었다 — 교환 경로를 하나도 못 찾았다";
            }
        }

        // W3 — 대상은 전부 파생이다: (a) 계급 · (b) 계급 ∩ 서명 · (c) 분류 실행이 보낸 요청.
        $tgt = ['a' => [], 'b' => [], 'c' => []];
        $nonce = [];
        foreach ($rows as $label => $r) {
            if ($r['recv'] === 'none') {
                continue;
            }
            if ($r['cls'] === self::TOKEN_GRANT || $r['cls'] === self::CODE_EXCHANGE) {
                $tgt['a'][] = $label;
            }
            $nonce[$label] = self::nonceParams($r['class'], $r['method']);
            if ($r['cls'] === self::CODE_EXCHANGE) {
                if ($nonce[$label] !== []) {
                    $tgt['b'][] = $label;
                } elseif (array_key_exists($label, self::nonceDropExempt())) {
                    $out[] = "(b) nonce 파라미터가 없어 빠진 CODE_EXCHANGE 행: $label — " . self::nonceDropExempt()[$label];
                } else {
                    $fails[] = "W3b $label: CODE_EXCHANGE 인데 이름에 nonce 가 든 파라미터가 없어 W3b 가 붙지 않는다 — "
                        . 'nonce 를 그 이름으로 받게 하거나, 정말 nonce 없는 흐름이면 이유와 함께 NONCE_DROP_EXEMPT 에 적어라';
                }
            }
            if (self::tally($r['sent'], self::isCertsGet(...)) > 0) {
                $tgt['c'][] = $label;
            }
        }
        foreach (self::nonceDropExempt() as $label => $reason) {
            if (($rows[$label]['cls'] ?? null) !== self::CODE_EXCHANGE || ($nonce[$label] ?? []) !== []) {
                $fails[] = "NONCE_DROP_EXEMPT[$label]: 낡은 면제다 — nonce 파라미터 없는 CODE_EXCHANGE 행이 아니다($reason)";
            }
        }
        $cells = [];
        $skipped = self::loadVariants();
        $out[] = sprintf('(a) 토큰응답 형식 변형 %d(측정만 %d) — 기존 테스트에서 파생 · 뺀 것: %s', count(self::$variants), count(array_filter(self::$variants, static fn (array $v): bool => $v['measure'])), implode(', ', $skipped));
        foreach ($tgt['a'] as $label) {
            array_push($cells, ...self::runVariantsA($rows[$label], $builderOf, $nonce[$label]));
        }
        $out[] = '(b) nonce 대상(서명에서 파생 — 파라미터 위치): ' . implode(', ', array_map(static fn (string $l): string => $l . '[' . implode(',', $nonce[$l]) . ']', $tgt['b']));
        foreach ($tgt['b'] as $label) {
            array_push($cells, ...self::runNonceB($rows[$label], $builderOf));
        }
        $out[] = '(c) 콜드 캐시 JWKS 대상(분류 실행이 /certs 를 조회한 행): ' . implode(', ', $tgt['c']);
        foreach ($tgt['c'] as $label) {
            $cells[] = self::runColdC($rows[$label], $builderOf);
            if ($rows[$label]['cls'] !== self::CODE_EXCHANGE) {
                $cells[] = self::runForgedC($rows[$label], $builderOf);
            }
        }
        $judged = self::judge($cells);
        array_push($out, ...$judged['table']);
        array_push($fails, ...$judged['fails']);

        // W1 — 손 목록 포함.
        $hand = self::checkHand($rows, $tgt);
        $out[] = $hand['line'];
        array_push($fails, ...$hand['fails']);
        foreach (self::warned() as $w => $where) {
            $out[] = sprintf('PHP 경고(판정 안 함) %s — %d 칸: %s', $w, count($where), implode(', ', array_slice($where, 0, 6)) . (count($where) > 6 ? ' …' : ''));
        }

        if (getenv('HP_MATRIX_PRINT') !== false) {
            fwrite(STDERR, "\n" . implode("\n", $out) . "\n" . implode("\n", $judged['summary']) . "\n");
        }
        self::assertGreaterThan(0, count($cells), 'W3 칸이 하나도 없다 — 대상 파생이 공허하다');
        // 요약은 실패 줄 **뒤에** 둔다 — 변이 프로브는 출력 꼬리만 보여 준다.
        if ($fails !== []) {
            self::fail(implode("\n", $fails) . "\n" . $classLine . "\n" . implode("\n", $judged['summary']));
        }
    }

    /** @return array<string, list<string>> 경고 => 그것을 낸 칸·행(`noteWarnings` 가 채운다) */
    private static function warned(): array
    {
        return self::$warned;
    }

    /** @return array<string, string> 비어 있어도 표다 — 상수의 리터럴 타입(`array{}`)으로 읽으면 조회가 「항상 거짓」이 된다. */
    private static function nonceDropExempt(): array
    {
        return self::NONCE_DROP_EXEMPT;
    }

    /** @return array<string, string> 칸 => `등록부 id: 이유` — `KNOWN_GAP_GROUPS` 를 행 × 변형으로 펼친 것. */
    private static function knownGaps(): array
    {
        $out = [];
        foreach (self::KNOWN_GAP_GROUPS as $id => $g) {
            foreach ($g['rows'] as $row) {
                foreach ($g['variants'] as $v) {
                    $out["W3{$g['axis']} $row/$v"] = "$id: {$g['reason']}";
                }
            }
        }

        return $out;
    }

    // ---- 기록하는 가짜 IdP ----

    private static function startIdp(): void
    {
        [self::$priv, $jwk] = self::rsaKey('k1');
        self::$jwk = $jwk;
        [self::$otherPriv] = self::rsaKey('k1');
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($sock, "빈 포트를 못 얻었다: $errstr");
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, (int) strrpos($name, ':') + 1);
        self::$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'hp-idp-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir(self::$dir));
        $iss = self::iss();
        // 문자열 인자 자리에 들어갈 보편 인자 — ⚠️ 평문이면 토큰을 받는 메서드(validate 둘·getKeyByKid)가 요청 없이 실패해
        // JWKS_FETCH 가 빈다(Go 판 실측). 그래서 이 IdP 키로 서명한 **유효한 JWS** 다. URL·폼에 안전한 문자만 쓴다.
        self::$universal = self::sign(self::$priv, 'k1', ['iss' => $iss, 'sub' => 'u1', 'aud' => 'c', 'exp' => time() + 300, 'iat' => time()]);
        self::$idToken = self::sign(self::$priv, 'k1', ['iss' => $iss, 'sub' => 'u1', 'aud' => 'c', 'exp' => time() + 300, 'iat' => time(), 'nonce' => self::$universal]);
        // fschmtt 는 access_token·refresh_token 을 **JWT 로 파싱**한다 — 평문이면 admin 이 요청 앞에서 실패한다. exp 를 짧게
        // 주어(30초 여유 안) fschmtt 의 토큰 캐시가 부여 경로를 가리지 않게 한다(expires_in 1 과 같은 이유).
        self::$access = self::sign(self::$priv, 'k1', ['iss' => $iss, 'sub' => 'svc', 'aud' => 'c', 'exp' => time() + 1, 'iat' => time()]);
        self::$refresh = self::sign(self::$priv, 'k1', ['iss' => $iss, 'sub' => 'svc', 'aud' => $iss, 'exp' => time() + 300, 'iat' => time(), 'typ' => 'Refresh']);
        self::resetIdp();
        $env = getenv();
        $env['HP_IDP_STATE'] = self::$dir;
        $pipes = [];
        $proc = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . self::$port, __DIR__ . '/Fixtures/hostile-idp-router.php'],
            [0 => ['pipe', 'r'], 1 => ['file', self::$dir . '/server.out', 'a'], 2 => ['file', self::$dir . '/server.err', 'a']],
            $pipes,
            self::$dir,
            $env,
        );
        self::assertIsResource($proc, '가짜 IdP 프로세스를 못 띄웠다');
        self::$proc = $proc;
        // ⚠️ 치명 오류·exit 는 finally 를 건너뛴다 — 그러면 `php -S` 가 고아로 남아 포트를 쥔다(실측: 변이 실행 뒤 하나가 남았다).
        // 종료 함수는 치명 오류 뒤에도 돈다. stopIdp 는 두 번 불려도 안전하다.
        register_shutdown_function(static function (): void {
            self::stopIdp();
        });
        // 준비 대기 — 단언이 아니라 기동 대기다(시간은 판정에 쓰지 않는다).
        for ($i = 0; $i < 500; $i++) {
            $c = @fsockopen('127.0.0.1', self::$port, $en, $es, 0.2);
            if ($c !== false) {
                fclose($c);

                return;
            }
            usleep(20000);
        }
        self::fail('가짜 IdP 가 뜨지 않았다: ' . (string) @file_get_contents(self::$dir . '/server.err'));
    }

    private static function stopIdp(): void
    {
        if (self::$proc !== null) {
            proc_terminate(self::$proc);
            proc_close(self::$proc);
            self::$proc = null;
        }
        foreach (['state.json', 'requests.log', 'server.out', 'server.err'] as $f) {
            @unlink(self::$dir . '/' . $f);
        }
        @rmdir(self::$dir);
    }

    private static function iss(): string
    {
        return 'http://127.0.0.1:' . self::$port . '/realms/r';
    }

    private static function cfg(): KeycloakConfig
    {
        return new KeycloakConfig('http://127.0.0.1:' . self::$port, 'r', 'c', self::SECRET);
    }

    /** @return array{0:string, 1:array<string,string>} */
    private static function rsaKey(string $kid): array
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        self::assertTrue(openssl_pkey_export($res, $priv));
        self::assertIsString($priv);
        $details = openssl_pkey_get_details($res);
        self::assertIsArray($details);
        $rsa = $details['rsa'];
        self::assertIsArray($rsa);
        self::assertIsString($rsa['n']);
        self::assertIsString($rsa['e']);
        $b64 = static fn (string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return [$priv, ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])]];
    }

    /** @param array<string, mixed> $claims */
    private static function sign(string $priv, string $kid, array $claims): string
    {
        return FbJwt::encode($claims, $priv, 'RS256', $kid);
    }

    /** 칸마다 상태를 비운다 — 정상 토큰 응답·살아 있는 JWKS·빈 기록. */
    private static function resetIdp(): void
    {
        self::writeState(null, false);
        file_put_contents(self::$dir . '/requests.log', '');
    }

    /** @param array{status:int,type:string,body:string}|null $tokenOverride */
    private static function writeState(?array $tokenOverride, bool $certsDown): void
    {
        file_put_contents(self::$dir . '/state.json', json_encode([
            // expires_in 을 기본 skew(30s) 보다 짧게 준다 — provider 캐시가 늘 식어 있어, 부여에 닿을 수 있는 메서드는 실제로 닿는다.
            'tokenDefault' => json_encode([
                'access_token' => self::$access, 'token_type' => 'Bearer', 'expires_in' => 1,
                'refresh_token' => self::$refresh, 'id_token' => self::$idToken, 'scope' => 'openid',
            ], JSON_THROW_ON_ERROR),
            'tokenOverride' => $tokenOverride,
            'certsDown' => $certsDown,
            'jwks' => json_encode(['keys' => [self::$jwk]], JSON_THROW_ON_ERROR),
        ], JSON_THROW_ON_ERROR));
    }

    private static function clearLog(): void
    {
        file_put_contents(self::$dir . '/requests.log', '');
    }

    /** @return list<array{0:string,1:string,2:string}> [메서드, 경로, grant_type] */
    private static function snapshot(): array
    {
        $out = [];
        foreach (explode("\n", (string) file_get_contents(self::$dir . '/requests.log')) as $line) {
            if ($line === '') {
                continue;
            }
            $r = json_decode($line, true);
            self::assertIsArray($r);
            self::assertTrue(isset($r[0], $r[1], $r[2]) && is_string($r[0]) && is_string($r[1]) && is_string($r[2]), "기록 줄이 깨졌다: $line");
            $out[] = [$r[0], $r[1], $r[2]];
        }

        return $out;
    }

    // ---- 선언 집합 ----

    /** @return array{0:string, 1:\Closure(KeycloakConfig): array<string, object>} */
    private static function builder(int $i): array
    {
        return self::builders()[$i];
    }

    /**
     * 수신자를 얻는 공개 API 뿌리 — **덜 데운 것부터**. 타입은 자기를 처음 닿게 하는 빌더의 새 인스턴스에서 불린다.
     * 어느 빌더에도 안 닿는 타입(값 타입·오류 타입)은 생성자를 합성 인자로 불러 만든 수신자다(Go 의 영값 수신자).
     *
     * @return list<array{0:string, 1:\Closure(KeycloakConfig): array<string, object>}>
     */
    private static function builders(): array
    {
        return [
            ['create', static fn (KeycloakConfig $cfg): array => ['kc' => KeycloakClient::create($cfg)]],
            ['create+admin', static function (KeycloakConfig $cfg): array {
                $kc = KeycloakClient::create($cfg);
                $admin = $kc->admin();

                return ['kc' => $kc, 'admin' => $admin, 'users' => $admin->users(), 'clients' => $admin->clients(),
                    'realms' => $admin->realms(), 'roles' => $admin->roles(), 'groups' => $admin->groups()];
            }],
            ['provider', static fn (KeycloakConfig $cfg): array => ['provider' => new ClientCredentialsTokenProvider(
                $cfg,
                new OidcEndpoints($cfg),
                new GuzzleClient(HttpOptions::guzzle($cfg)),
                new HttpFactory(),
                new HttpFactory(),
            )]],
        ];
    }

    /**
     * `FacadeDumpTest::reach()` 로 뿌리에서 닿는 SDK 객체(클래스마다 처음 닿은 것)와, 합성 인자에 쓸 객체 풀(SDK 객체 +
     * 그것이 직접 쥔 객체 — Guzzle·HttpFactory·fschmtt 클라이언트)을 모은다. 두 번째 걷기가 아니다(한 단계만 본다).
     *
     * @param array<string, object> $roots
     * @return array{own: array<string, object>, pool: list<object>}
     */
    private static function graph(array $roots): array
    {
        $own = [];
        $pool = [];
        FacadeDumpTest::reach($roots, 'root', new \SplObjectStorage(), static function (object $o) use (&$own, &$pool): void {
            if (!self::isOwn($o::class)) {
                return;
            }
            $own[$o::class] ??= $o;
            $pool[] = $o;
            for ($c = new \ReflectionClass($o); $c !== false; $c = $c->getParentClass()) {
                foreach ($c->getProperties() as $p) {
                    if ($p->isStatic() || $p->getDeclaringClass()->getName() !== $c->getName() || !$p->isInitialized($o)) {
                        continue;
                    }
                    $v = $p->getValue($o);
                    if (is_object($v)) {
                        $pool[] = $v;
                    }
                }
            }
        });

        return ['own' => $own, 'pool' => $pool];
    }

    /** @return array<string, int> 클래스 => 처음 닿게 하는 빌더 번호. */
    private static function probeBuilders(): array
    {
        $of = [];
        foreach (self::builders() as $i => [, $build]) {
            foreach (array_keys(self::graph($build(self::cfg()))['own']) as $class) {
                $of[$class] ??= $i;
            }
        }

        return $of;
    }

    private static function short(string $class): string
    {
        return str_starts_with($class, self::NS) ? substr($class, strlen(self::NS)) : $class;
    }

    /**
     * SDK 의 것인가 — ⚠️ 테스트 네임스페이스는 뺀다. `FacadeDumpTest::roots()` 의 실패 뿌리는 트레이스 인자에 러너 프레임의
     * 테스트 객체를 싣고, 걷기는 접두만 보므로 그 객체(와 PHPUnit 의 공개 표면)가 선언 집합에 들어왔다(실측).
     */
    private static function isOwn(string $class): bool
    {
        return str_starts_with($class, self::NS) && !str_starts_with($class, self::NS . 'Tests\\');
    }

    /**
     * `php/src` 의 선언 전수(클래스·인터페이스·트레이트·열거형, 파일당 여럿이어도) — 손 목록이 아니라 트리에서 얻는다.
     *
     * @return list<\ReflectionClass<object>>
     */
    private static function sourceTypes(): array
    {
        $src = (string) realpath(\dirname(__DIR__, 2) . '/src');
        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src)) as $file) {
            if ($file->getExtension() === 'php') {
                require_once $file->getPathname();
            }
        }
        $out = [];
        foreach ([...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()] as $name) {
            $rc = new \ReflectionClass($name);
            $f = $rc->getFileName();
            if ($f !== false && str_starts_with((string) realpath($f), $src)) {
                $out[] = $rc;
            }
        }
        usort($out, static fn (\ReflectionClass $a, \ReflectionClass $b): int => strcmp($a->getName(), $b->getName()));

        return $out;
    }

    /**
     * 선언 집합. 행: `FacadeDumpTest` 의 뿌리·걷기가 닿는 SDK 클래스마다 공개 메서드(SDK 가 선언한 것) ∪ 소스에 선언된
     * 공개 메서드 전수. 걷기가 안 닿는 클래스의 **인스턴스** 메서드는 수신자가 없어 UNDETERMINED 로 남는다.
     *
     * @return array{rows: list<array{label:string, class:class-string, method:string, unreached:string}>, fails: list<string>, inheritedLine:string}
     */
    private static function declared(): array
    {
        $reached = [];
        FacadeDumpTest::reach(FacadeDumpTest::roots(), 'root', new \SplObjectStorage(), static function (object $o) use (&$reached): void {
            if (self::isOwn($o::class)) {
                $reached[$o::class] = true;
            }
        });
        ksort($reached);
        $rows = [];
        foreach (array_keys($reached) as $class) {
            $rc = new \ReflectionClass($class);
            foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                if (self::isOwn($m->getDeclaringClass()->getName())) {
                    $label = self::short($class) . '::' . $m->getName();
                    $rows[$label] = ['label' => $label, 'class' => $class, 'method' => $m->getName(), 'unreached' => self::dynamicWhy($m)];
                }
            }
        }
        $sources = self::sourceTypes();
        [$fails, $inheritedLine] = self::checkInherited($sources);
        $walked = count($rows);
        foreach ($sources as $rc) {
            foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                if ($m->getDeclaringClass()->getName() !== $rc->getName()) {
                    continue;
                }
                $label = self::short($rc->getName()) . '::' . $m->getName();
                if (isset($rows[$label])) {
                    continue;
                }
                if ($rc->isInterface() || $rc->isTrait()) {
                    // 인터페이스·트레이트 메서드는 그것을 구현·사용하는 클래스의 행이 잰다 — 그런 행이 없으면 UNDETERMINED 다.
                    $covered = array_filter($rows, static fn (array $r): bool => $r['method'] === $m->getName()
                        && ($rc->isInterface() ? is_subclass_of($r['class'], $rc->getName()) : in_array($rc->getName(), self::traitsOf($r['class']), true)));
                    if ($covered !== []) {
                        continue;
                    }
                    $rows[$label] = ['label' => $label, 'class' => $rc->getName(), 'method' => $m->getName(),
                        'unreached' => ($rc->isInterface() ? '인터페이스' : '트레이트') . '를 구현·사용하는 행이 없다'];
                    continue;
                }
                $callable = $m->isStatic() || ($m->isConstructor() && $rc->isInstantiable());
                $rows[$label] = ['label' => $label, 'class' => $rc->getName(), 'method' => $m->getName(),
                    'unreached' => self::dynamicWhy($m) !== '' ? self::dynamicWhy($m)
                        : ($callable ? '' : '걷기가 닿지 않는 클래스라 수신자가 없다(FacadeDumpTest 의 뿌리에 닿게 하거나 이유와 함께 면제하라)')];
            }
        }
        ksort($rows);

        return ['rows' => array_values($rows), 'fails' => $fails,
            'inheritedLine' => $inheritedLine . sprintf(' — 걷기로 얻은 행 %d · 소스에서 더한 행 %d', $walked, count($rows) - $walked)];
    }

    /**
     * 이름을 파생할 수 없는 동적 표면(`__call`·`__callStatic`·`__get`) — 아무 이름으로나 교환·내부 객체를 내줄 수 있어
     * 합성 인자 한 번으로는 가를 수 없다. 그래서 행이 아니라 UNDETERMINED 로 두고 이유 있는 면제를 요구한다(Grok 레그 지목, 실측
     * SILENT → 이 규칙).
     */
    private static function dynamicWhy(\ReflectionMethod $m): string
    {
        return in_array(strtolower($m->getName()), ['__call', '__callstatic', '__get'], true)
            ? '동적 표면 — 이름을 파생할 수 없다(아무 이름으로나 교환·내부 객체를 내줄 수 있다). 없애거나 이유와 함께 면제하라' : '';
    }

    /**
     * 제3자 부모에게서 물려받은 공개 표면 — 걷기가 닿든 안 닿든 `php/src` 의 **클래스마다** 잰다. 면제는 SDK 클래스별이다
     * (부모별로 두면 그 부모를 물려받는 새 SDK 클래스가 조용히 빠진다 — Grok 레그 지목, 실측 SILENT). 예외 클래스가 `\Exception`
     * 의 접근자를 물려받는 것만 규칙으로 뺀다. 그리고 면제의 이유 「내보내지 않는다」를 잰다 — 공개 메서드의 반환 타입·공개
     * 프로퍼티 타입이 그 클래스를 담을 수 있으면 실패한다(`provider()` 같은 접근자가 생기면 league 표면이 그대로 소비자 손에 간다).
     *
     * @param list<\ReflectionClass<object>> $sources
     * @return array{0: list<string>, 1: string}
     */
    private static function checkInherited(array $sources): array
    {
        $fails = [];
        $seen = [];
        $ruled = 0;
        foreach ($sources as $rc) {
            if ($rc->isInterface() || $rc->isTrait()) {
                continue;
            }
            $own = self::short($rc->getName());
            foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                $declaring = $m->getDeclaringClass()->getName();
                if (self::isOwn($declaring)) {
                    continue;
                }
                if ($declaring === \Exception::class && $rc->isSubclassOf(\Throwable::class)) {
                    $ruled++;
                    continue;
                }
                $seen[$own][$declaring][] = $m->getName();
            }
        }
        foreach ($seen as $own => $byParent) {
            foreach ($byParent as $declaring => $methods) {
                if (!in_array($declaring, self::INHERITED_EXEMPT[$own][0] ?? [], true)) {
                    $fails[] = "선언 집합: $own 이 제3자 $declaring 의 공개 메서드 " . count($methods) . '개(' . implode(', ', array_slice($methods, 0, 4))
                        . ' …)를 물려받는다 — 행으로 부를 수 있게 하거나, SDK 클래스별로 이유와 함께 INHERITED_EXEMPT 에 적어라';
                }
            }
        }
        foreach (self::INHERITED_EXEMPT as $own => [$parents, $reason]) {
            foreach ($parents as $p) {
                if (!isset($seen[$own][$p])) {
                    $fails[] = "INHERITED_EXEMPT[$own]: 낡은 면제다 — $p 의 공개 메서드를 더는 물려받지 않는다($reason)";
                }
            }
            $fqcn = self::NS . $own;
            foreach ($sources as $rc) {
                foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                    if (self::isOwn($m->getDeclaringClass()->getName()) && self::typeCanHold($m->getReturnType(), $fqcn)) {
                        $fails[] = "INHERITED_EXEMPT[$own]: 이유(「내보내지 않는다」)가 거짓이다 — " . self::short($rc->getName()) . "::{$m->getName()} 가 그 타입을 반환한다";
                    }
                }
                foreach ($rc->getProperties(\ReflectionProperty::IS_PUBLIC) as $p) {
                    if (self::typeCanHold($p->getType(), $fqcn)) {
                        $fails[] = "INHERITED_EXEMPT[$own]: 이유(「내보내지 않는다」)가 거짓이다 — 공개 프로퍼티 " . self::short($rc->getName()) . "::\${$p->getName()}";
                    }
                }
            }
        }
        $line = '물려받은 제3자 표면(행 아님): ' . implode(' · ', array_map(
            static fn (string $o, array $ps): string => $o . ' ← ' . implode('·', array_map(self::short(...), array_keys($ps))),
            array_keys($seen),
            $seen,
        )) . " · 예외의 \\Exception 접근자 $ruled(규칙)";

        return [$fails, $line];
    }

    /** 이 타입 선언이 `$fqcn` 인스턴스를 담을 수 있는가 — 이름 있는 클래스·인터페이스 타입만 본다(mixed·object 는 못 가른다). */
    private static function typeCanHold(?\ReflectionType $t, string $fqcn): bool
    {
        $named = match (true) {
            $t instanceof \ReflectionNamedType => [$t],
            $t instanceof \ReflectionUnionType, $t instanceof \ReflectionIntersectionType => $t->getTypes(),
            default => [],
        };
        foreach ($named as $n) {
            if ($n instanceof \ReflectionNamedType && !$n->isBuiltin() && is_a($fqcn, $n->getName(), true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param class-string $class
     * @return list<string>
     */
    private static function traitsOf(string $class): array
    {
        $out = [];
        for ($c = new \ReflectionClass($class); $c !== false; $c = $c->getParentClass()) {
            array_push($out, ...$c->getTraitNames());
        }

        return $out;
    }

    // ---- 인자 합성 · 호출 ----

    private static function acceptsString(?\ReflectionType $t): bool
    {
        if ($t === null) {
            return true;
        }
        if ($t instanceof \ReflectionNamedType) {
            return in_array($t->getName(), ['string', 'mixed'], true);
        }
        if ($t instanceof \ReflectionUnionType) {
            foreach ($t->getTypes() as $u) {
                if (self::acceptsString($u)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 호출하는 메서드의 인자. 문자열을 받는 자리는 **선택 인자여도** 보편 인자다(nonce·redirect_uri 가 그 자리다) — 그 밖의
     * 선택 인자는 기본값, 필수 인자는 타입으로 합성한다. `$blank` 의 위치는 기본값(없으면 null)이다 — W3a 가 nonce 를 비운다.
     * `$flip` 이면 bool 자리는 기본값이어도 true 다(`flipRows`) · `$str` 은 문자열 자리의 보편 인자를 바꾼다(W3c 위조 토큰).
     *
     * @param list<object> $pool
     * @param list<int> $blank
     * @return list<mixed>
     */
    private static function args(\ReflectionFunctionAbstract $f, array $pool, array $blank = [], bool $flip = false, ?string $str = null): array
    {
        $out = [];
        foreach ($f->getParameters() as $i => $p) {
            if (in_array($i, $blank, true)) {
                $out[] = $p->isDefaultValueAvailable() ? $p->getDefaultValue() : null;
            } elseif (self::acceptsString($p->getType())) {
                $out[] = $str ?? self::$universal;
            } elseif ($flip && self::isBoolType($p->getType())) {
                $out[] = true;
            } elseif ($p->isDefaultValueAvailable()) {
                $out[] = $p->getDefaultValue();
            } else {
                $out[] = self::value($p->getType(), $pool, 0);
            }
        }

        return $out;
    }

    private static function isBoolType(?\ReflectionType $t): bool
    {
        $named = $t instanceof \ReflectionUnionType ? $t->getTypes() : [$t];
        foreach ($named as $n) {
            if ($n instanceof \ReflectionNamedType && in_array($n->getName(), ['bool', 'true', 'false'], true)) {
                return true;
            }
        }

        return false;
    }

    /** @param list<object> $pool */
    private static function value(?\ReflectionType $t, array $pool, int $depth): mixed
    {
        if ($t instanceof \ReflectionUnionType) {
            $last = null;
            foreach ($t->getTypes() as $u) {
                try {
                    return self::value($u, $pool, $depth);
                } catch (\LogicException $e) {
                    $last = $e;
                }
            }
            throw $last ?? new \LogicException('빈 유니언 타입');
        }
        if (!$t instanceof \ReflectionNamedType) {
            return self::$universal;
        }
        $n = $t->getName();

        return match ($n) {
            'string', 'mixed' => self::$universal,
            'int' => 1,
            'float' => 1.0,
            'bool', 'false' => false,
            'true' => true,
            'array', 'iterable' => [],
            'null' => null,
            'callable', \Closure::class => static fn (mixed ...$a): mixed => null,
            'object' => new \stdClass(),
            default => self::object($n, $pool, $depth),
        };
    }

    /** @param list<object> $pool */
    private static function object(string $class, array $pool, int $depth): object
    {
        foreach ($pool as $o) {
            if ($o instanceof $class) {
                return $o;
            }
        }
        if (!class_exists($class) && !interface_exists($class)) {
            throw new \LogicException("모르는 타입 $class");
        }
        $rc = new \ReflectionClass($class);
        if (!$rc->isInstantiable()) {
            if (is_a(\RuntimeException::class, $class, true)) {
                return new \RuntimeException('hp-synth');
            }
            throw new \LogicException("만들 수 없는 타입 $class(풀에도 없다)");
        }
        if ($depth > 3) {
            throw new \LogicException("합성이 너무 깊다: $class");
        }
        $ctor = $rc->getConstructor();
        if ($ctor === null) {
            return $rc->newInstance();
        }
        $args = [];
        foreach ($ctor->getParameters() as $p) {
            $args[] = $p->isDefaultValueAvailable() ? $p->getDefaultValue() : self::value($p->getType(), $pool, $depth + 1);
        }

        return $rc->newInstanceArgs($args);
    }

    /**
     * 이 IdP 위에 새로 만든 뿌리에서 수신자를 꺼낸다(행의 클래스를 처음 닿게 하는 빌더). 빌더가 안 닿는 클래스는 생성자를 합성
     * 인자로 불러 만든다. 정적 메서드·생성자는 수신자가 없다.
     *
     * @param array{class:class-string, method:string} $row
     * @param array<string, int> $builderOf
     * @return array{recv: ?object, src: string, pool: list<object>}
     */
    private static function receiver(array $row, array $builderOf): array
    {
        $i = $builderOf[$row['class']] ?? null;
        [$name, $build] = self::builder($i ?? 0);
        $g = self::graph($build(self::cfg()));
        $m = new \ReflectionMethod($row['class'], $row['method']);
        if ($m->isStatic() || $m->isConstructor()) {
            return ['recv' => null, 'src' => $m->isStatic() ? 'static' : 'new', 'pool' => $g['pool']];
        }
        if ($i !== null) {
            if (!isset($g['own'][$row['class']])) {
                throw new \LogicException("빌더 $name 가 탐침 때는 닿았는데 지금은 안 닿는다");
            }

            return ['recv' => $g['own'][$row['class']], 'src' => $name, 'pool' => $g['pool']];
        }

        return ['recv' => self::object($row['class'], $g['pool'], 0), 'src' => 'constructed', 'pool' => $g['pool']];
    }

    /**
     * ⚠️ 이 프레임의 인자는 예외 트레이스에 실린다 — 변형 본문·카나리아는 여기로 오지 않는다(수신자·이름·합성 인자뿐).
     * 호출 중 PHP 경고·알림은 PHPUnit 으로 넘기지 않고 `$lastWarnings` 에 모은다 — 판정하지 않고 표에 찍는다(fschmtt 는
     * access_token 없는 응답에 「Undefined array key」 경고를 낸다 — 실측).
     *
     * @param class-string $class
     * @param list<mixed> $args
     */
    private static function invoke(?object $recv, string $class, string $method, array $args): ?\Throwable
    {
        $warnings = [];
        set_error_handler(static function (int $no, string $msg, string $file, int $line) use (&$warnings): bool {
            $warnings[] = basename($file) . ':' . $line . ' ' . $msg;

            return true;
        });
        $err = null;
        try {
            if ($method === '__construct') {
                (new \ReflectionClass($class))->newInstanceArgs($args);
            } else {
                $m = new \ReflectionMethod($class, $method);
                $m->invokeArgs($m->isStatic() ? null : $recv, $args);
            }
        } catch (\Throwable $e) {
            $err = $e;
        } finally {
            restore_error_handler();
        }
        self::$lastWarnings = $warnings;

        return $err;
    }

    /** 마지막 호출의 PHP 경고를 어디서 났는지와 함께 모은다 — 판정하지 않는다. */
    private static function noteWarnings(string $where): int
    {
        foreach (self::$lastWarnings as $w) {
            self::$warned[$w][] = $where;
        }

        return count(self::$lastWarnings);
    }

    /**
     * 요청으로 가른다. 앞 줄이 이긴다: 코드 교환 > 토큰 부여 > JWKS 조회 > 그 밖의 요청 > 요청 없음.
     * ⚠️ 토큰 엔드포인트 POST 는 grant_type 이 무엇이든 TOKEN_GRANT 다 — 새 grant 가 OTHER 로 새지 않게.
     *
     * @param list<array{0:string,1:string,2:string}> $reqs
     */
    private static function classify(array $reqs, bool $failed): string
    {
        foreach ($reqs as $r) {
            if (self::isTokenPost($r) && $r[2] === 'authorization_code') {
                return self::CODE_EXCHANGE;
            }
        }
        if (self::tally($reqs, self::isTokenPost(...)) > 0) {
            return self::TOKEN_GRANT;
        }
        if (self::tally($reqs, self::isCertsGet(...)) > 0) {
            return self::JWKS_FETCH;
        }
        if ($reqs !== []) {
            return self::OTHER;
        }

        return $failed ? self::UNDETERMINED : self::NONE;
    }

    /** @param array{0:string,1:string,2:string} $r */
    private static function isTokenPost(array $r): bool
    {
        return $r[0] === 'POST' && str_ends_with($r[1], self::TOKEN_SUFFIX);
    }

    /** @param array{0:string,1:string,2:string} $r */
    private static function isCertsGet(array $r): bool
    {
        return $r[0] === 'GET' && str_ends_with($r[1], self::CERTS_SUFFIX);
    }

    /**
     * @param list<array{0:string,1:string,2:string}> $reqs
     * @param callable(array{0:string,1:string,2:string}): bool $pred
     */
    private static function tally(array $reqs, callable $pred): int
    {
        return count(array_filter($reqs, $pred));
    }

    /** @param list<array{0:string,1:string,2:string}> $reqs */
    private static function format(array $reqs): string
    {
        if ($reqs === []) {
            return '-';
        }
        $n = [];
        foreach ($reqs as [$method, $path, $grant]) {
            $p = str_replace(self::$universal, '{U}', str_starts_with($path, self::BASE) ? substr($path, strlen(self::BASE)) : $path);
            $k = $method . ' ' . $p . ($grant !== '' ? "[$grant]" : '');
            $n[$k] = ($n[$k] ?? 0) + 1;
        }

        return implode(', ', array_map(static fn (string $k, int $c): string => $c > 1 ? "$k ×$c" : $k, array_keys($n), $n));
    }

    private static function outcome(?\Throwable $e): string
    {
        return match (true) {
            $e === null => 'ok',
            $e instanceof \Error => 'crash ' . self::short($e::class),
            default => 'err ' . self::short($e::class),
        };
    }

    /**
     * @param array{label:string, class:class-string, method:string, unreached:string} $row
     * @param array<string, int> $builderOf
     * @return array{label:string, class:class-string, method:string, cls:string, reqs:string, recv:string, outcome:string, note:string, sent:list<array{0:string,1:string,2:string}>}
     */
    private static function runRow(array $row, array $builderOf): array
    {
        $first = self::runRowOnce($row, $builderOf, false);
        $m = new \ReflectionMethod($row['class'], $row['method']);
        $hasBool = array_filter($m->getParameters(), static fn (\ReflectionParameter $p): bool => self::isBoolType($p->getType())) !== [];
        if ($first['sent'] !== [] || !$hasBool) {
            return $first;
        }
        // bool 자리는 기본값(false)이 요청 앞에서 갈라 세울 수 있다 — 요청이 없었으면 true 로 한 번 더 부르고, 요청을 냈으면 그쪽을
        // 행으로 삼는다(W3 칸도 같은 인자로 부른다). Grok 레그 지목(`$send = false` 로 교환을 숨긴 메서드가 NONE), 실측 SILENT → 이 규칙.
        $second = self::runRowOnce($row, $builderOf, true);
        if ($second['sent'] === []) {
            return $first;
        }
        self::$flipRows[$row['label']] = true;
        $second['recv'] .= ' · bool=true';

        return $second;
    }

    /**
     * @param array{label:string, class:class-string, method:string, unreached:string} $row
     * @param array<string, int> $builderOf
     * @return array{label:string, class:class-string, method:string, cls:string, reqs:string, recv:string, outcome:string, note:string, sent:list<array{0:string,1:string,2:string}>}
     */
    private static function runRowOnce(array $row, array $builderOf, bool $flip): array
    {
        self::resetIdp();
        $e = null;
        try {
            $r = self::receiver($row, $builderOf);
        } catch (\Throwable $x) {
            return $row + ['cls' => self::UNDETERMINED, 'reqs' => '-', 'recv' => 'none', 'outcome' => '-',
                'note' => ' · 수신자 합성 실패: ' . $x::class . ': ' . $x->getMessage(), 'sent' => []];
        }
        self::clearLog(); // 뿌리를 만들며 나간 요청은 이 메서드의 몫이 아니다
        try {
            $args = self::args(new \ReflectionMethod($row['class'], $row['method']), $r['pool'], [], $flip);
            $e = self::invoke($r['recv'], $row['class'], $row['method'], $args);
        } catch (\Throwable $x) {
            return $row + ['cls' => self::UNDETERMINED, 'reqs' => '-', 'recv' => $r['src'], 'outcome' => '-',
                'note' => ' · 인자 합성 실패: ' . $x::class . ': ' . $x->getMessage(), 'sent' => []];
        }
        $warned = self::noteWarnings($row['label'] . '/분류');
        $sent = self::snapshot();
        $cls = self::classify($sent, $e !== null);

        return $row + ['cls' => $cls, 'reqs' => self::format($sent), 'recv' => $r['src'], 'outcome' => self::outcome($e) . ($warned > 0 ? " · PHP 경고 $warned" : ''),
            // 사유는 분류를 못 한 행에만 — 요청을 낸 행의 오류(admin 404 등)는 분류와 무관하다.
            'note' => $cls === self::UNDETERMINED && $e !== null ? ' · ' . $e::class . ': ' . $e->getMessage() : '', 'sent' => $sent];
    }

    /**
     * @param array{label:string, class:class-string, method:string, unreached:string} $row
     * @return array{label:string, class:class-string, method:string, cls:string, reqs:string, recv:string, outcome:string, note:string, sent:list<array{0:string,1:string,2:string}>}
     */
    private static function unreachedRow(array $row): array
    {
        return $row + ['cls' => self::UNDETERMINED, 'reqs' => '-', 'recv' => 'none', 'outcome' => '-', 'note' => ' · ' . $row['unreached'], 'sent' => []];
    }

    /** @return list<int> 이름에 "nonce" 가 든(대소문자 무시) 파라미터의 위치 — **이름 목록이 아니라 서명에서** 얻는다. */
    private static function nonceParams(string $class, string $method): array
    {
        $out = [];
        foreach ((new \ReflectionMethod($class, $method))->getParameters() as $i => $p) {
            if (str_contains(strtolower($p->getName()), 'nonce')) {
                $out[] = $i;
            }
        }

        return $out;
    }

    // ---- W3: 계급별 적대 변형 ----

    /**
     * W3a 변형 — 새로 만들지 않고 기존 테스트에서 가져온다(리플렉션으로 그 표를 그대로 읽는다):
     *   - `MalformedTokenResponseTest::variants()` 중 토큰 엔드포인트 응답. 그 테스트의 `EXPECTED` 가 토큰 호출(nonce 없는
     *     것) **전부에** 실패를 단언한 것만 단언하고, 그 밖(받아들이는 계약·호출마다 갈리는 계약)은 **측정만** 한다 — 계급에
     *     새 계약을 만들지 않는다. 응답이 아닌 주입(연결·핸들러·TLS 실패)은 이 IdP 가 낼 수 없어 뺀다.
     *   - `TokenSetTest::badAccessTokens()` 의 비문자열 access_token 전부와 `testMissingAccessTokenIsRejected` 의 누락.
     *
     * ⚠️ 공허 함정(Go 판과 같다): 이 본문들엔 쓸 수 있는 id_token 이 없다. nonce 를 준 exchangeCode 는 정상 토큰 응답이어도
     * 「missing id_token」으로 실패하므로 적대 응답이 안 닿아도 통과한다 — 그래서 W3a 는 nonce 파라미터를 비운다.
     *
     * @return list<string> 뺀 것
     */
    private static function loadVariants(): array
    {
        $mt = new \ReflectionClass(MalformedTokenResponseTest::class);
        $expected = $mt->getConstant('EXPECTED');
        $accepted = $mt->getConstant('ACCEPTED');
        $all = $mt->getMethod('variants')->invoke(null);
        $calls = $mt->getMethod('calls')->invoke(null);
        self::assertIsArray($expected);
        self::assertIsArray($accepted);
        self::assertIsArray($all);
        self::assertIsArray($calls);
        self::assertIsArray($calls['token'] ?? null, 'MalformedTokenResponseTest::calls() 에 token 호출이 없다');
        $tokenCalls = array_values(array_filter(array_map('strval', array_keys($calls['token'])), static fn (string $k): bool => !str_contains($k, 'nonce')));
        self::assertNotSame([], $tokenCalls);
        self::$variants = [];
        $skipped = [];
        foreach ($all as $name => $v) {
            $name = (string) $name;
            self::assertIsArray($v);
            if (($v['ep'] ?? null) !== 'token') {
                continue;
            }
            $code = (string) strtok($name, ' ');
            if (isset($v['fail'])) {
                $skipped[] = "$code(응답이 아닌 주입)";
                continue;
            }
            $byCall = $expected[$name] ?? null;
            $verdicts = [];
            foreach ($tokenCalls as $call) {
                $verdicts[$call] = is_array($byCall) ? ($byCall[$call] ?? null) : null;
            }
            $rejectAll = !in_array($name, $accepted, true) && !in_array(null, $verdicts, true) && !in_array('ok', $verdicts, true);
            self::assertIsInt($v['status']);
            self::assertIsString($v['type']);
            self::assertIsString($v['body']);
            self::assertIsArray($v['canaries']);
            $canaries = [];
            foreach ($v['canaries'] as $cn => $pair) {
                self::assertIsArray($pair);
                self::assertIsString($pair[0]);
                self::assertIsBool($pair[1]);
                $canaries[(string) $cn] = [$pair[0], $pair[1]];
            }
            self::$variants[$code] = ['from' => "MalformedTokenResponseTest $name" . ($rejectAll ? '' : ' (전부 거부로 단언되지 않았다: ' . json_encode($verdicts) . ')'),
                'measure' => !$rejectAll, 'status' => $v['status'], 'type' => $v['type'], 'body' => $v['body'], 'canaries' => $canaries];
        }
        $rt = 'LKatRT-refresh-token-canary';
        $at = static fn (?string $json): string => '{' . ($json === null ? '' : '"access_token":' . $json . ',')
            . '"token_type":"Bearer","expires_in":300,"refresh_token":"' . $rt . '"}';
        foreach (TokenSetTest::badAccessTokens() as $case => [$bad]) {
            self::$variants['at:' . str_replace(' ', '_', $case)] = ['from' => "TokenSetTest::badAccessTokens $case", 'measure' => false,
                'status' => 200, 'type' => 'application/json', 'body' => $at(json_encode($bad, JSON_THROW_ON_ERROR)), 'canaries' => ['at.RT' => [$rt, true]]];
        }
        // 누락은 그것을 단언하는 테스트가 있을 때만 단언한다(없어지면 측정만으로 내려간다).
        self::$variants['at:missing'] = ['from' => 'TokenSetTest::testMissingAccessTokenIsRejected',
            'measure' => self::testMethodBody('Token/TokenSetTest.php', 'testMissingAccessTokenIsRejected') === null,
            'status' => 200, 'type' => 'application/json', 'body' => $at(null), 'canaries' => ['at.RT' => [$rt, true]]];

        return $skipped;
    }

    /** W3a 대조 — 변형들과 같은 모양(id_token 없음)의 쓸 수 있는 토큰 응답. */
    private static function wellFormed(): string
    {
        return json_encode(['access_token' => self::$access, 'token_type' => 'Bearer', 'expires_in' => 300,
            'refresh_token' => self::$refresh], JSON_THROW_ON_ERROR);
    }

    /**
     * 수신자를 정상 응답으로 만든 **뒤에** 토큰 응답을 바꾸고 한 번 부른다. ⚠️ 변형은 코드 이름으로만 받는다(트레이스 인자).
     *
     * @param array{label:string, class:class-string, method:string} $row
     * @param array<string, int> $builderOf
     * @param list<int> $blank
     * @return array{sent: list<array{0:string,1:string,2:string}>, err: ?\Throwable}
     */
    private static function cell(array $row, array $builderOf, array $blank, string $variant, bool $certsDown = false): array
    {
        self::resetIdp();
        $r = self::receiver($row, $builderOf);
        self::clearLog();
        self::applyVariant($variant, $certsDown);
        $args = self::args(new \ReflectionMethod($row['class'], $row['method']), $r['pool'], $blank, isset(self::$flipRows[$row['label']]));
        $err = self::invoke($r['recv'], $row['class'], $row['method'], $args);
        self::noteWarnings($row['label'] . '/' . ($variant === '' ? '기본' : $variant));

        return ['sent' => self::snapshot(), 'err' => $err];
    }

    /** `$variant` — '' 이면 IdP 기본 응답, '대조' 는 W3a 대조, 'nonce:<코드>' 는 W3b, 그 밖은 W3a 변형 코드. */
    private static function applyVariant(string $variant, bool $certsDown): void
    {
        $json = 'application/json';
        $override = match (true) {
            $variant === '' => null,
            $variant === '대조' => ['status' => 200, 'type' => $json, 'body' => self::wellFormed()],
            str_starts_with($variant, 'nonce:') => ['status' => 200, 'type' => $json, 'body' => self::nonceBody(substr($variant, 6))],
            default => ['status' => self::$variants[$variant]['status'], 'type' => self::$variants[$variant]['type'], 'body' => self::$variants[$variant]['body']],
        };
        self::writeState($override, $certsDown);
    }

    /** @return array<string, string> 찍는 길 => 출력. `(string)` 은 원인 사슬 전부의 메시지·트레이스를 담는다. */
    private static function renderings(\Throwable $e): array
    {
        ob_start();
        var_dump($e);
        $out = ['getMessage' => $e->getMessage(), '(string)' => (string) $e, 'var_dump' => (string) ob_get_clean(), 'print_r' => print_r($e, true)];
        for ($l = $e->getPrevious(), $i = 1; $l !== null; $l = $l->getPrevious(), $i++) {
            $out["cause[$i]"] = $l::class . ': ' . $l->getMessage();
        }

        return $out;
    }

    /**
     * 적대 토큰 응답 한 칸의 실패 사유 — 비면 통과. `$ctlHits` 는 같은 행의 대조가 낸 토큰 요청 수다.
     *
     * @param list<array{0:string,1:string,2:string}> $sent
     * @return list<string>
     */
    private static function hostileWhy(array $sent, ?\Throwable $err, string $variant, int $ctlHits): array
    {
        $why = [];
        if ($err instanceof \Error) {
            $why[] = '크래시: ' . $err::class . ': ' . $err->getMessage();
        } elseif ($err === null) {
            $why[] = '오류 없이 성공했다';
        } elseif (!$err instanceof KeycloakException) {
            $why[] = 'SDK 오류 타입이 아니다: ' . $err::class;
        }
        if ($err !== null) {
            foreach (self::renderings($err) as $how => $out) {
                foreach (self::$variants[$variant]['canaries'] as $name => [$value, $prefix]) {
                    if (str_contains($out, $value)) {
                        $why[] = "카나리아 $name 가 $how 에 찍혔다(FULL)";
                    } elseif ($prefix && str_contains($out, substr($value, 0, 10))) {
                        $why[] = "카나리아 $name 가 $how 에 찍혔다(PREFIX)";
                    }
                }
            }
        }
        [$hits, $after] = self::afterToken($sent);
        if ($hits === 0) {
            $why[] = '토큰 엔드포인트에 한 번도 안 닿았다 — 변형이 공허하다';
        }
        // 하한만 두면 틀린 응답마다 재시도하는 새 메서드가 통과한다(Go 판 Grok 레그 지목). 상한은 손 상수가 아니라 같은 행의 대조다.
        if ($hits > $ctlHits) {
            $why[] = "토큰 요청 $hits 건 — 정상 응답 대조($ctlHits 건)보다 많다: 틀린 응답이 재시도를 부른다";
        }
        if ($after !== []) {
            $why[] = '적대 토큰 응답 뒤로 나아갔다: ' . self::format($after);
        }

        return $why;
    }

    /**
     * @param list<array{0:string,1:string,2:string}> $reqs
     * @return array{0:int, 1:list<array{0:string,1:string,2:string}>} 토큰 요청 수와, 첫 토큰 요청 **뒤에** 나간 토큰 아닌 요청
     */
    private static function afterToken(array $reqs): array
    {
        $hits = 0;
        $after = [];
        foreach ($reqs as $r) {
            if (self::isTokenPost($r)) {
                $hits++;
            } elseif ($hits > 0) {
                $after[] = $r;
            }
        }

        return [$hits, $after];
    }

    /**
     * @param array{label:string, class:class-string, method:string} $row
     * @param array<string, int> $builderOf
     * @param list<int> $nonce
     * @return list<array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}>
     */
    private static function runVariantsA(array $row, array $builderOf, array $nonce): array
    {
        // 대조 — 변형과 **같은 모양의** 정상 응답(id_token 없음). 성공하면 「오류다」가, 토큰 뒤로 나아가면(admin 자원 → 404)
        // 「뒤로 안 나아갔다」가 무게를 진다. 둘 다 아니면 행 전체가 공허하다.
        $c = self::cell($row, $builderOf, $nonce, '대조');
        [$hits, $after] = self::afterToken($c['sent']);
        $ctl = ['axis' => 'a', 'label' => $row['label'], 'variant' => '대조', 'why' => [], 'measure' => false,
            'note' => $c['err'] === null ? 'ok' : '↓' . count($after)];
        if ($c['err'] instanceof \Error) {
            $ctl['why'][] = '정상 응답에 크래시: ' . $c['err']::class . ': ' . $c['err']->getMessage();
        } elseif ($hits === 0) {
            $ctl['why'][] = '정상 응답에서 토큰 엔드포인트에 안 닿았다 — 이 행의 변형은 공허하다';
        } elseif ($c['err'] !== null && $after === []) {
            $ctl['why'][] = '정상 응답에 실패했고 토큰 뒤로 나아가지도 않았다 — 변형이 무엇을 바꿨는지 가를 수 없다: ' . $c['err']::class . ': ' . $c['err']->getMessage();
        }
        $cells = [$ctl];
        foreach (array_keys(self::$variants) as $v) {
            $x = self::cell($row, $builderOf, $nonce, $v);
            $cells[] = ['axis' => 'a', 'label' => $row['label'], 'variant' => $v, 'why' => self::hostileWhy($x['sent'], $x['err'], $v, $hits),
                'measure' => self::$variants[$v]['measure'], 'note' => $x['err'] === null ? 'ok' : self::short($x['err']::class)];
        }

        return $cells;
    }

    /**
     * W3b 변형 — 대조(맞는 id_token)와 다섯(nonce≠ · 다른 키 kid=k1 · 다른 키 kid=k2 · id_token 없음 · nonce 클레임 없음).
     * 다른 키로 서명할 때 kid 가 k1 이면 캐시된 키로 서명 검증이 실패하고, k2 면 키를 못 찾는다.
     *
     * 넷을 더 붙인다 — iss≠ · aud≠ · exp 지남 · alg=none(Grok 레그 지목: 다섯만 보면 nonce·서명만 맞추는 새 검사기가 통과한다, 실측
     * SILENT). 새 계약이 아니다 — `exchangeCode` 가 「서명·iss·aud·exp 까지 검증」을 약속하고 `JwtValidatorTest` 가 그 넷을
     * 단언한다(`from`). 그 테스트가 없어지면 측정만으로 내려간다. alg=none 은 검증기가 키를 찾기 **전에** 거부하므로 JWKS 도달을
     * 요구하지 않는다(`jwks`).
     *
     * @return array<string, array{kid:string, other:bool, set:array<string,mixed>, drop:list<string>, noIdToken:bool, alg:string, jwks:bool, want:string, from:string}>
     */
    private static function nonceVariants(): array
    {
        $jv = static fn (string $test): string => self::testMethodBody('JwtValidatorTest.php', $test) === null ? 'measure' : 'reject';

        return [
            '대조' => self::nv('ok'),
            'nonce≠' => self::nv('reject', set: ['nonce' => 'hp-other-nonce']),
            'key≠·kid=k1' => self::nv('reject', other: true),
            'key≠·kid=k2' => self::nv('reject', kid: 'k2', other: true),
            'id_token없음' => self::nv('reject', noIdToken: true, jwks: false),
            'nonce클레임없음' => self::nv('reject', drop: ['nonce']),
            'iss≠' => self::nv($jv('testRejectsWrongIssuer'), set: ['iss' => 'http://attacker.test/realms/r'], from: 'JwtValidatorTest::testRejectsWrongIssuer'),
            'aud≠' => self::nv($jv('testRejectsAudienceNotContainingClient'), set: ['aud' => 'other-client'], from: 'JwtValidatorTest::testRejectsAudienceNotContainingClient'),
            'exp지남' => self::nv($jv('testRejectsExpired'), set: ['exp' => time() - 3600], from: 'JwtValidatorTest::testRejectsExpired'),
            'alg=none' => self::nv($jv('testRejectsNoneAlg'), alg: 'none', jwks: false, from: 'JwtValidatorTest::testRejectsNoneAlg'),
        ];
    }

    /**
     * @param array<string, mixed> $set
     * @param list<string> $drop
     * @return array{kid:string, other:bool, set:array<string,mixed>, drop:list<string>, noIdToken:bool, alg:string, jwks:bool, want:string, from:string}
     */
    private static function nv(
        string $want,
        string $kid = 'k1',
        bool $other = false,
        array $set = [],
        array $drop = [],
        bool $noIdToken = false,
        string $alg = 'RS256',
        bool $jwks = true,
        string $from = '',
    ): array {
        return ['kid' => $kid, 'other' => $other, 'set' => $set, 'drop' => $drop, 'noIdToken' => $noIdToken, 'alg' => $alg,
            'jwks' => $jwks, 'want' => $want, 'from' => $from];
    }

    private static function nonceBody(string $code): string
    {
        $nv = self::nonceVariants()[$code];
        $body = ['access_token' => self::$access, 'token_type' => 'Bearer', 'expires_in' => 300, 'refresh_token' => self::$refresh];
        self::$lastIdToken = '';
        if (!$nv['noIdToken']) {
            $claims = array_diff_key(
                $nv['set'] + ['iss' => self::iss(), 'sub' => 'u1', 'aud' => 'c', 'exp' => time() + 300, 'iat' => time(), 'nonce' => self::$universal],
                array_flip($nv['drop']),
            );
            $b64 = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
            self::$lastIdToken = $nv['alg'] === 'none'
                ? $b64(json_encode(['alg' => 'none', 'kid' => 'k1', 'typ' => 'JWT'], JSON_THROW_ON_ERROR)) . '.' . $b64(json_encode($claims, JSON_THROW_ON_ERROR)) . '.'
                : self::sign($nv['other'] ? self::$otherPriv : self::$priv, $nv['kid'], $claims);
            $body['id_token'] = self::$lastIdToken;
        }

        return json_encode($body, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array{label:string, class:class-string, method:string} $row
     * nonce 파라미터는 합성 규칙대로 보편 인자다(문자열 자리) — 기본 응답의 id_token nonce 도 그것이라 대조가 통과한다.
     *
     * @param array<string, int> $builderOf
     * @return list<array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}>
     */
    private static function runNonceB(array $row, array $builderOf): array
    {
        $cells = [];
        foreach (self::nonceVariants() as $code => $nv) {
            $x = self::cell($row, $builderOf, [], 'nonce:' . $code);
            $certs = self::tally($x['sent'], self::isCertsGet(...));
            $c = ['axis' => 'b', 'label' => $row['label'], 'variant' => $code, 'why' => [], 'measure' => $nv['want'] === 'measure', 'note' => "certs $certs"];
            $err = $x['err'];
            if ($err instanceof \Error) {
                $c['why'][] = '크래시: ' . $err::class . ': ' . $err->getMessage();
            }
            if (self::tally($x['sent'], self::isTokenPost(...)) === 0) {
                $c['why'][] = '토큰 엔드포인트에 안 닿았다 — 변형이 공허하다';
            }
            // 서명된 id_token 이 있는 변형은 검증기에 닿아야 한다(콜드 캐시라 JWKS 를 조회한다) — 아니면 다른 이유로 실패한 것이다.
            if ($certs === 0 && $nv['jwks']) {
                $c['why'][] = 'JWKS 를 조회하지 않았다 — id_token 이 검증기에 닿지 않았다';
            }
            if ($nv['want'] === 'ok' && $err !== null) {
                $c['why'][] = '맞는 id_token 에 실패했다 — 아래 변형의 실패가 아무것도 증명하지 않는다: ' . $err::class . ': ' . $err->getMessage();
            } elseif ($nv['want'] !== 'ok' && $err === null) {
                $c['why'][] = '틀린 id_token 을 받아들였다';
            } elseif ($nv['want'] !== 'ok' && !$err instanceof KeycloakException) {
                $c['why'][] = 'SDK 오류 타입이 아니다: ' . ($err === null ? 'null' : $err::class);
            }
            // 거부 오류가 받은 id_token 을 원문으로 찍지 않는다 — MalformedTokenResponseTest 의 a2(위조 서명 id_token)와 같은 계약
            // (원문만 찾는다 — 앞 조각은 공개 헤더다). Grok 레그 지목: 이 축엔 누출 검사가 없었다(실측 SILENT).
            if ($err !== null && self::$lastIdToken !== '') {
                foreach (self::renderings($err) as $how => $out) {
                    if (str_contains($out, self::$lastIdToken)) {
                        $c['why'][] = "받은 id_token 원문이 $how 에 찍혔다";
                    }
                }
            }
            $cells[] = $c;
        }

        return $cells;
    }

    /**
     * 콜드 캐시 + /certs 503 에서 k 회 — 전부 실패하고 1 ≤ /certs 요청 ≤ k−1(하한은 콜드 경로 도달, 상한은 백오프). 요청 수만 잰다.
     *
     * @param array{label:string, class:class-string, method:string} $row
     * @param array<string, int> $builderOf
     * @return array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}
     */
    private static function runColdC(array $row, array $builderOf): array
    {
        self::resetIdp();
        $r = self::receiver($row, $builderOf); // 새 클라이언트 — 캐시가 비어 있다
        self::clearLog();
        self::writeState(null, true);
        $c = ['axis' => 'c', 'label' => $row['label'], 'variant' => '503×' . self::COLD_K, 'why' => [], 'measure' => false, 'note' => ''];
        $m = new \ReflectionMethod($row['class'], $row['method']);
        for ($i = 1; $i <= self::COLD_K; $i++) {
            $err = self::invoke($r['recv'], $row['class'], $row['method'], self::args($m, $r['pool'], [], isset(self::$flipRows[$row['label']])));
            self::noteWarnings($row['label'] . '/503');
            if ($err instanceof \Error) {
                $c['why'][] = "{$i}번째 호출이 크래시: " . $err::class . ': ' . $err->getMessage();
            } elseif ($err === null) {
                $c['why'][] = "{$i}번째 호출이 JWKS 503 인데 성공했다";
            } elseif (!$err instanceof KeycloakException) {
                $c['why'][] = "{$i}번째 호출의 오류가 SDK 오류 타입이 아니다: " . $err::class;
            }
        }
        $hits = self::tally(self::snapshot(), self::isCertsGet(...));
        $c['note'] = "certs $hits";
        if ($hits < 1) {
            $c['why'][] = "/certs 요청 $hits — 콜드 경로에 닿지 않았다(하한 1)";
        }
        if ($hits > self::COLD_K - 1) {
            $c['why'][] = "/certs 요청 $hits — 실패한 조회가 물러서지 않았다(상한 " . (self::COLD_K - 1) . ')';
        }

        return $c;
    }

    /**
     * JWKS 를 조회한 행(코드 교환 제외 — W3b 가 잰다)에 **위조 서명** 토큰 — 문자열 자리 전부가 다른 키(kid=k1)로 서명한 JWS 다. 거부해야
     * 하고 JWKS 에 닿아야 한다(서명 검사까지 갔다는 증명). Grok 레그 지목: 콜드 캐시 503 만 보면 백오프를 지나 서명을 안 보는 새 검증
     * 경로가 통과한다(실측 SILENT). 계약은 `JwtValidatorTest::testRejectsTamperedSignature` — 없어지면 측정만으로 내려간다.
     *
     * @param array{label:string, class:class-string, method:string} $row
     * @param array<string, int> $builderOf
     * @return array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}
     */
    private static function runForgedC(array $row, array $builderOf): array
    {
        self::resetIdp();
        $r = self::receiver($row, $builderOf);
        self::clearLog();
        $forged = self::sign(self::$otherPriv, 'k1', ['iss' => self::iss(), 'sub' => 'u1', 'aud' => 'c', 'exp' => time() + 300, 'iat' => time()]);
        $m = new \ReflectionMethod($row['class'], $row['method']);
        $err = self::invoke($r['recv'], $row['class'], $row['method'], self::args($m, $r['pool'], [], isset(self::$flipRows[$row['label']]), $forged));
        self::noteWarnings($row['label'] . '/위조서명');
        $certs = self::tally(self::snapshot(), self::isCertsGet(...));
        $c = ['axis' => 'c', 'label' => $row['label'], 'variant' => '위조서명', 'why' => [], 'note' => "certs $certs",
            'measure' => self::testMethodBody('JwtValidatorTest.php', 'testRejectsTamperedSignature') === null];
        if ($err instanceof \Error) {
            $c['why'][] = '크래시: ' . $err::class . ': ' . $err->getMessage();
        } elseif ($err === null) {
            $c['why'][] = '위조 서명 토큰을 받아들였다';
        } elseif (!$err instanceof KeycloakException) {
            $c['why'][] = 'SDK 오류 타입이 아니다: ' . $err::class;
        }
        if ($certs === 0) {
            $c['why'][] = 'JWKS 에 안 닿았다 — 서명 검사 전에 갈렸다(변형이 공허하다)';
        }

        return $c;
    }

    /**
     * 칸마다 통과·GAP·FAIL 을 정하고 판정표를 만든다.
     *
     * @param list<array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}> $cells
     * @return array{table: list<string>, fails: list<string>, summary: list<string>}
     */
    private static function judge(array $cells): array
    {
        $verdict = [];
        $fails = [];
        $observed = [];
        $measured = [];
        foreach ($cells as $c) {
            $key = "W3{$c['axis']} {$c['label']}/{$c['variant']}";
            $v = 'pass';
            if ($c['measure']) {
                $v = $c['why'] === [] ? 'm:rej' : 'm:ACC';
                $mk = "W3{$c['axis']} {$c['variant']}";
                $measured[$mk] ??= ['rej' => [], 'acc' => [], 'why' => []];
                if ($c['why'] === []) {
                    $measured[$mk]['rej'][] = $c['note'];
                } else {
                    $measured[$mk]['acc'][] = $c['label'];
                    foreach ($c['why'] as $w) {
                        // 사유는 종류만 모은다 — 찍힌 자리(렌더링)를 뺀 모양으로.
                        $measured[$mk]['why'][(string) preg_replace('/ 가 \S+ 에 찍혔다\((FULL|PREFIX)\)/', ' 누출', $w)] = true;
                    }
                }
            } elseif ($c['why'] !== []) {
                if (array_key_exists($key, self::knownGaps())) {
                    $v = 'GAP';
                    $observed[$key] = true;
                } else {
                    $v = 'FAIL';
                    $fails[] = "$key: " . implode(' · ', $c['why']);
                }
            }
            if ($c['note'] !== '' && ($c['axis'] !== 'a' || $c['variant'] === '대조')) {
                $v .= "({$c['note']})";
            }
            $verdict[$key] = $v;
        }
        $table = [];
        foreach (['a', 'b', 'c'] as $axis) {
            array_push($table, ...self::verdictTable($axis, $cells, $verdict));
        }
        foreach ($measured as $k => $m) {
            $kinds = array_values(array_unique($m['rej']));
            sort($kinds);
            $table[] = sprintf(
                '측정(단언 안 함) %s — 거부 %d · 받아들임 %d · 거부 오류 [%s] · 받아들인 행 [%s] · 사유 [%s]',
                $k,
                count($m['rej']),
                count($m['acc']),
                implode(' ', $kinds),
                self::compactLabels($m['acc']),
                implode('; ', array_keys($m['why'])),
            );
        }
        foreach (self::knownGaps() as $key => $reason) {
            if (!isset($observed[$key])) {
                $fails[] = "KNOWN_GAP_GROUPS 의 칸 $key: 더는 관측되지 않는다 — 낡은 항목을 지워라($reason)";
            }
        }
        $summary = [];
        foreach (['a', 'b', 'c'] as $axis) {
            $n = ['pass' => 0, 'GAP' => 0, 'FAIL' => 0, 'm:rej' => 0, 'm:ACC' => 0];
            $failedBy = [];
            foreach ($cells as $c) {
                if ($c['axis'] !== $axis) {
                    continue;
                }
                $v = explode('(', $verdict["W3{$c['axis']} {$c['label']}/{$c['variant']}"], 2)[0];
                $n[$v]++;
                if ($v === 'FAIL') {
                    $failedBy[$c['variant']] = ($failedBy[$c['variant']] ?? 0) + 1;
                }
            }
            $summary[] = sprintf(
                'W3%s 요약: pass %d · GAP %d · FAIL %d · 측정 %d(m:rej %d · m:ACC %d) · FAIL 열 [%s]',
                $axis,
                $n['pass'],
                $n['GAP'],
                $n['FAIL'],
                $n['m:rej'] + $n['m:ACC'],
                $n['m:rej'],
                $n['m:ACC'],
                implode(' ', array_map(static fn (string $k, int $x): string => $k . '×' . $x, array_keys($failedBy), $failedBy)),
            );
        }

        return ['table' => $table, 'fails' => $fails, 'summary' => $summary];
    }

    /**
     * `클래스::{메서드,…}` 로 묶는다(측정 줄이 행 수만큼 길어지지 않게).
     *
     * @param list<string> $labels
     */
    private static function compactLabels(array $labels): string
    {
        $by = [];
        foreach ($labels as $l) {
            $parts = explode('::', $l, 2);
            $by[$parts[0]][] = $parts[1] ?? '';
        }

        return implode(' ', array_map(static fn (string $c, array $ms): string => $c . '::{' . implode(',', $ms) . '}', array_keys($by), $by));
    }

    /**
     * 한 축의 판정표 — 행은 메서드, 열은 변형.
     *
     * @param list<array{axis:string, label:string, variant:string, why:list<string>, measure:bool, note:string}> $cells
     * @param array<string, string> $verdict
     * @return list<string>
     */
    private static function verdictTable(string $axis, array $cells, array $verdict): array
    {
        $labels = [];
        $cols = [];
        foreach ($cells as $c) {
            if ($c['axis'] === $axis) {
                $labels[$c['label']] = true;
                $cols[$c['variant']] = true;
            }
        }
        if ($labels === []) {
            return ["W3$axis 판정표: 대상 행이 없다"];
        }
        $cols = array_keys($cols);
        $width = [];
        foreach ($cols as $i => $col) {
            $width[$i] = mb_strlen($col);
            foreach (array_keys($labels) as $l) {
                $width[$i] = max($width[$i], mb_strlen($verdict["W3$axis $l/$col"] ?? ''));
            }
        }
        $out = [sprintf('W3%s 판정표 — %d행 × %d열 (pass · GAP=알려진 틈 · FAIL · m:rej/m:ACC=측정만: 거부/받아들임)', $axis, count($labels), count($cols))];
        $out[] = self::tableLine('행 \\ 변형', $cols, $width);
        foreach (array_keys($labels) as $l) {
            $out[] = self::tableLine($l, array_map(static fn (string $col): string => $verdict["W3$axis $l/$col"] ?? '', $cols), $width);
        }

        return $out;
    }

    /**
     * @param list<string> $vals
     * @param array<int, int> $width
     */
    private static function tableLine(string $first, array $vals, array $width): string
    {
        $pad = static fn (string $s, int $n): string => $s . str_repeat(' ', max(0, $n - mb_strlen($s)));
        $parts = [$pad($first, 52)];
        foreach ($vals as $i => $v) {
            $parts[] = $pad($v, $width[$i] ?? 0);
        }

        return rtrim(implode(' ', $parts));
    }

    // ---- W1: 손 목록 포함 ----

    /**
     * @param array<string, array{label:string, class:class-string, method:string, cls:string, reqs:string, recv:string, outcome:string, note:string, sent:list<array{0:string,1:string,2:string}>}> $rows
     * @param array{a:list<string>, b:list<string>, c:list<string>} $tgt
     * @return array{line:string, fails:list<string>}
     */
    private static function checkHand(array $rows, array $tgt): array
    {
        $fails = [];
        $anchors = [];
        $callsRunNames = [];
        foreach (self::HAND as [$label, $cls, $axis, $anchor, $call]) {
            $anchors[$anchor] = true;
            [$file, $fn] = explode('|', $anchor, 2);
            if ($anchor === 'MalformedTokenResponseTest.php|calls') {
                $callsRunNames[$call] = true;
            }
            $r = $rows[$label] ?? null;
            if ($r === null) {
                $fails[] = "W1 $label: 손 테스트($anchor)가 겨누는데 파생 집합에 행이 없다";
            } elseif ($r['cls'] !== $cls) {
                $fails[] = "W1 $label: 손 테스트($anchor)가 겨누는 계급은 $cls 인데 파생은 {$r['cls']} 다";
            } elseif ($axis !== 'row' && !in_array($label, $tgt[$axis], true)) {
                $fails[] = "W1 $label: 손 테스트($anchor)가 겨누는데 W3$axis 의 파생 대상에 없다";
            }
            $body = self::testMethodBody($file, $fn);
            if ($body === null) {
                $fails[] = "W1 $anchor: 앵커 메서드가 없다 — 손 테스트가 옮겨졌으면 표를 따라 고쳐라";
                continue;
            }
            if (!in_array($call, self::callsIn($body), true)) {
                $fails[] = "W1 $anchor: 앵커가 $call( 를 부르지 않는다 — 손 테스트의 대상이 바뀌었다";
            }
            if (!str_ends_with($label, '::' . $call)) {
                $row = $rows[$label] ?? null;
                if ($row === null || !in_array($call, self::callsReach($row['class'], $row['method']), true)) {
                    $fails[] = "W1 $label: 공개 입구가 $call 를 (같은 클래스의 비공개 메서드를 따라서도) 부르지 않는다 — 앵커($anchor)의 대상과 이어지지 않는다";
                }
            }
        }
        // MalformedTokenResponseTest::calls() 가 부르는 SDK 공개 이름은 전부 표에 있다 — 손 테스트에 대상이 늘면 여기가 먼저 운다.
        $public = [];
        foreach ($rows as $r) {
            $public[$r['method']] = true;
        }
        $nCalls = 0;
        $callsBody = self::testMethodBody('MalformedTokenResponseTest.php', 'calls');
        foreach ($callsBody === null ? [] : self::callsIn($callsBody) as $name) {
            if (!isset($public[$name])) {
                continue;
            }
            $nCalls++;
            if (!isset($callsRunNames[$name])) {
                $fails[] = "W1 MalformedTokenResponseTest::calls() 가 $name 를 부르는데 HAND 에 없다";
            }
        }
        if ($nCalls === 0) {
            $fails[] = 'W1 MalformedTokenResponseTest::calls() 에서 SDK 공개 호출을 하나도 못 읽었다 — 대조가 공허하다';
        }
        // 보안 기본값 가드의 PHP 행위 앵커는 전부 표의 앵커다 — 그 가드에 PHP 앵커가 늘면 여기가 운다.
        $root = \dirname(__DIR__, 3);
        $script = @file_get_contents($root . '/scripts/test/test-security-defaults.sh');
        $found = [];
        if ($script !== false) {
            foreach (self::SCRIPT_ANCHOR_RES as $re) {
                preg_match_all($re, $script, $m, PREG_SET_ORDER);
                foreach ($m as $hit) {
                    $found[$hit[1] . '|' . $hit[2]] = true;
                }
            }
            if ($found === []) {
                $fails[] = 'W1 test-security-defaults.sh 에서 PHP 행위 앵커를 하나도 못 읽었다 — 적는 모양이 바뀌었나?';
            }
            foreach (array_keys($found) as $a) {
                if (!isset($anchors[$a])) {
                    $fails[] = "W1 보안 기본값 가드의 PHP 앵커 $a 가 HAND 에 없다";
                }
            }
        } elseif (file_exists($root . '/.git')) {
            $fails[] = 'W1 저장소 체크아웃인데 보안 기본값 가드를 못 읽었다';
        }

        return ['line' => sprintf('W1 손 목록 %d 항목 · 앵커 %d — calls() 의 SDK 공개 호출 %d · 보안 기본값 가드의 PHP 행위 앵커 %d 와 대조', count(self::HAND), count($anchors), $nCalls, count($found)),
            'fails' => $fails];
    }

    /** `tests/Unit` 아래 파일의 테스트 클래스에서 메서드 본문(없으면 null). 클래스는 경로에서 얻고, 파일이 맞는지 대조한다. */
    private static function testMethodBody(string $file, string $method): ?string
    {
        $class = __NAMESPACE__ . '\\' . str_replace('/', '\\', substr($file, 0, -4));
        if (!class_exists($class) || !method_exists($class, $method)) {
            return null;
        }
        $m = new \ReflectionMethod($class, $method);
        $f = $m->getFileName();
        if ($f === false || !str_ends_with(str_replace('\\', '/', $f), 'tests/Unit/' . $file)) {
            return null;
        }

        return self::body($m);
    }

    private static function body(\ReflectionMethod $m): string
    {
        $f = $m->getFileName();
        $start = $m->getStartLine();
        $end = $m->getEndLine();
        if ($f === false || $start === false || $end === false) {
            return '';
        }
        $lines = file($f);

        return $lines === false ? '' : implode('', array_slice($lines, $start - 1, $end - $start + 1));
    }

    /** @return list<string> 본문이 `->이름(`·`?->이름(`·`::이름(` 꼴로 부르는 이름 전부. */
    private static function callsIn(string $body): array
    {
        preg_match_all('/(?:\??->|::)\s*([A-Za-z_]\w*)\s*\(/', $body, $m);

        return array_values(array_unique($m[1]));
    }

    /**
     * @param class-string $class
     * @return list<string> 메서드 본문과, 그것이 부르는 **같은 클래스의 비공개** 메서드 본문(추이적으로)이 부르는 이름.
     */
    private static function callsReach(string $class, string $method): array
    {
        $rc = new \ReflectionClass($class);
        $seen = [$method => true];
        $queue = [$method];
        $out = [];
        while ($queue !== []) {
            $name = array_shift($queue);
            foreach (self::callsIn(self::body($rc->getMethod($name))) as $c) {
                $out[$c] = true;
                if (!isset($seen[$c]) && $rc->hasMethod($c) && !$rc->getMethod($c)->isPublic() && $rc->getMethod($c)->getDeclaringClass()->getName() === $class) {
                    $seen[$c] = true;
                    $queue[] = $c;
                }
            }
        }

        return array_keys($out);
    }
}
