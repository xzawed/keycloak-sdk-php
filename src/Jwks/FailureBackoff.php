<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Jwks;

/**
 * 실패한 JWKS fetch 의 백오프 상태 기계.
 *
 * ⚠️ **`minRefetchIntervalSeconds`(30초)와 다른 축이다.** 30초 게이트는 *캐시가 찬 뒤* 미해결 kid
 * 홍수를 막는다. 이 클래스는 **캐시가 비어 있고 fetch 가 계속 실패할 때**를 막는다 — 그 자리에는
 * 게이트가 없어서, 측정상 20회 조회가 IdP 요청 20건을 그대로 냈다(2026-09-04 · 7개 언어 동일).
 *
 * ⚠️ **여기에 30초를 재사용하면 안 된다** — 일시적 503 한 번이 「30초간 어떤 토큰도 검증 불가」가
 * 된다. 그래서 짧게 시작해 지수적으로 늘리고 상한을 둔다.
 *
 * ⚠️ **sleep 하지 않는다.** 창 안에서는 IdP 를 때리지 않고 즉시 실패시킨다(negative cache).
 * 재시도 페이싱은 소비자 몫이다.
 *
 * ⚠️ **왜 `JwksStore` 안의 private 필드가 아니라 별도 클래스인가** — 시계를 주입해야 창을
 * 결정적으로 넘길 수 있는데(sleep 금지), 그 이음매를 `JwksStore` 의 **공개 생성자**에 얹으면
 * 테스트 전용 파라미터가 소비자 API 에 올라가고 `php-semver-checker` 가 V010(파라미터 추가)로
 * MAJOR 를 낸다. python `_internal/backoff.py` 와 같은 자리다.
 *
 * @internal 이 클래스는 SDK 내부 구현이다 — 공개 API 로 취급하지 않는다.
 */
final class FailureBackoff
{
    public const BASE_SECONDS = 0.2;
    public const CAP_SECONDS  = 5.0;

    private int $failures = 0;
    /** monotonic 초. `time()`은 1초 해상도라 0.2초 창을 잴 수 없다. */
    private ?float $lastFailureAt = null;

    /** @var callable():float */
    private $clock;
    /** @var callable():float */
    private $jitter;

    /**
     * @param null|callable():float $clock  기본은 monotonic 시계
     * @param null|callable():float $jitter 기본은 [0.5, 1.0) 배수
     */
    public function __construct(?callable $clock = null, ?callable $jitter = null)
    {
        $this->clock = $clock ?? static fn (): float => (float) \hrtime(true) / 1e9;
        // jitter 는 여러 인스턴스가 같은 순간에 복구를 시도해 IdP 를 다시 무너뜨리는
        // 것(thundering herd)을 흩는다. 암호용이 아니라 분산용이다.
        //
        // ⚠️ **PRNG API 를 쓰지 않는다 — 나노초 시계에서 뽑는다.** 이 값은 비밀이 아니지만,
        // 보안 민감 패키지에서 약한 PRNG 를 호출하면 정적분석이 정당하게 막는다(실측: sonar
        // S2245 · gosec G404). 일곱 언어가 **같은 관용**을 쓰고, rust 는 여기에 더해 런타임
        // 의존(`rand`)을 하나 늘리지 않는다는 이유가 겹친다.
        $this->jitter = $jitter ?? static fn (): float => 0.5 + (\hrtime(true) % 1000000) / 2000000;
    }

    public function failures(): int
    {
        return $this->failures;
    }

    /** 백오프 잔여 초. 0 이면 fetch 를 허용한다. */
    public function remaining(): float
    {
        if ($this->lastFailureAt === null) {
            return 0.0;
        }

        return \max(0.0, $this->delay() - (($this->clock)() - $this->lastFailureAt));
    }

    public function recordFailure(): void
    {
        $this->failures++;
        $this->lastFailureAt = ($this->clock)();
    }

    public function recordSuccess(): void
    {
        // ⚠️ 성공이 카운터를 되돌리지 않으면 오래 산 프로세스에서 백오프가 상한에 눌러붙는다.
        $this->failures = 0;
        $this->lastFailureAt = null;
    }

    private function delay(): float
    {
        $raw = self::BASE_SECONDS * (2 ** (\max($this->failures, 1) - 1));

        return \min($raw, self::CAP_SECONDS) * ($this->jitter)();
    }
}
