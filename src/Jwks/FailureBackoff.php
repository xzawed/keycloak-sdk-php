<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Jwks;

/**
 * Backoff state machine for failed JWKS fetches.
 *
 * ⚠️ **This is a different axis from `minRefetchIntervalSeconds` (30 seconds).** The 30-second gate stops a flood of
 * unresolved kids *after the cache is filled*. This class stops the case where **the cache is empty and the fetch keeps
 * failing** — there was no gate there, so in a measurement 20 lookups went out as 20 IdP requests (2026-09-04 · the same
 * in 7 languages).
 *
 * ⚠️ **Do not reuse the 30 seconds here** — a single transient 503 would become "no token can be validated for 30
 * seconds". So it starts short, grows exponentially and has a cap.
 *
 * ⚠️ **It does not sleep.** Inside the window it fails immediately without hitting the IdP (negative cache).
 * Retry pacing is the consumer's job.
 *
 * ⚠️ **Why a separate class rather than a private field inside `JwksStore`** — the clock has to be injected to step past
 * the window deterministically (no sleeping), and putting that seam on `JwksStore`'s **public constructor** would put a
 * test-only parameter on the consumer API, and `php-semver-checker` would report MAJOR for it as V010 (parameter added).
 * It is the same spot as python's `_internal/backoff.py`.
 *
 * @internal This class is an internal implementation detail of the SDK — do not treat it as public API.
 */
final class FailureBackoff
{
    public const BASE_SECONDS = 0.2;
    public const CAP_SECONDS  = 5.0;

    private int $failures = 0;
    /** monotonic 초. `time()`은 1초 해상도라 0.2초 창을 잴 수 없다. */
    private ?float $lastFailureAt = null;
    /**
     * 마지막 실패가 연 창의 길이(초). jitter 를 그 실패를 기록할 때 **한 번** 뽑아 고정한다 — 검사마다 다시 뽑으면 같은 실패가
     * 같은 순간에 한 번은 거부하고 한 번은 IdP 로 내보낸다(창이 0.5× 쪽으로 줄어 장애 중 요청이 최대 두 배).
     */
    private float $windowSeconds = 0.0;

    /** @var callable():float */
    private $clock;
    /** @var callable():float */
    private $jitter;

    /**
     * @param null|callable():float $clock  defaults to a monotonic clock
     * @param null|callable():float $jitter defaults to a [0.5, 1.0) multiplier
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

    /** Seconds of backoff remaining. 0 allows a fetch. */
    public function remaining(): float
    {
        if ($this->lastFailureAt === null) {
            return 0.0;
        }

        return \max(0.0, $this->windowSeconds - (($this->clock)() - $this->lastFailureAt));
    }

    public function recordFailure(): void
    {
        $this->failures++;
        $this->lastFailureAt = ($this->clock)();
        $this->windowSeconds = $this->delay();
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
