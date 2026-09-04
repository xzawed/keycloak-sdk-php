<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit\Jwks;

use PHPUnit\Framework\TestCase;
use Xzawed\Keycloak\Jwks\FailureBackoff;

/**
 * 실패한 JWKS fetch 백오프의 상태 기계.
 *
 * ⚠️ 여기가 콜드 캐시 + IdP 장애 축이다. `minRefetchIntervalSeconds`(30초) 게이트는 *캐시가 찬
 * 뒤* 미해결 kid 홍수만 막는다 — 캐시가 비어 있고 fetch 가 계속 실패하면 그 게이트에 닿지도
 * 못한다. 실측(2026-09-04): 20회 조회 → IdP 요청 **20건**, 7개 언어 동일.
 *
 * 배선(스토어가 이 기계를 실제로 부르는가)은 `JwksStoreTest` 가 요청 수로 증명한다.
 */
final class FailureBackoffTest extends TestCase
{
    /** 시계를 주입한다 — sleep 없이 창을 결정적으로 넘기기 위해서다. */
    private function backoff(float &$now, float $jitter = 1.0): FailureBackoff
    {
        return new FailureBackoff(
            static function () use (&$now): float {
                return $now;
            },
            static fn (): float => $jitter,
        );
    }

    public function testFreshBackoffAllowsAFetch(): void
    {
        $now = 1000.0;
        self::assertSame(0.0, $this->backoff($now)->remaining());
    }

    public function testFailureOpensAWindow(): void
    {
        $now = 1000.0;
        $b = $this->backoff($now);
        $b->recordFailure();
        self::assertSame(1, $b->failures());
        self::assertSame(FailureBackoff::BASE_SECONDS, $b->remaining());
    }

    /**
     * ⚠️ **이 테스트를 지우지 말 것 — 「한 번 실패하면 영원히 차단」도 결함 테스트는 통과한다.**
     * 그 동작은 원래 결함보다 나쁘다(IdP 가 복구돼도 SDK 가 영영 못 쓴다).
     */
    public function testWindowExpiresAndAllowsARetry(): void
    {
        $now = 1000.0;
        $b = $this->backoff($now);
        $b->recordFailure();
        $now += FailureBackoff::BASE_SECONDS;
        self::assertSame(0.0, $b->remaining());
    }

    public function testDelayGrowsExponentiallyAndIsCapped(): void
    {
        $now = 1000.0;
        $b = $this->backoff($now);
        $seen = [];
        for ($i = 0; $i < 8; $i++) {
            $b->recordFailure();
            $seen[] = $b->remaining();
        }
        self::assertSame(FailureBackoff::BASE_SECONDS, $seen[0]);
        self::assertSame(FailureBackoff::BASE_SECONDS * 2, $seen[1]);
        self::assertSame(FailureBackoff::BASE_SECONDS * 4, $seen[2]);
        self::assertSame(FailureBackoff::CAP_SECONDS, $seen[7]);
        self::assertSame(FailureBackoff::CAP_SECONDS, max($seen));
    }

    /** ⚠️ 대조군 — 성공이 카운터를 되돌리지 않으면 백오프가 상한에 눌러붙는다. */
    public function testSuccessResetsTheCounterAndTheWindow(): void
    {
        $now = 1000.0;
        $b = $this->backoff($now);
        for ($i = 0; $i < 5; $i++) {
            $b->recordFailure();
        }
        self::assertSame(5, $b->failures());

        $b->recordSuccess();
        self::assertSame(0, $b->failures());
        self::assertSame(0.0, $b->remaining());

        // 다음 실패는 상한이 아니라 base 에서 다시 시작한다.
        $b->recordFailure();
        self::assertSame(FailureBackoff::BASE_SECONDS, $b->remaining());
    }

    public function testJitterScalesTheWindow(): void
    {
        $now = 1000.0;
        $b = $this->backoff($now, 0.5);
        $b->recordFailure();
        self::assertSame(FailureBackoff::BASE_SECONDS * 0.5, $b->remaining());
    }

    public function testDefaultJitterStaysWithinTheBand(): void
    {
        // 100회면 밴드를 벗어나는 구현(예: 0..1)이 잡힌다.
        $b = new FailureBackoff();
        for ($i = 0; $i < 100; $i++) {
            $b->recordFailure();
            $r = $b->remaining();
            self::assertGreaterThan(0.0, $r);
            self::assertLessThanOrEqual(FailureBackoff::CAP_SECONDS, $r);
            $b->recordSuccess();
        }
    }
}
