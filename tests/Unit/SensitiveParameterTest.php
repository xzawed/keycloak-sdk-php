<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * ⚠️ **비밀을 인자로 받는 자리는 전부 `#[\SensitiveParameter]` 를 달아야 한다.**
 *
 * PHP 8.2+ 는 이 속성이 붙은 파라미터를 **스택트레이스에서 `Object(SensitiveParameterValue)`
 * 로 가린다.** 붙지 않으면 소비자 앱이 인증 오류 하나를 로깅하는 순간 refresh token 이나
 * PKCE verifier 가 원문으로 로그에 남는다 — 게시된 `1.0.0` 이 그 상태였다(생성자 넷에만
 * 붙어 있었다).
 *
 * ⚠️ **이 테스트는 손 목록이 아니다.** `php/src` 전체를 반사해 **이름이 비밀을 뜻하는
 * 문자열 파라미터**를 스스로 찾는다 — 새 메서드가 비밀을 받으면서 속성을 빠뜨리면 목록을
 * 고치지 않아도 여기서 실패한다. 목록으로 적으면 다음에 추가되는 자리를 놓친다.
 */
final class SensitiveParameterTest extends TestCase
{
    /**
     * 비밀을 뜻하는 파라미터 이름. ⚠️ `nonce`·`state` 는 **비밀이 아니다**(재생 방지용
     * 공개값이라 URL 로 이동한다) — 여기 넣으면 가드가 사실이 아닌 것을 강제한다.
     */
    private const SECRET_NAME = '/(secret|password|credential|verifier|(^|_|[a-z])(code|token)s?$)/i';

    /** @return list<class-string> */
    private static function sdkClasses(): array
    {
        $root = \dirname(__DIR__, 2) . '/src';
        $found = [];
        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root)) as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $src = (string) file_get_contents($file->getPathname());
            if (
                preg_match('/^namespace\s+([^;]+);/m', $src, $ns) !== 1
                || preg_match('/^(?:final\s+|abstract\s+|readonly\s+)*class\s+(\w+)/m', $src, $cls) !== 1
            ) {
                continue;
            }
            $fqcn = trim($ns[1]) . '\\' . $cls[1];
            if (class_exists($fqcn)) {
                $found[] = $fqcn;
            }
        }
        sort($found);
        return $found;
    }

    /**
     * 대조군 — 반사가 실제로 소스를 훑었는지. 클래스 목록이 비면 아래 단언이 0건 실행되고
     * 이 테스트는 **아무것도 안 보면서 초록**이 된다(이 저장소가 반복해 겪은 부류).
     */
    public function testReflectionActuallyFoundTheSdkClasses(): void
    {
        $classes = self::sdkClasses();
        self::assertGreaterThanOrEqual(10, count($classes), 'php/src 반사가 클래스를 거의 못 찾았다');
        self::assertContains(\Xzawed\Keycloak\AuthClient::class, $classes);
    }

    /**
     * 대조군 둘째 — 이름 정규식이 실제로 무언가를 고르는지. 정규식이 아무것도 안 고르면
     * 본 단언은 0건 실행되고 역시 조용히 통과한다.
     */
    public function testSecretNamePatternSelectsRealParameters(): void
    {
        $hits = 0;
        foreach ($this->secretStringParameters() as $_) {
            $hits++;
        }
        self::assertGreaterThanOrEqual(8, $hits, '비밀 이름 정규식이 고른 파라미터가 너무 적다 — 정규식이 낡았나?');
    }

    public function testEverySecretStringParameterIsMarkedSensitive(): void
    {
        $unmarked = [];
        foreach ($this->secretStringParameters() as [$where, $param]) {
            if ($param->getAttributes(\SensitiveParameter::class) === []) {
                $unmarked[] = $where . '($' . $param->getName() . ')';
            }
        }
        self::assertSame([], $unmarked, "#[\\SensitiveParameter] 가 빠진 자리:\n  " . implode("\n  ", $unmarked));
    }

    /**
     * `php/src` 의 모든 메서드·생성자에서 **문자열 타입이면서 이름이 비밀을 뜻하는** 파라미터.
     * 타입으로 좁히는 이유: `logoutUrl(TokenSet $tokens)` 처럼 값 객체를 받는 자리는 그 객체가
     * 스스로 마스킹하므로(§4 마스킹 바닥 계약) 여기 해당하지 않는다.
     *
     * @return \Generator<int, array{0: string, 1: \ReflectionParameter}>
     */
    private function secretStringParameters(): \Generator
    {
        foreach (self::sdkClasses() as $fqcn) {
            $rc = new \ReflectionClass($fqcn);
            foreach ($rc->getMethods() as $m) {
                if ($m->getDeclaringClass()->getName() !== $fqcn) {
                    continue;   // 상속받은 것은 선언한 클래스에서 한 번만 본다
                }
                foreach ($m->getParameters() as $p) {
                    $t = $p->getType();
                    if (!$t instanceof \ReflectionNamedType || $t->getName() !== 'string') {
                        continue;
                    }
                    if (preg_match(self::SECRET_NAME, $p->getName()) !== 1) {
                        continue;
                    }
                    yield [$rc->getShortName() . '::' . $m->getName(), $p];
                }
            }
        }
    }
}
