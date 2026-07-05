<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Integration;

use RuntimeException;
use Throwable;

/**
 * 실제 Keycloak 26.6 컨테이너 라이프사이클 — `docker` CLI 직접 구동(폴백 경로).
 *
 * ⚠️ testcontainers/testcontainers(^1.0)의 기본 Docker 연결은 PHP `unix://` 스트림 트랜스포트를 요구하는데
 * (`Http\Client\Socket\Client`가 `stream_socket_client('unix://...')`로 접속), 이 하네스의 네이티브 Windows PHP
 * 빌드에는 `unix` 스트림 래퍼가 컴파일되어 있지 않다(probe 확인:
 * `Http\Client\Socket\Exception\ConnectionException: Unable to find the socket transport "unix"`).
 * Docker Desktop(Windows)의 기본 컨텍스트도 `npipe:////./pipe/dockerDesktopLinuxEngine`이고 TCP(2375)는
 * 노출되어 있지 않아(`docker context ls`로 확인) `DOCKER_HOST` 폴백(`tcp://127.0.0.1:2375`)도 연결 불가하다.
 * 따라서 testcontainers-php의 `GenericContainer`/`WaitForHttp`가 아니라 `docker` CLI(PHP가 아닌 별도 프로세스 —
 * Docker Desktop과는 named pipe로 통신)를 `exec()`로 셸아웃해 직접 구동한다 — 브리프가 명시한 폴백
 * ("docker run 라이프사이클을 테스트 부트스트랩에서 직접 구동")을 채택했다. 이 경로는 실제 `docker` 커맨드를
 * 그대로 실행하므로 Windows/Linux 어느 CI 러너에서도(Docker 데몬만 있으면) 동일하게 동작한다.
 */
trait KeycloakContainerTrait
{
    private static ?string $containerName = null;

    private static string $baseUrl = '';

    public static function startKeycloak(): void
    {
        $realm = __DIR__ . DIRECTORY_SEPARATOR . 'testdata' . DIRECTORY_SEPARATOR . 'it-realm-realm.json';
        if (!is_file($realm)) {
            throw new RuntimeException("realm fixture not found: {$realm}");
        }

        $name = 'kc-php-it-' . bin2hex(random_bytes(4));

        try {
            self::runOrThrow([
                'docker', 'run', '-d', '--rm',
                '--name', $name,
                '-p', '127.0.0.1::8080',
                '-e', 'KC_BOOTSTRAP_ADMIN_USERNAME=admin',
                '-e', 'KC_BOOTSTRAP_ADMIN_PASSWORD=admin',
                '-e', 'KC_HEALTH_ENABLED=true',
                '-v', "{$realm}:/opt/keycloak/data/import/it-realm-realm.json:ro",
                'quay.io/keycloak/keycloak:26.6',
                'start-dev', '--import-realm',
            ], 'docker run');

            self::$containerName = $name;

            $port = self::resolveMappedPort($name, 8080);
            self::$baseUrl = "http://127.0.0.1:{$port}";

            self::waitForReady(self::$baseUrl . '/realms/it-realm/.well-known/openid-configuration', 120);
        } catch (Throwable $e) {
            self::forceRemove($name);
            self::$containerName = null;

            throw $e;
        }
    }

    public static function stopKeycloak(): void
    {
        if (self::$containerName === null) {
            return;
        }

        self::forceRemove(self::$containerName);
        self::$containerName = null;
    }

    private static function resolveMappedPort(string $containerName, int $containerPort): int
    {
        $output = self::runOrThrow(['docker', 'port', $containerName, "{$containerPort}/tcp"], 'docker port');

        $lines = array_values(array_filter(
            array_map(static fn (string $line): string => trim($line), explode("\n", $output)),
            static fn (string $line): bool => $line !== '',
        ));
        $first = $lines[0] ?? null;
        if ($first === null) {
            throw new RuntimeException("docker port returned no mapping for {$containerName}:{$containerPort}/tcp");
        }

        $colonPos = strrpos($first, ':');
        if ($colonPos === false) {
            throw new RuntimeException("unexpected docker port output: {$first}");
        }

        $port = (int) substr($first, $colonPos + 1);
        if ($port <= 0) {
            throw new RuntimeException("could not parse mapped port from: {$first}");
        }

        return $port;
    }

    private static function waitForReady(string $url, int $timeoutSeconds): void
    {
        $deadline = microtime(true) + $timeoutSeconds;
        $lastError = 'no attempt made';

        while (microtime(true) < $deadline) {
            $handle = curl_init($url);
            if ($handle === false) {
                throw new RuntimeException('curl_init failed');
            }
            curl_setopt_array($handle, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 2,
                CURLOPT_CONNECTTIMEOUT => 2,
            ]);
            $body = curl_exec($handle);
            $statusCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
            $curlError = curl_error($handle);
            curl_close($handle);

            if ($body !== false && $statusCode === 200) {
                return;
            }
            $lastError = $curlError !== '' ? $curlError : "HTTP {$statusCode}";
            usleep(1_000_000);
        }

        throw new RuntimeException(
            "Keycloak did not become ready within {$timeoutSeconds}s at {$url} (last: {$lastError})",
        );
    }

    private static function forceRemove(string $containerName): void
    {
        exec('docker rm -f ' . escapeshellarg($containerName) . ' 2>&1');
    }

    /**
     * @param list<string> $cmd
     */
    private static function runOrThrow(array $cmd, string $label): string
    {
        $escaped = implode(' ', array_map('escapeshellarg', $cmd));
        $output = [];
        $resultCode = 0;
        exec($escaped . ' 2>&1', $output, $resultCode);
        $joined = implode("\n", $output);
        if ($resultCode !== 0) {
            throw new RuntimeException(sprintf('%s failed (exit %d): %s', $label, $resultCode, $joined));
        }

        return $joined;
    }
}
