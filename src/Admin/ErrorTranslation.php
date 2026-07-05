<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Admin;

use Fschmtt\Keycloak\Exception\BuilderException;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use Xzawed\Keycloak\Exception\KeycloakAdminError;
use Xzawed\Keycloak\Exception\KeycloakConfigError;
use Xzawed\Keycloak\Exception\KeycloakConflictError;
use Xzawed\Keycloak\Exception\KeycloakException;
use Xzawed\Keycloak\Exception\KeycloakForbiddenError;
use Xzawed\Keycloak\Exception\KeycloakNotFoundError;
use Xzawed\Keycloak\Exception\KeycloakTransportError;

/**
 * fschmtt는 Guzzle 예외를 변환하지 않으므로(404/409/403 전부 raw ClientException) 경계에서 여기로 변환한다.
 */
final class ErrorTranslation
{
    /**
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function call(callable $fn): mixed
    {
        try {
            return $fn();
        } catch (ClientException $e) {
            $status = $e->getResponse()->getStatusCode();
            throw match ($status) {
                404 => new KeycloakNotFoundError($e->getMessage(), 404, $e),
                409 => new KeycloakConflictError($e->getMessage(), 409, $e),
                403 => new KeycloakForbiddenError($e->getMessage(), 403, $e),
                default => new KeycloakAdminError($e->getMessage(), $status, $e),
            };
        } catch (ServerException $e) {
            throw new KeycloakAdminError($e->getMessage(), $e->getResponse()->getStatusCode(), $e);
        } catch (ConnectException $e) {
            throw new KeycloakTransportError('admin request unreachable', previous: $e);
        } catch (RequestException $e) {
            throw new KeycloakTransportError('admin request failed', previous: $e);
        } catch (BuilderException $e) {
            throw new KeycloakConfigError($e->getMessage(), previous: $e);
        } catch (KeycloakException $e) {
            throw $e;   // 우리 자신의 SDK 예외 — 재래핑하지 않는다.
        } catch (\Throwable $e) {
            // fschmtt SerializerException(역직렬화 실패) 및 그 밖의 미분류 하위 라이브러리 예외를
            // 전부 여기로 수렴시켜 admin 파사드 밖으로 새지 않게 한다(JwtValidator의 \Throwable net과 동형).
            throw new KeycloakAdminError($e->getMessage(), null, $e);
        }
    }
}
