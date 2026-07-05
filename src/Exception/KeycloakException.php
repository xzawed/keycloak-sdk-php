<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

/** 모든 SDK 예외의 루트. 하위 라이브러리 예외는 경계에서 이 계급으로 변환된다. */
class KeycloakException extends \RuntimeException {}
