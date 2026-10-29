<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

/** The root of every SDK exception. Underlying library exceptions are translated into this hierarchy at the boundary. */
class KeycloakException extends \RuntimeException {}
