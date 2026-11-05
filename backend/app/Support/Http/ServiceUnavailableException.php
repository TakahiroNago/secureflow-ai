<?php

namespace App\Support\Http;

use RuntimeException;

/**
 * The request could not be completed because a dependency is not available. Rendered as 503, never
 * as AUTH_FAILED. The reason stays on the server: every 503 of an endpoint looks the same.
 */
class ServiceUnavailableException extends RuntimeException {}
