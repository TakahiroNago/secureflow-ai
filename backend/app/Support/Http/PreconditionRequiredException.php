<?php

namespace App\Support\Http;

use RuntimeException;

/**
 * An edit without a usable If-Match header (docs/api-design.md §1). Answered as 428.
 */
final class PreconditionRequiredException extends RuntimeException {}
