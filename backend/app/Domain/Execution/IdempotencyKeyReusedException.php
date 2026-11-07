<?php

namespace App\Domain\Execution;

use RuntimeException;

/**
 * 422 IDEMPOTENCY_KEY_REUSED (docs/api-design.md §3.6). It holds nothing from the execution the key belongs to.
 */
final class IdempotencyKeyReusedException extends RuntimeException {}
