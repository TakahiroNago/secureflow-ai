<?php

namespace App\Domain\Workflow;

use RuntimeException;

/**
 * 429 AI_LIMIT_EXCEEDED (docs/security-design.md §6). The limit was reached, so the AI was not called.
 */
final class AiLimitExceededException extends RuntimeException {}
