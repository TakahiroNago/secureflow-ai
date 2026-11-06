<?php

namespace App\Domain\Workflow;

use RuntimeException;

/**
 * The plan cannot be hashed. The message names the rule only, never the content.
 */
final class InvalidPlanException extends RuntimeException {}
