<?php

namespace App\Domain\Workflow;

use RuntimeException;

/**
 * 422 RISK_ACK_REQUIRED (docs/api-design.md §3.5). It holds nothing from the workflow.
 */
final class RiskAcknowledgementRequiredException extends RuntimeException {}
