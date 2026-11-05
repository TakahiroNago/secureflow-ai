<?php

namespace App\Security\Output;

use App\Security\Policy\PolicyDecision;

/**
 * A task that has the right shape and a known action. Its text is still what the AI wrote: masking, the
 * canary check and removing markup come in step 2-4.
 */
final readonly class ValidatedTask
{
    /**
     * @param  list<string>  $steps
     * @param  list<string>  $requestedPermissions  What the AI asked for. Never used to authorize anything.
     * @param  list<string>  $permissions  From ActionCatalog. The only ones that count.
     */
    public function __construct(
        public string $title,
        public string $description,
        public string $actionType,
        public array $steps,
        public string $priority,
        public array $requestedPermissions,
        public string $targetData,
        public string $impactSummary,
        public PolicyDecision $decision,
        public array $permissions,
    ) {}
}
