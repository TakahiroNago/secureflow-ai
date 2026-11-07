<?php

namespace App\Console\Commands;

use App\Domain\Execution\ExecutionProcessor;
use App\Models\WorkflowExecution;
use App\Support\Organization\OrganizationContext;
use App\Support\Organization\OrganizationScope;
use Illuminate\Console\Command;

/**
 * Runs every minute on the scheduler. A worker that dies leaves its row behind, and the workflow would stay Running
 * for ever (docs/security-design.md §11). It reads across organizations for ids only, and each row is then handled
 * inside its own organization. A run it gives up on cannot come back: its later updates need the row to be running.
 */
final class ExecutionsReapStaleCommand extends Command
{
    /** Longer than the job's time limit, so a job that is still running is not given up on. */
    public const RUNNING_LIMIT_SECONDS = 300;

    public const QUEUED_LIMIT_SECONDS = 900;

    private const BATCH = 100;

    protected $signature = 'executions:reap-stale';

    protected $description = 'Fail executions that are stuck in queued or running';

    public function handle(ExecutionProcessor $processor, OrganizationContext $context): int
    {
        // Across organizations on purpose: the one reader of every organization's rows, and each row is handled
        // inside its own organization's context below (docs/security-design.md §13.3).
        // nosemgrep: secureflow.php.without-global-scope
        $stuck = WorkflowExecution::query()
            ->withoutGlobalScope(OrganizationScope::class)
            ->where(fn ($query) => $query
                ->where(fn ($q) => $q->where('status', WorkflowExecution::STATUS_RUNNING)->where('heartbeat_at', '<', now()->subSeconds(self::RUNNING_LIMIT_SECONDS)))
                ->orWhere(fn ($q) => $q->where('status', WorkflowExecution::STATUS_QUEUED)->where('created_at', '<', now()->subSeconds(self::QUEUED_LIMIT_SECONDS))))
            ->limit(self::BATCH)
            ->get(['id', 'organization_id']);

        foreach ($stuck as $execution) {
            $context->run($execution->organization_id, fn () => $processor->fail($execution->id, ExecutionProcessor::ERROR_STALE));
        }

        return self::SUCCESS;
    }
}
