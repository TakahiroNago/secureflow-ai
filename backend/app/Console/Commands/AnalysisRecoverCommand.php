<?php

namespace App\Console\Commands;

use App\Domain\Workflow\AnalysisProcessor;
use App\Models\AiAnalysisRequest;
use App\Support\Organization\OrganizationContext;
use App\Support\Organization\OrganizationScope;
use Illuminate\Console\Command;

/**
 * Runs every minute on the scheduler. A worker that dies leaves its row behind, and a row that stays
 * unfinished would leave the user waiting for ever (docs/architecture.md §10).
 *
 * The only place that reads analyses across organizations. It takes ids, and each row is then handled
 * inside its own organization.
 */
final class AnalysisRecoverCommand extends Command
{
    /** Longer than the job's time limit, so a job that is still running is not given up on. */
    public const PROCESSING_LIMIT_SECONDS = 180;

    public const QUEUED_LIMIT_SECONDS = 900;

    private const BATCH = 100;

    protected $signature = 'analysis:recover';

    protected $description = 'Fail analyses that are stuck in queued or processing';

    public function handle(AnalysisProcessor $processor, OrganizationContext $context): int
    {
        $stuck = AiAnalysisRequest::query()
            ->withoutGlobalScope(OrganizationScope::class)
            ->where(fn ($query) => $query
                ->where(fn ($q) => $q->where('status', AiAnalysisRequest::STATUS_PROCESSING)->where('heartbeat_at', '<', now()->subSeconds(self::PROCESSING_LIMIT_SECONDS)))
                ->orWhere(fn ($q) => $q->where('status', AiAnalysisRequest::STATUS_QUEUED)->where('created_at', '<', now()->subSeconds(self::QUEUED_LIMIT_SECONDS))))
            ->limit(self::BATCH)
            ->get(['id', 'organization_id']);

        foreach ($stuck as $analysis) {
            $context->run($analysis->organization_id, fn () => $processor->fail($analysis->id, AnalysisProcessor::ERROR_STALE));
        }

        return self::SUCCESS;
    }
}
