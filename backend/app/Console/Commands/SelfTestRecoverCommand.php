<?php

namespace App\Console\Commands;

use App\Models\SecurityTestRun;
use App\SelfTest\SelfTestRuns;
use App\Support\Organization\OrganizationContext;
use App\Support\Organization\OrganizationScope;
use Illuminate\Console\Command;

/**
 * Runs every minute on the scheduler. A worker that dies leaves its run behind, and a run that stays unfinished
 * would block the next one for ever (one at a time per organization).
 *
 * The only place that reads self-test runs across organizations. It takes ids, and each row is then handled
 * inside its own organization.
 */
final class SelfTestRecoverCommand extends Command
{
    /** Longer than the job's time limit, so a job that is still running is not given up on. */
    public const RUNNING_LIMIT_SECONDS = 300;

    public const QUEUED_LIMIT_SECONDS = 900;

    private const BATCH = 100;

    protected $signature = 'selftest:recover';

    protected $description = 'Fail self-test runs that are stuck in queued or running';

    public function handle(SelfTestRuns $runs, OrganizationContext $context): int
    {
        // Across organizations on purpose: the one reader of every organization's rows, and each row is handled
        // inside its own organization's context below (docs/security-design.md §13.3).
        // nosemgrep: secureflow.php.without-global-scope
        $stuck = SecurityTestRun::query()
            ->withoutGlobalScope(OrganizationScope::class)
            ->where(fn ($query) => $query
                ->where(fn ($q) => $q->where('status', SecurityTestRun::STATUS_RUNNING)->where('heartbeat_at', '<', now()->subSeconds(self::RUNNING_LIMIT_SECONDS)))
                ->orWhere(fn ($q) => $q->where('status', SecurityTestRun::STATUS_QUEUED)->where('created_at', '<', now()->subSeconds(self::QUEUED_LIMIT_SECONDS))))
            ->limit(self::BATCH)
            ->get(['id', 'organization_id']);

        foreach ($stuck as $run) {
            $context->run($run->organization_id, fn () => $runs->fail($run->id, SelfTestRuns::ERROR_STALE));
        }

        return self::SUCCESS;
    }
}
