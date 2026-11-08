<?php

namespace App\SelfTest;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Jobs\RunSecuritySelfTestJob;
use App\Models\Organization;
use App\Models\SecurityTestRun;
use App\Models\User;
use App\Security\Policy\ActionCatalog;
use App\Security\Scanning\InputScanner;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * The life of a run (docs/test-strategy.md §6, docs/api-design.md §3.7): started by an admin with its audit record and
 * the job in one transaction; claimed by the worker with a conditional update; finished with its counts and the
 * completion record in one transaction. A run that cannot finish is failed, and the recovery command fails the ones
 * a dead worker left behind.
 */
final readonly class SelfTestRuns
{
    public const ERROR_FAILED = 'SELF_TEST_FAILED';

    public const ERROR_STALE = 'SELF_TEST_STALE';

    private const UNIQUE_VIOLATION = '23505';

    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private SelfTestRunner $runner,
        private InputScanner $scanner,
    ) {}

    /**
     * @throws SelfTestConflictException when a run of this organization is queued or running
     * @throws ServiceUnavailableException when the audit record cannot be written
     */
    public function start(User $admin): SecurityTestRun
    {
        $this->availability->assertAvailable();

        try {
            return SingleAttemptTransaction::run(DB::connection(), function () use ($admin): SecurityTestRun {
                // The organization's row serialises the check and the insert; the partial unique index backs it.
                Organization::query()->whereKey($admin->organization_id)->lockForUpdate()->firstOrFail();

                if (SecurityTestRun::query()->whereIn('status', SecurityTestRun::ACTIVE_STATUSES)->exists()) {
                    throw SelfTestConflictException::running();
                }

                $run = new SecurityTestRun;
                $run->forceFill(['triggered_by' => $admin->id, 'status' => SecurityTestRun::STATUS_QUEUED])->save();

                $this->audit->recordInTransaction(
                    AuditEntry::byUserOn(AuditEventType::SelftestStarted, $admin, 'security_test_run', $run->id),
                    'selftest_started_unrecorded',
                );

                RunSecuritySelfTestJob::dispatch($run->id, $admin->organization_id);

                // The counts and the timestamps are the row's defaults, which the instance does not have.
                return $run->refresh();
            });
        } catch (QueryException $exception) {
            if ($exception->getCode() === self::UNIQUE_VIOLATION && str_contains($exception->getMessage(), 'security_test_runs_one_active_unique')) {
                throw SelfTestConflictException::running();
            }

            throw $exception;
        }
    }

    /**
     * In the worker, inside the organization's context. Only one run can move the row out of queued.
     *
     * @param  list<SelfTestCase>|null  $cases  Every case by default.
     */
    public function process(string $runId, ?array $cases = null): void
    {
        $claimed = SecurityTestRun::query()
            ->whereKey($runId)
            ->where('status', SecurityTestRun::STATUS_QUEUED)
            ->update([
                'status' => SecurityTestRun::STATUS_RUNNING,
                'started_at' => now(),
                'heartbeat_at' => now(),
                'ruleset_version' => $this->scanner->rulesetVersion(),
                'policy_version' => ActionCatalog::VERSION,
            ]);

        if ($claimed !== 1) {
            return;
        }

        $run = SecurityTestRun::query()->findOrFail($runId);
        $admin = User::query()->find($run->triggered_by);

        if ($admin === null || ! $admin->is_active) {
            $this->fail($runId, self::ERROR_FAILED);

            return;
        }

        $cases ??= SelfTestCases::all();
        $context = app(SelfTestContext::class, ['organizationId' => $run->organization_id, 'admin' => $admin]);

        try {
            $counts = $this->runner->run($run, $context, $cases);
        } catch (Throwable $exception) {
            Log::error('selftest.run_error', ['metric' => 'selftest.run_error', 'run_id' => $runId, 'exception' => $exception::class]);
            $this->fail($runId, self::ERROR_FAILED);

            return;
        }

        $this->finish($run, $counts);
    }

    /**
     * Only a run that is still unfinished changes, so a late failure cannot undo a completion. Never throws: it runs
     * while something has already gone wrong, and the recovery command tries again.
     */
    public function fail(string $runId, string $errorCode): void
    {
        try {
            SingleAttemptTransaction::run(DB::connection(), function () use ($runId, $errorCode): void {
                $changed = SecurityTestRun::query()
                    ->whereKey($runId)
                    ->whereIn('status', SecurityTestRun::ACTIVE_STATUSES)
                    ->update(['status' => SecurityTestRun::STATUS_FAILED, 'error_code' => $errorCode, 'finished_at' => now()]);

                if ($changed !== 1) {
                    return;
                }

                $run = SecurityTestRun::query()->findOrFail($runId);

                $this->audit->recordInTransaction(
                    AuditEntry::systemOn(AuditEventType::SelftestCompleted, $run->organization_id, 'security_test_run', $run->id, [
                        'total' => $run->total, 'passed' => $run->passed, 'failed' => $run->failed, 'status' => SecurityTestRun::STATUS_FAILED, 'reason_code' => $errorCode,
                    ], 'failure'),
                    'selftest_completed_unrecorded',
                );
            });
        } catch (Throwable $exception) {
            Log::critical('selftest.fail_unrecorded', ['metric' => 'selftest.fail_unrecorded', 'run_id' => $runId, 'exception' => $exception::class]);
        }
    }

    /**
     * @param  array{total: int, passed: int, failed: int}  $counts
     *
     * @throws ServiceUnavailableException when the completion record cannot be written: the run is then failed by the caller
     */
    private function finish(SecurityTestRun $run, array $counts): void
    {
        try {
            SingleAttemptTransaction::run(DB::connection(), function () use ($run, $counts): void {
                $changed = SecurityTestRun::query()
                    ->whereKey($run->id)
                    ->where('status', SecurityTestRun::STATUS_RUNNING)
                    ->update([
                        'status' => SecurityTestRun::STATUS_COMPLETED,
                        'total' => $counts['total'],
                        'passed' => $counts['passed'],
                        'failed' => $counts['failed'],
                        'finished_at' => now(),
                    ]);

                if ($changed !== 1) {
                    return;
                }

                $this->audit->recordInTransaction(
                    AuditEntry::systemOn(AuditEventType::SelftestCompleted, $run->organization_id, 'security_test_run', $run->id, [
                        'total' => $counts['total'], 'passed' => $counts['passed'], 'failed' => $counts['failed'], 'status' => SecurityTestRun::STATUS_COMPLETED,
                    ], $counts['failed'] === 0 ? 'success' : 'failure'),
                    'selftest_completed_unrecorded',
                );
            });
        } catch (Throwable $exception) {
            Log::error('selftest.finish_error', ['metric' => 'selftest.finish_error', 'run_id' => $run->id, 'exception' => $exception::class]);
            $this->fail($run->id, self::ERROR_FAILED);
        }
    }
}
