<?php

namespace App\SelfTest;

use App\Models\SecurityTestResult;
use App\Models\SecurityTestRun;
use App\Support\Database\SingleAttemptTransaction;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Runs the cases one by one. A case that writes rows runs in a transaction that is always rolled back, so nothing it
 * made outlives it, and its audit records go with it. Each result is written in a transaction of its own, after the
 * case, so that a run that dies leaves the results it had. A case that throws is a failed case, named by the
 * exception's class only: a self-test must not fail as a whole because one check broke.
 */
final class SelfTestRunner
{
    /**
     * @param  list<SelfTestCase>  $cases
     * @return array{total: int, passed: int, failed: int}
     */
    public function run(SecurityTestRun $run, SelfTestContext $context, array $cases): array
    {
        $passed = $failed = 0;

        // The total first: the counts below must never exceed it.
        SecurityTestRun::query()->whereKey($run->id)->where('status', SecurityTestRun::STATUS_RUNNING)->update(['total' => count($cases)]);

        foreach ($cases as $case) {
            $started = hrtime(true);
            $outcome = $this->outcomeOf($case, $context);
            $durationMs = (int) round((hrtime(true) - $started) / 1_000_000);

            (new SecurityTestResult)->forceFill([
                'run_id' => $run->id,
                'case_id' => $case->id(),
                'category' => $case->category(),
                'name' => $case->name(),
                'expected' => $case->expected(),
                'actual' => $outcome->actual,
                'passed' => $outcome->passed,
                'duration_ms' => $durationMs,
                'details' => $outcome->details,
            ])->save();

            $outcome->passed ? $passed++ : $failed++;

            SecurityTestRun::query()->whereKey($run->id)->where('status', SecurityTestRun::STATUS_RUNNING)
                ->update(['heartbeat_at' => now(), 'passed' => $passed, 'failed' => $failed]);
        }

        return ['total' => count($cases), 'passed' => $passed, 'failed' => $failed];
    }

    private function outcomeOf(SelfTestCase $case, SelfTestContext $context): CaseOutcome
    {
        try {
            return $case->isolated() ? $this->isolated($case, $context) : $case->run($context);
        } catch (Throwable $exception) {
            // The class says what kind of thing went wrong; the message could hold anything.
            Log::warning('selftest.case_error', ['metric' => 'selftest.case_error', 'case' => $case->id(), 'exception' => $exception::class]);

            return CaseOutcome::of(false, 'error: '.class_basename($exception), ['exception' => $exception::class]);
        }
    }

    /**
     * The case's own transaction, always rolled back. One attempt: a case that hits a deadlock is a failed case.
     */
    private function isolated(SelfTestCase $case, SelfTestContext $context): CaseOutcome
    {
        try {
            SingleAttemptTransaction::run(DB::connection(), function () use ($case, $context): void {
                throw new RollbackSignal($case->run($context));
            });
        } catch (RollbackSignal $signal) {
            return $signal->outcome;
        }
    }
}
