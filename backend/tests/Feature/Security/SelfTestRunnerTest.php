<?php

use App\Ai\Contracts\AiProvider;
use App\Models\Organization;
use App\Models\SecurityTestRun;
use App\Models\User;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestCases;
use App\SelfTest\SelfTestContext;
use App\SelfTest\SelfTestRunner;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;

/*
| SELFTEST-01 to SELFTEST-04 (docs/test-strategy.md §32): every case passes on the application as it is, nothing a
| case makes outlives it, a broken check is a failed case and not a failed run, and the AI provider is never resolved.
*/

uses(DatabaseTransactions::class);

const SELF_TEST_TABLES = ['users', 'organizations', 'workflows', 'workflow_tasks', 'workflow_revisions', 'approvals', 'workflow_executions', 'ai_analysis_requests', 'ai_usage_logs', 'security_scans', 'security_findings', 'jobs'];

function selfTestContext(User $admin): SelfTestContext
{
    return app(SelfTestContext::class, ['organizationId' => $admin->organization_id, 'admin' => $admin]);
}

function runningRun(User $admin): SecurityTestRun
{
    $run = new SecurityTestRun;
    $run->forceFill(['triggered_by' => $admin->id, 'status' => SecurityTestRun::STATUS_RUNNING, 'started_at' => now(), 'heartbeat_at' => now()])->save();

    return $run;
}

/**
 * @return array<string, int>
 */
function rowCounts(): array
{
    $counts = [];
    foreach (SELF_TEST_TABLES as $table) {
        $counts[$table] = DB::table($table)->count();
    }

    return $counts;
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->admin = userIn($this->org->id, 'admin');
    // A login, so that the organization's audit chain has rows for ST-28 to verify, as it always has in use.
    loggedIn($this, $this->admin);
    // A provider that is resolved from the container is a case that called the AI: that must never happen.
    $this->app->bind(AiProvider::class, fn () => throw new LogicException('The self-test resolved the AI provider.'));
});

it('SELFTEST-01: every case passes on the application as it is, and leaves nothing behind', function () {
    $before = rowCounts();

    app(OrganizationContext::class)->run($this->org->id, function () {
        $run = runningRun($this->admin);

        $counts = app(SelfTestRunner::class)->run($run, selfTestContext($this->admin), SelfTestCases::all());

        $results = DB::table('security_test_results')->where('run_id', $run->id)->orderBy('case_id')->get();
        $failed = $results->where('passed', false)->map(fn ($r) => $r->case_id.': '.$r->actual.' '.$r->details)->values()->all();

        expect($failed)->toBe([])
            ->and($counts)->toBe(['total' => 26, 'passed' => 26, 'failed' => 0])
            ->and($results->pluck('case_id')->all())->toBe(['ST-01', 'ST-02', 'ST-03', 'ST-04', 'ST-06', 'ST-07', 'ST-08', 'ST-09', 'ST-10', 'ST-12', 'ST-13', 'ST-14', 'ST-15', 'ST-16', 'ST-17', 'ST-18', 'ST-19', 'ST-20', 'ST-21', 'ST-22', 'ST-28', 'ST-30', 'ST-35', 'ST-36', 'ST-37', 'ST-38'])
            ->and($results->every(fn ($r) => $r->duration_ms >= 0 && $r->expected !== '' && $r->actual !== ''))->toBeTrue()
            ->and(SecurityTestRun::query()->findOrFail($run->id)->passed)->toBe(26)
            ->and(SecurityTestRun::query()->findOrFail($run->id)->total)->toBe(26);
    });

    // The temporary users, organizations, workflows, approvals, executions and scans of the cases are gone.
    expect(rowCounts())->toBe($before);
});

it('SELFTEST-02: the cases cover every self-test mark of docs/test-strategy.md §5, each once', function () {
    $ids = array_map(fn ($case) => $case->id(), SelfTestCases::all());

    expect($ids)->toBe(array_values(array_unique($ids)))
        ->and(count($ids))->toBe(26)
        ->and(array_keys(SelfTestCases::CI_ONLY))->toBe(['ST-05', 'ST-11', 'ST-23', 'ST-24', 'ST-25', 'ST-26', 'ST-27', 'ST-29', 'ST-31', 'ST-32', 'ST-33', 'ST-34', 'ST-39'])
        ->and(array_intersect($ids, array_keys(SelfTestCases::CI_ONLY)))->toBe([]);
});

it('SELFTEST-03: a broken check is a failed case and the run goes on; a case that throws is named by its class only', function () {
    app(OrganizationContext::class)->run($this->org->id, function () {
        $run = runningRun($this->admin);
        $cases = [
            new ClosureCase('ST-98', 'workflow', 'passes', 'ok', fn () => CaseOutcome::of(true, 'fine')),
            new ClosureCase('ST-97', 'workflow', 'fails', 'ok', fn () => CaseOutcome::all(['a' => true, 'b' => false], 'fine')),
            new ClosureCase('ST-96', 'workflow', 'throws', 'ok', fn () => throw new RuntimeException('secret text that must not be stored')),
        ];

        $counts = app(SelfTestRunner::class)->run($run, selfTestContext($this->admin), $cases);
        $rows = DB::table('security_test_results')->where('run_id', $run->id)->get()->keyBy('case_id');

        expect($counts)->toBe(['total' => 3, 'passed' => 1, 'failed' => 2])
            ->and($rows['ST-98']->passed)->toBeTrue()
            ->and($rows['ST-97']->passed)->toBeFalse()
            ->and($rows['ST-97']->actual)->toBe('failed: b')
            ->and(json_decode($rows['ST-97']->details, true))->toBe(['failed_checks' => ['b']])
            ->and($rows['ST-96']->passed)->toBeFalse()
            ->and($rows['ST-96']->actual)->toBe('error: RuntimeException')
            ->and(json_encode($rows))->not->toContain('secret text')
            ->and(SecurityTestRun::query()->findOrFail($run->id)->failed)->toBe(2);
    });
});

it('SELFTEST-04: a case is rolled back whether it passes or fails, and its outcome is kept', function () {
    app(OrganizationContext::class)->run($this->org->id, function () {
        $run = runningRun($this->admin);
        $made = [];
        $cases = [
            new ClosureCase('ST-98', 'workflow', 'makes a user and passes', 'ok', function (SelfTestContext $context) use (&$made) {
                $made[] = $context->temporaryUser('member')->id;

                return CaseOutcome::of(true, 'made one');
            }),
            new ClosureCase('ST-97', 'workflow', 'makes a user and fails', 'ok', function (SelfTestContext $context) use (&$made) {
                $made[] = $context->temporaryUser('member')->id;

                return CaseOutcome::of(false, 'made one and failed');
            }),
        ];

        app(SelfTestRunner::class)->run($run, selfTestContext($this->admin), $cases);

        expect($made)->toHaveCount(2)
            ->and(User::query()->whereIn('id', $made)->count())->toBe(0)
            ->and(DB::table('security_test_results')->where('run_id', $run->id)->pluck('actual')->all())->toBe(['made one', 'made one and failed']);
    });
});
