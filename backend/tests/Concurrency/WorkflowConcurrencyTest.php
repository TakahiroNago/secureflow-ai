<?php

use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowTransition;
use App\Models\Organization;
use App\Support\Organization\OrganizationContext;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Process;

/*
| docs/security-design.md §11, with real processes and committed rows, so no test transaction here.
*/

afterEach(function () {
    resetWorkflowTables();

    foreach ($this->users ?? [] as $user) {
        ownerDb()->table('users')->where('id', $user->id)->delete();
    }
    if (isset($this->org)) {
        ownerDb()->table('organizations')->where('id', $this->org->id)->delete();
    }
});

function transitionInProcess(string $organizationId, string $workflowId, string $event): string
{
    return 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";'
        .' $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
        .' app(App\Support\Organization\OrganizationContext::class)->set("'.$organizationId.'");'
        .' $workflow = App\Models\Workflow::query()->findOrFail("'.$workflowId.'");'
        .' usleep(300000);'
        .' Illuminate\Support\Facades\DB::transaction(fn () => app(App\Domain\Workflow\WorkflowTransition::class)->apply($workflow, App\Domain\Workflow\WorkflowEvent::from("'.$event.'")));';
}

it('lets exactly one of several concurrent transitions through', function () {
    $this->org = Organization::factory()->create();
    $this->users = [userIn($this->org->id)];
    $workflow = workflowOf($this->users[0]);
    $script = transitionInProcess($this->org->id, $workflow->id, 'submit');

    $results = Process::concurrently(function ($pool) use ($script) {
        foreach (range(1, 4) as $ignored) {
            $pool->path(base_path())->command(['php', '-r', $script]);
        }
    });

    $succeeded = collect($results)->filter(fn ($result) => $result->successful());

    expect($succeeded)->toHaveCount(1);

    foreach (collect($results)->reject(fn ($result) => $result->successful()) as $result) {
        expect($result->errorOutput().$result->output())->toContain('WorkflowConflictException');
    }

    $row = appDb()->table('workflows')->where('id', $workflow->id)->first();

    expect($row->status)->toBe('pending')->and($row->lock_version)->toBe(1);
});

it('holds the row while a transition is open, so that another waits rather than passes it', function () {
    $this->org = Organization::factory()->create();
    $this->users = [userIn($this->org->id)];
    $workflow = workflowOf($this->users[0]);

    config(['database.connections.second' => config('database.connections.pgsql')]);
    $second = DB::connection('second');

    try {
        app(OrganizationContext::class)->run($this->org->id, fn () => DB::transaction(function () use ($workflow, $second) {
            app(WorkflowTransition::class)->apply($workflow, WorkflowEvent::Submit);

            $second->beginTransaction();
            $second->statement("SET LOCAL lock_timeout = '200ms'");

            try {
                $second->select('SELECT id FROM workflows WHERE id = ? FOR UPDATE', [$workflow->id]);
                $this->fail('The second connection should have had to wait for the row.');
            } catch (QueryException $exception) {
                expect($exception->getCode())->toBe('55P03');
            } finally {
                $second->rollBack();
            }

            // Not committed yet, so the other connection still reads the old state.
            expect($second->table('workflows')->where('id', $workflow->id)->value('status'))->toBe('draft');
        }));
    } finally {
        DB::purge('second');
    }

    expect(appDb()->table('workflows')->where('id', $workflow->id)->value('status'))->toBe('pending');
});

it('rolls the transition back with the transaction it belongs to', function () {
    $this->org = Organization::factory()->create();
    $this->users = [userIn($this->org->id)];
    $workflow = workflowOf($this->users[0]);

    try {
        app(OrganizationContext::class)->run($this->org->id, fn () => DB::transaction(function () use ($workflow) {
            app(WorkflowTransition::class)->apply($workflow, WorkflowEvent::Submit);

            throw new RuntimeException('the rest of the work failed');
        }));
    } catch (RuntimeException) {
        // Expected.
    }

    $row = appDb()->table('workflows')->where('id', $workflow->id)->first();

    expect($row->status)->toBe('draft')->and($row->lock_version)->toBe(0);
});

it('lets one of two concurrent decisions through on the same revision', function () {
    $this->org = Organization::factory()->create();
    $this->users = [userIn($this->org->id), userIn($this->org->id, 'admin'), userIn($this->org->id, 'admin')];
    $workflow = workflowOf($this->users[0]);
    $revision = insertRevision(appDb(), $workflow);

    config(['database.connections.second' => config('database.connections.pgsql')]);
    $second = DB::connection('second');

    try {
        DB::transaction(function () use ($workflow, $revision, $second) {
            insertApproval(appDb(), $workflow, $revision, $this->users[1]->id);

            $second->beginTransaction();
            $second->statement("SET LOCAL lock_timeout = '200ms'");

            // The second decision waits on the unique key of the first, which has not committed.
            try {
                insertApproval($second, $workflow, $revision, $this->users[2]->id);
                $this->fail('The second decision should not have passed.');
            } catch (QueryException $exception) {
                expect($exception->getCode())->toBe('55P03');
            } finally {
                $second->rollBack();
            }
        });

        $error = dbError($second, fn ($db) => insertApproval($db, $workflow, $revision, $this->users[2]->id));

        expect($error)->not->toBeNull()->and($error->getCode())->toBe('23505');
    } finally {
        DB::purge('second');
    }

    expect(appDb()->table('approvals')->where('workflow_revision_id', $revision)->count())->toBe(1);
});
