<?php

use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowStatus;
use App\Domain\Workflow\WorkflowTransition;
use App\Models\User;
use App\Models\Workflow;
use App\Support\Organization\OrganizationContext;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;

/*
| docs/security-design.md §11. The real race is in tests/Concurrency.
*/

uses(DatabaseTransactions::class);

function inOrganizationOf(Workflow $workflow, Closure $callback): mixed
{
    return app(OrganizationContext::class)->run($workflow->organization_id, $callback);
}

beforeEach(function () {
    $this->workflow = workflowOf(User::factory()->create());
});

it('moves the state and raises the version', function () {
    inOrganizationOf($this->workflow, fn () => DB::transaction(
        fn () => app(WorkflowTransition::class)->apply($this->workflow, WorkflowEvent::Submit),
    ));

    expect($this->workflow->status)->toBe(WorkflowStatus::Pending)
        ->and($this->workflow->lock_version)->toBe(1)
        ->and(DB::table('workflows')->where('id', $this->workflow->id)->value('status'))->toBe('pending');
});

it('refuses to run outside a transaction', function () {
    expect(fn () => inOrganizationOf($this->workflow, fn () => app(WorkflowTransition::class)->apply($this->workflow, WorkflowEvent::Submit)))
        ->toThrow(LogicException::class, 'open transaction');

    expect(DB::table('workflows')->where('id', $this->workflow->id)->value('status'))->toBe('draft');
});

it('refuses an event the state does not allow, and changes nothing', function () {
    $attempt = fn () => inOrganizationOf($this->workflow, fn () => DB::transaction(
        fn () => app(WorkflowTransition::class)->apply($this->workflow, WorkflowEvent::Approve),
    ));

    expect($attempt)->toThrow(WorkflowConflictException::class);
    expect(DB::table('workflows')->where('id', $this->workflow->id)->value('lock_version'))->toBe(0);
});

it('refuses a copy that was read before the last change', function () {
    $stale = $this->workflow->replicate()->setRawAttributes($this->workflow->getAttributes(), true);
    $stale->exists = true;

    inOrganizationOf($this->workflow, fn () => DB::transaction(
        fn () => app(WorkflowTransition::class)->apply($this->workflow, WorkflowEvent::Submit),
    ));

    try {
        inOrganizationOf($this->workflow, fn () => DB::transaction(
            fn () => app(WorkflowTransition::class)->apply($stale, WorkflowEvent::Edit),
        ));
        $this->fail('The stale copy should have been refused.');
    } catch (WorkflowConflictException $exception) {
        expect($exception->problemCode)->toBe('REVISION_CONFLICT');
    }

    expect(DB::table('workflows')->where('id', $this->workflow->id)->value('status'))->toBe('pending');
});

it('cannot transition a workflow of another organization: it is not found', function () {
    $other = User::factory()->create();

    $attempt = fn () => app(OrganizationContext::class)->run($other->organization_id, fn () => DB::transaction(
        fn () => app(WorkflowTransition::class)->apply($this->workflow, WorkflowEvent::Submit),
    ));

    expect($attempt)->toThrow(ModelNotFoundException::class);
    expect(DB::table('workflows')->where('id', $this->workflow->id)->value('status'))->toBe('draft');
});
