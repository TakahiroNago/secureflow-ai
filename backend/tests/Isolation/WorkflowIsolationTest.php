<?php

use App\Models\Approval;
use App\Models\Organization;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Support\Organization\MissingOrganizationContextException;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;

/*
| ST-23, at the level of models and policies (docs/security-design.md §13). The check of every endpoint
| follows with the endpoints, in step 1-6.
*/

uses(DatabaseTransactions::class);

const TENANT_MODELS = [Workflow::class, WorkflowRevision::class, WorkflowTask::class, Approval::class, WorkflowExecution::class];

function organizationWithEverything(): array
{
    $org = Organization::factory()->create();
    $creator = userIn($org->id);
    $admin = userIn($org->id, 'admin');
    $workflow = workflowOf($creator);
    $revision = insertRevision(appDb(), $workflow);
    insertTask(appDb(), $workflow);
    $approval = insertApproval(appDb(), $workflow, $revision, $admin->id);
    insertExecution(appDb(), $workflow, $revision, $approval);

    return ['org' => $org, 'workflow' => $workflow];
}

beforeEach(function () {
    $this->a = organizationWithEverything();
    $this->b = organizationWithEverything();
});

it('shows each organization only its own rows', function (string $model) {
    foreach ([$this->a, $this->b] as $side) {
        $rows = app(OrganizationContext::class)->run($side['org']->id, fn () => $model::query()->get());

        expect($rows)->toHaveCount(1)
            ->and($rows->first()->organization_id)->toBe($side['org']->id);
    }
})->with(TENANT_MODELS);

it('fails closed: without a context, no query runs at all', function (string $model) {
    expect(fn () => $model::query()->get())->toThrow(MissingOrganizationContextException::class);
})->with(TENANT_MODELS);

it('fails closed for every way to read a row by id', function () {
    $id = $this->a['workflow']->id;

    expect(fn () => Workflow::query()->find($id))->toThrow(MissingOrganizationContextException::class)
        ->and(fn () => Workflow::query()->whereKey($id)->exists())->toThrow(MissingOrganizationContextException::class)
        ->and(fn () => Workflow::query()->whereKey($id)->update(['title' => 'x']))->toThrow(MissingOrganizationContextException::class);
});

it('finds another organization\'s row by id from nowhere', function () {
    $idOfA = $this->a['workflow']->id;

    app(OrganizationContext::class)->run($this->b['org']->id, function () use ($idOfA) {
        expect(Workflow::query()->find($idOfA))->toBeNull()
            ->and(Workflow::query()->whereKey($idOfA)->update(['title' => 'changed']))->toBe(0)
            ->and(Workflow::query()->whereKey($idOfA)->exists())->toBeFalse();
    });

    expect(appDb()->table('workflows')->where('id', $idOfA)->value('title'))->not->toBe('changed');
});

it('keeps the scope on relations', function () {
    $tasks = app(OrganizationContext::class)->run($this->b['org']->id, fn () => $this->a['workflow']->tasks()->get());

    expect($tasks)->toBeEmpty();
});

it('puts a new row in the current organization', function () {
    $workflow = workflowOf(userIn($this->a['org']->id));

    expect($workflow->organization_id)->toBe($this->a['org']->id);
});

it('refuses to create a row for another organization, or with no context', function () {
    $creator = userIn($this->a['org']->id);
    $attributes = ['created_by' => $creator->id, 'organization_id' => $this->b['org']->id];

    expect(fn () => app(OrganizationContext::class)->run($this->a['org']->id, fn () => Workflow::factory()->create($attributes)))
        ->toThrow(LogicException::class, 'another organization')
        ->and(fn () => Workflow::factory()->create(['created_by' => $creator->id]))
        ->toThrow(MissingOrganizationContextException::class);
});

it('refuses to move a row to another organization', function () {
    $workflow = $this->a['workflow'];
    $workflow->organization_id = $this->b['org']->id;

    expect(fn () => app(OrganizationContext::class)->run($this->a['org']->id, fn () => $workflow->save()))
        ->toThrow(LogicException::class, 'another organization');
});

it('does not let request data choose the organization or the state', function () {
    expect((new Workflow)->getFillable())->toBe(['title', 'source_input_masked'])
        ->and((new Workflow)->fill(['organization_id' => 'x', 'status' => 'approved', 'created_by' => 'x', 'lock_version' => 9])->getAttributes())->toBe(['lock_version' => 0]);
});

it('restores the previous context, even when the callback fails', function () {
    $context = app(OrganizationContext::class);
    $context->set($this->a['org']->id);

    expect(fn () => $context->run($this->b['org']->id, fn () => throw new RuntimeException('boom')))->toThrow(RuntimeException::class);

    expect($context->id())->toBe($this->a['org']->id);
});

it('starts every request from an empty context', function () {
    $this->app->forgetScopedInstances();

    expect(fn () => app(OrganizationContext::class)->id())->toThrow(MissingOrganizationContextException::class);
});
