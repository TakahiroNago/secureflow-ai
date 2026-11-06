<?php

use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowStateMachine;
use App\Domain\Workflow\WorkflowStatus;

/*
| docs/architecture.md §9. Written out separately from the implementation, so that a change to the
| transition table has to be made twice. Every combination of state and event is checked.
*/

const ALLOWED_TRANSITIONS = [
    'draft' => ['submit' => 'pending', 'edit' => 'draft'],
    'pending' => ['approve' => 'approved', 'reject' => 'rejected', 'edit' => 'draft'],
    'approved' => ['edit' => 'draft', 'execute' => 'running'],
    'running' => ['complete' => 'completed', 'fail' => 'failed'],
    'completed' => [],
    'rejected' => ['reopen' => 'draft'],
    'failed' => ['reopen' => 'draft'],
];

dataset('every state and event', function () {
    foreach (WorkflowStatus::cases() as $status) {
        foreach (WorkflowEvent::cases() as $event) {
            yield "{$status->value} + {$event->value}" => [$status, $event];
        }
    }
});

it('covers all 56 combinations', function () {
    expect(count(WorkflowStatus::cases()) * count(WorkflowEvent::cases()))->toBe(56);
});

it('allows the designed transitions and refuses all others with 409', function (WorkflowStatus $status, WorkflowEvent $event) {
    $expected = ALLOWED_TRANSITIONS[$status->value][$event->value] ?? null;

    if ($expected !== null) {
        expect(WorkflowStateMachine::next($status, $event)->value)->toBe($expected);

        return;
    }

    try {
        WorkflowStateMachine::next($status, $event);
        $this->fail('The transition should have been refused.');
    } catch (WorkflowConflictException $exception) {
        expect($exception->problemCode)->toBe('WORKFLOW_INVALID_STATE');
    }
})->with('every state and event');

it('has no way out of a completed workflow, and no way to edit a running one', function (WorkflowEvent $event) {
    expect(fn () => WorkflowStateMachine::next(WorkflowStatus::Completed, $event))->toThrow(WorkflowConflictException::class);
})->with(WorkflowEvent::cases());

it('cannot reach approved or running without going through the approval', function () {
    foreach (WorkflowStatus::cases() as $status) {
        foreach (WorkflowEvent::cases() as $event) {
            try {
                $next = WorkflowStateMachine::next($status, $event);
            } catch (WorkflowConflictException) {
                continue;
            }

            if ($next === WorkflowStatus::Approved) {
                expect([$status, $event])->toBe([WorkflowStatus::Pending, WorkflowEvent::Approve]);
            }
            if ($next === WorkflowStatus::Running) {
                expect([$status, $event])->toBe([WorkflowStatus::Approved, WorkflowEvent::Execute]);
            }
        }
    }
});
