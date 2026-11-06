<?php

namespace App\Domain\Workflow;

/**
 * The allowed transitions (docs/architecture.md §9). Anything not listed is refused. Who may trigger a
 * transition is decided by WorkflowPolicy, and what else must hold by the step that adds the operation.
 */
final class WorkflowStateMachine
{
    private const TRANSITIONS = [
        'submit' => ['draft' => WorkflowStatus::Pending],
        'approve' => ['pending' => WorkflowStatus::Approved],
        'reject' => ['pending' => WorkflowStatus::Rejected],
        'edit' => [
            'draft' => WorkflowStatus::Draft,
            'pending' => WorkflowStatus::Draft,
            'approved' => WorkflowStatus::Draft,
        ],
        'reopen' => [
            'rejected' => WorkflowStatus::Draft,
            'failed' => WorkflowStatus::Draft,
        ],
        'execute' => ['approved' => WorkflowStatus::Running],
        'complete' => ['running' => WorkflowStatus::Completed],
        'fail' => ['running' => WorkflowStatus::Failed],
    ];

    /**
     * @throws WorkflowConflictException when the event is not allowed in this state
     */
    public static function next(WorkflowStatus $from, WorkflowEvent $event): WorkflowStatus
    {
        return self::TRANSITIONS[$event->value][$from->value] ?? throw WorkflowConflictException::invalidState();
    }
}
