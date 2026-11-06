<?php

namespace App\Domain\Workflow;

use App\Audit\TransactionBoundary;
use App\Models\Workflow;
use LogicException;

/**
 * Applies a transition under the row lock, with a conditional update (docs/security-design.md §11).
 * The caller owns the transaction, so that the revision and the audit record commit with the change.
 */
final readonly class WorkflowTransition
{
    public function __construct(private TransactionBoundary $boundary) {}

    /**
     * @throws WorkflowConflictException when the workflow changed since it was read, or the event is not allowed
     */
    public function apply(Workflow $workflow, WorkflowEvent $event): void
    {
        if ($this->boundary->businessLevel() < 1) {
            throw new LogicException('A workflow transition needs an open transaction.');
        }

        $current = Workflow::query()->whereKey($workflow->getKey())->lockForUpdate()->firstOrFail();

        if ($current->lock_version !== $workflow->lock_version) {
            throw WorkflowConflictException::revisionConflict();
        }

        $next = WorkflowStateMachine::next($current->status, $event);

        $updated = Workflow::query()
            ->whereKey($current->getKey())
            ->where('status', $current->status->value)
            ->where('lock_version', $current->lock_version)
            ->update(['status' => $next->value, 'lock_version' => $current->lock_version + 1]);

        if ($updated !== 1) {
            throw WorkflowConflictException::revisionConflict();
        }

        $workflow->refresh();
    }
}
