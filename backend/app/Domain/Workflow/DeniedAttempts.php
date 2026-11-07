<?php

namespace App\Domain\Workflow;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\User;
use App\Models\Workflow;

/**
 * A refused decision or execution, in a transaction of its own after the refusal has been decided.
 * recordAfterTransaction does not throw when the record cannot be written: the failure goes to the critical log, and
 * the attempt is still refused with the same answer (docs/security-design.md §16.1).
 */
final readonly class DeniedAttempts
{
    public function __construct(private AuditLogger $audit) {}

    public function record(AuditEventType $type, User $user, Workflow $workflow, string $reasonCode): void
    {
        $this->audit->recordAfterTransaction(
            AuditEntry::byUserOn($type, $user, 'workflow', $workflow->id, ['reason_code' => $reasonCode], 'denied'),
            $type === AuditEventType::ExecutionDenied ? 'execution_denied_unrecorded' : 'approval_denied_unrecorded',
        );
    }
}
