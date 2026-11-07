<?php

namespace App\Domain\Workflow;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\User;
use App\Models\Workflow;

/**
 * A refused attempt, in a transaction of its own after the refusal has been decided. recordAfterTransaction does
 * not throw when the record cannot be written: the failure goes to the critical log, and the attempt is still
 * refused with the same answer (docs/security-design.md §16.1).
 */
final readonly class ApprovalDenials
{
    public function __construct(private AuditLogger $audit) {}

    public function record(User $user, Workflow $workflow, string $reasonCode): void
    {
        $this->audit->recordAfterTransaction(
            AuditEntry::byUserOn(AuditEventType::ApprovalDenied, $user, 'workflow', $workflow->id, ['reason_code' => $reasonCode], 'denied'),
            'approval_denied_unrecorded',
        );
    }
}
