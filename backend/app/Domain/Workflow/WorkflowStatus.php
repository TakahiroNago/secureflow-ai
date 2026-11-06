<?php

namespace App\Domain\Workflow;

enum WorkflowStatus: string
{
    case Draft = 'draft';
    case Pending = 'pending';
    case Approved = 'approved';
    case Running = 'running';
    case Completed = 'completed';
    case Rejected = 'rejected';
    case Failed = 'failed';
}
