<?php

namespace App\Domain\Workflow;

enum WorkflowEvent: string
{
    case Submit = 'submit';
    case Approve = 'approve';
    case Reject = 'reject';
    case Edit = 'edit';
    case Reopen = 'reopen';
    case Execute = 'execute';
    case Complete = 'complete';
    case Fail = 'fail';
}
