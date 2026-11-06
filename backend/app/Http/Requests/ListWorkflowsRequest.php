<?php

namespace App\Http\Requests;

use App\Domain\Workflow\WorkflowStatus;
use Illuminate\Validation\Rule;

final class ListWorkflowsRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'status' => ['sometimes', Rule::enum(WorkflowStatus::class)],
            'cursor' => ['sometimes', 'string', 'max:1000'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
