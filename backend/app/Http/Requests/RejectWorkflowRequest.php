<?php

namespace App\Http\Requests;

final class RejectWorkflowRequest extends DecisionRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->planRules(),
            'reason' => ['required', 'string', $this->textRule()],
        ];
    }
}
