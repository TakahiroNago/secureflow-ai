<?php

namespace App\Http\Requests;

use Illuminate\Validation\Rule;

final class AiUsageSummaryRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['period' => ['sometimes', Rule::in(['day', 'month'])]];
    }
}
