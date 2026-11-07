<?php

namespace App\Http\Requests;

use Illuminate\Validation\Rule;

final class ListApprovalsRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'status' => ['sometimes', Rule::in(['pending'])],
            'cursor' => ['sometimes', 'string', 'max:1000'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
