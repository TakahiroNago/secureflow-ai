<?php

namespace App\Http\Requests;

final class ListTestRunsRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'cursor' => ['sometimes', 'string', 'max:1000'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
