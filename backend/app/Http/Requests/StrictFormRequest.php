<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;

/**
 * Unknown fields are rejected, not ignored (docs/api-design.md §1.3).
 */
abstract class StrictFormRequest extends FormRequest
{
    /**
     * @return array<string, mixed>
     */
    abstract public function rules(): array;

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator): void {
            $rules = $this->rules();

            foreach (array_keys($this->all()) as $field) {
                if (! array_key_exists($field, $rules)) {
                    $validator->errors()->add((string) $field, '不明な項目です。');
                }
            }
        });
    }
}
