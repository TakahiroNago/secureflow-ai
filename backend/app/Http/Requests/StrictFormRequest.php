<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;

/**
 * Unknown fields are rejected, not ignored (docs/api-design.md §1.3).
 */
abstract class StrictFormRequest extends FormRequest
{
    private const FIELD_NAME = '/^[a-z][a-z0-9_]{0,39}$/D';

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
                    // A name is only sent back when it looks like one: what was sent could be anything.
                    $name = preg_match(self::FIELD_NAME, (string) $field) === 1 ? (string) $field : 'unknown_field';
                    $validator->errors()->add($name, '不明な項目です。');
                }
            }
        });
    }
}
