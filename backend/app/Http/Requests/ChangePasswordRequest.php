<?php

namespace App\Http\Requests;

use App\Domain\Auth\PasswordPolicy;

final class ChangePasswordRequest extends StrictFormRequest
{
    /**
     * @return array<string, list<mixed>>
     */
    public function rules(): array
    {
        return [
            'current_password' => ['required', 'string', 'max:'.PasswordPolicy::MAX_LENGTH],
            'new_password' => PasswordPolicy::rules(),
        ];
    }
}
