<?php

namespace App\Http\Requests;

use App\Domain\Auth\PasswordPolicy;

final class LoginRequest extends StrictFormRequest
{
    /**
     * Format only, the same for every account. The password policy is not applied here, so an
     * older password can still log in and the response reveals nothing about it.
     *
     * @return array<string, list<string>>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email:rfc', 'not_regex:/[[:cntrl:]]/', 'max:254'],
            'password' => ['required', 'string', 'max:'.PasswordPolicy::MAX_LENGTH],
        ];
    }
}
