<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Auth\AuthenticatedSession;
use App\Http\Controllers\Controller;
use App\Http\Requests\ChangePasswordRequest;
use App\Models\User;
use App\Support\Http\ProblemDetails;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;

final class AccountPasswordController extends Controller
{
    public function __construct(private readonly AuthenticatedSession $session) {}

    /**
     * docs/api-design.md §3.1.2. A wrong current password does not count towards the account lock:
     * the caller already holds a session, and the rate limit stops guessing.
     */
    public function update(ChangePasswordRequest $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $newPassword = $request->string('new_password')->toString();

        if (! Hash::check($request->string('current_password')->toString(), $user->getAuthPassword())) {
            return ProblemDetails::response(422, 'CURRENT_PASSWORD_INVALID', 'Current password is invalid', '現在のパスワードが正しくありません。');
        }

        if (Hash::check($newPassword, $user->getAuthPassword())) {
            return ProblemDetails::response(422, 'VALIDATION_FAILED', 'Validation failed', '入力内容を確認してください。', [
                'new_password' => ['現在のパスワードと異なるものを指定してください。'],
            ]);
        }

        $user->forceFill(['password' => $newPassword, 'password_changed_at' => now()])->save();

        $this->session->keepAfterPasswordChange($request, $user);

        return new JsonResponse(['data' => ['password_changed_at' => $user->password_changed_at?->toIso8601String()]]);
    }
}
