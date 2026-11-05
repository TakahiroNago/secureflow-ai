<?php

namespace App\Http\Controllers\Api\V1;

use App\Audit\OutageLog;
use App\Domain\Auth\AuthenticatedSession;
use App\Domain\Auth\PasswordChangeResult;
use App\Domain\Auth\PasswordChangeService;
use App\Http\Controllers\Controller;
use App\Http\Requests\ChangePasswordRequest;
use App\Models\User;
use App\Support\Http\ProblemDetails;
use App\Support\Http\ServiceUnavailableException;
use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;

final class AccountPasswordController extends Controller
{
    public function __construct(
        private readonly AuthenticatedSession $session,
        private readonly PasswordChangeService $passwords,
        private readonly OutageLog $log,
    ) {}

    /**
     * docs/api-design.md §3.1.2. A wrong current password does not count towards the account lock:
     * the caller already holds a session, and the rate limit stops guessing.
     */
    public function update(ChangePasswordRequest $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $key = (string) $request->header('Idempotency-Key');

        if (! Str::isUuid($key)) {
            return ProblemDetails::response(422, 'VALIDATION_FAILED', 'Validation failed', '入力内容を確認してください。', [
                'idempotency_key' => ['Idempotency-Key ヘッダに UUID を指定してください。'],
            ]);
        }

        $owner = (string) Str::uuid7();
        $result = $this->passwords->change(
            $user,
            $key,
            $request->session()->getId(),
            $owner,
            $request->string('current_password')->toString(),
            $request->string('new_password')->toString(),
        );

        return match ($result->status) {
            PasswordChangeResult::CURRENT_INVALID => ProblemDetails::response(422, 'CURRENT_PASSWORD_INVALID', 'Current password is invalid', '現在のパスワードが正しくありません。'),
            PasswordChangeResult::SAME_AS_CURRENT => ProblemDetails::response(422, 'VALIDATION_FAILED', 'Validation failed', '入力内容を確認してください。', [
                'new_password' => ['現在のパスワードと異なるものを指定してください。'],
            ]),
            PasswordChangeResult::KEY_CONFLICT => ProblemDetails::response(409, 'IDEMPOTENCY_KEY_CONFLICT', 'Idempotency key conflict', '同じキーで異なる内容が送信されました。'),
            default => $this->completed($request, $result, $owner),
        };
    }

    /**
     * After the commit. If the session cannot be saved this throws, and the answer is 503 with the
     * change left committed: a retry with the same key finds it in the database and gets 200.
     */
    private function completed(ChangePasswordRequest $request, PasswordChangeResult $result, string $owner): JsonResponse
    {
        // A session from before the change may have passed its checks just before the commit.
        if ($result->replayed && ! $this->session->holdsPassword($request, (string) $result->passwordHash)) {
            $this->session->end($request);

            throw new AuthenticationException;
        }

        try {
            $finished = $this->session->finishPasswordChange($request, (string) $result->passwordHash, $owner);
        } catch (ServiceUnavailableException $exception) {
            $this->log->occurrence('auth.password_change_session_failed', 'auth.password_change_session_failed', [
                'outcome' => 'password_change_committed_session_failed',
            ]);

            throw $exception;
        }

        // A parallel request of this session rotated it. The change stands, and that request has the session.
        if (! $finished) {
            throw new AuthenticationException;
        }

        return new JsonResponse(['data' => [
            'password_changed_at' => CarbonImmutable::parse((string) $result->changedAt)->toIso8601String(),
        ]]);
    }
}
