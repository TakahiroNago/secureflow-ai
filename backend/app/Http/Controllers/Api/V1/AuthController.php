<?php

namespace App\Http\Controllers\Api\V1;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Auth\AuthenticatedSession;
use App\Domain\Auth\LoginService;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Support\Http\ProblemDetails;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class AuthController extends Controller
{
    public function __construct(
        private readonly LoginService $login,
        private readonly AuthenticatedSession $session,
        private readonly AuditLogger $audit,
    ) {}

    public function login(LoginRequest $request): JsonResponse|UserResource
    {
        $user = $this->login->attempt($request->string('email')->toString(), $request->string('password')->toString());

        if ($user === null) {
            return ProblemDetails::authFailed();
        }

        $this->session->start($request, $user);

        return new UserResource($user);
    }

    /**
     * The session ends first: a failing audit record must not keep it alive. Logging out involves no
     * credential check, so answering 204 here reveals nothing.
     */
    public function logout(Request $request): Response
    {
        /** @var User $user */
        $user = $request->user();

        $this->session->end($request);
        $this->audit->recordAfterTransaction(AuditEntry::byUser(AuditEventType::Logout, $user), 'logout_unrecorded');

        return response()->noContent();
    }

    public function me(Request $request): UserResource
    {
        return new UserResource($request->user());
    }
}
