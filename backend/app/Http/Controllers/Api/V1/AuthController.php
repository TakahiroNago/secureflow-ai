<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Auth\AuthenticatedSession;
use App\Domain\Auth\LoginService;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Resources\UserResource;
use App\Support\Http\ProblemDetails;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class AuthController extends Controller
{
    public function __construct(
        private readonly LoginService $login,
        private readonly AuthenticatedSession $session,
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

    public function logout(Request $request): Response
    {
        $this->session->end($request);

        return response()->noContent();
    }

    public function me(Request $request): UserResource
    {
        return new UserResource($request->user());
    }
}
