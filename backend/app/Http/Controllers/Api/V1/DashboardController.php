<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Dashboard\DashboardSummary;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class DashboardController extends Controller
{
    public function summary(Request $request, DashboardSummary $summary): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        return response()->json(['data' => $summary->for($user)]);
    }
}
