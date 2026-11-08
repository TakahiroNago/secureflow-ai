<?php

namespace App\Ai\Evaluation;

use App\Models\Organization;
use App\Models\OrganizationSetting;
use App\Models\User;
use App\Support\Organization\OrganizationContext;
use Illuminate\Support\Str;

/**
 * Where the evaluation runs: an organization of its own, with limits wide enough for the set, and one member who
 * cannot log in, because the password is random and kept by nobody. Both are reused on the next run.
 */
final readonly class EvaluationWorkspace
{
    public const ORGANIZATION = 'AI Evaluation';

    public const EMAIL = 'ai-evaluation@example.invalid';

    public const MONTHLY_TOKEN_LIMIT = 5_000_000;

    public const USER_DAILY_REQUEST_LIMIT = 500;

    public function __construct(private OrganizationContext $context) {}

    public function user(): User
    {
        $organization = Organization::query()->firstOrCreate(['name' => self::ORGANIZATION]);

        return $this->context->run($organization->id, function () use ($organization): User {
            $settings = $organization->settings()->firstOrCreate([], OrganizationSetting::DEFAULTS);
            $settings->forceFill([
                'monthly_token_limit' => self::MONTHLY_TOKEN_LIMIT,
                'user_daily_request_limit' => self::USER_DAILY_REQUEST_LIMIT,
            ])->save();

            $user = User::query()->where('email', self::EMAIL)->first();

            if ($user === null) {
                $user = new User;
                $user->forceFill([
                    'organization_id' => $organization->id,
                    'name' => self::ORGANIZATION,
                    'email' => self::EMAIL,
                    'password' => Str::random(64),
                    'role' => 'member',
                    'password_changed_at' => now(),
                ])->save();
            }

            return $user->refresh();
        });
    }
}
