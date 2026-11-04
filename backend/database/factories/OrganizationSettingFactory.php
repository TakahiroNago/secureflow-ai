<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\OrganizationSetting;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<OrganizationSetting>
 */
class OrganizationSettingFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'monthly_token_limit' => 1_000_000,
            'user_daily_request_limit' => 100,
            'max_input_chars' => 4000,
        ];
    }
}
