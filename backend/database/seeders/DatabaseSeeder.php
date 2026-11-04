<?php

namespace Database\Seeders;

use App\Models\Organization;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Initial data: an organization and its settings, safe to run again.
     *
     * This must never create a login-capable user (docs/architecture.md D18). The repository is
     * public, so known credentials must not exist. Users are created with `php artisan user:create`.
     */
    public function run(): void
    {
        $organization = Organization::query()->firstOrCreate(['name' => 'Default Organization']);

        $organization->settings()->firstOrCreate([], [
            'monthly_token_limit' => 1_000_000,
            'user_daily_request_limit' => 100,
            'max_input_chars' => 4000,
        ]);
    }
}
