<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;

/**
 * For tests only. Seeders must not use this: no fixed login-capable user may exist outside tests.
 *
 * @extends Factory<User>
 */
class UserFactory extends Factory
{
    public const TEST_PASSWORD = 'correct horse battery staple';

    /**
     * The hash is computed once per run.
     */
    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'password' => static::$password ??= Hash::make(self::TEST_PASSWORD),
            'role' => 'member',
        ];
    }

    public function admin(): static
    {
        return $this->state(['role' => 'admin']);
    }

    public function auditor(): static
    {
        return $this->state(['role' => 'auditor']);
    }

    public function inactive(): static
    {
        return $this->state(['is_active' => false]);
    }

    public function locked(): static
    {
        return $this->state(fn () => ['locked_until' => now()->addMinutes(15)]);
    }
}
