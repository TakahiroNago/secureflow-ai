<?php

namespace Database\Factories;

use App\Domain\Workflow\WorkflowStatus;
use App\Models\Workflow;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * For tests only. The organization comes from the current context and created_by must be given.
 *
 * @extends Factory<Workflow>
 */
class WorkflowFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'title' => fake()->sentence(3),
            'source_input_masked' => fake()->paragraph(),
            'status' => WorkflowStatus::Draft,
        ];
    }
}
