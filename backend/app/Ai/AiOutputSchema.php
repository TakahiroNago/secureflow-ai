<?php

namespace App\Ai;

use App\Security\Output\AiTaskSchema;
use App\Security\Policy\ActionCatalog;

/**
 * The JSON Schema sent with a request, in the form strict Structured Outputs needs: every property required, and none
 * beyond them. It helps the model and decides nothing: AiTaskSchema checks the answer whatever this says, including
 * the lengths, which a strict schema cannot express. Forbidden actions are listed so that they are reported, not hidden.
 */
final class AiOutputSchema
{
    private const MAX_TASKS = 10;

    /**
     * @return array<string, mixed>
     */
    public static function definition(): array
    {
        $text = ['type' => 'string'];
        $list = fn (int $min, int $max) => ['type' => 'array', 'items' => $text, 'minItems' => $min, 'maxItems' => $max];

        $task = [
            'title' => $text,
            'description' => $text,
            'action_type' => ['type' => 'string', 'enum' => ActionCatalog::types()],
            'steps' => $list(AiTaskSchema::MIN_STEPS, AiTaskSchema::MAX_STEPS),
            'priority' => ['type' => 'string', 'enum' => AiTaskSchema::PRIORITIES],
            'requested_permissions' => $list(0, 20),
            'target_data' => $text,
            'impact_summary' => $text,
        ];

        return [
            'type' => 'object',
            'properties' => [
                'tasks' => [
                    'type' => 'array',
                    'minItems' => 1,
                    'maxItems' => self::MAX_TASKS,
                    'items' => [
                        'type' => 'object',
                        'properties' => $task,
                        'required' => array_keys($task),
                        'additionalProperties' => false,
                    ],
                ],
            ],
            'required' => ['tasks'],
            'additionalProperties' => false,
        ];
    }
}
