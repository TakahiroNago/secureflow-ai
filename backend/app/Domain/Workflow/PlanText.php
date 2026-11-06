<?php

namespace App\Domain\Workflow;

use App\Security\Output\AiTaskSchema;

/**
 * The text of a plan, field by field, on its way to the scanner and back. A field is named by where it is,
 * counting from 1 as the screen does: "tasks.2.steps.1". Nothing here stores or logs the text.
 *
 * @phpstan-type TaskText array{title: string, description: string, steps: list<string>, target_data: string, impact_summary: string}
 */
final class PlanText
{
    public const TITLE_FIELD = 'title';

    /**
     * @param  list<TaskText>  $tasks
     * @return array<string, string>
     */
    public static function fields(array $tasks): array
    {
        $fields = [];

        foreach ($tasks as $index => $task) {
            $prefix = 'tasks.'.($index + 1).'.';

            foreach (array_keys(AiTaskSchema::TEXT_LIMITS) as $name) {
                $fields[$prefix.$name] = $task[$name];
            }

            foreach ($task['steps'] as $stepIndex => $step) {
                $fields[$prefix.'steps.'.($stepIndex + 1)] = $step;
            }
        }

        return $fields;
    }

    /**
     * The same plan with the masked text in place.
     *
     * @param  list<TaskText>  $tasks
     * @param  array<string, string>  $masked
     * @return list<TaskText>
     */
    public static function withMasked(array $tasks, array $masked): array
    {
        foreach ($tasks as $index => $task) {
            $prefix = 'tasks.'.($index + 1).'.';

            foreach (array_keys(AiTaskSchema::TEXT_LIMITS) as $name) {
                $task[$name] = $masked[$prefix.$name];
            }

            foreach (array_keys($task['steps']) as $stepIndex) {
                $task['steps'][$stepIndex] = $masked[$prefix.'steps.'.($stepIndex + 1)];
            }

            $tasks[$index] = $task;
        }

        return $tasks;
    }

    /**
     * Masking can make a text longer: "a@b.co" becomes "[EMAIL_REDACTED]". Cutting it could break the
     * replacement or change the meaning, so the caller refuses instead. Names only, never the text.
     *
     * @param  array<string, string>  $masked
     * @return list<string> The fields that no longer fit.
     */
    public static function tooLong(array $masked): array
    {
        $tooLong = [];

        foreach ($masked as $field => $text) {
            if (mb_strlen($text, 'UTF-8') > self::limitOf($field)) {
                $tooLong[] = $field;
            }
        }

        return $tooLong;
    }

    private static function limitOf(string $field): int
    {
        $name = explode('.', $field)[2] ?? '';

        return AiTaskSchema::TEXT_LIMITS[$name] ?? AiTaskSchema::STEP_LIMIT;
    }
}
