<?php

namespace App\Security\Output;

use App\Security\Policy\ActionCatalog;
use App\Security\Policy\PolicyDecision;
use JsonException;
use stdClass;

/**
 * Step 1-4 of docs/security-design.md §7: parsing, the schema and the allow list. An unknown action is a
 * violation. A forbidden one is not: the task is returned marked forbidden, and cannot be submitted.
 *
 * Known limit: json_decode keeps the last of two equal keys without saying so. Telling would take a parser
 * of our own, and the value that is kept is checked like any other.
 */
final class OutputValidator
{
    /** Above the largest valid answer without \u escapes, about 170 KB, and checked before anything is parsed. */
    public const MAX_BYTES = 262144;

    /** A valid answer needs 4 levels: the object, tasks, a task, and steps. */
    private const MAX_DEPTH = 8;

    /**
     * @return list<ValidatedTask>
     *
     * @throws InvalidAiOutputException
     */
    public function validate(string $output): array
    {
        if (strlen($output) > self::MAX_BYTES) {
            throw new InvalidAiOutputException('too_large');
        }

        try {
            $root = json_decode($output, false, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidAiOutputException('malformed_json');
        }

        AiTaskSchema::assertValid($root);

        /** @var stdClass $root */
        return array_values(array_map(fn (stdClass $task) => $this->task($task), $root->tasks));
    }

    private function task(stdClass $task): ValidatedTask
    {
        return new ValidatedTask(
            title: $task->title,
            description: $task->description,
            actionType: $task->action_type,
            steps: $task->steps,
            priority: $task->priority,
            requestedPermissions: $task->requested_permissions,
            targetData: $task->target_data,
            impactSummary: $task->impact_summary,
            decision: ActionCatalog::decision($task->action_type) ?? PolicyDecision::Forbidden,
            permissions: ActionCatalog::permissions($task->action_type),
        );
    }
}
