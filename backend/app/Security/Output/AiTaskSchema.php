<?php

namespace App\Security\Output;

use App\Security\Policy\ActionCatalog;
use stdClass;

/**
 * The shape of an AI answer (docs/security-design.md §7). It works on decoded objects and not on PHP arrays,
 * which could not tell {"0": ...} from [...]. Lengths count characters, not bytes.
 */
final class AiTaskSchema
{
    private const MIN_TASKS = 1;

    private const MAX_TASKS = 10;

    private const MIN_STEPS = 1;

    private const MAX_STEPS = 10;

    private const MAX_REQUESTED_PERMISSIONS = 20;

    private const PRIORITIES = ['low', 'medium', 'high'];

    private const TEXT_LIMITS = ['title' => 100, 'description' => 1000, 'target_data' => 500, 'impact_summary' => 1000];

    private const STEP_LIMIT = 200;

    private const PERMISSION_LIMIT = 50;

    private const TASK_KEYS = ['action_type', 'description', 'impact_summary', 'priority', 'requested_permissions', 'steps', 'target_data', 'title'];

    /**
     * @throws InvalidAiOutputException
     */
    public static function assertValid(mixed $root): void
    {
        if (! $root instanceof stdClass) {
            throw new InvalidAiOutputException('not_an_object');
        }

        self::assertKeys($root, ['tasks'], '');
        $tasks = $root->tasks;

        if (! is_array($tasks)) {
            throw new InvalidAiOutputException('not_a_list', 'tasks');
        }
        if (count($tasks) < self::MIN_TASKS || count($tasks) > self::MAX_TASKS) {
            throw new InvalidAiOutputException('task_count', 'tasks');
        }

        foreach ($tasks as $index => $task) {
            self::assertTask($task, 'tasks['.$index.']');
        }
    }

    private static function assertTask(mixed $task, string $position): void
    {
        if (! $task instanceof stdClass) {
            throw new InvalidAiOutputException('not_an_object', $position);
        }

        self::assertKeys($task, self::TASK_KEYS, $position);

        foreach (self::TEXT_LIMITS as $key => $limit) {
            self::assertText($task->{$key}, $limit, $position.'.'.$key);
        }

        self::assertList($task->steps, self::MIN_STEPS, self::MAX_STEPS, self::STEP_LIMIT, $position.'.steps');
        self::assertList($task->requested_permissions, 0, self::MAX_REQUESTED_PERMISSIONS, self::PERMISSION_LIMIT, $position.'.requested_permissions');

        if (! is_string($task->priority) || ! in_array($task->priority, self::PRIORITIES, true)) {
            throw new InvalidAiOutputException('unknown_priority', $position.'.priority');
        }
        // Exactly as listed: no trimming and no case folding.
        if (! is_string($task->action_type) || ! ActionCatalog::has($task->action_type)) {
            throw new InvalidAiOutputException('unknown_action', $position.'.action_type');
        }
    }

    /**
     * @param  list<string>  $expected
     */
    private static function assertKeys(stdClass $object, array $expected, string $position): void
    {
        $keys = array_map('strval', array_keys(get_object_vars($object)));

        if (array_diff($keys, $expected) !== []) {
            throw new InvalidAiOutputException('unknown_key', $position);
        }
        if (array_diff($expected, $keys) !== []) {
            throw new InvalidAiOutputException('missing_key', $position);
        }
    }

    private static function assertList(mixed $list, int $min, int $max, int $itemLimit, string $position): void
    {
        if (! is_array($list)) {
            throw new InvalidAiOutputException('not_a_list', $position);
        }
        if (count($list) < $min || count($list) > $max) {
            throw new InvalidAiOutputException('item_count', $position);
        }

        foreach ($list as $index => $item) {
            self::assertText($item, $itemLimit, $position.'['.$index.']');
        }
    }

    private static function assertText(mixed $value, int $limit, string $position): void
    {
        if (! is_string($value)) {
            throw new InvalidAiOutputException('not_a_string', $position);
        }
        if (mb_strlen($value, 'UTF-8') > $limit) {
            throw new InvalidAiOutputException('too_long', $position);
        }
        // Control characters other than a line feed and a tab.
        if (preg_match('/[^\P{Cc}\n\t]/u', $value) === 1) {
            throw new InvalidAiOutputException('control_character', $position);
        }
        // Includes the empty string. Spaces of every kind and invisible characters do not count as text.
        if (preg_match('/[^\s\p{Z}\p{Cf}]/u', $value) !== 1) {
            throw new InvalidAiOutputException('blank', $position);
        }
    }
}
