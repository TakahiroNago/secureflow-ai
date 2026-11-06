<?php

namespace App\Domain\Workflow;

use Normalizer;

/**
 * The approval hash, hash_version 1 (docs/security-design.md §9.2). The stored snapshot comes back from
 * jsonb with its keys in another order, so everything is normalized again before hashing.
 *
 * A plan that does not have exactly the designed shape is refused rather than hashed: a field nobody
 * approved must not be able to travel with the plan.
 */
final class PlanHasher
{
    public const HASH_VERSION = 1;

    private const DOMAIN = "secureflow.plan.v1\n";

    private const PLAN_KEYS = ['hash_version', 'organization_id', 'policy_version', 'revision_no', 'tasks', 'workflow_id'];

    private const TASK_KEYS = ['action_type', 'description', 'impact_summary', 'permissions', 'policy_decision', 'position', 'priority', 'steps', 'target_data', 'title'];

    private const TEXT_KEYS = ['action_type', 'description', 'impact_summary', 'policy_decision', 'priority', 'target_data', 'title'];

    private const JSON_FLAGS = JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

    /**
     * @param  array<array-key, mixed>  $plan
     * @return array<string, mixed> The form stored in workflow_revisions.plan_snapshot.
     *
     * @throws InvalidPlanException
     */
    public static function normalize(array $plan): array
    {
        self::assertKeys($plan, self::PLAN_KEYS);

        if ($plan['hash_version'] !== self::HASH_VERSION) {
            throw new InvalidPlanException('Unsupported hash_version.');
        }

        if (! is_int($plan['revision_no']) || $plan['revision_no'] < 1) {
            throw new InvalidPlanException('revision_no must be a positive integer.');
        }

        $tasks = $plan['tasks'];
        if (! is_array($tasks) || ! array_is_list($tasks)) {
            throw new InvalidPlanException('tasks must be a list.');
        }

        $tasks = array_map(self::normalizeTask(...), $tasks);
        usort($tasks, fn (array $a, array $b) => $a['position'] <=> $b['position']);

        $positions = array_column($tasks, 'position');
        if (count($positions) !== count(array_unique($positions))) {
            throw new InvalidPlanException('Task positions must be unique.');
        }

        return [
            'hash_version' => self::HASH_VERSION,
            'organization_id' => self::uuid($plan['organization_id']),
            'policy_version' => self::text($plan['policy_version']),
            'revision_no' => $plan['revision_no'],
            'tasks' => $tasks,
            'workflow_id' => self::uuid($plan['workflow_id']),
        ];
    }

    /**
     * @param  array<array-key, mixed>  $plan
     *
     * @throws InvalidPlanException
     */
    public static function canonicalJson(array $plan): string
    {
        return json_encode(self::normalize($plan), self::JSON_FLAGS);
    }

    /**
     * @param  array<array-key, mixed>  $plan
     * @return string 64 lowercase hexadecimal characters
     *
     * @throws InvalidPlanException
     */
    public static function hash(array $plan): string
    {
        return hash('sha256', self::DOMAIN.self::canonicalJson($plan));
    }

    /**
     * A snapshot that can no longer be normalized matches nothing.
     *
     * @param  array<array-key, mixed>  $snapshot
     */
    public static function matches(array $snapshot, string $hash): bool
    {
        try {
            return hash_equals(self::hash($snapshot), $hash);
        } catch (InvalidPlanException) {
            return false;
        }
    }

    /**
     * Keys are in byte order here, which is what the canonical form needs.
     *
     * @return array<string, mixed>
     */
    private static function normalizeTask(mixed $task): array
    {
        if (! is_array($task)) {
            throw new InvalidPlanException('A task must be an object.');
        }

        self::assertKeys($task, self::TASK_KEYS);

        if (! is_int($task['position'])) {
            throw new InvalidPlanException('position must be an integer.');
        }

        $normalized = ['position' => $task['position'], 'steps' => self::textList($task['steps'])];

        foreach (self::TEXT_KEYS as $key) {
            $normalized[$key] = self::text($task[$key]);
        }

        $permissions = self::textList($task['permissions']);
        sort($permissions, SORT_STRING);
        $normalized['permissions'] = $permissions;

        ksort($normalized, SORT_STRING);

        return $normalized;
    }

    /**
     * @param  array<array-key, mixed>  $values
     * @param  list<string>  $keys
     */
    private static function assertKeys(array $values, array $keys): void
    {
        $given = array_map('strval', array_keys($values));
        sort($given, SORT_STRING);

        if ($given !== $keys) {
            throw new InvalidPlanException('The plan does not have the designed fields.');
        }
    }

    /**
     * @return list<string>
     */
    private static function textList(mixed $values): array
    {
        if (! is_array($values) || ! array_is_list($values)) {
            throw new InvalidPlanException('Expected a list of strings.');
        }

        return array_map(self::text(...), $values);
    }

    private static function text(mixed $value): string
    {
        if (! is_string($value) || ! mb_check_encoding($value, 'UTF-8')) {
            throw new InvalidPlanException('Expected a valid UTF-8 string.');
        }

        // jsonb cannot store it, so the snapshot could never match the hash.
        if (str_contains($value, "\0")) {
            throw new InvalidPlanException('A string must not contain NUL.');
        }

        $normalized = Normalizer::normalize(str_replace(["\r\n", "\r"], "\n", $value), Normalizer::FORM_C);

        if (! is_string($normalized)) {
            throw new InvalidPlanException('A string could not be normalized.');
        }

        return $normalized;
    }

    private static function uuid(mixed $value): string
    {
        if (! is_string($value) || preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/D', $value) !== 1) {
            throw new InvalidPlanException('Expected a UUID.');
        }

        return strtolower($value);
    }
}
