<?php

namespace App\Security\Output;

use App\Domain\Workflow\PlanText;
use App\Security\Policy\PolicyDecision;
use App\Security\Scanning\InputFinding;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\ScanAction;
use App\Security\Scanning\ScanFailure;
use App\Security\Scanning\Severity;
use App\Security\Scanning\TextNormalizer;
use SensitiveParameter;

/**
 * docs/security-design.md §7: everything between the AI's answer and what is kept. The order matters.
 *
 * The canary is looked for first, so that a leak in a broken answer is still seen as a leak, and again after
 * markup is gone. Markup goes before the scan, because the scan has to read exactly what will be stored: removing a
 * tag could join the two halves of a secret. requested_permissions is written by the AI like everything else, so
 * it is scanned like everything else, although it never authorizes anything.
 *
 * What a canary cannot show: a translation, a summary or a part of the prompt that leaves the canary out.
 */
final readonly class OutputScanner
{
    public const RULE_CANARY = 'OUT-CANARY';

    public const RULE_MARKUP = 'OUT-MARKUP';

    public const RULE_PERMISSION_OVER = 'OUT-PERM-OVER';

    public const RULE_PERMISSION_UNDER = 'OUT-PERM-UNDER';

    public const RULE_FORBIDDEN = 'OUT-FORBIDDEN';

    /** Large enough for any answer that can be valid. A leak past this is not stored either: the answer is refused. */
    private const CANARY_SEARCH_BYTES = OutputValidator::MAX_BYTES;

    /** Only depth is limited here: this is a look for the canary, and the validator decides what is acceptable. */
    private const CANARY_SEARCH_DEPTH = 64;

    /** Above every limit of the schema. Only blankness is being asked about after stripping. */
    private const ANY_LENGTH = 1000000;

    public function __construct(
        private OutputValidator $validator = new OutputValidator,
        private InputScanner $scanner = new InputScanner,
        private MarkupStripper $stripper = new MarkupStripper,
        private TextNormalizer $normalizer = new TextNormalizer,
    ) {}

    /**
     * @throws InvalidAiOutputException
     */
    public function scan(#[SensitiveParameter] string $output, #[SensitiveParameter] string $canary): ScannedOutput
    {
        if ($this->leaksInAnswer($output, $canary)) {
            return $this->canaryLeak();
        }

        [$tasks, $markupFields] = $this->stripped($this->validator->validate($output));

        if ($this->leaks(implode('', self::allText($tasks)), $canary)) {
            return $this->canaryLeak();
        }

        $result = $this->scanner->scanFields(
            [...PlanText::fields(array_map(self::textOf(...), $tasks)), ...self::permissionFields($tasks)],
            [...self::markupFindings($markupFields), ...self::policyFindings($tasks)],
        );

        if ($result->blocks()) {
            return new ScannedOutput([], $result);
        }

        $masked = $result->maskedFields ?? [];

        // Masking made it too long for the plan. Cutting it could change what it says.
        if (PlanText::tooLong($masked) !== []) {
            throw new InvalidAiOutputException('masked_too_long');
        }

        return new ScannedOutput(self::maskedTasks($tasks, $masked), $result);
    }

    private function canaryLeak(): ScannedOutput
    {
        return new ScannedOutput([], $this->scanner->scanFields([], [new InputFinding(
            'canary',
            self::RULE_CANARY,
            Severity::Critical,
            ScanAction::Block,
            'AI の応答にシステムプロンプトの一部が含まれていたため処理を停止しました',
            null,
            null,
            null,
            null,
        )]));
    }

    /**
     * As written, and as decoded, because "C" is written differently from what it means. An answer that is
     * not JSON at all has only the first.
     */
    private function leaksInAnswer(string $output, string $canary): bool
    {
        if ($this->leaks(mb_strcut($output, 0, self::CANARY_SEARCH_BYTES, 'UTF-8'), $canary)) {
            return true;
        }

        $decoded = json_decode(substr($output, 0, self::CANARY_SEARCH_BYTES), true, self::CANARY_SEARCH_DEPTH);

        if (! is_array($decoded)) {
            return false;
        }

        [$keys, $values] = self::keysAndValues($decoded);

        return $this->leaks(implode('', $values), $canary) || $this->leaks(implode('', $keys), $canary);
    }

    /**
     * Spaces, punctuation, case, full width and invisible characters do not hide it, and neither does putting it
     * in pieces. A random value of this length is not there by accident.
     */
    private function leaks(string $text, string $canary): bool
    {
        try {
            $normalized = $this->normalizer->normalize($text)->text;
        } catch (ScanFailure) {
            return false;
        }

        return str_contains(self::lettersAndDigits($normalized), self::lettersAndDigits($canary));
    }

    private static function lettersAndDigits(string $text): string
    {
        return (string) preg_replace('/[^a-z0-9]/', '', strtolower($text));
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array{list<string>, list<string>}
     */
    private static function keysAndValues(array $data): array
    {
        $keys = [];
        $values = [];

        foreach ($data as $key => $value) {
            $keys[] = (string) $key;

            if (is_array($value)) {
                [$innerKeys, $innerValues] = self::keysAndValues($value);
                array_push($keys, ...$innerKeys);
                array_push($values, ...$innerValues);
            } elseif (is_string($value)) {
                $values[] = $value;
            }
        }

        return [$keys, $values];
    }

    /**
     * @param  list<ValidatedTask>  $tasks
     * @return array{list<ValidatedTask>, list<string>} The tasks, and the fields that had markup.
     *
     * @throws InvalidAiOutputException when nothing is left of a text
     */
    private function stripped(array $tasks): array
    {
        $markupFields = [];
        $result = [];

        foreach ($tasks as $index => $task) {
            $prefix = 'tasks.'.($index + 1).'.';

            $text = function (string $value, string $name) use ($prefix, &$markupFields): string {
                return $this->strippedText($value, $prefix.$name, $markupFields);
            };
            $list = function (array $values, string $name) use ($text): array {
                $stripped = [];

                foreach (array_values($values) as $position => $value) {
                    $stripped[] = $text($value, $name.'.'.($position + 1));
                }

                return $stripped;
            };

            $result[] = new ValidatedTask(
                $text($task->title, 'title'),
                $text($task->description, 'description'),
                $task->actionType,
                $list($task->steps, 'steps'),
                $task->priority,
                $list($task->requestedPermissions, 'requested_permissions'),
                $text($task->targetData, 'target_data'),
                $text($task->impactSummary, 'impact_summary'),
                $task->decision,
                $task->permissions,
            );
        }

        return [$result, $markupFields];
    }

    /**
     * @param  list<string>  $markupFields
     *
     * @throws InvalidAiOutputException
     */
    private function strippedText(string $value, string $field, array &$markupFields): string
    {
        $stripped = $this->stripper->strip($value);

        if ($stripped !== $value) {
            $markupFields[] = $field;
        }

        $problem = AiTaskSchema::textProblem($stripped, self::ANY_LENGTH);

        if ($problem !== null) {
            throw new InvalidAiOutputException($problem, $field);
        }

        return $stripped;
    }

    /**
     * @param  list<string>  $fields
     * @return list<InputFinding>
     */
    private static function markupFindings(array $fields): array
    {
        return array_map(fn (string $field) => new InputFinding(
            'markup',
            self::RULE_MARKUP,
            Severity::Low,
            ScanAction::Record,
            'AI の応答から HTML やスクリプトを除去しました',
            null,
            null,
            $field,
            null,
        ), $fields);
    }

    /**
     * What is asked for and what is forbidden. The values are not repeated: what the AI wrote there can be anything.
     * Authorization never looks at what was asked for, so this is for the person who approves.
     *
     * @param  list<ValidatedTask>  $tasks
     * @return list<InputFinding>
     */
    private static function policyFindings(array $tasks): array
    {
        $findings = [];

        foreach ($tasks as $index => $task) {
            $prefix = 'tasks.'.($index + 1).'.';

            if (array_diff($task->requestedPermissions, $task->permissions) !== []) {
                $findings[] = new InputFinding('permission_mismatch', self::RULE_PERMISSION_OVER, Severity::Medium, ScanAction::Warn, 'AI が操作に必要な権限より多くの権限を申告しました。認可にはサーバーが導出した権限のみを使います', null, null, $prefix.'requested_permissions', null);
            }

            if (array_diff($task->permissions, $task->requestedPermissions) !== []) {
                $findings[] = new InputFinding('permission_mismatch', self::RULE_PERMISSION_UNDER, Severity::Low, ScanAction::Record, 'AI の申告した権限が操作に必要な権限より少なくなっています。認可にはサーバーが導出した権限のみを使います', null, null, $prefix.'requested_permissions', null);
            }

            if ($task->decision === PolicyDecision::Forbidden) {
                $findings[] = new InputFinding('forbidden_action', self::RULE_FORBIDDEN, Severity::High, ScanAction::Warn, 'AI が禁止された操作を提案しました。このタスクを含むワークフローは提出できません', null, null, $prefix.'action_type', null);
            }
        }

        return $findings;
    }

    /**
     * @param  list<ValidatedTask>  $tasks
     * @return list<string>
     */
    private static function allText(array $tasks): array
    {
        $text = [];

        foreach ($tasks as $task) {
            array_push($text, $task->title, $task->description, ...$task->steps, ...$task->requestedPermissions);
            array_push($text, $task->targetData, $task->impactSummary);
        }

        return $text;
    }

    /**
     * @return array{title: string, description: string, steps: list<string>, target_data: string, impact_summary: string}
     */
    private static function textOf(ValidatedTask $task): array
    {
        return [
            'title' => $task->title,
            'description' => $task->description,
            'steps' => $task->steps,
            'target_data' => $task->targetData,
            'impact_summary' => $task->impactSummary,
        ];
    }

    /**
     * @param  list<ValidatedTask>  $tasks
     * @return array<string, string>
     */
    private static function permissionFields(array $tasks): array
    {
        $fields = [];

        foreach ($tasks as $index => $task) {
            foreach ($task->requestedPermissions as $position => $permission) {
                $fields['tasks.'.($index + 1).'.requested_permissions.'.($position + 1)] = $permission;
            }
        }

        return $fields;
    }

    /**
     * @param  list<ValidatedTask>  $tasks
     * @param  array<string, string>  $masked
     * @return list<ValidatedTask>
     */
    private static function maskedTasks(array $tasks, array $masked): array
    {
        $texts = PlanText::withMasked(array_map(self::textOf(...), $tasks), $masked);
        $result = [];

        foreach ($tasks as $index => $task) {
            $text = $texts[$index];
            $requested = [];

            foreach (array_keys($task->requestedPermissions) as $position) {
                $requested[] = $masked['tasks.'.($index + 1).'.requested_permissions.'.($position + 1)];
            }

            $result[] = new ValidatedTask(
                $text['title'],
                $text['description'],
                $task->actionType,
                $text['steps'],
                $task->priority,
                $requested,
                $text['target_data'],
                $text['impact_summary'],
                $task->decision,
                $task->permissions,
            );
        }

        return $result;
    }
}
