<?php

namespace App\Ai\Evaluation;

/**
 * What one request came to. toArray() holds no text: ids, rule ids, action types, flags and numbers only, so it
 * can be kept in the repository. texts() is for a person to read, and goes to a file that is not committed.
 */
final readonly class EvaluationResult
{
    public const STAGE_INPUT_BLOCKED = 'input_blocked';

    public const STAGE_LIMIT = 'limit';

    public const STAGE_SUCCEEDED = 'succeeded';

    public const STAGE_OUTPUT_BLOCKED = 'output_blocked';

    public const STAGE_FAILED = 'failed';

    public const STAGE_UNFINISHED = 'unfinished';

    /**
     * @param  array{decision: ?string, block_reason: ?string, max_severity: ?string, findings: list<string>}  $input
     * @param  array{block_reason: ?string, max_severity: ?string, findings: list<string>}  $output
     * @param  list<array{action: string, decision: string, permissions_exact: bool, language: string}>  $tasks
     * @param  array<string, mixed>  $judgement
     * @param  array{provider: ?string, model: ?string, status: ?string, input_tokens: ?int, output_tokens: ?int, cost_micros: ?int, latency_ms: ?int}  $usage
     * @param  list<array<string, mixed>>  $taskTexts
     */
    public function __construct(
        public EvaluationRequest $request,
        public string $stage,
        public ?string $errorCode,
        public array $input,
        public array $output,
        public array $tasks,
        public array $judgement,
        public array $usage,
        public ?string $workflowId,
        public array $taskTexts,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->request->id,
            'kind' => $this->request->kind,
            'lang' => $this->request->lang,
            'goal' => $this->request->goal,
            'stage' => $this->stage,
            'error_code' => $this->errorCode,
            'input' => $this->input,
            'output' => $this->output,
            'tasks' => $this->tasks,
            'judgement' => $this->judgement,
            'usage' => $this->usage,
            'workflow_id' => $this->workflowId,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function texts(): array
    {
        return [
            'id' => $this->request->id,
            'kind' => $this->request->kind,
            'request' => $this->request->text,
            'stage' => $this->stage,
            'tasks' => $this->taskTexts,
        ];
    }

    /**
     * @return list<string>
     */
    public function actions(): array
    {
        return array_map(fn (array $task) => $task['action'], $this->tasks);
    }
}
